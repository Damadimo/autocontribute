from __future__ import annotations

import copy
from typing import Any
from unittest.mock import Mock

import httpx
import pytest
from openai import APIConnectionError, InternalServerError, RateLimitError
from openai.types.responses import Response

import autocontribute.openai_adapter as openai_adapter
from autocontribute.exceptions import ConfigurationError, ModelError, ModelRequestError
from autocontribute.model_retry import retry_decision
from autocontribute.pricing import MODELS, ModelUsage
from autocontribute.providers import TurnRequest
from autocontribute.transcript import ToolCall, TranscriptKind, tool_definitions

_API_KEY = "openai-turn-test-key-placeholder"
_USER_MESSAGE: dict[str, Any] = {
    "type": "message",
    "role": "user",
    "content": [{"type": "input_text", "text": "Fix issue 12 in /workspace."}],
}
# Item and usage shapes from the 2026-10-22 probe of gpt-5.6-sol with openai 2.45.0.
_USAGE: dict[str, Any] = {
    "input_tokens": 2_412,
    "input_tokens_details": {"cached_tokens": 1_920, "cache_write_tokens": 380},
    "output_tokens": 160,
    "output_tokens_details": {"reasoning_tokens": 96},
    "total_tokens": 2_572,
}
_REASONING: dict[str, Any] = {
    "id": "rs_68f9a1c2d3",
    "type": "reasoning",
    "summary": [],
    "encrypted_content": "gAAAAABo-opaque-reasoning",
}
_SHELL_CALL: dict[str, Any] = {
    "id": "sh_68f9a1c2d4",
    "type": "shell_call",
    "call_id": "call_9d14ac6f2b73485e",
    "action": {"commands": ["cat hello.py"], "timeout_ms": 120_000, "max_output_length": 4_096},
    "environment": {"type": "local"},
    "status": "in_progress",
    "created_by": "resp_68f9a1c2d2",
}
_PATCH_CALL: dict[str, Any] = {
    "id": "apc_68f9a1c2d5",
    "type": "apply_patch_call",
    "call_id": "call_Rjsqzz96C5xzPb0j",
    "operation": {
        "type": "update_file",
        "path": "/workspace/hello.py",
        "diff": "@@\n-print('hi')\n+print('Hello, world!')\n",
    },
    "status": "completed",
    "created_by": "resp_68f9a1c2d2",
}
_SUBMIT_CALL: dict[str, Any] = {
    "id": "fc_68f9a1c2d6",
    "type": "function_call",
    "call_id": "call_3ef1b8c79a4d6520",
    "name": "submit",
    "arguments": '{"outcome":"skip","skip_reason":"Already fixed on main."}',
    "status": "completed",
}
_COMMENTARY: dict[str, Any] = {
    "id": "msg_68f9a1c2d7",
    "type": "message",
    "role": "assistant",
    "status": "completed",
    "phase": "final_answer",
    "content": [{"type": "output_text", "text": "The issue is fixed.", "annotations": []}],
}


def _response(
    *output: dict[str, Any],
    status: str = "completed",
    incomplete_reason: str | None = None,
    error_code: str | None = None,
    usage: dict[str, Any] | None = None,
) -> Response:
    data: dict[str, Any] = {
        "id": "resp_68f9a1c2d2",
        "created_at": 1_792_000_000.0,
        "model": "gpt-5.6-sol",
        "object": "response",
        "output": [copy.deepcopy(item) for item in output],
        "parallel_tool_calls": True,
        "tool_choice": "auto",
        "tools": [],
        "status": status,
        "usage": copy.deepcopy(_USAGE if usage is None else usage),
    }
    if incomplete_reason is not None:
        data["incomplete_details"] = {"reason": incomplete_reason}
    if error_code is not None:
        data["error"] = {"code": error_code, "message": "provider detail that must not leak"}
    # The SDK builds responses without validation; model_construct does the same.
    return Response.model_construct(**data)


def _request(kind: TranscriptKind = "agent") -> TurnRequest:
    return TurnRequest(
        spec=MODELS["gpt-5.6-sol"],
        effort="high",
        instructions="You are fixing one GitHub issue.",
        kind=kind,
        run_id="0123456789abcdef",
        items=[_USER_MESSAGE],
        max_output_tokens=32_000,
        timeout_seconds=600.0,
    )


def _client(
    monkeypatch: pytest.MonkeyPatch,
    response: Response | None = None,
    *,
    error: Exception | None = None,
) -> tuple[Mock, Mock]:
    monkeypatch.setenv("OPENAI_API_KEY", _API_KEY)
    client = Mock()
    client.responses.create.return_value = response
    client.responses.create.side_effect = error
    constructor = Mock(return_value=client)
    monkeypatch.setattr(openai_adapter, "OpenAI", constructor)
    return client, constructor


def _status_error(
    error_type: type[RateLimitError | InternalServerError],
    status: int,
    *,
    code: str,
    headers: dict[str, str],
) -> Exception:
    request = httpx.Request("POST", "https://api.openai.com/v1/responses")
    response = httpx.Response(status, request=request, headers=headers)
    return error_type(
        "provider message", response=response, body={"type": code, "code": code, "message": "x"}
    )


def test_request_holds_the_transcript_constants(monkeypatch: pytest.MonkeyPatch) -> None:
    client, constructor = _client(monkeypatch, _response(_REASONING, _SHELL_CALL))

    openai_adapter.step(_request())

    constructor.assert_called_once_with(api_key=_API_KEY, max_retries=0)
    client.responses.create.assert_called_once_with(
        model="gpt-5.6-sol",
        instructions="You are fixing one GitHub issue.",
        input=[_USER_MESSAGE],
        tools=tool_definitions("openai", "agent"),
        tool_choice="auto",
        parallel_tool_calls=True,
        reasoning={"effort": "high"},
        store=False,
        include=["reasoning.encrypted_content"],
        max_output_tokens=32_000,
        truncation="disabled",
        prompt_cache_key="ac:0123456789abcdef:agent",
        timeout=600.0,
    )
    client.close.assert_called_once_with()


def test_calls_are_normalized_and_items_replayed_without_output_only_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _client(monkeypatch, _response(_REASONING, _SHELL_CALL, _PATCH_CALL, _SUBMIT_CALL))

    turn = openai_adapter.step(_request())

    assert turn.stop == "tool_use"
    assert turn.output_items == (
        _REASONING,
        {key: value for key, value in _SHELL_CALL.items() if key != "created_by"},
        {key: value for key, value in _PATCH_CALL.items() if key != "created_by"},
        _SUBMIT_CALL,
    )
    assert turn.tool_calls == (
        ToolCall(call_id="call_9d14ac6f2b73485e", name="shell", arguments=_SHELL_CALL["action"]),
        ToolCall(
            call_id="call_Rjsqzz96C5xzPb0j", name="apply_patch", arguments=_PATCH_CALL["operation"]
        ),
        ToolCall(
            call_id="call_3ef1b8c79a4d6520",
            name="submit",
            arguments={"outcome": "skip", "skip_reason": "Already fixed on main."},
        ),
    )
    assert (turn.response_id, turn.model) == ("resp_68f9a1c2d2", "gpt-5.6-sol")


def test_cached_and_cache_write_tokens_are_disjoint_parts_of_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _client(monkeypatch, _response(_REASONING, _SHELL_CALL))

    turn = openai_adapter.step(_request())

    assert turn.usage == ModelUsage(
        input_tokens=2_412,
        cached_input_tokens=1_920,
        cache_write_tokens=380,
        output_tokens=160,
        reasoning_tokens=96,
        total_tokens=2_572,
    )


def test_cache_details_above_input_fail_the_turn(monkeypatch: pytest.MonkeyPatch) -> None:
    usage = copy.deepcopy(_USAGE)
    usage["input_tokens_details"]["cache_write_tokens"] = 500
    _client(monkeypatch, _response(_REASONING, usage=usage))

    with pytest.raises(ModelError, match="input-token details above input_tokens"):
        openai_adapter.step(_request())


def test_a_message_without_calls_ends_the_turn_and_keeps_its_phase(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _client(monkeypatch, _response(_REASONING, _COMMENTARY))

    turn = openai_adapter.step(_request())

    assert turn.stop == "end_turn"
    assert turn.tool_calls == ()
    assert turn.output_items[1]["phase"] == "final_answer"


def test_output_limit_returns_an_empty_turn_to_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    response = _response(_REASONING, status="incomplete", incomplete_reason="max_output_tokens")
    _client(monkeypatch, response)

    turn = openai_adapter.step(_request())

    assert turn.stop == "max_output_tokens"
    assert (turn.output_items, turn.tool_calls) == ((), ())
    assert turn.usage.output_tokens == 160


def test_content_filter_ends_the_run(monkeypatch: pytest.MonkeyPatch) -> None:
    response = _response(_REASONING, status="incomplete", incomplete_reason="content_filter")
    _client(monkeypatch, response)

    with pytest.raises(ModelError, match="incomplete: content_filter") as raised:
        openai_adapter.step(_request())

    assert not isinstance(raised.value, ModelRequestError)


def test_unknown_incomplete_reason_is_not_echoed(monkeypatch: pytest.MonkeyPatch) -> None:
    response = _response(status="incomplete", incomplete_reason="upstream private diagnostic")
    _client(monkeypatch, response)

    with pytest.raises(ModelError) as raised:
        openai_adapter.step(_request())

    assert str(raised.value) == "Model response did not complete"


def test_a_refusal_ends_the_run_without_echoing_it(monkeypatch: pytest.MonkeyPatch) -> None:
    refusal = copy.deepcopy(_COMMENTARY)
    refusal["content"] = [{"type": "refusal", "refusal": "I can't help with this exploit."}]
    _client(monkeypatch, _response(_REASONING, refusal, _SHELL_CALL))

    with pytest.raises(ModelError) as raised:
        openai_adapter.step(_request())

    assert str(raised.value) == "Model refused the request"
    assert not isinstance(raised.value, ModelRequestError)


@pytest.mark.parametrize(
    ("code", "message", "retried"),
    [
        ("server_error", "Model response failed (code: server_error)", True),
        ("rate_limit_exceeded", "Model response failed (code: rate_limit_exceeded)", True),
        ("cyber_policy", "Model response failed (code: cyber_policy)", False),
        (
            "misalignment_policy_violation",
            "Model response failed (code: misalignment_policy_violation)",
            False,
        ),
    ],
)
def test_failed_responses_map_into_the_retry_classification(
    monkeypatch: pytest.MonkeyPatch,
    code: str,
    message: str,
    retried: bool,
) -> None:
    _client(monkeypatch, _response(status="failed", error_code=code))

    with pytest.raises(ModelRequestError) as raised:
        openai_adapter.step(_request())

    error = raised.value
    assert str(error) == message
    decision = retry_decision(
        status_code=error.status_code,
        provider_code=error.provider_code,
        retry_after=error.retry_after_seconds,
        timed_out=False,
        attempt=1,
        jitter=0.0,
    )
    assert decision.retry is retried


@pytest.mark.parametrize(
    ("code", "message"),
    [
        ("bio_policy", "Model response failed (code: bio_policy)"),
        ("invalid_prompt", "Model response failed (code: invalid_prompt)"),
        ("upstream_private_code", "Model response failed"),
    ],
)
def test_other_failed_responses_end_the_run(
    monkeypatch: pytest.MonkeyPatch,
    code: str,
    message: str,
) -> None:
    _client(monkeypatch, _response(status="failed", error_code=code))

    with pytest.raises(ModelError) as raised:
        openai_adapter.step(_request())

    assert str(raised.value) == message
    assert not isinstance(raised.value, ModelRequestError)


@pytest.mark.parametrize("status", ["queued", "in_progress", "cancelled"])
def test_background_statuses_fail_the_turn(monkeypatch: pytest.MonkeyPatch, status: str) -> None:
    _client(monkeypatch, _response(status=status))

    with pytest.raises(ModelError, match="did not complete"):
        openai_adapter.step(_request())


def test_http_errors_keep_status_code_and_retry_after(monkeypatch: pytest.MonkeyPatch) -> None:
    quota = _status_error(RateLimitError, 429, code="insufficient_quota", headers={})
    overloaded = _status_error(
        InternalServerError, 503, code="server_is_overloaded", headers={"retry-after": "7"}
    )
    connection = APIConnectionError(
        request=httpx.Request("POST", "https://api.openai.com/v1/responses")
    )

    decisions = []
    for error in (quota, overloaded, connection):
        client, _ = _client(monkeypatch, error=error)
        with pytest.raises(ModelRequestError) as raised:
            openai_adapter.step(_request())
        client.close.assert_called_once_with()
        decisions.append(
            (
                raised.value.status_code,
                raised.value.provider_code,
                raised.value.retry_after_seconds,
            )
        )

    assert decisions == [(429, "insufficient_quota", None), (503, None, 7.0), (None, None, None)]


@pytest.mark.parametrize(
    ("item", "message"),
    [
        (
            {"id": "ws_1", "type": "web_search_call", "status": "completed"},
            "unsupported output item",
        ),
        ({**_SUBMIT_CALL, "name": "submit_review"}, "function outside its tool set"),
        ({**_SUBMIT_CALL, "arguments": "{not json"}, "not a JSON object"),
        ({**_SUBMIT_CALL, "arguments": "[1, 2]"}, "not a JSON object"),
        ({**_SHELL_CALL, "call_id": "call 1; rm -rf /"}, "invalid tool call"),
    ],
    ids=["unknown-item", "foreign-function", "invalid-json", "non-object", "unsafe-call-id"],
)
def test_malformed_output_fails_the_turn(
    monkeypatch: pytest.MonkeyPatch,
    item: dict[str, Any],
    message: str,
) -> None:
    _client(monkeypatch, _response(_REASONING, item))

    with pytest.raises(ModelError, match=message):
        openai_adapter.step(_request())


def test_critic_submit_uses_its_own_function_name(monkeypatch: pytest.MonkeyPatch) -> None:
    review = {**_SUBMIT_CALL, "name": "submit_review", "arguments": '{"verdict":"approve"}'}
    client, _ = _client(monkeypatch, _response(review))

    turn = openai_adapter.step(_request("critic"))

    assert turn.tool_calls[0].name == "submit_review"
    request = client.responses.create.call_args.kwargs
    assert request["tools"] == tool_definitions("openai", "critic")
    assert request["prompt_cache_key"] == "ac:0123456789abcdef:critic"


def test_missing_key_fails_before_the_client_is_built(monkeypatch: pytest.MonkeyPatch) -> None:
    _, constructor = _client(monkeypatch, _response(_REASONING))
    monkeypatch.delenv("OPENAI_API_KEY")

    with pytest.raises(ConfigurationError, match="OPENAI_API_KEY"):
        openai_adapter.step(_request())

    constructor.assert_not_called()
