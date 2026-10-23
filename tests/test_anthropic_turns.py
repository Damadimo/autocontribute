from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx2
import pytest

import autocontribute.anthropic_adapter as anthropic_adapter
from autocontribute.exceptions import ConfigurationError, ModelError, ModelRequestError
from autocontribute.model_retry import retry_decision
from autocontribute.pricing import MODELS, ModelUsage
from autocontribute.providers import TurnRequest
from autocontribute.transcript import (
    ToolCall,
    ToolResult,
    Transcript,
    TranscriptKind,
    append_tool_results,
    append_turn,
    append_user_text,
    tool_definitions,
)

_API_KEY = "anthropic-turn-test-key-placeholder"
_RUN_ID = "0123456789abcdef"
_INSTRUCTIONS = "You are fixing one GitHub issue."
# Identifiers, block shapes, usage fields and error bodies follow the anthropic-ref examples.
_REQUEST_ID = "req_011CSHoEeqs5C35K2UUqR7Fy"
_MESSAGE_ID = "msg_01XFDUDYJgAACzvnptvVoYEL"
_USER_MESSAGE: dict[str, Any] = {
    "role": "user",
    "content": [{"type": "text", "text": "Fix issue 12 in /workspace."}],
}
_USAGE: dict[str, Any] = {
    "input_tokens": 12,
    "cache_creation_input_tokens": 380,
    "cache_read_input_tokens": 2_020,
    "output_tokens": 160,
}
# Adaptive thinking with the default display: the text is empty and the signature is opaque.
_THINKING: dict[str, Any] = {
    "type": "thinking",
    "thinking": "",
    "signature": "EqQBCgIYAhIM1gbcDa9GJwZA2b3hGgxqWzLV0jCZqB4mFSAiMF7u",
}
_REDACTED_THINKING: dict[str, Any] = {
    "type": "redacted_thinking",
    "data": "EmwKAhgBEgy3va3pzix/LafPsn4aDFIT2Xlxh0L5L8rLVyIwxtE3rAFBa8cr3qpP",
}
_TEXT: dict[str, Any] = {"type": "text", "text": "I'll read the file first."}
_BASH_CALL: dict[str, Any] = {
    "type": "tool_use",
    "id": "toolu_01A09q90qw90lq917835lq9",
    "name": "bash",
    "input": {"command": "cat hello.py"},
    "caller": {"type": "direct"},
}
_EDIT_CALL: dict[str, Any] = {
    "type": "tool_use",
    "id": "toolu_01EditQ90qw90lq917835lq9",
    "name": "str_replace_based_edit_tool",
    "input": {
        "command": "str_replace",
        "path": "/workspace/hello.py",
        "old_str": "print('hi')",
        "new_str": "print('Hello, world!')",
    },
}
_SUBMIT_CALL: dict[str, Any] = {
    "type": "tool_use",
    "id": "toolu_01SubmitQ90qw90lq917835",
    "name": "submit",
    "input": {"outcome": "skip", "skip_reason": "Already fixed on main."},
}


def _events(
    blocks: tuple[dict[str, Any], ...],
    *,
    stop_reason: str,
    stop_details: dict[str, Any] | None,
    usage: dict[str, Any],
) -> list[dict[str, Any]]:
    """Return the events of a streamed message: each block starts empty and fills by deltas."""

    events: list[dict[str, Any]] = [
        {
            "type": "message_start",
            "message": {
                "id": _MESSAGE_ID,
                "type": "message",
                "role": "assistant",
                "model": "claude-opus-5-5",
                "content": [],
                "stop_reason": None,
                "stop_sequence": None,
                "usage": {**usage, "output_tokens": 1},
            },
        }
    ]
    for index, block in enumerate(blocks):
        deltas: list[dict[str, Any]] = []
        if block["type"] == "thinking":
            start = {**block, "thinking": "", "signature": ""}
            deltas.append({"type": "signature_delta", "signature": block["signature"]})
        elif block["type"] == "text":
            start = {**block, "text": ""}
            deltas.append({"type": "text_delta", "text": block["text"]})
        elif block["type"] == "tool_use":
            start = {**block, "input": {}}
            arguments = json.dumps(block["input"])
            deltas.extend(
                {"type": "input_json_delta", "partial_json": part}
                for part in (arguments[:9], arguments[9:])
            )
        else:
            start = block
        events.append({"type": "content_block_start", "index": index, "content_block": start})
        events.extend(
            {"type": "content_block_delta", "index": index, "delta": delta} for delta in deltas
        )
        events.append({"type": "content_block_stop", "index": index})
    events.append(
        {
            "type": "message_delta",
            "delta": {
                "stop_reason": stop_reason,
                "stop_sequence": None,
                "stop_details": stop_details,
            },
            "usage": {"output_tokens": usage["output_tokens"]},
        }
    )
    events.append({"type": "message_stop"})
    return events


def _sse(events: list[dict[str, Any]]) -> bytes:
    return b"".join(
        f"event: {event['type']}\ndata: {json.dumps(event)}\n\n".encode() for event in events
    )


def _message(
    *blocks: dict[str, Any],
    stop_reason: str = "tool_use",
    stop_details: dict[str, Any] | None = None,
    usage: dict[str, Any] | None = None,
) -> httpx2.Response:
    events = _events(
        blocks,
        stop_reason=stop_reason,
        stop_details=stop_details,
        usage=_USAGE if usage is None else usage,
    )
    return httpx2.Response(
        200,
        headers={"content-type": "text/event-stream", "request-id": _REQUEST_ID},
        content=_sse(events),
    )


def _error(status: int, error_type: str, headers: dict[str, str] | None = None) -> httpx2.Response:
    return httpx2.Response(
        status,
        headers={"request-id": _REQUEST_ID, **(headers or {})},
        json={
            "type": "error",
            "error": {"type": error_type, "message": "provider detail that must not leak"},
            "request_id": _REQUEST_ID,
        },
    )


def _error_event(error_type: str) -> httpx2.Response:
    """A stream that starts and then fails, as an overloaded API does mid-response."""

    start = _events((), stop_reason="end_turn", stop_details=None, usage=_USAGE)[:1]
    error = {"type": "error", "error": {"type": error_type, "message": "provider detail"}}
    return httpx2.Response(
        200,
        headers={"content-type": "text/event-stream", "request-id": _REQUEST_ID},
        content=_sse(start) + f"event: error\ndata: {json.dumps(error)}\n\n".encode(),
    )


def _serve(
    monkeypatch: pytest.MonkeyPatch,
    *responses: httpx2.Response | Exception,
) -> tuple[list[httpx2.Request], list[dict[str, Any]]]:
    """Serve the Messages endpoint from ``responses`` and record what the adapter sent."""

    monkeypatch.setenv("ANTHROPIC_API_KEY", _API_KEY)
    requests: list[httpx2.Request] = []
    options: list[dict[str, Any]] = []
    pending = list(responses)

    def handle(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        response = pending.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    sdk_client: Callable[..., Any] = anthropic_adapter.Anthropic

    def client(**client_options: Any) -> Any:
        options.append(client_options)
        transport = httpx2.MockTransport(handle)
        return sdk_client(**client_options, http_client=httpx2.Client(transport=transport))

    monkeypatch.setattr(anthropic_adapter, "Anthropic", client)
    return requests, options


def _request(
    kind: TranscriptKind = "agent",
    items: list[dict[str, Any]] | None = None,
) -> TurnRequest:
    return TurnRequest(
        spec=MODELS["claude-opus-5-5"],
        effort="high",
        instructions=_INSTRUCTIONS,
        kind=kind,
        run_id=_RUN_ID,
        items=[_USER_MESSAGE] if items is None else items,
        max_output_tokens=64_000,
        timeout_seconds=600.0,
    )


def _body(request: httpx2.Request) -> dict[str, Any]:
    body: dict[str, Any] = json.loads(request.content)
    return body


def test_request_streams_with_cache_breakpoints_effort_and_no_sampling_or_thinking(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests, options = _serve(monkeypatch, _message(_THINKING, _BASH_CALL))

    anthropic_adapter.step(_request())

    assert options == [{"api_key": _API_KEY, "max_retries": 0}]
    assert [request.url.path for request in requests] == ["/v1/messages"]
    assert _body(requests[0]) == {
        "model": "claude-opus-5-5",
        "system": [{"type": "text", "text": _INSTRUCTIONS, "cache_control": {"type": "ephemeral"}}],
        "messages": [_USER_MESSAGE],
        "tools": tool_definitions("anthropic", "agent"),
        "max_tokens": 64_000,
        "output_config": {"effort": "high"},
        "cache_control": {"type": "ephemeral"},
        "stream": True,
    }
    assert requests[0].extensions["timeout"]["read"] == 600.0


def test_calls_are_normalized_and_content_is_kept_as_received(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    blocks = (_THINKING, _REDACTED_THINKING, _TEXT, _BASH_CALL, _EDIT_CALL, _SUBMIT_CALL)
    _serve(monkeypatch, _message(*blocks))

    turn = anthropic_adapter.step(_request())

    assert turn.stop == "tool_use"
    assert turn.output_items == blocks
    assert turn.tool_calls == (
        ToolCall(call_id=_BASH_CALL["id"], name="bash", arguments={"command": "cat hello.py"}),
        ToolCall(
            call_id=_EDIT_CALL["id"],
            name="str_replace_based_edit_tool",
            arguments=_EDIT_CALL["input"],
        ),
        ToolCall(call_id=_SUBMIT_CALL["id"], name="submit", arguments=_SUBMIT_CALL["input"]),
    )
    assert (turn.response_id, turn.model) == (_MESSAGE_ID, "claude-opus-5-5")


def test_next_request_replays_the_turn_unchanged_and_answers_it_in_one_user_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests, _ = _serve(
        monkeypatch,
        _message(_THINKING, _TEXT, _BASH_CALL),
        _message(_TEXT, stop_reason="end_turn"),
    )
    transcript = Transcript(
        model="claude-opus-5-5",
        effort="high",
        kind="agent",
        run_id=_RUN_ID,
        instructions=_INSTRUCTIONS,
    )
    append_user_text(transcript, "Fix issue 12 in /workspace.", host_values=frozenset())

    append_turn(transcript, anthropic_adapter.step(_request(items=transcript.items)))
    append_tool_results(
        transcript,
        [
            ToolResult(
                call_id=_BASH_CALL["id"],
                output="cat: hello.py: No such file or directory",
                is_error=True,
            )
        ],
        host_values=frozenset(),
    )
    append_user_text(transcript, "9 turns left.", host_values=frozenset())
    anthropic_adapter.step(_request(items=transcript.items))

    first, second = (_body(request) for request in requests)
    assert second["messages"] == [
        _USER_MESSAGE,
        {"role": "assistant", "content": [_THINKING, _TEXT, _BASH_CALL]},
        {
            "role": "user",
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": _BASH_CALL["id"],
                    "content": "cat: hello.py: No such file or directory",
                    "is_error": True,
                },
                {"type": "text", "text": "9 turns left."},
            ],
        },
    ]
    assert {key: value for key, value in second.items() if key != "messages"} == {
        key: value for key, value in first.items() if key != "messages"
    }


def test_input_counts_cache_reads_and_writes_and_reasoning_is_not_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _serve(monkeypatch, _message(_THINKING, _BASH_CALL))

    turn = anthropic_adapter.step(_request())

    assert turn.usage == ModelUsage(
        input_tokens=2_412,
        cached_input_tokens=2_020,
        cache_write_tokens=380,
        output_tokens=160,
        reasoning_tokens=0,
        total_tokens=2_572,
    )


def test_missing_cache_fields_count_as_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    _serve(monkeypatch, _message(_BASH_CALL, usage={"input_tokens": 50, "output_tokens": 7}))

    turn = anthropic_adapter.step(_request())

    assert turn.usage == ModelUsage(input_tokens=50, output_tokens=7, total_tokens=57)


def test_a_turn_without_calls_ends_the_turn(monkeypatch: pytest.MonkeyPatch) -> None:
    _serve(monkeypatch, _message(_THINKING, _TEXT, stop_reason="end_turn"))

    turn = anthropic_adapter.step(_request())

    assert turn.stop == "end_turn"
    assert turn.tool_calls == ()
    assert turn.output_items == (_THINKING, _TEXT)


def test_output_limit_returns_an_empty_turn_to_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    _serve(monkeypatch, _message(_THINKING, _EDIT_CALL, stop_reason="max_tokens"))

    turn = anthropic_adapter.step(_request())

    assert turn.stop == "max_output_tokens"
    assert (turn.output_items, turn.tool_calls) == ((), ())
    assert turn.usage.output_tokens == 160


@pytest.mark.parametrize(
    ("stop_details", "message"),
    [
        (
            {"type": "refusal", "category": "cyber", "explanation": "Exploit development."},
            "Model refused the request (category: cyber)",
        ),
        (
            {"type": "refusal", "category": "reasoning_extraction", "explanation": None},
            "Model refused the request (category: reasoning_extraction)",
        ),
        ({"type": "refusal", "category": None, "explanation": None}, "Model refused the request"),
        (
            {"type": "refusal", "category": "upstream private category", "explanation": "x"},
            "Model refused the request",
        ),
        (None, "Model refused the request"),
    ],
    ids=["cyber", "reasoning-extraction", "no-category", "unknown-category", "no-details"],
)
def test_a_refusal_ends_the_run_naming_only_a_known_category(
    monkeypatch: pytest.MonkeyPatch,
    stop_details: dict[str, Any] | None,
    message: str,
) -> None:
    # A classifier can stop the stream after partial output; nothing of it is kept.
    response = _message(_TEXT, stop_reason="refusal", stop_details=stop_details)
    _serve(monkeypatch, response)

    with pytest.raises(ModelError) as raised:
        anthropic_adapter.step(_request())

    assert str(raised.value) == message
    assert not isinstance(raised.value, ModelRequestError)


@pytest.mark.parametrize(
    ("stop_reason", "message"),
    [
        ("pause_turn", "Model provider paused a turn without server tools"),
        (
            "model_context_window_exceeded",
            "Model response did not complete: model_context_window_exceeded",
        ),
        ("upstream private reason", "Model response did not complete"),
    ],
)
def test_other_stop_reasons_fail_the_turn(
    monkeypatch: pytest.MonkeyPatch,
    stop_reason: str,
    message: str,
) -> None:
    _serve(monkeypatch, _message(_TEXT, stop_reason=stop_reason))

    with pytest.raises(ModelError) as raised:
        anthropic_adapter.step(_request())

    assert str(raised.value) == message
    assert not isinstance(raised.value, ModelRequestError)


@pytest.mark.parametrize(
    ("kind", "blocks", "stop_reason", "message"),
    [
        ("agent", (), "end_turn", "empty response"),
        (
            "agent",
            ({"type": "server_tool_use", "id": "srvtoolu_01", "name": "web_search", "input": {}},),
            "end_turn",
            "unsupported content block",
        ),
        ("agent", ({**_SUBMIT_CALL, "name": "submit_review"},), "tool_use", "outside its tool"),
        ("critic", (_EDIT_CALL,), "tool_use", "outside its tool set"),
        ("triage", (_BASH_CALL,), "tool_use", "outside its tool set"),
        ("agent", ({**_BASH_CALL, "name": "shell"},), "tool_use", "outside its tool set"),
        ("agent", ({**_BASH_CALL, "id": "toolu 01; rm -rf /"},), "tool_use", "invalid tool call"),
        ("agent", (_TEXT,), "tool_use", "does not match its tool calls"),
        ("agent", (_BASH_CALL,), "end_turn", "does not match its tool calls"),
    ],
    ids=[
        "empty",
        "server-tool",
        "foreign-submit",
        "edit-for-critic",
        "bash-for-triage",
        "openai-tool-name",
        "unsafe-call-id",
        "tool-use-without-calls",
        "end-turn-with-calls",
    ],
)
def test_malformed_responses_fail_the_turn(
    monkeypatch: pytest.MonkeyPatch,
    kind: TranscriptKind,
    blocks: tuple[dict[str, Any], ...],
    stop_reason: str,
    message: str,
) -> None:
    _serve(monkeypatch, _message(*blocks, stop_reason=stop_reason))

    with pytest.raises(ModelError, match=message):
        anthropic_adapter.step(_request(kind))


def test_critic_declares_its_tools_and_submits_a_review(monkeypatch: pytest.MonkeyPatch) -> None:
    review = {**_SUBMIT_CALL, "name": "submit_review", "input": {"verdict": "approve"}}
    requests, _ = _serve(monkeypatch, _message(_BASH_CALL, review))

    turn = anthropic_adapter.step(_request("critic"))

    assert [call.name for call in turn.tool_calls] == ["bash", "submit_review"]
    assert _body(requests[0])["tools"] == tool_definitions("anthropic", "critic")


@pytest.mark.parametrize(
    ("response", "status", "retry_after", "retried"),
    [
        (_error(529, "overloaded_error", {"retry-after": "12"}), 529, 12.0, True),
        (_error(429, "rate_limit_error", {"retry-after-ms": "1500"}), 429, 1.5, True),
        (_error(500, "api_error"), 500, None, True),
        (_error_event("overloaded_error"), 529, None, True),
        (_error_event("api_error"), 500, None, True),
        (_error_event("rate_limit_error"), 429, None, True),
        (_error_event("invalid_request_error"), 400, None, False),
        (_error(400, "invalid_request_error"), 400, None, False),
        (_error(402, "billing_error"), 402, None, False),
    ],
    ids=[
        "overloaded",
        "rate-limited",
        "server-error",
        "overloaded-mid-stream",
        "server-error-mid-stream",
        "rate-limited-mid-stream",
        "bad-mid-stream",
        "bad",
        "billing",
    ],
)
def test_http_errors_map_into_the_retry_classification(
    monkeypatch: pytest.MonkeyPatch,
    response: httpx2.Response,
    status: int,
    retry_after: float | None,
    retried: bool,
) -> None:
    _serve(monkeypatch, response)

    with pytest.raises(ModelRequestError) as raised:
        anthropic_adapter.step(_request())

    error = raised.value
    assert str(error) == (
        f"Anthropic Messages request failed (HTTP {status}; request ID: {_REQUEST_ID})"
    )
    assert (error.status_code, error.provider_code, error.retry_after_seconds) == (
        status,
        None,
        retry_after,
    )
    decision = retry_decision(
        status_code=error.status_code,
        provider_code=error.provider_code,
        retry_after=error.retry_after_seconds,
        timed_out=False,
        attempt=1,
        jitter=0.0,
    )
    assert decision.retry is retried


def test_an_unlisted_error_type_mid_stream_is_retried_like_a_dropped_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _serve(monkeypatch, _error_event("upstream_private_error"))

    with pytest.raises(ModelRequestError) as raised:
        anthropic_adapter.step(_request())

    assert str(raised.value) == f"Anthropic Messages request failed (request ID: {_REQUEST_ID})"
    assert raised.value.status_code is None
    decision = retry_decision(
        status_code=None,
        provider_code=None,
        retry_after=None,
        timed_out=False,
        attempt=1,
        jitter=0.0,
    )
    assert (decision.retry, decision.reason) == (True, "connection error")


def test_connection_errors_are_retried_without_a_status(monkeypatch: pytest.MonkeyPatch) -> None:
    _serve(monkeypatch, httpx2.ConnectError("connection refused"))

    with pytest.raises(ModelRequestError) as raised:
        anthropic_adapter.step(_request())

    assert str(raised.value) == "Anthropic Messages request failed"
    assert raised.value.status_code is None
    assert retry_decision(
        status_code=None,
        provider_code=None,
        retry_after=None,
        timed_out=False,
        attempt=1,
        jitter=0.0,
    ).retry


@pytest.mark.parametrize("request_id", ["req 1; echo", _API_KEY, "x" * 129])
def test_unsafe_request_ids_are_not_echoed(
    monkeypatch: pytest.MonkeyPatch,
    request_id: str,
) -> None:
    response = _error(529, "overloaded_error")
    response.headers["request-id"] = request_id
    _serve(monkeypatch, response)

    with pytest.raises(ModelRequestError) as raised:
        anthropic_adapter.step(_request())

    assert str(raised.value) == "Anthropic Messages request failed (HTTP 529)"


def test_missing_key_fails_before_the_client_is_built(monkeypatch: pytest.MonkeyPatch) -> None:
    requests, options = _serve(monkeypatch, _message(_BASH_CALL))
    monkeypatch.delenv("ANTHROPIC_API_KEY")

    with pytest.raises(ConfigurationError, match="ANTHROPIC_API_KEY"):
        anthropic_adapter.step(_request())

    assert (requests, options) == ([], [])
