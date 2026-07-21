from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from pydantic import BaseModel

import autocontribute.providers as providers
from autocontribute.config import ModelProfile
from autocontribute.exceptions import ConfigurationError, ModelError
from autocontribute.providers import ModelUsage, OpenAICompatibleProvider, OpenAIResponsesProvider
from autocontribute.redaction import MODEL_INPUT_REDACTION

_API_KEY_ENV = "AUTOCONTRIBUTE_TEST_MODEL_KEY"
_API_KEY = "sk-test-placeholder"


class Verdict(BaseModel):
    accepted: bool
    summary: str


def _profile(monkeypatch: pytest.MonkeyPatch, *, compatible: bool = False) -> ModelProfile:
    monkeypatch.setenv(_API_KEY_ENV, _API_KEY)
    return ModelProfile(
        provider="openai_compatible" if compatible else "openai",
        model="test-model",
        api_key_env=_API_KEY_ENV,
        base_url="https://models.example.test/v1" if compatible else None,
        reasoning_effort="high",
        reasoning_mode="standard" if compatible else "pro",
        max_output_tokens=40_000,
        timeout_seconds=900,
    )


def _responses_usage() -> SimpleNamespace:
    return SimpleNamespace(
        input_tokens=120,
        input_tokens_details=SimpleNamespace(cached_tokens=70, cache_write_tokens=11),
        output_tokens=45,
        output_tokens_details=SimpleNamespace(reasoning_tokens=30),
        total_tokens=165,
    )


def _responses_response(
    *content: SimpleNamespace,
    status: str | None = "completed",
    incomplete_reason: str | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        id="resp_test",
        model="test-model-2026-07-21",
        status=status,
        incomplete_details=(
            SimpleNamespace(reason=incomplete_reason) if incomplete_reason else None
        ),
        output=[
            SimpleNamespace(type="reasoning"),
            SimpleNamespace(type="message", content=list(content)),
        ],
        usage=_responses_usage(),
    )


def _responses_provider(
    monkeypatch: pytest.MonkeyPatch, response: object
) -> tuple[OpenAIResponsesProvider, Mock, Mock]:
    client = Mock()
    client.responses.parse.return_value = response
    constructor = Mock(return_value=client)
    monkeypatch.setattr(providers, "OpenAI", constructor)
    return OpenAIResponsesProvider(_profile(monkeypatch)), client, constructor


def _chat_usage() -> SimpleNamespace:
    return SimpleNamespace(
        prompt_tokens=80,
        prompt_tokens_details=SimpleNamespace(cached_tokens=25, cache_write_tokens=9),
        completion_tokens=20,
        completion_tokens_details=SimpleNamespace(reasoning_tokens=12),
        total_tokens=100,
    )


def _chat_response(
    *,
    content: str | None = '{"accepted": true, "summary": "ready"}',
    refusal: str | None = None,
    finish_reason: str | None = "stop",
    choices: int = 1,
) -> SimpleNamespace:
    choice = SimpleNamespace(
        finish_reason=finish_reason,
        message=SimpleNamespace(content=content, refusal=refusal),
    )
    return SimpleNamespace(
        id="chat_test",
        model="compatible-model-v1",
        choices=[choice] * choices,
        usage=_chat_usage(),
    )


def _compatible_provider(
    monkeypatch: pytest.MonkeyPatch, response: object
) -> tuple[OpenAICompatibleProvider, Mock, Mock]:
    client = Mock()
    client.chat.completions.create.return_value = response
    constructor = Mock(return_value=client)
    monkeypatch.setattr(providers, "OpenAI", constructor)
    return OpenAICompatibleProvider(_profile(monkeypatch, compatible=True)), client, constructor


def test_responses_provider_parses_one_output_and_maps_detailed_usage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = Verdict(accepted=True, summary="well scoped")
    response = _responses_response(SimpleNamespace(type="output_text", parsed=expected))
    provider, client, constructor = _responses_provider(monkeypatch, response)

    result = provider.generate(
        instructions="Return a strict verdict.",
        prompt="Review the patch.",
        output_type=Verdict,
    )

    assert result.output == expected
    assert result.response_id == "resp_test"
    assert result.model == "test-model-2026-07-21"
    assert result.usage == ModelUsage(
        input_tokens=120,
        cached_input_tokens=70,
        cache_write_tokens=11,
        output_tokens=45,
        reasoning_tokens=30,
        total_tokens=165,
    )
    constructor.assert_called_once_with(
        api_key=_API_KEY,
        base_url=None,
        timeout=900.0,
        max_retries=2,
    )
    client.responses.parse.assert_called_once_with(
        model="test-model",
        instructions="Return a strict verdict.",
        input="Review the patch.",
        reasoning={"effort": "high", "mode": "pro"},
        text_format=Verdict,
        max_output_tokens=40_000,
        store=False,
    )


def test_responses_provider_rejects_refusal_even_after_parsed_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _responses_response(
        SimpleNamespace(
            type="output_text",
            parsed=Verdict(accepted=True, summary="must not be returned"),
        ),
        SimpleNamespace(type="refusal", refusal="I cannot assess this request"),
    )
    provider, _, _ = _responses_provider(monkeypatch, response)

    with pytest.raises(ModelError, match=r"refused.*cannot assess"):
        provider.generate(instructions="Review.", prompt="Patch.", output_type=Verdict)


def test_responses_provider_rejects_incomplete_response_with_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _responses_response(status="incomplete", incomplete_reason="max_output_tokens")
    provider, _, _ = _responses_provider(monkeypatch, response)

    with pytest.raises(ModelError, match="incomplete: max_output_tokens"):
        provider.generate(instructions="Review.", prompt="Patch.", output_type=Verdict)


@pytest.mark.parametrize("status", [None, "failed", "queued", "cancelled"])
def test_responses_provider_rejects_every_non_completed_status(
    monkeypatch: pytest.MonkeyPatch, status: str | None
) -> None:
    response = _responses_response(status=status)
    provider, _, _ = _responses_provider(monkeypatch, response)

    with pytest.raises(ModelError, match="did not complete"):
        provider.generate(instructions="Review.", prompt="Patch.", output_type=Verdict)


def test_responses_provider_rejects_multiple_parsed_outputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _responses_response(
        SimpleNamespace(type="output_text", parsed=Verdict(accepted=True, summary="first")),
        SimpleNamespace(type="output_text", parsed=Verdict(accepted=False, summary="second")),
    )
    provider, _, _ = _responses_provider(monkeypatch, response)

    with pytest.raises(ModelError, match="multiple schema-conforming outputs"):
        provider.generate(instructions="Review.", prompt="Patch.", output_type=Verdict)


def test_responses_provider_rejects_unexpected_parsed_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _responses_response(
        SimpleNamespace(type="output_text", parsed={"accepted": True, "summary": "unsafe"})
    )
    provider, _, _ = _responses_provider(monkeypatch, response)

    with pytest.raises(ModelError, match="unexpected parsed output type"):
        provider.generate(instructions="Review.", prompt="Patch.", output_type=Verdict)


@pytest.mark.parametrize("compatible", [False, True])
def test_provider_requires_key_before_constructing_sdk_client(
    monkeypatch: pytest.MonkeyPatch, compatible: bool
) -> None:
    profile = _profile(monkeypatch, compatible=compatible)
    monkeypatch.delenv(_API_KEY_ENV)
    constructor = Mock()
    monkeypatch.setattr(providers, "OpenAI", constructor)
    provider_type = OpenAICompatibleProvider if compatible else OpenAIResponsesProvider

    with pytest.raises(ConfigurationError, match=_API_KEY_ENV):
        provider_type(profile)

    constructor.assert_not_called()


def test_provider_request_error_does_not_echo_sensitive_provider_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _responses_response(
        SimpleNamespace(type="output_text", parsed=Verdict(accepted=True, summary="not reached"))
    )
    provider, client, _ = _responses_provider(monkeypatch, response)
    failure = RuntimeError(f"request body contained {_API_KEY} and private prompt")
    failure.request_id = "req_safe_to_log"  # type: ignore[attr-defined]
    client.responses.parse.side_effect = failure

    with pytest.raises(ModelError) as raised:
        provider.generate(instructions="Private.", prompt="Secret.", output_type=Verdict)

    assert str(raised.value) == "OpenAI Responses request failed (request ID: req_safe_to_log)"
    assert _API_KEY not in str(raised.value)
    assert "private prompt" not in str(raised.value)


@pytest.mark.parametrize("compatible", [False, True])
def test_provider_scrubs_sensitive_text_immediately_before_request(
    monkeypatch: pytest.MonkeyPatch, compatible: bool
) -> None:
    environment_secret = "provider-bound-secret-729384"
    monkeypatch.setenv("AUTOCONTRIBUTE_SECONDARY_SECRET", environment_secret)
    provider: OpenAICompatibleProvider | OpenAIResponsesProvider
    if compatible:
        provider, client, _ = _compatible_provider(monkeypatch, _chat_response())
    else:
        parsed = Verdict(accepted=True, summary="ready")
        response = _responses_response(SimpleNamespace(type="output_text", parsed=parsed))
        provider, client, _ = _responses_provider(monkeypatch, response)

    provider.generate(
        instructions=f"Do not reveal {_API_KEY}.",
        prompt=(
            f"environment = {environment_secret}\n"
            "Authorization: Bearer opaqueBearerValue123456789\n"
            "token = ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ\n"
            'password = "example-placeholder-value"'
        ),
        output_type=Verdict,
    )

    if compatible:
        messages = client.chat.completions.create.call_args.kwargs["messages"]
        sent_instructions = messages[0]["content"]
        sent_prompt = messages[1]["content"]
    else:
        request = client.responses.parse.call_args.kwargs
        sent_instructions = request["instructions"]
        sent_prompt = request["input"]
    assert _API_KEY not in sent_instructions
    assert environment_secret not in sent_prompt
    assert "opaqueBearerValue123456789" not in sent_prompt
    assert "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ" not in sent_prompt
    assert MODEL_INPUT_REDACTION in sent_instructions
    assert 'password = "example-placeholder-value"' in sent_prompt


def test_compatible_provider_validates_json_and_maps_usage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider, client, constructor = _compatible_provider(monkeypatch, _chat_response())

    result = provider.generate(
        instructions="Return a strict verdict.",
        prompt="Review the patch.",
        output_type=Verdict,
    )

    assert result.output == Verdict(accepted=True, summary="ready")
    assert result.response_id == "chat_test"
    assert result.model == "compatible-model-v1"
    assert result.usage == ModelUsage(
        input_tokens=80,
        cached_input_tokens=25,
        cache_write_tokens=9,
        output_tokens=20,
        reasoning_tokens=12,
        total_tokens=100,
    )
    constructor.assert_called_once_with(
        api_key=_API_KEY,
        base_url="https://models.example.test/v1",
        timeout=900.0,
        max_retries=2,
    )
    request = client.chat.completions.create.call_args.kwargs
    assert request["messages"] == [
        {"role": "system", "content": "Return a strict verdict."},
        {"role": "user", "content": "Review the patch."},
    ]
    assert request["response_format"] == {
        "type": "json_schema",
        "json_schema": {
            "name": "verdict",
            "strict": True,
            "schema": Verdict.model_json_schema(),
        },
    }
    assert request["reasoning_effort"] == "high"


def test_compatible_provider_rejects_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    provider, _, _ = _compatible_provider(
        monkeypatch,
        _chat_response(content=None, refusal="cannot comply"),
    )

    with pytest.raises(ModelError, match=r"refused.*cannot comply"):
        provider.generate(instructions="Review.", prompt="Patch.", output_type=Verdict)


@pytest.mark.parametrize("finish_reason", [None, "length", "content_filter", "tool_calls"])
def test_compatible_provider_rejects_non_stop_finish_reason(
    monkeypatch: pytest.MonkeyPatch, finish_reason: str | None
) -> None:
    provider, _, _ = _compatible_provider(
        monkeypatch,
        _chat_response(finish_reason=finish_reason),
    )

    with pytest.raises(ModelError, match="did not complete"):
        provider.generate(instructions="Review.", prompt="Patch.", output_type=Verdict)


@pytest.mark.parametrize(
    "response",
    [
        _chat_response(content="not-json"),
        _chat_response(content='{"accepted": true}'),
        _chat_response(choices=0),
        _chat_response(choices=2),
    ],
)
def test_compatible_provider_rejects_invalid_or_ambiguous_output(
    monkeypatch: pytest.MonkeyPatch, response: SimpleNamespace
) -> None:
    provider, _, _ = _compatible_provider(monkeypatch, response)

    with pytest.raises(ModelError):
        provider.generate(instructions="Review.", prompt="Patch.", output_type=Verdict)


def test_invalid_usage_is_not_silently_underreported(monkeypatch: pytest.MonkeyPatch) -> None:
    response = _responses_response(
        SimpleNamespace(type="output_text", parsed=Verdict(accepted=True, summary="valid output"))
    )
    response.usage.output_tokens = -1
    provider, _, _ = _responses_provider(monkeypatch, response)

    with pytest.raises(ModelError, match="invalid usage field: output_tokens"):
        provider.generate(instructions="Review.", prompt="Patch.", output_type=Verdict)
