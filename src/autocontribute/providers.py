"""Model-provider boundary with strict, typed outputs and no tool side effects."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Generic, Protocol, TypeVar

from openai import OpenAI
from openai.types.shared_params import Reasoning
from pydantic import BaseModel, ValidationError

from autocontribute.config import ModelProfile, validate_model_identifier
from autocontribute.exceptions import ModelError
from autocontribute.redaction import redact_model_input

OutputT = TypeVar("OutputT", bound=BaseModel)

# Retries must remain visible to the orchestrator so every potentially billable
# request receives its own durable budget reservation.  The SDK otherwise
# retries selected failures internally, outside Autocontribute's hard limits.
_SDK_MAX_RETRIES = 0
_SAFE_INCOMPLETE_REASONS: frozenset[str] = frozenset({"content_filter", "max_output_tokens"})
_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


@dataclass(frozen=True)
class ModelUsage:
    input_tokens: int = 0
    cached_input_tokens: int = 0
    cache_write_tokens: int = 0
    output_tokens: int = 0
    reasoning_tokens: int = 0
    total_tokens: int = 0


@dataclass(frozen=True)
class ModelResult(Generic[OutputT]):
    output: OutputT
    response_id: str
    model: str
    usage: ModelUsage


class ModelProvider(Protocol):
    def generate(
        self,
        *,
        instructions: str,
        prompt: str,
        output_type: type[OutputT],
        max_output_tokens: int | None = None,
        timeout_seconds: float | None = None,
    ) -> ModelResult[OutputT]: ...


def _token_count(container: object | None, field: str, *, required: bool = False) -> int:
    """Read a non-negative SDK token count without silently accepting bad data."""

    if container is None:
        if required:
            raise ModelError(f"Model provider omitted required usage field: {field}")
        return 0
    value = getattr(container, field, None)
    if value is None:
        if required:
            raise ModelError(f"Model provider omitted required usage field: {field}")
        return 0
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ModelError(f"Model provider returned invalid usage field: {field}")
    return int(value)


def _responses_usage(raw_usage: object | None) -> ModelUsage:
    input_details = getattr(raw_usage, "input_tokens_details", None)
    output_details = getattr(raw_usage, "output_tokens_details", None)
    usage = ModelUsage(
        input_tokens=_token_count(raw_usage, "input_tokens", required=True),
        cached_input_tokens=_token_count(input_details, "cached_tokens"),
        cache_write_tokens=_token_count(input_details, "cache_write_tokens"),
        output_tokens=_token_count(raw_usage, "output_tokens", required=True),
        reasoning_tokens=_token_count(output_details, "reasoning_tokens"),
        total_tokens=_token_count(raw_usage, "total_tokens", required=True),
    )
    return _validate_usage(usage)


def _chat_usage(raw_usage: object | None) -> ModelUsage:
    prompt_details = getattr(raw_usage, "prompt_tokens_details", None)
    completion_details = getattr(raw_usage, "completion_tokens_details", None)
    usage = ModelUsage(
        input_tokens=_token_count(raw_usage, "prompt_tokens", required=True),
        cached_input_tokens=_token_count(prompt_details, "cached_tokens"),
        cache_write_tokens=_token_count(prompt_details, "cache_write_tokens"),
        output_tokens=_token_count(raw_usage, "completion_tokens", required=True),
        reasoning_tokens=_token_count(completion_details, "reasoning_tokens"),
        total_tokens=_token_count(raw_usage, "total_tokens", required=True),
    )
    return _validate_usage(usage)


def _validate_usage(usage: ModelUsage) -> ModelUsage:
    if usage.cached_input_tokens + usage.cache_write_tokens > usage.input_tokens:
        raise ModelError("Model provider returned input-token details above input_tokens")
    if usage.reasoning_tokens > usage.output_tokens:
        raise ModelError("Model provider returned reasoning_tokens above output_tokens")
    if usage.total_tokens != usage.input_tokens + usage.output_tokens:
        raise ModelError("Model provider returned inconsistent total_tokens")
    return usage


def _effective_output_tokens(configured: int, requested: int | None) -> int:
    if requested is None:
        return configured
    if isinstance(requested, bool) or not isinstance(requested, int) or requested < 1:
        raise ModelError("Model request output-token limit must be a positive integer")
    return min(configured, requested)


def _effective_timeout(configured: float, requested: float | None) -> float:
    if requested is None:
        return configured
    if (
        isinstance(requested, bool)
        or not isinstance(requested, (int, float))
        or not math.isfinite(requested)
        or requested <= 0
    ):
        raise ModelError("Model request timeout must be positive")
    return min(configured, float(requested))


def _request_error(
    provider: str,
    exc: Exception,
    *,
    profile: ModelProfile,
    configured_api_key: str,
) -> ModelError:
    """Create a useful error without echoing provider bodies, prompts, or credentials."""

    request_id = getattr(exc, "request_id", None)
    safe_request_id: str | None = None
    if isinstance(request_id, str) and _SAFE_REQUEST_ID.fullmatch(request_id):
        try:
            _assert_secret_free_model_output(profile, configured_api_key, request_id)
        except ModelError:
            pass
        else:
            safe_request_id = request_id
    request_suffix = f" (request ID: {safe_request_id})" if safe_request_id is not None else ""
    return ModelError(f"{provider} request failed{request_suffix}")


def _model_output_strings(value: object) -> Iterator[str]:
    """Yield every model-authored string from JSON-like structured output."""

    if isinstance(value, str):
        yield value
        return
    if isinstance(value, BaseModel):
        yield from _model_output_strings(value.model_dump(mode="json"))
        return
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _model_output_strings(key)
            yield from _model_output_strings(item)
        return
    if isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            yield from _model_output_strings(item)


def _assert_secret_free_model_output(
    profile: ModelProfile,
    configured_api_key: str,
    *values: object,
) -> None:
    """Reject credential reflection without returning or logging the reflected value."""

    secret_names = (profile.api_key_env,)
    for value in values:
        for text in _model_output_strings(value):
            if (
                configured_api_key in text
                or redact_model_input(
                    text,
                    secret_env_names=secret_names,
                )
                != text
            ):
                raise ModelError("Model provider response contained credential material")


def _response_identity(response: object) -> tuple[str, str]:
    response_id = getattr(response, "id", None)
    model = getattr(response, "model", None)
    if not isinstance(response_id, str) or not response_id:
        raise ModelError("Model provider returned no response identifier")
    try:
        resolved_model = validate_model_identifier(model)
    except ValueError as exc:
        raise ModelError("Model provider returned an invalid model identifier") from exc
    return response_id, resolved_model


def _require_deployment_model(profile: ModelProfile, model: str) -> None:
    expected = profile.deployment_model
    if expected is not None and model != expected:
        raise ModelError(
            "Model provider resolved a different model ID than the calibrated deployment; "
            "set expected_response_model to the exact provider-returned snapshot and recalibrate"
        )


class OpenAIResponsesProvider:
    """Official Responses API adapter, optimized for current reasoning models."""

    def __init__(self, profile: ModelProfile) -> None:
        self.profile = profile
        self._api_key = profile.require_api_key()
        self.client = OpenAI(
            api_key=self._api_key,
            base_url=str(profile.base_url) if profile.base_url else None,
            timeout=profile.timeout_seconds,
            max_retries=_SDK_MAX_RETRIES,
        )

    def generate(
        self,
        *,
        instructions: str,
        prompt: str,
        output_type: type[OutputT],
        max_output_tokens: int | None = None,
        timeout_seconds: float | None = None,
    ) -> ModelResult[OutputT]:
        instructions, prompt = _scrub_request_text(self.profile, instructions, prompt)
        output_limit = _effective_output_tokens(self.profile.max_output_tokens, max_output_tokens)
        request_timeout = _effective_timeout(self.profile.timeout_seconds, timeout_seconds)
        reasoning: Reasoning = {"effort": self.profile.reasoning_effort}
        if self.profile.reasoning_mode:
            reasoning["mode"] = self.profile.reasoning_mode
        try:
            response = self.client.responses.parse(
                model=self.profile.model,
                instructions=instructions,
                input=prompt,
                reasoning=reasoning,
                text_format=output_type,
                max_output_tokens=output_limit,
                store=False,
                timeout=request_timeout,
            )
        except Exception as exc:
            raise _request_error(
                "OpenAI Responses",
                exc,
                profile=self.profile,
                configured_api_key=self._api_key,
            ) from None

        incomplete_details = getattr(response, "incomplete_details", None)
        incomplete_reason = getattr(incomplete_details, "reason", None)
        boundary_values: list[object] = [
            getattr(response, "id", None),
            getattr(response, "model", None),
            getattr(response, "status", None),
            incomplete_reason,
            getattr(response, "output_text", None),
        ]
        for output in getattr(response, "output", []):
            for item in getattr(output, "content", []):
                boundary_values.extend(
                    (
                        getattr(item, "text", None),
                        getattr(item, "parsed", None),
                        getattr(item, "refusal", None),
                    )
                )
        _assert_secret_free_model_output(self.profile, self._api_key, *boundary_values)

        status = getattr(response, "status", None)
        if status != "completed":
            if status == "incomplete" and incomplete_reason in _SAFE_INCOMPLETE_REASONS:
                raise ModelError(f"Model response was incomplete: {incomplete_reason}")
            raise ModelError("Model response did not complete")

        parsed_candidates: list[OutputT] = []
        for output in response.output:
            if getattr(output, "type", None) != "message":
                continue
            for item in getattr(output, "content", []):
                if getattr(item, "type", None) == "refusal":
                    refusal = getattr(item, "refusal", None)
                    refusal_text = (
                        refusal if isinstance(refusal, str) and refusal else "unspecified"
                    )
                    raise ModelError(f"Model refused the request: {refusal_text}")
                if getattr(item, "type", None) != "output_text":
                    continue
                candidate = getattr(item, "parsed", None)
                if candidate is not None:
                    if not isinstance(candidate, output_type):
                        raise ModelError("Model returned an unexpected parsed output type")
                    parsed_candidates.append(candidate)
        if not parsed_candidates:
            raise ModelError("Model returned no schema-conforming output")
        if len(parsed_candidates) != 1:
            raise ModelError("Model returned multiple schema-conforming outputs")

        response_id, model = _response_identity(response)
        _require_deployment_model(self.profile, model)
        return ModelResult(
            output=parsed_candidates[0],
            response_id=response_id,
            model=model,
            usage=_responses_usage(getattr(response, "usage", None)),
        )


class OpenAICompatibleProvider:
    """Adapter for servers implementing structured Chat Completions."""

    def __init__(self, profile: ModelProfile) -> None:
        self.profile = profile
        self._api_key = profile.require_api_key()
        self.client = OpenAI(
            api_key=self._api_key,
            base_url=str(profile.base_url),
            timeout=profile.timeout_seconds,
            max_retries=_SDK_MAX_RETRIES,
        )

    def generate(
        self,
        *,
        instructions: str,
        prompt: str,
        output_type: type[OutputT],
        max_output_tokens: int | None = None,
        timeout_seconds: float | None = None,
    ) -> ModelResult[OutputT]:
        instructions, prompt = _scrub_request_text(self.profile, instructions, prompt)
        output_limit = _effective_output_tokens(self.profile.max_output_tokens, max_output_tokens)
        request_timeout = _effective_timeout(self.profile.timeout_seconds, timeout_seconds)
        schema = output_type.model_json_schema()
        try:
            response = self.client.chat.completions.create(
                model=self.profile.model,
                messages=[
                    {"role": "system", "content": instructions},
                    {"role": "user", "content": prompt},
                ],
                response_format={
                    "type": "json_schema",
                    "json_schema": {
                        "name": output_type.__name__.lower(),
                        "strict": True,
                        "schema": schema,
                    },
                },
                max_completion_tokens=output_limit,
                reasoning_effort=self.profile.reasoning_effort,
                timeout=request_timeout,
            )
        except Exception as exc:
            raise _request_error(
                "OpenAI-compatible",
                exc,
                profile=self.profile,
                configured_api_key=self._api_key,
            ) from None

        choices = list(response.choices)
        boundary_values = [getattr(response, "id", None), getattr(response, "model", None)]
        for candidate_choice in choices:
            candidate_message = getattr(candidate_choice, "message", None)
            boundary_values.extend(
                (
                    getattr(candidate_choice, "finish_reason", None),
                    getattr(candidate_message, "content", None),
                    getattr(candidate_message, "refusal", None),
                )
            )
        _assert_secret_free_model_output(self.profile, self._api_key, *boundary_values)
        if len(choices) != 1:
            raise ModelError("Compatible provider returned an unexpected number of choices")
        choice = choices[0]
        message = choice.message
        refusal = getattr(message, "refusal", None)
        if refusal:
            refusal_text = refusal if isinstance(refusal, str) else "unspecified"
            raise ModelError(f"Model refused the request: {refusal_text}")
        finish_reason = getattr(choice, "finish_reason", None)
        if finish_reason != "stop":
            raise ModelError("Compatible provider response did not complete")
        if not isinstance(message.content, str):
            raise ModelError("Compatible provider returned no JSON text")
        try:
            parsed = output_type.model_validate(json.loads(message.content))
        except (json.JSONDecodeError, ValidationError) as exc:
            raise ModelError("Compatible provider returned invalid structured output") from exc

        response_id, model = _response_identity(response)
        _require_deployment_model(self.profile, model)
        return ModelResult(
            output=parsed,
            response_id=response_id,
            model=model,
            usage=_chat_usage(getattr(response, "usage", None)),
        )


def _scrub_request_text(profile: ModelProfile, instructions: str, prompt: str) -> tuple[str, str]:
    secret_names = (profile.api_key_env,)
    return (
        redact_model_input(instructions, secret_env_names=secret_names),
        redact_model_input(prompt, secret_env_names=secret_names),
    )


def create_provider(profile: ModelProfile) -> ModelProvider:
    if profile.provider == "openai":
        return OpenAIResponsesProvider(profile)
    if profile.provider == "openai_compatible":
        return OpenAICompatibleProvider(profile)
    raise ModelError(f"Unsupported model provider: {profile.provider}")


__all__ = [
    "ModelProvider",
    "ModelResult",
    "ModelUsage",
    "OpenAICompatibleProvider",
    "OpenAIResponsesProvider",
    "create_provider",
]
