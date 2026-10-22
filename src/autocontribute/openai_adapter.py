"""OpenAI SDK adapters. Only the model worker imports this module.

The parent process holds the GitHub token, so third-party SDK code runs in the worker alone.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator

from openai import APIStatusError, OpenAI
from openai.types.shared_params import Reasoning
from pydantic import BaseModel, ValidationError

from autocontribute.config import ModelProfile, validate_model_identifier
from autocontribute.exceptions import ModelError, ModelRequestError
from autocontribute.model_retry import PROVIDER_ERROR_CODES, retry_after_seconds
from autocontribute.pricing import ModelUsage
from autocontribute.providers import (
    ModelProvider,
    ModelResult,
    OutputT,
    _effective_output_tokens,
    _effective_timeout,
    _require_expected_response_model,
    _scrub_request_text,
    _validate_usage,
)
from autocontribute.redaction import redact_model_input

# Retries must remain visible to the orchestrator so every potentially billable
# request receives its own durable budget reservation.  The SDK otherwise
# retries selected failures internally, outside Autocontribute's hard limits.
_SDK_MAX_RETRIES = 0
_SAFE_INCOMPLETE_REASONS: frozenset[str] = frozenset({"content_filter", "max_output_tokens"})
_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


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


def _request_error(
    provider: str,
    exc: Exception,
    *,
    api_key_env: str,
    api_key: str,
) -> ModelRequestError:
    """Create a useful error without echoing provider bodies, prompts, or credentials.

    Preserve only a numeric status, an allowlisted error code and the Retry-After wait from a
    genuine OpenAI SDK HTTP exception. All other response-body fields remain intentionally
    unavailable because a compatible endpoint can place arbitrary prompt or credential material
    in otherwise token-shaped error metadata.
    """

    details: list[str] = []
    http_status: int | None = None
    provider_code: str | None = None
    retry_after: float | None = None
    if isinstance(exc, APIStatusError):
        status_code = getattr(exc, "status_code", None)
        if type(status_code) is int and 400 <= status_code <= 599:
            http_status = status_code
            details.append(f"HTTP {status_code}")
        # Billing errors can carry a specific code while their type stays insufficient_quota.
        for candidate in (getattr(exc, "code", None), getattr(exc, "type", None)):
            if isinstance(candidate, str) and candidate in PROVIDER_ERROR_CODES:
                provider_code = candidate
                details.append(f"code: {candidate}")
                break
        retry_after = retry_after_seconds(exc.response.headers)

    request_id = getattr(exc, "request_id", None)
    if isinstance(request_id, str) and _SAFE_REQUEST_ID.fullmatch(request_id):
        try:
            _assert_secret_free_model_output(api_key_env, api_key, request_id)
        except ModelError:
            pass
        else:
            details.append(f"request ID: {request_id}")
    detail_suffix = f" ({'; '.join(details)})" if details else ""
    return ModelRequestError(
        f"{provider} request failed{detail_suffix}",
        status_code=http_status,
        provider_code=provider_code,
        retry_after_seconds=retry_after,
    )


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
    api_key_env: str,
    api_key: str,
    *values: object,
) -> None:
    """Reject credential reflection without returning or logging the reflected value."""

    for value in values:
        for text in _model_output_strings(value):
            if api_key in text or redact_model_input(text, secret_env_names=(api_key_env,)) != text:
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
                api_key_env=self.profile.api_key_env,
                api_key=self._api_key,
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
        _assert_secret_free_model_output(self.profile.api_key_env, self._api_key, *boundary_values)

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
        _require_expected_response_model(self.profile, model)
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
                api_key_env=self.profile.api_key_env,
                api_key=self._api_key,
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
        _assert_secret_free_model_output(self.profile.api_key_env, self._api_key, *boundary_values)
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
        _require_expected_response_model(self.profile, model)
        return ModelResult(
            output=parsed,
            response_id=response_id,
            model=model,
            usage=_chat_usage(getattr(response, "usage", None)),
        )


def _create_in_process_provider(profile: ModelProfile) -> ModelProvider:
    if profile.provider == "openai":
        return OpenAIResponsesProvider(profile)
    if profile.provider == "openai_compatible":
        return OpenAICompatibleProvider(profile)
    raise ModelError(f"Unsupported model provider: {profile.provider}")


__all__ = [
    "OpenAICompatibleProvider",
    "OpenAIResponsesProvider",
]
