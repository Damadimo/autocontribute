"""OpenAI SDK adapters. Only the model worker imports this module.

The parent process holds the GitHub token, so third-party SDK code runs in the worker alone.
"""

from __future__ import annotations

import json
from typing import Final, cast

from openai import APIStatusError, OpenAI
from openai.types.responses import Response, ResponseError, ResponseInputParam, ToolParam
from openai.types.shared_params import Reasoning
from pydantic import JsonValue, ValidationError

from autocontribute.config import ModelProfile
from autocontribute.exceptions import ModelError, ModelRequestError
from autocontribute.model_retry import PROVIDER_ERROR_CODES, retry_after_seconds
from autocontribute.pricing import API_KEY_ENVS, ModelUsage
from autocontribute.providers import (
    ModelProvider,
    ModelResult,
    OutputT,
    TurnRequest,
    _assert_secret_free_model_output,
    _effective_output_tokens,
    _effective_timeout,
    _require_api_key,
    _require_expected_response_model,
    _response_identity,
    _safe_request_id,
    _scrub_request_text,
    _token_count,
    _validate_usage,
)
from autocontribute.transcript import (
    NATIVE_CALL_NAMES,
    SUBMIT_TOOLS,
    ToolCall,
    TranscriptKind,
    Turn,
    tool_definitions,
)

# Retries must remain visible to the orchestrator so every potentially billable
# request receives its own durable budget reservation.  The SDK otherwise
# retries selected failures internally, outside Autocontribute's hard limits.
_SDK_MAX_RETRIES = 0
_SAFE_INCOMPLETE_REASONS: frozenset[str] = frozenset({"content_filter", "max_output_tokens"})
# Codes of failed responses that another attempt can fix.
_RETRIABLE_FAILURE_CODES: Final = frozenset({"server_error", "rate_limit_exceeded"})
# Codes of failed responses that end the run and may be named in its error; other codes are not
# echoed. Safety stops in PROVIDER_ERROR_CODES are named too and also reach retry decisions.
_NAMED_FAILURE_CODES: Final = frozenset(
    {
        "invalid_prompt",
        "bio_policy",
        "potentially_unintended_data_transfer",
        "potentially_unintended_data_access",
        "potentially_unintended_destructive_activity",
    }
)


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

    request_id = _safe_request_id(
        getattr(exc, "request_id", None), api_key_env=api_key_env, api_key=api_key
    )
    if request_id is not None:
        details.append(f"request ID: {request_id}")
    detail_suffix = f" ({'; '.join(details)})" if details else ""
    return ModelRequestError(
        f"{provider} request failed{detail_suffix}",
        status_code=http_status,
        provider_code=provider_code,
        retry_after_seconds=retry_after,
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


def step(request: TurnRequest) -> Turn:
    """Send one transcript request to the Responses API and normalize the response."""

    api_key_env = API_KEY_ENVS["openai"]
    api_key = _require_api_key(api_key_env)
    client = OpenAI(api_key=api_key, max_retries=_SDK_MAX_RETRIES)
    try:
        response = client.responses.create(
            model=request.spec.id,
            instructions=request.instructions,
            input=cast("ResponseInputParam", request.items),
            tools=cast("list[ToolParam]", tool_definitions("openai", request.kind)),
            tool_choice="auto",
            parallel_tool_calls=True,
            reasoning={"effort": request.effort},
            store=False,
            include=["reasoning.encrypted_content"],
            max_output_tokens=request.max_output_tokens,
            truncation="disabled",
            prompt_cache_key=f"ac:{request.run_id}:{request.kind}",
            timeout=request.timeout_seconds,
        )
    except Exception as exc:
        raise _request_error(
            "OpenAI Responses",
            exc,
            api_key_env=api_key_env,
            api_key=api_key,
        ) from None
    finally:
        client.close()
    return _turn(response, kind=request.kind)


def _turn(response: Response, *, kind: TranscriptKind) -> Turn:
    # A response that failed before generating anything can come without usage.
    if response.status == "failed":
        raise _failure(response.error)
    response_id, model = _response_identity(response)
    usage = _responses_usage(response.usage)
    if response.status == "incomplete":
        reason = getattr(response.incomplete_details, "reason", None)
        if reason == "max_output_tokens":
            # Partial calls must not run: the caller re-sends the same input with more room.
            return Turn(
                stop="max_output_tokens",
                output_items=(),
                tool_calls=(),
                response_id=response_id,
                model=model,
                usage=usage,
            )
        if reason in _SAFE_INCOMPLETE_REASONS:
            raise ModelError(f"Model response was incomplete: {reason}")
        raise ModelError("Model response did not complete")
    if response.status != "completed":
        raise ModelError("Model response did not complete")
    output_items: list[dict[str, JsonValue]] = []
    tool_calls: list[ToolCall] = []
    try:
        for output in response.output:
            item = output.model_dump(mode="json", exclude_none=True)
            # Output-only field: input items have no created_by.
            item.pop("created_by", None)
            call = _tool_call(item, kind)
            if call is not None:
                tool_calls.append(call)
            output_items.append(item)
        return Turn(
            stop="tool_use" if tool_calls else "end_turn",
            output_items=tuple(output_items),
            tool_calls=tuple(tool_calls),
            response_id=response_id,
            model=model,
            usage=usage,
        )
    except ValidationError as exc:
        raise ModelError("Model response contained an invalid tool call") from exc


def _tool_call(item: dict[str, JsonValue], kind: TranscriptKind) -> ToolCall | None:
    item_type = item.get("type")
    if item_type == "reasoning":
        return None
    if item_type == "message":
        content = item.get("content")
        if isinstance(content, list) and any(
            isinstance(part, dict) and part.get("type") == "refusal" for part in content
        ):
            raise ModelError("Model refused the request")
        return None
    if item_type == "shell_call":
        return ToolCall.model_validate(
            {
                "call_id": item.get("call_id"),
                "name": NATIVE_CALL_NAMES["openai"]["shell"],
                "arguments": item.get("action"),
            }
        )
    if item_type == "apply_patch_call":
        return ToolCall.model_validate(
            {
                "call_id": item.get("call_id"),
                "name": NATIVE_CALL_NAMES["openai"]["edit"],
                "arguments": item.get("operation"),
            }
        )
    if item_type == "function_call":
        submit_name = SUBMIT_TOOLS[kind].name
        if item.get("name") != submit_name:
            raise ModelError("Model called a function outside its tool set")
        return ToolCall.model_validate(
            {
                "call_id": item.get("call_id"),
                "name": submit_name,
                "arguments": _function_arguments(item.get("arguments")),
            }
        )
    raise ModelError("Model response contained an unsupported output item")


def _function_arguments(raw: JsonValue) -> dict[str, JsonValue]:
    try:
        arguments = json.loads(raw) if isinstance(raw, str) else None
    except json.JSONDecodeError:
        arguments = None
    if not isinstance(arguments, dict):
        raise ModelError("Model returned function arguments that are not a JSON object")
    return arguments


def _failure(error: ResponseError | None) -> ModelError:
    code = getattr(error, "code", None)
    if code in _RETRIABLE_FAILURE_CODES:
        return ModelRequestError(f"Model response failed (code: {code})")
    if code in PROVIDER_ERROR_CODES:
        return ModelRequestError(f"Model response failed (code: {code})", provider_code=code)
    if code in _NAMED_FAILURE_CODES:
        return ModelError(f"Model response failed (code: {code})")
    return ModelError("Model response failed")


def _create_in_process_provider(profile: ModelProfile) -> ModelProvider:
    if profile.provider == "openai":
        return OpenAIResponsesProvider(profile)
    if profile.provider == "openai_compatible":
        return OpenAICompatibleProvider(profile)
    raise ModelError(f"Unsupported model provider: {profile.provider}")


__all__ = [
    "OpenAICompatibleProvider",
    "OpenAIResponsesProvider",
    "step",
]
