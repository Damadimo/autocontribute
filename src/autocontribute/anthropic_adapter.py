"""Anthropic Messages API adapter. Only the model worker imports this module.

The parent process holds the GitHub token, so third-party SDK code runs in the worker alone.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final, cast

from anthropic import Anthropic, APIStatusError
from anthropic.types import Message, MessageParam, RefusalStopDetails, ToolUnionParam, Usage
from pydantic import JsonValue, ValidationError

from autocontribute.exceptions import ModelError, ModelRequestError
from autocontribute.model_retry import retry_after_seconds
from autocontribute.pricing import API_KEY_ENVS, ModelUsage
from autocontribute.providers import (
    TurnRequest,
    _require_api_key,
    _response_identity,
    _safe_request_id,
    _token_count,
    _validate_usage,
)
from autocontribute.transcript import (
    SUBMIT_TOOLS,
    ToolCall,
    TranscriptKind,
    Turn,
    tool_call_names,
    tool_definitions,
)

# Retries stay with the orchestrator, so every billable attempt gets its own reservation.
_SDK_MAX_RETRIES: Final = 0
# The names the shell and edit tools are declared with, and the names their calls carry.
_CALL_NAMES: Final[Mapping[str, str]] = MappingProxyType(
    {"bash": "shell", "str_replace_based_edit_tool": "edit"}
)
_CONTENT_BLOCK_TYPES: Final = frozenset({"text", "thinking", "redacted_thinking", "tool_use"})
# Refusal categories that may be named in the run's error; other values are not echoed.
_REFUSAL_CATEGORIES: Final = frozenset(
    {"cyber", "bio", "frontier_llm", "reasoning_extraction", "general_harms"}
)
# The status each error type is documented with. An error event inside a stream arrives on the
# stream's 200 response, so its type is the only sign of how the request failed.
_ERROR_TYPE_STATUSES: Final[Mapping[str, int]] = MappingProxyType(
    {
        "invalid_request_error": 400,
        "authentication_error": 401,
        "billing_error": 402,
        "permission_error": 403,
        "not_found_error": 404,
        "request_too_large": 413,
        "rate_limit_error": 429,
        "api_error": 500,
        "timeout_error": 504,
        "overloaded_error": 529,
    }
)


def step(request: TurnRequest) -> Turn:
    """Send one transcript request to the Messages API and normalize the response."""

    api_key_env = API_KEY_ENVS["anthropic"]
    api_key = _require_api_key(api_key_env)
    client = Anthropic(api_key=api_key, max_retries=_SDK_MAX_RETRIES)
    try:
        # Streamed because the SDK refuses a plain request whose output cap could outlast the
        # connection.
        with client.messages.stream(
            model=request.spec.id,
            # This breakpoint caches the tools and the instructions, which never change; the
            # top-level one follows the end of the growing transcript.
            system=[
                {
                    "type": "text",
                    "text": request.instructions,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=cast("list[MessageParam]", request.items),
            tools=cast("list[ToolUnionParam]", tool_definitions("anthropic", request.kind)),
            max_tokens=request.max_output_tokens,
            output_config={"effort": request.effort},
            cache_control={"type": "ephemeral"},
            timeout=request.timeout_seconds,
        ) as stream:
            message = stream.get_final_message()
    except Exception as exc:
        raise _request_error(exc, api_key_env=api_key_env, api_key=api_key) from None
    finally:
        client.close()
    return _turn(message, kind=request.kind)


def _turn(message: Message, *, kind: TranscriptKind) -> Turn:
    response_id, model = _response_identity(message)
    usage = _messages_usage(message.usage)
    stop_reason = message.stop_reason
    if stop_reason == "max_tokens":
        # Partial calls must not run: the caller re-sends the same input with more room.
        return Turn(
            stop="max_output_tokens",
            output_items=(),
            tool_calls=(),
            response_id=response_id,
            model=model,
            usage=usage,
        )
    if stop_reason == "refusal":
        raise _refusal(message.stop_details)
    if stop_reason == "pause_turn":
        # Only server tools pause a turn, and no transcript declares one.
        raise ModelError("Model provider paused a turn without server tools")
    if stop_reason == "model_context_window_exceeded":
        raise ModelError("Model response did not complete: model_context_window_exceeded")
    if stop_reason not in ("tool_use", "end_turn"):
        raise ModelError("Model response did not complete")
    output_items: list[dict[str, JsonValue]] = []
    tool_calls: list[ToolCall] = []
    try:
        for block in message.content:
            if block.type not in _CONTENT_BLOCK_TYPES:
                raise ModelError("Model response contained an unsupported content block")
            if block.type == "tool_use":
                tool_calls.append(
                    ToolCall.model_validate(
                        {
                            "call_id": block.id,
                            "name": _call_name(block.name, kind),
                            "arguments": block.input,
                        }
                    )
                )
            # Dumped as the SDK sends a content block back, so thinking signatures and every
            # other field are replayed exactly as received.
            output_items.append(block.model_dump(mode="json", exclude_unset=True, by_alias=True))
    except ValidationError as exc:
        raise ModelError("Model response contained an invalid tool call") from exc
    if not output_items:
        # The API rejects an empty assistant message, so this turn could never be replayed.
        raise ModelError("Model returned an empty response")
    if (stop_reason == "tool_use") != bool(tool_calls):
        raise ModelError("Model response stop reason does not match its tool calls")
    return Turn(
        stop="tool_use" if tool_calls else "end_turn",
        output_items=tuple(output_items),
        tool_calls=tuple(tool_calls),
        response_id=response_id,
        model=model,
        usage=usage,
    )


def _call_name(declared: str, kind: TranscriptKind) -> str:
    submit_name = SUBMIT_TOOLS[kind].name
    name = submit_name if declared == submit_name else _CALL_NAMES.get(declared)
    if name not in tool_call_names("anthropic", kind):
        raise ModelError("Model called a tool outside its tool set")
    return name


def _messages_usage(raw_usage: Usage) -> ModelUsage:
    # input_tokens counts only the tokens after the last cache breakpoint.
    uncached = _token_count(raw_usage, "input_tokens", required=True)
    cache_write = _token_count(raw_usage, "cache_creation_input_tokens")
    cached = _token_count(raw_usage, "cache_read_input_tokens")
    output = _token_count(raw_usage, "output_tokens", required=True)
    input_tokens = uncached + cache_write + cached
    return _validate_usage(
        ModelUsage(
            input_tokens=input_tokens,
            cached_input_tokens=cached,
            cache_write_tokens=cache_write,
            output_tokens=output,
            reasoning_tokens=0,
            total_tokens=input_tokens + output,
        )
    )


def _refusal(details: RefusalStopDetails | None) -> ModelError:
    # The explanation is provider free text and is never echoed.
    category = getattr(details, "category", None)
    if category in _REFUSAL_CATEGORIES:
        return ModelError(f"Model refused the request (category: {category})")
    return ModelError("Model refused the request")


def _request_error(exc: Exception, *, api_key_env: str, api_key: str) -> ModelRequestError:
    """Keep the HTTP status, the Retry-After wait and a safe request ID, never the error body."""

    details: list[str] = []
    http_status: int | None = None
    retry_after: float | None = None
    if isinstance(exc, APIStatusError):
        status_code = exc.status_code
        if type(status_code) is int and 400 <= status_code <= 599:
            http_status = status_code
        else:
            http_status = _ERROR_TYPE_STATUSES.get(exc.type or "")
        if http_status is not None:
            details.append(f"HTTP {http_status}")
        retry_after = retry_after_seconds(exc.response.headers)
    request_id = _safe_request_id(
        getattr(exc, "request_id", None), api_key_env=api_key_env, api_key=api_key
    )
    if request_id is not None:
        details.append(f"request ID: {request_id}")
    detail_suffix = f" ({'; '.join(details)})" if details else ""
    return ModelRequestError(
        f"Anthropic Messages request failed{detail_suffix}",
        status_code=http_status,
        retry_after_seconds=retry_after,
    )


__all__ = ["step"]
