"""Model-provider boundary with strict, typed outputs and no tool side effects."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Generic, Protocol, TypeVar

from openai import OpenAI
from openai.types.shared_params import Reasoning
from pydantic import BaseModel, ValidationError

from autocontribute.config import ModelProfile
from autocontribute.exceptions import ModelError

OutputT = TypeVar("OutputT", bound=BaseModel)


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
    ) -> ModelResult[OutputT]: ...


def _token_count(container: object | None, field: str) -> int:
    """Read a non-negative SDK token count without silently accepting bad data."""

    if container is None:
        return 0
    value = getattr(container, field, None)
    if value is None:
        return 0
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ModelError(f"Model provider returned invalid usage field: {field}")
    return int(value)


def _responses_usage(raw_usage: object | None) -> ModelUsage:
    input_details = getattr(raw_usage, "input_tokens_details", None)
    output_details = getattr(raw_usage, "output_tokens_details", None)
    return ModelUsage(
        input_tokens=_token_count(raw_usage, "input_tokens"),
        cached_input_tokens=_token_count(input_details, "cached_tokens"),
        cache_write_tokens=_token_count(input_details, "cache_write_tokens"),
        output_tokens=_token_count(raw_usage, "output_tokens"),
        reasoning_tokens=_token_count(output_details, "reasoning_tokens"),
        total_tokens=_token_count(raw_usage, "total_tokens"),
    )


def _chat_usage(raw_usage: object | None) -> ModelUsage:
    prompt_details = getattr(raw_usage, "prompt_tokens_details", None)
    completion_details = getattr(raw_usage, "completion_tokens_details", None)
    return ModelUsage(
        input_tokens=_token_count(raw_usage, "prompt_tokens"),
        cached_input_tokens=_token_count(prompt_details, "cached_tokens"),
        cache_write_tokens=_token_count(prompt_details, "cache_write_tokens"),
        output_tokens=_token_count(raw_usage, "completion_tokens"),
        reasoning_tokens=_token_count(completion_details, "reasoning_tokens"),
        total_tokens=_token_count(raw_usage, "total_tokens"),
    )


def _request_error(provider: str, exc: Exception) -> ModelError:
    """Create a useful error without echoing provider bodies, prompts, or credentials."""

    request_id = getattr(exc, "request_id", None)
    request_suffix = f" (request ID: {request_id})" if isinstance(request_id, str) else ""
    return ModelError(f"{provider} request failed{request_suffix}")


def _response_identity(response: object) -> tuple[str, str]:
    response_id = getattr(response, "id", None)
    model = getattr(response, "model", None)
    if not isinstance(response_id, str) or not response_id:
        raise ModelError("Model provider returned no response identifier")
    if not isinstance(model, str) or not model:
        raise ModelError("Model provider returned no model identifier")
    return response_id, model


class OpenAIResponsesProvider:
    """Official Responses API adapter, optimized for current reasoning models."""

    def __init__(self, profile: ModelProfile) -> None:
        self.profile = profile
        self.client = OpenAI(
            api_key=profile.require_api_key(),
            base_url=str(profile.base_url) if profile.base_url else None,
            timeout=profile.timeout_seconds,
            max_retries=2,
        )

    def generate(
        self,
        *,
        instructions: str,
        prompt: str,
        output_type: type[OutputT],
    ) -> ModelResult[OutputT]:
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
                max_output_tokens=self.profile.max_output_tokens,
                store=False,
            )
        except Exception as exc:
            raise _request_error("OpenAI Responses", exc) from exc

        status = getattr(response, "status", None)
        if status != "completed":
            details = getattr(response, "incomplete_details", None)
            reason = getattr(details, "reason", None)
            if status == "incomplete" and isinstance(reason, str):
                raise ModelError(f"Model response was incomplete: {reason}")
            status_text = status if isinstance(status, str) else "missing"
            raise ModelError(f"Model response did not complete (status: {status_text})")

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
        self.client = OpenAI(
            api_key=profile.require_api_key(),
            base_url=str(profile.base_url),
            timeout=profile.timeout_seconds,
            max_retries=2,
        )

    def generate(
        self,
        *,
        instructions: str,
        prompt: str,
        output_type: type[OutputT],
    ) -> ModelResult[OutputT]:
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
                max_completion_tokens=self.profile.max_output_tokens,
                reasoning_effort=self.profile.reasoning_effort,
            )
        except Exception as exc:
            raise _request_error("OpenAI-compatible", exc) from exc

        choices = list(response.choices)
        if len(choices) != 1:
            raise ModelError("Compatible provider returned an unexpected number of choices")
        choice = choices[0]
        message = choice.message
        refusal = getattr(message, "refusal", None)
        if refusal:
            raise ModelError(f"Model refused the request: {refusal}")
        finish_reason = getattr(choice, "finish_reason", None)
        if finish_reason != "stop":
            reason_text = finish_reason if isinstance(finish_reason, str) else "missing"
            raise ModelError(
                f"Compatible provider response did not complete (finish reason: {reason_text})"
            )
        if not isinstance(message.content, str):
            raise ModelError("Compatible provider returned no JSON text")
        try:
            parsed = output_type.model_validate(json.loads(message.content))
        except (json.JSONDecodeError, ValidationError) as exc:
            raise ModelError("Compatible provider returned invalid structured output") from exc

        response_id, model = _response_identity(response)
        return ModelResult(
            output=parsed,
            response_id=response_id,
            model=model,
            usage=_chat_usage(getattr(response, "usage", None)),
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
