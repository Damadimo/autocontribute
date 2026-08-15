"""Model-provider boundary with strict, typed outputs and no tool side effects."""

from __future__ import annotations

import json
import math
import os
import re
import selectors
import signal
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from contextlib import suppress
from dataclasses import dataclass
from typing import Generic, Literal, Protocol, TypeVar, cast

from openai import APIStatusError, OpenAI
from openai.types.shared_params import Reasoning
from pydantic import BaseModel, ConfigDict, ValidationError

from autocontribute.config import ModelProfile, validate_model_identifier
from autocontribute.domain import ContributionPlan, CriticReview, PatchProposal
from autocontribute.exceptions import ModelError, ModelRequestError, ModelTimeoutError
from autocontribute.redaction import redact_model_input

OutputT = TypeVar("OutputT", bound=BaseModel)

# Retries must remain visible to the orchestrator so every potentially billable
# request receives its own durable budget reservation.  The SDK otherwise
# retries selected failures internally, outside Autocontribute's hard limits.
_SDK_MAX_RETRIES = 0
_SAFE_INCOMPLETE_REASONS: frozenset[str] = frozenset({"content_filter", "max_output_tokens"})
_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MODEL_WORKER_PROTOCOL = "autocontribute.model-call.v1"
_MAX_MODEL_REQUEST_BYTES = 8 * 1024 * 1024
_MAX_MODEL_RESULT_BYTES = 8 * 1024 * 1024
_WORKER_TERM_GRACE_SECONDS = 0.25
_WORKER_POLL_SECONDS = 0.05
_WORKER_ENV_ALLOWLIST = (
    "LANG",
    "LC_ALL",
    "PATH",
    "REQUESTS_CA_BUNDLE",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
)


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


class ModelCapabilityResponse(BaseModel):
    """Allowlisted doctor response shared with the isolated model worker."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["ready"]


_OUTPUT_SCHEMAS: dict[str, type[BaseModel]] = {
    "contribution_plan": ContributionPlan,
    "patch_proposal": PatchProposal,
    "critic_review": CriticReview,
    "model_capability": ModelCapabilityResponse,
}


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
) -> ModelRequestError:
    """Create a useful error without echoing provider bodies, prompts, or credentials.

    Preserve only a numeric status from a genuine OpenAI SDK HTTP exception. All response-body
    fields remain intentionally unavailable because a compatible endpoint can place arbitrary
    prompt or credential material in otherwise token-shaped error metadata.
    """

    details: list[str] = []
    http_status: int | None = None
    if isinstance(exc, APIStatusError):
        status_code = getattr(exc, "status_code", None)
        if type(status_code) is int and 400 <= status_code <= 599:
            http_status = status_code
            details.append(f"HTTP {status_code}")

    request_id = getattr(exc, "request_id", None)
    if isinstance(request_id, str) and _SAFE_REQUEST_ID.fullmatch(request_id):
        try:
            _assert_secret_free_model_output(profile, configured_api_key, request_id)
        except ModelError:
            pass
        else:
            details.append(f"request ID: {request_id}")
    detail_suffix = f" ({'; '.join(details)})" if details else ""
    return ModelRequestError(f"{provider} request failed{detail_suffix}", status_code=http_status)


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


def _output_schema_id(output_type: type[BaseModel]) -> str:
    for schema_id, allowed_type in _OUTPUT_SCHEMAS.items():
        if output_type is allowed_type:
            return schema_id
    raise ModelError("Model request used an output schema outside the production allowlist")


def _output_schema_type(schema_id: str) -> type[BaseModel]:
    output_type = _OUTPUT_SCHEMAS.get(schema_id)
    if output_type is None:
        raise ModelError("Model worker received an output schema outside the production allowlist")
    return output_type


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ModelError("Model worker IPC value was not canonical JSON") from exc


def _model_worker_command() -> tuple[str, ...]:
    """Return the immutable production worker command (private seam for process tests)."""

    return (sys.executable, "-I", "-m", "autocontribute.model_worker")


def _worker_environment(profile: ModelProfile) -> dict[str, str]:
    """Give the worker its model credential without repository or GitHub credentials."""

    environment = {
        name: value for name in _WORKER_ENV_ALLOWLIST if (value := os.environ.get(name)) is not None
    }
    environment[profile.api_key_env] = profile.require_api_key()
    return environment


def _process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _signal_process_group(process_group: int, signal_number: int) -> bool:
    try:
        os.killpg(process_group, signal_number)
    except ProcessLookupError:
        return False
    return True


def _terminate_worker(process: subprocess.Popen[bytes]) -> tuple[bool, bool, int | None]:
    """TERM, then KILL, the worker's private process group and reap its leader."""

    process.poll()
    term_sent = False
    kill_sent = False
    if _process_group_exists(process.pid):
        term_sent = _signal_process_group(process.pid, signal.SIGTERM)
        grace_deadline = time.monotonic() + _WORKER_TERM_GRACE_SECONDS
        while time.monotonic() < grace_deadline:
            process.poll()
            if not _process_group_exists(process.pid):
                break
            time.sleep(0.01)
        if _process_group_exists(process.pid):
            kill_sent = _signal_process_group(process.pid, signal.SIGKILL)
    if process.poll() is None:
        process.wait()
    else:
        # ``poll`` reaps on CPython, while ``wait`` makes that contract explicit.
        process.wait()
    return term_sent, kill_sent, process.returncode


class _WorkerDeadlineExpired(Exception):
    pass


def _collect_worker_payload(
    process: subprocess.Popen[bytes],
    result_fd: int,
    *,
    deadline: float,
) -> bytes:
    payload = bytearray()
    reached_eof = False
    os.set_blocking(result_fd, False)
    selector = selectors.DefaultSelector()
    selector.register(result_fd, selectors.EVENT_READ)
    try:
        while not (reached_eof and process.poll() is not None):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _WorkerDeadlineExpired
            events = selector.select(timeout=min(remaining, _WORKER_POLL_SECONDS))
            for _key, _events in events:
                read_size = min(65_536, _MAX_MODEL_RESULT_BYTES + 1 - len(payload))
                if read_size <= 0:
                    raise ModelError("Model worker result exceeded the bounded IPC limit")
                try:
                    chunk = os.read(result_fd, read_size)
                except BlockingIOError:
                    continue
                if not chunk:
                    reached_eof = True
                    selector.unregister(result_fd)
                    break
                payload.extend(chunk)
                if len(payload) > _MAX_MODEL_RESULT_BYTES:
                    raise ModelError("Model worker result exceeded the bounded IPC limit")
        if time.monotonic() >= deadline:
            raise _WorkerDeadlineExpired
        return bytes(payload)
    finally:
        selector.close()


def _strict_worker_envelope(payload: bytes) -> dict[str, object]:
    if not payload:
        raise ModelError("Model worker returned no IPC result")
    try:
        decoded = payload.decode("utf-8", errors="strict")
        raw_envelope = json.loads(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ModelError("Model worker returned invalid IPC JSON") from exc
    if not isinstance(raw_envelope, dict) or any(not isinstance(key, str) for key in raw_envelope):
        raise ModelError("Model worker returned an invalid IPC envelope")
    envelope = cast("dict[str, object]", raw_envelope)
    if _canonical_json_bytes(envelope) != payload:
        raise ModelError("Model worker returned non-canonical IPC JSON")
    return envelope


def _worker_result(
    payload: bytes,
    *,
    output_type: type[OutputT],
    output_schema: str,
) -> ModelResult[OutputT]:
    envelope = _strict_worker_envelope(payload)
    if envelope.get("protocol") != _MODEL_WORKER_PROTOCOL:
        raise ModelError("Model worker returned an incompatible IPC protocol")
    status = envelope.get("status")
    if status == "error":
        error_code = envelope.get("error_code")
        expected_keys = {"protocol", "status", "error_code", "message"}
        http_status: int | None = None
        if error_code == "provider_request_error" and "http_status" in envelope:
            expected_keys = expected_keys | {"http_status"}
            raw_status = envelope.get("http_status")
            if (
                isinstance(raw_status, bool)
                or not isinstance(raw_status, int)
                or not 400 <= raw_status <= 599
            ):
                raise ModelError("Model worker returned an invalid provider HTTP status")
            http_status = raw_status
        if set(envelope) != expected_keys:
            raise ModelError("Model worker returned an invalid error envelope")
        message = envelope.get("message")
        if error_code not in {"provider_error", "provider_request_error", "worker_error"}:
            raise ModelError("Model worker returned an unknown error code")
        if (
            not isinstance(message, str)
            or not message
            or len(message) > 1_000
            or not message.isprintable()
        ):
            raise ModelError("Model worker returned an invalid error message")
        if error_code == "provider_request_error":
            raise ModelRequestError(message, status_code=http_status)
        raise ModelError(message)
    expected_keys = {
        "protocol",
        "status",
        "output_schema",
        "output",
        "response_id",
        "model",
        "usage",
    }
    if status != "ok" or set(envelope) != expected_keys:
        raise ModelError("Model worker returned an invalid success envelope")
    if envelope.get("output_schema") != output_schema:
        raise ModelError("Model worker returned output for a different schema")
    response_id = envelope.get("response_id")
    if (
        not isinstance(response_id, str)
        or not response_id
        or len(response_id) > 256
        or not response_id.isprintable()
    ):
        raise ModelError("Model worker returned an invalid response identifier")
    try:
        model = validate_model_identifier(envelope.get("model"))
    except ValueError as exc:
        raise ModelError("Model worker returned an invalid model identifier") from exc
    raw_usage = envelope.get("usage")
    usage_fields = {
        "input_tokens",
        "cached_input_tokens",
        "cache_write_tokens",
        "output_tokens",
        "reasoning_tokens",
        "total_tokens",
    }
    if not isinstance(raw_usage, dict) or set(raw_usage) != usage_fields:
        raise ModelError("Model worker returned invalid usage evidence")
    counts: dict[str, int] = {}
    for field in sorted(usage_fields):
        value = raw_usage.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ModelError(f"Model worker returned invalid usage field: {field}")
        counts[field] = value
    usage = _validate_usage(ModelUsage(**counts))
    try:
        output = output_type.model_validate(envelope.get("output"))
    except ValidationError as exc:
        raise ModelError(
            "Model worker returned output that violated its allowlisted schema"
        ) from exc
    return ModelResult(output=output, response_id=response_id, model=model, usage=usage)


class SubprocessModelProvider:
    """Run one built-in provider call in a killable, isolated process group."""

    def __init__(self, profile: ModelProfile) -> None:
        if os.name != "posix":  # pragma: no cover - production is the systemd/Linux deployment
            raise ModelError("Hard model deadlines require a POSIX process-group runtime")
        profile.require_api_key()
        self.profile = profile.model_copy(deep=True)

    def generate(
        self,
        *,
        instructions: str,
        prompt: str,
        output_type: type[OutputT],
        max_output_tokens: int | None = None,
        timeout_seconds: float | None = None,
    ) -> ModelResult[OutputT]:
        output_schema = _output_schema_id(output_type)
        output_limit = _effective_output_tokens(self.profile.max_output_tokens, max_output_tokens)
        request_timeout = _effective_timeout(self.profile.timeout_seconds, timeout_seconds)
        started = time.monotonic()
        deadline = started + request_timeout
        safe_instructions, safe_prompt = _scrub_request_text(self.profile, instructions, prompt)
        request = _canonical_json_bytes(
            {
                "protocol": _MODEL_WORKER_PROTOCOL,
                "profile": self.profile.model_dump(mode="json"),
                "instructions": safe_instructions,
                "prompt": safe_prompt,
                "output_schema": output_schema,
                "max_output_tokens": output_limit,
                "timeout_seconds": request_timeout,
            }
        )
        if len(request) > _MAX_MODEL_REQUEST_BYTES:
            raise ModelError("Model worker request exceeded the bounded IPC limit")
        if time.monotonic() >= deadline:
            raise ModelTimeoutError(
                timeout_seconds=request_timeout,
                elapsed_seconds=max(0.0, time.monotonic() - started),
                term_sent=False,
                kill_sent=False,
                child_exit_code=None,
            )

        result_read_fd, result_write_fd = os.pipe()
        process: subprocess.Popen[bytes] | None = None
        try:
            with tempfile.TemporaryFile() as request_file:
                request_file.write(request)
                request_file.flush()
                request_file.seek(0)
                command = (
                    *_model_worker_command(),
                    "--request-fd",
                    str(request_file.fileno()),
                    "--result-fd",
                    str(result_write_fd),
                )
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    close_fds=True,
                    pass_fds=(request_file.fileno(), result_write_fd),
                    start_new_session=True,
                    env=_worker_environment(self.profile),
                )
            os.close(result_write_fd)
            result_write_fd = -1
            try:
                payload = _collect_worker_payload(process, result_read_fd, deadline=deadline)
            except _WorkerDeadlineExpired:
                with suppress(OSError):
                    os.close(result_read_fd)
                result_read_fd = -1
                term_sent, kill_sent, exit_code = _terminate_worker(process)
                raise ModelTimeoutError(
                    timeout_seconds=request_timeout,
                    elapsed_seconds=max(0.0, time.monotonic() - started),
                    term_sent=term_sent,
                    kill_sent=kill_sent,
                    child_exit_code=exit_code,
                ) from None
            except BaseException:
                _terminate_worker(process)
                raise

            with suppress(OSError):
                os.close(result_read_fd)
            result_read_fd = -1
            exit_code = process.wait()
            if time.monotonic() >= deadline:
                term_sent, kill_sent, _ = _terminate_worker(process)
                raise ModelTimeoutError(
                    timeout_seconds=request_timeout,
                    elapsed_seconds=max(0.0, time.monotonic() - started),
                    term_sent=term_sent,
                    kill_sent=kill_sent,
                    child_exit_code=exit_code,
                )
            if _process_group_exists(process.pid):
                _terminate_worker(process)
                raise ModelError("Model worker left an unexpected descendant process")
            if exit_code != 0:
                raise ModelError("Model worker exited without a valid result")
            try:
                result = _worker_result(
                    payload,
                    output_type=output_type,
                    output_schema=output_schema,
                )
                _require_deployment_model(self.profile, result.model)
            except ModelError:
                if time.monotonic() >= deadline:
                    raise ModelTimeoutError(
                        timeout_seconds=request_timeout,
                        elapsed_seconds=max(0.0, time.monotonic() - started),
                        term_sent=False,
                        kill_sent=False,
                        child_exit_code=exit_code,
                    ) from None
                raise
            if time.monotonic() >= deadline:
                raise ModelTimeoutError(
                    timeout_seconds=request_timeout,
                    elapsed_seconds=max(0.0, time.monotonic() - started),
                    term_sent=False,
                    kill_sent=False,
                    child_exit_code=exit_code,
                )
            return result
        except OSError as exc:
            if process is not None:
                _terminate_worker(process)
            raise ModelError("Model worker process could not be executed") from exc
        finally:
            if result_write_fd >= 0:
                with suppress(OSError):
                    os.close(result_write_fd)
            if result_read_fd >= 0:
                with suppress(OSError):
                    os.close(result_read_fd)


def _create_in_process_provider(profile: ModelProfile) -> ModelProvider:
    if profile.provider == "openai":
        return OpenAIResponsesProvider(profile)
    if profile.provider == "openai_compatible":
        return OpenAICompatibleProvider(profile)
    raise ModelError(f"Unsupported model provider: {profile.provider}")


def create_provider(profile: ModelProfile) -> ModelProvider:
    """Create the production provider with an application-owned hard deadline."""

    return SubprocessModelProvider(profile)


__all__ = [
    "ModelCapabilityResponse",
    "ModelProvider",
    "ModelResult",
    "ModelUsage",
    "OpenAICompatibleProvider",
    "OpenAIResponsesProvider",
    "SubprocessModelProvider",
    "create_provider",
]
