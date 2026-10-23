"""Parent side of the model boundary: one killable worker process per request, strict IPC.

This module must not import a provider SDK; the SDK adapters live in worker-only modules.
"""

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
from collections.abc import Callable, Iterator
from contextlib import suppress
from dataclasses import dataclass
from typing import Final, Generic, Literal, NoReturn, Protocol, TypeVar, cast

from pydantic import BaseModel, ConfigDict, JsonValue, ValidationError

from autocontribute.config import ModelProfile, validate_model_identifier
from autocontribute.domain import ContributionPlan, CriticReview, PatchProposal
from autocontribute.exceptions import (
    ConfigurationError,
    ModelError,
    ModelRequestError,
    ModelTimeoutError,
)
from autocontribute.model_retry import PROVIDER_ERROR_CODES
from autocontribute.pricing import API_KEY_ENVS, Effort, ModelSpec, ModelUsage
from autocontribute.redaction import redact_model_input
from autocontribute.transcript import (
    Transcript,
    TranscriptKind,
    Turn,
    canonical_json,
    tool_call_names,
)

OutputT = TypeVar("OutputT", bound=BaseModel)
_ResultT = TypeVar("_ResultT")

_MODEL_WORKER_PROTOCOL = "autocontribute.model-call.v1"
_MODEL_TURN_PROTOCOL = "autocontribute.model-turn.v1"
# A transcript near the 200K-token limit, encrypted reasoning included, is a few MB.
_MAX_MODEL_REQUEST_BYTES = 32 * 1024 * 1024
_MAX_MODEL_RESULT_BYTES = 32 * 1024 * 1024
MAX_TOOL_ARGUMENT_BYTES: Final = 256 * 1024
MAX_TURN_SECONDS: Final = 600.0
_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_REQUEST_ERROR_DETAIL_KEYS = frozenset({"http_status", "provider_code", "retry_after_seconds"})
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


class TurnProvider(Protocol):
    def step(
        self,
        *,
        transcript: Transcript,
        max_output_tokens: int,
        timeout_seconds: float,
    ) -> Turn: ...


@dataclass(frozen=True, slots=True)
class TurnRequest:
    """One model-turn request, as the worker hands it to a provider adapter."""

    spec: ModelSpec
    effort: Effort
    instructions: str
    kind: TranscriptKind
    run_id: str
    items: list[dict[str, JsonValue]]
    max_output_tokens: int
    timeout_seconds: float


def _require_api_key(env_name: str) -> str:
    value = os.environ.get(env_name)
    if not value:
        raise ConfigurationError(
            f"Model credential is missing; set environment variable {env_name}"
        )
    return value


def _validate_usage(usage: ModelUsage) -> ModelUsage:
    if usage.cached_input_tokens + usage.cache_write_tokens > usage.input_tokens:
        raise ModelError("Model provider returned input-token details above input_tokens")
    if usage.reasoning_tokens > usage.output_tokens:
        raise ModelError("Model provider returned reasoning_tokens above output_tokens")
    if usage.total_tokens != usage.input_tokens + usage.output_tokens:
        raise ModelError("Model provider returned inconsistent total_tokens")
    return usage


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


def _safe_request_id(request_id: object, *, api_key_env: str, api_key: str) -> str | None:
    """Return a provider request ID that is safe to put in an error message, else None."""

    if not isinstance(request_id, str) or not _SAFE_REQUEST_ID.fullmatch(request_id):
        return None
    try:
        _assert_secret_free_model_output(api_key_env, api_key, request_id)
    except ModelError:
        return None
    return request_id


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


def _require_expected_response_model(profile: ModelProfile, model: str) -> None:
    expected = profile.expected_response_model
    if expected is not None and model != expected:
        raise ModelError(
            "Model provider resolved a different model ID than expected_response_model; "
            "set it to the exact provider-returned snapshot"
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
        return canonical_json(value)
    except (TypeError, ValueError) as exc:
        raise ModelError("Model worker IPC value was not canonical JSON") from exc


def _model_worker_command() -> tuple[str, ...]:
    """Return the immutable production worker command (private seam for process tests)."""

    return (sys.executable, "-I", "-m", "autocontribute.model_worker")


def _worker_environment(api_key_env: str, api_key: str) -> dict[str, str]:
    """Give the worker its model credential without repository or GitHub credentials."""

    environment = {
        name: value for name in _WORKER_ENV_ALLOWLIST if (value := os.environ.get(name)) is not None
    }
    environment[api_key_env] = api_key
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


def _request_error_details(
    envelope: dict[str, object],
) -> tuple[int | None, str | None, float | None]:
    http_status: int | None = None
    if "http_status" in envelope:
        raw_status = envelope["http_status"]
        if (
            isinstance(raw_status, bool)
            or not isinstance(raw_status, int)
            or not 400 <= raw_status <= 599
        ):
            raise ModelError("Model worker returned an invalid provider HTTP status")
        http_status = raw_status
    provider_code: str | None = None
    if "provider_code" in envelope:
        raw_code = envelope["provider_code"]
        if not isinstance(raw_code, str) or raw_code not in PROVIDER_ERROR_CODES:
            raise ModelError("Model worker returned an unknown provider error code")
        provider_code = raw_code
    retry_after: float | None = None
    if "retry_after_seconds" in envelope:
        raw_wait = envelope["retry_after_seconds"]
        if (
            isinstance(raw_wait, bool)
            or not isinstance(raw_wait, (int, float))
            or not math.isfinite(raw_wait)
            or raw_wait < 0
        ):
            raise ModelError("Model worker returned an invalid Retry-After value")
        retry_after = float(raw_wait)
    return http_status, provider_code, retry_after


def _success_envelope(
    payload: bytes,
    *,
    protocol: str,
    result_keys: frozenset[str],
) -> dict[str, object]:
    """Return a success envelope's fields, or raise the error the worker reported."""

    envelope = _strict_worker_envelope(payload)
    if envelope.get("protocol") != protocol:
        raise ModelError("Model worker returned an incompatible IPC protocol")
    status = envelope.get("status")
    if status == "error":
        _raise_worker_error(envelope)
    if status != "ok" or set(envelope) != {"protocol", "status", *result_keys}:
        raise ModelError("Model worker returned an invalid success envelope")
    return envelope


def _raise_worker_error(envelope: dict[str, object]) -> NoReturn:
    error_code = envelope.get("error_code")
    expected_keys = {"protocol", "status", "error_code", "message"}
    if error_code == "provider_request_error":
        expected_keys |= _REQUEST_ERROR_DETAIL_KEYS & envelope.keys()
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
        http_status, provider_code, retry_after = _request_error_details(envelope)
        raise ModelRequestError(
            message,
            status_code=http_status,
            provider_code=provider_code,
            retry_after_seconds=retry_after,
        )
    raise ModelError(message)


def _envelope_identity(envelope: dict[str, object]) -> tuple[str, str]:
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
    return response_id, model


def _envelope_usage(envelope: dict[str, object]) -> ModelUsage:
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
    return _validate_usage(ModelUsage(**counts))


def _worker_result(
    payload: bytes,
    *,
    output_type: type[OutputT],
    output_schema: str,
) -> ModelResult[OutputT]:
    envelope = _success_envelope(
        payload,
        protocol=_MODEL_WORKER_PROTOCOL,
        result_keys=frozenset({"output_schema", "output", "response_id", "model", "usage"}),
    )
    if envelope.get("output_schema") != output_schema:
        raise ModelError("Model worker returned output for a different schema")
    response_id, model = _envelope_identity(envelope)
    usage = _envelope_usage(envelope)
    try:
        output = output_type.model_validate(envelope.get("output"))
    except ValidationError as exc:
        raise ModelError(
            "Model worker returned output that violated its allowlisted schema"
        ) from exc
    return ModelResult(output=output, response_id=response_id, model=model, usage=usage)


def _turn_result(payload: bytes, *, spec: ModelSpec, kind: TranscriptKind) -> Turn:
    envelope = _success_envelope(
        payload,
        protocol=_MODEL_TURN_PROTOCOL,
        result_keys=frozenset(
            {"stop", "output_items", "tool_calls", "response_id", "model", "usage"}
        ),
    )
    response_id, model = _envelope_identity(envelope)
    if model not in spec.response_models:
        raise ModelError("Model provider served a model that the model table does not accept")
    usage = _envelope_usage(envelope)
    tool_calls = envelope.get("tool_calls")
    if not isinstance(tool_calls, list) or not all(isinstance(call, dict) for call in tool_calls):
        raise ModelError("Model worker returned invalid tool calls")
    allowed_names = tool_call_names(spec.provider, kind)
    for call in tool_calls:
        if call.get("name") not in allowed_names:
            raise ModelError("Model called a tool outside its transcript's tool set")
        if len(_canonical_json_bytes(call.get("arguments"))) > MAX_TOOL_ARGUMENT_BYTES:
            raise ModelError("Model tool call arguments exceeded the size limit")
    try:
        return Turn.model_validate(
            {
                "stop": envelope.get("stop"),
                "output_items": envelope.get("output_items"),
                "tool_calls": tool_calls,
                "response_id": response_id,
                "model": model,
                "usage": usage,
            }
        )
    except ValidationError as exc:
        raise ModelError("Model worker returned an invalid turn") from exc


def _run_worker(
    request: bytes,
    *,
    environment: dict[str, str],
    timeout_seconds: float,
    started: float,
    parse: Callable[[bytes], _ResultT],
) -> _ResultT:
    """Run one worker process for ``request`` and parse its result, all before the deadline."""

    deadline = started + timeout_seconds
    if len(request) > _MAX_MODEL_REQUEST_BYTES:
        raise ModelError("Model worker request exceeded the bounded IPC limit")
    if time.monotonic() >= deadline:
        raise ModelTimeoutError(
            timeout_seconds=timeout_seconds,
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
                env=environment,
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
                timeout_seconds=timeout_seconds,
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
                timeout_seconds=timeout_seconds,
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
            result = parse(payload)
        except ModelError:
            if time.monotonic() >= deadline:
                raise ModelTimeoutError(
                    timeout_seconds=timeout_seconds,
                    elapsed_seconds=max(0.0, time.monotonic() - started),
                    term_sent=False,
                    kill_sent=False,
                    child_exit_code=exit_code,
                ) from None
            raise
        if time.monotonic() >= deadline:
            raise ModelTimeoutError(
                timeout_seconds=timeout_seconds,
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


class SubprocessModelProvider:
    """Run one built-in provider call in a killable, isolated process group."""

    def __init__(self, profile: ModelProfile) -> None:
        if os.name != "posix":  # pragma: no cover - supported hosts are POSIX
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

        def parse(payload: bytes) -> ModelResult[OutputT]:
            result = _worker_result(payload, output_type=output_type, output_schema=output_schema)
            _require_expected_response_model(self.profile, result.model)
            return result

        return _run_worker(
            request,
            environment=_worker_environment(
                self.profile.api_key_env, self.profile.require_api_key()
            ),
            timeout_seconds=request_timeout,
            started=started,
            parse=parse,
        )


class SubprocessTurnProvider:
    """Send each transcript request from a fresh, killable worker process.

    The worker gets only this provider's key, so third-party SDK code never runs beside the
    GitHub token. Transcript text is sent as appended; it was scrubbed once, when appended.
    """

    def __init__(self, spec: ModelSpec, effort: Effort) -> None:
        if os.name != "posix":  # pragma: no cover - supported hosts are POSIX
            raise ModelError("Hard model deadlines require a POSIX process-group runtime")
        if effort not in spec.efforts:
            raise ConfigurationError(f"{spec.id} does not support reasoning effort {effort}")
        _require_api_key(API_KEY_ENVS[spec.provider])
        self.spec = spec
        self.effort = effort

    def step(
        self,
        *,
        transcript: Transcript,
        max_output_tokens: int,
        timeout_seconds: float,
    ) -> Turn:
        if transcript.model != self.spec.id:
            raise ModelError("Transcript is bound to a different model")
        if not transcript.awaiting_model:
            raise ModelError("Transcript is not waiting for a model turn")
        output_limit = _effective_output_tokens(self.spec.max_output_tokens, max_output_tokens)
        request_timeout = _effective_timeout(MAX_TURN_SECONDS, timeout_seconds)
        started = time.monotonic()
        request = _canonical_json_bytes(
            {
                "protocol": _MODEL_TURN_PROTOCOL,
                "model_id": self.spec.id,
                "effort": self.effort,
                "instructions": transcript.instructions,
                "transcript": {
                    "kind": transcript.kind,
                    "run_id": transcript.run_id,
                    "items": transcript.items,
                },
                "max_output_tokens": output_limit,
                "timeout_seconds": request_timeout,
            }
        )
        api_key_env = API_KEY_ENVS[self.spec.provider]
        return _run_worker(
            request,
            environment=_worker_environment(api_key_env, _require_api_key(api_key_env)),
            timeout_seconds=request_timeout,
            started=started,
            parse=lambda payload: _turn_result(payload, spec=self.spec, kind=transcript.kind),
        )


def create_provider(profile: ModelProfile) -> ModelProvider:
    """Create the production provider with an application-owned hard deadline."""

    return SubprocessModelProvider(profile)


__all__ = [
    "MAX_TOOL_ARGUMENT_BYTES",
    "MAX_TURN_SECONDS",
    "ModelCapabilityResponse",
    "ModelProvider",
    "ModelResult",
    "ModelUsage",
    "SubprocessModelProvider",
    "SubprocessTurnProvider",
    "TurnProvider",
    "TurnRequest",
    "create_provider",
]
