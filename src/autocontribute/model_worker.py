"""Single-call model worker for the application's hard process deadline.

This module is intentionally an internal executable.  It accepts only inherited file
descriptors, validates one canonical bounded request, and writes one canonical bounded result.
"""

from __future__ import annotations

import argparse
import math
import os
from contextlib import suppress

from pydantic import BaseModel, ValidationError

from autocontribute.config import ModelProfile
from autocontribute.exceptions import ModelError
from autocontribute.providers import (
    _MAX_MODEL_REQUEST_BYTES,
    _MAX_MODEL_RESULT_BYTES,
    _MODEL_WORKER_PROTOCOL,
    _canonical_json_bytes,
    _create_in_process_provider,
    _output_schema_type,
    _strict_worker_envelope,
)


def _read_bounded(fd: int) -> bytes:
    payload = bytearray()
    while True:
        chunk = os.read(fd, min(65_536, _MAX_MODEL_REQUEST_BYTES + 1 - len(payload)))
        if not chunk:
            break
        payload.extend(chunk)
        if len(payload) > _MAX_MODEL_REQUEST_BYTES:
            raise ModelError("Model worker request exceeded the bounded IPC limit")
    return bytes(payload)


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("model worker result pipe closed")
        view = view[written:]


def _request(
    payload: bytes,
) -> tuple[
    ModelProfile,
    str,
    str,
    str,
    type[BaseModel],
    int,
    float,
]:
    envelope = _strict_worker_envelope(payload)
    expected_keys = {
        "protocol",
        "profile",
        "instructions",
        "prompt",
        "output_schema",
        "max_output_tokens",
        "timeout_seconds",
    }
    if set(envelope) != expected_keys or envelope.get("protocol") != _MODEL_WORKER_PROTOCOL:
        raise ModelError("Model worker received an invalid IPC request")
    raw_profile = envelope.get("profile")
    try:
        profile = ModelProfile.model_validate(raw_profile)
    except ValidationError as exc:
        raise ModelError("Model worker received an invalid provider profile") from exc
    instructions = envelope.get("instructions")
    prompt = envelope.get("prompt")
    output_schema = envelope.get("output_schema")
    output_limit = envelope.get("max_output_tokens")
    timeout_seconds = envelope.get("timeout_seconds")
    if not isinstance(instructions, str) or not isinstance(prompt, str):
        raise ModelError("Model worker received invalid request text")
    if not isinstance(output_schema, str):
        raise ModelError("Model worker received an invalid output schema identifier")
    output_type = _output_schema_type(output_schema)
    if (
        isinstance(output_limit, bool)
        or not isinstance(output_limit, int)
        or output_limit < 1
        or output_limit > profile.max_output_tokens
    ):
        raise ModelError("Model worker received an invalid output-token limit")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
        or timeout_seconds > profile.timeout_seconds
    ):
        raise ModelError("Model worker received an invalid request timeout")
    return (
        profile,
        instructions,
        prompt,
        output_schema,
        output_type,
        output_limit,
        float(timeout_seconds),
    )


def _safe_provider_message(error: ModelError) -> str:
    message = str(error)
    if message and len(message) <= 1_000 and message.isprintable():
        return message
    return "Model provider request failed"


def _error_result(error_code: str, message: str) -> bytes:
    return _canonical_json_bytes(
        {
            "protocol": _MODEL_WORKER_PROTOCOL,
            "status": "error",
            "error_code": error_code,
            "message": message,
        }
    )


def _execute(payload: bytes) -> bytes:
    (
        profile,
        instructions,
        prompt,
        output_schema,
        output_type,
        output_limit,
        timeout_seconds,
    ) = _request(payload)
    provider = _create_in_process_provider(profile)
    try:
        result = provider.generate(
            instructions=instructions,
            prompt=prompt,
            output_type=output_type,
            max_output_tokens=output_limit,
            timeout_seconds=timeout_seconds,
        )
    finally:
        close = getattr(provider, "close", None)
        if not callable(close):
            close = getattr(getattr(provider, "client", None), "close", None)
        if callable(close):
            close()
    response = _canonical_json_bytes(
        {
            "protocol": _MODEL_WORKER_PROTOCOL,
            "status": "ok",
            "output_schema": output_schema,
            "output": result.output.model_dump(mode="json"),
            "response_id": result.response_id,
            "model": result.model,
            "usage": {
                "input_tokens": result.usage.input_tokens,
                "cached_input_tokens": result.usage.cached_input_tokens,
                "cache_write_tokens": result.usage.cache_write_tokens,
                "output_tokens": result.usage.output_tokens,
                "reasoning_tokens": result.usage.reasoning_tokens,
                "total_tokens": result.usage.total_tokens,
            },
        }
    )
    if len(response) > _MAX_MODEL_RESULT_BYTES:
        return _error_result("worker_error", "Model worker result exceeded the bounded IPC limit")
    return response


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--request-fd", required=True, type=int)
    parser.add_argument("--result-fd", required=True, type=int)
    arguments = parser.parse_args()
    result_fd = arguments.result_fd
    try:
        try:
            payload = _read_bounded(arguments.request_fd)
            response = _execute(payload)
        except ModelError as exc:
            response = _error_result("provider_error", _safe_provider_message(exc))
        except Exception:
            response = _error_result("worker_error", "Model worker failed")
        _write_all(result_fd, response)
        return 0
    finally:
        with suppress(OSError):
            os.close(arguments.request_fd)
        with suppress(OSError):
            os.close(result_fd)


if __name__ == "__main__":  # pragma: no cover - exercised through the parent process
    raise SystemExit(main())
