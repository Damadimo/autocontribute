"""Single-request model worker for the application's hard process deadline.

This module is intentionally an internal executable.  It accepts only inherited file
descriptors, validates one canonical bounded transcript-turn request (model-turn.v1), and
writes one canonical bounded result.
"""

from __future__ import annotations

import argparse
import dataclasses
import math
import os
from contextlib import suppress
from typing import cast

from pydantic import JsonValue

from autocontribute import openai_adapter
from autocontribute.exceptions import ModelError, ModelRequestError
from autocontribute.model_retry import PROVIDER_ERROR_CODES
from autocontribute.pricing import MODELS
from autocontribute.providers import (
    _MAX_MODEL_REQUEST_BYTES,
    _MAX_MODEL_RESULT_BYTES,
    _MODEL_TURN_PROTOCOL,
    MAX_TURN_SECONDS,
    TurnRequest,
    _canonical_json_bytes,
    _strict_worker_envelope,
)
from autocontribute.transcript import TOOL_SETS, TranscriptKind, Turn


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


def _turn_request(envelope: dict[str, object]) -> TurnRequest:
    expected_keys = {
        "protocol",
        "model_id",
        "effort",
        "instructions",
        "transcript",
        "max_output_tokens",
        "timeout_seconds",
    }
    if set(envelope) != expected_keys:
        raise ModelError("Model worker received an invalid IPC request")
    model_id = envelope["model_id"]
    spec = MODELS.get(model_id) if isinstance(model_id, str) else None
    if spec is None:
        raise ModelError("Model worker received a model outside the built-in table")
    effort = envelope["effort"]
    if effort not in spec.efforts:
        raise ModelError("Model worker received an effort the model does not support")
    instructions = envelope["instructions"]
    if not isinstance(instructions, str):
        raise ModelError("Model worker received invalid request text")
    transcript = envelope["transcript"]
    if not isinstance(transcript, dict) or set(transcript) != {"kind", "run_id", "items"}:
        raise ModelError("Model worker received an invalid transcript")
    kind = transcript["kind"]
    run_id = transcript["run_id"]
    items = transcript["items"]
    if (
        kind not in TOOL_SETS
        or not isinstance(run_id, str)
        or not isinstance(items, list)
        or not all(isinstance(item, dict) for item in items)
    ):
        raise ModelError("Model worker received an invalid transcript")
    output_limit = envelope["max_output_tokens"]
    if (
        isinstance(output_limit, bool)
        or not isinstance(output_limit, int)
        or not 1 <= output_limit <= spec.max_output_tokens
    ):
        raise ModelError("Model worker received an invalid output-token limit")
    timeout_seconds = envelope["timeout_seconds"]
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or not 0 < timeout_seconds <= MAX_TURN_SECONDS
    ):
        raise ModelError("Model worker received an invalid request timeout")
    return TurnRequest(
        spec=spec,
        effort=effort,
        instructions=instructions,
        kind=cast("TranscriptKind", kind),
        run_id=run_id,
        items=cast("list[dict[str, JsonValue]]", items),
        max_output_tokens=output_limit,
        timeout_seconds=float(timeout_seconds),
    )


def _safe_provider_message(error: ModelError) -> str:
    message = str(error)
    if message and len(message) <= 1_000 and message.isprintable():
        return message
    return "Model provider request failed"


def _error_result(
    error_code: str,
    message: str,
    *,
    http_status: int | None = None,
    provider_code: str | None = None,
    retry_after_seconds: float | None = None,
) -> bytes:
    envelope: dict[str, object] = {
        "protocol": _MODEL_TURN_PROTOCOL,
        "status": "error",
        "error_code": error_code,
        "message": message,
    }
    if http_status is not None:
        envelope["http_status"] = http_status
    if provider_code is not None:
        envelope["provider_code"] = provider_code
    if retry_after_seconds is not None:
        envelope["retry_after_seconds"] = retry_after_seconds
    return _canonical_json_bytes(envelope)


def _request_error_result(error: ModelRequestError) -> bytes:
    """Serialize a request failure, dropping details the parent would reject."""

    status_code = error.status_code
    if not (type(status_code) is int and 400 <= status_code <= 599):
        status_code = None
    provider_code = error.provider_code if error.provider_code in PROVIDER_ERROR_CODES else None
    retry_after = error.retry_after_seconds
    if retry_after is not None and not (math.isfinite(retry_after) and retry_after >= 0):
        retry_after = None
    return _error_result(
        "provider_request_error",
        _safe_provider_message(error),
        http_status=status_code,
        provider_code=provider_code,
        retry_after_seconds=retry_after,
    )


def _execute_turn(envelope: dict[str, object]) -> bytes:
    turn = _step(_turn_request(envelope))
    response = _canonical_json_bytes(
        {
            "protocol": _MODEL_TURN_PROTOCOL,
            "status": "ok",
            "stop": turn.stop,
            "output_items": list(turn.output_items),
            "tool_calls": [call.model_dump(mode="json") for call in turn.tool_calls],
            "response_id": turn.response_id,
            "model": turn.model,
            "usage": dataclasses.asdict(turn.usage),
        }
    )
    if len(response) > _MAX_MODEL_RESULT_BYTES:
        return _error_result("worker_error", "Model worker result exceeded the bounded IPC limit")
    return response


def _step(request: TurnRequest) -> Turn:
    if request.spec.provider == "anthropic":
        # Imported on demand so that OpenAI turns do not load a second SDK.
        from autocontribute import anthropic_adapter

        return anthropic_adapter.step(request)
    return openai_adapter.step(request)


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--request-fd", required=True, type=int)
    parser.add_argument("--result-fd", required=True, type=int)
    arguments = parser.parse_args()
    result_fd = arguments.result_fd
    try:
        try:
            envelope = _strict_worker_envelope(_read_bounded(arguments.request_fd))
            if envelope.get("protocol") != _MODEL_TURN_PROTOCOL:
                raise ModelError("Model worker received an incompatible IPC protocol")
            response = _execute_turn(envelope)
        except ModelRequestError as exc:
            response = _request_error_result(exc)
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
