from __future__ import annotations

import os
import signal
import subprocess
import sys
from pathlib import Path

import pytest

import autocontribute.providers as providers
from autocontribute import model_worker
from autocontribute.exceptions import ModelError, ModelRequestError, ModelTimeoutError
from autocontribute.pricing import MODELS
from autocontribute.providers import (
    _MODEL_TURN_PROTOCOL,
    SubprocessTurnProvider,
    _canonical_json_bytes,
    _turn_result,
)
from autocontribute.transcript import Transcript, Turn, append_user_text

_SPEC = MODELS["gpt-5.6-sol"]

_WORKER_SOURCE = r"""
import argparse
import json
import os
import signal
import time

parser = argparse.ArgumentParser()
parser.add_argument("mode")
parser.add_argument("--request-fd", required=True, type=int)
parser.add_argument("--result-fd", required=True, type=int)
args = parser.parse_args()

while os.read(args.request_fd, 65536):
    pass
response = {
    "protocol": "autocontribute.model-turn.v1",
    "status": "ok",
    "stop": "end_turn",
    "output_items": [],
    "tool_calls": [],
    "response_id": "response-process-test",
    "model": "gpt-5.6-sol",
    "usage": {
        "input_tokens": 11,
        "cached_input_tokens": 3,
        "cache_write_tokens": 2,
        "output_tokens": 7,
        "reasoning_tokens": 4,
        "total_tokens": 18,
    },
}
payload = json.dumps(
    response,
    ensure_ascii=True,
    allow_nan=False,
    sort_keys=True,
    separators=(",", ":"),
).encode("utf-8")

if args.mode == "success":
    os.write(args.result_fd, payload)
elif args.mode == "noncanonical":
    os.write(args.result_fd, json.dumps(response).encode("utf-8"))
elif args.mode == "resist":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    time.sleep(60)
elif args.mode == "late":
    def publish_late(_signal, _frame):
        try:
            os.write(args.result_fd, payload)
        except OSError:
            pass
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, publish_late)
    time.sleep(60)
elif args.mode == "ignore-sdk-timeout":
    time.sleep(60)
else:
    raise SystemExit(2)
"""


def _provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    mode: str,
) -> SubprocessTurnProvider:
    worker = tmp_path / "model-process-worker.py"
    worker.write_text(_WORKER_SOURCE, encoding="utf-8")
    monkeypatch.setenv("OPENAI_API_KEY", "model-process-test-secret")
    monkeypatch.setattr(
        providers,
        "_model_worker_command",
        lambda: (sys.executable, str(worker), mode),
    )
    return SubprocessTurnProvider(_SPEC, frozenset())


def _step(provider: SubprocessTurnProvider, *, timeout_seconds: float) -> Turn:
    transcript = Transcript(
        model=_SPEC.id,
        effort="low",
        kind="triage",
        run_id="0123456789abcdef",
        instructions="Assess the issue.",
    )
    append_user_text(transcript, "Issue 12.", host_values=frozenset())
    return provider.step(
        transcript=transcript, max_output_tokens=1_000, timeout_seconds=timeout_seconds
    )


def _parse(payload: bytes) -> Turn:
    return _turn_result(payload, spec=_SPEC, kind="triage", host_values=frozenset())


def test_parent_process_never_imports_provider_sdks() -> None:
    probe = (
        "import sys\n"
        "import autocontribute.cli\n"
        "print(sorted({name.split('.')[0] for name in sys.modules} & {'anthropic', 'openai'}))\n"
    )

    completed = subprocess.run(
        [sys.executable, "-I", "-c", probe],
        capture_output=True,
        check=True,
        text=True,
    )

    assert completed.stdout == "[]\n"


def test_process_provider_round_trips_a_turn_and_its_usage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    turn = _step(_provider(tmp_path, monkeypatch, mode="success"), timeout_seconds=2)

    assert turn.stop == "end_turn"
    assert turn.response_id == "response-process-test"
    assert (turn.usage.input_tokens, turn.usage.cached_input_tokens) == (11, 3)
    assert (turn.usage.output_tokens, turn.usage.total_tokens) == (7, 18)


def test_process_provider_enforces_deadline_when_child_ignores_sdk_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = _provider(tmp_path, monkeypatch, mode="ignore-sdk-timeout")

    with pytest.raises(ModelTimeoutError) as raised:
        _step(provider, timeout_seconds=0.15)

    assert raised.value.term_sent
    assert not raised.value.kill_sent
    assert raised.value.child_exit_code == -signal.SIGTERM


def test_process_provider_kills_sigterm_resistant_process_group_and_reaps_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = _provider(tmp_path, monkeypatch, mode="resist")

    with pytest.raises(ModelTimeoutError) as raised:
        _step(provider, timeout_seconds=0.15)

    assert raised.value.term_sent
    assert raised.value.kill_sent
    assert raised.value.child_exit_code == -signal.SIGKILL


def test_process_provider_rejects_result_published_during_timeout_shutdown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = _provider(tmp_path, monkeypatch, mode="late")

    with pytest.raises(ModelTimeoutError) as raised:
        _step(provider, timeout_seconds=0.15)

    assert raised.value.term_sent
    assert not raised.value.kill_sent


def test_process_provider_rejects_noncanonical_ipc_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = _provider(tmp_path, monkeypatch, mode="noncanonical")

    with pytest.raises(ModelError, match="non-canonical IPC JSON"):
        _step(provider, timeout_seconds=2)


def _error_envelope(**fields: object) -> bytes:
    return _canonical_json_bytes(
        {
            "protocol": _MODEL_TURN_PROTOCOL,
            "status": "error",
            "error_code": "provider_request_error",
            "message": "OpenAI Responses request failed",
            **fields,
        }
    )


def test_worker_error_envelope_round_trips_provider_request_details() -> None:
    payload = model_worker._error_result(
        "provider_request_error",
        "OpenAI Responses request failed (HTTP 429; code: insufficient_quota)",
        http_status=429,
        provider_code="insufficient_quota",
        retry_after_seconds=2.5,
    )

    with pytest.raises(ModelRequestError) as raised:
        _parse(payload)

    assert str(raised.value) == (
        "OpenAI Responses request failed (HTTP 429; code: insufficient_quota)"
    )
    assert raised.value.status_code == 429
    assert raised.value.provider_code == "insufficient_quota"
    assert raised.value.retry_after_seconds == 2.5


def test_worker_error_envelope_round_trips_statusless_request_failure() -> None:
    payload = model_worker._error_result(
        "provider_request_error", "OpenAI Responses request failed"
    )

    with pytest.raises(ModelRequestError) as raised:
        _parse(payload)

    assert raised.value.status_code is None


@pytest.mark.parametrize("http_status", [200, 399, 600, True, "503"])
def test_worker_result_rejects_invalid_provider_http_status(http_status: object) -> None:
    with pytest.raises(ModelError, match="invalid provider HTTP status"):
        _parse(_error_envelope(http_status=http_status))


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("http_status", 503),
        ("provider_code", "insufficient_quota"),
        ("retry_after_seconds", 1.0),
    ],
)
def test_worker_result_rejects_request_details_on_other_error_codes(
    key: str,
    value: object,
) -> None:
    payload = _canonical_json_bytes(
        {
            "protocol": _MODEL_TURN_PROTOCOL,
            "status": "error",
            "error_code": "provider_error",
            "message": "Model provider request failed",
            key: value,
        }
    )

    with pytest.raises(ModelError, match="invalid error envelope"):
        _parse(payload)


@pytest.mark.parametrize("provider_code", ["rate_limit_exceeded", 7, None, ["cyber_policy"]])
def test_worker_result_rejects_unknown_provider_codes(provider_code: object) -> None:
    with pytest.raises(ModelError, match="unknown provider error code"):
        _parse(_error_envelope(provider_code=provider_code))


@pytest.mark.parametrize("retry_after", [-1, -0.5, "5", True, None, [1]])
def test_worker_result_rejects_invalid_retry_after(retry_after: object) -> None:
    with pytest.raises(ModelError, match="invalid Retry-After value"):
        _parse(_error_envelope(retry_after_seconds=retry_after))


def _worker_main_payload(monkeypatch: pytest.MonkeyPatch, error: Exception) -> bytes:
    def failing_execute(_envelope: dict[str, object]) -> bytes:
        raise error

    monkeypatch.setattr(model_worker, "_execute_turn", failing_execute)
    request_read, request_write = os.pipe()
    result_read, result_write = os.pipe()
    os.write(request_write, _canonical_json_bytes({"protocol": _MODEL_TURN_PROTOCOL}))
    os.close(request_write)
    monkeypatch.setattr(
        sys,
        "argv",
        ["worker", "--request-fd", str(request_read), "--result-fd", str(result_write)],
    )

    assert model_worker.main() == 0

    payload = os.read(result_read, 65_536)
    os.close(result_read)
    return payload


def _request_error_from(payload: bytes) -> ModelRequestError:
    with pytest.raises(ModelRequestError) as raised:
        _parse(payload)
    return raised.value


def test_worker_main_forwards_status_allowlisted_code_and_retry_after(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _worker_main_payload(
        monkeypatch,
        ModelRequestError(
            "OpenAI Responses request failed (HTTP 429; code: credit_balance_exhausted)",
            status_code=429,
            provider_code="credit_balance_exhausted",
            retry_after_seconds=4.0,
        ),
    )

    error = _request_error_from(payload)
    assert error.status_code == 429
    assert error.provider_code == "credit_balance_exhausted"
    assert error.retry_after_seconds == 4.0


def test_worker_main_drops_request_details_the_parent_would_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _worker_main_payload(
        monkeypatch,
        ModelRequestError(
            "OpenAI Responses request failed (HTTP 429)",
            status_code=429,
            provider_code="confidentialmergercodename",
            retry_after_seconds=-1.0,
        ),
    )

    assert b"confidentialmergercodename" not in payload
    error = _request_error_from(payload)
    assert error.status_code == 429
    assert error.provider_code is None
    assert error.retry_after_seconds is None


def test_worker_main_refuses_another_protocol(monkeypatch: pytest.MonkeyPatch) -> None:
    request_read, request_write = os.pipe()
    result_read, result_write = os.pipe()
    os.write(request_write, _canonical_json_bytes({"protocol": "autocontribute.model-call.v1"}))
    os.close(request_write)
    monkeypatch.setattr(
        sys,
        "argv",
        ["worker", "--request-fd", str(request_read), "--result-fd", str(result_write)],
    )

    assert model_worker.main() == 0
    payload = os.read(result_read, 65_536)
    os.close(result_read)

    with pytest.raises(ModelError, match="incompatible IPC protocol"):
        _parse(payload)
