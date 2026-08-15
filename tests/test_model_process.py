from __future__ import annotations

import signal
import sys
from pathlib import Path

import pytest
from pydantic import BaseModel

import autocontribute.providers as providers
from autocontribute.config import ModelProfile
from autocontribute.domain import ContributionPlan
from autocontribute.exceptions import ModelError, ModelTimeoutError
from autocontribute.providers import ModelResult, ModelUsage, SubprocessModelProvider

_API_KEY_ENV = "AUTOCONTRIBUTE_MODEL_PROCESS_TEST_KEY"

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

request_bytes = b""
while True:
    chunk = os.read(args.request_fd, 65536)
    if not chunk:
        break
    request_bytes += chunk
request = json.loads(request_bytes)

plan = {
    "decision": "proceed",
    "decision_reason": "The issue has a bounded and reproducible fix.",
    "contribution_kind": "bugfix",
    "issue_understanding": "The documented boundary returns the wrong value.",
    "acceptance_criteria": ["Return the documented value."],
    "implementation_steps": ["Change the return value.", "Run the focused test."],
    "files_to_read": ["app.py", "tests/test_app.py"],
    "reproduction_command": "python -m pytest tests/test_app.py",
    "validation_commands": ["python -m pytest tests/test_app.py"],
    "risks": ["Callers may rely on the old incorrect value."],
    "maintainer_fit": "Small fix with focused regression coverage.",
}
response = {
    "protocol": "autocontribute.model-call.v1",
    "status": "ok",
    "output_schema": request["output_schema"],
    "output": plan,
    "response_id": "response-process-test",
    "model": "test-model-snapshot",
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


def _profile(monkeypatch: pytest.MonkeyPatch) -> ModelProfile:
    monkeypatch.setenv(_API_KEY_ENV, "model-process-test-secret")
    return ModelProfile(
        provider="openai",
        model="test-model",
        expected_response_model="test-model-snapshot",
        immutable_response_model_attested=True,
        api_key_env=_API_KEY_ENV,
        max_output_tokens=2_000,
        timeout_seconds=10,
    )


def _provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    mode: str,
) -> SubprocessModelProvider:
    worker = tmp_path / "model-process-worker.py"
    worker.write_text(_WORKER_SOURCE, encoding="utf-8")
    monkeypatch.setattr(
        providers,
        "_model_worker_command",
        lambda: (sys.executable, str(worker), mode),
    )
    return SubprocessModelProvider(_profile(monkeypatch))


def _generate(
    provider: SubprocessModelProvider,
    *,
    timeout_seconds: float,
) -> ModelResult[ContributionPlan]:
    return provider.generate(
        instructions="Return a strict plan.",
        prompt="Fix the documented boundary.",
        output_type=ContributionPlan,
        max_output_tokens=1_000,
        timeout_seconds=timeout_seconds,
    )


def test_production_factory_cannot_select_the_in_process_sdk_adapter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert isinstance(providers.create_provider(_profile(monkeypatch)), SubprocessModelProvider)


def test_process_provider_round_trips_allowlisted_output_and_usage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _generate(_provider(tmp_path, monkeypatch, mode="success"), timeout_seconds=2)

    assert result.output.decision == "proceed"
    assert result.response_id == "response-process-test"
    assert result.model == "test-model-snapshot"
    assert result.usage == ModelUsage(
        input_tokens=11,
        cached_input_tokens=3,
        cache_write_tokens=2,
        output_tokens=7,
        reasoning_tokens=4,
        total_tokens=18,
    )


def test_process_provider_enforces_deadline_when_child_ignores_sdk_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = _provider(tmp_path, monkeypatch, mode="ignore-sdk-timeout")

    with pytest.raises(ModelTimeoutError) as raised:
        _generate(provider, timeout_seconds=0.15)

    assert raised.value.term_sent
    assert not raised.value.kill_sent
    assert raised.value.child_exit_code == -signal.SIGTERM


def test_process_provider_kills_sigterm_resistant_process_group_and_reaps_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = _provider(tmp_path, monkeypatch, mode="resist")

    with pytest.raises(ModelTimeoutError) as raised:
        _generate(provider, timeout_seconds=0.15)

    assert raised.value.term_sent
    assert raised.value.kill_sent
    assert raised.value.child_exit_code == -signal.SIGKILL


def test_process_provider_rejects_result_published_during_timeout_shutdown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = _provider(tmp_path, monkeypatch, mode="late")

    with pytest.raises(ModelTimeoutError) as raised:
        _generate(provider, timeout_seconds=0.15)

    assert raised.value.term_sent
    assert not raised.value.kill_sent


def test_process_provider_rejects_non_allowlisted_schema_before_spawning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ArbitraryOutput(BaseModel):
        value: str

    provider = _provider(tmp_path, monkeypatch, mode="success")

    with pytest.raises(ModelError, match="outside the production allowlist"):
        provider.generate(
            instructions="Return arbitrary output.",
            prompt="No.",
            output_type=ArbitraryOutput,
            timeout_seconds=1,
        )


def test_process_provider_rejects_noncanonical_ipc_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = _provider(tmp_path, monkeypatch, mode="noncanonical")

    with pytest.raises(ModelError, match="non-canonical IPC JSON"):
        _generate(provider, timeout_seconds=2)


def test_worker_error_envelope_round_trips_provider_request_status() -> None:
    from autocontribute import model_worker
    from autocontribute.exceptions import ModelRequestError
    from autocontribute.providers import _output_schema_id, _worker_result

    payload = model_worker._error_result(
        "provider_request_error",
        "OpenAI Responses request failed (HTTP 503)",
        http_status=503,
    )

    with pytest.raises(ModelRequestError) as raised:
        _worker_result(
            payload,
            output_type=ContributionPlan,
            output_schema=_output_schema_id(ContributionPlan),
        )

    assert raised.value.status_code == 503
    assert str(raised.value) == "OpenAI Responses request failed (HTTP 503)"


def test_worker_error_envelope_round_trips_statusless_request_failure() -> None:
    from autocontribute import model_worker
    from autocontribute.exceptions import ModelRequestError
    from autocontribute.providers import _output_schema_id, _worker_result

    payload = model_worker._error_result(
        "provider_request_error",
        "OpenAI Responses request failed",
    )

    with pytest.raises(ModelRequestError) as raised:
        _worker_result(
            payload,
            output_type=ContributionPlan,
            output_schema=_output_schema_id(ContributionPlan),
        )

    assert raised.value.status_code is None


@pytest.mark.parametrize("http_status", [200, 399, 600, True, "503"])
def test_worker_result_rejects_invalid_provider_http_status(http_status: object) -> None:
    from autocontribute.providers import (
        _MODEL_WORKER_PROTOCOL,
        _canonical_json_bytes,
        _output_schema_id,
        _worker_result,
    )

    payload = _canonical_json_bytes(
        {
            "protocol": _MODEL_WORKER_PROTOCOL,
            "status": "error",
            "error_code": "provider_request_error",
            "message": "OpenAI Responses request failed",
            "http_status": http_status,
        }
    )

    with pytest.raises(ModelError, match="invalid provider HTTP status"):
        _worker_result(
            payload,
            output_type=ContributionPlan,
            output_schema=_output_schema_id(ContributionPlan),
        )


def test_worker_result_rejects_http_status_on_other_error_codes() -> None:
    from autocontribute.providers import (
        _MODEL_WORKER_PROTOCOL,
        _canonical_json_bytes,
        _output_schema_id,
        _worker_result,
    )

    payload = _canonical_json_bytes(
        {
            "protocol": _MODEL_WORKER_PROTOCOL,
            "status": "error",
            "error_code": "provider_error",
            "message": "Model provider request failed",
            "http_status": 503,
        }
    )

    with pytest.raises(ModelError, match="invalid error envelope"):
        _worker_result(
            payload,
            output_type=ContributionPlan,
            output_schema=_output_schema_id(ContributionPlan),
        )


def test_worker_main_serializes_provider_request_error_with_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import os

    from autocontribute import model_worker
    from autocontribute.exceptions import ModelRequestError
    from autocontribute.providers import _output_schema_id, _worker_result

    def failing_execute(_payload: bytes) -> bytes:
        raise ModelRequestError("OpenAI Responses request failed (HTTP 429)", status_code=429)

    monkeypatch.setattr(model_worker, "_execute", failing_execute)
    request_read, request_write = os.pipe()
    result_read, result_write = os.pipe()
    os.write(request_write, b"{}")
    os.close(request_write)
    monkeypatch.setattr(
        sys,
        "argv",
        ["worker", "--request-fd", str(request_read), "--result-fd", str(result_write)],
    )

    assert model_worker.main() == 0

    payload = os.read(result_read, 65_536)
    os.close(result_read)
    with pytest.raises(ModelRequestError) as raised:
        _worker_result(
            payload,
            output_type=ContributionPlan,
            output_schema=_output_schema_id(ContributionPlan),
        )
    assert raised.value.status_code == 429
