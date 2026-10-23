from __future__ import annotations

import json
import os
import signal
import sys
from pathlib import Path
from typing import Any

import pytest

import autocontribute.providers as providers
from autocontribute import anthropic_adapter, model_worker
from autocontribute.exceptions import (
    ConfigurationError,
    ModelError,
    ModelRequestError,
    ModelTimeoutError,
)
from autocontribute.pricing import API_KEY_ENVS, MODELS, ModelUsage
from autocontribute.providers import (
    _MODEL_TURN_PROTOCOL,
    _MODEL_WORKER_PROTOCOL,
    _WORKER_ENV_ALLOWLIST,
    MAX_TOOL_ARGUMENT_BYTES,
    SubprocessTurnProvider,
    _turn_result,
)
from autocontribute.transcript import (
    ToolCall,
    Transcript,
    TranscriptKind,
    Turn,
    append_turn,
    append_user_text,
    canonical_json,
)

_API_KEY = "openai-turn-process-test-key"
_RUN_ID = "0123456789abcdef"
# Records the request and the environment names it was started with, then replies.
_WORKER_SOURCE = r"""
import argparse
import json
import os
import time

parser = argparse.ArgumentParser()
parser.add_argument("reply")
parser.add_argument("record")
parser.add_argument("--request-fd", required=True, type=int)
parser.add_argument("--result-fd", required=True, type=int)
args = parser.parse_args()

request = b""
while chunk := os.read(args.request_fd, 65536):
    request += chunk
with open(args.record, "w", encoding="utf-8") as record:
    json.dump(
        {
            "request": json.loads(request),
            "environment": sorted(os.environ),
            "model_keys": {
                name: os.environ.get(name) for name in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY")
            },
        },
        record,
    )
if args.reply == "sleep":
    time.sleep(60)
with open(args.reply, "rb") as reply:
    os.write(args.result_fd, reply.read())
"""
_REASONING = {"id": "rs_1", "type": "reasoning", "summary": [], "encrypted_content": "gAAAA"}
_SHELL_CALL = {
    "id": "sh_1",
    "type": "shell_call",
    "call_id": "call_9d14ac6f2b73485e",
    "action": {"commands": ["cat hello.py"]},
    "status": "in_progress",
}
_USAGE = {
    "input_tokens": 2_412,
    "cached_input_tokens": 1_920,
    "cache_write_tokens": 380,
    "output_tokens": 160,
    "reasoning_tokens": 96,
    "total_tokens": 2_572,
}


def _reply(**overrides: object) -> dict[str, object]:
    reply: dict[str, object] = {
        "protocol": _MODEL_TURN_PROTOCOL,
        "status": "ok",
        "stop": "tool_use",
        "output_items": [_REASONING, _SHELL_CALL],
        "tool_calls": [
            {
                "call_id": "call_9d14ac6f2b73485e",
                "name": "shell",
                "arguments": {"commands": ["cat hello.py"]},
            }
        ],
        "response_id": "resp_68f9a1c2d2",
        "model": "gpt-5.6-sol",
        "usage": _USAGE,
    }
    return {**reply, **overrides}


def _transcript(model: str = "gpt-5.6-sol", kind: TranscriptKind = "agent") -> Transcript:
    transcript = Transcript(model=model, kind=kind, run_id=_RUN_ID, instructions="Fix the issue.")
    append_user_text(transcript, "Fix issue 12.")
    return transcript


def _provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reply: dict[str, object] | None = None,
    model: str = "gpt-5.6-sol",
) -> tuple[SubprocessTurnProvider, Path]:
    spec = MODELS[model]
    monkeypatch.setenv(API_KEY_ENVS[spec.provider], _API_KEY)
    worker = tmp_path / "turn-worker.py"
    worker.write_text(_WORKER_SOURCE, encoding="utf-8")
    record = tmp_path / "record.json"
    reply_argument = "sleep"
    if reply is not None:
        reply_path = tmp_path / "reply.json"
        reply_path.write_bytes(canonical_json(reply))
        reply_argument = str(reply_path)
    monkeypatch.setattr(
        providers,
        "_model_worker_command",
        lambda: (sys.executable, str(worker), reply_argument, str(record)),
    )
    return SubprocessTurnProvider(spec, "high"), record


def _parse(envelope: dict[str, object], kind: TranscriptKind = "agent") -> Turn:
    return _turn_result(canonical_json(envelope), spec=MODELS["gpt-5.6-sol"], kind=kind)


def test_turn_round_trips_through_a_worker_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider, record = _provider(tmp_path, monkeypatch, _reply())
    transcript = _transcript()

    turn = provider.step(transcript=transcript, max_output_tokens=32_000, timeout_seconds=30)

    assert turn == Turn(
        stop="tool_use",
        output_items=(_REASONING, _SHELL_CALL),
        tool_calls=(
            ToolCall(
                call_id="call_9d14ac6f2b73485e",
                name="shell",
                arguments={"commands": ["cat hello.py"]},
            ),
        ),
        response_id="resp_68f9a1c2d2",
        model="gpt-5.6-sol",
        usage=ModelUsage(**_USAGE),
    )
    assert json.loads(record.read_text(encoding="utf-8"))["request"] == {
        "protocol": "autocontribute.model-turn.v1",
        "model_id": "gpt-5.6-sol",
        "effort": "high",
        "instructions": "Fix the issue.",
        "transcript": {"kind": "agent", "run_id": _RUN_ID, "items": transcript.items},
        "max_output_tokens": 32_000,
        "timeout_seconds": 30.0,
    }


@pytest.mark.parametrize(
    ("model", "own_key", "other_key"),
    [
        ("gpt-5.6-sol", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"),
        ("claude-opus-5-5", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"),
    ],
)
def test_worker_environment_holds_only_allowlisted_names_and_the_model_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    model: str,
    own_key: str,
    other_key: str,
) -> None:
    provider, record = _provider(tmp_path, monkeypatch, _reply(model=model), model)
    sensitive = {
        "AUTOCONTRIBUTE_GITHUB_TOKEN": "github-token-placeholder",
        "GH_TOKEN": "gh-token-placeholder",
        "GITHUB_TOKEN": "actions-token-placeholder",
        other_key: "other-provider-key-placeholder",
        "AWS_SECRET_ACCESS_KEY": "aws-secret-placeholder",
        "DATABASE_PASSWORD": "database-password-placeholder",
        "DOCKER_HOST": "unix:///var/run/docker.sock",
        "HTTPS_PROXY": "http://user:pass@proxy.example:3128",
        "SSH_AUTH_SOCK": "/tmp/ssh-agent.sock",
    }
    for name, value in sensitive.items():
        monkeypatch.setenv(name, value)

    provider.step(transcript=_transcript(model), max_output_tokens=1_000, timeout_seconds=30)

    recorded = json.loads(record.read_text(encoding="utf-8"))
    # The interpreter adds LC_CTYPE when it coerces the C locale; macOS adds the last name.
    added_by_runtime = {"LC_CTYPE", "__CF_USER_TEXT_ENCODING"}
    allowlisted = {name for name in _WORKER_ENV_ALLOWLIST if name in os.environ}
    assert set(recorded["environment"]) - added_by_runtime == allowlisted | {own_key}
    assert not set(sensitive) & set(recorded["environment"])
    assert recorded["model_keys"] == {own_key: _API_KEY, other_key: None}


def test_step_refuses_a_transcript_bound_to_another_model(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider, record = _provider(tmp_path, monkeypatch, _reply())

    for model in ("claude-opus-5-5", "gpt-5.6-terra"):
        with pytest.raises(ModelError, match="bound to a different model"):
            provider.step(
                transcript=_transcript(model), max_output_tokens=1_000, timeout_seconds=30
            )

    assert not record.exists()


def test_step_refuses_a_transcript_that_is_not_waiting_for_the_model(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider, record = _provider(tmp_path, monkeypatch, _reply())
    empty = Transcript(model="gpt-5.6-sol", kind="agent", run_id=_RUN_ID, instructions="Fix it.")
    with_open_call = _transcript()
    append_turn(with_open_call, _parse(_reply()))

    for transcript in (empty, with_open_call):
        with pytest.raises(ModelError, match="not waiting for a model turn"):
            provider.step(transcript=transcript, max_output_tokens=1_000, timeout_seconds=30)

    assert not record.exists()


def test_step_kills_a_worker_that_outlives_the_turn_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider, _ = _provider(tmp_path, monkeypatch)

    with pytest.raises(ModelTimeoutError) as raised:
        provider.step(transcript=_transcript(), max_output_tokens=1_000, timeout_seconds=0.3)

    assert raised.value.term_sent
    assert raised.value.child_exit_code == -signal.SIGTERM


def test_oversized_request_is_refused_before_a_worker_starts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider, record = _provider(tmp_path, monkeypatch, _reply())
    monkeypatch.setattr(providers, "_MAX_MODEL_REQUEST_BYTES", 4_096)
    transcript = _transcript()
    append_user_text(transcript, "x" * 4_096)

    with pytest.raises(ModelError, match="request exceeded the bounded IPC limit"):
        provider.step(transcript=transcript, max_output_tokens=1_000, timeout_seconds=30)

    assert not record.exists()


def test_provider_needs_a_supported_effort_and_its_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", _API_KEY)
    with pytest.raises(ConfigurationError, match="does not support reasoning effort max"):
        SubprocessTurnProvider(MODELS["gpt-5.5"], "max")

    monkeypatch.delenv("OPENAI_API_KEY")
    with pytest.raises(ConfigurationError, match="OPENAI_API_KEY"):
        SubprocessTurnProvider(MODELS["gpt-5.6-sol"], "high")


def _oversized_arguments() -> dict[str, object]:
    return {"commands": ["x" * MAX_TOOL_ARGUMENT_BYTES]}


@pytest.mark.parametrize(
    ("kind", "envelope", "message"),
    [
        (
            "critic",
            _reply(
                tool_calls=[{"call_id": "call_1", "name": "apply_patch", "arguments": {}}],
            ),
            "outside its transcript's tool set",
        ),
        (
            "agent",
            _reply(tool_calls=[{"call_id": "call_1", "name": "edit", "arguments": {}}]),
            "outside its transcript's tool set",
        ),
        (
            "agent",
            _reply(tool_calls=[{"call_id": "call_1", "name": ["shell"], "arguments": {}}]),
            "outside its transcript's tool set",
        ),
        (
            "agent",
            {
                "protocol": _MODEL_TURN_PROTOCOL,
                "status": "error",
                "error_code": ["provider_error"],
                "message": "Model provider request failed",
            },
            "unknown error code",
        ),
        (
            "agent",
            _reply(
                tool_calls=[
                    {"call_id": "call_1", "name": "shell", "arguments": {}},
                    {"call_id": "call_1", "name": "apply_patch", "arguments": {}},
                ]
            ),
            "invalid turn",
        ),
        (
            "agent",
            _reply(
                tool_calls=[
                    {"call_id": "call_1", "name": "shell", "arguments": _oversized_arguments()}
                ]
            ),
            "exceeded the size limit",
        ),
        ("agent", _reply(model="gpt-5.6-terra"), "does not accept"),
        ("agent", _reply(model="gpt-5.6"), "does not accept"),
        ("agent", _reply(stop="pause_turn"), "invalid turn"),
        ("agent", _reply(stop="end_turn"), "invalid turn"),
        (
            "agent",
            _reply(
                tool_calls=[{"call_id": "call_1", "name": "shell", "arguments": {}, "extra": 1}]
            ),
            "invalid turn",
        ),
        (
            "agent",
            _reply(tool_calls=[{"call_id": "call 1", "name": "shell", "arguments": {}}]),
            "invalid turn",
        ),
        ("agent", _reply(output_items=["not an object"]), "invalid turn"),
        ("agent", _reply(tool_calls={"call_id": "call_1"}), "invalid tool calls"),
        ("agent", {**_reply(), "usage": {**_USAGE, "output_tokens": True}}, "invalid usage field"),
        ("agent", {**_reply(), "protocol": _MODEL_WORKER_PROTOCOL}, "incompatible IPC protocol"),
        (
            "agent",
            {key: value for key, value in _reply().items() if key != "stop"},
            "invalid success envelope",
        ),
    ],
    ids=[
        "tool-outside-kind",
        "other-providers-tool",
        "non-string-name",
        "non-string-error-code",
        "repeated-call-id",
        "oversized-arguments",
        "other-model",
        "unresolved-alias",
        "unknown-stop",
        "stop-without-calls",
        "extra-call-key",
        "unsafe-call-id",
        "non-object-item",
        "calls-not-a-list",
        "boolean-usage",
        "call-protocol",
        "missing-key",
    ],
)
def test_parent_rejects_invalid_turn_results(
    kind: TranscriptKind,
    envelope: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ModelError, match=message):
        _parse(envelope, kind)


def test_parent_accepts_the_tables_snapshot_ids_for_an_entry() -> None:
    turn = _turn_result(
        canonical_json(_reply(model="gpt-5.5-2026-04-23")),
        spec=MODELS["gpt-5.5"],
        kind="agent",
    )

    assert turn.model == "gpt-5.5-2026-04-23"


def test_parent_rejects_non_canonical_turn_json() -> None:
    with pytest.raises(ModelError, match="non-canonical IPC JSON"):
        _turn_result(json.dumps(_reply()).encode("utf-8"), spec=MODELS["gpt-5.6-sol"], kind="agent")


def _run_worker_main(monkeypatch: pytest.MonkeyPatch, request: dict[str, object]) -> bytes:
    request_read, request_write = os.pipe()
    result_read, result_write = os.pipe()
    os.write(request_write, canonical_json(request))
    os.close(request_write)
    monkeypatch.setattr(
        sys,
        "argv",
        ["worker", "--request-fd", str(request_read), "--result-fd", str(result_write)],
    )

    assert model_worker.main() == 0

    payload = os.read(result_read, 1 << 20)
    os.close(result_read)
    return payload


def _worker_request(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "protocol": _MODEL_TURN_PROTOCOL,
        "model_id": "gpt-5.6-sol",
        "effort": "high",
        "instructions": "Fix the issue.",
        "transcript": {"kind": "agent", "run_id": _RUN_ID, "items": _transcript().items},
        "max_output_tokens": 32_000,
        "timeout_seconds": 600.0,
    }
    return {**request, **overrides}


def test_worker_answers_a_turn_request_from_the_adapter(monkeypatch: pytest.MonkeyPatch) -> None:
    expected = _parse(_reply())
    seen: list[Any] = []

    def step(request: providers.TurnRequest) -> Turn:
        seen.append(request)
        return expected

    monkeypatch.setattr(model_worker.openai_adapter, "step", step)

    payload = _run_worker_main(monkeypatch, _worker_request())

    assert _turn_result(payload, spec=MODELS["gpt-5.6-sol"], kind="agent") == expected
    assert seen == [
        providers.TurnRequest(
            spec=MODELS["gpt-5.6-sol"],
            effort="high",
            instructions="Fix the issue.",
            kind="agent",
            run_id=_RUN_ID,
            items=_transcript().items,
            max_output_tokens=32_000,
            timeout_seconds=600.0,
        )
    ]


def test_worker_sends_anthropic_turns_to_the_anthropic_adapter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bash_call = {
        "type": "tool_use",
        "id": "toolu_01A09q90qw90lq917835lq9",
        "name": "bash",
        "input": {"command": "cat hello.py"},
    }
    expected = Turn(
        stop="tool_use",
        output_items=(bash_call,),
        tool_calls=(ToolCall(call_id=bash_call["id"], name="shell", arguments=bash_call["input"]),),
        response_id="msg_01XFDUDYJgAACzvnptvVoYEL",
        model="claude-opus-5-5",
        usage=ModelUsage(**_USAGE),
    )
    seen: list[str] = []

    def step(request: providers.TurnRequest) -> Turn:
        seen.append(request.spec.id)
        return expected

    monkeypatch.setattr(anthropic_adapter, "step", step)
    monkeypatch.setattr(
        model_worker.openai_adapter,
        "step",
        lambda _request: pytest.fail("the OpenAI adapter must not run"),
    )
    items = _transcript("claude-opus-5-5").items

    payload = _run_worker_main(
        monkeypatch,
        _worker_request(
            model_id="claude-opus-5-5",
            transcript={"kind": "agent", "run_id": _RUN_ID, "items": items},
            max_output_tokens=64_000,
        ),
    )

    assert _turn_result(payload, spec=MODELS["claude-opus-5-5"], kind="agent") == expected
    assert seen == ["claude-opus-5-5"]


def test_worker_reports_turn_failures_in_the_turn_protocol(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def step(_request: providers.TurnRequest) -> Turn:
        raise ModelRequestError(
            "OpenAI Responses request failed (HTTP 429; code: insufficient_quota)",
            status_code=429,
            provider_code="insufficient_quota",
            retry_after_seconds=3.0,
        )

    monkeypatch.setattr(model_worker.openai_adapter, "step", step)

    payload = _run_worker_main(monkeypatch, _worker_request())

    with pytest.raises(ModelRequestError) as raised:
        _turn_result(payload, spec=MODELS["gpt-5.6-sol"], kind="agent")
    assert (
        raised.value.status_code,
        raised.value.provider_code,
        raised.value.retry_after_seconds,
    ) == (429, "insufficient_quota", 3.0)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"model_id": "gpt-5.6"}, "outside the built-in table"),
        ({"model_id": "gpt-5.5", "effort": "max"}, "effort the model does not support"),
        ({"instructions": None}, "invalid request text"),
        ({"transcript": {"kind": "agent", "items": []}}, "invalid transcript"),
        ({"transcript": {"kind": "review", "run_id": _RUN_ID, "items": []}}, "invalid transcript"),
        (
            {"transcript": {"kind": "agent", "run_id": _RUN_ID, "items": ["x"]}},
            "invalid transcript",
        ),
        ({"max_output_tokens": 0}, "invalid output-token limit"),
        ({"max_output_tokens": 128_001}, "invalid output-token limit"),
        ({"timeout_seconds": 600.5}, "invalid request timeout"),
        ({"timeout_seconds": True}, "invalid request timeout"),
        ({"unexpected": 1}, "invalid IPC request"),
    ],
)
def test_worker_validates_turn_requests(
    monkeypatch: pytest.MonkeyPatch,
    overrides: dict[str, object],
    message: str,
) -> None:
    monkeypatch.setattr(
        model_worker.openai_adapter,
        "step",
        lambda _request: pytest.fail("the adapter must not run"),
    )

    payload = _run_worker_main(monkeypatch, _worker_request(**overrides))

    with pytest.raises(ModelError, match=message):
        _turn_result(payload, spec=MODELS["gpt-5.6-sol"], kind="agent")
