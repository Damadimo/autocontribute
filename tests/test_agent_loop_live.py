"""Opt-in test that drives the real agent loop against a real Docker session.

A scripted provider stands in for the model; everything else is real: the budget and the
store, the session container, host-side edits with the in-container syntax check, saved
output, and patch extraction. Enabled by the security-integration workflow.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from pydantic import JsonValue

from autocontribute.agent_loop import CheckReport, Solver, SubmittedFix
from autocontribute.agent_tools import SessionTools
from autocontribute.budget import RunBudget
from autocontribute.config import SandboxConfig
from autocontribute.instructions import load_instructions
from autocontribute.patches import extract_patch
from autocontribute.pricing import ModelUsage, Provider
from autocontribute.repository import RepositoryWorkspace
from autocontribute.sandbox import SessionContainer, docker_client_environment
from autocontribute.store import RunStore
from autocontribute.submissions import AgentSubmission
from autocontribute.transcript import ToolCall, Transcript, Turn, start_transcript
from autocontribute.workspace_files import WorkspaceFiles

pytestmark = pytest.mark.skipif(
    os.environ.get("AUTOCONTRIBUTE_RUN_DOCKER_TESTS") != "1",
    reason="set AUTOCONTRIBUTE_RUN_DOCKER_TESTS=1 to run live Docker isolation tests",
)

# The smallest official Python image, as in test_sandbox_live.py.
_PYTHON = "python@sha256:e32be0e55814a08977501ca863271d9bd02443710db8f2afaf8372e2c4508530"
_SESSION_CONFIG = SandboxConfig(memory="512m", cpus=1.0, pids_limit=64)
_MODELS: dict[Provider, str] = {"openai": "gpt-5.6-sol", "anthropic": "claude-opus-5-5"}
_TEST_COMMAND = "python -m unittest -q test_calc"
# The fix keeps calc.py's size, so bytecode cached within the same second would hide it.
_ENVIRONMENT = {"PYTHONDONTWRITEBYTECODE": "1"}
_FIX: dict[str, JsonValue] = {
    "outcome": "fixed",
    "skip_reason": None,
    "summary": "add subtracted its arguments; it now adds them.",
    "pr_title": "Fix add returning the difference",
    "pr_body": "add returned a - b. It now returns a + b.\n\nFixes #1",
    "commit_message": "Fix add returning the difference",
    "test_files": ["test_calc.py"],
    "test_command": _TEST_COMMAND,
}
_IDS = itertools.count(1)


def _docker(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *arguments],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
        env=docker_client_environment(),
    )


@pytest.fixture(scope="module")
def python_image() -> Iterator[str]:
    if shutil.which("docker") is None:
        pytest.fail("live Docker tests were requested but Docker is not installed")
    present = _docker("image", "inspect", _PYTHON).returncode == 0
    if not present:
        pulled = _docker("pull", "--quiet", _PYTHON)
        assert pulled.returncode == 0, pulled.stderr
    try:
        yield _PYTHON
    finally:
        if not present:
            _docker("image", "rm", _PYTHON)


@pytest.fixture
def live_root() -> Iterator[Path]:
    # Colima shares only $HOME with its VM, and pytest's tmp_path is outside it on macOS.
    with tempfile.TemporaryDirectory(
        prefix=".autocontribute-live-", dir=Path(__file__).resolve().parents[1]
    ) as temporary:
        yield Path(temporary)


def _fixture_repository(root: Path) -> RepositoryWorkspace:
    source = root / "source"
    source.mkdir()
    (source / ".gitignore").write_text("__pycache__/\n", encoding="utf-8")
    (source / "calc.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
    (source / "test_calc.py").write_text(
        "import unittest\n\nfrom calc import add\n\n\n"
        "class AddTest(unittest.TestCase):\n"
        "    def test_adds(self):\n"
        "        self.assertEqual(add(2, 3), 5)\n",
        encoding="utf-8",
    )
    environment = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
    for arguments in (
        ["init", "--quiet"],
        ["add", "."],
        ["-c", "user.name=F", "-c", "user.email=f@example.invalid", "commit", "-qm", "base"],
    ):
        subprocess.run(["git", *arguments], cwd=source, env=environment, check=True)
    base = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=source,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return RepositoryWorkspace.clone(str(source), base, root / "work", allow_local_source=True)


class _Checker:
    """The submit checks, reduced to what this fixture needs: a patch and a passing test."""

    def __init__(self, workspace: RepositoryWorkspace, session: SessionContainer) -> None:
        self.workspace = workspace
        self.session = session
        self.checks = 0

    def diff_sha256(self) -> str:
        return hashlib.sha256(extract_patch(self.workspace).text.encode()).hexdigest()

    def check(self, submission: AgentSubmission) -> CheckReport:
        self.checks += 1
        patch = extract_patch(self.workspace)
        tests = self.session.exec(
            submission.test_command or _TEST_COMMAND, timeout_seconds=60, environment=_ENVIRONMENT
        )
        passed = bool(patch.files) and tests.result.passed
        return CheckReport(
            passed=passed,
            diff_sha256=hashlib.sha256(patch.text.encode()).hexdigest(),
            text=f"{patch.text}\nTests: exit {tests.result.exit_code}",
        )

    def check_text(self, submission: AgentSubmission) -> str | None:
        return None


def _call(provider: Provider, name: str, arguments: dict[str, JsonValue]) -> ToolCall:
    prefix = "call" if provider == "openai" else "toolu"
    return ToolCall(call_id=f"{prefix}_{next(_IDS)}", name=name, arguments=arguments)


def _shell(provider: Provider, *commands: str) -> list[ToolCall]:
    if provider == "openai":
        return [_call(provider, "shell", {"commands": list(commands), "timeout_ms": 60_000})]
    return [_call(provider, "bash", {"command": command}) for command in commands]


def _fix(provider: Provider) -> ToolCall:
    if provider == "openai":
        diff = "@@\n def add(a, b):\n-    return a - b\n+    return a + b\n"
        return _call(
            provider, "apply_patch", {"type": "update_file", "path": "calc.py", "diff": diff}
        )
    return _call(
        provider,
        "str_replace_based_edit_tool",
        {
            "command": "str_replace",
            "path": "/workspace/calc.py",
            "old_str": "return a - b",
            "new_str": "return a + b",
        },
    )


def _turn(provider: Provider, calls: list[ToolCall]) -> Turn:
    items: list[dict[str, JsonValue]] = []
    for call in calls:
        if provider == "anthropic":
            items.append(
                {"type": "tool_use", "id": call.call_id, "name": call.name, "input": call.arguments}
            )
        elif call.name == "shell":
            items.append({"type": "shell_call", "call_id": call.call_id, "action": call.arguments})
        elif call.name == "apply_patch":
            items.append(
                {"type": "apply_patch_call", "call_id": call.call_id, "operation": call.arguments}
            )
        else:
            items.append(
                {
                    "type": "function_call",
                    "call_id": call.call_id,
                    "name": call.name,
                    "arguments": json.dumps(call.arguments),
                }
            )
    return Turn(
        stop="tool_use",
        output_items=tuple(items),
        tool_calls=tuple(calls),
        response_id=f"resp_{next(_IDS)}",
        model=_MODELS[provider],
        usage=ModelUsage(input_tokens=1_000, output_tokens=100, total_tokens=1_100),
    )


class _ScriptedProvider:
    def __init__(self, turns: list[Turn]) -> None:
        self.turns = turns

    def step(
        self, *, transcript: Transcript, max_output_tokens: int, timeout_seconds: float
    ) -> Turn:
        return self.turns.pop(0)


def _results(transcript: Transcript) -> list[str]:
    """The text of every tool result, in order."""

    texts: list[str] = []
    for item in transcript.items:
        if item.get("type") == "shell_call_output":
            chunks: Any = item["output"]
            texts.extend(chunk["stdout"] + chunk["stderr"] for chunk in chunks)
        elif item.get("type") in {"apply_patch_call_output", "function_call_output"}:
            texts.append(str(item["output"]))
        elif item.get("role") == "user":
            blocks: Any = item["content"]
            texts.extend(block["content"] for block in blocks if block["type"] == "tool_result")
    return texts


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
def test_live_agent_loop_fixes_a_fixture_repository_in_a_real_session(
    live_root: Path, python_image: str, provider: Provider
) -> None:
    workspace = _fixture_repository(live_root)
    store = RunStore(live_root / "state")
    manifest = store.create_run()
    budget = RunBudget(
        store,
        manifest,
        max_cost_usd=Decimal(10),
        max_model_calls=200,
        max_run_minutes=10,
        assert_lease=lambda: None,
    )
    script = _ScriptedProvider(
        [
            _turn(provider, _shell(provider, _TEST_COMMAND, "seq 1 5000")),
            _turn(provider, _shell(provider, "wc -l < /tmp/ac-out/1.log")),
            _turn(provider, [_fix(provider)]),
            _turn(provider, _shell(provider, _TEST_COMMAND, "cat calc.py")),
            _turn(provider, [_call(provider, "submit", _FIX)]),
            _turn(provider, [_call(provider, "submit", _FIX)]),
        ]
    )
    transcript = start_transcript(
        model=_MODELS[provider],
        effort="high",
        kind="agent",
        run_id=manifest.run_id,
        instructions=load_instructions("agent"),
        task="Fix issue #1: add(2, 3) returns -1.",
        host_values=frozenset(),
    )

    with SessionContainer(
        _SESSION_CONFIG,
        image=python_image,
        workspace=workspace.path,
        run_id=manifest.run_id,
        store_root=store.root,
    ) as session:
        name = session.name
        checker = _Checker(workspace, session)
        solver = Solver(
            transcript,
            checker=checker,
            provider=script,
            budget=budget,
            store=store,
            host_values=frozenset(),
            tools=SessionTools(
                session,
                WorkspaceFiles(workspace.path),
                command_timeout_seconds=_SESSION_CONFIG.command_timeout_seconds,
                seconds_left=budget.seconds_left,
                environment=_ENVIRONMENT,
            ),
        )
        outcome = solver.run()

    assert _docker("container", "inspect", name).returncode != 0, "session was not removed"
    assert isinstance(outcome, SubmittedFix), outcome
    assert checker.checks == 1
    assert extract_patch(workspace).paths == ("calc.py",)
    results = _results(solver.loop.transcript)
    failing_run, long_output, saved_lines, edit, passing_run, source = results[:6]
    assert "FAILED (failures=1)" in failing_run
    assert "The full output is in /tmp/ac-out/1.log." in long_output
    assert len(long_output) < 10_200
    assert saved_lines.strip() == "5000"
    assert "syntax check" not in edit
    assert "FAILED" not in passing_run
    assert "return a + b" in source
    assert results[-1] == "Fix confirmed."
    saved = store.get(manifest.run_id)
    assert saved.model_calls == 6
    assert saved.model_reservation is None
    artifact = store.runs_dir / manifest.run_id / "agent-1.jsonl"
    assert len(artifact.read_text().splitlines()) == 1 + len(solver.loop.transcript.items)
