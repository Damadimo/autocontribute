from __future__ import annotations

import hashlib
import itertools
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import JsonValue

from autocontribute.agent_loop import (
    AgentLoop,
    CheckReport,
    DidNotFinish,
    Finished,
    LoopFailure,
    SkippedIssue,
    Solver,
    SubmittedFix,
)
from autocontribute.agent_tools import SessionTools
from autocontribute.budget import RunBudget
from autocontribute.domain import CommandResult
from autocontribute.exceptions import ModelError, ModelRequestError, ModelTimeoutError
from autocontribute.instructions import load_instructions
from autocontribute.pricing import ModelUsage, Provider
from autocontribute.sandbox import SessionCommandResult, SessionContainer
from autocontribute.store import RunStore
from autocontribute.submissions import (
    AgentSubmission,
    ReviewBlocker,
    ReviewSubmission,
    TriageSubmission,
)
from autocontribute.transcript import (
    SUBMIT_TOOLS,
    ToolCall,
    Transcript,
    TranscriptKind,
    Turn,
    start_transcript,
)
from autocontribute.workspace_files import WorkspaceFiles

_MODELS: dict[Provider, str] = {"openai": "gpt-5.6-sol", "anthropic": "claude-opus-5-5"}
_PROVIDERS = pytest.mark.parametrize("provider", ["openai", "anthropic"])
_HOST_SECRET = "host-secret-value-0123456789"
_IDS = itertools.count(1)
_BUGGY = "def add(a, b):\n    return a - b\n"
_FIXED_SOURCE = "def add(a, b):\n    return a + b\n"
_FIX = {
    "outcome": "fixed",
    "skip_reason": None,
    "summary": "add subtracted its arguments; it now adds them.",
    "pr_title": "Fix add returning the difference",
    "pr_body": "add returned a - b. It now returns a + b.\n\nFixes #1",
    "commit_message": "Fix add returning the difference",
    "test_files": ["test_calc.py"],
    "test_command": "pytest -q test_calc.py",
}
_SKIP = {
    "outcome": "skip",
    "skip_reason": "The issue needs a design decision from the maintainers.",
    "summary": "Two behaviours are reasonable and the issue does not choose one.",
    "pr_title": None,
    "pr_body": None,
    "commit_message": None,
    "test_files": [],
    "test_command": None,
}


@dataclass(frozen=True)
class Shell:
    command: str
    options: dict[str, JsonValue] = field(default_factory=dict)


@dataclass(frozen=True)
class Write:
    path: str
    text: str


@dataclass(frozen=True)
class Replace:
    path: str
    old: str
    new: str


@dataclass(frozen=True)
class Submit:
    arguments: Mapping[str, JsonValue]
    name: str = "submit"


@dataclass(frozen=True)
class Raw:
    name: str
    arguments: dict[str, JsonValue]


Action = Shell | Write | Replace | Submit | Raw


def _native(provider: Provider, action: Action) -> tuple[str, dict[str, JsonValue]]:
    if isinstance(action, Shell):
        if provider == "openai":
            return "shell", {"commands": [action.command], **action.options}
        return "bash", {"command": action.command}
    if isinstance(action, Write):
        if provider == "openai":
            diff = "".join(f"+{line}\n" for line in action.text.splitlines())
            return "apply_patch", {"type": "create_file", "path": action.path, "diff": diff}
        return "str_replace_based_edit_tool", {
            "command": "create",
            "path": action.path,
            "file_text": action.text,
        }
    if isinstance(action, Replace):
        if provider == "openai":
            diff = f"@@\n-{action.old}\n+{action.new}\n"
            return "apply_patch", {"type": "update_file", "path": action.path, "diff": diff}
        return "str_replace_based_edit_tool", {
            "command": "str_replace",
            "path": action.path,
            "old_str": action.old,
            "new_str": action.new,
        }
    if isinstance(action, Submit):
        return action.name, dict(action.arguments)
    return action.name, action.arguments


def _item(provider: Provider, call: ToolCall) -> dict[str, JsonValue]:
    if provider == "anthropic":
        return {"type": "tool_use", "id": call.call_id, "name": call.name, "input": call.arguments}
    if call.name == "shell":
        return {
            "type": "shell_call",
            "call_id": call.call_id,
            "action": call.arguments,
            "status": "in_progress",
        }
    if call.name == "apply_patch":
        return {
            "type": "apply_patch_call",
            "call_id": call.call_id,
            "operation": call.arguments,
            "status": "completed",
        }
    return {
        "type": "function_call",
        "call_id": call.call_id,
        "name": call.name,
        "arguments": json.dumps(call.arguments),
    }


def turn(
    provider: Provider,
    *actions: Action,
    input_tokens: int = 1_000,
    output_tokens: int = 100,
    opaque: str = "opaque-reasoning",
) -> Turn:
    """A model turn that makes ``actions``, as the provider's adapter returns it."""

    number = next(_IDS)
    calls = []
    for action in actions:
        name, arguments = _native(provider, action)
        prefix = "call" if provider == "openai" else "toolu"
        calls.append(ToolCall(call_id=f"{prefix}_{next(_IDS)}", name=name, arguments=arguments))
    items: list[dict[str, JsonValue]] = [
        {"type": "reasoning", "id": f"rs_{number}", "summary": [], "encrypted_content": opaque}
        if provider == "openai"
        else {"type": "thinking", "thinking": "", "signature": opaque}
    ]
    items.extend(_item(provider, call) for call in calls)
    if not calls:
        items.append(
            {
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "I think it is done."}],
            }
            if provider == "openai"
            else {"type": "text", "text": "I think it is done."}
        )
    return Turn(
        stop="tool_use" if calls else "end_turn",
        output_items=tuple(items),
        tool_calls=tuple(calls),
        response_id=f"resp_{number}",
        model=_MODELS[provider],
        usage=_usage(input_tokens, output_tokens),
    )


def cut_off(provider: Provider, *, output_tokens: int) -> Turn:
    return Turn(
        stop="max_output_tokens",
        output_items=(),
        tool_calls=(),
        response_id=f"resp_{next(_IDS)}",
        model=_MODELS[provider],
        usage=_usage(1_000, output_tokens),
    )


def _usage(input_tokens: int, output_tokens: int) -> ModelUsage:
    return ModelUsage(
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        total_tokens=input_tokens + output_tokens,
    )


Step = Turn | ModelError | Callable[[Transcript], Turn]


class ScriptedProvider:
    """Plays a script of turns, provider errors and callbacks, and records each request."""

    def __init__(self, *steps: Step) -> None:
        self.steps = list(steps)
        self.requests: list[tuple[int, float]] = []

    def step(
        self, *, transcript: Transcript, max_output_tokens: int, timeout_seconds: float
    ) -> Turn:
        self.requests.append((max_output_tokens, timeout_seconds))
        step = self.steps.pop(0)
        if isinstance(step, ModelError):
            raise step
        if isinstance(step, Turn):
            return step
        return step(transcript)


class FakeSession:
    """Runs ``pytest`` against the real workspace: it passes once add adds."""

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace
        self.commands: list[str] = []
        self.answers: dict[str, CommandResult] = {}
        self.infrastructure_failure: str | None = None

    def exec(
        self,
        command: str,
        *,
        timeout_seconds: int,
        environment: Mapping[str, str] | None = None,
    ) -> SessionCommandResult:
        if command.startswith("file="):
            return SessionCommandResult(_command(command), None, restarted=False)
        self.commands.append(command)
        if command in self.answers:
            result = self.answers[command]
        elif command.startswith("pytest"):
            fixed = "a + b" in (self.workspace / "calc.py").read_text()
            result = _command(command, 0 if fixed else 1, "1 passed" if fixed else "1 failed")
        else:
            result = _command(command)
        return SessionCommandResult(result, self.infrastructure_failure, restarted=False)

    def save_output(self, number: int, text: str) -> str | None:
        return f"/tmp/ac-out/{number}.log"

    def restart(self) -> None:
        raise AssertionError("not expected")


def _command(command: str, exit_code: int = 0, stdout: str = "") -> CommandResult:
    return CommandResult(
        command=command, exit_code=exit_code, duration_seconds=0.1, stdout=stdout, stderr=""
    )


class FakeChecker:
    """Checks pass once add adds; the diff is the content of calc.py."""

    def __init__(self, workspace: Path, *, verdicts: list[bool] | None = None) -> None:
        self.workspace = workspace
        self.verdicts = verdicts
        self.checked: list[AgentSubmission] = []

    def diff_sha256(self) -> str:
        return hashlib.sha256((self.workspace / "calc.py").read_bytes()).hexdigest()

    def check(self, submission: AgentSubmission) -> CheckReport:
        self.checked.append(submission)
        passed = (
            self.verdicts.pop(0)
            if self.verdicts is not None
            else "a + b" in (self.workspace / "calc.py").read_text()
        )
        return CheckReport(
            passed=passed,
            diff_sha256=self.diff_sha256(),
            text=f"Checks {'passed' if passed else 'failed'} (check {len(self.checked)}).",
        )

    def check_text(self, submission: AgentSubmission) -> str | None:
        if "@everyone" in (submission.pr_body or ""):
            return "the text must not mention @everyone or @here"
        return None


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


@dataclass
class Harness:
    store: RunStore
    budget: RunBudget
    clock: Clock
    workspace: Path
    session: FakeSession
    sleeps: list[float]

    @property
    def run_id(self) -> str:
        return self.budget.manifest.run_id

    def transcript(
        self, provider: Provider, kind: TranscriptKind = "agent", task: str = "Fix issue #1."
    ) -> Transcript:
        return start_transcript(
            model=_MODELS[provider] if kind != "triage" else "claude-haiku-5-5",
            effort="high",
            kind=kind,
            run_id=self.run_id,
            instructions=load_instructions(kind),
            task=task,
            host_values=frozenset({_HOST_SECRET}),
        )

    def tools(self) -> SessionTools:
        return SessionTools(
            cast(SessionContainer, self.session),
            WorkspaceFiles(self.workspace),
            command_timeout_seconds=900,
            seconds_left=self.budget.seconds_left,
        )

    def solver(
        self,
        provider: ScriptedProvider,
        model: Provider,
        *,
        checker: FakeChecker | None = None,
        task: str = "Fix issue #1.",
        nested_guidance: Mapping[str, str] | None = None,
    ) -> Solver:
        return Solver(
            self.transcript(model, task=task),
            checker=checker or FakeChecker(self.workspace),
            provider=provider,
            budget=self.budget,
            store=self.store,
            host_values=frozenset({_HOST_SECRET}),
            tools=self.tools(),
            nested_guidance=nested_guidance,
            sleep=self.sleeps.append,
        )

    def events(self) -> list[tuple[str, dict[str, str]]]:
        return [
            (event["event_type"], json.loads(event["details"]))
            for event in self.store.events(self.run_id)
            if event["event_type"].startswith("model.")
        ]

    def artifact(self, name: str = "agent-1.jsonl") -> list[dict[str, Any]]:
        path = self.store.runs_dir / self.run_id / name
        return [json.loads(line) for line in path.read_text().splitlines()]


def _harness(tmp_path: Path, *, max_cost: str = "10", minutes: float = 90) -> Harness:
    store = RunStore(tmp_path / "state")
    clock = Clock()
    budget = RunBudget(
        store,
        store.create_run(),
        max_cost_usd=Decimal(max_cost),
        max_model_calls=200,
        max_run_minutes=minutes,
        assert_lease=lambda: None,
        clock=clock,
    )
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "calc.py").write_text(_BUGGY)
    return Harness(store, budget, clock, workspace, FakeSession(workspace), [])


@pytest.fixture
def harness(tmp_path: Path) -> Harness:
    return _harness(tmp_path)


def _texts(transcript: Transcript) -> list[str]:
    """Every text the model was sent after the task: tool results and user messages."""

    texts: list[str] = []
    for item in transcript.items:
        if item.get("type") == "message" and item.get("role") == "user":
            texts.extend(part["text"] for part in cast(list[dict[str, str]], item["content"]))
        elif item.get("type") in {"function_call_output", "apply_patch_call_output"}:
            texts.append(str(item["output"]))
        elif item.get("type") == "shell_call_output":
            chunks = cast(list[dict[str, str]], item["output"])
            texts.extend(chunk["stdout"] + chunk["stderr"] for chunk in chunks)
        elif item.get("role") == "user":
            for block in cast(list[dict[str, Any]], item["content"]):
                texts.append(str(block.get("text", block.get("content", ""))))
    return texts[1:]


@_PROVIDERS
def test_the_solver_reproduces_fixes_checks_and_confirms(
    harness: Harness, provider: Provider
) -> None:
    script = ScriptedProvider(
        turn(provider, Shell("pytest -q test_calc.py")),
        turn(provider, Replace("calc.py", "    return a - b", "    return a + b")),
        turn(provider, Shell("pytest -q test_calc.py"), Shell("git diff")),
        turn(provider, Submit(_FIX)),
        turn(provider, Submit(_FIX)),
    )
    checker = FakeChecker(harness.workspace)
    solver = harness.solver(script, provider, checker=checker)

    outcome = solver.run()

    assert isinstance(outcome, SubmittedFix)
    assert outcome.submission == AgentSubmission.model_validate(_FIX)
    assert outcome.check.passed
    assert len(checker.checked) == 1
    assert (harness.workspace / "calc.py").read_text() == _FIXED_SOURCE
    assert harness.session.commands == ["pytest -q test_calc.py"] * 2 + ["git diff"]
    texts = _texts(solver.loop.transcript)
    assert "Checks passed (check 1)." in texts[-2]
    assert "call submit again without changing anything to confirm" in texts[-2]
    assert texts[-1] == "Fix confirmed."
    manifest = harness.store.get(harness.run_id)
    assert manifest.model_calls == 5
    assert manifest.model_reservation is None
    assert manifest.model_cost_usd > 0
    assert [event for event, _ in harness.events()] == [
        "model.call.started",
        "model.call.completed",
    ] * 5
    assert harness.events()[0][1]["transcript"] == "agent-1"
    assert harness.events()[-2][1]["turn"] == "5"
    assert script.requests[0] == (32_000 if provider == "openai" else 64_000, 600)


def test_every_request_is_reserved_before_it_is_sent(harness: Harness) -> None:
    def reserved(transcript: Transcript) -> Turn:
        manifest = harness.store.get(harness.run_id)
        assert manifest.model_reservation is not None
        assert manifest.model_reservation.call == manifest.model_calls
        assert manifest.model_reservation.role == "agent"
        return turn("openai", Submit(_SKIP))

    outcome = harness.solver(ScriptedProvider(reserved), "openai").run()

    assert isinstance(outcome, SkippedIssue)


@_PROVIDERS
def test_skip_ends_the_attempt_with_its_reason(harness: Harness, provider: Provider) -> None:
    script = ScriptedProvider(turn(provider, Submit(_SKIP), Shell("touch late.txt")))
    solver = harness.solver(script, provider)

    outcome = solver.run()

    assert isinstance(outcome, SkippedIssue)
    assert outcome.reason == "The issue needs a design decision from the maintainers."
    # Calls after the one that ended the task do not run.
    assert harness.session.commands == []
    assert "Not run: an earlier call in this turn ended the task." in _texts(solver.loop.transcript)


@_PROVIDERS
def test_an_invalid_submit_gets_an_error_result_and_the_loop_goes_on(
    harness: Harness, provider: Provider
) -> None:
    incomplete = {**_FIX, "pr_title": None}
    script = ScriptedProvider(turn(provider, Submit(incomplete)), turn(provider, Submit(_SKIP)))
    solver = harness.solver(script, provider)

    outcome = solver.run()

    assert isinstance(outcome, SkippedIssue)
    error = _texts(solver.loop.transcript)[0]
    assert error.startswith("Invalid submit call: ")
    assert "outcome fixed needs pr_title" in error
    if provider == "anthropic":
        results = solver.loop.transcript.items[2]["content"]
        assert cast(list[dict[str, Any]], results)[0]["is_error"] is True


def test_a_changed_diff_is_checked_again_before_it_can_be_confirmed(harness: Harness) -> None:
    (harness.workspace / "calc.py").write_text(_FIXED_SOURCE)
    script = ScriptedProvider(
        turn("openai", Submit(_FIX)),
        turn("openai", Replace("calc.py", "    return a + b", "    return b + a")),
        turn("openai", Submit(_FIX)),
        turn("openai", Submit(_FIX)),
    )
    checker = FakeChecker(harness.workspace, verdicts=[True, True])

    outcome = harness.solver(script, "openai", checker=checker).run()

    assert isinstance(outcome, SubmittedFix)
    assert len(checker.checked) == 2
    assert outcome.check.text == "Checks passed (check 2)."


def test_the_confirming_submit_text_is_checked_and_used(harness: Harness) -> None:
    (harness.workspace / "calc.py").write_text(_FIXED_SOURCE)
    broadcast = {**_FIX, "pr_body": "@everyone please review.\n\nFixes #1"}
    final = {**_FIX, "pr_body": "add now adds.\n\nFixes #1"}
    script = ScriptedProvider(
        turn("openai", Submit(_FIX)),
        turn("openai", Submit(broadcast)),
        turn("openai", Submit(final)),
    )
    checker = FakeChecker(harness.workspace)
    solver = harness.solver(script, "openai", checker=checker)

    outcome = solver.run()

    assert isinstance(outcome, SubmittedFix)
    assert len(checker.checked) == 1
    assert outcome.submission.pr_body == "add now adds.\n\nFixes #1"
    assert _texts(solver.loop.transcript)[1] == (
        "The diff is unchanged, but the pull request text cannot be published: the text must "
        "not mention @everyone or @here. Correct it and call submit again. Submits left: 2."
    )


def test_the_third_failed_check_ends_the_round(harness: Harness) -> None:
    script = ScriptedProvider(*(turn("openai", Submit(_FIX)) for _ in range(3)))
    checker = FakeChecker(harness.workspace)
    solver = harness.solver(script, "openai", checker=checker)

    outcome = solver.run()

    assert outcome == DidNotFinish("submit_limit", "No further submit is allowed")
    assert len(checker.checked) == 3
    texts = _texts(solver.loop.transcript)
    assert texts[0].endswith("Fix the problems above and call submit again. Submits left: 3.")
    assert texts[2].endswith(
        "No submits are left for a fix and its confirmation, so the attempt ends here."
    )


def test_the_fourth_submit_can_only_confirm(harness: Harness) -> None:
    script = ScriptedProvider(
        turn("openai", Submit(_FIX)),
        turn("openai", Submit(_FIX)),
        turn("openai", Replace("calc.py", "    return a - b", "    return a + b")),
        turn("openai", Submit(_FIX)),
        turn("openai", Replace("calc.py", "    return a + b", "    return b + a")),
        turn("openai", Submit(_FIX)),
    )
    checker = FakeChecker(harness.workspace)

    outcome = harness.solver(script, "openai", checker=checker).run()

    assert isinstance(outcome, DidNotFinish)
    assert outcome.reason == "submit_limit"
    assert len(checker.checked) == 3


@_PROVIDERS
def test_turns_without_tool_calls_get_two_nudges(harness: Harness, provider: Provider) -> None:
    script = ScriptedProvider(turn(provider), turn(provider), turn(provider))
    solver = harness.solver(script, provider)

    outcome = solver.run()

    assert outcome == DidNotFinish(
        "no_tool_call", "The model kept ending turns without a tool call"
    )
    nudge = "Continue the task; call submit when you are done or submit with outcome skip."
    assert _texts(solver.loop.transcript) == [nudge, nudge]


@_PROVIDERS
def test_three_malformed_turns_in_a_row_end_the_attempt(
    harness: Harness, provider: Provider
) -> None:
    bad = (
        Raw("shell", {"commands": ["ls"], "timeout_ms": 0})
        if provider == "openai"
        else Raw("bash", {})
    )
    script = ScriptedProvider(
        turn(provider, bad),
        turn(provider, bad),
        turn(provider, Shell("ls")),
        turn(provider, bad, Submit({"outcome": "fixed"})),
        turn(provider, bad),
        turn(provider, bad),
    )

    outcome = harness.solver(script, provider).run()

    assert outcome == DidNotFinish("malformed", "3 turns in a row had only invalid tool calls")
    assert harness.session.commands == ["ls"]


def test_the_same_failing_command_three_times_in_a_row_ends_the_attempt(
    harness: Harness,
) -> None:
    script = ScriptedProvider(
        turn("anthropic", Shell("pytest -q")),
        turn("anthropic", Shell("pytest -q")),
        turn("anthropic", Write("notes.txt", "try again")),
        turn("anthropic", Shell("pytest -q")),
        turn("anthropic", Shell("pytest -q")),
        turn("anthropic", Shell("pytest -q")),
    )

    outcome = harness.solver(script, "anthropic").run()

    assert outcome == DidNotFinish("repeated_failure", "The same command failed 3 times in a row")
    assert harness.session.commands == ["pytest -q"] * 5


def test_a_token_in_tool_arguments_is_refused_with_a_request_for_a_placeholder(
    harness: Harness,
) -> None:
    token = "ghp_" + "A1b2C3d4" * 5
    script = ScriptedProvider(
        turn("openai", Shell(f"curl -H 'Authorization: token {token}' x")),
        turn("openai", Submit(_SKIP)),
    )
    solver = harness.solver(script, "openai")

    solver.run()

    assert harness.session.commands == []
    refusal = _texts(solver.loop.transcript)[0]
    assert refusal.startswith("Refused: the arguments contain what looks like a credential.")
    assert "placeholder" in refusal


@_PROVIDERS
def test_nested_guidance_follows_the_first_edit_under_its_directory(
    harness: Harness, provider: Provider
) -> None:
    script = ScriptedProvider(
        turn(provider, Write("other.py", "x = 1\n")),
        turn(provider, Write("pkg/sub/a.py", "a = 1\n")),
        turn(provider, Write("pkg/sub/b.py", "b = 1\n"), Write("docs/x.md", "x\n")),
        turn(provider, Submit(_SKIP)),
    )
    solver = harness.solver(
        script,
        provider,
        nested_guidance={"pkg/sub/": "Guidance for pkg/sub", "docs": "Guidance for docs"},
    )

    solver.run()

    texts = _texts(solver.loop.transcript)
    assert texts.count("Guidance for pkg/sub") == 1
    assert texts.count("Guidance for docs") == 1
    assert texts.index("Guidance for pkg/sub") == 2
    assert texts.index("Guidance for docs") == 5


def test_reminders_come_ten_turns_before_the_cap_which_ends_the_transcript(
    harness: Harness,
) -> None:
    script = ScriptedProvider(*(turn("openai", Shell(f"echo {n}")) for n in range(40)))
    loop = AgentLoop(
        harness.transcript("openai", kind="critic"),
        number=2,
        submission=ReviewSubmission,
        provider=script,
        budget=harness.budget,
        store=harness.store,
        host_values=frozenset(),
        tools=harness.tools(),
    )

    outcome = loop.run()

    assert outcome == DidNotFinish("turns", "The transcript reached its turn cap of 40")
    assert loop.turns == 40
    reminders = [text for text in _texts(loop.transcript) if text.startswith("Reminder")]
    assert reminders == ["Reminder: 10 turns are left. Finish up and call submit_review."]
    assert (harness.store.runs_dir / harness.run_id / "critic-2.jsonl").is_file()


def test_the_budget_reminder_then_the_budget_ends_the_transcript(tmp_path: Path) -> None:
    # The agent may spend $0.55 of a $1 run; the first turn spends $0.425 of it.
    harness = _harness(tmp_path, max_cost="1")
    script = ScriptedProvider(turn("openai", Shell("ls"), output_tokens=14_000))
    solver = harness.solver(script, "openai")

    outcome = solver.run()

    assert isinstance(outcome, DidNotFinish)
    assert outcome.reason == "budget"
    assert "agent budget" in outcome.detail
    assert _texts(solver.loop.transcript)[-1] == (
        "Reminder: about a quarter of the budget for this task is left. Finish up and call "
        "submit, or submit with outcome skip."
    )
    assert len(script.requests) == 1


def test_a_deadline_reached_between_turns_ends_the_transcript(harness: Harness) -> None:
    def slow(transcript: Transcript) -> Turn:
        harness.clock.now += 90 * 60
        return turn("openai", Shell("ls"))

    outcome = harness.solver(ScriptedProvider(slow), "openai").run()

    assert outcome == DidNotFinish("time", "The run reached its time limit")


@_PROVIDERS
def test_the_context_limit_gives_one_last_turn_that_needs_no_confirmation(
    harness: Harness, provider: Provider
) -> None:
    (harness.workspace / "calc.py").write_text(_FIXED_SOURCE)
    task = "Fix issue #1.\n" + "context " * 21_000
    checker = FakeChecker(harness.workspace)
    script = ScriptedProvider(
        turn(provider, Shell("cat calc.py"), input_tokens=170_000, output_tokens=30_000),
        turn(provider, Submit(_FIX)),
    )
    solver = harness.solver(script, provider, checker=checker, task=task)

    outcome = solver.run()

    assert isinstance(outcome, SubmittedFix)
    assert len(checker.checked) == 1
    texts = _texts(solver.loop.transcript)
    assert texts[1].startswith("This conversation has reached its length limit")
    assert texts[2] == "Checks passed (check 1)."


def test_the_last_turn_without_a_submission_does_not_finish(harness: Harness) -> None:
    task = "Fix issue #1.\n" + "context " * 21_000
    script = ScriptedProvider(
        turn("openai", Shell("ls"), input_tokens=170_000, output_tokens=30_000),
        turn("openai", Shell("ls")),
    )

    outcome = harness.solver(script, "openai", task=task).run()

    assert outcome == DidNotFinish("context", "The transcript reached its context limit")


def test_no_request_crosses_the_long_context_tier(harness: Harness) -> None:
    script = ScriptedProvider()

    outcome = harness.solver(script, "openai", task="x" * 280_000).run()

    assert outcome == DidNotFinish("context", "The transcript is too long for one more turn")
    assert script.requests == []


def test_a_transient_provider_error_is_retried_after_charging_the_attempt(
    harness: Harness,
) -> None:
    script = ScriptedProvider(
        ModelRequestError("overloaded", status_code=529, retry_after_seconds=4),
        turn("anthropic", Submit(_SKIP)),
    )

    outcome = harness.solver(script, "anthropic").run()

    assert isinstance(outcome, SkippedIssue)
    assert 4 <= harness.sleeps[0] <= 5
    events = harness.events()
    assert [event for event, _ in events] == [
        "model.call.started",
        "model.call.failed",
        "model.call.retry_scheduled",
        "model.call.started",
        "model.call.completed",
    ]
    reserved = Decimal(events[0][1]["reserved_cost_usd"])
    settled = Decimal(events[-1][1]["cost_usd"])
    assert harness.store.get(harness.run_id).model_cost_usd == reserved + settled


@pytest.mark.parametrize(
    ("errors", "message", "sleeps"),
    [
        ([ModelRequestError("bad request", status_code=400)], "bad request (HTTP 400)", 0),
        ([ModelError("Model refused the request")], "Model refused the request", 0),
        (
            [
                ModelTimeoutError(
                    timeout_seconds=600,
                    elapsed_seconds=600,
                    term_sent=True,
                    kill_sent=False,
                    child_exit_code=None,
                )
            ]
            * 3,
            "timeout after 3 attempts",
            2,
        ),
        (
            [ModelRequestError("rate limited", status_code=429, retry_after_seconds=100)],
            "rate limited (no time is left to retry)",
            0,
        ),
    ],
)
def test_provider_failures_end_the_loop_with_the_reservation_kept(
    tmp_path: Path, errors: list[ModelError], message: str, sleeps: int
) -> None:
    harness = _harness(tmp_path, minutes=1.5)
    script = ScriptedProvider(*errors)

    outcome = harness.solver(script, "openai").run()

    assert isinstance(outcome, LoopFailure)
    assert outcome.source == "provider"
    assert message in outcome.message
    assert len(harness.sleeps) == sleeps
    assert harness.store.get(harness.run_id).model_reservation is not None


@pytest.mark.parametrize(
    ("provider", "caps"),
    [("openai", [32_000, 64_000]), ("anthropic", [64_000, 128_000])],
)
def test_a_turn_cut_off_at_its_output_limit_is_sent_again_with_a_larger_one(
    harness: Harness, provider: Provider, caps: list[int]
) -> None:
    script = ScriptedProvider(
        cut_off(provider, output_tokens=caps[0]), turn(provider, Submit(_SKIP))
    )
    solver = harness.solver(script, provider)

    outcome = solver.run()

    assert isinstance(outcome, SkippedIssue)
    assert [cap for cap, _ in script.requests] == caps
    assert solver.loop.turns == 1


def test_a_turn_cut_off_twice_fails(harness: Harness) -> None:
    script = ScriptedProvider(
        cut_off("openai", output_tokens=32_000), cut_off("openai", output_tokens=64_000)
    )

    outcome = harness.solver(script, "openai").run()

    assert outcome == LoopFailure("provider", "The model's turn did not fit in 64000 output tokens")


def test_a_turn_cut_off_at_a_limit_the_budget_lowered_did_not_finish(tmp_path: Path) -> None:
    harness = _harness(tmp_path, max_cost="1")
    script = ScriptedProvider(lambda transcript: cut_off("openai", output_tokens=1_000))

    outcome = harness.solver(script, "openai").run()

    assert script.requests[0][0] < 32_000
    assert outcome == DidNotFinish("budget", "The budget left too little room for the turn")


def test_a_failed_sandbox_fails_the_loop(harness: Harness) -> None:
    harness.session.infrastructure_failure = "the sandbox container stopped"
    script = ScriptedProvider(turn("openai", Shell("pytest -q")))

    outcome = harness.solver(script, "openai").run()

    assert outcome == LoopFailure(
        "sandbox", "The sandbox failed during an agent command: the sandbox container stopped"
    )


@_PROVIDERS
def test_critic_blockers_continue_the_same_transcript_in_a_new_round(
    harness: Harness, provider: Provider
) -> None:
    script = ScriptedProvider(
        turn(provider, Replace("calc.py", "    return a - b", "    return a + b")),
        turn(provider, Submit(_FIX)),
        turn(provider, Submit(_FIX)),
        turn(provider, Write("test_calc.py", "def test_add():\n    assert add(2, 2) == 4\n")),
        turn(provider, Submit(_FIX)),
        turn(provider, Submit(_FIX)),
    )
    checker = FakeChecker(harness.workspace)
    solver = harness.solver(script, provider, checker=checker)
    assert isinstance(solver.run(), SubmittedFix)
    before = [json.dumps(item) for item in solver.loop.transcript.items]
    blocker = ReviewBlocker(
        category="weak_test",
        path="test_calc.py",
        line=None,
        evidence="No test asserts that add adds.",
        check_command=None,
        fix_hint="Add a test for add(2, 2).",
    )

    outcome = solver.address_blockers([blocker])

    assert isinstance(outcome, SubmittedFix)
    assert len(checker.checked) == 2
    after = [json.dumps(item) for item in solver.loop.transcript.items]
    # Only the last user message may gain the blockers (Anthropic joins it); the rest is kept.
    assert after[: len(before) - 1] == before[:-1]
    message = next(text for text in _texts(solver.loop.transcript) if "reviewer" in text)
    assert message.startswith("A reviewer checked the change you submitted")
    assert '"fix_hint": "Add a test for add(2, 2)."' in message
    assert solver.loop.turns == 6


def test_a_transcript_with_only_a_submit_tool_ends_at_its_first_submission(
    harness: Harness,
) -> None:
    triage = {
        "suitable": True,
        "reasons": ["Clear reproduction."],
        "already_fixed": False,
        "needs_design": False,
        "difficulty": "small",
    }
    script = ScriptedProvider(turn("anthropic", Submit(triage, name="submit_triage")))
    loop = AgentLoop(
        harness.transcript("anthropic", kind="triage"),
        number=3,
        submission=TriageSubmission,
        provider=script,
        budget=harness.budget,
        store=harness.store,
        host_values=frozenset(),
    )

    outcome = loop.run()

    assert outcome == Finished(TriageSubmission.model_validate(triage))
    assert script.requests[0][0] == 4_000
    assert harness.events()[0][1]["scope"] == "triage"


def test_triage_has_one_turn(harness: Harness) -> None:
    loop = AgentLoop(
        harness.transcript("anthropic", kind="triage"),
        number=1,
        submission=TriageSubmission,
        provider=ScriptedProvider(turn("anthropic")),
        budget=harness.budget,
        store=harness.store,
        host_values=frozenset(),
    )

    assert loop.run() == DidNotFinish("turns", "The transcript reached its turn cap of 1")


def test_the_transcript_artifact_is_redacted_except_opaque_fields(harness: Harness) -> None:
    harness.session.answers["env"] = _command(
        "env", stdout=f"DSN=https://admin:hunter2-secret@db.example\nKEY={_HOST_SECRET}\n"
    )
    opaque = "gAAAA-opaque password=hunter2hunter2hunter2"
    script = ScriptedProvider(
        turn("openai", Shell("env"), opaque=opaque), turn("openai", Submit(_SKIP))
    )

    harness.solver(script, "openai").run()

    lines = harness.artifact()
    assert lines[0]["kind"] == "agent"
    assert lines[0]["model"] == "gpt-5.6-sol"
    assert lines[0]["instructions"] == load_instructions("agent")
    reasoning = next(line for line in lines if line.get("type") == "reasoning")
    assert reasoning["encrypted_content"] == opaque
    text = "\n".join(json.dumps(line) for line in lines)
    assert "hunter2-secret" not in text
    assert _HOST_SECRET not in text
    assert "[REDACTED:" in text


def test_the_loop_checks_its_arguments(harness: Harness) -> None:
    transcript = harness.transcript("openai")
    common: dict[str, Any] = {
        "provider": ScriptedProvider(),
        "budget": harness.budget,
        "store": harness.store,
        "host_values": frozenset(),
    }

    with pytest.raises(ValueError, match="submit AgentSubmission"):
        AgentLoop(transcript, number=1, submission=ReviewSubmission, **common)
    with pytest.raises(ValueError, match="session tools"):
        AgentLoop(transcript, number=1, submission=AgentSubmission, **common)
    with pytest.raises(ValueError, match="root's guidance"):
        AgentLoop(
            transcript,
            number=1,
            submission=AgentSubmission,
            tools=harness.tools(),
            nested_guidance={"/": "root"},
            **common,
        )
    assert SUBMIT_TOOLS["agent"].arguments is AgentSubmission
