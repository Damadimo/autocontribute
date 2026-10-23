from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from decimal import Decimal
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import JsonValue
from test_agent_loop import FakeSession, ScriptedProvider, Shell, Submit, turn
from test_task_messages import _check, _facts

from autocontribute.agent_loop import CheckReport, DidNotFinish, SubmittedFix
from autocontribute.budget import RunBudget
from autocontribute.critic import MAX_CRITIC_ROUNDS, Critic, CriticRound
from autocontribute.pricing import Provider
from autocontribute.sandbox import SessionContainer
from autocontribute.store import RunStore
from autocontribute.submissions import AgentSubmission
from autocontribute.suite_runs import CheckRun, SuiteRun

_MODELS: dict[Provider, str] = {"openai": "gpt-5.6-sol", "anthropic": "claude-opus-5-5"}
_PROVIDERS = pytest.mark.parametrize("provider", ["openai", "anthropic"])
_PATCH = (
    "diff --git a/calc.py b/calc.py\n--- a/calc.py\n+++ b/calc.py\n@@ -1,2 +1,2 @@\n"
    " def add(a, b):\n-    return a - b\n+    return a + b\n"
)
_FIX = SubmittedFix(
    submission=AgentSubmission(
        outcome="fixed",
        skip_reason=None,
        summary="add subtracted; it adds now.",
        pr_title="Fix add",
        pr_body="This fixes all known bugs in calc.\n\nFixes #7",
        commit_message="Fix add",
        test_files=["tests/test_calc.py"],
        test_command=None,
    ),
    check=CheckReport(passed=True, diff_sha256="c" * 64, text="Checks passed."),
)


class FakeSandbox:
    """Review sessions on the copy they get, and check commands answered from a table."""

    def __init__(self, checks: Mapping[str, CheckRun] | None = None) -> None:
        self.checks = dict(checks or {})
        self.sessions: list[Path] = []
        self.checked: list[tuple[str, str]] = []

    @property
    def environment(self) -> Mapping[str, str]:
        return {"PATH": "/usr/bin:/bin"}

    def run_suite(
        self, source: Path, *, timeout_seconds: int, test_command: str | None = None
    ) -> SuiteRun:
        raise AssertionError("the critic runs no suite")

    def run_check(self, source: Path, command: str, *, timeout_seconds: int) -> CheckRun:
        self.checked.append((source.name, command))
        return self.checks[command]

    @contextmanager
    def session(self, workspace: Path, *, timeout_seconds: int) -> Iterator[SessionContainer]:
        assert (workspace / "calc.py").is_file()
        self.sessions.append(workspace)
        yield cast(SessionContainer, FakeSession(workspace))


class Harness:
    def __init__(self, tmp_path: Path, sandbox: FakeSandbox, provider: Provider) -> None:
        self.store = RunStore(tmp_path / "state")
        self.budget = RunBudget(
            self.store,
            self.store.create_run(),
            max_cost_usd=Decimal(10),
            max_model_calls=200,
            max_run_minutes=90,
            assert_lease=lambda: None,
        )
        self.validated = tmp_path / "run" / "repository.validation"
        (self.validated / "docs").mkdir(parents=True)
        (self.validated / "calc.py").write_text("def add(a, b):\n    return a + b\n")
        (self.validated / "docs" / "STYLE.md").write_text("Never print from library code.\n")
        self.sandbox = sandbox
        self.provider = provider
        self.script = ScriptedProvider()
        self.critic = Critic(
            _facts(),
            sandbox,
            provider=self.script,
            model=_MODELS[provider],
            budget=self.budget,
            store=self.store,
            host_values=frozenset(),
            command_timeout_seconds=900,
            guidance_paths=["CONTRIBUTING.md"],
        )

    def review(self, *reviews: Mapping[str, JsonValue], **check: Any) -> Any:
        self.script.steps = [
            turn(self.provider, Shell("python -m pytest -q")),
            *(turn(self.provider, Submit(review, name="submit_review")) for review in reviews),
        ]
        return self.critic.review(_FIX, _check(**check), patch=_PATCH, validated=self.validated)

    def first_message(self, round_number: int) -> str:
        path = self.store.runs_dir / self.budget.manifest.run_id / f"critic-{round_number}.jsonl"
        lines = [json.loads(line) for line in path.read_text().splitlines()]
        first = lines[1]
        content = first["content"][0]
        return str(content.get("text"))


def _review(
    verdict: str = "approve", *blockers: dict[str, JsonValue], **changes: Any
) -> dict[str, JsonValue]:
    return {
        "verdict": verdict,
        "blockers": list(blockers),
        "notes": [],
        "no_test_needed": False,
        "summary": "Checked the fix and its test.",
        **changes,
    }


def _blocker(
    category: str, evidence: str, command: str | None, path: str | None = "calc.py"
) -> dict[str, JsonValue]:
    return {
        "category": category,
        "path": path,
        "line": None,
        "evidence": evidence,
        "check_command": command,
        "fix_hint": "Fix it.",
    }


def _ran(exit_code: int, **changes: Any) -> CheckRun:
    return CheckRun(
        **{
            "exit_code": exit_code,
            "timed_out": False,
            "failure": None,
            "output_tail": "",
            **changes,
        }
    )


@_PROVIDERS
def test_an_approval_reviews_a_throwaway_copy_of_the_validated_tree(
    tmp_path: Path, provider: Provider
) -> None:
    harness = Harness(tmp_path, FakeSandbox(), provider)

    outcome = harness.review(_review())

    assert isinstance(outcome, CriticRound)
    assert outcome.number == 1 and outcome.decision == "approve" and not outcome.confirmed
    (session,) = harness.sandbox.sessions
    assert session.name.startswith("repository.validation.review-")
    assert not session.exists() and harness.validated.exists()
    message = harness.first_message(1)
    assert "This is review round 1." in message
    assert "Blockers from the previous round" not in message


def test_blockers_are_kept_only_when_their_check_fails_or_their_quote_is_there(
    tmp_path: Path,
) -> None:
    sandbox = FakeSandbox(
        {
            "check bug": _ran(1),
            "check fixed": _ran(0),
            "check missing": _ran(127),
            "check slow": _ran(124, timed_out=True),
            "check broken": _ran(2, failure="the build command failed with exit 2: make"),
        }
    )
    harness = Harness(tmp_path, sandbox, "openai")
    bug = _blocker("definite_bug", "add drops b", "check bug")
    claim = _blocker("misleading_text", 'The body says "This fixes all known bugs in calc."', None)
    rule = _blocker(
        "policy_violation",
        'docs/STYLE.md says "Never print from library code."',
        None,
        path="docs/STYLE.md",
    )

    outcome = harness.review(
        _review(
            "request_changes",
            bug,
            _blocker("issue_not_fixed", "still wrong", "check fixed"),
            _blocker("regression", "breaks x", None),
            _blocker("weak_test", "flaky", "check missing"),
            _blocker("risky_change", "slow", "check slow"),
            _blocker("definite_bug", "build", "check broken"),
            claim,
            rule,
            _blocker("scope_creep", "The hunk `print('debugging here')` is unrelated", None),
        )
    )

    assert isinstance(outcome, CriticRound) and outcome.decision == "request_changes"
    assert [blocker.model_dump() for blocker in outcome.confirmed] == [bug, claim, rule]
    assert [dropped.reason for dropped in outcome.dropped] == [
        "its check passes",
        "it has no check command",
        "its check could not run",
        "its check could not run",
        "its check could not run: the build command failed with exit 2: make",
        "the passage it quotes is not there",
    ]
    assert all(source == "repository.validation" for source, _ in sandbox.checked)


def test_round_two_sees_round_one_and_rejects_a_repeated_blocker(tmp_path: Path) -> None:
    harness = Harness(tmp_path, FakeSandbox({"check bug": _ran(1)}), "anthropic")
    bug = _blocker("definite_bug", "add drops b", "check bug")
    first = harness.review(_review("request_changes", bug))
    assert isinstance(first, CriticRound) and first.decision == "request_changes"

    second = harness.review(_review("request_changes", {**bug, "line": 2}))

    assert isinstance(second, CriticRound) and second.decision == "reject"
    assert second.reason == "blockers from review round 1 are still there: definite_bug in calc.py"
    message = harness.first_message(2)
    assert "This is review round 2." in message and "Blockers from the previous round" in message
    with pytest.raises(ValueError, match=f"at most {MAX_CRITIC_ROUNDS} rounds"):
        harness.critic.review(_FIX, _check(), patch=_PATCH, validated=harness.validated)


def test_new_blockers_in_the_last_round_reject_the_run(tmp_path: Path) -> None:
    harness = Harness(
        tmp_path, FakeSandbox({"check bug": _ran(1), "check other": _ran(1)}), "openai"
    )
    harness.review(_review("request_changes", _blocker("definite_bug", "x", "check bug")))

    second = harness.review(
        _review("request_changes", _blocker("regression", "y", "check other", path="other.py"))
    )

    assert isinstance(second, CriticRound) and second.decision == "reject"
    assert second.reason == "blockers remain after the last review round: regression in other.py"


def test_round_two_approves_once_the_blockers_are_fixed(tmp_path: Path) -> None:
    harness = Harness(tmp_path, FakeSandbox({"check bug": _ran(1)}), "openai")
    harness.review(_review("request_changes", _blocker("definite_bug", "x", "check bug")))

    second = harness.review(_review("approve"))

    assert isinstance(second, CriticRound) and second.decision == "approve"


def test_abandon_rejects_the_run(tmp_path: Path) -> None:
    harness = Harness(tmp_path, FakeSandbox(), "openai")

    outcome = harness.review(_review("abandon", summary="The issue needs a design decision."))

    assert isinstance(outcome, CriticRound) and outcome.decision == "reject"
    assert outcome.reason == (
        "the reviewer abandoned the change: The issue needs a design decision."
    )


def test_a_source_change_without_a_test_needs_the_critics_waiver(tmp_path: Path) -> None:
    harness = Harness(tmp_path, FakeSandbox(), "openai")

    unwaived = harness.review(_review(), test_waiver_needed=True)

    assert isinstance(unwaived, CriticRound) and unwaived.decision == "request_changes"
    assert [blocker.category for blocker in unwaived.confirmed] == ["weak_test"]
    assert "No test" in harness.first_message(1)

    waived = harness.review(_review(no_test_needed=True), test_waiver_needed=True)
    assert isinstance(waived, CriticRound) and waived.decision == "approve"


def test_a_critic_that_never_submits_did_not_finish(tmp_path: Path) -> None:
    harness = Harness(tmp_path, FakeSandbox(), "openai")
    harness.script.steps = [turn("openai") for _ in range(3)]

    outcome = harness.critic.review(_FIX, _check(), patch=_PATCH, validated=harness.validated)

    assert isinstance(outcome, DidNotFinish) and outcome.reason == "no_tool_call"
    assert harness.critic.rounds == []
