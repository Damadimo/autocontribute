from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Iterator, Mapping
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any

import pytest

from autocontribute.config import PolicyConfig, QualityConfig
from autocontribute.environment_builder import PreparedEnvironment
from autocontribute.environment_setup import EnvironmentImage
from autocontribute.environments import EnvironmentBaseline, EnvironmentRecipe
from autocontribute.exceptions import StateError
from autocontribute.fix_checks import FixCheckResult, FixChecks
from autocontribute.repository import RepositoryWorkspace
from autocontribute.sandbox import SessionContainer
from autocontribute.store import RunStore
from autocontribute.submissions import AgentSubmission
from autocontribute.suite_results import CaseResult
from autocontribute.suite_runs import CheckRun, SuiteRun, summarize_baseline
from autocontribute.workspace_copies import copy_workspace

_BUGGY = "def add(a, b):\n    return a - b\n"
_FIXED = "def add(a, b):\n    return a + b\n"
_BASE_TESTS = "from calc import add\n\n\ndef test_zero():\n    assert add(0, 0) == 0\n"
_NEW_TEST = "\n\ndef test_adds():\n    assert add(1, 2) == 3\n"
_RECIPE = EnvironmentRecipe(
    repository="acme/calc",
    language="python",
    base_image="python:3.12-bookworm",
    system_packages=[],
    setup_commands=[],
    build_commands=[],
    test_command="python -m pytest -p no:cacheprovider --junitxml=/tmp/ac-report.xml",
    test_framework="pytest",
    test_report="/tmp/ac-report.xml",
    env={},
    offline_env={},
    fetch_tags=False,
    fetch_submodules=False,
    source="detected",
    dependency_digest="b" * 64,
)
_HOST_SECRET = "host-secret-value-0123456789"
_SUBMISSION = AgentSubmission(
    outcome="fixed",
    skip_reason=None,
    summary="add subtracted; it adds now.",
    pr_title="Fix add",
    pr_body="add returned a - b.\n\nFixes #1",
    commit_message="Fix add",
    test_files=["tests/test_calc.py"],
    test_command="python -m pytest tests/test_calc.py",
)


def _git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull},
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


class FakeSandbox:
    """Runs a pretend pytest on the tree it gets: results follow the code in it.

    A test asserting ``add(1, 2) == 3`` passes once add adds; a test module that imports
    ``missing`` fails to collect; ``flaky`` lists tests that fail in their next run only;
    ``broken`` lists tests that fail while ``src/calc.py`` holds ``raise``.
    """

    def __init__(self) -> None:
        self.runs: list[tuple[str, str | None]] = []
        self.flaky: set[str] = set()
        self.broken: set[str] = set()
        self.durations = 1.0

    @property
    def environment(self) -> Mapping[str, str]:
        return {}

    def run_suite(
        self, source: Path, *, timeout_seconds: int, test_command: str | None = None
    ) -> SuiteRun:
        self.runs.append((source.name, test_command))
        calc = (source / "src" / "calc.py").read_text(encoding="utf-8")
        selected = test_command.split()[6:] if test_command else None
        results: dict[str, CaseResult] = {}
        for path in sorted((source / "tests").glob("test_*.py")):
            relative = path.relative_to(source).as_posix()
            if selected is not None and relative not in selected:
                continue
            module = relative.removesuffix(".py").replace("/", ".")
            text = path.read_text(encoding="utf-8")
            if "import missing" in text or ("import add_all" in text and "add_all" not in calc):
                results[module] = CaseResult(
                    module, "error", None, "ImportError: cannot import", collection_error=True
                )
                continue
            for name, body in re.findall(r"^def (test_\w+).*\n((?:[ \t]+.*\n?)*)", text, re.M):
                test_id = f"{module}::{name}"
                failing = (
                    ("add(1, 2) == 3" in body and "a + b" not in calc)
                    or (test_id in self.broken and "raise" in calc)
                    or test_id in self.flaky
                )
                self.flaky.discard(test_id)
                results[test_id] = (
                    CaseResult(test_id, "failed", 0.1, "AssertionError: assert -1 == 3")
                    if failing
                    else CaseResult(test_id, "passed", 0.1, "")
                )
        failed = any(result.status != "passed" for result in results.values())
        return SuiteRun(int(failed), False, self.durations, results, True, None, "== output ==")

    def run_check(self, source: Path, command: str, *, timeout_seconds: int) -> CheckRun:
        raise AssertionError("the checks run no single command")

    def session(
        self, workspace: Path, *, timeout_seconds: int
    ) -> AbstractContextManager[SessionContainer]:
        raise AssertionError("the checks open no session")


class Harness:
    def __init__(self, tmp_path: Path, **options: Any) -> None:
        source = tmp_path / "source"
        source.mkdir(parents=True)
        (tmp_path / "run").mkdir()
        _git(source, "init", "--quiet")
        for relative, content in {
            "src/calc.py": _BUGGY,
            "tests/test_calc.py": _BASE_TESTS,
            "tests/test_other.py": "def test_other():\n    assert True\n",
            "README.md": "calc\n",
        }.items():
            path = source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        _git(source, "add", ".")
        _git(
            source, "-c", "user.name=T", "-c", "user.email=t@example.invalid", "commit", "-qm", "b"
        )
        base = _git(source, "rev-parse", "HEAD")
        self.workspace = RepositoryWorkspace.clone(
            str(source), base, tmp_path / "run" / "repository", allow_local_source=True
        )
        snapshot = tmp_path / "run" / "repository.snapshot"
        copy_workspace(self.workspace.path, snapshot)
        self.sandbox = FakeSandbox()
        baseline_run = self.sandbox.run_suite(snapshot, timeout_seconds=900)
        self.sandbox.runs.clear()
        self.baseline = summarize_baseline([baseline_run, baseline_run], base_sha=base)
        self.store = RunStore(tmp_path / "state")
        self.seconds_left = 3_600.0
        prepared = PreparedEnvironment(
            EnvironmentImage(
                "sha256:" + "e" * 64, "tag", "python", "sha256:" + "d" * 64, "k", False
            ),
            _RECIPE,
            options.pop("baseline", None) or self.baseline,
            snapshot,
        )
        self.checks = FixChecks(
            self.workspace,
            prepared,
            self.sandbox,
            store=self.store,
            run_id="run1",
            quality=QualityConfig(),
            policy=PolicyConfig(),
            command_timeout_seconds=900,
            seconds_left=lambda: self.seconds_left,
            host_values=frozenset({_HOST_SECRET}),
            **options,
        )

    def write(self, relative: str, content: str) -> None:
        path = self.workspace.path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def check(self, submission: AgentSubmission = _SUBMISSION) -> FixCheckResult:
        report = self.checks.check(submission)
        result = self.checks.results[report.diff_sha256]
        assert report.passed is result.passed
        assert report.diff_sha256 == self.checks.diff_sha256()
        self.text = report.text
        return result


@pytest.fixture
def harness(tmp_path: Path) -> Iterator[Harness]:
    yield Harness(tmp_path)


def _gate(result: FixCheckResult, name: str) -> bool:
    return next(gate.passed for gate in result.gates if gate.gate == name)


def test_a_reproduced_fix_passes_red_green_and_regression(harness: Harness) -> None:
    harness.write("src/calc.py", _FIXED)
    harness.write("tests/test_calc.py", _BASE_TESTS + _NEW_TEST)

    result = harness.check()

    assert result.passed and not result.test_waiver_needed
    assert result.test_paths == ["tests/test_calc.py"] and result.source_paths == ["src/calc.py"]
    red_green = result.red_green
    assert red_green is not None and red_green.status == "passed"
    assert red_green.targets == red_green.reproduced == ["tests.test_calc::test_adds"]
    assert [run.kind for run in red_green.runs] == ["red", "green", "green", "green"]
    regression = result.regression
    assert regression is not None and regression.status == "passed" and regression.full_suite
    assert [run.kind for run in regression.runs] == ["related", "full_suite"]
    related = "python -m pytest -p no:cacheprovider --junitxml=/tmp/ac-report.xml"
    assert harness.sandbox.runs == [
        ("repository.red", f"{related} tests/test_calc.py"),
        *[("repository.validation", f"{related} tests/test_calc.py")] * 4,
        ("repository.validation", None),
    ]
    assert not harness.checks.validated.with_name("repository.red").exists()
    assert (harness.checks.validated / "src" / "calc.py").read_text() == _FIXED
    assert "+    return a + b" in harness.text
    assert "Red/green: passed: 1 test(s) fail without the fix and pass with it" in harness.text
    assert "Regression: passed: the full suite shows no new failure." in harness.text
    assert "Read the diff above as a maintainer would" in harness.text
    assert "Tests that already existed are edited: tests/test_calc.py" in harness.text


def test_a_test_that_passes_without_the_fix_reproduces_nothing(harness: Harness) -> None:
    harness.write("src/calc.py", _FIXED)
    harness.write(
        "tests/test_calc.py", _BASE_TESTS + "\n\ndef test_zeros():\n    assert add(0, 0) == 0\n"
    )

    result = harness.check()

    assert not result.passed
    assert result.red_green is not None and result.red_green.status == "failed"
    assert "no new or changed test fails with an assertion" in result.red_green.detail
    assert result.red_green.targets == ["tests.test_calc::test_zeros"]


def test_a_test_that_only_fails_to_import_reproduces_nothing(harness: Harness) -> None:
    harness.write("src/calc.py", _FIXED + "\n\ndef add_all(*n):\n    return sum(n)\n")
    harness.write(
        "tests/test_all.py",
        "from calc import add_all\n\n\ndef test_add_all():\n    assert add_all(1, 2) == 3\n",
    )

    result = harness.check()

    assert result.red_green is not None and result.red_green.status == "failed"
    assert result.red_green.uncollected == ["tests.test_all"]
    assert "fail only to import or collect" in result.red_green.detail


def test_a_broken_existing_test_is_a_confirmed_regression(harness: Harness) -> None:
    harness.sandbox.broken = {"tests.test_other::test_other"}
    harness.write("src/calc.py", "def add(a, b):\n    raise ValueError\n    return a + b\n")
    harness.write("tests/test_calc.py", _BASE_TESTS + _NEW_TEST)

    result = harness.check()

    regression = result.regression
    assert regression is not None and regression.status == "failed"
    assert regression.new_failures == ["tests.test_other::test_other"]
    assert [run.kind for run in regression.runs] == ["related", "full_suite", "rerun", "rerun"]
    assert "1 test(s) that passed before the change now fail" in harness.text
    assert "End of the rerun run's output:\n== output ==" in harness.text


def test_a_failure_that_passes_on_a_re_run_does_not_count(harness: Harness) -> None:
    harness.sandbox.flaky = {"tests.test_other::test_other"}
    harness.write("src/calc.py", _FIXED)
    harness.write("tests/test_calc.py", _BASE_TESTS + _NEW_TEST)

    result = harness.check()

    assert result.passed
    assert result.regression is not None
    assert [run.kind for run in result.regression.runs] == ["related", "full_suite", "rerun"]


def test_a_suite_too_slow_for_the_time_left_runs_related_tests_only(tmp_path: Path) -> None:
    slow = Harness(tmp_path).baseline.model_copy(update={"durations_seconds": [700.0, 720.0]})
    harness = Harness(tmp_path / "slow", baseline=slow)
    harness.seconds_left = 600.0
    harness.write("src/calc.py", _FIXED)
    harness.write("tests/test_calc.py", _BASE_TESTS + _NEW_TEST)

    result = harness.check()

    assert result.passed
    assert result.regression is not None and not result.regression.full_suite
    assert result.regression.detail == (
        "related tests show no new failure; the full suite was not run: the full suite takes "
        "about 720 s and 600 s are left"
    )


def test_a_suite_that_cannot_run_is_recorded_as_not_run(tmp_path: Path) -> None:
    slow = EnvironmentBaseline.model_validate(
        {**Harness(tmp_path).baseline.model_dump(), "timed_out": True}
    )
    harness = Harness(tmp_path / "slow", baseline=slow)
    harness.write("README.md", "calc, documented\n")

    result = harness.check()

    assert result.passed and not result.test_waiver_needed
    assert result.red_green is not None and result.red_green.status == "not_applicable"
    assert result.regression is not None and result.regression.status == "not_run"
    assert result.regression.detail.startswith("not run: the full suite did not finish")


def test_a_source_change_without_a_test_needs_the_critic_to_waive_it(harness: Harness) -> None:
    harness.write("src/calc.py", _FIXED)

    result = harness.check()

    assert result.passed and result.test_waiver_needed
    assert "Your change edits source files but no test" in harness.text


def test_a_test_only_patch_must_pass_three_times(harness: Harness) -> None:
    harness.write("tests/test_calc.py", _BASE_TESTS + "\n\ndef test_one():\n    assert 1\n")

    result = harness.check()

    assert result.passed
    assert result.red_green is not None and result.red_green.status == "passed"
    assert result.red_green.targets == ["tests.test_calc::test_one"]
    assert [run.kind for run in result.red_green.runs] == ["green"] * 3


def test_failing_gates_stop_before_any_test_runs(harness: Harness) -> None:
    harness.write("src/calc.py", _FIXED)
    harness.write(".github/CODEOWNERS", "* @someone\n")

    result = harness.check()

    assert not result.passed and not _gate(result, "forbidden_paths")
    assert result.red_green is None and result.regression is None
    assert harness.sandbox.runs == []
    assert not harness.checks.validated.exists()
    assert "No test ran, because a gate failed." in harness.text


def test_pull_request_text_is_checked_with_the_diff(harness: Harness) -> None:
    harness.write("src/calc.py", _FIXED)
    harness.write("tests/test_calc.py", _BASE_TESTS + _NEW_TEST)
    submission = _SUBMISSION.model_copy(
        update={"pr_title": "x" * 201, "pr_body": "cc @everyone", "test_files": ["tests/t.py"]}
    )

    result = harness.check(submission)

    assert not result.passed and not _gate(result, "pull_request_text")
    assert "the title must be one line of at most 200 characters" in harness.text
    assert harness.checks.check_text(submission) == (
        "the title must be one line of at most 200 characters; the text must not mention "
        "@everyone or @here"
    )
    assert harness.checks.check_text(_SUBMISSION) is None
    assert "submit lists test files the diff does not change: tests/t.py" in harness.text


def test_a_non_utf8_patch_fails_its_gate(harness: Harness) -> None:
    (harness.workspace.path / "src" / "latin.py").write_bytes(b"name = '\xe9'\n")

    result = harness.check()

    assert [gate.gate for gate in result.gates] == ["utf8"]
    assert "src/latin.py" in result.gates[0].evidence


def test_a_host_secret_in_the_patch_stops_every_run(harness: Harness) -> None:
    harness.write("src/calc.py", f"# {_HOST_SECRET}\n" + _FIXED)

    with pytest.raises(StateError, match="every run is stopped"):
        harness.checks.check(_SUBMISSION)

    breaker = harness.store.circuit_breaker_status()
    assert breaker.is_tripped and breaker.source == "secret_scanner:run1"
    assert _HOST_SECRET not in (breaker.reason or "")


def test_out_of_time_fails_the_red_green_step(harness: Harness) -> None:
    harness.seconds_left = 0.5
    harness.write("src/calc.py", _FIXED)
    harness.write("tests/test_calc.py", _BASE_TESTS + _NEW_TEST)

    result = harness.check()

    assert not result.passed
    assert result.red_green is not None and result.red_green.detail == "the run is out of time"


class BrokenRelatedSandbox(FakeSandbox):
    """The build of the related run fails once the patch breaks the source."""

    def run_suite(
        self, source: Path, *, timeout_seconds: int, test_command: str | None = None
    ) -> SuiteRun:
        if test_command is not None and "raise" in (source / "src" / "calc.py").read_text():
            self.runs.append((source.name, test_command))
            failure = "the build command failed with exit 2: make"
            return SuiteRun(2, False, 3.0, {}, False, failure, "error: x")
        return super().run_suite(source, timeout_seconds=timeout_seconds, test_command=test_command)


def test_an_unusable_related_run_fails_unless_the_full_suite_decides(tmp_path: Path) -> None:
    slow = Harness(tmp_path).baseline.model_copy(update={"durations_seconds": [600.0, 600.0]})
    skipped = Harness(tmp_path / "skipped", baseline=slow)
    skipped.checks._sandbox = BrokenRelatedSandbox()
    skipped.seconds_left = 500.0
    skipped.write("src/calc.py", "def add(a, b):\n    raise RuntimeError\n")

    result = skipped.check()

    assert not result.passed
    assert result.regression is not None and result.regression.status == "failed"
    assert result.regression.detail == (
        "the related tests did not run: the build command failed with exit 2: make; the full "
        "suite was not run: the full suite takes about 600 s and 500 s are left"
    )

    decided = Harness(tmp_path / "decided")
    decided.checks._sandbox = BrokenRelatedSandbox()
    decided.write("src/calc.py", "def add(a, b):\n    raise RuntimeError\n    return a + b\n")

    full = decided.check()

    assert full.regression is not None and full.regression.status == "passed"
    assert [run.kind for run in full.regression.runs] == ["related", "full_suite"]


def test_an_unchanged_flaky_test_does_not_count_as_the_reproduction(harness: Harness) -> None:
    # The new test passes with or without the fix, so it reproduces nothing.
    harness.write(
        "tests/test_calc.py", _BASE_TESTS + "\n\ndef test_new():\n    assert add(0, 2) != 5\n"
    )
    harness.write("src/calc.py", _FIXED)
    # An unchanged test of the same file fails once, in the red run.
    harness.sandbox.flaky.add("tests.test_calc::test_zero")

    result = harness.check()

    assert result.red_green is not None and result.red_green.status == "failed"
    assert result.red_green.reproduced == []
    assert result.red_green.targets == ["tests.test_calc::test_new"]


def test_an_edited_existing_test_can_be_the_reproduction(harness: Harness) -> None:
    harness.write("tests/test_calc.py", _BASE_TESTS.replace("add(0, 0) == 0", "add(1, 2) == 3"))
    harness.write("src/calc.py", _FIXED)

    result = harness.check()

    assert result.red_green is not None and result.red_green.status == "passed"
    assert result.red_green.reproduced == ["tests.test_calc::test_zero"]
