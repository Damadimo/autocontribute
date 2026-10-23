"""The controller's checks of a submitted fix, behind the solver's submit (DESIGN §7.1).

Each check extracts the patch from the agent's workspace ``W`` and runs the diff gates. When
they pass, the tests run in the validation sandbox: red/green on ``R``, a copy of the
post-setup snapshot ``S`` with only the patch's test hunks, then on ``V``, a copy of ``S``
with the whole patch; and regression on ``V`` against the baseline, related tests first and
then the full suite when its baseline duration fits the time left. ``V`` stays for the critic
until the next check replaces it.

The agent gets the result as text: the full diff, every gate, red/green and regression, and a
short checklist. :class:`FixCheckResult` holds the same, already scrubbed, for the critic and
for ``validation.json`` (§7.5).
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final, Literal

from autocontribute.agent_loop import CheckReport
from autocontribute.config import PolicyConfig, QualityConfig
from autocontribute.diff_gates import (
    DEFAULT_MAX_SOURCE_FILES,
    DEFAULT_MAX_SOURCE_LINES,
    diff_gates,
    is_workflow_path,
)
from autocontribute.domain import DomainModel, GateResult
from autocontribute.environment_builder import PreparedEnvironment
from autocontribute.exceptions import (
    CircuitBreakerTrigger,
    PatchEncodingError,
    RepositoryError,
    StateError,
)
from autocontribute.patches import (
    FilePatch,
    Patch,
    PatchSplit,
    extract_patch,
    is_test_path,
    split_patch,
)
from autocontribute.redaction import redact_text, scrub_for_model
from autocontribute.repository import RepositoryWorkspace
from autocontribute.store import RunStore
from autocontribute.submissions import AgentSubmission
from autocontribute.suite_runs import (
    Reproduction,
    SuiteRun,
    green_failure,
    new_failures,
    reproduction,
    still_failing,
)
from autocontribute.suite_selection import related_test_command
from autocontribute.validation_sandbox import ValidationSandbox
from autocontribute.workspace_copies import copy_workspace, remove_workspace_copy
from autocontribute.workspace_files import WorkspaceFiles

GREEN_RUNS: Final = 3
# A new failure counts once it fails in the run that found it and in each re-run.
REGRESSION_RERUNS: Final = 2
_TAIL_CHARACTERS: Final = 3_000
_DIFF_CHARACTERS: Final = 60_000
_LISTED_TESTS: Final = 10
_TITLE_CHARACTERS: Final = 200
# Leaves room for the testing note and the disclosure under publication's 50,000 characters.
_BODY_CHARACTERS: Final = 45_000
_DOCS_SUFFIXES: Final = frozenset({".md", ".rst", ".txt", ".adoc", ".asciidoc", ".markdown"})
_DOCS_DIRECTORIES: Final = frozenset({"doc", "docs", "documentation"})
_TYPING_NAMES: Final = ("*.pyi", "py.typed", "*.d.ts")
_BUILD_CONFIG_NAMES: Final = frozenset(
    {
        ".dockerignore",
        ".editorconfig",
        ".flake8",
        ".gitattributes",
        ".gitignore",
        ".pre-commit-config.yaml",
        "cmakelists.txt",
        "dockerfile",
        "gnumakefile",
        "justfile",
        "makefile",
        "mypy.ini",
        "noxfile.py",
        "pytest.ini",
        "ruff.toml",
        "tox.ini",
    }
)
_CHECKLIST: Final = (
    "Read the diff above as a maintainer would and remove:",
    "- hunks the issue does not need, including formatting changes;",
    "- debug output such as print or console.log calls;",
    "- scratch, generated or stray files;",
    "- changes to tests that already existed, unless the issue is about them.",
)
_OUT_OF_TIME: Final = "the run is out of time"

SuiteRunKind = Literal["red", "green", "related", "full_suite", "rerun"]


class SuiteRunEvidence(DomainModel):
    """One test run, as the agent, the critic and ``validation.json`` see it."""

    kind: SuiteRunKind
    command: str
    exit_code: int
    timed_out: bool
    duration_seconds: float
    # Why the run says nothing about the tests: a build command or the container failed, or
    # the test report could not be read.
    failure: str | None
    passed: int
    failed: int
    skipped: int
    # The end of the test output, scrubbed.
    output_tail: str


class RedGreenEvidence(DomainModel):
    """Whether the patch's tests fail without its source changes and pass with them."""

    status: Literal["passed", "failed", "not_applicable"]
    detail: str
    # Tests the patch adds, or that it turns from passing to failing without its fix.
    targets: list[str]
    # The targets that failed with an assertion without the fix.
    reproduced: list[str]
    # Files or modules whose tests could not be collected without the fix.
    uncollected: list[str]
    runs: list[SuiteRunEvidence]


class RegressionEvidence(DomainModel):
    """The patched tests against the baseline; ``not_run`` is never a pass."""

    status: Literal["passed", "failed", "not_run"]
    detail: str
    full_suite: bool
    # Tests that passed in every baseline run and fail with the patch in every run here.
    new_failures: list[str]
    runs: list[SuiteRunEvidence]


class FixCheckResult(DomainModel):
    """One check of a submitted fix, already scrubbed for the critic and ``validation.json``."""

    diff_sha256: str
    passed: bool
    gates: list[GateResult]
    test_paths: list[str]
    source_paths: list[str]
    # None when the gates failed, so no test ran.
    red_green: RedGreenEvidence | None
    regression: RegressionEvidence | None
    # The patch changes source files without a test, outside documentation, typing, build
    # and CI configuration: only the critic's ``no_test_needed`` allows that (§7.1, item 5).
    test_waiver_needed: bool
    notes: list[str]


@dataclass(frozen=True, slots=True)
class _RegressionRun:
    # Why the run says nothing about individual tests; None when it does.
    unusable: str | None
    new_failures: list[str]


class FixChecks:
    """The :class:`autocontribute.agent_loop.FixChecker` of one run.

    ``seconds_left`` returns the run's remaining time; no test run gets more, and none gets
    more than ``command_timeout_seconds``. ``max_source_files`` and ``max_source_lines`` are
    the limits for non-test files (``quality.max_source_*``).
    """

    def __init__(
        self,
        workspace: RepositoryWorkspace,
        environment: PreparedEnvironment,
        sandbox: ValidationSandbox,
        *,
        store: RunStore,
        run_id: str,
        quality: QualityConfig,
        policy: PolicyConfig,
        command_timeout_seconds: int,
        seconds_left: Callable[[], float],
        host_values: frozenset[str],
        max_source_files: int = DEFAULT_MAX_SOURCE_FILES,
        max_source_lines: int = DEFAULT_MAX_SOURCE_LINES,
    ) -> None:
        self._workspace = workspace
        self._recipe = environment.recipe
        self._baseline = environment.baseline
        self._snapshot = environment.snapshot
        self._sandbox = sandbox
        self._store = store
        self._run_id = run_id
        self._quality = quality
        self._policy = policy
        self._timeout_limit = command_timeout_seconds
        self._seconds_left = seconds_left
        self._host_values = host_values
        self._max_source_files = max_source_files
        self._max_source_lines = max_source_lines
        self._base_paths: frozenset[str] | None = None
        self.results: dict[str, FixCheckResult] = {}
        # V of the latest check, present only when its gates passed; the critic reviews a
        # copy of it.
        self.validated = workspace.path.with_name(f"{workspace.path.name}.validation")
        self._red = workspace.path.with_name(f"{workspace.path.name}.red")

    def diff_sha256(self) -> str:
        return hashlib.sha256(self._workspace.patch_bytes()).hexdigest()

    def check(self, submission: AgentSubmission) -> CheckReport:
        """Check the workspace's current patch and the submission's pull request text.

        Raises :class:`StateError`, after stopping every run, when an exact host secret
        value is in the patch.
        """

        sha = self.diff_sha256()
        remove_workspace_copy(self.validated)
        try:
            patch = extract_patch(self._workspace)
        except PatchEncodingError as exc:
            gate = GateResult(gate="utf8", passed=False, evidence=str(exc))
            result = self._result(sha, [gate], Patch(()), Patch(()), None, None, [])
            return self._report(result, "(the patch is not UTF-8 text, so it is not shown)")
        split = self._split(patch)
        outcome = diff_gates(
            self._workspace,
            patch,
            split,
            quality=self._quality,
            policy=self._policy,
            host_values=self._host_values,
            max_source_files=self._max_source_files,
            max_source_lines=self._max_source_lines,
        )
        if outcome.host_secret:
            self._stop_for_host_secret(sha)
        gates = [*outcome.gates, _text_gate(submission)]
        notes = _notes(patch, split, submission)
        red_green = regression = None
        if outcome.passed:
            red_green, regression = self._run_tests(patch, split)
        result = self._result(sha, gates, split.tests, split.sources, red_green, regression, notes)
        return self._report(result, patch.text)

    def _split(self, patch: Patch) -> PatchSplit:
        try:
            return split_patch(patch, WorkspaceFiles(self._workspace.path))
        except RepositoryError:
            # A Rust source the host cannot read safely, which the gates refuse anyway.
            tests = tuple(file for file in patch.files if is_test_path(file.path))
            sources = tuple(file for file in patch.files if not is_test_path(file.path))
            return PatchSplit(Patch(tests), Patch(sources))

    def _stop_for_host_secret(self, sha: str) -> None:
        trigger_hash = hashlib.sha256(
            json.dumps({"diff_sha256": sha, "run_id": self._run_id}, sort_keys=True).encode()
        ).hexdigest()
        self._store.record_stop(
            CircuitBreakerTrigger(
                source=f"secret_scanner:{self._run_id}",
                reason=(
                    "The agent's patch contains a secret value of this machine; the value was "
                    "not kept."
                ),
                trigger_hash=trigger_hash,
            )
        )
        raise StateError("A secret value of this machine reached the patch; every run is stopped")

    def _run_tests(
        self, patch: Patch, split: PatchSplit
    ) -> tuple[RedGreenEvidence, RegressionEvidence]:
        try:
            _patched_copy(self._snapshot, self.validated, patch, self._workspace.base_sha)
            red_green = self._red_green(patch, split)
        except RepositoryError as exc:
            remove_workspace_copy(self.validated)
            detail = f"the patch does not apply to the post-setup snapshot: {exc}"
            return _red_green("failed", detail, None, []), _regression(
                "not_run", detail, False, [], []
            )
        finally:
            remove_workspace_copy(self._red)
        return red_green, self._regression(patch)

    def _red_green(self, patch: Patch, split: PatchSplit) -> RedGreenEvidence:
        tests = [file.path for file in split.tests.files if not _deleted(file)]
        if not tests:
            return _red_green("not_applicable", "the patch changes no test", None, [])
        runs: list[SuiteRunEvidence] = []
        found: Reproduction | None = None
        if split.sources.files:
            _patched_copy(self._snapshot, self._red, split.tests, self._workspace.base_sha)
            red_command = related_test_command(self._recipe, tests, self._tree(split.tests.files))
            red = self._run(self._red, red_command)
            if red is None:
                return _red_green("failed", _OUT_OF_TIME, None, runs)
            runs.append(self._evidence("red", red_command, red))
            found = reproduction(self._baseline, red)
        command = related_test_command(self._recipe, tests, self._tree(patch.files))
        green: list[SuiteRun] = []
        failure: str | None = None
        while len(green) < GREEN_RUNS and failure is None:
            run = self._run(self.validated, command)
            if run is None:
                return _red_green("failed", _OUT_OF_TIME, found, runs)
            green.append(run)
            runs.append(self._evidence("green", command, run))
            # A patch of tests alone reproduces nothing; its new tests must pass.
            found = found or reproduction(self._baseline, run)
            failure = green_failure(found, green)
        if found is None:
            raise StateError("The green step ran without finding its tests")
        if not split.sources.files:
            detail = failure or f"the test-only patch passed {GREEN_RUNS} runs in a row"
            return _red_green("failed" if failure else "passed", detail, found, runs)
        if not found.reproduced:
            return _red_green("failed", _not_reproduced(found, runs[0]), found, runs)
        if failure is not None:
            return _red_green("failed", f"with the fix, {failure}", found, runs)
        detail = (
            f"{len(found.reproduced)} test(s) fail without the fix and pass with it, "
            f"{GREEN_RUNS} runs in a row"
        )
        return _red_green("passed", detail, found, runs)

    def _regression(self, patch: Patch) -> RegressionEvidence:
        paths = [file.path for file in patch.files]
        runs: list[SuiteRunEvidence] = []
        related = related_test_command(self._recipe, paths, self._tree(patch.files))
        related_ran = False
        if related is not None:
            outcome = self._regression_run("related", related, runs)
            if outcome is not None and outcome.new_failures:
                detail = _new_failures_detail(outcome.new_failures)
                return _regression("failed", detail, False, outcome.new_failures, runs)
            # A related run that says nothing leaves the decision to the full suite.
            related_ran = outcome is not None and outcome.unusable is None
        full_duration = max(self._baseline.durations_seconds, default=0.0)
        timeout = self._timeout()
        if self._baseline.timed_out:
            skipped = "the full suite did not finish within the baseline's time limit"
        elif full_duration >= timeout:
            skipped = f"the full suite takes about {full_duration:.0f} s and {timeout} s are left"
        else:
            outcome = self._regression_run("full_suite", None, runs)
            if outcome is None:
                skipped = _OUT_OF_TIME
            elif outcome.unusable is not None:
                detail = f"the patched suite did not run: {outcome.unusable}"
                return _regression("failed", detail, True, [], runs)
            elif outcome.new_failures:
                detail = _new_failures_detail(outcome.new_failures)
                return _regression("failed", detail, True, outcome.new_failures, runs)
            else:
                return _regression("passed", "the full suite shows no new failure", True, [], runs)
        if not related_ran:
            return _regression("not_run", f"not run: {skipped}", False, [], runs)
        detail = f"related tests show no new failure; the full suite was not run: {skipped}"
        return _regression("passed", detail, False, [], runs)

    def _regression_run(
        self, kind: SuiteRunKind, command: str | None, runs: list[SuiteRunEvidence]
    ) -> _RegressionRun | None:
        """Run one regression command and re-run its new failures; None when out of time."""

        run = self._run(self.validated, command)
        if run is None:
            return None
        runs.append(self._evidence(kind, command, run))
        if run.failure is not None or run.timed_out:
            return _RegressionRun(run.failure or "the run timed out", [])
        found = new_failures(self._baseline, run, full_suite=command is None)
        for _ in range(REGRESSION_RERUNS):
            if not found:
                break
            rerun = self._run(self.validated, command)
            if rerun is None:
                break
            runs.append(self._evidence("rerun", command, rerun))
            found = still_failing(found, rerun)
        return _RegressionRun(None, found)

    def _run(self, source: Path, command: str | None) -> SuiteRun | None:
        timeout = self._timeout()
        if timeout < 1:
            return None
        return self._sandbox.run_suite(source, timeout_seconds=timeout, test_command=command)

    def _timeout(self) -> int:
        return min(self._timeout_limit, math.floor(self._seconds_left()))

    def _tree(self, files: Sequence[FilePatch]) -> frozenset[str]:
        """The paths of the base tree with ``files`` applied: what a command will find."""

        if self._base_paths is None:
            self._base_paths = frozenset(entry.path for entry in self._workspace.base_tree())
        deleted = {file.path for file in files if _deleted(file)}
        return (self._base_paths | {file.path for file in files}) - deleted

    def _evidence(self, kind: SuiteRunKind, command: str | None, run: SuiteRun) -> SuiteRunEvidence:
        statuses = [result.status for result in run.results.values()]
        tail = redact_text(scrub_for_model(run.output_tail, self._host_values))
        return SuiteRunEvidence(
            kind=kind,
            command=command or self._recipe.test_command,
            exit_code=run.exit_code,
            timed_out=run.timed_out,
            duration_seconds=run.duration_seconds,
            failure=run.failure,
            passed=statuses.count("passed"),
            failed=statuses.count("failed") + statuses.count("error"),
            skipped=statuses.count("skipped"),
            output_tail=tail[-_TAIL_CHARACTERS:],
        )

    def _result(
        self,
        sha: str,
        gates: list[GateResult],
        tests: Patch,
        sources: Patch,
        red_green: RedGreenEvidence | None,
        regression: RegressionEvidence | None,
        notes: list[str],
    ) -> FixCheckResult:
        passed = (
            all(gate.passed for gate in gates)
            and red_green is not None
            and red_green.status != "failed"
            and regression is not None
            and regression.status != "failed"
        )
        result = FixCheckResult(
            diff_sha256=sha,
            passed=passed,
            gates=gates,
            test_paths=list(tests.paths),
            source_paths=list(sources.paths),
            red_green=red_green,
            regression=regression,
            test_waiver_needed=bool(sources.files)
            and not tests.files
            and not all(_needs_no_test(path) for path in sources.paths),
            notes=notes,
        )
        self.results[sha] = result
        return result

    def _report(self, result: FixCheckResult, diff: str) -> CheckReport:
        return CheckReport(
            passed=result.passed, diff_sha256=result.diff_sha256, text=render_check(result, diff)
        )


def render_check(result: FixCheckResult, diff: str) -> str:
    """The text the agent gets back from a submit: the diff, the results and the checklist."""

    lines = [
        f"The controller's checks of your change: {'PASSED' if result.passed else 'FAILED'}.",
        "",
        "Your diff against the base commit:",
        _cut(diff, _DIFF_CHARACTERS),
        "",
        "Gates:",
        *(
            f"- {'pass' if gate.passed else 'FAIL'} {gate.gate}: {gate.evidence}"
            for gate in result.gates
        ),
    ]
    if result.red_green is None or result.regression is None:
        lines += ["", "No test ran, because a gate failed."]
    else:
        lines += [
            "",
            *_red_green_lines(result.red_green),
            "",
            *_regression_lines(result.regression),
        ]
    if result.test_waiver_needed:
        lines += [
            "",
            "Your change edits source files but no test. A reviewer accepts that only when no "
            "test can show the fix, as for documentation, typing, build or CI configuration. "
            "Otherwise add a test that fails without your change.",
        ]
    if result.notes:
        lines += ["", "Observations:", *(f"- {note}" for note in result.notes)]
    lines += ["", *_CHECKLIST]
    return "\n".join(lines)


def _red_green_lines(evidence: RedGreenEvidence) -> list[str]:
    lines = [f"Red/green: {evidence.status}: {evidence.detail}."]
    for label, tests in (
        ("New or changed tests", evidence.targets),
        ("Failing without the fix", evidence.reproduced),
        ("Not collected without the fix", evidence.uncollected),
    ):
        if tests:
            lines.append(f"{label}: {_listed(tests)}")
    lines += _run_lines(evidence.runs, show_tail=evidence.status == "failed")
    return lines


def _regression_lines(evidence: RegressionEvidence) -> list[str]:
    lines = [f"Regression: {evidence.status}: {evidence.detail}."]
    lines += _run_lines(evidence.runs, show_tail=evidence.status == "failed")
    return lines


def _run_lines(runs: Sequence[SuiteRunEvidence], *, show_tail: bool) -> list[str]:
    lines = [
        f"- {run.kind} run `{run.command}`: {run.passed} passed, {run.failed} failed, "
        f"{run.skipped} skipped, exit {run.exit_code}"
        + (" (timed out)" if run.timed_out else "")
        + (f"; {run.failure}" if run.failure else "")
        for run in runs
    ]
    failing = next((run for run in reversed(runs) if run.exit_code or run.failure), None)
    if show_tail and failing is not None and failing.output_tail:
        lines += [f"End of the {failing.kind} run's output:", failing.output_tail]
    return lines


def _red_green(
    status: Literal["passed", "failed", "not_applicable"],
    detail: str,
    found: Reproduction | None,
    runs: list[SuiteRunEvidence],
) -> RedGreenEvidence:
    return RedGreenEvidence(
        status=status,
        detail=detail,
        targets=list(found.targets) if found else [],
        reproduced=list(found.reproduced) if found else [],
        uncollected=list(found.uncollected) if found else [],
        runs=runs,
    )


def _regression(
    status: Literal["passed", "failed", "not_run"],
    detail: str,
    full_suite: bool,
    found: list[str],
    runs: list[SuiteRunEvidence],
) -> RegressionEvidence:
    return RegressionEvidence(
        status=status, detail=detail, full_suite=full_suite, new_failures=found, runs=runs
    )


def _not_reproduced(found: Reproduction, red: SuiteRunEvidence) -> str:
    if red.failure or red.timed_out:
        return f"the tests did not run without the fix: {red.failure or 'the run timed out'}"
    if found.uncollected and not found.targets:
        return (
            "without the fix the new tests fail only to import or collect, which shows nothing "
            "about the bug; write a test that fails with an assertion"
        )
    if not found.targets:
        return "no new or changed test ran"
    return (
        "no new or changed test fails with an assertion without the fix; it must fail "
        "because of the bug"
    )


def _new_failures_detail(found: list[str]) -> str:
    return f"{len(found)} test(s) that passed before the change now fail: {_listed(found)}"


def _patched_copy(snapshot: Path, destination: Path, patch: Patch, base_sha: str) -> None:
    copy_workspace(snapshot, destination)
    if patch.files:
        RepositoryWorkspace(destination, base_sha).apply_patch(patch.text)


def _deleted(file: FilePatch) -> bool:
    return "\ndeleted file mode " in file.header


def _needs_no_test(path: str) -> bool:
    """Documentation, typing stubs, build and CI configuration (§7.1, item 5)."""

    pure = PurePosixPath(path.casefold())
    return (
        pure.suffix in _DOCS_SUFFIXES
        or any(part in _DOCS_DIRECTORIES for part in pure.parts[:-1])
        or any(pure.match(pattern) for pattern in _TYPING_NAMES)
        or pure.name in _BUILD_CONFIG_NAMES
        or is_workflow_path(path)
    )


def _text_gate(submission: AgentSubmission) -> GateResult:
    problems = []
    title = submission.pr_title or ""
    if len(title) > _TITLE_CHARACTERS or "\n" in title.strip():
        problems.append(f"the title must be one line of at most {_TITLE_CHARACTERS} characters")
    if len(submission.pr_body or "") > _BODY_CHARACTERS:
        problems.append(f"the body must stay under {_BODY_CHARACTERS:,} characters")
    texts = (title, submission.pr_body or "", submission.commit_message or "")
    if any(mention in text.casefold() for text in texts for mention in ("@everyone", "@here")):
        problems.append("the text must not mention @everyone or @here")
    return GateResult(
        gate="pull_request_text",
        passed=not problems,
        evidence="; ".join(problems) or "title, body and commit message are within limits",
    )


def _notes(patch: Patch, split: PatchSplit, submission: AgentSubmission) -> list[str]:
    notes = []
    edited = [
        file.path
        for file in split.tests.files
        if "\nnew file mode " not in file.header and not _deleted(file)
    ]
    if edited:
        notes.append(f"Tests that already existed are edited: {', '.join(edited)}")
    created = [
        file.path
        for file in split.sources.files
        if "\nnew file mode " in file.header and not _needs_no_test(file.path)
    ]
    if created:
        notes.append(f"New non-test files: {', '.join(created)}")
    unlisted = sorted(set(submission.test_files) - set(patch.paths))
    if unlisted:
        notes.append(f"submit lists test files the diff does not change: {', '.join(unlisted)}")
    return notes


def _listed(tests: Sequence[str]) -> str:
    more = f" and {len(tests) - _LISTED_TESTS} more" if len(tests) > _LISTED_TESTS else ""
    return ", ".join(tests[:_LISTED_TESTS]) + more


def _cut(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    head = limit // 2
    return (
        f"{text[:head]}\n[... {len(text) - limit} characters of the diff omitted; run git diff "
        f"to read them ...]\n{text[len(text) - (limit - head) :]}"
    )


__all__ = [
    "GREEN_RUNS",
    "REGRESSION_RERUNS",
    "FixCheckResult",
    "FixChecks",
    "RedGreenEvidence",
    "RegressionEvidence",
    "SuiteRunEvidence",
    "SuiteRunKind",
    "render_check",
]
