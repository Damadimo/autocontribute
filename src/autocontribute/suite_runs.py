"""Offline test runs on workspace copies, and what they say about a patch (DESIGN §5.3, §7.1).

Every run copies a tree (the post-setup snapshot ``S``, or a patched copy of it), starts a
fresh network-less container from the environment image, runs the recipe's build commands and
its test command, and reads the per-test report. The baseline runs the unmodified base two or
three times; the acceptance gate decides from it whether the environment is good enough to
validate a patch against, and the red/green and regression helpers compare later runs with it.
"""

from __future__ import annotations

import secrets
from collections import Counter
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from autocontribute.config import SandboxConfig
from autocontribute.domain import CommandResult
from autocontribute.environments import TOOL_ROOT, EnvironmentBaseline, EnvironmentRecipe
from autocontribute.exceptions import SuiteReportError
from autocontribute.quality import environment_failure_signature
from autocontribute.sandbox import SessionContainer
from autocontribute.suite_results import MAX_REPORT_BYTES, CaseResult, CaseStatus, parse_report
from autocontribute.workspace_copies import copy_workspace, remove_workspace_copy

# The whole suite stands for one test when the runner writes no per-test report.
SUITE_TEST_ID: Final = "<suite>"
BASELINE_TIME_LIMIT_SECONDS: Final = 900
_OUTPUT_TAIL_LINES: Final = 200
_MAX_SUITE_MESSAGE_CHARACTERS: Final = 2_000
_MIN_PASS_RATE: Final = 0.8
_MAX_FLAKY_SHARE: Final = 0.02
# Failures sharing a broken-environment signature reject the environment when there are more
# than this many and they are most of the failures (research-envsetup.md §B9).
_MAX_INFRASTRUCTURE_FAILURES: Final = 5
_FAILING: Final[frozenset[CaseStatus]] = frozenset({"failed", "error"})
_NOT_REPRODUCED_SIGNATURES: Final = (
    "ImportError",
    "ModuleNotFoundError",
    "SyntaxError",
    "IndentationError",
    "collection failure",
    "Cannot find module",
    "error[E0",
    "the test did not finish",
)


@dataclass(frozen=True, slots=True)
class SuiteRun:
    """One offline run of the build commands and the test command on a fresh copy."""

    exit_code: int
    timed_out: bool
    duration_seconds: float
    results: Mapping[str, CaseResult]
    per_test: bool
    # Why the run says nothing about the tests: a build command or the container failed, or
    # the report could not be read.
    failure: str | None
    # The end of the test command's output, for logs and the setup agent.
    output_tail: str


@dataclass(frozen=True, slots=True)
class Reproduction:
    """What the tests of a patch show on the unpatched source (the red step of §7.1)."""

    # Tests the patch adds, or turns from passing on the base to failing.
    targets: tuple[str, ...]
    # The targets that fail with an assertion, not an import, syntax or collection error.
    reproduced: tuple[str, ...]


def run_suite(
    config: SandboxConfig,
    *,
    image_id: str,
    recipe: EnvironmentRecipe,
    source: Path,
    run_id: str,
    store_root: Path,
    timeout_seconds: int,
) -> SuiteRun:
    """Run the recipe's build and test commands offline on a copy of ``source``."""

    copy = source.with_name(f"{source.name}.run-{secrets.token_hex(4)}")
    copy_workspace(source, copy)
    environment = {**recipe.env, **recipe.offline_env}
    try:
        with SessionContainer(
            config,
            image=image_id,
            workspace=copy,
            run_id=run_id,
            store_root=store_root,
            volumes=(TOOL_ROOT,),
        ) as container:
            for command in recipe.build_commands:
                built = container.exec(
                    command, timeout_seconds=timeout_seconds, environment=environment
                )
                if built.infrastructure_failure is not None or not built.result.passed:
                    outcome = (
                        "timed out"
                        if built.result.timed_out
                        else f"failed with exit {built.result.exit_code}"
                    )
                    return SuiteRun(
                        built.result.exit_code,
                        # Only a test command over the limit makes validation targeted.
                        timed_out=False,
                        duration_seconds=built.result.duration_seconds,
                        results={},
                        per_test=False,
                        failure=built.infrastructure_failure
                        or f"the build command {outcome}: {command}",
                        output_tail=_tail(built.result.stdout, built.result.stderr),
                    )
            tested = container.exec(
                recipe.test_command, timeout_seconds=timeout_seconds, environment=environment
            )
            result = tested.result
            output = _tail(result.stdout, result.stderr)
            failure = tested.infrastructure_failure
            results: Mapping[str, CaseResult] = {}
            if not result.timed_out and failure is None:
                results, failure = _read_results(container, recipe, result, output)
            return SuiteRun(
                result.exit_code,
                result.timed_out,
                result.duration_seconds,
                results,
                per_test=recipe.test_report is not None,
                failure=failure,
                output_tail=output,
            )
    finally:
        remove_workspace_copy(copy)


def run_baseline(
    config: SandboxConfig,
    *,
    image_id: str,
    recipe: EnvironmentRecipe,
    snapshot: Path,
    base_sha: str,
    run_id: str,
    store_root: Path,
) -> tuple[EnvironmentBaseline, tuple[SuiteRun, ...]]:
    """Run the unmodified base twice, and a third time when any test's result differs."""

    timeout = min(config.command_timeout_seconds, BASELINE_TIME_LIMIT_SECONDS)

    def run_once() -> SuiteRun:
        return run_suite(
            config,
            image_id=image_id,
            recipe=recipe,
            source=snapshot,
            run_id=run_id,
            store_root=store_root,
            timeout_seconds=timeout,
        )

    runs = [run_once()]
    # A suite over the limit is not run again, and a broken run would fail the gate anyway.
    if not runs[0].timed_out and runs[0].failure is None:
        runs.append(run_once())
        if _statuses(runs[0]) != _statuses(runs[1]):
            runs.append(run_once())
    return summarize_baseline(runs, base_sha=base_sha), tuple(runs)


def summarize_baseline(runs: Sequence[SuiteRun], *, base_sha: str) -> EnvironmentBaseline:
    """Sort every test seen in any run by whether its result held across the runs."""

    tests = sorted({test_id for run in runs for test_id in run.results})
    pass_stable: list[str] = []
    fail_before: list[str] = []
    flaky: list[str] = []
    skip: list[str] = []
    durations: dict[str, float] = {}
    for test_id in tests:
        seen = [run.results.get(test_id) for run in runs]
        statuses = {None if result is None else result.status for result in seen}
        if statuses == {"passed"}:
            pass_stable.append(test_id)
        elif statuses == {"skipped"}:
            skip.append(test_id)
        elif statuses <= _FAILING:
            fail_before.append(test_id)
        else:
            flaky.append(test_id)
        timings = [r.duration_seconds for r in seen if r is not None and r.duration_seconds]
        if timings:
            durations[test_id] = max(timings)
    return EnvironmentBaseline(
        base_sha=base_sha,
        exit_codes=[run.exit_code for run in runs],
        durations_seconds=[run.duration_seconds for run in runs],
        per_test=all(run.per_test for run in runs),
        timed_out=any(run.timed_out for run in runs),
        collected=len(tests),
        pass_stable=pass_stable,
        fail_before=fail_before,
        flaky=flaky,
        skip=skip,
        test_durations=durations,
    )


def acceptance_failure(baseline: EnvironmentBaseline, runs: Sequence[SuiteRun]) -> str | None:
    """Say why the environment is not good enough to validate patches against, or ``None``.

    A suite that exceeds the time limit is accepted for targeted validation (§5.3): only
    the setup checks and the related tests a patch touches can then speak for it.
    """

    if baseline.timed_out:
        return None
    for run in runs:
        if run.failure is not None:
            return run.failure
    if baseline.collected == 0:
        return "the test command ran no tests"
    considered = baseline.collected - len(baseline.skip)
    if considered == 0:
        return f"all {baseline.collected} tests were skipped"
    if len(baseline.pass_stable) < _MIN_PASS_RATE * considered:
        return (
            f"only {len(baseline.pass_stable)} of {considered} tests passed on the unmodified base"
        )
    # One flaky test in a small suite is tolerated; more than 2% of the suite is not.
    if len(baseline.flaky) > 1 and len(baseline.flaky) >= _MAX_FLAKY_SHARE * baseline.collected:
        return f"{len(baseline.flaky)} of {baseline.collected} tests gave different results"
    signatures = Counter(
        signature
        for test_id in baseline.fail_before
        if (result := runs[0].results.get(test_id)) is not None
        and (signature := environment_failure_signature(result.message)) is not None
    )
    for signature, count in signatures.most_common(1):
        if count > _MAX_INFRASTRUCTURE_FAILURES and 2 * count > len(baseline.fail_before):
            return f"{count} of the failing tests show that {signature}"
    return None


def reproduction(baseline: EnvironmentBaseline, red: SuiteRun) -> Reproduction:
    """Find the tests a patch's test hunks add or break on the unpatched source.

    ``red`` ran on the snapshot with only the test part of the patch applied. A target that
    fails for an import, syntax or collection error, or a run that timed out, reproduces
    nothing: the test may only be failing because the code it calls does not exist yet.
    """

    if red.failure is not None or red.timed_out or not red.per_test:
        return Reproduction((), ())
    known = {*baseline.pass_stable, *baseline.fail_before, *baseline.flaky, *baseline.skip}
    stable = set(baseline.pass_stable)
    targets = sorted(
        test_id
        for test_id, result in red.results.items()
        if test_id not in known or (test_id in stable and result.status in _FAILING)
    )
    reproduced = [
        test_id
        for test_id in targets
        if red.results[test_id].status == "failed"
        and not any(text in red.results[test_id].message for text in _NOT_REPRODUCED_SIGNATURES)
    ]
    return Reproduction(tuple(targets), tuple(reproduced))


def green_failure(found: Reproduction, green: Sequence[SuiteRun]) -> str | None:
    """Say why the full patch does not make every target pass in every run, or ``None``.

    The design asks for three passing runs in a row on the patched copy.
    """

    if not green:
        return "the patched tests were not run"
    for number, run in enumerate(green, start=1):
        if run.failure is not None:
            return f"run {number} of the patched tests failed: {run.failure}"
        if run.timed_out:
            return f"run {number} of the patched tests timed out"
        failing = [
            test_id
            for test_id in found.targets
            if (result := run.results.get(test_id)) is None or result.status != "passed"
        ]
        if failing:
            return f"run {number} did not pass {len(failing)} patched tests: " + ", ".join(
                failing[:5]
            )
    return None


def new_failures(
    baseline: EnvironmentBaseline,
    run: SuiteRun,
    *,
    removed_tests: Collection[str] = (),
    full_suite: bool = True,
) -> list[str]:
    """Return tests that passed in every baseline run and now fail, error or disappear.

    Tests the patch deleted or renamed are left out, and so is every test missing from a
    targeted ``run`` (``full_suite=False``), which never ran them. Failing-before and flaky
    tests are ignored. Re-run the result through :func:`still_failing` twice before counting.
    """

    if run.failure is not None or run.timed_out:
        raise ValueError("a failed or timed-out run says nothing about individual tests")
    failures: list[str] = []
    for test_id in baseline.pass_stable:
        result = run.results.get(test_id)
        if test_id in removed_tests:
            continue
        if (result is None and full_suite) or (result is not None and result.status in _FAILING):
            failures.append(test_id)
    return failures


def still_failing(candidates: Collection[str], rerun: SuiteRun) -> list[str]:
    """Keep the candidate failures that fail, error or are missing again in ``rerun``."""

    if rerun.failure is not None or rerun.timed_out:
        return sorted(candidates)
    return sorted(
        test_id
        for test_id in candidates
        if (result := rerun.results.get(test_id)) is None or result.status in _FAILING
    )


def _read_results(
    container: SessionContainer, recipe: EnvironmentRecipe, result: CommandResult, output: str
) -> tuple[Mapping[str, CaseResult], str | None]:
    if recipe.test_report is None:
        status: CaseStatus = "passed" if result.passed else "failed"
        suite = CaseResult(
            SUITE_TEST_ID,
            status,
            result.duration_seconds,
            "" if result.passed else output[-_MAX_SUITE_MESSAGE_CHARACTERS:],
        )
        return {SUITE_TEST_ID: suite}, None
    report = container.read_file(recipe.test_report, max_bytes=MAX_REPORT_BYTES)
    if report is None:
        return {}, f"the test command wrote no readable report at {recipe.test_report}"
    try:
        return parse_report(recipe.test_framework, report), None
    except SuiteReportError as exc:
        return {}, str(exc)


def _statuses(run: SuiteRun) -> dict[str, CaseStatus]:
    return {test_id: result.status for test_id, result in run.results.items()}


def _tail(stdout: str, stderr: str) -> str:
    lines = f"{stdout}\n{stderr}".strip().splitlines()
    return "\n".join(lines[-_OUTPUT_TAIL_LINES:])


__all__ = [
    "BASELINE_TIME_LIMIT_SECONDS",
    "SUITE_TEST_ID",
    "Reproduction",
    "SuiteRun",
    "acceptance_failure",
    "green_failure",
    "new_failures",
    "reproduction",
    "run_baseline",
    "run_suite",
    "still_failing",
    "summarize_baseline",
]
