from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any, ClassVar

import pytest

import autocontribute.suite_runs as suite_runs
from autocontribute.config import SandboxConfig
from autocontribute.domain import CommandResult
from autocontribute.environments import EnvironmentBaseline, EnvironmentRecipe, TestFramework
from autocontribute.sandbox import SessionCommandResult
from autocontribute.suite_results import CaseResult, CaseStatus, parse_report
from autocontribute.suite_runs import (
    SUITE_TEST_ID,
    CheckRun,
    Reproduction,
    SuiteRun,
    acceptance_failure,
    green_failure,
    new_failures,
    reproduction,
    run_baseline,
    run_check,
    run_suite,
    still_failing,
    summarize_baseline,
)

_BASE_SHA = "a" * 40
_IMAGE = "sha256:" + "e" * 64
_JUNIT = (
    b"<testsuites><testsuite>"
    b'<testcase classname="tests.test_a" name="test_ok" time="0.5"/>'
    b'<testcase classname="tests.test_a" name="test_net" time="0.1">'
    b'<failure message="Network is unreachable"/></testcase>'
    b"</testsuite></testsuites>"
)


def _recipe(**changes: Any) -> EnvironmentRecipe:
    fields: dict[str, Any] = {
        "repository": "acme/demo",
        "language": "python",
        "base_image": "python:3.13-bookworm",
        "system_packages": [],
        "setup_commands": [],
        "build_commands": ["make generated"],
        "test_command": "python -m pytest --junitxml=/tmp/ac-report.xml",
        "test_framework": "pytest",
        "test_report": "/tmp/ac-report.xml",
        "env": {"PATH": "/opt/ac/venv/bin:/usr/bin:/bin"},
        "offline_env": {"UV_OFFLINE": "1"},
        "fetch_tags": False,
        "fetch_submodules": False,
        "source": "detected",
        "dependency_digest": "b" * 64,
    }
    return EnvironmentRecipe.model_validate({**fields, **changes})


def _command(exit_code: int = 0, *, timed_out: bool = False, output: str = "") -> CommandResult:
    return CommandResult(
        command="",
        exit_code=exit_code,
        duration_seconds=2.0,
        stdout=output,
        stderr="",
        timed_out=timed_out,
    )


class _FakeContainer:
    """Stands in for a session container: scripted command results and report bytes."""

    instances: ClassVar[list[_FakeContainer]] = []
    outcomes: ClassVar[list[SessionCommandResult]] = []
    report: ClassVar[bytes | None] = _JUNIT

    def __init__(self, config: SandboxConfig, **options: Any) -> None:
        self.options = options
        self.commands: list[tuple[str, Mapping[str, str]]] = []
        self.workspace_seen = (options["workspace"] / "marker").read_text(encoding="utf-8")
        _FakeContainer.instances.append(self)

    def __enter__(self) -> _FakeContainer:
        return self

    def __exit__(self, *_exception: object) -> None:
        pass

    def exec(
        self, command: str, *, timeout_seconds: int, environment: Mapping[str, str]
    ) -> SessionCommandResult:
        self.commands.append((command, dict(environment)))
        if _FakeContainer.outcomes:
            return _FakeContainer.outcomes.pop(0)
        return SessionCommandResult(_command(), None, restarted=False)

    def read_file(self, path: str, *, max_bytes: int) -> bytes | None:
        assert path == "/tmp/ac-report.xml"
        return _FakeContainer.report


@pytest.fixture
def fake_container(monkeypatch: pytest.MonkeyPatch) -> Iterator[type[_FakeContainer]]:
    _FakeContainer.instances = []
    _FakeContainer.outcomes = []
    _FakeContainer.report = _JUNIT
    monkeypatch.setattr(suite_runs, "SessionContainer", _FakeContainer)
    yield _FakeContainer


def _snapshot(tmp_path: Path) -> Path:
    snapshot = tmp_path / "workspace.snapshot"
    snapshot.mkdir(parents=True)
    (snapshot / "marker").write_text("snapshot", encoding="utf-8")
    return snapshot


def _run(recipe: EnvironmentRecipe, tmp_path: Path) -> SuiteRun:
    return run_suite(
        SandboxConfig(),
        image_id=_IMAGE,
        recipe=recipe,
        source=_snapshot(tmp_path),
        run_id="run1",
        store_root=tmp_path / "state",
        timeout_seconds=600,
    )


def test_suite_runs_build_then_tests_offline_on_a_removed_copy(
    tmp_path: Path, fake_container: type[_FakeContainer]
) -> None:
    run = _run(_recipe(), tmp_path)

    container = fake_container.instances[0]
    assert container.options["image"] == _IMAGE
    assert container.options["volumes"] == ("/opt/ac",)
    assert container.options["workspace"].name.startswith("workspace.snapshot.run-")
    assert not container.options["workspace"].exists()
    assert container.workspace_seen == "snapshot"
    assert [command for command, _ in container.commands] == [
        "make generated",
        "python -m pytest --junitxml=/tmp/ac-report.xml",
    ]
    assert container.commands[1][1] == {
        "PATH": "/opt/ac/venv/bin:/usr/bin:/bin",
        "UV_OFFLINE": "1",
    }
    assert run.failure is None and run.per_test
    assert {test_id: result.status for test_id, result in run.results.items()} == {
        "tests.test_a::test_ok": "passed",
        "tests.test_a::test_net": "failed",
    }


def test_a_run_of_related_tests_replaces_only_the_test_command(
    tmp_path: Path, fake_container: type[_FakeContainer]
) -> None:
    related = "python -m pytest --junitxml=/tmp/ac-report.xml tests/test_a.py"

    run = run_suite(
        SandboxConfig(),
        image_id=_IMAGE,
        recipe=_recipe(),
        source=_snapshot(tmp_path),
        run_id="run1",
        store_root=tmp_path / "state",
        timeout_seconds=600,
        test_command=related,
    )

    assert [command for command, _ in fake_container.instances[0].commands] == [
        "make generated",
        related,
    ]
    assert run.failure is None and len(run.results) == 2


def test_suite_run_reports_build_failures_missing_reports_and_container_failures(
    tmp_path: Path, fake_container: type[_FakeContainer]
) -> None:
    fake_container.outcomes = [SessionCommandResult(_command(2, output="no rule"), None, False)]
    build = _run(_recipe(), tmp_path / "1")
    assert build.failure == "the build command failed with exit 2: make generated"
    assert build.output_tail == "no rule"
    assert len(fake_container.instances[0].commands) == 1

    fake_container.outcomes = [
        SessionCommandResult(_command(124, timed_out=True), None, True),
    ]
    slow_build = _run(_recipe(), tmp_path / "2")
    assert slow_build.failure == "the build command timed out: make generated"
    assert not slow_build.timed_out

    fake_container.report = None
    missing = _run(_recipe(build_commands=[]), tmp_path / "3")
    assert missing.failure == "the test command wrote no readable report at /tmp/ac-report.xml"

    fake_container.report = b"<testsuites"
    malformed = _run(_recipe(build_commands=[]), tmp_path / "4")
    assert malformed.failure is not None and "not well-formed" in malformed.failure

    fake_container.outcomes = [
        SessionCommandResult(_command(137), "the sandbox ran out of memory (limit 4g)", True)
    ]
    memory = _run(_recipe(build_commands=[]), tmp_path / "5")
    assert memory.failure == "the sandbox ran out of memory (limit 4g)"
    assert memory.results == {}


def test_suite_without_a_report_counts_as_one_test(
    tmp_path: Path, fake_container: type[_FakeContainer]
) -> None:
    fake_container.outcomes = [SessionCommandResult(_command(1, output="FAILED"), None, False)]

    run = _run(_recipe(build_commands=[], test_framework="other", test_report=None), tmp_path)

    assert not run.per_test
    assert run.results == {SUITE_TEST_ID: CaseResult(SUITE_TEST_ID, "failed", 2.0, "FAILED")}


def test_a_check_runs_after_the_build_on_its_own_removed_copy(
    tmp_path: Path, fake_container: type[_FakeContainer]
) -> None:
    fake_container.outcomes = [
        SessionCommandResult(_command(), None, False),
        SessionCommandResult(_command(1, output="AssertionError"), None, False),
    ]

    def check(source: Path) -> CheckRun:
        return run_check(
            SandboxConfig(),
            image_id=_IMAGE,
            recipe=_recipe(),
            source=source,
            run_id="run1",
            store_root=tmp_path / "state",
            command="python -c 'assert False'",
            timeout_seconds=60,
        )

    failing = check(_snapshot(tmp_path / "1"))

    container = fake_container.instances[0]
    assert container.options["workspace"].name.startswith("workspace.snapshot.check-")
    assert not container.options["workspace"].exists()
    assert [command for command, _ in container.commands] == [
        "make generated",
        "python -c 'assert False'",
    ]
    assert container.commands[1][1]["UV_OFFLINE"] == "1"
    assert failing == CheckRun(1, False, None, "AssertionError")

    fake_container.outcomes = [SessionCommandResult(_command(2), None, False)]
    broken = check(_snapshot(tmp_path / "2"))
    assert broken.failure == "the build command failed with exit 2: make generated"


def test_timed_out_suite_has_no_results(
    tmp_path: Path, fake_container: type[_FakeContainer]
) -> None:
    fake_container.outcomes = [SessionCommandResult(_command(124, timed_out=True), None, True)]

    run = _run(_recipe(build_commands=[]), tmp_path)

    assert run.timed_out and run.failure is None and run.results == {}


def _suite(statuses: Mapping[str, CaseStatus], **changes: Any) -> SuiteRun:
    fields: dict[str, Any] = {
        "exit_code": 1,
        "timed_out": False,
        "duration_seconds": 3.0,
        "results": {
            test_id: CaseResult(test_id, status, 0.25, "" if status == "passed" else "boom")
            for test_id, status in statuses.items()
        },
        "per_test": True,
        "failure": None,
        "output_tail": "",
    }
    fields.update(changes)
    return SuiteRun(**fields)


def test_baseline_runs_twice_and_a_third_time_when_results_differ(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    planned = [
        _suite({"a": "passed", "b": "failed", "c": "passed"}),
        _suite({"a": "passed", "b": "failed", "c": "failed"}),
        _suite({"a": "passed", "b": "failed", "c": "passed", "d": "skipped"}),
    ]
    timeouts: list[int] = []

    def fake_run_suite(*_args: Any, timeout_seconds: int, **_kwargs: Any) -> SuiteRun:
        timeouts.append(timeout_seconds)
        return planned.pop(0)

    monkeypatch.setattr(suite_runs, "run_suite", fake_run_suite)

    baseline, runs = run_baseline(
        SandboxConfig(command_timeout_seconds=1_200),
        image_id=_IMAGE,
        recipe=_recipe(),
        snapshot=tmp_path,
        base_sha=_BASE_SHA,
        run_id="run1",
        store_root=tmp_path,
    )

    assert len(runs) == 3
    assert timeouts == [900, 900, 900]
    assert baseline.pass_stable == ["a"]
    assert baseline.fail_before == ["b"]
    assert baseline.flaky == ["c", "d"]
    assert baseline.collected == 4
    assert baseline.exit_codes == [1, 1, 1]

    def baseline_runs(*suites: SuiteRun) -> int:
        planned[:] = list(suites)
        timeouts.clear()
        _, runs = run_baseline(
            SandboxConfig(),
            image_id=_IMAGE,
            recipe=_recipe(),
            snapshot=tmp_path,
            base_sha=_BASE_SHA,
            run_id="run1",
            store_root=tmp_path,
        )
        assert len(timeouts) == len(runs)
        return len(runs)

    same = _suite({"a": "passed", "b": "failed"})
    assert baseline_runs(same, same, same) == 2
    # A run that timed out or broke fails the gate; repeating it would only cost time.
    assert baseline_runs(_suite({}, timed_out=True), same) == 1
    assert (
        baseline_runs(_suite({}, failure="the build command failed with exit 2: make"), same) == 1
    )


def test_baseline_sorts_tests_by_how_their_results_held() -> None:
    first = _suite({"pass": "passed", "fail": "failed", "error": "error", "skip": "skipped"})
    second = _suite({"pass": "passed", "fail": "error", "error": "error", "skip": "skipped"})

    baseline = summarize_baseline([first, second], base_sha=_BASE_SHA)

    assert baseline == EnvironmentBaseline(
        base_sha=_BASE_SHA,
        exit_codes=[1, 1],
        durations_seconds=[3.0, 3.0],
        per_test=True,
        timed_out=False,
        collected=4,
        pass_stable=["pass"],
        fail_before=["error", "fail"],
        flaky=[],
        skip=["skip"],
        test_durations={"pass": 0.25, "fail": 0.25, "error": 0.25, "skip": 0.25},
    )


def _accepted(runs: list[SuiteRun]) -> str | None:
    return acceptance_failure(summarize_baseline(runs, base_sha=_BASE_SHA), runs)


def test_acceptance_gate_takes_a_mostly_passing_stable_suite() -> None:
    statuses: dict[str, CaseStatus] = {f"t{n}": "passed" for n in range(80)}
    statuses.update({f"f{n}": "failed" for n in range(20)})
    statuses.update({f"s{n}": "skipped" for n in range(50)})

    assert _accepted([_suite(statuses), _suite(statuses)]) is None


@pytest.mark.parametrize(
    ("runs", "reason"),
    [
        ([_suite({}, failure="the build command failed with exit 2: make")], "build command"),
        ([_suite({}), _suite({})], "ran no tests"),
        ([_suite({"a": "skipped"}), _suite({"a": "skipped"})], "all 1 tests were skipped"),
        (
            [_suite({"a": "passed", "b": "failed"}), _suite({"a": "passed", "b": "failed"})],
            "only 1 of 2 tests passed",
        ),
    ],
)
def test_acceptance_gate_refuses_broken_or_empty_suites(runs: list[SuiteRun], reason: str) -> None:
    failure = _accepted(runs)

    assert failure is not None and reason in failure


def test_acceptance_gate_tolerates_one_flaky_test_but_not_more_than_two_percent() -> None:
    stable: dict[str, CaseStatus] = {f"t{n}": "passed" for n in range(98)}
    one_flaky = [_suite({**stable, "x": "passed"}), _suite({**stable, "x": "failed"})]
    assert _accepted(one_flaky) is None

    two_flaky = [
        _suite({**stable, "x": "passed", "y": "passed"}),
        _suite({**stable, "x": "failed", "y": "failed"}),
    ]
    assert _accepted(two_flaky) == "2 of 100 tests gave different results"


def test_acceptance_gate_refuses_failures_dominated_by_a_broken_environment() -> None:
    def suite(message: str) -> SuiteRun:
        results = {f"t{n}": CaseResult(f"t{n}", "passed", None, "") for n in range(90)}
        results.update({f"f{n}": CaseResult(f"f{n}", "failed", None, message) for n in range(10)})
        return _suite({}, results=results)

    missing_module = "ModuleNotFoundError: No module named 'yaml'"
    assert _accepted([suite(missing_module), suite(missing_module)]) == (
        "10 of the failing tests show that a Python module was unavailable"
    )
    offline = "OSError: [Errno 101] Network is unreachable"
    assert _accepted([suite(offline), suite(offline)]) is None


def test_a_suite_over_the_time_limit_is_refused() -> None:
    # A hung test command collects nothing; acceptance needs a finished run.
    assert _accepted([_suite({}, timed_out=True, duration_seconds=900.0)]) == (
        "the test command did not finish within 900 s"
    )


def _reported(framework: TestFramework, report: bytes) -> SuiteRun:
    return _suite({}, results=parse_report(framework, report))


def _junit(*cases: str) -> bytes:
    return ("<testsuites><testsuite>" + "".join(cases) + "</testsuite></testsuites>").encode()


def _case(classname: str, name: str, outcome: str = "") -> str:
    return f'<testcase classname="{classname}" name="{name}" time="0.1">{outcome}</testcase>'


_ASSERTION = '<failure message="AssertionError: assert 2 == 3">assert 2 == 3</failure>'
_FIXTURE_ERROR = '<error message="failed on setup with &quot;KeyError&quot;">KeyError</error>'
_COLLECTION_ERROR = '<error message="collection failure">ImportError: cannot import sub</error>'


def test_red_step_finds_new_and_newly_failing_tests_and_what_they_reproduce() -> None:
    base = _reported(
        "pytest",
        _junit(
            _case("tests.test_calc", "test_add"),
            _case("tests.test_cli", "test_run"),
            _case("tests.test_cli", "test_old_fail", _ASSERTION),
        ),
    )
    baseline = summarize_baseline([base, base], base_sha=_BASE_SHA)
    # The patch adds tests to test_calc for a function that does not exist yet, changes
    # test_run, and adds a test whose fixture errors.
    red = _reported(
        "pytest",
        _junit(
            _case("", "tests.test_calc", _COLLECTION_ERROR),
            _case("tests.test_cli", "test_run", _ASSERTION),
            _case("tests.test_cli", "test_old_fail", _ASSERTION),
            _case("tests.test_cli.TestNew", "test_assert", _ASSERTION),
            _case("tests.test_cli.TestNew", "test_fixture", _FIXTURE_ERROR),
            _case("tests.test_cli.TestNew", "test_pass"),
        ),
    )

    found = reproduction(baseline, red)

    assert found == Reproduction(
        targets=(
            "tests.test_cli.TestNew::test_assert",
            "tests.test_cli.TestNew::test_fixture",
            "tests.test_cli.TestNew::test_pass",
            "tests.test_cli::test_run",
        ),
        reproduced=("tests.test_cli.TestNew::test_assert", "tests.test_cli::test_run"),
        uncollected=("tests.test_calc",),
    )
    assert reproduction(baseline, _suite({}, timed_out=True)) == Reproduction((), (), ())
    assert reproduction(baseline, _suite({"x": "failed"}, per_test=False)).targets == ()


def test_without_per_test_results_the_suite_is_the_one_target() -> None:
    baseline = summarize_baseline(
        [_suite({SUITE_TEST_ID: "passed"}, per_test=False)] * 2, base_sha=_BASE_SHA
    )

    def red(message: str) -> SuiteRun:
        result = CaseResult(SUITE_TEST_ID, "failed", 1.0, message)
        return _suite({}, results={SUITE_TEST_ID: result}, per_test=False)

    assert reproduction(baseline, red("AssertionError: 2 != 3")) == Reproduction(
        (SUITE_TEST_ID,), (SUITE_TEST_ID,), ()
    )
    assert reproduction(baseline, red("ImportError: cannot import name 'add'")) == Reproduction(
        (SUITE_TEST_ID,), (), ()
    )
    passing = _suite({SUITE_TEST_ID: "passed"}, per_test=False)
    assert reproduction(baseline, passing) == Reproduction((SUITE_TEST_ID,), (), ())


def test_green_step_needs_every_target_to_pass_in_every_run() -> None:
    found = Reproduction(
        targets=("tests.test_cli::test_run",), reproduced=(), uncollected=("tests.test_calc",)
    )

    def green(*calc: str) -> SuiteRun:
        return _reported("pytest", _junit(_case("tests.test_cli", "test_run"), *calc))

    passing = green(
        _case("tests.test_calc", "test_add"),
        _case("tests.test_calc.TestSub", "test_sub"),
        _case("tests.test_calc", "test_slow", '<skipped message="slow"/>'),
    )
    assert green_failure(found, [passing, passing, passing]) is None
    assert green_failure(found, []) == "the patched tests were not run"
    assert green_failure(found, [passing, _suite({})]) == (
        "run 2 did not pass 2 patched tests: tests.test_cli::test_run, tests.test_calc"
    )
    assert green_failure(found, [green(_case("", "tests.test_calc", _COLLECTION_ERROR))]) == (
        "run 1 did not pass 1 patched tests: tests.test_calc"
    )
    assert green_failure(
        found,
        [green(_case("tests.test_calc", "test_add"), _case("tests.test_calc", "b", _ASSERTION))],
    ) == ("run 1 did not pass 1 patched tests: tests.test_calc::b")
    assert green_failure(found, [_suite({}, timed_out=True)]) == (
        "run 1 of the patched tests timed out"
    )


def _go_events(*events: dict[str, object]) -> bytes:
    return b"\n".join(json.dumps(event).encode() for event in events)


def test_red_green_on_a_go_package_that_does_not_build_without_the_fix() -> None:
    package = "example.com/m/calc"
    base = _reported(
        "go",
        _go_events(
            {"Action": "run", "Package": package, "Test": "TestAdd"},
            {"Action": "pass", "Package": package, "Test": "TestAdd"},
            {"Action": "pass", "Package": package},
        ),
    )
    baseline = summarize_baseline([base, base], base_sha=_BASE_SHA)
    red = _reported(
        "go",
        _go_events(
            {"Action": "output", "Package": package, "Output": "calc_test.go:9: undefined: Sub\n"},
            {"Action": "fail", "Package": package},
        ),
    )

    found = reproduction(baseline, red)

    assert found == Reproduction(targets=(), reproduced=(), uncollected=(package,))
    green = _reported(
        "go",
        _go_events(
            {"Action": "run", "Package": package, "Test": "TestAdd"},
            {"Action": "pass", "Package": package, "Test": "TestAdd"},
            {"Action": "run", "Package": package, "Test": "TestSub"},
            {"Action": "pass", "Package": package, "Test": "TestSub"},
            {"Action": "pass", "Package": package},
        ),
    )
    assert green_failure(found, [green] * 3) is None
    assert green_failure(found, [red]) == f"run 1 did not pass 1 patched tests: {package}"


def test_red_green_on_a_jest_file_that_fails_to_load_without_the_fix() -> None:
    def jest(*suites: dict[str, object]) -> SuiteRun:
        return _reported("jest", json.dumps({"testResults": list(suites)}).encode())

    loading = {
        "name": "/workspace/src/sub.test.js",
        "status": "failed",
        "message": "Cannot find module '../sub' from 'src/sub.test.js'",
        "assertionResults": [],
    }
    passing = {
        "name": "/workspace/src/sub.test.js",
        "status": "passed",
        "assertionResults": [{"fullName": "sub works", "status": "passed"}],
    }
    baseline = summarize_baseline([jest(), jest()], base_sha=_BASE_SHA)

    found = reproduction(baseline, jest(loading))

    assert found == Reproduction(targets=(), reproduced=(), uncollected=("src/sub.test.js",))
    assert green_failure(found, [jest(passing)] * 3) is None
    assert green_failure(found, [jest(loading)]) == (
        "run 1 did not pass 1 patched tests: src/sub.test.js"
    )


def test_regressions_are_stable_passes_that_fail_or_vanish_unless_removed() -> None:
    baseline = summarize_baseline(
        [_suite({"a": "passed", "b": "passed", "c": "passed", "d": "failed"})] * 2,
        base_sha=_BASE_SHA,
    )
    run = _suite({"a": "error", "d": "passed"})

    assert new_failures(baseline, run) == ["a", "b", "c"]
    assert new_failures(baseline, run, removed_tests={"c"}) == ["a", "b"]
    assert new_failures(baseline, run, full_suite=False) == ["a"]
    assert still_failing(["a", "b"], _suite({"a": "passed"})) == ["b"]
    assert still_failing(["a"], _suite({}, failure="the sandbox container stopped")) == ["a"]
    with pytest.raises(ValueError, match="says nothing"):
        new_failures(baseline, _suite({}, timed_out=True))


def test_a_stable_pass_that_is_now_skipped_is_a_regression() -> None:
    baseline = summarize_baseline(
        [_suite({"a": "passed", "b": "passed", "s": "skipped"})] * 2, base_sha=_BASE_SHA
    )
    run = _suite({"a": "skipped", "b": "passed", "s": "skipped"})

    assert new_failures(baseline, run) == ["a"]
    assert still_failing(["a"], _suite({"a": "skipped"})) == ["a"]
