from __future__ import annotations

import pytest

from autocontribute.config import AutocontributeConfig
from autocontribute.domain import CommandResult, CriticReview, ReviewScores
from autocontribute.quality import (
    actionable_validation_failure_reason,
    evaluate_quality,
    infrastructure_failure_reason,
)


def _review(
    *,
    score: int = 95,
    verdict: str = "approve",
    blockers: list[str] | None = None,
    missing: list[str] | None = None,
) -> CriticReview:
    return CriticReview(
        verdict=verdict,
        summary="The change is focused and verified.",
        scores=ReviewScores(
            correctness=score,
            issue_alignment=score,
            tests=score,
            repository_conventions=score,
            diff_hygiene=score,
            maintainer_clarity=score,
        ),
        blocking_findings=blockers or [],
        non_blocking_findings=[],
        issue_requirements_met=["regression fixed"],
        issue_requirements_missing=missing or [],
        test_evidence_assessment="The regression test fails before and passes after.",
        maintainer_perspective="Ready for review.",
    )


REQUIRED_COMMAND = "pytest tests/test_math.py"


def _passing_command(command: str = REQUIRED_COMMAND) -> CommandResult:
    return CommandResult(
        command=command,
        exit_code=0,
        duration_seconds=1.2,
        stdout="1 passed",
        stderr="",
    )


def _gate_map(report: object) -> dict[str, bool]:
    return {gate.gate: gate.passed for gate in report.gates}  # type: ignore[attr-defined]


def _gate_evidence(report: object, name: str) -> str:
    return next(  # type: ignore[attr-defined]
        gate.evidence for gate in report.gates if gate.gate == name
    )


CLEAN_DIFF = """\
diff --git a/src/math.py b/src/math.py
index 1111111..2222222 100644
--- a/src/math.py
+++ b/src/math.py
@@ -1 +1 @@
-return 1
+return 2
diff --git a/tests/test_math.py b/tests/test_math.py
index 3333333..4444444 100644
--- a/tests/test_math.py
+++ b/tests/test_math.py
@@ -1 +1 @@
-assert calculate() == 1
+assert calculate() == 2
"""


def test_clean_diff_passes_all_quality_gates() -> None:
    report = evaluate_quality(
        diff=CLEAN_DIFF,
        command_results=[_passing_command()],
        required_commands=[REQUIRED_COMMAND],
        review=_review(),
        config=AutocontributeConfig(),
    )

    assert report.ready
    assert report.readiness_score == 95
    assert report.changed_files == 2
    assert report.changed_lines == 4
    assert not report.failed_gates


def test_bugfix_requires_same_reproduction_to_fail_then_pass() -> None:
    patched = _passing_command()
    baseline = patched.model_copy(update={"exit_code": 1, "stdout": "", "stderr": "AssertionError"})
    report = evaluate_quality(
        diff=CLEAN_DIFF,
        command_results=[patched],
        required_commands=[REQUIRED_COMMAND],
        baseline_result=baseline,
        contribution_kind="bugfix",
        review=_review(),
        config=AutocontributeConfig(),
    )
    assert _gate_map(report)["regression_evidence"]
    assert report.ready

    missing = evaluate_quality(
        diff=CLEAN_DIFF,
        command_results=[patched],
        required_commands=[REQUIRED_COMMAND],
        contribution_kind="bugfix",
        review=_review(),
        config=AutocontributeConfig(),
    )
    assert not _gate_map(missing)["regression_evidence"]
    assert not missing.ready


def test_scope_limits_are_hard_gates() -> None:
    config = AutocontributeConfig(quality={"max_files_changed": 1, "max_changed_lines": 3})

    report = evaluate_quality(
        diff=CLEAN_DIFF,
        command_results=[_passing_command()],
        required_commands=[REQUIRED_COMMAND],
        review=_review(),
        config=config,
    )

    gates = _gate_map(report)
    assert not report.ready
    assert not gates["file_count"]
    assert not gates["changed_lines"]


UNSAFE_DIFF = """\
diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
new file mode 100644
--- /dev/null
+++ b/.github/workflows/ci.yml
@@ -0,0 +1 @@
+token: ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ
diff --git a/requirements.txt b/requirements.txt
index 1111111..2222222 100644
--- a/requirements.txt
+++ b/requirements.txt
@@ -1 +1 @@
-safe-package==1.0
+safe-package==2.0
diff --git a/assets/logo.png b/assets/logo.png
new file mode 100644
index 0000000..1111111
GIT binary patch
literal 3
abc
diff --git a/link b/link
new file mode 120000
index 0000000..1111111
--- /dev/null
+++ b/link
@@ -0,0 +1 @@
+/etc/passwd
diff --git a/run.sh b/run.sh
old mode 100644
new mode 100755
"""


def test_unsafe_diff_fails_file_and_policy_gates_without_leaking_secret() -> None:
    report = evaluate_quality(
        diff=UNSAFE_DIFF,
        command_results=[_passing_command()],
        required_commands=[REQUIRED_COMMAND],
        review=_review(),
        config=AutocontributeConfig(),
    )

    gates = _gate_map(report)
    assert not report.ready
    assert not gates["no_binary_files"]
    assert not gates["no_symlinks"]
    assert not gates["no_mode_changes"]
    assert not gates["forbidden_paths"]
    assert not gates["dependency_policy"]
    assert not gates["workflow_policy"]
    assert not gates["secret_scan"]
    serialized = report.model_dump_json()
    assert "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ" not in serialized


def test_policy_can_allow_dependency_and_workflow_changes_explicitly() -> None:
    config = AutocontributeConfig(
        policy={"allow_dependency_changes": True, "allow_workflow_changes": True},
        quality={"forbidden_paths": []},
    )
    diff = """\
diff --git a/package.json b/package.json
index 1111111..2222222 100644
--- a/package.json
+++ b/package.json
@@ -1 +1 @@
-{"dependencies": {"safe-package": "1"}}
+{"dependencies": {"safe-package": "2"}}
diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
index 3333333..4444444 100644
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -1 +1 @@
-run: old-command
+run: new-command
"""

    report = evaluate_quality(
        diff=diff,
        command_results=[_passing_command()],
        required_commands=[REQUIRED_COMMAND],
        review=_review(),
        config=config,
    )

    gates = _gate_map(report)
    assert gates["dependency_policy"]
    assert gates["workflow_policy"]
    assert report.ready


def test_validation_and_critic_evidence_are_independent_gates() -> None:
    failed_validation = CommandResult(
        command="pytest",
        exit_code=0,
        duration_seconds=900,
        stdout="",
        stderr="",
        timed_out=True,
    )
    report = evaluate_quality(
        diff=CLEAN_DIFF,
        command_results=[failed_validation],
        required_commands=["pytest"],
        review=_review(
            score=79,
            verdict="reject",
            blockers=["The fix changes an unrelated behavior."],
            missing=["Preserve compatibility."],
        ),
        config=AutocontributeConfig(),
    )

    gates = _gate_map(report)
    assert not gates["validation"]
    assert not gates["critic_verdict"]
    assert not gates["critic_blockers"]
    assert not gates["issue_requirements"]
    assert not gates["minimum_review_dimension"]
    assert not gates["readiness_score"]


def test_required_validation_fails_when_no_trusted_commands_are_supplied() -> None:
    report = evaluate_quality(
        diff=CLEAN_DIFF,
        command_results=[_passing_command("model-suggested-check")],
        required_commands=[],
        review=_review(),
        config=AutocontributeConfig(),
    )

    gates = _gate_map(report)
    assert gates["validation"]
    assert not gates["required_validation"]
    assert "no operator-required commands" in _gate_evidence(report, "required_validation")


def test_required_validation_fails_when_a_required_command_was_skipped() -> None:
    report = evaluate_quality(
        diff=CLEAN_DIFF,
        command_results=[_passing_command("trusted-one")],
        required_commands=["trusted-one", "trusted-two"],
        review=_review(),
        config=AutocontributeConfig(),
    )

    assert not _gate_map(report)["required_validation"]
    assert "not executed: 'trusted-two'" in _gate_evidence(report, "required_validation")


def test_required_validation_fails_when_a_required_command_failed() -> None:
    failed = _passing_command("trusted-check").model_copy(
        update={"exit_code": 1, "stdout": "", "stderr": "test failed"}
    )
    report = evaluate_quality(
        diff=CLEAN_DIFF,
        command_results=[failed],
        required_commands=["trusted-check"],
        review=_review(),
        config=AutocontributeConfig(),
    )

    gates = _gate_map(report)
    assert not gates["required_validation"]
    assert not gates["validation"]
    assert "failed: 'trusted-check'" in _gate_evidence(report, "required_validation")


@pytest.mark.parametrize(
    ("update", "reason"),
    [
        ({"exit_code": 124, "timed_out": True}, "timed out"),
        ({"exit_code": -9}, "host signal"),
        ({"exit_code": 125}, "could not be started"),
        ({"exit_code": 126}, "exit code 126"),
        ({"exit_code": 127}, "exit code 127"),
        ({"exit_code": 130}, "external or resource-limit termination"),
        ({"exit_code": 137}, "external or resource-limit termination"),
        ({"exit_code": 143}, "external or resource-limit termination"),
        ({"stderr": "sh: tool: command not found"}, "not installed"),
        ({"stderr": "No such file or directory"}, "file or executable was missing"),
        ({"stdout": "no tests collected"}, "discovered no tests"),
        ({"stdout": "No tests were executed!"}, "discovered no tests"),
        ({"stderr": "ModuleNotFoundError: No module named 'suite'"}, "module was unavailable"),
        ({"stderr": "ImportError: No module named dependency"}, "module was unavailable"),
        ({"stderr": "Error: Cannot find module 'dependency'"}, "module was unavailable"),
        (
            {"stderr": "Sources/App.swift:1:8: error: no such module 'Dependency'"},
            "module was unavailable",
        ),
        (
            {"stderr": "src/Main.hs:3:1: error: Could not find module 'Dependency'"},
            "module was unavailable",
        ),
        (
            {"stderr": "src/main.m:1:9: fatal error: module 'MissingSDK' not found"},
            "module was unavailable",
        ),
        (
            {"stderr": "src/main.swift:1:1: error: missing required module 'SwiftShims'"},
            "module was unavailable",
        ),
        (
            {"stderr": "src/Main.hs:3:1: error: Could not load module 'Missing.Package'"},
            "module was unavailable",
        ),
        ({"stderr": "npm ERR! Missing script: test"}, "script was missing"),
        ({"stderr": 'error Command "test" not found.'}, "script was missing"),
        (
            {"stderr": "INTERNALERROR> AssertionError: plugin state was not initialized"},
            "runner failed internally",
        ),
        (
            {
                "stderr": (
                    '  File "/usr/local/lib/python3.9/site-packages/tool/core.py", line 7\n'
                    "    match value:\n"
                    "          ^\n"
                    "SyntaxError: invalid syntax"
                )
            },
            "package was incompatible",
        ),
        (
            {"stderr": "error[E0463]: can't find crate for `std`\ntarget may not be installed"},
            "dependency or type environment",
        ),
        (
            {"stderr": "error[E0463]: can't find crate for `serde`"},
            "dependency or type environment",
        ),
        (
            {"stderr": "error TS2688: Cannot find type definition file for 'node'."},
            "dependency or type environment",
        ),
        (
            {"stderr": "Example.java:3: error: package dep does not exist"},
            "dependency or type environment",
        ),
        (
            {
                "stderr": (
                    "Program.cs(3,2): error CS0246: The type or namespace name 'Dep' "
                    "could not be found"
                )
            },
            "dependency or type environment",
        ),
        (
            {"stderr": "[ERROR] COMPILATION ERROR: invalid target release: 21"},
            "toolchain was unavailable",
        ),
        ({"stderr": "OSError: [Errno 28] No space left on device"}, "storage was unavailable"),
        ({"stderr": "java.lang.OutOfMemoryError: Java heap space"}, "memory was exhausted"),
        ({"stderr": "Permission denied"}, "lacked permission"),
        ({"stderr": "curl: Could not resolve host: example.test"}, "name resolution failed"),
        (
            {"stderr": "npm ERR! getaddrinfo ENOTFOUND registry.npmjs.org"},
            "name resolution failed",
        ),
        (
            {"stderr": "java.net.UnknownHostException: repo.maven.apache.org"},
            "name resolution failed",
        ),
        ({"stderr": "OSError: Network is unreachable"}, "network was unavailable"),
        ({"stderr": "curl: Could not connect to server"}, "network was unavailable"),
        (
            {"stderr": "FAILED test_remote.py - ProxyError: Cannot connect to proxy"},
            "network was unavailable",
        ),
        (
            {"stderr": "Cannot connect to the Docker daemon. Is the docker daemon running?"},
            "Docker validation service",
        ),
        (
            {"stderr": "[output truncated by autocontribute]"},
            "output was truncated",
        ),
    ],
)
def test_infrastructure_failures_are_not_regression_evidence(
    update: dict[str, object], reason: str
) -> None:
    patched = _passing_command()
    baseline = patched.model_copy(update={"exit_code": 1, "stdout": "", "stderr": "", **update})

    assert infrastructure_failure_reason(baseline) is not None
    assert actionable_validation_failure_reason(baseline) is None

    report = evaluate_quality(
        diff=CLEAN_DIFF,
        command_results=[patched],
        required_commands=[REQUIRED_COMMAND],
        baseline_result=baseline,
        contribution_kind="bugfix",
        review=_review(),
        config=AutocontributeConfig(),
    )

    assert not _gate_map(report)["regression_evidence"]
    evidence = _gate_evidence(report, "regression_evidence")
    assert "baseline failure rejected" in evidence
    assert reason in evidence


def test_assertion_failure_is_actionable_validation_evidence() -> None:
    result = _passing_command().model_copy(
        update={"exit_code": 1, "stdout": "", "stderr": "AssertionError: expected 2"}
    )

    assert infrastructure_failure_reason(result) is None
    assert actionable_validation_failure_reason(result) == "an assertion failed"


@pytest.mark.parametrize(
    "stderr",
    [
        "FAILED tests/test_value.py::test_value - assert 1 == 2",
        "src/value.py:12:8: error: incompatible types in assignment",
        "src/value.ts(12,8): error TS2322: Type 'str' is not assignable",
        "error[E0308]: mismatched types\n --> src/lib.rs:12:8",
        "[ERROR] src/main/java/Example.java:[12,8] incompatible types: String cannot be int",
        "src/value.py:12:8: E501 line too long",
    ],
)
def test_explicit_test_compile_and_lint_failures_are_actionable(stderr: str) -> None:
    result = _passing_command().model_copy(update={"exit_code": 1, "stdout": "", "stderr": stderr})

    assert actionable_validation_failure_reason(result) is not None


def test_unknown_nonzero_failure_is_not_actionable() -> None:
    result = _passing_command().model_copy(update={"exit_code": 1, "stdout": "", "stderr": ""})

    assert infrastructure_failure_reason(result) is None
    assert actionable_validation_failure_reason(result) is None


@pytest.mark.parametrize(
    "stderr",
    [
        "error TS2322: Type 'str' is not assignable",
        "error[E0308]: mismatched types",
        "COMPILATION ERROR",
    ],
)
def test_unlocated_compiler_summary_is_not_actionable(stderr: str) -> None:
    result = _passing_command().model_copy(update={"exit_code": 1, "stdout": "", "stderr": stderr})

    assert infrastructure_failure_reason(result) is None
    assert actionable_validation_failure_reason(result) is None


@pytest.mark.parametrize(
    "stderr",
    [
        "site-packages/tool.py line 1 " * 5_000,
        "error[E1234]: " * 5_000,
        "error CS0246: type x " * 5_000,
    ],
)
def test_failure_classification_handles_repeated_signatures_without_overlap(stderr: str) -> None:
    result = _passing_command().model_copy(update={"exit_code": 1, "stdout": "", "stderr": stderr})

    assert actionable_validation_failure_reason(result) is None


def test_passing_command_is_never_classified_as_infrastructure_failure() -> None:
    result = _passing_command().model_copy(update={"stdout": "no tests collected"})

    assert infrastructure_failure_reason(result) is None
    assert actionable_validation_failure_reason(result) is None


def test_missing_validation_and_unsafe_paths_fail_closed() -> None:
    diff = """\
diff --git a/../outside.py b/../outside.py
index 1111111..2222222 100644
--- a/../outside.py
+++ b/../outside.py
@@ -1 +1 @@
-old = True
+new = True
"""
    report = evaluate_quality(
        diff=diff,
        command_results=[],
        required_commands=[REQUIRED_COMMAND],
        review=_review(),
        config=AutocontributeConfig(),
    )

    gates = _gate_map(report)
    assert not report.ready
    assert not gates["safe_paths"]
    assert not gates["validation"]


def test_empty_or_unparseable_diff_never_becomes_ready() -> None:
    report = evaluate_quality(
        diff="not a git diff",
        command_results=[_passing_command()],
        required_commands=[REQUIRED_COMMAND],
        review=_review(),
        config=AutocontributeConfig(),
    )

    gates = _gate_map(report)
    assert not report.ready
    assert not gates["diff_present"]
    assert not gates["file_count"]
    assert not gates["changed_lines"]


def test_diff_content_that_resembles_file_headers_is_counted() -> None:
    diff = """\
diff --git a/operators.txt b/operators.txt
index 1111111..2222222 100644
--- a/operators.txt
+++ b/operators.txt
@@ -1 +1 @@
----old
++++new
"""

    report = evaluate_quality(
        diff=diff,
        command_results=[_passing_command()],
        required_commands=[REQUIRED_COMMAND],
        review=_review(),
        config=AutocontributeConfig(),
    )

    assert report.ready
    assert report.changed_lines == 2
