from __future__ import annotations

from autocontribute.config import AutocontributeConfig
from autocontribute.domain import CommandResult, CriticReview, ReviewScores
from autocontribute.quality import evaluate_quality


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


def _passing_command() -> CommandResult:
    return CommandResult(
        command="pytest tests/test_math.py",
        exit_code=0,
        duration_seconds=1.2,
        stdout="1 passed",
        stderr="",
    )


def _gate_map(report: object) -> dict[str, bool]:
    return {gate.gate: gate.passed for gate in report.gates}  # type: ignore[attr-defined]


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
        review=_review(),
        config=AutocontributeConfig(),
    )

    assert report.ready
    assert report.changed_lines == 2
