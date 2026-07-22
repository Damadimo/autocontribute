import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

import autocontribute.cli as cli
from autocontribute.cli import app
from autocontribute.config import load_config
from autocontribute.deployment import compute_deployment_fingerprint
from autocontribute.domain import (
    CommandResult,
    CriticReview,
    FileEdit,
    GateResult,
    IssueCandidate,
    IssueComment,
    PatchProposal,
    QualityReport,
    RepositoryInfo,
    ReviewScores,
    RunStatus,
)
from autocontribute.evaluation import EvaluationStore, EvaluationVerdict
from autocontribute.exceptions import PublicationResumeRequired, StateError
from autocontribute.lifecycle import LifecycleSyncResult
from autocontribute.preparation import (
    compute_preparation_config_fingerprint,
    compute_preparation_fingerprint,
    render_validation_artifact,
)
from autocontribute.store import RunStore

runner = CliRunner()

_REVIEW_PATCH = (
    "diff --git a/src/widget.py b/src/widget.py\n"
    "--- a/src/widget.py\n"
    "+++ b/src/widget.py\n"
    "@@ -1 +1 @@\n"
    "-review_patch_old_marker = 1\n"
    "+review_patch_new_marker = 2\n"
)


class _ReviewGitHub:
    api_origin = "https://api.github.com"

    def __enter__(self):  # type: ignore[no-untyped-def]
        return self

    def __exit__(self, *_: object) -> None:
        pass

    def authenticated_login(self) -> str:
        return "octocat"


def _ready_review_run(tmp_path: Path) -> tuple[Path, RunStore, str]:
    config_path = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config_path.write_text(
        "identity:\n"
        "  name: Review Author Exact Marker\n"
        "  email: review-author@example.invalid\n"
        "github:\n"
        "  repositories: [example/project]\n"
        "validation:\n"
        "  required_commands:\n"
        "    example/project: [python -m pytest]\n"
        f"storage:\n  path: {state}\n",
        encoding="utf-8",
    )
    settings = load_config(config_path)
    store = RunStore(state)
    manifest = store.create_run()
    now = datetime.now(UTC)
    manifest.candidate = IssueCandidate(
        repository="example/project",
        number=42,
        title="ISSUE_TITLE_EXACT_MARKER",
        body="ISSUE_BODY_EXACT_MARKER\nSecond exact issue-body line.\x1b[2J",
        html_url="https://github.com/example/project/issues/42",
        state="open",
        author="issue-author-marker",
        labels=["bug", "help wanted"],
        assignees=[],
        comments=1,
        discussion=[
            IssueComment(
                author="discussion-author-marker",
                author_association="MEMBER",
                body="ISSUE_DISCUSSION_EXACT_MARKER",
                html_url=("https://github.com/example/project/issues/42#issuecomment-77"),
                created_at=now - timedelta(hours=1),
                updated_at=now,
            )
        ],
        created_at=now - timedelta(days=2),
        updated_at=now,
    )
    manifest.repository = RepositoryInfo(
        full_name="example/project",
        html_url="https://github.com/example/project",
        clone_url="https://github.com/example/project.git",
        default_branch="main",
        stars=10_000,
        archived=False,
        disabled=False,
        private=False,
        pushed_at=now,
        license_spdx="MIT",
    )
    manifest.base_sha = "a" * 40
    edit = FileEdit(
        operation="replace",
        path="src/widget.py",
        find="review_patch_old_marker = 1\n",
        replace="review_patch_new_marker = 2\n",
        content=None,
        rationale="Exercise exact immutable-review evidence.",
    )
    manifest.proposal = PatchProposal(
        summary="Apply the exact review fixture change.",
        edits=[edit],
        validation_commands=["python -m pytest"],
        commit_message="COMMIT_MESSAGE_EXACT_MARKER",
        pull_request_title="PR_TITLE_EXACT_MARKER",
        pull_request_body=("PR_BODY_EXACT_MARKER\n\n---\n\n" + settings.policy.ai_disclosure),
        limitations=[],
    )
    review = CriticReview(
        verdict="approve",
        summary="The focused fixture change is ready.",
        scores=ReviewScores(
            correctness=95,
            issue_alignment=95,
            tests=95,
            repository_conventions=95,
            diff_hygiene=95,
            maintainer_clarity=95,
        ),
        blocking_findings=[],
        non_blocking_findings=[],
        issue_requirements_met=["The exact marker is updated."],
        issue_requirements_missing=[],
        test_evidence_assessment="The configured command passed.",
        maintainer_perspective="Small and reviewable.",
    )
    manifest.patched_validation = [
        CommandResult(
            command="python -m pytest",
            exit_code=0,
            duration_seconds=1.25,
            stdout="VALIDATION_STDOUT_EXACT_MARKER",
            stderr="VALIDATION_STDERR_EXACT_MARKER",
        )
    ]
    manifest.quality = QualityReport(
        ready=True,
        readiness_score=95,
        gates=[GateResult(gate="fixture", passed=True, evidence="passed")],
        review=review,
        changed_files=1,
        changed_lines=2,
    )
    store.write_artifact(manifest.run_id, "contribution.patch", _REVIEW_PATCH)
    store.write_artifact(
        manifest.run_id,
        "validation.json",
        render_validation_artifact(manifest),
    )
    manifest.preparation_config_fingerprint = compute_preparation_config_fingerprint(
        settings,
        repository="example/project",
    )
    manifest.preparation_fingerprint = compute_preparation_fingerprint(
        manifest,
        diff=_REVIEW_PATCH,
    )
    manifest.status = RunStatus.READY_FOR_APPROVAL
    store.save(manifest, event="fixture.ready_for_review", details={})
    return config_path, store, manifest.run_id


def test_approval_review_ignores_tampered_report_and_approves_displayed_fingerprint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path, store, run_id = _ready_review_run(tmp_path)
    forged_marker = "FORGED_REPORT_CONTENT_MUST_NEVER_BE_REVIEWED"
    (store.artifact_dir(run_id) / "report.md").write_text(
        f"# Trusted review\n\n{forged_marker}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "_github_client", lambda *_: _ReviewGitHub())

    shown = runner.invoke(
        app,
        ["runs", "show", run_id, "--config", str(config_path)],
    )
    approved = runner.invoke(
        app,
        ["approve", run_id, "--yes", "--config", str(config_path)],
    )

    assert shown.exit_code == 0, shown.output
    assert approved.exit_code == 0, approved.output
    durable = store.get(run_id)
    assert durable.status == RunStatus.APPROVED
    assert durable.approval is not None
    expected_markers = [
        "ISSUE_TITLE_EXACT_MARKER",
        "ISSUE_BODY_EXACT_MARKER",
        "Second exact issue-body line.",
        "discussion-author-marker",
        "MEMBER",
        "ISSUE_DISCUSSION_EXACT_MARKER",
        "https://github.com/example/project/issues/42#issuecomment-77",
        "diff --git a/src/widget.py b/src/widget.py",
        "-review_patch_old_marker = 1",
        "+review_patch_new_marker = 2",
        "VALIDATION_STDOUT_EXACT_MARKER",
        "VALIDATION_STDERR_EXACT_MARKER",
        "PR_TITLE_EXACT_MARKER",
        "PR_BODY_EXACT_MARKER",
        "COMMIT_MESSAGE_EXACT_MARKER",
        "Review Author Exact Marker",
        "review-author@example.invalid",
        durable.approval.manifest_hash,
    ]
    for result in (shown, approved):
        assert forged_marker not in result.output
        assert "\x1b" not in result.output
        assert r"\x1b[2J" in result.output
        for marker in expected_markers:
            assert marker in result.output
        assert result.output.count("Review Author Exact Marker") >= 2
        assert result.output.count("review-author@example.invalid") >= 2


def test_approval_rejects_evidence_race_after_interactive_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path, store, run_id = _ready_review_run(tmp_path)
    monkeypatch.setattr(cli, "_github_client", lambda *_: _ReviewGitHub())
    confirmations: list[str] = []

    def mutate_evidence_then_confirm(prompt: str, **_: object) -> bool:
        confirmations.append(prompt)
        mutated = store.get(run_id)
        assert mutated.proposal is not None
        mutated.proposal.pull_request_title = "PR_TITLE_RACED_AFTER_REVIEW"
        patch = (store.artifact_dir(run_id) / "contribution.patch").read_bytes()
        mutated.preparation_fingerprint = compute_preparation_fingerprint(
            mutated,
            diff=patch,
        )
        store.save(mutated, event="fixture.review_race", details={})
        return True

    monkeypatch.setattr(cli.typer, "confirm", mutate_evidence_then_confirm)

    result = runner.invoke(
        app,
        ["approve", run_id, "--config", str(config_path)],
    )

    assert result.exit_code == 1, result.output
    assert len(confirmations) == 1
    assert "PR_TITLE_EXACT_MARKER" in result.output
    assert "PR_TITLE_RACED_AFTER_REVIEW" not in result.output
    assert "review" in result.output.casefold()
    assert "changed" in result.output.casefold()
    durable = store.get(run_id)
    assert durable.status == RunStatus.READY_FOR_APPROVAL
    assert durable.approval is None
    assert "approval.created" not in {event["event_type"] for event in store.events(run_id)}


def test_init_and_config_validation_are_offline(tmp_path: Path) -> None:
    config = tmp_path / "autocontribute.yml"

    initialized = runner.invoke(app, ["init", "--path", str(config)])
    validated = runner.invoke(
        app,
        ["config", "validate", "--config", str(config)],
    )

    assert initialized.exit_code == 0, initialized.output
    assert config.is_file()
    assert "Configuration is valid" in validated.output
    assert "gpt-5.6" in validated.output


def test_init_does_not_overwrite_without_force(tmp_path: Path) -> None:
    config = tmp_path / "autocontribute.yml"
    config.write_text("sentinel", encoding="utf-8")

    result = runner.invoke(app, ["init", "--path", str(config)])

    assert result.exit_code == 1
    assert config.read_text(encoding="utf-8") == "sentinel"


def test_expert_evaluation_cli_records_and_reports_shadow_gate(tmp_path: Path) -> None:
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    settings = load_config(config)
    store = RunStore(state)
    run = store.create_run(deployment_fingerprint=compute_deployment_fingerprint(settings))
    store.transition(run, RunStatus.DISCOVERING, reason="fixture")
    store.transition(run, RunStatus.SKIPPED, reason="fixture")

    recorded = runner.invoke(
        app,
        [
            "eval",
            "record",
            run.run_id,
            "--reviewer",
            "expert",
            "--verdict",
            "correct_abstention",
            "--yes",
            "--config",
            str(config),
        ],
    )
    report = runner.invoke(app, ["eval", "report", "--config", str(config), "--json"])

    assert recorded.exit_code == 0, recorded.output
    assert "correct_abstention" in recorded.output
    assert report.exit_code == 0, report.output
    assert '"total_cases": 1' in report.output
    assert '"shadow_gate_passed": false' in report.output
    assert run.deployment_fingerprint in report.output


def test_eval_record_previews_every_field_and_refusal_writes_nothing(tmp_path: Path) -> None:
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    store = RunStore(state)
    run = store.create_run()
    store.transition(run, RunStatus.DISCOVERING, reason="fixture")
    store.transition(run, RunStatus.SKIPPED, reason="fixture")

    result = runner.invoke(
        app,
        [
            "eval",
            "record",
            run.run_id,
            "--reviewer",
            "expert\x1b[2J",
            "--verdict",
            "correct_abstention",
            "--notes",
            "Exact evidence\u202e marker",
            "--policy-failure",
            "--config",
            str(config),
        ],
        input="n\n",
    )

    assert result.exit_code == 1
    assert "BEGIN COMPLETE EVALUATION JSON" in result.output
    assert '"agent_prepared": false' in result.output
    assert '"policy_failure": true' in result.output
    assert '"security_failure": false' in result.output
    assert '"etiquette_failure": false' in result.output
    assert '"verdict": "correct_abstention"' in result.output
    assert "\\u001b[2J" in result.output
    assert "\\u202e" in result.output
    assert "\x1b" not in result.output
    assert not store.evaluation_revision_anchors()
    assert not list((state / "evaluations").glob("*.json"))


def test_eval_record_rejects_subject_drift_after_confirmation_preview(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    store = RunStore(state)
    run = store.create_run()
    store.transition(run, RunStatus.DISCOVERING, reason="fixture")
    store.transition(run, RunStatus.SKIPPED, reason="fixture")

    def mutate_subject_then_confirm(_: str, **__: object) -> bool:
        changed = store.get(run.run_id)
        changed.error = "Evidence changed during the confirmation prompt."
        store.save(changed, event="fixture.evaluation_confirmation_race", details={})
        return True

    monkeypatch.setattr(cli.typer, "confirm", mutate_subject_then_confirm)
    result = runner.invoke(
        app,
        [
            "eval",
            "record",
            run.run_id,
            "--reviewer",
            "expert",
            "--verdict",
            "correct_abstention",
            "--config",
            str(config),
        ],
    )

    assert result.exit_code == 1, result.output
    assert "BEGIN COMPLETE EVALUATION JSON" in result.output
    assert "subject no longer matches" in result.output
    assert not store.evaluation_revision_anchors()


def test_eval_amend_appends_a_confirmed_full_replacement(tmp_path: Path) -> None:
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    store = RunStore(state)
    run = store.create_run()
    store.transition(run, RunStatus.DISCOVERING, reason="fixture")
    store.transition(run, RunStatus.SKIPPED, reason="fixture")
    evaluations = EvaluationStore(store)
    initial = evaluations.record(
        run.run_id,
        reviewer="initial expert",
        verdict=EvaluationVerdict.CORRECT_ABSTENTION,
        policy_failure=True,
        notes="This judgment contained a transcription error.",
    )

    result = runner.invoke(
        app,
        [
            "eval",
            "amend",
            run.run_id,
            "--reviewer",
            "correcting expert",
            "--verdict",
            "incorrect_abstention",
            "--reason",
            "The original verdict and safety flag were transcribed incorrectly.",
            "--notes",
            "Second review found an actionable issue.",
            "--yes",
            "--config",
            str(config),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Exact expert-evaluation preview (revision 2)" in result.output
    assert '"amendment_reason"' in result.output
    assert '"policy_failure": false' in result.output
    assert "Appended revision 2" in result.output
    history = evaluations.history(run.run_id)
    assert history[0] == initial
    assert len(history) == 2
    assert history[-1].verdict == EvaluationVerdict.INCORRECT_ABSTENTION
    assert not history[-1].policy_failure
    assert evaluations.list() == [history[-1]]


def test_state_backup_cli_creates_verified_snapshot_and_requires_overwrite(
    tmp_path: Path,
) -> None:
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    output = tmp_path / "persistence" / "state.sqlite3"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    store = RunStore(state)
    run = store.create_run()

    created = runner.invoke(
        app,
        [
            "state",
            "backup",
            "--config",
            str(config),
            "--output",
            str(output),
        ],
    )

    assert created.exit_code == 0, created.output
    assert "Verified state snapshot" in created.output
    with sqlite3.connect(output) as snapshot:
        assert snapshot.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert snapshot.execute(
            "SELECT run_id FROM runs WHERE run_id = ?", (run.run_id,)
        ).fetchone() == (run.run_id,)

    refused = runner.invoke(
        app,
        [
            "state",
            "backup",
            "--config",
            str(config),
            "--output",
            str(output),
        ],
    )
    replaced = runner.invoke(
        app,
        [
            "state",
            "backup",
            "--config",
            str(config),
            "--output",
            str(output),
            "--overwrite",
        ],
    )

    assert refused.exit_code == 1
    assert "already exists" in refused.output
    assert replaced.exit_code == 0, replaced.output


def test_state_backup_cli_uses_storage_local_default(tmp_path: Path) -> None:
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    RunStore(state).create_run()

    result = runner.invoke(app, ["state", "backup", "--config", str(config)])

    assert result.exit_code == 0, result.output
    assert (state / "snapshots" / "state.sqlite3").is_file()


def test_complete_state_bundle_cli_round_trip_restores_evidence(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_config = tmp_path / "source.yml"
    bundle = tmp_path / "backups" / "state.bundle.zip"
    source_config.write_text(f"storage:\n  path: {source_root}\n", encoding="utf-8")
    source = RunStore(source_root)
    run = source.create_run()
    source.write_artifact(run.run_id, "review-note.txt", "sealed evidence\n")

    backed_up = runner.invoke(
        app,
        [
            "state",
            "backup",
            "--complete",
            "--output",
            str(bundle),
            "--config",
            str(source_config),
        ],
    )

    assert backed_up.exit_code == 0, backed_up.output
    assert "Verified complete state bundle" in backed_up.output
    assert bundle.is_file()

    restored_root = tmp_path / "restored"
    restored_config = tmp_path / "restored.yml"
    restored_config.write_text(f"storage:\n  path: {restored_root}\n", encoding="utf-8")
    restored = runner.invoke(
        app,
        [
            "state",
            "restore",
            "--complete",
            "--input",
            str(bundle),
            "--config",
            str(restored_config),
        ],
    )

    assert restored.exit_code == 0, restored.output
    assert "Verified complete state restored" in restored.output
    recovered = RunStore(restored_root)
    assert recovered.get(run.run_id) == run
    assert (
        recovered.artifact_dir(run.run_id).joinpath("review-note.txt").read_text()
        == "sealed evidence\n"
    )


def test_complete_state_backup_cli_uses_distinct_default(tmp_path: Path) -> None:
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    RunStore(state).create_run()

    result = runner.invoke(
        app,
        ["state", "backup", "--complete", "--config", str(config)],
    )

    assert result.exit_code == 0, result.output
    assert (state / "snapshots" / "state.bundle.zip").is_file()


def test_state_restore_cli_promotes_only_verified_snapshot(tmp_path: Path) -> None:
    source = RunStore(tmp_path / "source")
    run = source.create_run()
    snapshot = source.create_snapshot(tmp_path / "backup.sqlite3")
    restored_root = tmp_path / "restored"
    config = tmp_path / "autocontribute.yml"
    config.write_text(f"storage:\n  path: {restored_root}\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["state", "restore", "--input", str(snapshot), "--config", str(config)],
    )

    assert result.exit_code == 0, result.output
    assert "Verified state restored" in result.output
    assert RunStore(restored_root).get(run.run_id).run_id == run.run_id


def test_safety_cli_persists_stop_status_and_audited_resume(tmp_path: Path) -> None:
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")

    stopped = runner.invoke(
        app,
        [
            "safety",
            "stop",
            "--actor",
            "operator",
            "--reason",
            "Review maintainer feedback",
            "--config",
            str(config),
        ],
    )
    status = runner.invoke(
        app,
        ["safety", "status", "--config", str(config), "--json"],
    )
    breaker_before_resume = RunStore(state).circuit_breaker_status()
    trigger_hash = breaker_before_resume.trigger_hash
    active_revision = breaker_before_resume.active_revision
    assert trigger_hash is not None
    assert active_revision is not None
    resumed = runner.invoke(
        app,
        [
            "safety",
            "resume",
            "--actor",
            "operator",
            "--reason",
            "Feedback reviewed and stop condition resolved",
            "--expected-trigger-hash",
            active_revision,
            "--config",
            str(config),
        ],
    )

    assert stopped.exit_code == 0, stopped.output
    assert "Safety stop activated" in stopped.output
    assert status.exit_code == 0, status.output
    assert '"is_tripped": true' in status.output
    assert '"reason": "Review maintainer feedback"' in status.output
    assert f'"trigger_hash": "{trigger_hash}"' in status.output
    assert f'"active_revision": "{active_revision}"' in status.output
    assert resumed.exit_code == 0, resumed.output
    assert "explicitly resumed" in resumed.output
    breaker = RunStore(state).circuit_breaker_status()
    assert not breaker.is_tripped
    assert breaker.epoch == 2


def test_safety_stop_while_stopped_records_new_evidence_and_validates_input(
    tmp_path: Path,
) -> None:
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")

    first = runner.invoke(
        app,
        [
            "safety",
            "stop",
            "--actor",
            "first",
            "--reason",
            "first reason",
            "--config",
            str(config),
        ],
    )
    second = runner.invoke(
        app,
        [
            "safety",
            "stop",
            "--actor",
            "second",
            "--reason",
            "second reason",
            "--config",
            str(config),
        ],
    )
    blank = runner.invoke(
        app,
        [
            "safety",
            "stop",
            "--actor",
            " ",
            "--reason",
            "ignored",
            "--config",
            str(config),
        ],
    )

    assert first.exit_code == 0, first.output
    assert second.exit_code == 0, second.output
    assert blank.exit_code == 1, blank.output
    status = RunStore(state).circuit_breaker_status()
    assert len(status.active_triggers) == 2
    assert status.source == "operator:second"
    assert status.reason == "second reason"


def test_scheduled_run_syncs_lifecycle_before_orchestration(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    calls: list[str] = []

    class FakeGitHub:
        def __init__(self, *_: object, **__: object) -> None:
            pass

        def close(self) -> None:
            calls.append("close")

    class FakeOrchestrator:
        def __init__(self, _: object, *, store: RunStore, github: object) -> None:
            self.store = store

        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *_: object) -> None:
            pass

        def run(self, *, issue_reference: str | None = None):  # type: ignore[no-untyped-def]
            calls.append("run")
            manifest = self.store.create_run()
            manifest.status = RunStatus.SKIPPED
            manifest.skip_reason = "fixture"
            self.store.save(manifest, event="test.skipped", details={})
            return manifest

    def fake_sync(
        settings: object,
        store: RunStore,
        github: object,
        *,
        resume_submitting_publications: bool = False,
    ) -> LifecycleSyncResult:
        calls.append(f"sync:{resume_submitting_publications}")
        return LifecycleSyncResult(observations=())

    monkeypatch.setattr(cli, "GitHubClient", FakeGitHub)
    monkeypatch.setattr(cli, "Orchestrator", FakeOrchestrator)
    monkeypatch.setattr(cli, "_sync_lifecycle", fake_sync)

    result = runner.invoke(app, ["run", "--scheduled", "--config", str(config)])

    assert result.exit_code == 0, result.output
    assert calls == ["sync:False", "run", "close"]


def test_auto_path_resyncs_lifecycle_immediately_before_publisher(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(
        "github:\n"
        "  repositories: [example/project]\n"
        "validation:\n"
        "  required_commands:\n"
        "    example/project: [python -m pytest]\n"
        "publishing:\n"
        "  mode: auto\n"
        "  max_open_pull_requests: 1\n"
        "models:\n"
        "  scout:\n"
        "    expected_response_model: gpt-5.6-2026-07-21\n"
        "    immutable_response_model_attested: true\n"
        "    pricing: &pricing\n"
        "      input_usd_per_million_tokens: 1\n"
        "      output_usd_per_million_tokens: 1\n"
        "  builder:\n"
        "    expected_response_model: gpt-5.6-2026-07-21\n"
        "    immutable_response_model_attested: true\n"
        "    pricing: *pricing\n"
        "  critic:\n"
        "    expected_response_model: gpt-5.6-2026-07-21\n"
        "    immutable_response_model_attested: true\n"
        "    pricing: *pricing\n"
        "budget:\n"
        "  max_model_cost_usd_per_run: 10\n"
        f"storage:\n  path: {state}\n",
        encoding="utf-8",
    )
    calls: list[str] = []

    class FakeGitHub:
        def __init__(self, *_: object, **__: object) -> None:
            pass

        def close(self) -> None:
            calls.append("close")

    class FakeOrchestrator:
        def __init__(self, _: object, *, store: RunStore, github: object) -> None:
            self.store = store

        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *_: object) -> None:
            pass

        def run(self, *, issue_reference: str | None = None):  # type: ignore[no-untyped-def]
            calls.append("run")
            manifest = self.store.create_run()
            manifest.status = RunStatus.READY_FOR_APPROVAL
            self.store.save(manifest, event="test.ready", details={})
            return manifest

    class FakePublisher:
        def __init__(self, _: object, store: RunStore, github: object) -> None:
            self.store = store

        def publish(self, run_id: str):  # type: ignore[no-untyped-def]
            calls.append("publish")
            manifest = self.store.get(run_id)
            manifest.status = RunStatus.PR_OPEN
            manifest.pull_request_url = "https://github.com/example/project/pull/7"
            self.store.save(manifest, event="test.published", details={})
            return manifest

    def fake_sync(
        settings: object,
        store: RunStore,
        github: object,
        *,
        resume_submitting_publications: bool = False,
    ) -> LifecycleSyncResult:
        calls.append(f"sync:{resume_submitting_publications}")
        return LifecycleSyncResult(observations=())

    monkeypatch.setattr(cli, "GitHubClient", FakeGitHub)
    monkeypatch.setattr(cli, "Orchestrator", FakeOrchestrator)
    monkeypatch.setattr(cli, "Publisher", FakePublisher)
    monkeypatch.setattr(cli, "_sync_lifecycle", fake_sync)
    monkeypatch.setenv("AUTOCONTRIBUTE_ALLOW_AUTO_PUBLISH", "1")

    result = runner.invoke(app, ["run", "--scheduled", "--config", str(config)])

    assert result.exit_code == 0, result.output
    assert calls == ["sync:True", "run", "sync:False", "publish", "close"]


def test_manual_publish_syncs_lifecycle_and_preserves_target_retry(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    store = RunStore(state)
    run = store.create_run()
    run.status = RunStatus.SUBMITTING
    store.save(run, event="test.submitting", details={})
    calls: list[str] = []

    class FakeGitHub:
        def __init__(self, *_: object, **__: object) -> None:
            pass

        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *_: object) -> None:
            calls.append("close")

    class FakePublisher:
        def __init__(self, _: object, publisher_store: RunStore, github: object) -> None:
            self.store = publisher_store

        def publish(self, run_id: str):  # type: ignore[no-untyped-def]
            calls.append("publish")
            manifest = self.store.get(run_id)
            manifest.status = RunStatus.PR_OPEN
            manifest.pull_request_url = "https://github.com/example/project/pull/7"
            self.store.save(manifest, event="test.published", details={})
            return manifest

    def fake_sync(
        settings: object,
        sync_store: RunStore,
        github: object,
        *,
        publication_retry_run_id: str | None = None,
    ) -> LifecycleSyncResult:
        assert sync_store.root == store.root
        calls.append(f"sync:{publication_retry_run_id}")
        return LifecycleSyncResult(observations=())

    monkeypatch.setattr(cli, "GitHubClient", FakeGitHub)
    monkeypatch.setattr(cli, "Publisher", FakePublisher)
    monkeypatch.setattr(cli, "_sync_lifecycle", fake_sync)
    monkeypatch.setattr(cli, "_show_report", lambda *args: None)
    monkeypatch.setattr(cli, "_refresh_report", lambda *args: None)

    result = runner.invoke(
        app,
        ["publish", run.run_id, "--yes", "--config", str(config)],
    )

    assert result.exit_code == 0, result.output
    assert calls == [f"sync:{run.run_id}", "publish", "close"]


def test_manual_publish_returns_reconciled_target_without_a_new_publish_call(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    store = RunStore(state)
    run = store.create_run()
    run.status = RunStatus.SUBMITTING
    store.save(run, event="test.submitting", details={})
    calls: list[str] = []

    class FakeGitHub:
        def __init__(self, *_: object, **__: object) -> None:
            pass

        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *_: object) -> None:
            calls.append("close")

    class FakePublisher:
        def __init__(self, *_: object, **__: object) -> None:
            pytest.fail("a reconciled PR must not enter the new-publication path")

    def fake_sync(
        settings: object,
        sync_store: RunStore,
        github: object,
        *,
        publication_retry_run_id: str | None = None,
    ) -> LifecycleSyncResult:
        assert publication_retry_run_id == run.run_id
        reconciled = sync_store.get(run.run_id)
        reconciled.status = RunStatus.PR_OPEN
        reconciled.pull_request_url = "https://github.com/example/project/pull/7"
        sync_store.save(reconciled, event="test.reconciled", details={})
        calls.append("reconcile")
        return LifecycleSyncResult(observations=())

    monkeypatch.setattr(cli, "GitHubClient", FakeGitHub)
    monkeypatch.setattr(cli, "Publisher", FakePublisher)
    monkeypatch.setattr(cli, "_sync_lifecycle", fake_sync)
    monkeypatch.setattr(cli, "_show_report", lambda *args: None)
    monkeypatch.setattr(cli, "_refresh_report", lambda *args: None)

    result = runner.invoke(
        app,
        ["publish", run.run_id, "--yes", "--config", str(config)],
    )

    assert result.exit_code == 0, result.output
    assert calls == ["reconcile", "close"]


def test_lifecycle_sync_adopts_existing_pr_without_automatic_opt_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    settings = load_config(config)
    settings.publishing.mode = "auto"
    monkeypatch.delenv(settings.publishing.auto_publish_env, raising=False)
    store = RunStore(state)
    submitting = store.create_run()
    submitting.status = RunStatus.SUBMITTING
    store.save(submitting, event="test.submitting", details={})
    calls: list[str] = []

    class FakePublisher:
        def __init__(self, settings: object, store: RunStore, github: object) -> None:
            self.store = store

        def reconcile_submitting(self, run_id: str) -> None:
            calls.append(f"reconcile:{run_id}")
            manifest = self.store.get(run_id)
            manifest.status = RunStatus.PR_OPEN
            manifest.pull_request_url = "https://github.com/example/project/pull/7"
            self.store.save(manifest, event="test.reconciled", details={})

        def publish(self, run_id: str) -> None:
            pytest.fail(f"read-only reconciliation must not publish {run_id}")

    def fake_sync(
        github: object,
        observed_store: RunStore,
        *,
        assert_owned: Callable[[], object] | None = None,
    ) -> LifecycleSyncResult:
        assert observed_store is store
        assert assert_owned is not None
        assert_owned()
        calls.append("observe")
        return LifecycleSyncResult(observations=())

    monkeypatch.setattr(cli, "Publisher", FakePublisher)
    monkeypatch.setattr(cli, "sync_open_pull_requests", fake_sync)

    result = cli._sync_lifecycle(
        settings,
        store,
        object(),  # type: ignore[arg-type]
        resume_submitting_publications=True,
    )

    assert result == LifecycleSyncResult(observations=())
    assert calls == [f"reconcile:{submitting.run_id}", "observe"]
    reconciled = store.get(submitting.run_id)
    assert reconciled.status == RunStatus.PR_OPEN
    assert reconciled.pull_request_url == "https://github.com/example/project/pull/7"


@pytest.mark.parametrize(
    ("mode", "auto_publish_env", "opt_in", "publishes", "failure"),
    [
        pytest.param(
            "review_required",
            None,
            None,
            False,
            "publishing.mode is review_required",
            id="review-required",
        ),
        pytest.param(
            "auto",
            None,
            None,
            False,
            "AUTOCONTRIBUTE_ALLOW_AUTO_PUBLISH is not enabled",
            id="auto-opt-in-missing",
        ),
        pytest.param("auto", None, "yes", True, None, id="auto-opt-in-enabled"),
        pytest.param(
            "auto",
            "CI",
            "true",
            False,
            "CI is not enabled as the dedicated automatic-publication switch",
            id="generic-ci-variable-is-not-opt-in",
        ),
    ],
)
def test_scheduled_lifecycle_resumes_only_with_live_automatic_authorization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    auto_publish_env: str | None,
    opt_in: str | None,
    publishes: bool,
    failure: str | None,
) -> None:
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    settings = load_config(config)
    settings.publishing.mode = mode  # type: ignore[assignment]
    if auto_publish_env is not None:
        settings.publishing.auto_publish_env = auto_publish_env
    if opt_in is not None:
        monkeypatch.setenv(settings.publishing.auto_publish_env, opt_in)
    elif mode == "auto":
        monkeypatch.delenv(settings.publishing.auto_publish_env, raising=False)
        monkeypatch.setenv("CI", "true")
    store = RunStore(state)
    submitting = store.create_run()
    submitting.status = RunStatus.SUBMITTING
    store.save(submitting, event="test.submitting", details={})
    calls: list[str] = []

    class FakePublisher:
        def __init__(self, settings: object, store: RunStore, github: object) -> None:
            pass

        def reconcile_submitting(self, run_id: str) -> None:
            calls.append(f"reconcile:{run_id}")
            raise PublicationResumeRequired("no remote pull request yet")

        def publish(self, run_id: str) -> None:
            calls.append(f"publish:{run_id}")

    def fake_sync(
        github: object,
        observed_store: RunStore,
        *,
        assert_owned: Callable[[], object] | None = None,
    ) -> LifecycleSyncResult:
        assert observed_store is store
        assert assert_owned is not None
        assert_owned()
        calls.append("observe")
        return LifecycleSyncResult(observations=())

    monkeypatch.setattr(cli, "Publisher", FakePublisher)
    monkeypatch.setattr(cli, "sync_open_pull_requests", fake_sync)

    if publishes:
        result = cli._sync_lifecycle(
            settings,
            store,
            object(),  # type: ignore[arg-type]
            resume_submitting_publications=True,
        )
        assert result == LifecycleSyncResult(observations=())
    else:
        assert failure is not None
        with pytest.raises(PublicationResumeRequired, match=failure):
            cli._sync_lifecycle(
                settings,
                store,
                object(),  # type: ignore[arg-type]
                resume_submitting_publications=True,
            )

    expected = [f"reconcile:{submitting.run_id}"]
    if publishes:
        expected.append(f"publish:{submitting.run_id}")
    expected.append("observe")
    assert calls == expected
    assert store.get(submitting.run_id).status == RunStatus.SUBMITTING


def test_lifecycle_sync_reconciles_target_submitting_run_before_exact_publication_retry(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    settings = load_config(config)
    store = RunStore(state)
    target = store.create_run()
    target.status = RunStatus.SUBMITTING
    store.save(target, event="test.target_submitting", details={})
    other = store.create_run()
    other.status = RunStatus.SUBMITTING
    store.save(other, event="test.other_submitting", details={})
    calls: list[str] = []

    class FakePublisher:
        def __init__(self, settings: object, store: RunStore, github: object) -> None:
            pass

        def reconcile_submitting(self, run_id: str) -> None:
            calls.append(f"reconcile:{run_id}")

    def fake_sync(
        github: object,
        observed_store: RunStore,
        *,
        assert_owned: Callable[[], object] | None = None,
    ) -> LifecycleSyncResult:
        assert observed_store is store
        assert assert_owned is not None
        assert_owned()
        calls.append("observe")
        return LifecycleSyncResult(observations=())

    monkeypatch.setattr(cli, "Publisher", FakePublisher)
    monkeypatch.setattr(cli, "sync_open_pull_requests", fake_sync)

    result = cli._sync_lifecycle(
        settings,
        store,
        object(),  # type: ignore[arg-type]
        publication_retry_run_id=target.run_id,
    )

    assert result == LifecycleSyncResult(observations=())
    assert calls == [
        f"reconcile:{target.run_id}",
        f"reconcile:{other.run_id}",
        "observe",
    ]


def test_lifecycle_sync_resumes_only_the_explicit_manual_retry_target(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    settings = load_config(config)
    store = RunStore(state)
    target = store.create_run()
    target.status = RunStatus.SUBMITTING
    store.save(target, event="test.target_submitting", details={})
    other = store.create_run()
    other.status = RunStatus.SUBMITTING
    store.save(other, event="test.other_submitting", details={})
    calls: list[str] = []

    class FakePublisher:
        def __init__(self, settings: object, store: RunStore, github: object) -> None:
            pass

        def reconcile_submitting(self, run_id: str) -> None:
            calls.append(f"reconcile:{run_id}")
            raise PublicationResumeRequired("no remote pull request yet")

        def publish(self, run_id: str) -> None:
            calls.append(f"publish:{run_id}")

    def fake_sync(
        github: object,
        observed_store: RunStore,
        *,
        assert_owned: Callable[[], object] | None = None,
    ) -> LifecycleSyncResult:
        assert observed_store is store
        assert assert_owned is not None
        assert_owned()
        calls.append("observe")
        return LifecycleSyncResult(observations=())

    monkeypatch.setattr(cli, "Publisher", FakePublisher)
    monkeypatch.setattr(cli, "sync_open_pull_requests", fake_sync)

    with pytest.raises(PublicationResumeRequired, match=r"publishing\.mode is review_required"):
        cli._sync_lifecycle(
            settings,
            store,
            object(),  # type: ignore[arg-type]
            publication_retry_run_id=target.run_id,
        )

    assert calls == [
        f"reconcile:{target.run_id}",
        f"publish:{target.run_id}",
        f"reconcile:{other.run_id}",
        "observe",
    ]


def test_lifecycle_sync_observes_and_continues_reconciliation_before_failing_closed(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    settings = load_config(config)
    store = RunStore(state)
    ambiguous = store.create_run()
    ambiguous.status = RunStatus.SUBMITTING
    store.save(ambiguous, event="test.ambiguous_submitting", details={})
    reconcilable = store.create_run()
    reconcilable.status = RunStatus.SUBMITTING
    store.save(reconcilable, event="test.reconcilable_submitting", details={})
    calls: list[str] = []

    class FakePublisher:
        def __init__(self, settings: object, store: RunStore, github: object) -> None:
            pass

        def reconcile_submitting(self, run_id: str) -> None:
            calls.append(f"reconcile:{run_id}")
            if run_id == ambiguous.run_id:
                raise StateError("publication remains ambiguous")

    def fake_sync(
        github: object,
        observed_store: RunStore,
        *,
        assert_owned: Callable[[], object] | None = None,
    ) -> LifecycleSyncResult:
        assert observed_store is store
        assert assert_owned is not None
        assert_owned()
        calls.append("observe")
        return LifecycleSyncResult(observations=())

    monkeypatch.setattr(cli, "Publisher", FakePublisher)
    monkeypatch.setattr(cli, "sync_open_pull_requests", fake_sync)

    with pytest.raises(StateError, match="publication remains ambiguous"):
        cli._sync_lifecycle(settings, store, object())  # type: ignore[arg-type]

    assert calls == [
        f"reconcile:{ambiguous.run_id}",
        f"reconcile:{reconcilable.run_id}",
        "observe",
    ]


def test_lifecycle_sync_stops_reconciliation_after_lease_takeover(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    settings = load_config(config)
    store = RunStore(state)
    first = store.create_run()
    first.status = RunStatus.SUBMITTING
    store.save(first, event="test.first_submitting", details={})
    second = store.create_run()
    second.status = RunStatus.SUBMITTING
    store.save(second, event="test.second_submitting", details={})
    calls: list[str] = []

    class FakePublisher:
        def __init__(self, settings: object, store: RunStore, github: object) -> None:
            pass

        def reconcile_submitting(self, run_id: str) -> None:
            calls.append(f"reconcile:{run_id}")
            lease = store.get_lease("autocontribute.lifecycle")
            assert lease is not None
            takeover = store.acquire_lease(
                "autocontribute.lifecycle",
                "replacement-worker",
                ttl=timedelta(minutes=5),
                now=lease.expires_at,
            )
            assert takeover is not None

    def fake_sync(
        github: object,
        observed_store: RunStore,
        *,
        assert_owned: Callable[[], object] | None = None,
    ) -> LifecycleSyncResult:
        calls.append("observe")
        return LifecycleSyncResult(observations=())

    monkeypatch.setattr(cli, "Publisher", FakePublisher)
    monkeypatch.setattr(cli, "sync_open_pull_requests", fake_sync)

    with pytest.raises(StateError, match="no longer owned"):
        cli._sync_lifecycle(settings, store, object())  # type: ignore[arg-type]

    assert calls == [f"reconcile:{first.run_id}"]


def test_lifecycle_sync_command_reports_bounded_summary(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")

    class FakeGitHub:
        def __init__(self, *_: object, **__: object) -> None:
            pass

        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *_: object) -> None:
            pass

    monkeypatch.setattr(cli, "GitHubClient", FakeGitHub)
    monkeypatch.setattr(
        cli,
        "_sync_lifecycle",
        lambda settings, store, github: LifecycleSyncResult(observations=()),
    )

    result = runner.invoke(app, ["lifecycle", "sync", "--config", str(config)])

    assert result.exit_code == 0, result.output
    assert "Lifecycle sync: 0 PR(s), 0 new snapshot(s), 0 safety signal(s)" in result.output
