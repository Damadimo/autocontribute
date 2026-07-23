from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from autocontribute.coordination import (
    PUBLICATION_HEARTBEAT_INTERVAL,
    PUBLICATION_LEASE_NAME,
    PUBLICATION_LEASE_TTL,
    LeaseHeartbeatGuard,
)
from autocontribute.domain import (
    CommandResult,
    CriticReview,
    FileEdit,
    GateResult,
    IssueCandidate,
    PatchProposal,
    QualityReport,
    RepositoryInfo,
    ReviewScores,
    RunManifest,
    RunStatus,
)
from autocontribute.evaluation import (
    EvaluationStore,
    EvaluationSummary,
    EvaluationVerdict,
    ExpertEvaluationAmendment,
    evaluation_hash,
)
from autocontribute.exceptions import StateError
from autocontribute.preparation import compute_preparation_fingerprint
from autocontribute.store import RunStore

_PATCH = b"diff --git a/app.py b/app.py\n-old\n+new\n"
_DEPLOYMENT_FINGERPRINT = "d" * 64


def _new_run(store: RunStore) -> RunManifest:
    return store.create_run(deployment_fingerprint=_DEPLOYMENT_FINGERPRINT)


def _summary(evaluations: EvaluationStore) -> EvaluationSummary:
    return evaluations.summary(deployment_fingerprint=_DEPLOYMENT_FINGERPRINT)


def _ready_run(store: RunStore) -> RunManifest:
    run = _new_run(store)
    now = run.created_at
    run.candidate = IssueCandidate(
        repository="example/project",
        number=42,
        title="Correct the boundary",
        body="The current boundary result is incorrect.",
        html_url="https://github.com/example/project/issues/42",
        state="open",
        author="maintainer",
        labels=["bug"],
        assignees=[],
        comments=1,
        created_at=now,
        updated_at=now,
    )
    run.repository = RepositoryInfo(
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
    run.base_sha = "b" * 40
    run.proposal = PatchProposal(
        summary="Correct the boundary result.",
        edits=[
            FileEdit(
                operation="replace",
                path="app.py",
                find="old",
                replace="new",
                content=None,
                rationale="Match the documented behavior.",
            )
        ],
        validation_commands=["python -m pytest"],
        commit_message="Correct the boundary result",
        pull_request_title="Correct the boundary result",
        pull_request_body="Fixes #42.",
        limitations=[],
    )
    review = CriticReview(
        verdict="approve",
        summary="The focused change is ready.",
        scores=ReviewScores(
            correctness=96,
            issue_alignment=97,
            tests=95,
            repository_conventions=95,
            diff_hygiene=98,
            maintainer_clarity=96,
        ),
        blocking_findings=[],
        non_blocking_findings=[],
        issue_requirements_met=["The boundary is corrected"],
        issue_requirements_missing=[],
        test_evidence_assessment="The regression command passed.",
        maintainer_perspective="Small and reviewable.",
    )
    run.quality = QualityReport(
        ready=True,
        readiness_score=96,
        gates=[GateResult(gate="validation", passed=True, evidence="1/1 passed")],
        review=review,
        changed_files=1,
        changed_lines=2,
    )
    run.patched_validation = [
        CommandResult(
            command="python -m pytest",
            exit_code=0,
            duration_seconds=1.0,
            stdout="1 passed",
            stderr="",
        )
    ]
    store.write_artifact(run.run_id, "contribution.patch", _PATCH.decode("utf-8"))
    run.preparation_fingerprint = compute_preparation_fingerprint(run, diff=_PATCH)
    run.status = RunStatus.READY_FOR_APPROVAL
    store.save(run, event="fixture.ready", details={})
    return run


def test_expert_evaluation_is_immutable_and_bound_to_run(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = _new_run(store)
    store.transition(run, RunStatus.DISCOVERING, reason="fixture")
    store.transition(run, RunStatus.SKIPPED, reason="insufficient evidence")
    evaluations = EvaluationStore(store)

    evaluation = evaluations.record(
        run.run_id,
        reviewer="expert@example.invalid",
        verdict=EvaluationVerdict.CORRECT_ABSTENTION,
        notes="The issue had no reproducible acceptance criteria.",
    )

    assert len(evaluation.subject_hash) == 64
    assert evaluations.list() == [evaluation]
    reopened = EvaluationStore(RunStore(store.root))
    assert reopened.list() == [evaluation]
    assert reopened.summary(deployment_fingerprint=_DEPLOYMENT_FINGERPRINT).total_cases == 1
    with pytest.raises(StateError, match="already has"):
        reopened.record(
            run.run_id,
            reviewer="second-reviewer",
            verdict=EvaluationVerdict.CORRECT_ABSTENTION,
        )


def test_prepared_evaluation_survives_publication_lifecycle_changes(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = _ready_run(store)
    evaluations = EvaluationStore(store)
    evaluation = evaluations.record(
        run.run_id,
        reviewer="expert",
        verdict=EvaluationVerdict.ACCEPT_AS_IS,
    )

    run.publishing_login = "octocat"
    run.publishing_api_origin = "https://api.github.com"
    run.commit_author_name = "Octocat"
    run.commit_author_email = "octocat@users.noreply.github.com"
    run.commit_committer_name = "Octocat"
    run.commit_committer_email = "octocat@users.noreply.github.com"
    run.publication_draft = True
    run.publication_ready_for_review = False
    run.upstream_repository_id = 1001
    run.upstream_repository_node_id = "R_upstream_fixture"
    run.fork_repository_id = 2001
    run.fork_repository_node_id = "R_fork_fixture"
    store.save(run, event="fixture.publication_context_bound", details={})
    store.transition(run, RunStatus.APPROVED, reason="fixture approval")
    run.branch_name = "autocontribute/fixture"
    run.commit_sha = "a" * 40
    run.pull_request_creation_started = True
    run.publication_compensation_reason = "created_pr_base_moved"
    store.save(run, event="fixture.committed", details={})
    store.transition(run, RunStatus.SUBMITTING, reason="fixture publication")
    run.pull_request_url = "https://github.com/example/project/pull/1"
    run.pull_request_node_id = "PR_fixture_1"
    store.save(run, event="fixture.pull_request", details={})
    store.transition(run, RunStatus.PR_OPEN, reason="fixture opened")

    reopened = EvaluationStore(RunStore(store.root))
    assert reopened.list() == [evaluation]
    amendment = reopened.amend(
        run.run_id,
        reviewer="expert",
        verdict=EvaluationVerdict.NEEDS_MINOR_CHANGES,
        amendment_reason="Publication review identified a minor wording improvement.",
    )
    assert reopened.history(run.run_id) == [evaluation, amendment]
    assert reopened.list() == [amendment]
    assert reopened.summary(deployment_fingerprint=_DEPLOYMENT_FINGERPRINT).total_cases == 1


def test_evaluation_rejects_changed_prepared_artifact(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = _ready_run(store)
    evaluations = EvaluationStore(store)
    evaluations.record(
        run.run_id,
        reviewer="expert",
        verdict=EvaluationVerdict.ACCEPT_AS_IS,
    )

    store.write_artifact(run.run_id, "contribution.patch", "tampered patch")

    with pytest.raises(StateError, match="invalid preparation evidence"):
        _summary(evaluations)


def test_prepared_run_cannot_be_graded_as_an_abstention(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = _ready_run(store)

    with pytest.raises(ValueError, match="prepared-artifact verdict"):
        EvaluationStore(store).record(
            run.run_id,
            reviewer="expert",
            verdict=EvaluationVerdict.CORRECT_ABSTENTION,
        )


def test_unfinished_run_cannot_be_counted_as_an_abstention(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = _new_run(store)

    with pytest.raises(StateError, match="not a completed evaluation outcome"):
        EvaluationStore(store).record(
            run.run_id,
            reviewer="expert",
            verdict=EvaluationVerdict.CORRECT_ABSTENTION,
        )


def test_empty_ready_manifest_cannot_be_counted_as_prepared(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = _new_run(store)
    run.status = RunStatus.READY_FOR_APPROVAL
    store.save(run, event="fixture.ready", details={})

    with pytest.raises(StateError, match="missing its contribution patch"):
        EvaluationStore(store).record(
            run.run_id,
            reviewer="expert",
            verdict=EvaluationVerdict.ACCEPT_AS_IS,
        )


def test_evaluation_corpus_rejects_copied_or_renamed_records(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = _new_run(store)
    store.transition(run, RunStatus.DISCOVERING, reason="fixture")
    store.transition(run, RunStatus.SKIPPED, reason="fixture")
    evaluations = EvaluationStore(store)
    evaluations.record(
        run.run_id,
        reviewer="expert",
        verdict=EvaluationVerdict.CORRECT_ABSTENTION,
    )
    original = evaluations.root / f"{run.run_id}.json"
    copied = evaluations.root / f"{'f' * 16}.json"
    copied.write_bytes(original.read_bytes())

    with pytest.raises(StateError, match="filename does not match"):
        _summary(evaluations)


def test_evaluation_corpus_rejects_deleted_anchored_record(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = _new_run(store)
    store.transition(run, RunStatus.DISCOVERING, reason="fixture")
    store.transition(run, RunStatus.SKIPPED, reason="fixture")
    evaluations = EvaluationStore(store)
    evaluations.record(
        run.run_id,
        reviewer="expert",
        verdict=EvaluationVerdict.CORRECT_ABSTENTION,
    )
    (evaluations.root / f"{run.run_id}.json").unlink()

    with pytest.raises(StateError, match="Anchored evaluation record is missing"):
        _summary(evaluations)


def test_edited_agent_outcome_cannot_turn_an_abstention_into_an_acceptance(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    run = _new_run(store)
    store.transition(run, RunStatus.DISCOVERING, reason="fixture")
    store.transition(run, RunStatus.SKIPPED, reason="fixture")
    evaluations = EvaluationStore(store)
    evaluations.record(
        run.run_id,
        reviewer="expert",
        verdict=EvaluationVerdict.CORRECT_ABSTENTION,
    )
    path = evaluations.root / f"{run.run_id}.json"
    record = json.loads(path.read_text(encoding="utf-8"))
    record["agent_prepared"] = True
    record["verdict"] = EvaluationVerdict.ACCEPT_AS_IS.value
    path.write_text(json.dumps(record), encoding="utf-8")

    with pytest.raises(StateError, match="missing its contribution patch"):
        _summary(evaluations)


def test_edited_verdict_cannot_inflate_accept_as_is_precision(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = _ready_run(store)
    evaluations = EvaluationStore(store)
    evaluations.record(
        run.run_id,
        reviewer="expert",
        verdict=EvaluationVerdict.REJECT,
    )
    path = evaluations.root / f"{run.run_id}.json"
    record = json.loads(path.read_text(encoding="utf-8"))
    record["verdict"] = EvaluationVerdict.ACCEPT_AS_IS.value
    path.write_text(json.dumps(record), encoding="utf-8")

    with pytest.raises(StateError, match="does not match its ledger anchor"):
        _summary(evaluations)


def test_edited_subject_hash_cannot_rebind_an_evaluation(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = _new_run(store)
    store.transition(run, RunStatus.DISCOVERING, reason="fixture")
    store.transition(run, RunStatus.SKIPPED, reason="fixture")
    evaluations = EvaluationStore(store)
    evaluations.record(
        run.run_id,
        reviewer="expert",
        verdict=EvaluationVerdict.CORRECT_ABSTENTION,
    )
    path = evaluations.root / f"{run.run_id}.json"
    record = json.loads(path.read_text(encoding="utf-8"))
    record["subject_hash"] = "0" * 64
    path.write_text(json.dumps(record), encoding="utf-8")

    with pytest.raises(StateError, match="subject no longer matches"):
        _summary(evaluations)


def test_interrupted_anchored_record_can_be_recovered_with_exact_arguments(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    run = _new_run(store)
    store.transition(run, RunStatus.DISCOVERING, reason="fixture")
    store.transition(run, RunStatus.SKIPPED, reason="fixture")
    evaluations = EvaluationStore(store)
    evaluation = evaluations.record(
        run.run_id,
        reviewer="expert",
        verdict=EvaluationVerdict.CORRECT_ABSTENTION,
        notes="No actionable issue was available.",
    )
    path = evaluations.root / f"{run.run_id}.json"
    anchor = json.loads(store.evaluation_record_anchors()[0]["details"])
    temporary = path.with_name(f"{run.run_id}.{anchor['evaluation_hash']}.json.tmp")
    path.replace(temporary)

    reopened = EvaluationStore(RunStore(store.root))
    recovered = reopened.record(
        run.run_id,
        reviewer="expert",
        verdict=EvaluationVerdict.CORRECT_ABSTENTION,
        notes="No actionable issue was available.",
    )

    assert recovered == evaluation
    assert reopened.list() == [evaluation]


def test_amendment_preserves_history_and_latest_revision_drives_summary(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = _new_run(store)
    store.transition(run, RunStatus.DISCOVERING, reason="fixture")
    store.transition(run, RunStatus.SKIPPED, reason="fixture")
    evaluations = EvaluationStore(store)
    original = evaluations.record(
        run.run_id,
        reviewer="first expert",
        verdict=EvaluationVerdict.CORRECT_ABSTENTION,
        notes="Initially believed the skip was correct.",
    )

    amendment = evaluations.amend(
        run.run_id,
        reviewer="correcting expert",
        verdict=EvaluationVerdict.INCORRECT_ABSTENTION,
        amendment_reason="The issue included a reproducible case that was overlooked.",
        notes="The agent should have selected the issue.",
    )

    assert amendment.revision == 2
    assert amendment.supersedes_evaluation_hash == evaluation_hash(original)
    assert evaluations.history(run.run_id) == [original, amendment]
    assert evaluations.list() == [amendment]
    summary = _summary(evaluations)
    assert summary.correct_abstentions == 0
    assert summary.incorrect_abstentions == 1
    assert (evaluations.root / f"{run.run_id}.json").is_file()
    assert (evaluations.root / f"{run.run_id}.revision-000002.json").is_file()
    assert [event["event_type"] for event in store.events(run.run_id)][-2:] == [
        "evaluation.recorded",
        "evaluation.amended",
    ]


def test_amendment_requires_a_non_blank_reason(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = _new_run(store)
    store.transition(run, RunStatus.DISCOVERING, reason="fixture")
    store.transition(run, RunStatus.SKIPPED, reason="fixture")
    evaluations = EvaluationStore(store)
    evaluations.record(
        run.run_id,
        reviewer="expert",
        verdict=EvaluationVerdict.CORRECT_ABSTENTION,
    )

    with pytest.raises(ValueError, match="amendment reason"):
        evaluations.amend(
            run.run_id,
            reviewer="expert",
            verdict=EvaluationVerdict.INCORRECT_ABSTENTION,
            amendment_reason="   ",
        )

    assert len(evaluations.history(run.run_id)) == 1


def test_two_previews_cannot_create_concurrent_amendment_forks(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = _new_run(store)
    store.transition(run, RunStatus.DISCOVERING, reason="fixture")
    store.transition(run, RunStatus.SKIPPED, reason="fixture")
    evaluations = EvaluationStore(store)
    evaluations.record(
        run.run_id,
        reviewer="initial expert",
        verdict=EvaluationVerdict.CORRECT_ABSTENTION,
    )
    first = evaluations.preview_amendment(
        run.run_id,
        reviewer="first correcting expert",
        verdict=EvaluationVerdict.INCORRECT_ABSTENTION,
        amendment_reason="First independently reviewed correction.",
    )
    second = evaluations.preview_amendment(
        run.run_id,
        reviewer="second correcting expert",
        verdict=EvaluationVerdict.INCORRECT_ABSTENTION,
        amendment_reason="Second independently reviewed correction.",
    )

    def commit(preview: ExpertEvaluationAmendment) -> str:
        try:
            evaluations.commit_preview(preview)
        except StateError:
            return "blocked"
        return "recorded"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(commit, [first, second]))

    assert sorted(outcomes) == ["blocked", "recorded"]
    history = evaluations.history(run.run_id)
    assert len(history) == 2
    assert isinstance(history[-1], ExpertEvaluationAmendment)
    assert history[-1] in (first, second)
    assert (
        len(
            [
                event
                for event in store.events(run.run_id)
                if event["event_type"] == "evaluation.amended"
            ]
        )
        == 1
    )


def test_evaluation_commit_cannot_race_a_publisher_holding_the_gate_lease(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    run = _new_run(store)
    store.transition(run, RunStatus.DISCOVERING, reason="fixture")
    store.transition(run, RunStatus.SKIPPED, reason="fixture")
    evaluations = EvaluationStore(store)
    original = evaluations.record(
        run.run_id,
        reviewer="initial expert",
        verdict=EvaluationVerdict.CORRECT_ABSTENTION,
    )
    amendment = evaluations.preview_amendment(
        run.run_id,
        reviewer="correcting expert",
        verdict=EvaluationVerdict.INCORRECT_ABSTENTION,
        amendment_reason="The issue was actionable after all.",
    )

    with (
        LeaseHeartbeatGuard(
            store,
            PUBLICATION_LEASE_NAME,
            ttl=PUBLICATION_LEASE_TTL,
            heartbeat_interval=PUBLICATION_HEARTBEAT_INTERVAL,
        ),
        pytest.raises(StateError, match="held by another worker"),
    ):
        evaluations.commit_preview(amendment)

    assert evaluations.history(run.run_id) == [original]
    assert evaluations.commit_preview(amendment) == amendment


def test_interrupted_amendment_can_only_recover_the_exact_pending_revision(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    run = _new_run(store)
    store.transition(run, RunStatus.DISCOVERING, reason="fixture")
    store.transition(run, RunStatus.SKIPPED, reason="fixture")
    evaluations = EvaluationStore(store)
    original = evaluations.record(
        run.run_id,
        reviewer="expert",
        verdict=EvaluationVerdict.CORRECT_ABSTENTION,
    )
    amendment = evaluations.amend(
        run.run_id,
        reviewer="correcting expert",
        verdict=EvaluationVerdict.INCORRECT_ABSTENTION,
        amendment_reason="The original reviewer missed actionable acceptance criteria.",
        notes="Corrected after a second evidence review.",
    )
    path = evaluations.root / f"{run.run_id}.revision-000002.json"
    temporary = path.with_name(f"{path.stem}.{evaluation_hash(amendment)}.json.tmp")
    path.replace(temporary)

    reopened = EvaluationStore(RunStore(store.root))
    with pytest.raises(StateError, match="different interrupted evaluation revision"):
        reopened.amend(
            run.run_id,
            reviewer="different expert",
            verdict=EvaluationVerdict.INCORRECT_ABSTENTION,
            amendment_reason="A different correction.",
        )
    with pytest.raises(StateError, match="pending record is missing"):
        # Recovery fails closed if the only matching staged evidence is unavailable.
        temporary.rename(temporary.with_suffix(".unavailable"))
        reopened.amend(
            run.run_id,
            reviewer="correcting expert",
            verdict=EvaluationVerdict.INCORRECT_ABSTENTION,
            amendment_reason="The original reviewer missed actionable acceptance criteria.",
            notes="Corrected after a second evidence review.",
        )
    temporary.with_suffix(".unavailable").rename(temporary)

    recovered = reopened.amend(
        run.run_id,
        reviewer="correcting expert",
        verdict=EvaluationVerdict.INCORRECT_ABSTENTION,
        amendment_reason="The original reviewer missed actionable acceptance criteria.",
        notes="Corrected after a second evidence review.",
    )

    assert recovered == amendment
    assert reopened.history(run.run_id) == [original, amendment]


def test_deleted_or_edited_historical_revision_fails_closed(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = _new_run(store)
    store.transition(run, RunStatus.DISCOVERING, reason="fixture")
    store.transition(run, RunStatus.SKIPPED, reason="fixture")
    evaluations = EvaluationStore(store)
    evaluations.record(
        run.run_id,
        reviewer="expert",
        verdict=EvaluationVerdict.CORRECT_ABSTENTION,
    )
    evaluations.amend(
        run.run_id,
        reviewer="correcting expert",
        verdict=EvaluationVerdict.INCORRECT_ABSTENTION,
        amendment_reason="The abstention was not justified by the issue evidence.",
    )
    amendment_path = evaluations.root / f"{run.run_id}.revision-000002.json"
    encoded = json.loads(amendment_path.read_text(encoding="utf-8"))
    encoded["notes"] = "unanchored edit"
    amendment_path.write_text(json.dumps(encoded), encoding="utf-8")

    with pytest.raises(StateError, match="does not match its ledger anchor"):
        evaluations.list()

    amendment_path.unlink()
    with pytest.raises(StateError, match="Anchored evaluation record is missing"):
        evaluations.list()


def test_subject_drift_after_preview_prevents_evaluation_append(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = _new_run(store)
    store.transition(run, RunStatus.DISCOVERING, reason="fixture")
    store.transition(run, RunStatus.SKIPPED, reason="fixture")
    evaluations = EvaluationStore(store)
    preview = evaluations.preview_record(
        run.run_id,
        reviewer="expert",
        verdict=EvaluationVerdict.CORRECT_ABSTENTION,
    )
    changed = store.get(run.run_id)
    changed.error = "Evidence changed after the expert preview."
    store.save(changed, event="fixture.evaluation_preview_race", details={})

    with pytest.raises(StateError, match="subject no longer matches"):
        evaluations.commit_preview(preview)

    assert not store.evaluation_revision_anchors()
    assert not list(evaluations.root.glob("*.json"))


def test_shadow_gate_requires_volume_precision_and_zero_safety_failures(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    evaluations = EvaluationStore(store)
    for index in range(100):
        if index < 20:
            run = _ready_run(store)
            verdict = EvaluationVerdict.ACCEPT_AS_IS
        else:
            run = _new_run(store)
            store.transition(run, RunStatus.DISCOVERING, reason="fixture")
            store.transition(run, RunStatus.SKIPPED, reason="fixture")
            verdict = EvaluationVerdict.CORRECT_ABSTENTION
        evaluations.record(run.run_id, reviewer="expert", verdict=verdict)

    summary = _summary(evaluations)

    assert summary.total_cases == 100
    assert summary.prepared_cases == 20
    assert summary.accept_as_is_precision == 1.0
    assert summary.shadow_gate_passed
    assert summary.corpus_cursor == store.evaluation_corpus_cursor()

    next_deployment = "e" * 64
    next_run = store.create_run(deployment_fingerprint=next_deployment)
    store.transition(next_run, RunStatus.DISCOVERING, reason="fixture")
    store.transition(next_run, RunStatus.SKIPPED, reason="fixture")
    evaluations.record(
        next_run.run_id,
        reviewer="expert",
        verdict=EvaluationVerdict.CORRECT_ABSTENTION,
    )

    next_summary = evaluations.summary(deployment_fingerprint=next_deployment)
    assert next_summary.total_cases == 1
    assert not next_summary.shadow_gate_passed


def test_shadow_gate_rejects_corpus_cursor_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = RunStore(tmp_path / "state")
    run = _new_run(store)
    store.transition(run, RunStatus.DISCOVERING, reason="fixture")
    store.transition(run, RunStatus.SKIPPED, reason="fixture")
    evaluations = EvaluationStore(store)
    evaluations.record(
        run.run_id,
        reviewer="expert",
        verdict=EvaluationVerdict.CORRECT_ABSTENTION,
    )
    original_cursor = store.evaluation_corpus_cursor
    calls = 0

    def drifting_cursor() -> str:
        nonlocal calls
        calls += 1
        return original_cursor() if calls == 1 else "f" * 64

    monkeypatch.setattr(store, "evaluation_corpus_cursor", drifting_cursor)

    with pytest.raises(StateError, match="corpus changed"):
        _summary(evaluations)


def test_shadow_gate_rejects_timestamp_drift_outside_selected_hundred(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    evaluations = EvaluationStore(store)
    negative_run_id = ""
    for index in range(21):
        run = _ready_run(store)
        evaluations.record(
            run.run_id,
            reviewer="expert",
            verdict=(EvaluationVerdict.REJECT if index == 0 else EvaluationVerdict.ACCEPT_AS_IS),
            policy_failure=index == 0,
        )
        if index == 0:
            negative_run_id = run.run_id
    for _ in range(80):
        run = _new_run(store)
        store.transition(run, RunStatus.DISCOVERING, reason="fixture")
        store.transition(run, RunStatus.SKIPPED, reason="fixture")
        evaluations.record(
            run.run_id,
            reviewer="expert",
            verdict=EvaluationVerdict.CORRECT_ABSTENTION,
        )

    initial = _summary(evaluations)
    assert initial.total_cases == 100
    assert initial.prepared_cases == 21
    assert initial.safety_failures == 1
    assert not initial.shadow_gate_passed

    # Selection must validate every candidate before limiting. Otherwise moving this sole negative
    # row after run 101 replaces it with a positive case and turns the gate green.
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE runs SET created_at = ? WHERE run_id = ?",
            ("9999-12-31T23:59:59+00:00", negative_run_id),
        )

    with pytest.raises(StateError, match="manifest disagrees with its state row"):
        _summary(evaluations)


def test_cohort_rejects_manifest_drift_from_immutable_creation_deployment(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    run = _new_run(store)
    store.transition(run, RunStatus.DISCOVERING, reason="fixture")
    store.transition(run, RunStatus.SKIPPED, reason="fixture")
    run.deployment_fingerprint = "e" * 64
    store.save(run, event="fixture.deployment_tampered", details={})

    with pytest.raises(StateError, match="manifest disagrees with its state row"):
        _summary(EvaluationStore(store))


def test_one_policy_failure_blocks_shadow_gate(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    evaluations = EvaluationStore(store)
    run = _new_run(store)
    store.transition(run, RunStatus.DISCOVERING, reason="fixture")
    store.transition(run, RunStatus.SKIPPED, reason="fixture")
    evaluations.record(
        run.run_id,
        reviewer="expert",
        verdict=EvaluationVerdict.CORRECT_ABSTENTION,
        policy_failure=True,
    )

    summary = _summary(evaluations)

    assert summary.safety_failures == 1
    assert not summary.shadow_gate_passed


def test_shadow_gate_verifies_hashes_for_every_run_event(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    evaluated = _new_run(store)
    store.transition(evaluated, RunStatus.DISCOVERING, reason="fixture")
    store.transition(evaluated, RunStatus.SKIPPED, reason="fixture")
    evaluations = EvaluationStore(store)
    evaluations.record(
        evaluated.run_id,
        reviewer="expert",
        verdict=EvaluationVerdict.CORRECT_ABSTENTION,
    )
    unrelated = _new_run(store)
    store.transition(unrelated, RunStatus.DISCOVERING, reason="fixture")
    store.transition(unrelated, RunStatus.SKIPPED, reason="fixture")

    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            """
            UPDATE events SET details_json = '{"reason":"tampered"}'
            WHERE run_id = ? AND event_type = 'run.transitioned'
            """,
            (unrelated.run_id,),
        )

    with pytest.raises(StateError, match="Event hash mismatch"):
        _summary(evaluations)


def test_shadow_gate_verifies_every_event_predecessor(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = _new_run(store)
    store.transition(run, RunStatus.DISCOVERING, reason="fixture")
    store.transition(run, RunStatus.SKIPPED, reason="fixture")
    evaluations = EvaluationStore(store)
    evaluations.record(
        run.run_id,
        reviewer="expert",
        verdict=EvaluationVerdict.CORRECT_ABSTENTION,
    )

    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            """
            UPDATE events SET previous_hash = ?
            WHERE run_id = ? AND event_type = 'run.transitioned'
            """,
            ("0" * 64, run.run_id),
        )

    with pytest.raises(StateError, match="Event predecessor mismatch"):
        _summary(evaluations)


def test_deleted_tail_cannot_replace_first_cohort_failure_with_a_positive_grade(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    evaluations = EvaluationStore(store)
    deleted_run_id = ""
    for index in range(20):
        run = _ready_run(store)
        evaluations.record(
            run.run_id,
            reviewer="expert",
            verdict=(EvaluationVerdict.REJECT if index == 0 else EvaluationVerdict.ACCEPT_AS_IS),
            policy_failure=index == 0,
        )
        if index == 0:
            deleted_run_id = run.run_id
    for _ in range(80):
        run = _new_run(store)
        store.transition(run, RunStatus.DISCOVERING, reason="fixture")
        store.transition(run, RunStatus.SKIPPED, reason="fixture")
        evaluations.record(
            run.run_id,
            reviewer="expert",
            verdict=EvaluationVerdict.CORRECT_ABSTENTION,
        )

    initial = _summary(evaluations)
    assert initial.accept_as_is_precision == 0.95
    assert initial.safety_failures == 1
    assert not initial.shadow_gate_passed

    # Deleting both the negative grade and its tail event used to permit a second grade for the
    # same run, changing this cohort to 100% precision with no recorded safety failures.
    (evaluations.root / f"{deleted_run_id}.json").unlink()
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            """
            DELETE FROM events
            WHERE run_id = ? AND event_type = 'evaluation.recorded'
            """,
            (deleted_run_id,),
        )

    with pytest.raises(StateError, match="Event ledger anchor mismatch"):
        evaluations.record(
            deleted_run_id,
            reviewer="expert",
            verdict=EvaluationVerdict.ACCEPT_AS_IS,
        )
    with pytest.raises(StateError, match="Event ledger anchor mismatch"):
        _summary(evaluations)
