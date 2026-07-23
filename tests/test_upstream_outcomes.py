from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from autocontribute.config import AutocontributeConfig
from autocontribute.deployment import compute_deployment_fingerprint
from autocontribute.domain import (
    Approval,
    IssueCandidate,
    RepositoryInfo,
    RunManifest,
    RunStatus,
)
from autocontribute.evaluation import EvaluationRevision, EvaluationVerdict, ExpertEvaluation
from autocontribute.exceptions import StateError
from autocontribute.github import (
    CheckRunDetails,
    GitHubComment,
    PullRequestCommit,
    PullRequestDetails,
    PullRequestReference,
    PullRequestReview,
    PullRequestTimelineEvent,
)
from autocontribute.lifecycle import (
    PullRequestLifecycleSnapshot,
    parse_lifecycle_snapshot_json,
)
from autocontribute.store import LifecycleSnapshot, RunStore
from autocontribute.upstream_outcomes import (
    ExpertOutcome,
    PublicationAuthorization,
    UpstreamOutcome,
    UpstreamOutcomeGate,
    UpstreamPublicationScope,
    classify_exact_human_approval,
)

NOW = datetime(2026, 7, 22, 12, tzinfo=UTC)
DEPLOYMENT = "d" * 64
REPOSITORY = "example/project"
LOGIN = "octocat"
API_ORIGIN = "https://api.github.com"
ZERO_HASH = "0" * 64


class FakeStore:
    def __init__(self) -> None:
        self.runs: list[RunManifest] = []
        self.events_by_run: dict[str, list[dict[str, str]]] = {}
        self.snapshots_by_run: dict[str, list[LifecycleSnapshot]] = {}
        self.publication_sequences: dict[str, int] = {}

    def verify_event_chains(self, *, run_id: str | None = None) -> None:
        assert run_id is None or run_id in self.events_by_run

    def oldest_runs(
        self,
        *,
        limit: int = 100,
        deployment_fingerprint: str | None = None,
    ) -> list[RunManifest]:
        matching = [
            run
            for run in self.runs
            if deployment_fingerprint is None
            or run.deployment_fingerprint == deployment_fingerprint
        ]
        return matching[:limit]

    def run_deployment_fingerprint(self, run_id: str) -> str | None:
        return next(run.deployment_fingerprint for run in self.runs if run.run_id == run_id)

    def events(self, run_id: str) -> list[dict[str, str]]:
        return [dict(event) for event in self.events_by_run[run_id]]

    def lifecycle_snapshots(self, run_id: str) -> list[LifecycleSnapshot]:
        return list(self.snapshots_by_run.get(run_id, []))

    def publication_ledger_sequence(self, run_id: str) -> int:
        return self.publication_sequences[run_id]

    def upstream_outcome_corpus_cursor(
        self,
        deployment_fingerprint: str,
        publishing_login: str,
        publishing_api_origin: str,
        *,
        exclude_run_id: str | None = None,
    ) -> str:
        del publishing_login, publishing_api_origin
        payload = []
        for manifest in self.runs:
            if (
                manifest.deployment_fingerprint != deployment_fingerprint
                or manifest.run_id == exclude_run_id
            ):
                continue
            payload.append(
                {
                    "manifest": manifest.model_dump(mode="json"),
                    "publication_sequence": self.publication_sequences.get(manifest.run_id),
                    "events": self.events_by_run[manifest.run_id],
                    "lifecycle": [
                        {
                            "fingerprint": row.fingerprint,
                            "snapshot_json": row.snapshot_json,
                        }
                        for row in self.snapshots_by_run.get(manifest.run_id, [])
                    ],
                }
            )
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
        return hashlib.sha256(b"fake-upstream-outcome-corpus\0" + encoded).hexdigest()


class DriftingFakeStore(FakeStore):
    def __init__(self) -> None:
        super().__init__()
        self.cursor_reads = 0

    def upstream_outcome_corpus_cursor(
        self,
        deployment_fingerprint: str,
        publishing_login: str,
        publishing_api_origin: str,
        *,
        exclude_run_id: str | None = None,
    ) -> str:
        cursor = super().upstream_outcome_corpus_cursor(
            deployment_fingerprint,
            publishing_login,
            publishing_api_origin,
            exclude_run_id=exclude_run_id,
        )
        self.cursor_reads += 1
        return cursor if self.cursor_reads == 1 else "f" * 64


class FakeEvaluations:
    def __init__(self) -> None:
        self.latest: dict[str, EvaluationRevision] = {}

    def list(self) -> list[EvaluationRevision]:
        return [self.latest[run_id] for run_id in sorted(self.latest)]


def _scope(deployment_fingerprint: str = DEPLOYMENT) -> UpstreamPublicationScope:
    return UpstreamPublicationScope(
        deployment_fingerprint=deployment_fingerprint,
        publishing_login=LOGIN,
        publishing_api_origin=API_ORIGIN,
    )


def _rollout_config(
    mode: str,
    *,
    auto_publish_env: str = "AUTOCONTRIBUTE_ALLOW_AUTO_PUBLISH",
    repository: str = REPOSITORY,
) -> AutocontributeConfig:
    profile = {
        "expected_response_model": "immutable-model-snapshot-v1",
        "immutable_response_model_attested": True,
        "pricing": {
            "input_usd_per_million_tokens": "2",
            "output_usd_per_million_tokens": "10",
        },
    }
    return AutocontributeConfig.model_validate(
        {
            "github": {"repositories": [repository], "owners": []},
            "validation": {"required_commands": {repository: ["python -m pytest"]}},
            "models": {role: profile for role in ("scout", "builder", "critic")},
            "budget": {"max_model_cost_usd_per_run": "25"},
            "publishing": {
                "mode": mode,
                "draft": True,
                "ready_for_review": True,
                "max_new_pull_requests_per_day": 1,
                "max_open_pull_requests": 1,
                "repository_cooldown_days": 7,
                "auto_publish_env": auto_publish_env,
            },
        }
    )


def _deployment_fingerprint(config: AutocontributeConfig) -> str:
    return compute_deployment_fingerprint(
        config,
        source_digest="1" * 64,
        runtime_digest="2" * 64,
    )


def _add_publication(
    store: FakeStore,
    evaluations: FakeEvaluations,
    index: int,
    *,
    automatic: bool = False,
    merged: bool = True,
    head_sha: str | None = None,
    verdict: EvaluationVerdict | None = EvaluationVerdict.ACCEPT_AS_IS,
    approval: bool = True,
    repository: str = REPOSITORY,
    deployment_fingerprint: str = DEPLOYMENT,
    ready_for_review: bool = False,
    publication_sequence: int | None = None,
) -> RunManifest:
    run_id = f"{index + 1:016x}"
    number = index + 1
    commit_sha = f"{index + 1:040x}"
    created_at = NOW + timedelta(minutes=index)
    manifest = RunManifest(
        run_id=run_id,
        status=RunStatus.PR_OPEN,
        created_at=created_at,
        updated_at=created_at,
        deployment_fingerprint=deployment_fingerprint,
        candidate=IssueCandidate(
            repository=repository,
            number=number,
            title=f"Issue {number}",
            body="A narrow, reproducible issue.",
            html_url=f"https://github.com/{repository}/issues/{number}",
            state="open",
            author="maintainer",
            labels=["bug"],
            assignees=[],
            comments=0,
            created_at=created_at,
            updated_at=created_at,
        ),
        repository=RepositoryInfo(
            full_name=repository,
            html_url=f"https://github.com/{repository}",
            clone_url=f"https://github.com/{repository}.git",
            default_branch="main",
            stars=10_000,
            archived=False,
            disabled=False,
            private=False,
            pushed_at=created_at,
            license_spdx="MIT",
        ),
        base_sha="b" * 40,
        publishing_login=LOGIN,
        publishing_api_origin=API_ORIGIN,
        commit_author_name="Octocat",
        commit_author_email="octocat@users.noreply.github.com",
        commit_committer_name="Octocat",
        commit_committer_email="octocat@users.noreply.github.com",
        publication_draft=True,
        publication_ready_for_review=ready_for_review,
        branch_name=f"autocontribute/issue-{number}-{run_id}",
        commit_sha=commit_sha,
        pull_request_creation_started=True,
        pull_request_ready_started=ready_for_review,
        pull_request_ready_completed=ready_for_review,
        pull_request_url=f"https://github.com/{repository}/pull/{number}",
    )
    if approval:
        manifest.approval = Approval(
            actor=LOGIN,
            approved_at=created_at + timedelta(seconds=1),
            expires_at=created_at + timedelta(hours=24),
            manifest_hash="a" * 64,
            attestation="I reviewed and approve the exact contribution.",
        )
    store.runs.append(manifest)
    store.publication_sequences[run_id] = (
        publication_sequence if publication_sequence is not None else index + 1
    )
    store.events_by_run[run_id] = _publication_events(manifest, automatic=automatic)
    store.snapshots_by_run[run_id] = [
        _lifecycle_row(
            manifest,
            merged=merged,
            head_sha=head_sha or commit_sha,
        )
    ]
    if verdict is not None:
        evaluations.latest[run_id] = ExpertEvaluation(
            run_id=run_id,
            reviewer="expert",
            reviewed_at=created_at + timedelta(hours=2),
            agent_prepared=True,
            verdict=verdict,
            subject_hash=hashlib.sha256(run_id.encode()).hexdigest(),
        )
    return manifest


def _publication_events(
    manifest: RunManifest,
    *,
    automatic: bool,
) -> list[dict[str, str]]:
    assert manifest.candidate is not None
    assert manifest.deployment_fingerprint is not None
    assert manifest.publication_ready_for_review is not None
    repository = manifest.candidate.repository
    details: list[tuple[str, dict[str, str]]] = [
        (
            "run.created",
            {
                "deployment_fingerprint": manifest.deployment_fingerprint,
                "status": "queued",
            },
        )
    ]
    if automatic:
        details.append(
            (
                "publication.gate.held",
                {
                    "corpus_cursor": "c" * 64,
                    "outcome_corpus_cursor": "d" * 64,
                    "deployment_fingerprint": manifest.deployment_fingerprint,
                    "held_at": (manifest.created_at + timedelta(seconds=1)).isoformat(),
                },
            )
        )
    elif manifest.approval is not None:
        details.append(
            (
                "approval.created",
                {
                    "actor": manifest.approval.actor,
                    "expires_at": manifest.approval.expires_at.isoformat(),
                    "manifest_hash": manifest.approval.manifest_hash,
                },
            )
        )
    details.extend(
        [
            (
                "publication.intent.begun",
                {
                    "repository": repository,
                    "branch": manifest.branch_name or "",
                    "draft": "true",
                    "ready_for_review": (
                        "true" if manifest.publication_ready_for_review else "false"
                    ),
                    "publishing_login": LOGIN,
                    "publishing_api_origin": API_ORIGIN,
                    "commit_author_name": "Octocat",
                    "commit_author_email": "octocat@users.noreply.github.com",
                    "commit_committer_name": "Octocat",
                    "commit_committer_email": "octocat@users.noreply.github.com",
                },
            ),
            (
                "pull_request.created.response",
                {
                    "url": manifest.pull_request_url or "",
                    "repository": repository,
                    "number": str(manifest.candidate.number if manifest.candidate else 0),
                    "state": "open",
                    "head_sha": manifest.commit_sha or "",
                    "base_sha": manifest.base_sha or "",
                },
            ),
        ]
    )
    if manifest.publication_ready_for_review:
        ready_details = {
            "url": manifest.pull_request_url or "",
            "repository": repository,
            "number": str(manifest.candidate.number),
            "head_sha": manifest.commit_sha or "",
        }
        details.extend(
            [
                ("pull_request.ready_for_review.started", ready_details),
                ("pull_request.ready_for_review.completed", ready_details),
            ]
        )
    details.append(
        (
            "run.transitioned",
            {
                "from": RunStatus.SUBMITTING.value,
                "to": RunStatus.PR_OPEN.value,
                "reason": "pull request opened",
            },
        )
    )
    events: list[dict[str, str]] = []
    previous = ZERO_HASH
    for sequence, (event_type, event_details) in enumerate(details, start=1):
        event_hash = hashlib.sha256(f"{manifest.run_id}:{sequence}".encode()).hexdigest()
        occurred_at = manifest.created_at + timedelta(seconds=sequence + 1)
        events.append(
            {
                "occurred_at": occurred_at.isoformat(),
                "event_type": event_type,
                "details": json.dumps(event_details, sort_keys=True, separators=(",", ":")),
                "previous_hash": previous,
                "event_hash": event_hash,
            }
        )
        previous = event_hash
    return events


def _event(store: FakeStore, run_id: str, event_type: str) -> dict[str, str]:
    return next(event for event in store.events_by_run[run_id] if event["event_type"] == event_type)


def _replace_event_details(event: dict[str, str], details: dict[str, str]) -> None:
    event["details"] = json.dumps(details, sort_keys=True, separators=(",", ":"))


def _append_event(
    store: FakeStore,
    manifest: RunManifest,
    event_type: str,
    details: dict[str, str],
) -> None:
    events = store.events_by_run[manifest.run_id]
    sequence = len(events) + 1
    events.append(
        {
            "occurred_at": (manifest.created_at + timedelta(seconds=sequence + 1)).isoformat(),
            "event_type": event_type,
            "details": json.dumps(details, sort_keys=True, separators=(",", ":")),
            "previous_hash": events[-1]["event_hash"] if events else ZERO_HASH,
            "event_hash": hashlib.sha256(
                f"{manifest.run_id}:appended:{sequence}".encode()
            ).hexdigest(),
        }
    )


def _lifecycle_row(
    manifest: RunManifest,
    *,
    merged: bool,
    head_sha: str,
    updated_at: datetime | None = None,
    observed_at: datetime | None = None,
    commits: tuple[PullRequestCommit, ...] | None = None,
    timeline_events: tuple[PullRequestTimelineEvent, ...] | None = None,
    references: tuple[PullRequestReference, ...] = (),
) -> LifecycleSnapshot:
    assert manifest.candidate is not None
    assert manifest.pull_request_url is not None
    repository = manifest.candidate.repository
    repository_name = repository.split("/", 1)[1]
    updated = updated_at or manifest.created_at + timedelta(hours=3)
    terminal_at = updated - timedelta(minutes=1) if merged else None
    commit_history = commits or (
        PullRequestCommit(
            position=1,
            sha=head_sha,
            node_id=f"C_{head_sha}",
            parent_shas=(manifest.base_sha or "b" * 40,),
        ),
    )
    retained_timeline = timeline_events
    if retained_timeline is None:
        retained_timeline = (
            (
                PullRequestTimelineEvent(
                    identifier=1,
                    node_id=f"E_closed_{manifest.run_id}",
                    event="closed",
                    actor="maintainer",
                    commit_sha=None,
                    created_at=terminal_at,
                ),
                PullRequestTimelineEvent(
                    identifier=2,
                    node_id=f"E_merged_{manifest.run_id}",
                    event="merged",
                    actor="maintainer",
                    commit_sha="e" * 40,
                    created_at=terminal_at,
                ),
            )
            if terminal_at is not None
            else ()
        )
    pull_request = PullRequestDetails(
        repository=repository,
        number=manifest.candidate.number,
        html_url=manifest.pull_request_url,
        state="closed" if merged else "open",
        draft=not merged,
        merged=merged,
        updated_at=updated,
        merged_at=terminal_at,
        closed_at=terminal_at,
        merge_commit_sha="e" * 40 if merged else None,
        head_sha=head_sha,
        base_sha=manifest.base_sha or "b" * 40,
        head_repository=f"{LOGIN}/{repository_name}",
        issue_comment_count=0,
        review_comment_count=0,
        commit_count=len(commit_history),
        title="A focused contribution",
        body="Fixes the exact issue.",
        base_ref="main",
        head_ref=manifest.branch_name or "branch",
        head_label=f"{LOGIN}:{manifest.branch_name}",
        node_id=f"PR_{manifest.run_id}",
    )
    snapshot = PullRequestLifecycleSnapshot(
        observed_at=observed_at or updated,
        expected_head_sha=manifest.commit_sha or "",
        pull_request=pull_request,
        commits=commit_history,
        reviews=(),
        issue_comments=(),
        review_comments=(),
        check_runs=(),
        commit_statuses=(),
        timeline_item_count=len(retained_timeline) + len(references),
        timeline_events=retained_timeline,
        references=references,
    )
    return LifecycleSnapshot(
        run_id=manifest.run_id,
        fingerprint=snapshot.fingerprint(),
        observed_at=snapshot.observed_at,
        snapshot_json=snapshot.to_json(),
    )


def _stored_snapshot(
    manifest: RunManifest,
    snapshot: PullRequestLifecycleSnapshot,
) -> LifecycleSnapshot:
    return LifecycleSnapshot(
        run_id=manifest.run_id,
        fingerprint=snapshot.fingerprint(),
        observed_at=snapshot.observed_at,
        snapshot_json=snapshot.to_json(),
    )


def _parsed_snapshot(row: LifecycleSnapshot) -> PullRequestLifecycleSnapshot:
    return parse_lifecycle_snapshot_json(row.snapshot_json, observed_at=row.observed_at)


def _passing_manual_cohort(
    store: FakeStore,
    evaluations: FakeEvaluations,
) -> None:
    for index in range(20):
        _add_publication(store, evaluations, index)


def test_review_to_auto_switch_preserves_the_exact_first_twenty_cohort() -> None:
    review_config = _rollout_config(
        "review_required",
        auto_publish_env="REVIEW_ONLY_SWITCH",
    )
    auto_config = _rollout_config("auto")
    review_fingerprint = _deployment_fingerprint(review_config)
    auto_fingerprint = _deployment_fingerprint(auto_config)
    assert review_fingerprint == auto_fingerprint

    ready_drift = review_config.model_copy(deep=True)
    ready_drift.publishing.ready_for_review = False
    draft_drift = ready_drift.model_copy(deep=True)
    draft_drift.publishing.draft = False
    model_drift = review_config.model_copy(deep=True)
    model_drift.models.builder.model = "different-builder"
    policy_drift = review_config.model_copy(deep=True)
    policy_drift.policy.require_contribution_guidelines = False
    assert _deployment_fingerprint(ready_drift) != review_fingerprint
    assert _deployment_fingerprint(draft_drift) != _deployment_fingerprint(ready_drift)
    assert _deployment_fingerprint(model_drift) != review_fingerprint
    assert _deployment_fingerprint(policy_drift) != review_fingerprint
    assert (
        _deployment_fingerprint(_rollout_config("auto", repository="example/other"))
        != review_fingerprint
    )

    store = FakeStore()
    evaluations = FakeEvaluations()
    for index in range(20):
        _add_publication(
            store,
            evaluations,
            index,
            deployment_fingerprint=review_fingerprint,
            ready_for_review=True,
        )

    review_summary = UpstreamOutcomeGate(store, evaluations).summary(_scope(review_fingerprint))
    auto_summary = UpstreamOutcomeGate(store, evaluations).summary(_scope(auto_fingerprint))

    expected = [f"{index + 1:016x}" for index in range(20)]
    assert [member.run_id for member in review_summary.manual_cohort] == expected
    assert [member.run_id for member in auto_summary.manual_cohort] == expected
    assert auto_summary.manual_cohort_passed is True
    assert auto_summary.corpus_cursor == review_summary.corpus_cursor
    assert auto_summary.decision_digest == review_summary.decision_digest


def test_fixed_cohort_is_account_wide_and_preserves_each_repository_proof() -> None:
    store = FakeStore()
    evaluations = FakeEvaluations()
    repositories = ("example/first", "example/second")
    for index in range(20):
        _add_publication(
            store,
            evaluations,
            index,
            repository=repositories[index % len(repositories)],
        )

    summary = UpstreamOutcomeGate(store, evaluations).summary(_scope())

    assert summary.gate_passed is True
    assert [member.repository for member in summary.manual_cohort] == [
        repositories[index % len(repositories)] for index in range(20)
    ]
    assert "repository" not in summary.scope.model_dump()


def test_fixed_cohort_uses_global_publication_ledger_order() -> None:
    store = FakeStore()
    evaluations = FakeEvaluations()
    for index in range(20):
        sequence = 2 if index == 0 else 1 if index == 1 else index + 1
        _add_publication(
            store,
            evaluations,
            index,
            publication_sequence=sequence,
        )

    summary = UpstreamOutcomeGate(store, evaluations).summary(_scope())

    assert [member.run_id for member in summary.manual_cohort[:2]] == [
        f"{2:016x}",
        f"{1:016x}",
    ]
    assert summary.gate_passed is True


def test_exact_fixed_manual_cohort_and_prior_auto_pass() -> None:
    store = FakeStore()
    evaluations = FakeEvaluations()
    _passing_manual_cohort(store, evaluations)
    automatic = _add_publication(store, evaluations, 20, automatic=True)

    summary = UpstreamOutcomeGate(store, evaluations).summary(_scope())

    assert summary.gate_passed is True
    assert summary.manual_cohort_passed is True
    assert summary.prior_automatic_passed is True
    assert len(summary.manual_cohort) == 20
    assert [member.cohort_position for member in summary.manual_cohort] == list(range(1, 21))
    assert all(member.manual_member_passed for member in summary.manual_cohort)
    assert [member.run_id for member in summary.prior_automatic] == [automatic.run_id]
    assert summary.prior_automatic[0].automatic_member_passed is True


def test_failed_fixed_member_is_not_replaced_by_later_success() -> None:
    store = FakeStore()
    evaluations = FakeEvaluations()
    failed = _add_publication(
        store,
        evaluations,
        0,
        verdict=EvaluationVerdict.NEEDS_MINOR_CHANGES,
    )
    for index in range(1, 21):
        _add_publication(store, evaluations, index)

    summary = UpstreamOutcomeGate(store, evaluations).summary(_scope())

    assert summary.exact_manual_publications == 21
    assert len(summary.manual_cohort) == 20
    assert summary.manual_cohort[0].run_id == failed.run_id
    assert summary.manual_cohort[0].expert_outcome == ExpertOutcome.FAILED
    assert store.runs[20].run_id not in {member.run_id for member in summary.manual_cohort}
    assert summary.manual_cohort_passed is False
    assert summary.gate_passed is False


def test_missing_expert_grade_keeps_fixed_member_pending() -> None:
    store = FakeStore()
    evaluations = FakeEvaluations()
    missing = _add_publication(store, evaluations, 0, verdict=None)
    for index in range(1, 20):
        _add_publication(store, evaluations, index)

    summary = UpstreamOutcomeGate(store, evaluations).summary(_scope())

    member = next(item for item in summary.manual_cohort if item.run_id == missing.run_id)
    assert member.expert_outcome == ExpertOutcome.PENDING
    assert member.evaluation_hash is None
    assert summary.gate_passed is False


def test_every_prior_auto_must_be_merged_as_is() -> None:
    store = FakeStore()
    evaluations = FakeEvaluations()
    _passing_manual_cohort(store, evaluations)
    pending = _add_publication(store, evaluations, 20, automatic=True, merged=False)

    summary = UpstreamOutcomeGate(store, evaluations).summary(_scope())

    assert summary.manual_cohort_passed is True
    assert summary.prior_automatic_passed is False
    assert summary.prior_automatic[0].run_id == pending.run_id
    assert summary.prior_automatic[0].outcome == UpstreamOutcome.PENDING
    assert summary.gate_passed is False


def test_original_commit_drift_is_a_permanent_failed_outcome() -> None:
    store = FakeStore()
    evaluations = FakeEvaluations()
    _passing_manual_cohort(store, evaluations)
    drifted = _add_publication(
        store,
        evaluations,
        20,
        automatic=True,
        head_sha="f" * 40,
    )

    summary = UpstreamOutcomeGate(store, evaluations).summary(_scope())

    member = summary.prior_automatic[0]
    assert member.run_id == drifted.run_id
    assert member.outcome == UpstreamOutcome.FAILED
    assert "head_drift" in member.reasons[0]
    assert summary.gate_passed is False


@pytest.mark.parametrize("history", ["force_push", "close_reopen"])
def test_clean_current_head_cannot_erase_adverse_timeline_history(history: str) -> None:
    store = FakeStore()
    evaluations = FakeEvaluations()
    _passing_manual_cohort(store, evaluations)
    automatic = _add_publication(store, evaluations, 20, automatic=True, merged=False)
    observed = automatic.created_at + timedelta(hours=2)
    if history == "force_push":
        timeline = (
            PullRequestTimelineEvent(
                identifier=1,
                node_id="E_force_push",
                event="head_ref_force_pushed",
                actor="octocat",
                commit_sha=automatic.commit_sha,
                created_at=observed,
            ),
        )
    else:
        timeline = (
            PullRequestTimelineEvent(
                identifier=1,
                node_id="E_closed_once",
                event="closed",
                actor="maintainer",
                commit_sha=None,
                created_at=observed,
            ),
            PullRequestTimelineEvent(
                identifier=2,
                node_id="E_reopened_once",
                event="reopened",
                actor="maintainer",
                commit_sha=None,
                created_at=observed + timedelta(minutes=1),
            ),
        )
    store.snapshots_by_run[automatic.run_id] = [
        _lifecycle_row(
            automatic,
            merged=False,
            head_sha=automatic.commit_sha or "",
            timeline_events=timeline,
        )
    ]

    summary = UpstreamOutcomeGate(store, evaluations).summary(_scope())

    member = summary.prior_automatic[0]
    assert member.outcome == UpstreamOutcome.FAILED
    assert ("head_ref_force_pushed" if history == "force_push" else "close_reopen") in (
        member.reasons[0]
    )


def test_merged_pr_must_retain_only_the_original_prepared_commit() -> None:
    store = FakeStore()
    evaluations = FakeEvaluations()
    _passing_manual_cohort(store, evaluations)
    automatic = _add_publication(store, evaluations, 20, automatic=True)
    intermediate_sha = "9" * 40
    commits = (
        PullRequestCommit(
            position=1,
            sha=intermediate_sha,
            node_id="C_intermediate",
            parent_shas=(automatic.base_sha or "",),
        ),
        PullRequestCommit(
            position=2,
            sha=automatic.commit_sha or "",
            node_id="C_prepared",
            parent_shas=(intermediate_sha,),
        ),
    )
    store.snapshots_by_run[automatic.run_id] = [
        _lifecycle_row(
            automatic,
            merged=True,
            head_sha=automatic.commit_sha or "",
            commits=commits,
        )
    ]

    summary = UpstreamOutcomeGate(store, evaluations).summary(_scope())

    assert summary.prior_automatic[0].outcome == UpstreamOutcome.FAILED
    assert "commit_history" in summary.prior_automatic[0].reasons[0]


def test_later_green_and_approval_do_not_erase_historical_adverse_evidence() -> None:
    store = FakeStore()
    evaluations = FakeEvaluations()
    _passing_manual_cohort(store, evaluations)
    automatic = _add_publication(store, evaluations, 20, automatic=True)
    row = store.snapshots_by_run[automatic.run_id][0]
    snapshot = _parsed_snapshot(row)
    adverse_at = automatic.created_at + timedelta(hours=1)
    clean_at = adverse_at + timedelta(minutes=5)
    snapshot = replace(
        snapshot,
        reviews=(
            PullRequestReview(
                identifier=1,
                author="maintainer",
                author_association="MEMBER",
                state="CHANGES_REQUESTED",
                body="Please adjust this.",
                html_url=f"{automatic.pull_request_url}#pullrequestreview-1",
                submitted_at=adverse_at,
            ),
            PullRequestReview(
                identifier=2,
                author="maintainer",
                author_association="MEMBER",
                state="APPROVED",
                body="Looks good now.",
                html_url=f"{automatic.pull_request_url}#pullrequestreview-2",
                submitted_at=clean_at,
            ),
        ),
        check_runs=(
            CheckRunDetails(
                identifier=1,
                name="tests",
                status="completed",
                conclusion="failure",
                details_url="https://github.com/checks/1",
                app_name="ci",
                started_at=adverse_at,
                completed_at=adverse_at + timedelta(minutes=1),
            ),
            CheckRunDetails(
                identifier=2,
                name="tests",
                status="completed",
                conclusion="success",
                details_url="https://github.com/checks/2",
                app_name="ci",
                started_at=clean_at,
                completed_at=clean_at + timedelta(minutes=1),
            ),
        ),
    )
    store.snapshots_by_run[automatic.run_id] = [_stored_snapshot(automatic, snapshot)]

    summary = UpstreamOutcomeGate(store, evaluations).summary(_scope())

    member = summary.prior_automatic[0]
    assert member.outcome == UpstreamOutcome.FAILED
    assert "historical_changes_requested" in member.reasons[0]
    assert "historical_ci_failure" in member.reasons[0]


def test_later_dismissal_snapshot_cannot_erase_changes_requested() -> None:
    store = FakeStore()
    evaluations = FakeEvaluations()
    _passing_manual_cohort(store, evaluations)
    automatic = _add_publication(store, evaluations, 20, automatic=True)
    base_row = store.snapshots_by_run[automatic.run_id][0]
    base = _parsed_snapshot(base_row)
    submitted_at = automatic.created_at + timedelta(hours=1)
    requested = PullRequestReview(
        identifier=1,
        author="maintainer",
        author_association="MEMBER",
        state="CHANGES_REQUESTED",
        body="Please change this contribution.",
        html_url=f"{automatic.pull_request_url}#pullrequestreview-1",
        submitted_at=submitted_at,
    )
    adverse = replace(base, reviews=(requested,))
    dismissed = replace(
        base,
        observed_at=base.observed_at + timedelta(hours=1),
        pull_request=replace(
            base.pull_request,
            updated_at=base.pull_request.updated_at + timedelta(hours=1),
        ),
        reviews=(replace(requested, state="DISMISSED"),),
    )
    store.snapshots_by_run[automatic.run_id] = [
        _stored_snapshot(automatic, adverse),
        _stored_snapshot(automatic, dismissed),
    ]

    summary = UpstreamOutcomeGate(store, evaluations).summary(_scope())

    assert summary.prior_automatic[0].outcome == UpstreamOutcome.FAILED
    assert "historical_changes_requested" in summary.prior_automatic[0].reasons[0]


def test_maintainer_stop_remains_a_permanent_failed_outcome() -> None:
    store = FakeStore()
    evaluations = FakeEvaluations()
    _passing_manual_cohort(store, evaluations)
    automatic = _add_publication(store, evaluations, 20, automatic=True)
    row = store.snapshots_by_run[automatic.run_id][0]
    snapshot = _parsed_snapshot(row)
    created_at = automatic.created_at + timedelta(hours=1)
    stop = GitHubComment(
        identifier=1,
        author="maintainer",
        author_association="OWNER",
        body="Please close this pull request and stop automated contributions.",
        html_url=f"{automatic.pull_request_url}#issuecomment-1",
        created_at=created_at,
        updated_at=created_at,
    )
    snapshot = replace(
        snapshot,
        pull_request=replace(snapshot.pull_request, issue_comment_count=1),
        issue_comments=(stop,),
    )
    store.snapshots_by_run[automatic.run_id] = [_stored_snapshot(automatic, snapshot)]

    summary = UpstreamOutcomeGate(store, evaluations).summary(_scope())

    assert summary.prior_automatic[0].outcome == UpstreamOutcome.FAILED
    assert "maintainer_stop" in summary.prior_automatic[0].reasons[0]


def test_revert_observed_after_merge_permanently_fails_the_outcome() -> None:
    store = FakeStore()
    evaluations = FakeEvaluations()
    _passing_manual_cohort(store, evaluations)
    automatic = _add_publication(store, evaluations, 20, automatic=True)
    first_row = store.snapshots_by_run[automatic.run_id][0]
    first = _parsed_snapshot(first_row)
    assert first.pull_request.merged_at is not None
    reverted_at = first.pull_request.merged_at + timedelta(hours=1)
    reference = PullRequestReference(
        identifier=3,
        node_id="E_revert_reference",
        source_url=f"https://github.com/{REPOSITORY}/pull/999",
        source_title=f"Revert #{automatic.candidate.number if automatic.candidate else 0}",
        source_body=f"This reverts {automatic.pull_request_url}",
        source_state="closed",
        source_merged_at=reverted_at,
        created_at=reverted_at,
    )
    later = replace(
        first,
        observed_at=first.observed_at + timedelta(hours=2),
        pull_request=replace(
            first.pull_request,
            updated_at=first.pull_request.updated_at + timedelta(hours=2),
        ),
        timeline_item_count=first.timeline_item_count + 1,
        references=(reference,),
    )
    store.snapshots_by_run[automatic.run_id] = [
        first_row,
        _stored_snapshot(automatic, later),
    ]

    summary = UpstreamOutcomeGate(store, evaluations).summary(_scope())

    assert summary.prior_automatic[0].outcome == UpstreamOutcome.FAILED
    assert "reverted" in summary.prior_automatic[0].reasons[0]


def test_legacy_partial_lifecycle_history_can_never_prove_merge_as_is() -> None:
    store = FakeStore()
    evaluations = FakeEvaluations()
    _passing_manual_cohort(store, evaluations)
    automatic = _add_publication(store, evaluations, 20, automatic=True)
    current_row = store.snapshots_by_run[automatic.run_id][0]
    payload = json.loads(current_row.snapshot_json)
    del payload["evidence_version"]
    del payload["commits"]
    del payload["timeline_events"]
    del payload["timeline_item_count"]
    del payload["pull_request"]["commit_count"]
    for reference in payload["references"]:
        del reference["node_id"]
    legacy_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    legacy = parse_lifecycle_snapshot_json(
        legacy_json,
        observed_at=current_row.observed_at,
    )
    assert legacy.has_complete_upstream_history is False
    store.snapshots_by_run[automatic.run_id] = [
        LifecycleSnapshot(
            run_id=automatic.run_id,
            fingerprint=legacy.fingerprint(),
            observed_at=current_row.observed_at,
            snapshot_json=legacy_json,
        )
    ]

    summary = UpstreamOutcomeGate(store, evaluations).summary(_scope())

    assert summary.prior_automatic[0].outcome == UpstreamOutcome.UNKNOWN
    assert "lacks complete upstream history" in summary.prior_automatic[0].reasons[0]
    assert summary.gate_passed is False


def test_ambiguous_authorization_blocks_instead_of_becoming_manual() -> None:
    store = FakeStore()
    evaluations = FakeEvaluations()
    _passing_manual_cohort(store, evaluations)
    ambiguous = _add_publication(store, evaluations, 20, approval=False, verdict=None)

    summary = UpstreamOutcomeGate(store, evaluations).summary(_scope())

    assert [member.run_id for member in summary.ambiguous] == [ambiguous.run_id]
    assert summary.ambiguous[0].authorization == PublicationAuthorization.AMBIGUOUS
    assert summary.ambiguous[0].outcome == UpstreamOutcome.UNKNOWN
    assert summary.gate_passed is False


def test_conflicting_manifest_and_ledger_publication_identity_blocks() -> None:
    store = FakeStore()
    evaluations = FakeEvaluations()
    _passing_manual_cohort(store, evaluations)
    conflicting = _add_publication(store, evaluations, 20)
    intent = _event(store, conflicting.run_id, "publication.intent.begun")
    details = json.loads(intent["details"])
    details["publishing_login"] = "different-account"
    _replace_event_details(intent, details)

    summary = UpstreamOutcomeGate(store, evaluations).summary(_scope())

    assert [member.run_id for member in summary.ambiguous] == [conflicting.run_id]
    assert "conflicting publication identities" in summary.ambiguous[0].reasons[0]
    assert summary.gate_passed is False


def test_auto_hold_wins_over_an_existing_human_approval() -> None:
    store = FakeStore()
    evaluations = FakeEvaluations()
    _passing_manual_cohort(store, evaluations)
    automatic = _add_publication(store, evaluations, 20, automatic=True, approval=True)

    summary = UpstreamOutcomeGate(store, evaluations).summary(_scope())

    assert automatic.run_id not in {member.run_id for member in summary.manual_cohort}
    assert summary.prior_automatic[0].authorization == PublicationAuthorization.AUTO


def test_exact_human_approval_exposes_ledger_bound_intent_time() -> None:
    store = FakeStore()
    evaluations = FakeEvaluations()
    publication = _add_publication(store, evaluations, 0)
    events = tuple(store.events_by_run[publication.run_id])

    authority = classify_exact_human_approval(publication, events)

    assert authority is not None
    approval = _event(store, publication.run_id, "approval.created")
    intent = _event(store, publication.run_id, "publication.intent.begun")
    assert authority.approval_event_hash == approval["event_hash"]
    assert authority.publication_intent_event_hash == intent["event_hash"]
    assert authority.publication_intent_at == datetime.fromisoformat(intent["occurred_at"])


@pytest.mark.parametrize("corruption", ["missing_intent", "automatic_hold"])
def test_exact_human_approval_rejects_non_review_authority(corruption: str) -> None:
    store = FakeStore()
    evaluations = FakeEvaluations()
    publication = _add_publication(
        store,
        evaluations,
        0,
        automatic=corruption == "automatic_hold",
        approval=True,
    )
    events = store.events_by_run[publication.run_id]
    if corruption == "missing_intent":
        events[:] = [event for event in events if event["event_type"] != "publication.intent.begun"]

    assert classify_exact_human_approval(publication, tuple(events)) is None


def test_pre_v6_automatic_hold_is_ambiguous() -> None:
    store = FakeStore()
    evaluations = FakeEvaluations()
    _passing_manual_cohort(store, evaluations)
    automatic = _add_publication(store, evaluations, 20, automatic=True)
    hold = _event(store, automatic.run_id, "publication.gate.held")
    details = json.loads(hold["details"])
    del details["outcome_corpus_cursor"]
    _replace_event_details(hold, details)

    summary = UpstreamOutcomeGate(store, evaluations).summary(_scope())

    assert [member.run_id for member in summary.ambiguous] == [automatic.run_id]
    assert "unsupported evidence shape" in summary.ambiguous[0].reasons[0]
    assert summary.gate_passed is False


@pytest.mark.parametrize(
    ("automatic", "authorization_event"),
    [
        (False, "approval.created"),
        (True, "publication.gate.held"),
    ],
)
def test_authorization_recorded_after_publication_intent_is_ambiguous(
    automatic: bool,
    authorization_event: str,
) -> None:
    store = FakeStore()
    evaluations = FakeEvaluations()
    publication = _add_publication(
        store,
        evaluations,
        0,
        automatic=automatic,
    )
    events = store.events_by_run[publication.run_id]
    authorization = next(event for event in events if event["event_type"] == authorization_event)
    events.remove(authorization)
    transition_index = next(
        index for index, event in enumerate(events) if event["event_type"] == "run.transitioned"
    )
    events.insert(transition_index, authorization)

    summary = UpstreamOutcomeGate(store, evaluations).summary(_scope())

    assert [member.run_id for member in summary.ambiguous] == [publication.run_id]
    assert summary.gate_passed is False


def test_ready_for_review_requires_exact_completed_ledger_sequence() -> None:
    store = FakeStore()
    evaluations = FakeEvaluations()
    incomplete = _add_publication(
        store,
        evaluations,
        0,
        ready_for_review=True,
    )
    store.events_by_run[incomplete.run_id] = [
        event
        for event in store.events_by_run[incomplete.run_id]
        if event["event_type"] != "pull_request.ready_for_review.completed"
    ]

    summary = UpstreamOutcomeGate(store, evaluations).summary(_scope())

    member = summary.manual_cohort[0]
    assert member.run_id == incomplete.run_id
    assert member.outcome == UpstreamOutcome.UNKNOWN
    assert "completion evidence" in member.reasons[0]
    assert summary.gate_passed is False


def test_terminal_canonical_pr_allows_ready_transition_to_be_skipped() -> None:
    store = FakeStore()
    evaluations = FakeEvaluations()
    terminal = _add_publication(
        store,
        evaluations,
        0,
        ready_for_review=True,
    )
    terminal.pull_request_ready_started = False
    terminal.pull_request_ready_completed = False
    store.events_by_run[terminal.run_id] = [
        event
        for event in store.events_by_run[terminal.run_id]
        if not event["event_type"].startswith("pull_request.ready_for_review.")
    ]
    canonical = _event(store, terminal.run_id, "pull_request.created.response")
    details = json.loads(canonical["details"])
    details["state"] = "merged"
    _replace_event_details(canonical, details)

    summary = UpstreamOutcomeGate(store, evaluations).summary(_scope())

    assert summary.manual_cohort[0].outcome == UpstreamOutcome.MERGED_AS_IS
    assert summary.manual_cohort[0].repository == REPOSITORY


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("base_sha", "not-a-sha", "base commit"),
        ("commit_author_email", "invalid", "Git identity"),
        ("commit_committer_name", "Different", "author and committer"),
    ],
)
def test_noncanonical_publication_identity_fails_closed(
    field: str,
    value: str,
    reason: str,
) -> None:
    store = FakeStore()
    evaluations = FakeEvaluations()
    publication = _add_publication(store, evaluations, 0)
    setattr(publication, field, value)

    summary = UpstreamOutcomeGate(store, evaluations).summary(_scope())

    assert summary.manual_cohort[0].outcome == UpstreamOutcome.UNKNOWN
    assert reason in summary.manual_cohort[0].reasons[0]


def test_exact_ready_candidate_can_be_excluded_before_its_hold() -> None:
    store = FakeStore()
    evaluations = FakeEvaluations()
    _passing_manual_cohort(store, evaluations)
    candidate = _add_publication(store, evaluations, 20, verdict=None, approval=False)
    candidate.status = RunStatus.READY_FOR_APPROVAL
    candidate.branch_name = None
    candidate.commit_sha = None
    candidate.pull_request_url = None
    candidate.pull_request_creation_started = False
    created_event, context_event = store.events_by_run[candidate.run_id][:2]
    context_event["event_type"] = "publication.context.bound"
    _replace_event_details(
        context_event,
        {
            "publishing_login": LOGIN,
            "publishing_api_origin": API_ORIGIN,
            "publication_draft": "true",
            "publication_ready_for_review": "false",
        },
    )
    store.events_by_run[candidate.run_id] = [created_event, context_event]
    store.snapshots_by_run[candidate.run_id] = []

    ordinary_summary = UpstreamOutcomeGate(store, evaluations).summary(_scope())
    summary = UpstreamOutcomeGate(store, evaluations).summary(
        _scope(),
        exclude_run_id=candidate.run_id,
    )

    assert ordinary_summary.gate_passed is True
    assert ordinary_summary.prior_automatic == ()
    assert ordinary_summary.ambiguous == ()
    assert summary.gate_passed is True
    assert summary.prior_automatic == ()


def test_verified_no_pr_automatic_compensation_does_not_poison_prior_prs() -> None:
    store = FakeStore()
    evaluations = FakeEvaluations()
    _passing_manual_cohort(store, evaluations)
    automatic = _add_publication(
        store,
        evaluations,
        20,
        automatic=True,
        merged=False,
    )
    automatic.status = RunStatus.FAILED
    automatic.pull_request_url = None
    automatic.pull_request_creation_started = False
    automatic.pull_request_ready_started = False
    automatic.pull_request_ready_completed = False
    store.snapshots_by_run[automatic.run_id] = []
    store.events_by_run[automatic.run_id] = [
        event
        for event in store.events_by_run[automatic.run_id]
        if event["event_type"]
        in {"run.created", "publication.gate.held", "publication.intent.begun"}
    ]
    reason = "verified absent remote publication state before pull-request creation"
    fork = "octocat/project"
    head = f"{LOGIN}:{automatic.branch_name}"
    absence = {
        "repository": REPOSITORY,
        "head": head,
        "fork": fork,
        "branch": automatic.branch_name or "",
        "commit_sha": automatic.commit_sha or "",
        "reason": reason,
    }
    _append_event(store, automatic, "publication.absence.verified", absence)
    _append_event(
        store,
        automatic,
        "publication.compensation.verified",
        {
            **absence,
            "pull_request": "absent",
            "remote_branch": "absent",
        },
    )
    _append_event(
        store,
        automatic,
        "run.transitioned",
        {
            "from": RunStatus.SUBMITTING.value,
            "to": RunStatus.FAILED.value,
            "reason": reason,
        },
    )
    hold = json.loads(_event(store, automatic.run_id, "publication.gate.held")["details"])
    _append_event(
        store,
        automatic,
        "publication.gate.released",
        {
            "outcome": "verified_compensation",
            "corpus_cursor": hold["corpus_cursor"],
            "held_at": hold["held_at"],
            "deployment_fingerprint": hold["deployment_fingerprint"],
            "outcome_corpus_cursor": hold["outcome_corpus_cursor"],
        },
    )

    summary = UpstreamOutcomeGate(store, evaluations).summary(_scope())

    assert summary.gate_passed is True
    assert summary.prior_automatic == ()

    store.events_by_run[automatic.run_id] = [
        event
        for event in store.events_by_run[automatic.run_id]
        if event["event_type"] != "publication.compensation.verified"
    ]
    incomplete = UpstreamOutcomeGate(store, evaluations).summary(_scope())
    assert incomplete.gate_passed is False
    assert incomplete.prior_automatic[0].outcome == UpstreamOutcome.UNKNOWN


def test_held_submitting_recovery_can_be_excluded_but_prior_auto_cannot() -> None:
    store = FakeStore()
    evaluations = FakeEvaluations()
    _passing_manual_cohort(store, evaluations)
    automatic = _add_publication(store, evaluations, 20, automatic=True)
    automatic.status = RunStatus.SUBMITTING

    recovery = UpstreamOutcomeGate(store, evaluations).summary(
        _scope(),
        exclude_run_id=automatic.run_id,
    )
    assert recovery.gate_passed is True
    assert recovery.prior_automatic == ()

    _append_event(
        store,
        automatic,
        "publication.gate.released",
        {"outcome": "fixture"},
    )
    with pytest.raises(StateError, match="automatic outcome-gate hold"):
        UpstreamOutcomeGate(store, evaluations).summary(
            _scope(),
            exclude_run_id=automatic.run_id,
        )
    store.events_by_run[automatic.run_id].pop()

    automatic.status = RunStatus.PR_OPEN
    with pytest.raises(StateError, match=r"cannot be excluded|Only the exact"):
        UpstreamOutcomeGate(store, evaluations).summary(
            _scope(),
            exclude_run_id=automatic.run_id,
        )


def test_cursor_excludes_unfingerprinted_observation_time() -> None:
    store = FakeStore()
    evaluations = FakeEvaluations()
    _passing_manual_cohort(store, evaluations)
    gate = UpstreamOutcomeGate(store, evaluations)
    before = gate.summary(_scope())

    for run_id, rows in store.snapshots_by_run.items():
        store.snapshots_by_run[run_id] = [
            replace(row, observed_at=row.observed_at + timedelta(days=30)) for row in rows
        ]
    after = gate.summary(_scope())

    assert before.corpus_cursor == after.corpus_cursor
    assert before.gate_passed == after.gate_passed


def test_store_corpus_drift_during_classification_fails_closed() -> None:
    store = DriftingFakeStore()
    evaluations = FakeEvaluations()
    _passing_manual_cohort(store, evaluations)

    with pytest.raises(StateError, match="corpus changed"):
        UpstreamOutcomeGate(store, evaluations).summary(_scope())


def test_github_time_regression_is_unknown_and_blocks() -> None:
    store = FakeStore()
    evaluations = FakeEvaluations()
    _passing_manual_cohort(store, evaluations)
    automatic = _add_publication(store, evaluations, 20, automatic=True, merged=False)
    first = store.snapshots_by_run[automatic.run_id][0]
    original_snapshot = parse_lifecycle_snapshot_json(
        first.snapshot_json,
        observed_at=first.observed_at,
    )
    first_snapshot = replace(
        original_snapshot,
        pull_request=replace(
            original_snapshot.pull_request,
            updated_at=automatic.created_at + timedelta(hours=4),
        ),
    )
    first_row = LifecycleSnapshot(
        run_id=automatic.run_id,
        fingerprint=first_snapshot.fingerprint(),
        observed_at=first.observed_at,
        snapshot_json=first_snapshot.to_json(),
    )
    regressed = _lifecycle_row(
        automatic,
        merged=False,
        head_sha=automatic.commit_sha or "",
        updated_at=automatic.created_at + timedelta(hours=3),
    )
    store.snapshots_by_run[automatic.run_id] = [first_row, regressed]

    summary = UpstreamOutcomeGate(store, evaluations).summary(_scope())

    assert summary.prior_automatic[0].outcome == UpstreamOutcome.UNKNOWN
    assert "regressed" in summary.prior_automatic[0].reasons[0]
    assert summary.gate_passed is False


def test_classifier_consumes_real_store_ledger_and_lifecycle_apis(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    manifest = store.create_run(deployment_fingerprint=DEPLOYMENT)
    manifest.candidate = IssueCandidate(
        repository=REPOSITORY,
        number=1,
        title="Issue 1",
        body="A narrow issue.",
        html_url=f"https://github.com/{REPOSITORY}/issues/1",
        state="open",
        author="maintainer",
        labels=["bug"],
        assignees=[],
        comments=0,
        created_at=manifest.created_at,
        updated_at=manifest.created_at,
    )
    manifest.repository = RepositoryInfo(
        full_name=REPOSITORY,
        html_url=f"https://github.com/{REPOSITORY}",
        clone_url=f"https://github.com/{REPOSITORY}.git",
        default_branch="main",
        stars=10_000,
        archived=False,
        disabled=False,
        private=False,
        pushed_at=manifest.created_at,
        license_spdx="MIT",
    )
    manifest.base_sha = "b" * 40
    manifest.status = RunStatus.READY_FOR_APPROVAL
    manifest.approval = Approval(
        actor=LOGIN,
        approved_at=manifest.created_at,
        expires_at=manifest.created_at + timedelta(hours=24),
        manifest_hash="a" * 64,
        attestation="I reviewed the exact contribution.",
    )
    store.save(
        manifest,
        event="approval.created",
        details={
            "actor": LOGIN,
            "expires_at": manifest.approval.expires_at.isoformat(),
            "manifest_hash": manifest.approval.manifest_hash,
        },
    )
    manifest = store.begin_publication(
        manifest,
        REPOSITORY,
        branch_name=f"autocontribute/issue-1-{manifest.run_id}",
        publication_draft=True,
        publication_ready_for_review=False,
        publishing_login=LOGIN,
        publishing_api_origin=API_ORIGIN,
        commit_author_name="Octocat",
        commit_author_email="octocat@users.noreply.github.com",
        commit_committer_name="Octocat",
        commit_committer_email="octocat@users.noreply.github.com",
        max_per_utc_day=10,
        repository_cooldown=timedelta(0),
    )
    manifest.commit_sha = "c" * 40
    manifest.pull_request_creation_started = True
    manifest.pull_request_url = f"https://github.com/{REPOSITORY}/pull/1"
    store.save(
        manifest,
        event="pull_request.created.response",
        details={
            "url": manifest.pull_request_url,
            "repository": REPOSITORY,
            "number": "1",
            "state": "open",
            "head_sha": manifest.commit_sha,
            "base_sha": manifest.base_sha,
        },
    )
    store.transition(manifest, RunStatus.PR_OPEN, reason="pull request opened")
    row = _lifecycle_row(
        manifest,
        merged=True,
        head_sha=manifest.commit_sha,
    )
    assert store.record_lifecycle_snapshot(
        manifest.run_id,
        row.fingerprint,
        row.snapshot_json,
    )

    summary = UpstreamOutcomeGate(store, FakeEvaluations()).summary(_scope())

    assert summary.exact_manual_publications == 1
    assert summary.manual_cohort[0].authorization == PublicationAuthorization.REVIEW_REQUIRED
    assert summary.manual_cohort[0].outcome == UpstreamOutcome.MERGED_AS_IS
    assert summary.manual_cohort[0].expert_outcome == ExpertOutcome.PENDING
    assert summary.gate_passed is False
