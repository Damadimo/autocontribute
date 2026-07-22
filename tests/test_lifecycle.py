from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from autocontribute.coordination import LeaseHeartbeatGuard
from autocontribute.domain import IssueCandidate, RepositoryInfo, RunManifest, RunStatus
from autocontribute.exceptions import GitHubError, StateError
from autocontribute.github import (
    CheckRunDetails,
    CommitStatusDetails,
    GitHubComment,
    PullRequestCommit,
    PullRequestDetails,
    PullRequestReference,
    PullRequestReview,
    PullRequestTimeline,
    PullRequestTimelineEvent,
)
from autocontribute.lifecycle import (
    LifecycleObserver,
    LifecycleSignalKind,
    PullRequestLifecycleSnapshot,
    classify_lifecycle,
    parse_lifecycle_snapshot_json,
    parse_pull_request_url,
    sync_open_pull_requests,
)
from autocontribute.store import RunStore

NOW = datetime(2026, 7, 21, 12, tzinfo=UTC)


def _pull_request(**changes: object) -> PullRequestDetails:
    values: dict[str, object] = {
        "repository": "example/project",
        "number": 7,
        "html_url": "https://github.com/example/project/pull/7",
        "state": "open",
        "draft": True,
        "merged": False,
        "updated_at": NOW,
        "merged_at": None,
        "closed_at": None,
        "merge_commit_sha": None,
        "head_sha": "a" * 40,
        "base_sha": "b" * 40,
        "head_repository": "example/project",
        "issue_comment_count": 0,
        "review_comment_count": 0,
        "commit_count": 1,
        "title": "Fix lifecycle evidence",
        "body": "",
        "base_ref": "main",
        "head_ref": "fix-lifecycle",
        "head_label": "example:fix-lifecycle",
        "node_id": "PR_fixture_node_7",
    }
    values.update(changes)
    return PullRequestDetails(**values)  # type: ignore[arg-type]


def _review(
    identifier: int,
    *,
    state: str = "COMMENTED",
    body: str = "",
    author: str = "maintainer",
    association: str = "MEMBER",
) -> PullRequestReview:
    return PullRequestReview(
        identifier=identifier,
        author=author,
        author_association=association,
        state=state,
        body=body,
        html_url=f"https://github.com/example/project/pull/7#review-{identifier}",
        submitted_at=NOW,
    )


def _comment(
    identifier: int,
    body: str,
    *,
    author: str = "maintainer",
    association: str = "MEMBER",
) -> GitHubComment:
    return GitHubComment(
        identifier=identifier,
        author=author,
        author_association=association,
        body=body,
        html_url=f"https://github.com/example/project/pull/7#comment-{identifier}",
        created_at=NOW,
        updated_at=NOW,
    )


def _check(
    identifier: int,
    conclusion: str | None,
    *,
    completed_at: datetime | None = NOW,
) -> CheckRunDetails:
    return CheckRunDetails(
        identifier=identifier,
        name="unit",
        status="completed" if conclusion else "in_progress",
        conclusion=conclusion,
        details_url=f"https://ci.example.invalid/check/{identifier}",
        app_name="github-actions",
        started_at=NOW - timedelta(minutes=5),
        completed_at=completed_at,
    )


def _status(
    identifier: int,
    state: str,
    *,
    updated_at: datetime = NOW,
) -> CommitStatusDetails:
    return CommitStatusDetails(
        identifier=identifier,
        context="buildkite/test",
        state=state,
        description=state,
        target_url=f"https://ci.example.invalid/status/{identifier}",
        creator="ci-bot",
        created_at=updated_at,
        updated_at=updated_at,
    )


def _snapshot(
    *,
    pull_request: PullRequestDetails | None = None,
    expected_head_sha: str = "a" * 40,
    commits: tuple[PullRequestCommit, ...] | None = None,
    reviews: tuple[PullRequestReview, ...] = (),
    issue_comments: tuple[GitHubComment, ...] = (),
    review_comments: tuple[GitHubComment, ...] = (),
    checks: tuple[CheckRunDetails, ...] = (),
    statuses: tuple[CommitStatusDetails, ...] = (),
    references: tuple[PullRequestReference, ...] = (),
    timeline_events: tuple[PullRequestTimelineEvent, ...] | None = None,
    timeline_item_count: int | None = None,
) -> PullRequestLifecycleSnapshot:
    pull_request = pull_request or _pull_request()
    commit_evidence = (
        commits
        if commits is not None
        else (
            PullRequestCommit(
                position=1,
                sha=pull_request.head_sha,
                node_id=f"C_{pull_request.head_sha}",
                parent_shas=(pull_request.base_sha,),
            ),
        )
    )
    if timeline_events is None:
        default_events: list[PullRequestTimelineEvent] = []
        if pull_request.merged:
            default_events.append(
                PullRequestTimelineEvent(
                    identifier=90,
                    node_id="ME_fixture_90",
                    event="merged",
                    actor="maintainer",
                    commit_sha=pull_request.merge_commit_sha,
                    created_at=pull_request.merged_at or NOW,
                )
            )
        if pull_request.state == "closed":
            default_events.append(
                PullRequestTimelineEvent(
                    identifier=91,
                    node_id="CE_fixture_91",
                    event="closed",
                    actor="maintainer",
                    commit_sha=None,
                    created_at=pull_request.closed_at or NOW,
                )
            )
        timeline_events = tuple(default_events)
    return PullRequestLifecycleSnapshot(
        observed_at=NOW,
        expected_head_sha=expected_head_sha,
        pull_request=pull_request,
        commits=commit_evidence,
        reviews=reviews,
        issue_comments=issue_comments,
        review_comments=review_comments,
        check_runs=checks,
        commit_statuses=statuses,
        timeline_item_count=(
            len(timeline_events) + len(references)
            if timeline_item_count is None
            else timeline_item_count
        ),
        timeline_events=timeline_events,
        references=references,
    )


class FakeLifecycleGitHub:
    def __init__(
        self,
        pull_requests: list[PullRequestDetails] | None = None,
        *,
        api_origin: str = "https://api.github.com",
    ) -> None:
        self.api_origin = api_origin
        self.pull_requests = pull_requests or [_pull_request(), _pull_request()]
        self.reviews: list[PullRequestReview] = []
        self.issue_comments: list[GitHubComment] = []
        self.review_comments: list[GitHubComment] = []
        self.check_runs: list[CheckRunDetails] = []
        self.statuses: list[CommitStatusDetails] = []
        self.references: list[PullRequestReference] = []
        self.commits: list[PullRequestCommit] = [
            PullRequestCommit(
                position=1,
                sha=self.pull_requests[0].head_sha,
                node_id=f"C_{self.pull_requests[0].head_sha}",
                parent_shas=(self.pull_requests[0].base_sha,),
            )
        ]
        self.timeline_events: list[PullRequestTimelineEvent] = []
        self.timeline_item_count = 0
        self.get_calls = 0

    def get_pull_request(self, repository: str, number: int) -> PullRequestDetails:
        value = self.pull_requests[min(self.get_calls, len(self.pull_requests) - 1)]
        self.get_calls += 1
        return value

    def list_pull_request_reviews(
        self, repository: str, number: int, *, max_reviews: int = 500
    ) -> list[PullRequestReview]:
        return self.reviews

    def list_pull_request_commits(
        self,
        repository: str,
        number: int,
        *,
        expected_count: int,
        expected_head_sha: str,
        max_commits: int = 250,
    ) -> list[PullRequestCommit]:
        assert expected_count == len(self.commits)
        assert self.commits[-1].sha == expected_head_sha
        return self.commits

    def list_issue_comments(
        self,
        repository: str,
        number: int,
        *,
        expected_count: int | None = None,
        max_comments: int = 500,
    ) -> list[GitHubComment]:
        assert expected_count == len(self.issue_comments)
        return self.issue_comments

    def list_review_comments(
        self,
        repository: str,
        number: int,
        *,
        expected_count: int | None = None,
        max_comments: int = 500,
    ) -> list[GitHubComment]:
        assert expected_count == len(self.review_comments)
        return self.review_comments

    def list_check_runs(
        self, repository: str, ref: str, *, max_check_runs: int = 500
    ) -> list[CheckRunDetails]:
        return self.check_runs

    def list_commit_statuses(
        self, repository: str, ref: str, *, max_statuses: int = 500
    ) -> list[CommitStatusDetails]:
        return self.statuses

    def get_pull_request_timeline(
        self, repository: str, number: int, *, max_events: int = 1_000
    ) -> PullRequestTimeline:
        return PullRequestTimeline(
            item_count=self.timeline_item_count,
            events=tuple(self.timeline_events),
            references=tuple(self.references),
        )


class FakeLifecycleStore:
    def __init__(self) -> None:
        self.snapshots: dict[str, str] = {}
        self.triggers: dict[str, tuple[str, str]] = {}

    def record_lifecycle_snapshot(self, run_id: str, fingerprint: str, snapshot_json: str) -> bool:
        if fingerprint in self.snapshots:
            assert self.snapshots[fingerprint] == snapshot_json
            return False
        self.snapshots[fingerprint] = snapshot_json
        return True

    def trip_circuit_breaker(self, *, source: str, reason: str, trigger_hash: str) -> bool:
        if trigger_hash in self.triggers:
            return False
        self.triggers[trigger_hash] = (source, reason)
        return True


def _published_run(
    store: RunStore,
    *,
    repository: str = "example/project",
    number: int = 7,
    pull_request_url: str | None = None,
    commit_sha: str = "a" * 40,
    publishing_api_origin: str = "https://api.github.com",
) -> RunManifest:
    run = store.create_run()
    run.status = RunStatus.PR_OPEN
    run.candidate = IssueCandidate(
        repository=repository,
        number=42,
        title="Fix parser boundary",
        body="Reproduction and expected behavior.",
        html_url=f"https://github.com/{repository}/issues/42",
        state="open",
        author="maintainer",
        labels=["bug"],
        assignees=[],
        comments=0,
        created_at=NOW,
        updated_at=NOW,
    )
    run.repository = RepositoryInfo(
        full_name=repository,
        html_url=f"https://github.com/{repository}",
        clone_url=f"https://github.com/{repository}.git",
        default_branch="main",
        stars=100,
        archived=False,
        disabled=False,
        private=False,
        pushed_at=NOW,
        license_spdx="MIT",
    )
    run.commit_sha = commit_sha
    run.pull_request_url = pull_request_url or f"https://github.com/{repository}/pull/{number}"
    run.publishing_api_origin = publishing_api_origin
    store.save(run, event="test.published", details={})
    return run


def test_observer_records_immutable_snapshot_and_deduplicates_signals() -> None:
    pull_request = _pull_request(issue_comment_count=1)
    github = FakeLifecycleGitHub([pull_request, pull_request, pull_request, pull_request])
    github.reviews = [_review(10, state="CHANGES_REQUESTED")]
    github.issue_comments = [_comment(20, "Please close this PR and stop automated submissions.")]
    github.check_runs = [_check(30, "failure")]
    github.timeline_events = [
        PullRequestTimelineEvent(
            identifier=40,
            node_id="HRFPE_fixture_40",
            event="head_ref_force_pushed",
            actor="contributor",
            commit_sha="a" * 40,
            created_at=NOW,
        )
    ]
    github.timeline_item_count = 1
    store = FakeLifecycleStore()
    observer = LifecycleObserver(github, store)

    first = observer.observe(
        "run-1",
        repository="example/project",
        number=7,
        expected_head_sha="a" * 40,
        observed_at=NOW,
    )
    second = observer.observe(
        "run-1",
        repository="example/project",
        number=7,
        expected_head_sha="a" * 40,
        observed_at=NOW + timedelta(hours=1),
    )

    assert first.snapshot_recorded
    assert not second.snapshot_recorded
    assert first.snapshot.fingerprint() == second.snapshot.fingerprint()
    assert len(store.snapshots) == 1
    assert len(store.triggers) == 3
    assert len(first.newly_tripped) == 3
    assert second.newly_tripped == ()
    assert {signal.kind for signal in first.signals} == {
        LifecycleSignalKind.CHANGES_REQUESTED,
        LifecycleSignalKind.MAINTAINER_STOP,
        LifecycleSignalKind.CI_FAILED,
    }
    stored = json.loads(next(iter(store.snapshots.values())))
    assert "observed_at" not in stored
    assert stored["pull_request"]["number"] == 7
    assert stored["commits"][0]["sha"] == "a" * 40
    assert stored["timeline_events"][0]["event"] == "head_ref_force_pushed"


def test_lifecycle_snapshot_strict_parser_round_trips_complete_evidence() -> None:
    pull_request = _pull_request(
        state="closed",
        merged=True,
        merged_at=NOW,
        closed_at=NOW,
        merge_commit_sha="c" * 40,
        issue_comment_count=1,
        review_comment_count=1,
    )
    reference = PullRequestReference(
        identifier=60,
        node_id="CRE_fixture_60",
        source_url="https://github.com/example/project/pull/8",
        source_title="Revert the change",
        source_body="Reverts example/project#7",
        source_state="closed",
        source_merged_at=NOW,
        created_at=NOW,
    )
    snapshot = _snapshot(
        pull_request=pull_request,
        reviews=(_review(10, state="APPROVED"),),
        issue_comments=(_comment(20, "Looks good."),),
        review_comments=(_comment(21, "Resolved."),),
        checks=(_check(30, "success"),),
        statuses=(_status(40, "success"),),
        references=(reference,),
    )

    parsed = parse_lifecycle_snapshot_json(snapshot.to_json(), observed_at=NOW)

    assert parsed == snapshot
    assert parsed.fingerprint() == snapshot.fingerprint()


def test_lifecycle_snapshot_accepts_ordered_close_reopen_history() -> None:
    events = (
        PullRequestTimelineEvent(
            identifier=1,
            node_id="CE_fixture_1",
            event="closed",
            actor="maintainer",
            commit_sha=None,
            created_at=NOW,
        ),
        PullRequestTimelineEvent(
            identifier=2,
            node_id="RE_fixture_2",
            event="reopened",
            actor="maintainer",
            commit_sha=None,
            created_at=NOW + timedelta(minutes=1),
        ),
    )
    snapshot = _snapshot(timeline_events=events, timeline_item_count=2)

    parsed = parse_lifecycle_snapshot_json(snapshot.to_json(), observed_at=NOW)

    assert [event.event for event in parsed.timeline_events] == ["closed", "reopened"]
    assert parsed.pull_request.state == "open"


def test_lifecycle_snapshot_rejects_tampered_commit_chain() -> None:
    commits = (
        PullRequestCommit(
            position=1,
            sha="b" * 40,
            node_id="C_fixture_b",
            parent_shas=("c" * 40,),
        ),
        PullRequestCommit(
            position=2,
            sha="a" * 40,
            node_id="C_fixture_a",
            parent_shas=("b" * 40,),
        ),
    )
    snapshot = _snapshot(
        pull_request=_pull_request(commit_count=2),
        commits=commits,
    )
    payload = json.loads(snapshot.to_json())
    payload["commits"][1]["parent_shas"] = ["d" * 40]
    tampered = json.dumps(payload, sort_keys=True, separators=(",", ":"))

    with pytest.raises(ValueError, match="commit history is not contiguous"):
        parse_lifecycle_snapshot_json(tampered, observed_at=NOW)


def test_commit_and_timeline_history_mutations_change_snapshot_fingerprint() -> None:
    snapshot = _snapshot()
    changed_commit = replace(
        snapshot,
        commits=(replace(snapshot.commits[0], node_id="C_replaced_identity"),),
    )
    changed_history = replace(
        snapshot,
        timeline_item_count=1,
        timeline_events=(
            PullRequestTimelineEvent(
                identifier=1,
                node_id="HRFPE_fixture_1",
                event="head_ref_force_pushed",
                actor="contributor",
                commit_sha="a" * 40,
                created_at=NOW,
            ),
        ),
    )
    changed_unretained_history = replace(snapshot, timeline_item_count=1)

    assert (
        len(
            {
                snapshot.fingerprint(),
                changed_commit.fingerprint(),
                changed_history.fingerprint(),
                changed_unretained_history.fingerprint(),
            }
        )
        == 4
    )


def test_classifier_ignores_untrusted_stop_text_and_superseded_ci_failures() -> None:
    snapshot = _snapshot(
        reviews=(
            _review(40, state="CHANGES_REQUESTED"),
            replace(
                _review(41, state="APPROVED"),
                submitted_at=NOW + timedelta(minutes=1),
            ),
        ),
        issue_comments=(
            _comment(1, "Close this PR and stop automation.", association="NONE"),
            _comment(
                2,
                "Close this PR and stop automation.",
                author="maintainer-bot[bot]",
            ),
            _comment(3, "Do not stop work; this is still wanted."),
        ),
        checks=(
            _check(10, "failure", completed_at=NOW - timedelta(minutes=2)),
            _check(11, "success", completed_at=NOW),
        ),
        statuses=(
            _status(20, "failure", updated_at=NOW - timedelta(minutes=2)),
            _status(21, "success", updated_at=NOW),
        ),
    )

    assert classify_lifecycle(snapshot) == ()


@pytest.mark.parametrize(
    "body",
    [
        "Do not stop the tests; please close this PR.",
        "Don't stop CI, but withdraw this contribution.",
        "Never stop checking regressions; stop automated submissions.",
    ],
)
def test_classifier_preserves_stop_requests_after_an_unrelated_negated_directive(
    body: str,
) -> None:
    signals = classify_lifecycle(_snapshot(issue_comments=(_comment(1, body),)))

    assert [signal.kind for signal in signals] == [LifecycleSignalKind.MAINTAINER_STOP]


@pytest.mark.parametrize(
    "body",
    [
        "Do not stop work; this is still wanted.",
        "Please do not close this PR.",
        "Never withdraw this contribution.",
    ],
)
def test_classifier_ignores_negated_stop_directives(body: str) -> None:
    assert classify_lifecycle(_snapshot(issue_comments=(_comment(1, body),))) == ()


def test_classifier_detects_head_drift_and_closed_unmerged() -> None:
    pull_request = _pull_request(
        state="closed",
        closed_at=NOW,
        head_sha="b" * 40,
    )

    signals = classify_lifecycle(_snapshot(pull_request=pull_request))

    assert {signal.kind for signal in signals} == {
        LifecycleSignalKind.HEAD_DRIFT,
        LifecycleSignalKind.CLOSED_UNMERGED,
    }


def test_edited_stop_evidence_produces_a_new_trigger_hash() -> None:
    original = _comment(1, "Stop this automated contribution.")
    edited = replace(
        original,
        body="Stop this PR and all automated work.",
        updated_at=NOW + timedelta(minutes=1),
    )

    original_signal = classify_lifecycle(_snapshot(issue_comments=(original,)))[0]
    edited_signal = classify_lifecycle(_snapshot(issue_comments=(edited,)))[0]

    assert original_signal.evidence_key != edited_signal.evidence_key
    assert original_signal.trigger_hash() != edited_signal.trigger_hash()


def test_edited_stop_evidence_retrips_breaker_after_operator_resume(tmp_path) -> None:  # type: ignore[no-untyped-def]
    store = RunStore(tmp_path / "state")
    run = store.create_run()
    pull_request = _pull_request(issue_comment_count=1)
    github = FakeLifecycleGitHub([pull_request, pull_request])
    original = _comment(1, "Stop this automated contribution.")
    github.issue_comments = [original]
    observer = LifecycleObserver(github, store)

    first = observer.observe(
        run.run_id,
        repository="example/project",
        number=7,
        expected_head_sha="a" * 40,
    )
    assert len(first.newly_tripped) == 1
    first_status = store.circuit_breaker_status()
    assert first_status.active_revision is not None
    assert store.resume_circuit_breaker(
        actor="operator",
        reason="reviewed original request",
        expected_trigger_hash=first_status.active_revision,
    )

    unchanged = observer.observe(
        run.run_id,
        repository="example/project",
        number=7,
        expected_head_sha="a" * 40,
    )
    assert unchanged.newly_tripped == ()
    assert not store.circuit_breaker_status().is_tripped

    github.issue_comments = [
        replace(
            original,
            body="Stop this PR and all automated work.",
            updated_at=NOW + timedelta(minutes=1),
        )
    ]
    edited = observer.observe(
        run.run_id,
        repository="example/project",
        number=7,
        expected_head_sha="a" * 40,
    )

    assert len(edited.newly_tripped) == 1
    assert edited.newly_tripped != first.newly_tripped
    assert store.circuit_breaker_status().is_tripped


def test_revert_requires_merged_source_and_explicit_target() -> None:
    pull_request = _pull_request(
        state="closed",
        merged=True,
        merged_at=NOW,
        closed_at=NOW,
        merge_commit_sha="b" * 40,
    )
    explicit = PullRequestReference(
        identifier=1,
        node_id="CRE_fixture_1",
        source_url="https://github.com/example/project/pull/8",
        source_title="Revert parser fix",
        source_body="Reverts example/project#7",
        source_state="closed",
        source_merged_at=NOW + timedelta(hours=1),
        created_at=NOW + timedelta(minutes=30),
    )
    unmerged = replace(explicit, identifier=2, source_merged_at=None)
    vague = replace(
        explicit,
        identifier=3,
        source_body="Back out a recent parser change without linking a contribution.",
    )
    premature = replace(
        explicit,
        identifier=4,
        source_merged_at=NOW - timedelta(minutes=1),
    )

    signals = classify_lifecycle(
        _snapshot(
            pull_request=pull_request,
            references=(explicit, unmerged, vague, premature),
        )
    )

    assert [signal.kind for signal in signals] == [LifecycleSignalKind.REVERTED]
    assert signals[0].source_url.endswith("/pull/8")


def test_observer_rejects_top_level_race_before_persisting() -> None:
    first = _pull_request()
    changed = replace(first, updated_at=NOW + timedelta(seconds=1))
    github = FakeLifecycleGitHub([first, changed])
    store = FakeLifecycleStore()

    with pytest.raises(GitHubError, match="changed while lifecycle evidence"):
        LifecycleObserver(github, store).observe(
            "run-1",
            repository="example/project",
            number=7,
            expected_head_sha="a" * 40,
        )

    assert store.snapshots == {}
    assert store.triggers == {}


def test_observer_fences_takeover_after_remote_observation(tmp_path) -> None:  # type: ignore[no-untyped-def]
    store = RunStore(tmp_path / "state")
    run = store.create_run()
    pull_request = _pull_request(issue_comment_count=1)

    class TakeoverGitHub(FakeLifecycleGitHub):
        def get_pull_request(self, repository: str, number: int) -> PullRequestDetails:
            result = super().get_pull_request(repository, number)
            if self.get_calls == 2:
                lease = store.get_lease("autocontribute.lifecycle")
                assert lease is not None
                takeover = store.acquire_lease(
                    "autocontribute.lifecycle",
                    "replacement-worker",
                    ttl=timedelta(minutes=5),
                    now=lease.expires_at,
                )
                assert takeover is not None
            return result

    github = TakeoverGitHub([pull_request, pull_request])
    github.issue_comments = [_comment(20, "Stop this automated contribution.")]
    guard = LeaseHeartbeatGuard(
        store,
        "autocontribute.lifecycle",
        owner="stale-worker",
        ttl=timedelta(minutes=5),
        heartbeat_interval=timedelta(minutes=1),
    )

    with pytest.raises(StateError, match="no longer owned"), guard:
        LifecycleObserver(
            github,
            store,
            assert_owned=guard.assert_owned,
        ).observe(
            run.run_id,
            repository="example/project",
            number=7,
            expected_head_sha="a" * 40,
        )

    assert store.lifecycle_snapshots(run.run_id) == []
    assert not store.circuit_breaker_status().is_tripped


@pytest.mark.parametrize(
    "value",
    [
        "http://github.com/example/project/pull/7",
        "https://github.com/example/project/issues/7",
        "https://github.com/example/project/pull/7?diff=split",
        "https://github.com/example/project/pull/07",
        "https://evil.invalid/example/project/pull/7",
    ],
)
def test_pull_request_url_parser_rejects_noncanonical_targets(value: str) -> None:
    with pytest.raises(StateError, match="non-canonical"):
        parse_pull_request_url(value, api_origin="https://api.github.com")

    assert parse_pull_request_url(
        "https://github.com/example/project/pull/7",
        api_origin="https://api.github.com",
    ) == ("example/project", 7)


def test_pull_request_url_parser_binds_ghes_origin_and_custom_port() -> None:
    url = "https://git.example.com:8443/example/project/pull/7"

    assert parse_pull_request_url(
        url,
        api_origin="https://git.example.com:8443",
    ) == ("example/project", 7)

    with pytest.raises(StateError, match="non-canonical"):
        parse_pull_request_url(url, api_origin="https://git.example.com")


def test_lifecycle_sync_observes_every_published_run_and_deduplicates_snapshots(
    tmp_path,
) -> None:  # type: ignore[no-untyped-def]
    store = RunStore(tmp_path / "state")
    run = _published_run(store)
    github = FakeLifecycleGitHub()

    first = sync_open_pull_requests(github, store)
    second = sync_open_pull_requests(github, store)

    assert first.runs_checked == 1
    assert first.snapshots_recorded == 1
    assert first.signals_detected == 0
    assert first.newly_tripped == 0
    assert second.snapshots_recorded == 0
    assert len(store.lifecycle_snapshots(run.run_id)) == 1
    assert not store.circuit_breaker_status().is_tripped


def test_lifecycle_sync_observes_ghes_pull_request_bound_to_durable_origin(tmp_path) -> None:
    store = RunStore(tmp_path / "state")
    api_origin = "https://git.example.com:8443"
    pull_request_url = "https://git.example.com:8443/example/project/pull/7"
    _published_run(
        store,
        pull_request_url=pull_request_url,
        publishing_api_origin=api_origin,
    )
    pull_request = _pull_request(html_url=pull_request_url)
    github = FakeLifecycleGitHub(
        [pull_request, pull_request],
        api_origin=api_origin,
    )

    result = sync_open_pull_requests(github, store)

    assert result.runs_checked == 1
    assert github.get_calls == 2


@pytest.mark.parametrize("stored_origin", [None, "https://other.example.com"])
def test_lifecycle_sync_rejects_missing_or_drifted_publishing_origin_before_reads(
    tmp_path,
    stored_origin: str | None,
) -> None:  # type: ignore[no-untyped-def]
    store = RunStore(tmp_path / "state")
    run = _published_run(store)
    run.publishing_api_origin = stored_origin
    store.save(run, event="test.origin_drift", details={})
    github = FakeLifecycleGitHub()

    with pytest.raises(StateError, match=r"publishing API origin|different GitHub API origin"):
        sync_open_pull_requests(github, store)

    assert github.get_calls == 0


def test_lifecycle_sync_validates_complete_target_set_before_github_reads(tmp_path) -> None:  # type: ignore[no-untyped-def]
    store = RunStore(tmp_path / "state")
    _published_run(store)
    _published_run(
        store,
        repository="example/other",
        number=8,
        commit_sha="not-a-commit-sha",
    )
    github = FakeLifecycleGitHub()

    with pytest.raises(StateError, match="canonical contribution commit SHA"):
        sync_open_pull_requests(github, store)

    assert github.get_calls == 0
    assert store.lifecycle_snapshots(store.list_open_pull_request_runs()[0].run_id) == []
