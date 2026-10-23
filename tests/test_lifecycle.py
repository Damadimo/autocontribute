from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from autocontribute.coordination import LeaseHeartbeatGuard
from autocontribute.domain import IssueCandidate, RepositoryInfo, RunManifest, RunStatus
from autocontribute.exceptions import (
    CircuitBreakerTrigger,
    GitHubError,
    GitHubRateLimitError,
    GitHubSafetyError,
    StateError,
    StopScope,
)
from autocontribute.github import (
    CheckRunDetails,
    CommitComparison,
    CommitStatusDetails,
    GitHubComment,
    PullRequestDetails,
    PullRequestReference,
    PullRequestReview,
)
from autocontribute.lifecycle import (
    REPOSITORY_COOLDOWN,
    LifecycleObserver,
    LifecycleSignalKind,
    PullRequestLifecycleSnapshot,
    classify_lifecycle,
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


def _check(identifier: int, conclusion: str | None) -> CheckRunDetails:
    return CheckRunDetails(
        identifier=identifier,
        name="unit",
        status="completed" if conclusion else "in_progress",
        conclusion=conclusion,
        details_url=f"https://ci.example.invalid/check/{identifier}",
        app_name="github-actions",
        started_at=NOW - timedelta(minutes=5),
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
        target_url=f"https://ci.example.invalid/status/{identifier}",
        created_at=updated_at,
        updated_at=updated_at,
    )


def _snapshot(
    *,
    pull_request: PullRequestDetails | None = None,
    expected_head_sha: str = "a" * 40,
    reviews: tuple[PullRequestReview, ...] = (),
    issue_comments: tuple[GitHubComment, ...] = (),
    review_comments: tuple[GitHubComment, ...] = (),
    checks: tuple[CheckRunDetails, ...] = (),
    statuses: tuple[CommitStatusDetails, ...] = (),
    references: tuple[PullRequestReference, ...] = (),
    publishing_login: str | None = "octocat",
    head_comparison: CommitComparison | None = None,
) -> PullRequestLifecycleSnapshot:
    return PullRequestLifecycleSnapshot(
        expected_head_sha=expected_head_sha,
        pull_request=pull_request or _pull_request(),
        reviews=reviews,
        issue_comments=issue_comments,
        review_comments=review_comments,
        check_runs=checks,
        commit_statuses=statuses,
        references=references,
        publishing_login=publishing_login,
        head_comparison=head_comparison,
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
        self.comparison: CommitComparison | None = None
        self.get_calls = 0
        self.reference_calls = 0
        self.compare_calls = 0

    def get_pull_request(self, repository: str, number: int) -> PullRequestDetails:
        value = self.pull_requests[min(self.get_calls, len(self.pull_requests) - 1)]
        self.get_calls += 1
        return value

    def list_pull_request_reviews(
        self, repository: str, number: int, *, max_reviews: int = 500
    ) -> list[PullRequestReview]:
        return self.reviews

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

    def list_pull_request_references(
        self, repository: str, number: int, *, max_events: int = 1_000
    ) -> list[PullRequestReference]:
        self.reference_calls += 1
        return self.references

    def compare_commits(self, repository: str, base: str, head: str) -> CommitComparison | None:
        self.compare_calls += 1
        return self.comparison


class FakeLifecycleStore:
    def __init__(self) -> None:
        self.triggers: dict[str, CircuitBreakerTrigger] = {}

    def record_stop(self, trigger: CircuitBreakerTrigger) -> bool:
        if trigger.trigger_hash in self.triggers:
            return False
        self.triggers[trigger.trigger_hash] = trigger
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
    store.transition(run, RunStatus.DISCOVERING, reason="fixture started")
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
    run.publishing_login = "octocat"
    lease_owner = f"lifecycle-fixture-{run.run_id}"
    lease = store.acquire_lease(
        "autocontribute.run",
        lease_owner,
        ttl=timedelta(minutes=1),
    )
    assert lease is not None
    store.claim_candidate(run, lease=lease)
    assert store.release_lease("autocontribute.run", lease_owner, lease.generation)
    run.status = RunStatus.PR_OPEN
    store.save(run, event="test.published", details={})
    return run


def test_observer_records_attention_and_each_stop_once_across_observations() -> None:
    pull_request = _pull_request(issue_comment_count=1)
    github = FakeLifecycleGitHub([pull_request, pull_request, pull_request, pull_request])
    github.reviews = [_review(10, state="CHANGES_REQUESTED")]
    github.issue_comments = [_comment(20, "Please close this PR and stop automated submissions.")]
    github.check_runs = [_check(30, "failure")]
    store = FakeLifecycleStore()
    observer = LifecycleObserver(github, store)

    first = observer.observe(
        repository="example/project",
        number=7,
        expected_head_sha="a" * 40,
        publishing_login="octocat",
    )
    second = observer.observe(
        repository="example/project",
        number=7,
        expected_head_sha="a" * 40,
        publishing_login="octocat",
    )

    assert first.snapshot == second.snapshot
    assert {signal.kind for signal in first.signals} == {
        LifecycleSignalKind.CHANGES_REQUESTED,
        LifecycleSignalKind.AUTOMATION_STOP,
        LifecycleSignalKind.CI_FAILED,
    }
    assert [item.kind for item in first.attention] == ["changes_requested", "ci_failed"]
    assert first.attention == tuple(
        item.model_copy(update={"observed_at": first.attention[0].observed_at})
        for item in second.attention
    )
    (hold,) = store.triggers.values()
    assert (hold.scope, hold.scope_key, hold.maintainer_stop) == (
        StopScope.REPOSITORY,
        "example/project",
        True,
    )
    assert hold.expires_at is None
    assert first.newly_recorded == (hold.trigger_hash,)
    assert second.newly_recorded == ()
    assert github.compare_calls == 0


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
            _check(10, "failure"),
            _check(11, "success"),
        ),
        statuses=(
            _status(20, "failure", updated_at=NOW - timedelta(minutes=2)),
            _status(21, "success", updated_at=NOW),
        ),
    )

    assert classify_lifecycle(snapshot) == ()


@pytest.mark.parametrize(
    ("body", "kind"),
    [
        ("Do not stop the tests; please close this PR.", LifecycleSignalKind.MAINTAINER_STOP),
        ("Don't stop CI, but withdraw this contribution.", LifecycleSignalKind.MAINTAINER_STOP),
        (
            "Never stop checking regressions; stop automated submissions.",
            LifecycleSignalKind.AUTOMATION_STOP,
        ),
    ],
)
def test_classifier_preserves_stop_requests_after_an_unrelated_negated_directive(
    body: str, kind: LifecycleSignalKind
) -> None:
    signals = classify_lifecycle(_snapshot(issue_comments=(_comment(1, body),)))

    assert [signal.kind for signal in signals] == [kind]


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


@pytest.mark.parametrize(
    "body",
    [
        "Don't change this file; the PR should only touch the parser",
        "Please don't add a new dependency in this PR",
        "Do not merge this PR until CI is green",
        "Stop the work loop when the flag is set",
        "Don't worry, I think this will work.",
        "I don't think this PR needs a changelog entry.",
        "Don't forget to add a test to this PR.",
        "Thanks! Let's stop here and merge this PR.",
        "Could you rebase? I don't see the fix in the PR yet.",
        "We do not accept PRs without a linked issue.",
    ],
)
def test_review_chatter_that_names_a_pull_request_is_not_a_stop(body: str) -> None:
    assert classify_lifecycle(_snapshot(issue_comments=(_comment(1, body),))) == ()


@pytest.mark.parametrize(
    ("body", "kind"),
    [
        ("Please close this PR.", LifecycleSignalKind.MAINTAINER_STOP),
        ("Stop this PR and all automated work.", LifecycleSignalKind.MAINTAINER_STOP),
        ("No PR is needed here.", LifecycleSignalKind.MAINTAINER_STOP),
        ("Stop this automated contribution.", LifecycleSignalKind.AUTOMATION_STOP),
        ("We don\u2019t accept AI-generated changes.", LifecycleSignalKind.AUTOMATION_STOP),
        ("Bot pull requests will be closed.", LifecycleSignalKind.AUTOMATION_STOP),
        ("Please don't open LLM-generated PRs here.", LifecycleSignalKind.AUTOMATION_STOP),
        ("We are not accepting outside contributions.", LifecycleSignalKind.AUTOMATION_STOP),
    ],
)
def test_stop_text_is_aimed_at_this_pull_request_or_at_automation(
    body: str, kind: LifecycleSignalKind
) -> None:
    signals = classify_lifecycle(_snapshot(reviews=(_review(1, body=body),)))

    assert [signal.kind for signal in signals] == [kind]


@pytest.mark.parametrize(
    ("conclusion", "kinds"),
    [
        ("failure", [LifecycleSignalKind.CI_FAILED]),
        ("timed_out", [LifecycleSignalKind.CI_FAILED]),
        ("startup_failure", [LifecycleSignalKind.CI_FAILED]),
        ("action_required", []),
        ("cancelled", []),
        ("neutral", []),
        ("skipped", []),
        ("stale", []),
    ],
)
def test_only_checks_that_failed_on_the_patch_need_attention(
    conclusion: str, kinds: list[LifecycleSignalKind]
) -> None:
    signals = classify_lifecycle(_snapshot(checks=(_check(10, conclusion),)))

    assert [signal.kind for signal in signals] == kinds


def _moved_head(**changes: object) -> PullRequestLifecycleSnapshot:
    values: dict[str, object] = {
        "pull_request": _pull_request(head_sha="b" * 40),
        "head_comparison": CommitComparison(
            status="ahead",
            total_commits=2,
            author_logins=("maintainer", "pre-commit-ci[bot]"),
        ),
    }
    values.update(changes)
    return _snapshot(**values)  # type: ignore[arg-type]


def test_commits_added_by_other_accounts_only_need_attention() -> None:
    (signal,) = classify_lifecycle(_moved_head())

    assert signal.kind == LifecycleSignalKind.MAINTAINER_PUSH
    assert signal.attention(NOW) is not None
    assert signal.stops(api_origin="https://api.github.com", observed_at=NOW) == ()


@pytest.mark.parametrize(
    "changes",
    [
        {"head_comparison": None},
        {"publishing_login": None},
        {
            "head_comparison": CommitComparison(
                status="diverged", total_commits=1, author_logins=("maintainer",)
            )
        },
        {
            "head_comparison": CommitComparison(
                status="ahead", total_commits=1, author_logins=(None,)
            )
        },
        {
            "head_comparison": CommitComparison(
                status="ahead", total_commits=2, author_logins=("maintainer", "OctoCat")
            )
        },
        {
            "head_comparison": CommitComparison(
                status="ahead", total_commits=300, author_logins=("maintainer",)
            )
        },
    ],
)
def test_head_drift_from_an_unknown_pusher_stays_a_global_stop(changes: dict[str, object]) -> None:
    (signal,) = classify_lifecycle(_moved_head(**changes))

    assert signal.kind == LifecycleSignalKind.HEAD_DRIFT
    assert signal.attention(NOW) is None
    (stop,) = signal.stops(api_origin="https://api.github.com", observed_at=NOW)
    assert stop.scope == StopScope.GLOBAL
    assert stop.trigger_hash == signal.trigger_hash()


def test_observer_compares_commits_only_when_the_head_moved() -> None:
    moved = _pull_request(head_sha="b" * 40)
    github = FakeLifecycleGitHub([moved, moved])
    github.comparison = CommitComparison(
        status="ahead", total_commits=1, author_logins=("maintainer",)
    )
    store = FakeLifecycleStore()

    observation = LifecycleObserver(github, store).observe(
        repository="example/project",
        number=7,
        expected_head_sha="a" * 40,
        publishing_login="octocat",
    )

    assert github.compare_calls == 1
    assert [item.kind for item in observation.attention] == ["maintainer_push"]
    assert store.triggers == {}


def test_signals_record_stops_at_their_scope(tmp_path) -> None:  # type: ignore[no-untyped-def]
    store = RunStore(tmp_path / "state")
    closed = _pull_request(state="closed", closed_at=NOW, issue_comment_count=1)
    github = FakeLifecycleGitHub([closed, closed])
    github.issue_comments = [_comment(1, "Please close this PR; it duplicates #6.")]

    observation = LifecycleObserver(github, store).observe(
        repository="example/project",
        number=7,
        expected_head_sha="a" * 40,
        publishing_login="octocat",
    )

    assert observation.snapshot.pull_request_state == "closed"
    assert len(observation.newly_recorded) == 3
    assert not store.circuit_breaker_status().is_tripped
    holds = {(hold.scope, hold.source.rsplit(":", 1)[1]): hold for hold in store.active_holds()}
    assert set(holds) == {
        (StopScope.PULL_REQUEST, "maintainer_stop"),
        (StopScope.REPOSITORY, "maintainer_stop"),
        (StopScope.REPOSITORY, "closed_unmerged"),
    }
    assert holds[(StopScope.PULL_REQUEST, "maintainer_stop")].scope_key == closed.html_url
    assert holds[(StopScope.PULL_REQUEST, "maintainer_stop")].expires_at is None
    for kind in ("maintainer_stop", "closed_unmerged"):
        hold = holds[(StopScope.REPOSITORY, kind)]
        assert hold.scope_key == "example/project"
        assert hold.expires_at is not None
        assert hold.expires_at - hold.created_at == pytest.approx(
            REPOSITORY_COOLDOWN, abs=timedelta(seconds=5)
        )
    assert store.active_holds(now=datetime.now(UTC) + REPOSITORY_COOLDOWN + timedelta(minutes=1))


def test_revert_holds_the_repository_and_all_publication(tmp_path) -> None:  # type: ignore[no-untyped-def]
    store = RunStore(tmp_path / "state")
    merged = _pull_request(
        state="closed",
        merged=True,
        merged_at=NOW,
        closed_at=NOW,
        merge_commit_sha="b" * 40,
    )
    github = FakeLifecycleGitHub([merged, merged])
    github.references = [
        PullRequestReference(
            identifier=1,
            source_url="https://github.com/example/project/pull/8",
            source_title="Revert parser fix",
            source_body="Reverts example/project#7",
            source_state="closed",
            source_merged_at=NOW + timedelta(hours=1),
            created_at=NOW + timedelta(minutes=30),
        )
    ]

    LifecycleObserver(github, store).observe(
        repository="example/project",
        number=7,
        expected_head_sha="a" * 40,
        publishing_login="octocat",
    )

    assert {(hold.scope, hold.scope_key) for hold in store.active_holds()} == {
        (StopScope.REPOSITORY, "example/project"),
        (StopScope.PUBLICATION, "https://api.github.com"),
    }
    assert not store.circuit_breaker_status().is_tripped


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


def test_edited_stop_evidence_returns_a_released_hold(tmp_path) -> None:  # type: ignore[no-untyped-def]
    store = RunStore(tmp_path / "state")
    pull_request = _pull_request(issue_comment_count=1)
    github = FakeLifecycleGitHub([pull_request, pull_request])
    original = _comment(1, "Stop this automated contribution.")
    github.issue_comments = [original]
    observer = LifecycleObserver(github, store)

    first = observer.observe(
        repository="example/project",
        number=7,
        expected_head_sha="a" * 40,
        publishing_login="octocat",
    )
    assert len(first.newly_recorded) == 1
    (hold,) = store.active_holds()
    assert store.release_hold(hold.hold_id, actor="operator", reason="reviewed original request")

    unchanged = observer.observe(
        repository="example/project",
        number=7,
        expected_head_sha="a" * 40,
        publishing_login="octocat",
    )
    assert unchanged.newly_recorded == ()
    assert store.active_holds() == []

    github.issue_comments = [
        replace(
            original,
            body="Stop all automated work on this project.",
            updated_at=NOW + timedelta(minutes=1),
        )
    ]
    edited = observer.observe(
        repository="example/project",
        number=7,
        expected_head_sha="a" * 40,
        publishing_login="octocat",
    )

    assert len(edited.newly_recorded) == 1
    assert edited.newly_recorded != first.newly_recorded
    assert [item.scope for item in store.active_holds()] == [StopScope.REPOSITORY]
    assert not store.circuit_breaker_status().is_tripped


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


def test_observer_reads_revert_references_only_for_merged_pull_requests() -> None:
    merged = _pull_request(
        state="closed",
        merged=True,
        merged_at=NOW,
        closed_at=NOW,
        merge_commit_sha="b" * 40,
    )
    revert = PullRequestReference(
        identifier=1,
        source_url="https://github.com/example/project/pull/8",
        source_title="Revert parser fix",
        source_body="Reverts example/project#7",
        source_state="closed",
        source_merged_at=NOW + timedelta(hours=1),
        created_at=NOW + timedelta(minutes=30),
    )
    open_github = FakeLifecycleGitHub()
    open_github.references = [revert]
    merged_github = FakeLifecycleGitHub([merged, merged])
    merged_github.references = [revert]

    opened = LifecycleObserver(open_github, FakeLifecycleStore()).observe(
        repository="example/project",
        number=7,
        expected_head_sha="a" * 40,
        publishing_login="octocat",
    )
    reverted = LifecycleObserver(merged_github, FakeLifecycleStore()).observe(
        repository="example/project",
        number=7,
        expected_head_sha="a" * 40,
        publishing_login="octocat",
    )

    assert open_github.reference_calls == 0
    assert opened.snapshot.references == ()
    assert merged_github.reference_calls == 1
    assert [signal.kind for signal in reverted.signals] == [LifecycleSignalKind.REVERTED]


def test_observer_rejects_top_level_race_before_tripping() -> None:
    first = _pull_request()
    changed = replace(first, updated_at=NOW + timedelta(seconds=1))
    github = FakeLifecycleGitHub([first, changed])
    store = FakeLifecycleStore()

    with pytest.raises(GitHubError, match="changed while lifecycle evidence"):
        LifecycleObserver(github, store).observe(
            repository="example/project",
            number=7,
            expected_head_sha="a" * 40,
            publishing_login="octocat",
        )

    assert store.triggers == {}


def test_observer_fences_takeover_after_remote_observation(tmp_path) -> None:  # type: ignore[no-untyped-def]
    store = RunStore(tmp_path / "state")
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
            repository="example/project",
            number=7,
            expected_head_sha="a" * 40,
            publishing_login="octocat",
        )

    assert not store.circuit_breaker_status().is_tripped
    assert store.active_holds() == []


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


def test_lifecycle_sync_observes_every_published_run(tmp_path) -> None:  # type: ignore[no-untyped-def]
    store = RunStore(tmp_path / "state")
    _published_run(store)
    github = FakeLifecycleGitHub()

    result = sync_open_pull_requests(github, store)

    assert result.runs_checked == 1
    assert result.signals_detected == 0
    assert result.newly_recorded == 0
    assert result.failures == ()
    assert github.get_calls == 2
    assert not store.circuit_breaker_status().is_tripped


def test_lifecycle_sync_keeps_attention_on_the_run_and_stops_after_close(tmp_path) -> None:  # type: ignore[no-untyped-def]
    store = RunStore(tmp_path / "state")
    run = _published_run(store)
    github = FakeLifecycleGitHub([_pull_request()] * 4)
    github.reviews = [_review(10, state="CHANGES_REQUESTED")]
    github.check_runs = [_check(30, "failure"), replace(_check(31, "cancelled"), name="lint")]

    first = sync_open_pull_requests(github, store)
    events_after_first = len(store.events(run.run_id))
    second = sync_open_pull_requests(github, store)

    observed = store.get(run.run_id)
    assert (first.signals_detected, second.signals_detected) == (2, 2)
    assert observed.pull_request_state == "open"
    assert [item.kind for item in observed.pull_request_attention] == [
        "changes_requested",
        "ci_failed",
    ]
    assert len(store.events(run.run_id)) == events_after_first
    assert store.events(run.run_id)[-1]["event_type"] == "lifecycle.observed"
    assert not store.circuit_breaker_status().is_tripped
    assert store.active_holds() == []

    closed = _pull_request(state="closed", closed_at=NOW)
    github.pull_requests = [closed] * 2
    github.get_calls = 0
    github.reviews = []
    github.check_runs = []
    sync_open_pull_requests(github, store)

    assert store.get(run.run_id).pull_request_state == "closed"
    assert store.get(run.run_id).status == RunStatus.PR_OPEN
    assert [hold.scope_key for hold in store.active_holds()] == ["example/project"]
    assert store.list_open_pull_request_runs() == []
    assert sync_open_pull_requests(github, store).runs_checked == 0
    assert github.get_calls == 2


class PartlyUnreadableGitHub(FakeLifecycleGitHub):
    """Serves each requested pull request but cannot read checks in one repository."""

    def __init__(self, unreadable: str, error: type[GitHubError] = GitHubError) -> None:
        super().__init__()
        self.unreadable = unreadable
        self.error = error
        self.attempts = 0

    def get_pull_request(self, repository: str, number: int) -> PullRequestDetails:
        self.get_calls += 1
        return _pull_request(
            repository=repository,
            number=number,
            html_url=f"https://github.com/{repository}/pull/{number}",
        )

    def list_check_runs(
        self, repository: str, ref: str, *, max_check_runs: int = 500
    ) -> list[CheckRunDetails]:
        if repository != self.unreadable:
            return []
        self.attempts += 1
        message = (
            f"GitHub returned 403 for GET /repos/{repository}/commits/{ref}/check-runs "
            f"(request ABCD:{self.attempts}): Resource not accessible by personal access token"
        )
        if self.error is GitHubSafetyError:
            raise GitHubSafetyError(
                message,
                trigger=CircuitBreakerTrigger(source="fixture", reason="fixture", trigger_hash="x"),
            )
        raise self.error(message)


def test_one_unreadable_pull_request_does_not_stop_lifecycle_sync(tmp_path) -> None:  # type: ignore[no-untyped-def]
    store = RunStore(tmp_path / "state")
    broken = _published_run(store, repository="example/broken", number=3)
    healthy = _published_run(store, repository="example/healthy", number=4)
    github = PartlyUnreadableGitHub("example/broken")

    first = sync_open_pull_requests(github, store)
    second = sync_open_pull_requests(github, store)

    assert first.runs_checked == 2
    assert [observation.snapshot.pull_request.number for observation in first.observations] == [4]
    (failure,) = first.failures
    assert failure.run_id == broken.run_id
    assert failure.pull_request_url == "https://github.com/example/broken/pull/3"
    assert "Resource not accessible" in failure.error
    assert len(second.failures) == 1
    (attention,) = store.get(broken.run_id).pull_request_attention
    assert attention.kind == "observation_failed"
    assert "request ABCD" not in attention.reason
    assert store.get(broken.run_id).pull_request_state is None
    assert store.get(healthy.run_id).pull_request_state == "open"
    assert not store.circuit_breaker_status().is_tripped


@pytest.mark.parametrize("error", [GitHubSafetyError, GitHubRateLimitError])
def test_lifecycle_sync_still_ends_on_a_safety_stop_or_rate_limit(
    tmp_path, error: type[GitHubError]
) -> None:  # type: ignore[no-untyped-def]
    store = RunStore(tmp_path / "state")
    broken = _published_run(store, repository="example/broken", number=3)
    github = PartlyUnreadableGitHub("example/broken", error)

    with pytest.raises(error):
        sync_open_pull_requests(github, store)

    assert store.get(broken.run_id).pull_request_attention == []


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
