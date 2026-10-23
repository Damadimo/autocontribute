"""Read-only pull-request observation and deterministic, scoped safety signals."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Final, Literal, Protocol
from urllib.parse import urlparse

from autocontribute.domain import (
    PullRequestAttention,
    PullRequestAttentionKind,
    RunManifest,
    RunStatus,
    utc_now,
)
from autocontribute.exceptions import (
    CircuitBreakerTrigger,
    ConfigurationError,
    GitHubError,
    GitHubRateLimitError,
    GitHubSafetyError,
    StateError,
    StopScope,
)
from autocontribute.github import (
    BranchPush,
    CheckRunDetails,
    CommitStatusDetails,
    GitHubComment,
    PullRequestDetails,
    PullRequestReference,
    PullRequestReview,
)
from autocontribute.github_origin import canonical_api_origin, web_origin_for_api
from autocontribute.stop_text import AUTOMATION_STOP

_MAINTAINER_ASSOCIATIONS = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})
# Action-required, cancelled, neutral, skipped and stale runs say nothing about the patch: they
# wait for a human, were superseded, or did not apply.
_FAILING_CHECK_CONCLUSIONS = frozenset({"failure", "startup_failure", "timed_out"})
_FAILING_COMMIT_STATES = frozenset({"error", "failure"})
# On this tool's own pull request, a project that stops taking contributions turns it away too.
_NOT_ACCEPTING = re.compile(
    r"\b(?:not|no\s+longer)\s+accepting\s+(?:any\s+)?(?:new\s+|outside\s+|external\s+)?"
    r"(?:pull\s+requests|prs|contributions|submissions)\b",
    re.IGNORECASE,
)
_PULL_REQUEST_STOP = re.compile(
    r"\b(?:close|withdraw|abandon)\s+(?:(?:this|your|the)\s+)?"
    r"(?:pull\s+request|pr|contribution|patch)\b"
    r"|\bstop\s+(?:this|your)\s+(?:pull\s+request|pr|contribution|work)\b"
    r"|\bno\s+(?:pull\s+request|pr|contribution)\s+(?:is\s+)?needed\b",
    re.IGNORECASE,
)
_NEGATED_STOP_DIRECTIVE = re.compile(
    r"\b(?:do\s+not|don't|never)\s+"
    r"(?:stop|cease|pause|hold\s+off|close|withdraw)\b",
    re.IGNORECASE,
)
_PULL_REQUEST_PATH: Final = re.compile(r"/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/pull/([1-9][0-9]*)")
_COMMIT_SHA: Final = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})")
# Request IDs differ on every attempt; without them a failure that repeats is recorded once.
_REQUEST_ID: Final = re.compile(r"\s*\(request [^)]*\)")
MAX_LIFECYCLE_RUNS: Final = 1_000
REPOSITORY_COOLDOWN: Final = timedelta(days=30)
# A merged pull request is watched this long for a merged revert.
REVERT_WATCH: Final = timedelta(days=30)


class LifecycleStore(Protocol):
    """The narrow durable interface needed by lifecycle observation."""

    def record_stop(self, trigger: CircuitBreakerTrigger) -> bool: ...


class LifecycleRunStore(LifecycleStore, Protocol):
    """Durable run enumeration plus the observer's append-only write surface."""

    def list_open_pull_request_runs(
        self, *, limit: int = MAX_LIFECYCLE_RUNS
    ) -> list[RunManifest]: ...

    def list_merged_pull_request_runs(
        self, *, merged_since: datetime, limit: int = MAX_LIFECYCLE_RUNS
    ) -> list[RunManifest]: ...

    def save(self, manifest: RunManifest, *, event: str, details: dict[str, str]) -> None: ...


class LifecycleGitHub(Protocol):
    """Read-only GitHub surface used by the observer and simple test doubles."""

    @property
    def api_origin(self) -> str: ...

    def get_pull_request(self, repository: str, number: int) -> PullRequestDetails: ...

    def list_pull_request_reviews(
        self, repository: str, number: int, *, max_reviews: int = 500
    ) -> list[PullRequestReview]: ...

    def list_issue_comments(
        self,
        repository: str,
        number: int,
        *,
        expected_count: int | None = None,
        max_comments: int = 500,
    ) -> list[GitHubComment]: ...

    def list_review_comments(
        self,
        repository: str,
        number: int,
        *,
        expected_count: int | None = None,
        max_comments: int = 500,
    ) -> list[GitHubComment]: ...

    def list_check_runs(
        self, repository: str, ref: str, *, max_check_runs: int = 500
    ) -> list[CheckRunDetails]: ...

    def list_commit_statuses(
        self, repository: str, ref: str, *, max_statuses: int = 500
    ) -> list[CommitStatusDetails]: ...

    def list_pull_request_references(
        self, repository: str, number: int, *, max_events: int = 1_000
    ) -> list[PullRequestReference]: ...

    def list_branch_pushes(self, repository: str, branch: str) -> list[BranchPush]: ...


class LifecycleSignalKind(StrEnum):
    HEAD_DRIFT = "head_drift"
    MAINTAINER_PUSH = "maintainer_push"
    CHANGES_REQUESTED = "changes_requested"
    MAINTAINER_STOP = "maintainer_stop"
    AUTOMATION_STOP = "automation_stop"
    CI_FAILED = "ci_failed"
    CLOSED_UNMERGED = "closed_unmerged"
    REVERTED = "reverted"


_STOP_REASONS: Final = {
    LifecycleSignalKind.AUTOMATION_STOP: "turns away automated or AI contributions",
    LifecycleSignalKind.MAINTAINER_STOP: "asks to close or stop this pull request",
}
# Routine review and CI events go to the approving human and stop nothing.
_ATTENTION_KINDS: Final[dict[LifecycleSignalKind, PullRequestAttentionKind]] = {
    LifecycleSignalKind.CHANGES_REQUESTED: "changes_requested",
    LifecycleSignalKind.CI_FAILED: "ci_failed",
    LifecycleSignalKind.MAINTAINER_PUSH: "maintainer_push",
}


@dataclass(frozen=True, slots=True)
class PullRequestLifecycleSnapshot:
    expected_head_sha: str
    pull_request: PullRequestDetails
    reviews: tuple[PullRequestReview, ...]
    issue_comments: tuple[GitHubComment, ...]
    review_comments: tuple[GitHubComment, ...]
    check_runs: tuple[CheckRunDetails, ...]
    commit_statuses: tuple[CommitStatusDetails, ...]
    references: tuple[PullRequestReference, ...]
    publishing_login: str | None = None
    # Read only when the head moved: the head branch's latest updates, newest first; empty when
    # GitHub could not show them.
    head_pushes: tuple[BranchPush, ...] = ()

    @property
    def pull_request_state(self) -> Literal["open", "merged", "closed"]:
        if self.pull_request.merged:
            return "merged"
        return "closed" if self.pull_request.state == "closed" else "open"


@dataclass(frozen=True, slots=True)
class LifecycleSignal:
    kind: LifecycleSignalKind
    repository: str
    pull_request_number: int
    pull_request_url: str
    evidence_key: str
    reason: str
    source_url: str

    @property
    def source(self) -> str:
        return f"github_lifecycle:{self.repository}#{self.pull_request_number}:{self.kind.value}"

    def trigger_hash(self) -> str:
        return _hash_payload(
            {
                "kind": self.kind.value,
                "repository": self.repository.casefold(),
                "pull_request_number": self.pull_request_number,
                "evidence_key": self.evidence_key,
            }
        )

    def attention(self, observed_at: datetime) -> PullRequestAttention | None:
        kind = _ATTENTION_KINDS.get(self.kind)
        if kind is None:
            return None
        return PullRequestAttention(
            kind=kind,
            reason=self.reason,
            source_url=self.source_url,
            evidence_hash=self.trigger_hash(),
            observed_at=observed_at,
        )

    def stops(self, *, api_origin: str, observed_at: datetime) -> tuple[CircuitBreakerTrigger, ...]:
        """The scoped stops this signal records, from narrowest to widest."""

        cooldown = observed_at + REPOSITORY_COOLDOWN
        match self.kind:
            case LifecycleSignalKind.HEAD_DRIFT:
                return (self._stop(StopScope.GLOBAL),)
            case LifecycleSignalKind.CLOSED_UNMERGED:
                return (self._stop(StopScope.REPOSITORY, self.repository, expires_at=cooldown),)
            case LifecycleSignalKind.MAINTAINER_STOP:
                return (
                    self._stop(StopScope.PULL_REQUEST, self.pull_request_url),
                    self._stop(StopScope.REPOSITORY, self.repository, expires_at=cooldown),
                )
            case LifecycleSignalKind.AUTOMATION_STOP:
                return (
                    self._stop(
                        StopScope.REPOSITORY, self.repository, counts_toward_escalation=True
                    ),
                )
            case LifecycleSignalKind.REVERTED:
                return (
                    self._stop(StopScope.REPOSITORY, self.repository),
                    self._stop(StopScope.PUBLICATION, api_origin),
                )
        return ()

    def _stop(
        self,
        scope: StopScope,
        scope_key: str = "",
        *,
        expires_at: datetime | None = None,
        counts_toward_escalation: bool = False,
    ) -> CircuitBreakerTrigger:
        return CircuitBreakerTrigger(
            source=self.source,
            reason=f"{self.reason}: {self.source_url}",
            trigger_hash=(
                self.trigger_hash()
                if scope is StopScope.GLOBAL
                else _hash_payload({"scope": scope.value, "signal": self.trigger_hash()})
            ),
            scope=scope,
            scope_key=scope_key,
            expires_at=expires_at,
            counts_toward_escalation=counts_toward_escalation,
        )


@dataclass(frozen=True, slots=True)
class LifecycleObservation:
    snapshot: PullRequestLifecycleSnapshot
    signals: tuple[LifecycleSignal, ...]
    attention: tuple[PullRequestAttention, ...]
    newly_recorded: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RevertWatch:
    """A merged pull request read only for a revert merged after it."""

    pull_request: PullRequestDetails
    signals: tuple[LifecycleSignal, ...]
    newly_recorded: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class LifecycleFailure:
    """A pull request whose observation failed; the others were still observed."""

    run_id: str
    pull_request_url: str
    error: str


@dataclass(frozen=True, slots=True)
class LifecycleSyncResult:
    observations: tuple[LifecycleObservation, ...]
    failures: tuple[LifecycleFailure, ...] = ()
    revert_watches: tuple[RevertWatch, ...] = ()

    @property
    def runs_checked(self) -> int:
        return len(self.observations) + len(self.revert_watches) + len(self.failures)

    @property
    def signals_detected(self) -> int:
        return sum(len(item.signals) for item in self.observations) + sum(
            len(item.signals) for item in self.revert_watches
        )

    @property
    def newly_recorded(self) -> int:
        return sum(len(item.newly_recorded) for item in self.observations) + sum(
            len(item.newly_recorded) for item in self.revert_watches
        )


class LifecycleObserver:
    """Collect one complete bounded snapshot and record its stops at their scope."""

    def __init__(
        self,
        github: LifecycleGitHub,
        store: LifecycleStore,
        *,
        assert_owned: Callable[[], object] | None = None,
    ) -> None:
        self.github = github
        self.store = store
        self._assert_owned = assert_owned

    def observe(
        self,
        *,
        repository: str,
        number: int,
        expected_head_sha: str,
        publishing_login: str | None,
    ) -> LifecycleObservation:
        normalized_repository = _identity(repository, field="repository")
        expected_sha = _identity(expected_head_sha, field="expected head SHA")
        if isinstance(number, bool) or not isinstance(number, int) or number < 1:
            raise ValueError("pull request number must be a positive integer")

        pull_request = self.github.get_pull_request(normalized_repository, number)
        _require_identity(pull_request, normalized_repository, number)
        reviews = self.github.list_pull_request_reviews(normalized_repository, number)
        issue_comments = self.github.list_issue_comments(
            normalized_repository,
            number,
            expected_count=pull_request.issue_comment_count,
        )
        review_comments = self.github.list_review_comments(
            normalized_repository,
            number,
            expected_count=pull_request.review_comment_count,
        )
        check_runs = self.github.list_check_runs(normalized_repository, pull_request.head_sha)
        commit_statuses = self.github.list_commit_statuses(
            normalized_repository, pull_request.head_sha
        )
        references = (
            self.github.list_pull_request_references(normalized_repository, number)
            if pull_request.merged
            else []
        )
        head_pushes: list[BranchPush] = []
        if pull_request.head_sha.casefold() != expected_sha.casefold():
            try:
                head_pushes = self.github.list_branch_pushes(
                    pull_request.head_repository, pull_request.head_ref
                )
            except (GitHubSafetyError, GitHubRateLimitError):
                raise
            except GitHubError:
                # Who pushed stays unknown, which classifies as a possible credential leak.
                head_pushes = []

        # A second top-level read catches comment/review/state/head races during pagination.
        confirmed = self.github.get_pull_request(normalized_repository, number)
        if confirmed != pull_request:
            raise GitHubError(
                "Pull request changed while lifecycle evidence was fetched; retry observation"
            )
        self._assert_lease_owned()

        snapshot = PullRequestLifecycleSnapshot(
            expected_head_sha=expected_sha,
            pull_request=pull_request,
            reviews=tuple(sorted(reviews, key=lambda review: review.identifier)),
            issue_comments=tuple(sorted(issue_comments, key=lambda comment: comment.identifier)),
            review_comments=tuple(sorted(review_comments, key=lambda comment: comment.identifier)),
            check_runs=tuple(
                sorted(
                    check_runs,
                    key=lambda check: (check.app_name.casefold(), check.name, check.identifier),
                )
            ),
            commit_statuses=tuple(
                sorted(
                    commit_statuses,
                    key=lambda status: (
                        status.context.casefold(),
                        status.created_at,
                        status.identifier,
                    ),
                )
            ),
            references=tuple(
                sorted(
                    references,
                    key=lambda reference: (reference.created_at, reference.identifier),
                )
            ),
            publishing_login=publishing_login,
            head_pushes=tuple(head_pushes),
        )
        signals = classify_lifecycle(snapshot)
        observed_at = utc_now()
        attention = tuple(
            item for item in (signal.attention(observed_at) for signal in signals) if item
        )
        return LifecycleObservation(
            snapshot=snapshot,
            signals=signals,
            attention=attention,
            newly_recorded=self._record_stops(signals, observed_at=observed_at),
        )

    def watch_for_revert(self, *, repository: str, number: int) -> RevertWatch:
        """Read a merged pull request's references only, for a revert merged after it."""

        normalized_repository = _identity(repository, field="repository")
        if isinstance(number, bool) or not isinstance(number, int) or number < 1:
            raise ValueError("pull request number must be a positive integer")
        pull_request = self.github.get_pull_request(normalized_repository, number)
        _require_identity(pull_request, normalized_repository, number)
        references = self.github.list_pull_request_references(normalized_repository, number)
        if self.github.get_pull_request(normalized_repository, number) != pull_request:
            raise GitHubError(
                "Pull request changed while lifecycle evidence was fetched; retry observation"
            )
        self._assert_lease_owned()
        signals = _ordered(_revert_signals(pull_request, references))
        return RevertWatch(
            pull_request=pull_request,
            signals=signals,
            newly_recorded=self._record_stops(signals, observed_at=utc_now()),
        )

    def _record_stops(
        self, signals: Sequence[LifecycleSignal], *, observed_at: datetime
    ) -> tuple[str, ...]:
        newly_recorded: list[str] = []
        for signal in signals:
            for trigger in signal.stops(api_origin=self.github.api_origin, observed_at=observed_at):
                self._assert_lease_owned()
                if self.store.record_stop(trigger):
                    newly_recorded.append(trigger.trigger_hash)
        return tuple(newly_recorded)

    def _assert_lease_owned(self) -> None:
        if self._assert_owned is not None:
            self._assert_owned()


def parse_pull_request_url(value: str, *, api_origin: str) -> tuple[str, int]:
    """Parse one canonical PR URL bound to the configured GitHub instance."""

    if not isinstance(value, str):
        raise TypeError("pull-request URL must be a string")
    if value != value.strip():
        raise StateError("Published run contains a non-canonical GitHub pull-request URL")
    try:
        parsed = urlparse(value)
        parsed_port = parsed.port
        expected = urlparse(web_origin_for_api(api_origin))
    except (ConfigurationError, ValueError) as exc:
        raise StateError("Published run contains a non-canonical GitHub pull-request URL") from exc
    if (
        parsed.scheme != expected.scheme
        or parsed.hostname != expected.hostname
        or parsed_port != expected.port
        or parsed.username is not None
        or parsed.password is not None
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise StateError("Published run contains a non-canonical GitHub pull-request URL")
    match = _PULL_REQUEST_PATH.fullmatch(parsed.path)
    if match is None:
        raise StateError("Published run contains a non-canonical GitHub pull-request URL")
    repository = f"{match.group(1)}/{match.group(2)}"
    return repository, int(match.group(3))


def sync_open_pull_requests(
    github: LifecycleGitHub,
    store: LifecycleRunStore,
    *,
    max_runs: int = MAX_LIFECYCLE_RUNS,
    assert_owned: Callable[[], object] | None = None,
) -> LifecycleSyncResult:
    """Observe every open PR, and watch each PR merged in the last 30 days for a revert.

    The complete local target set is validated before any GitHub read.
    """

    reported_api_origin = github.api_origin
    try:
        current_api_origin = canonical_api_origin(reported_api_origin)
    except ConfigurationError as exc:
        raise StateError("Lifecycle GitHub client has an invalid API origin") from exc
    if reported_api_origin != current_api_origin:
        raise StateError("Lifecycle GitHub client returned a non-canonical API origin")
    open_targets = _sync_targets(
        store.list_open_pull_request_runs(limit=max_runs), api_origin=current_api_origin
    )
    merged_targets = _sync_targets(
        store.list_merged_pull_request_runs(merged_since=utc_now() - REVERT_WATCH, limit=max_runs),
        api_origin=current_api_origin,
    )

    observer = LifecycleObserver(github, store, assert_owned=assert_owned)
    observations: list[LifecycleObservation] = []
    revert_watches: list[RevertWatch] = []
    failures: list[LifecycleFailure] = []
    for manifest, pull_request_url, repository, number, commit_sha in open_targets:
        if assert_owned is not None:
            assert_owned()
        try:
            observation = observer.observe(
                repository=repository,
                number=number,
                expected_head_sha=commit_sha,
                publishing_login=manifest.publishing_login,
            )
        except (GitHubSafetyError, GitHubRateLimitError):
            raise
        except GitHubError as exc:
            # One unreadable pull request must not hide the others or stop preparation.
            failures.append(LifecycleFailure(manifest.run_id, pull_request_url, str(exc)))
            state = manifest.pull_request_state
            merged_at = manifest.pull_request_merged_at
            attention: tuple[PullRequestAttention, ...] = (
                _observation_failure(pull_request_url, exc),
            )
        else:
            observations.append(observation)
            state = observation.snapshot.pull_request_state
            merged_at = observation.snapshot.pull_request.merged_at if state == "merged" else None
            attention = observation.attention
        if assert_owned is not None:
            assert_owned()
        _record_on_run(store, manifest, state=state, merged_at=merged_at, attention=attention)
    for manifest, pull_request_url, repository, number, _ in merged_targets:
        if assert_owned is not None:
            assert_owned()
        try:
            revert_watches.append(observer.watch_for_revert(repository=repository, number=number))
        except (GitHubSafetyError, GitHubRateLimitError):
            raise
        except GitHubError as exc:
            failures.append(LifecycleFailure(manifest.run_id, pull_request_url, str(exc)))
            if assert_owned is not None:
                assert_owned()
            _record_on_run(
                store,
                manifest,
                state=manifest.pull_request_state,
                merged_at=manifest.pull_request_merged_at,
                attention=(_observation_failure(pull_request_url, exc),),
            )
    return LifecycleSyncResult(
        observations=tuple(observations),
        failures=tuple(failures),
        revert_watches=tuple(revert_watches),
    )


def _sync_targets(
    manifests: Sequence[RunManifest], *, api_origin: str
) -> list[tuple[RunManifest, str, str, int, str]]:
    """Validate published runs and name the pull request each one observes."""

    targets: list[tuple[RunManifest, str, str, int, str]] = []
    seen: set[tuple[str, int]] = set()
    for manifest in manifests:
        if manifest.status != RunStatus.PR_OPEN:
            raise StateError("Lifecycle enumeration returned a run that is not PR-open")
        if manifest.candidate is None or manifest.repository is None:
            raise StateError(f"Published run {manifest.run_id} is missing repository evidence")
        if not manifest.pull_request_url:
            raise StateError(f"Published run {manifest.run_id} is missing its pull-request URL")
        if not manifest.publishing_api_origin:
            raise StateError(
                f"Published run {manifest.run_id} is missing its publishing API origin"
            )
        try:
            durable_api_origin = canonical_api_origin(manifest.publishing_api_origin)
        except ConfigurationError as exc:
            raise StateError(
                f"Published run {manifest.run_id} has an invalid publishing API origin"
            ) from exc
        if manifest.publishing_api_origin != durable_api_origin:
            raise StateError(
                f"Published run {manifest.run_id} has a non-canonical publishing API origin"
            )
        if durable_api_origin != api_origin:
            raise StateError(
                f"Published run {manifest.run_id} belongs to a different GitHub API origin"
            )
        repository, number = parse_pull_request_url(
            manifest.pull_request_url,
            api_origin=durable_api_origin,
        )
        expected_repository = manifest.candidate.repository
        if repository.casefold() != expected_repository.casefold():
            raise StateError(
                f"Published run {manifest.run_id} pull-request URL does not match its candidate"
            )
        if manifest.repository.full_name.casefold() != expected_repository.casefold():
            raise StateError(
                f"Published run {manifest.run_id} repository evidence is internally inconsistent"
            )
        commit_sha = manifest.commit_sha or ""
        if _COMMIT_SHA.fullmatch(commit_sha) is None:
            raise StateError(
                f"Published run {manifest.run_id} is missing a canonical contribution commit SHA"
            )
        identity = (repository.casefold(), number)
        if identity in seen:
            raise StateError("Multiple durable runs refer to the same pull request")
        seen.add(identity)
        targets.append((manifest, manifest.pull_request_url, repository, number, commit_sha))
    return targets


def _observation_failure(pull_request_url: str, error: GitHubError) -> PullRequestAttention:
    message = _REQUEST_ID.sub("", str(error))
    return PullRequestAttention(
        kind="observation_failed",
        reason=f"Lifecycle sync could not read this pull request: {message}",
        source_url=pull_request_url,
        evidence_hash=_hash_payload(
            {"kind": "observation_failed", "pull_request": pull_request_url, "error": message}
        ),
        observed_at=utc_now(),
    )


def _record_on_run(
    store: LifecycleRunStore,
    manifest: RunManifest,
    *,
    state: Literal["open", "merged", "closed"] | None,
    merged_at: datetime | None,
    attention: tuple[PullRequestAttention, ...],
) -> None:
    """Save the observed state and each attention entry the run does not have yet."""

    known = {item.evidence_hash for item in manifest.pull_request_attention}
    new = [item for item in attention if item.evidence_hash not in known]
    if (
        state == manifest.pull_request_state
        and merged_at == manifest.pull_request_merged_at
        and not new
    ):
        return
    manifest.pull_request_state = state
    manifest.pull_request_merged_at = merged_at
    manifest.pull_request_attention.extend(new)
    store.save(
        manifest,
        event="lifecycle.observed",
        details={
            "pull_request_state": state or "unknown",
            "attention": ",".join(item.kind for item in new) or "none",
        },
    )


def classify_lifecycle(
    snapshot: PullRequestLifecycleSnapshot,
) -> tuple[LifecycleSignal, ...]:
    """Return deterministic signals without model judgment or mutable state."""

    pull_request = snapshot.pull_request
    signals: list[LifecycleSignal] = []

    if pull_request.head_sha.casefold() != snapshot.expected_head_sha.casefold():
        signals.append(
            _signal(
                LifecycleSignalKind.MAINTAINER_PUSH,
                pull_request,
                evidence_key=pull_request.head_sha.casefold(),
                reason="Someone with push access to the repository added commits to this PR",
                source_url=pull_request.html_url,
            )
            if _pushed_by_others(snapshot)
            else _signal(
                LifecycleSignalKind.HEAD_DRIFT,
                pull_request,
                evidence_key=pull_request.head_sha.casefold(),
                reason=(
                    "Published pull-request head no longer matches the prepared commit, and "
                    "GitHub does not show that every push since then came from another account"
                ),
                source_url=pull_request.html_url,
            )
        )

    for review in _latest_effective_reviews(snapshot.reviews):
        if review.state == "CHANGES_REQUESTED" and _is_maintainer(
            review.author, review.author_association
        ):
            review_version = _evidence_version(
                review.author,
                review.author_association,
                review.state,
                review.body,
                review.submitted_at,
            )
            signals.append(
                _signal(
                    LifecycleSignalKind.CHANGES_REQUESTED,
                    pull_request,
                    evidence_key=(f"review:{review.identifier}:{review_version}"),
                    reason="A maintainer submitted a changes-requested review",
                    source_url=review.html_url,
                )
            )

    # Explicit stop text remains safety evidence even if a later review changes its vote.
    for review in snapshot.reviews:
        stop = _stop_kind(review.body)
        if stop is not None and _is_maintainer(review.author, review.author_association):
            review_version = _evidence_version(
                review.author,
                review.author_association,
                review.body,
                review.submitted_at,
            )
            signals.append(
                _signal(
                    stop,
                    pull_request,
                    evidence_key=(f"review-stop:{review.identifier}:{review_version}"),
                    reason=f"A maintainer review {_STOP_REASONS[stop]}",
                    source_url=review.html_url,
                )
            )

    for comment_kind, comments in (
        ("issue-comment", snapshot.issue_comments),
        ("review-comment", snapshot.review_comments),
    ):
        for comment in comments:
            stop = _stop_kind(comment.body)
            if stop is not None and _is_maintainer(comment.author, comment.author_association):
                comment_version = _evidence_version(
                    comment.author,
                    comment.author_association,
                    comment.body,
                    comment.updated_at,
                )
                signals.append(
                    _signal(
                        stop,
                        pull_request,
                        evidence_key=(f"{comment_kind}:{comment.identifier}:{comment_version}"),
                        reason=f"A maintainer comment {_STOP_REASONS[stop]}",
                        source_url=comment.html_url,
                    )
                )

    for check in _latest_check_runs(snapshot.check_runs):
        if check.status == "completed" and check.conclusion in _FAILING_CHECK_CONCLUSIONS:
            signals.append(
                _signal(
                    LifecycleSignalKind.CI_FAILED,
                    pull_request,
                    evidence_key=f"check-run:{check.identifier}:{check.conclusion}",
                    reason=f"Latest CI check {check.name!r} completed with {check.conclusion}",
                    source_url=check.details_url or pull_request.html_url,
                )
            )

    for status in _latest_commit_statuses(snapshot.commit_statuses):
        if status.state in _FAILING_COMMIT_STATES:
            signals.append(
                _signal(
                    LifecycleSignalKind.CI_FAILED,
                    pull_request,
                    evidence_key=f"commit-status:{status.identifier}:{status.state}",
                    reason=f"Latest commit status {status.context!r} is {status.state}",
                    source_url=status.target_url or pull_request.html_url,
                )
            )

    if pull_request.state == "closed" and not pull_request.merged:
        closed_marker = pull_request.closed_at.isoformat() if pull_request.closed_at else "unknown"
        signals.append(
            _signal(
                LifecycleSignalKind.CLOSED_UNMERGED,
                pull_request,
                evidence_key=f"closed:{closed_marker}",
                reason="Pull request was closed without being merged",
                source_url=pull_request.html_url,
            )
        )

    signals.extend(_revert_signals(pull_request, snapshot.references))

    return _ordered(signals)


def _ordered(signals: Sequence[LifecycleSignal]) -> tuple[LifecycleSignal, ...]:
    # API ordering must never influence breaker trigger order or hashes.
    return tuple(
        sorted(
            signals,
            key=lambda signal: (signal.kind.value, signal.evidence_key, signal.source_url),
        )
    )


def _revert_signals(
    pull_request: PullRequestDetails, references: Sequence[PullRequestReference]
) -> list[LifecycleSignal]:
    signals: list[LifecycleSignal] = []
    for reference in references:
        if (
            not pull_request.merged
            or pull_request.merged_at is None
            or reference.source_state != "closed"
            or reference.source_merged_at is None
            or reference.source_merged_at <= pull_request.merged_at
        ):
            continue
        if _is_explicit_revert(reference, pull_request):
            reference_version = _evidence_version(
                reference.source_title,
                reference.source_body,
                reference.source_merged_at,
            )
            signals.append(
                _signal(
                    LifecycleSignalKind.REVERTED,
                    pull_request,
                    evidence_key=(f"revert-reference:{reference.identifier}:{reference_version}"),
                    reason="A merged pull request explicitly reverts this contribution",
                    source_url=reference.source_url,
                )
            )
    return signals


def _signal(
    kind: LifecycleSignalKind,
    pull_request: PullRequestDetails,
    *,
    evidence_key: str,
    reason: str,
    source_url: str,
) -> LifecycleSignal:
    return LifecycleSignal(
        kind=kind,
        repository=pull_request.repository,
        pull_request_number=pull_request.number,
        pull_request_url=pull_request.html_url,
        evidence_key=evidence_key,
        reason=reason,
        source_url=source_url,
    )


def _evidence_version(*values: object) -> str:
    """Version mutable GitHub evidence so an edited stop cannot reuse an acknowledged trigger."""

    return _hash_payload(values)


def _is_maintainer(author: str, association: str) -> bool:
    return association.upper() in _MAINTAINER_ASSOCIATIONS and not author.casefold().endswith(
        "[bot]"
    )


def _stop_kind(text: str) -> LifecycleSignalKind | None:
    """Whether text asks to stop automated work in general, this pull request, or nothing."""

    # Mask only the negated directive itself. Skipping its whole sentence would also discard a
    # later, independent stop such as "Don't stop CI, but withdraw this contribution."
    unmasked = text.replace("\u2019", "'")
    without_negated_directives = _NEGATED_STOP_DIRECTIVE.sub("", unmasked)
    if AUTOMATION_STOP.search(without_negated_directives) or _NOT_ACCEPTING.search(
        without_negated_directives
    ):
        return LifecycleSignalKind.AUTOMATION_STOP
    if _PULL_REQUEST_STOP.search(without_negated_directives):
        return LifecycleSignalKind.MAINTAINER_STOP
    return None


def _pushed_by_others(snapshot: PullRequestLifecycleSnapshot) -> bool:
    """Whether fast-forward pushes by other accounts lead from the prepared commit to the head.

    GitHub lets only the fork owner and people with push access to the upstream repository push
    to the branch, so such pushes come from the project. Commit authorship cannot tell them from
    a push made with this tool's own credentials, because it follows the author email; the
    pusher can. A force push, a push by the publishing account or by no known account, or a gap
    in GitHub's record may come from this tool's credentials.
    """

    login = snapshot.publishing_login
    if login is None:
        return False
    # Newest first, so a commit that a later push restored maps to that later push.
    pushes_by_result: dict[str, BranchPush] = {}
    for update in snapshot.head_pushes:
        pushes_by_result.setdefault(update.after.casefold(), update)
    current = snapshot.pull_request.head_sha.casefold()
    expected = snapshot.expected_head_sha.casefold()
    for _ in snapshot.head_pushes:
        if current == expected:
            return True
        push = pushes_by_result.get(current)
        if (
            push is None
            or push.activity_type != "push"
            or push.actor_login is None
            or push.actor_login.casefold() == login.casefold()
        ):
            return False
        current = push.before.casefold()
    return current == expected


def _latest_check_runs(
    check_runs: Sequence[CheckRunDetails],
) -> tuple[CheckRunDetails, ...]:
    latest: dict[tuple[str, str], CheckRunDetails] = {}
    for check in check_runs:
        key = (check.app_name.casefold(), check.name.casefold())
        current = latest.get(key)
        check_order = (
            check.started_at or datetime.min.replace(tzinfo=UTC),
            check.identifier,
        )
        if current is None:
            latest[key] = check
            continue
        current_order = (
            current.started_at or datetime.min.replace(tzinfo=UTC),
            current.identifier,
        )
        if check_order > current_order:
            latest[key] = check
    return tuple(latest[key] for key in sorted(latest))


def _latest_effective_reviews(
    reviews: Sequence[PullRequestReview],
) -> tuple[PullRequestReview, ...]:
    latest: dict[str, PullRequestReview] = {}
    for review in reviews:
        if review.state not in {"APPROVED", "CHANGES_REQUESTED", "DISMISSED"}:
            continue
        key = review.author.casefold()
        current = latest.get(key)
        review_order = (
            review.submitted_at or datetime.min.replace(tzinfo=UTC),
            review.identifier,
        )
        if current is None:
            latest[key] = review
            continue
        current_order = (
            current.submitted_at or datetime.min.replace(tzinfo=UTC),
            current.identifier,
        )
        if review_order > current_order:
            latest[key] = review
    return tuple(latest[key] for key in sorted(latest))


def _latest_commit_statuses(
    statuses: Sequence[CommitStatusDetails],
) -> tuple[CommitStatusDetails, ...]:
    latest: dict[str, CommitStatusDetails] = {}
    for status in statuses:
        key = status.context.casefold()
        current = latest.get(key)
        if current is None or (status.updated_at, status.created_at, status.identifier) > (
            current.updated_at,
            current.created_at,
            current.identifier,
        ):
            latest[key] = status
    return tuple(latest[key] for key in sorted(latest))


def _is_explicit_revert(
    reference: PullRequestReference,
    pull_request: PullRequestDetails,
) -> bool:
    repository = pull_request.repository
    number = pull_request.number
    text = f"{reference.source_title}\n{reference.source_body}"
    repository_target = re.escape(f"{repository}#{number}")
    local_target = rf"\#{number}(?!\d)"
    url_target = re.escape(pull_request.html_url)
    if re.search(
        rf"\breverts?\s+(?:{repository_target}|{url_target}|{local_target})",
        text,
        re.IGNORECASE,
    ):
        return True
    return bool(
        pull_request.merge_commit_sha
        and re.search(
            rf"\bthis\s+reverts\s+commit\s+{re.escape(pull_request.merge_commit_sha)}\b",
            text,
            re.IGNORECASE,
        )
    )


def _require_identity(pull_request: PullRequestDetails, repository: str, number: int) -> None:
    if pull_request.repository.casefold() != repository.casefold() or pull_request.number != number:
        raise GitHubError("GitHub returned a different pull request than requested")


def _identity(value: str, *, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string")
    normalized = value.strip()
    if not normalized or "\0" in normalized or len(normalized) > 255:
        raise ValueError(f"{field} must be 1-255 non-NUL characters")
    return normalized


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=_json_default,
    )


def _json_default(value: object) -> str:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("lifecycle timestamps must be timezone-aware")
        return value.astimezone(UTC).isoformat()
    raise TypeError(f"Cannot serialize lifecycle value of type {type(value).__name__}")


def _hash_payload(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


__all__ = [
    "MAX_LIFECYCLE_RUNS",
    "REPOSITORY_COOLDOWN",
    "REVERT_WATCH",
    "LifecycleFailure",
    "LifecycleGitHub",
    "LifecycleObservation",
    "LifecycleObserver",
    "LifecycleRunStore",
    "LifecycleSignal",
    "LifecycleSignalKind",
    "LifecycleStore",
    "LifecycleSyncResult",
    "PullRequestLifecycleSnapshot",
    "RevertWatch",
    "classify_lifecycle",
    "parse_pull_request_url",
    "sync_open_pull_requests",
]
