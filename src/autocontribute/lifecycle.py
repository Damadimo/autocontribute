"""Read-only pull-request observation and deterministic safety signals."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final, NoReturn, Protocol, cast
from urllib.parse import urlparse

from autocontribute.domain import RunManifest, RunStatus
from autocontribute.exceptions import ConfigurationError, GitHubError, StateError
from autocontribute.github import (
    CheckRunDetails,
    CommitStatusDetails,
    GitHubComment,
    PullRequestDetails,
    PullRequestReference,
    PullRequestReview,
)
from autocontribute.github_origin import canonical_api_origin, web_origin_for_api

_MAINTAINER_ASSOCIATIONS = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})
_NONPASSING_CHECK_CONCLUSIONS = frozenset(
    {"action_required", "cancelled", "failure", "stale", "startup_failure", "timed_out"}
)
_FAILING_COMMIT_STATES = frozenset({"error", "failure"})
_AUTHOR_ASSOCIATIONS = frozenset(
    {
        "COLLABORATOR",
        "CONTRIBUTOR",
        "FIRST_TIMER",
        "FIRST_TIME_CONTRIBUTOR",
        "MANNEQUIN",
        "MEMBER",
        "NONE",
        "OWNER",
    }
)
_REVIEW_STATES = frozenset({"APPROVED", "CHANGES_REQUESTED", "COMMENTED", "DISMISSED", "PENDING"})
_CHECK_STATUSES = frozenset(
    {"completed", "in_progress", "pending", "queued", "requested", "waiting"}
)
_CHECK_CONCLUSIONS = frozenset(
    {
        "action_required",
        "cancelled",
        "failure",
        "neutral",
        "skipped",
        "stale",
        "startup_failure",
        "success",
        "timed_out",
    }
)
_COMMIT_STATES = frozenset({"error", "failure", "pending", "success"})
_MAINTAINER_STOP = re.compile(
    r"(?:"
    r"\b(?:do\s+not|don't|stop|cease|hold\s+off|not\s+accepting|"
    r"no\s+longer\s+accept(?:ing)?)\b[^\n.!?]{0,120}"
    r"\b(?:ai(?:-generated|-assisted)?|automat(?:ed|ion)|bots?|pull\s+requests?|prs?|"
    r"contributions?|submissions?|work)\b"
    r"|\b(?:ai(?:-generated|-assisted)?|automat(?:ed|ion)|bots?|pull\s+requests?|prs?|"
    r"contributions?|submissions?)\b[^\n.!?]{0,120}"
    r"\b(?:not\s+(?:accepted|allowed|welcome)|are\s+closed)\b"
    r"|\b(?:close|withdraw)\s+(?:this\s+)?(?:pull\s+request|pr|contribution)\b"
    r"|\bno\s+(?:pull\s+requests?|prs?|contributions?)\s+(?:are\s+)?needed\b"
    r")",
    re.IGNORECASE,
)
_NEGATED_STOP_DIRECTIVE = re.compile(
    r"\b(?:do\s+not|don't|never)\s+"
    r"(?:stop|cease|pause|hold\s+off|close|withdraw)\b",
    re.IGNORECASE,
)
_PULL_REQUEST_PATH: Final = re.compile(r"/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/pull/([1-9][0-9]*)")
_REPOSITORY_NAME: Final = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_COMMIT_SHA: Final = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})")
MAX_LIFECYCLE_RUNS: Final = 1_000


class LifecycleStore(Protocol):
    """The narrow durable interface needed by lifecycle observation."""

    def record_lifecycle_snapshot(
        self, run_id: str, fingerprint: str, snapshot_json: str
    ) -> bool: ...

    def trip_circuit_breaker(self, *, source: str, reason: str, trigger_hash: str) -> bool: ...


class LifecycleRunStore(LifecycleStore, Protocol):
    """Durable run enumeration plus the observer's append-only write surface."""

    def list_open_pull_request_runs(
        self, *, limit: int = MAX_LIFECYCLE_RUNS
    ) -> list[RunManifest]: ...


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


class LifecycleSignalKind(StrEnum):
    HEAD_DRIFT = "head_drift"
    CHANGES_REQUESTED = "changes_requested"
    MAINTAINER_STOP = "maintainer_stop"
    CI_FAILED = "ci_failed"
    CLOSED_UNMERGED = "closed_unmerged"
    REVERTED = "reverted"


@dataclass(frozen=True, slots=True)
class PullRequestLifecycleSnapshot:
    observed_at: datetime
    expected_head_sha: str
    pull_request: PullRequestDetails
    reviews: tuple[PullRequestReview, ...]
    issue_comments: tuple[GitHubComment, ...]
    review_comments: tuple[GitHubComment, ...]
    check_runs: tuple[CheckRunDetails, ...]
    commit_statuses: tuple[CommitStatusDetails, ...]
    references: tuple[PullRequestReference, ...]

    def to_json(self) -> str:
        """Serialize stable evidence; the store records its own durable observation time."""

        return _canonical_json(self._evidence_payload())

    def fingerprint(self) -> str:
        """Hash evidence, excluding the polling time so unchanged observations deduplicate."""

        return _hash_payload(self._evidence_payload())

    def _evidence_payload(self) -> dict[str, object]:
        evidence = asdict(self)
        del evidence["observed_at"]
        return evidence


def parse_lifecycle_snapshot_json(
    value: str,
    *,
    observed_at: datetime,
) -> PullRequestLifecycleSnapshot:
    """Parse one exact canonical lifecycle payload without coercing stored values.

    ``observed_at`` is storage metadata rather than GitHub evidence. It is carried on the
    reconstructed object for compatibility, but is deliberately excluded from the fingerprint
    and must never be used to establish an upstream outcome or order observations.
    """

    if not isinstance(value, str):
        raise TypeError("lifecycle snapshot must be a JSON string")
    try:
        decoded: object = json.loads(
            value,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("lifecycle snapshot is not valid JSON") from exc
    payload = _exact_object(
        decoded,
        field="lifecycle snapshot",
        keys={
            "check_runs",
            "commit_statuses",
            "expected_head_sha",
            "issue_comments",
            "pull_request",
            "references",
            "review_comments",
            "reviews",
        },
    )
    snapshot = PullRequestLifecycleSnapshot(
        observed_at=_aware_utc_timestamp(observed_at, field="lifecycle observation metadata"),
        expected_head_sha=_full_sha(payload, "expected_head_sha", field="expected head SHA"),
        pull_request=_parsed_pull_request(payload["pull_request"]),
        reviews=tuple(
            _parsed_review(item)
            for item in _object_sequence(payload["reviews"], field="pull request reviews")
        ),
        issue_comments=tuple(
            _parsed_comment(item)
            for item in _object_sequence(payload["issue_comments"], field="issue comments")
        ),
        review_comments=tuple(
            _parsed_comment(item)
            for item in _object_sequence(payload["review_comments"], field="review comments")
        ),
        check_runs=tuple(
            _parsed_check_run(item)
            for item in _object_sequence(payload["check_runs"], field="check runs")
        ),
        commit_statuses=tuple(
            _parsed_commit_status(item)
            for item in _object_sequence(payload["commit_statuses"], field="commit statuses")
        ),
        references=tuple(
            _parsed_reference(item)
            for item in _object_sequence(payload["references"], field="pull request references")
        ),
    )
    _validate_snapshot_shape(snapshot)
    if snapshot.to_json() != value:
        raise ValueError("lifecycle snapshot must use canonical JSON serialization")
    return snapshot


@dataclass(frozen=True, slots=True)
class LifecycleSignal:
    kind: LifecycleSignalKind
    repository: str
    pull_request_number: int
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


@dataclass(frozen=True, slots=True)
class LifecycleObservation:
    snapshot: PullRequestLifecycleSnapshot
    signals: tuple[LifecycleSignal, ...]
    snapshot_recorded: bool
    newly_tripped: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class LifecycleRunObservation:
    run_id: str
    repository: str
    pull_request_number: int
    observation: LifecycleObservation


@dataclass(frozen=True, slots=True)
class LifecycleSyncResult:
    observations: tuple[LifecycleRunObservation, ...]

    @property
    def runs_checked(self) -> int:
        return len(self.observations)

    @property
    def snapshots_recorded(self) -> int:
        return sum(item.observation.snapshot_recorded for item in self.observations)

    @property
    def signals_detected(self) -> int:
        return sum(len(item.observation.signals) for item in self.observations)

    @property
    def newly_tripped(self) -> int:
        return sum(len(item.observation.newly_tripped) for item in self.observations)


class LifecycleObserver:
    """Collect one complete bounded snapshot, persist it, and activate hard stops."""

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
        bind_safety = getattr(github, "bind_safety_trigger_handler", None)
        if callable(bind_safety):
            bind_safety(
                lambda trigger: store.trip_circuit_breaker(
                    source=trigger.source,
                    reason=trigger.reason,
                    trigger_hash=trigger.trigger_hash,
                )
            )

    def observe(
        self,
        run_id: str,
        *,
        repository: str,
        number: int,
        expected_head_sha: str,
        observed_at: datetime | None = None,
    ) -> LifecycleObservation:
        normalized_run_id = _identity(run_id, field="run ID")
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

        # A second top-level read catches comment/review/state/head races during pagination.
        confirmed = self.github.get_pull_request(normalized_repository, number)
        if confirmed != pull_request:
            raise GitHubError(
                "Pull request changed while lifecycle evidence was fetched; retry observation"
            )
        self._assert_lease_owned()

        snapshot = PullRequestLifecycleSnapshot(
            observed_at=_observation_time(observed_at),
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
            references=tuple(sorted(references, key=lambda reference: reference.identifier)),
        )
        signals = classify_lifecycle(snapshot)
        fingerprint = snapshot.fingerprint()
        snapshot_json = snapshot.to_json()
        self._assert_lease_owned()
        snapshot_recorded = self.store.record_lifecycle_snapshot(
            normalized_run_id,
            fingerprint,
            snapshot_json,
        )
        newly_tripped: list[str] = []
        for signal in signals:
            trigger_hash = signal.trigger_hash()
            self._assert_lease_owned()
            if self.store.trip_circuit_breaker(
                source=signal.source,
                reason=signal.reason,
                trigger_hash=trigger_hash,
            ):
                newly_tripped.append(trigger_hash)
        return LifecycleObservation(
            snapshot=snapshot,
            signals=signals,
            snapshot_recorded=snapshot_recorded,
            newly_tripped=tuple(newly_tripped),
        )

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


def _parsed_pull_request(value: object) -> PullRequestDetails:
    record = _exact_object(
        value,
        field="pull request",
        keys={
            "base_ref",
            "base_sha",
            "body",
            "closed_at",
            "draft",
            "head_label",
            "head_ref",
            "head_repository",
            "head_sha",
            "html_url",
            "issue_comment_count",
            "merge_commit_sha",
            "merged",
            "merged_at",
            "number",
            "repository",
            "review_comment_count",
            "state",
            "title",
            "updated_at",
        },
    )
    pull_request = PullRequestDetails(
        repository=_repository(record, "repository", field="pull request repository"),
        number=_positive_integer(record, "number", field="pull request number"),
        html_url=_text(record, "html_url", field="pull request URL"),
        state=_choice(record, "state", field="pull request state", choices={"open", "closed"}),
        draft=_boolean(record, "draft", field="pull request draft state"),
        merged=_boolean(record, "merged", field="pull request merged state"),
        updated_at=_timestamp(record, "updated_at", field="pull request update time"),
        merged_at=_optional_timestamp(record, "merged_at", field="pull request merge time"),
        closed_at=_optional_timestamp(record, "closed_at", field="pull request close time"),
        merge_commit_sha=_optional_full_sha(
            record,
            "merge_commit_sha",
            field="pull request merge commit SHA",
        ),
        head_sha=_full_sha(record, "head_sha", field="pull request head SHA"),
        base_sha=_full_sha(record, "base_sha", field="pull request base SHA"),
        head_repository=_repository(
            record,
            "head_repository",
            field="pull request head repository",
        ),
        issue_comment_count=_nonnegative_integer(
            record,
            "issue_comment_count",
            field="pull request issue comment count",
        ),
        review_comment_count=_nonnegative_integer(
            record,
            "review_comment_count",
            field="pull request review comment count",
        ),
        title=_text(record, "title", field="pull request title"),
        body=_text(record, "body", field="pull request body", empty=True),
        base_ref=_text(record, "base_ref", field="pull request base ref"),
        head_ref=_text(record, "head_ref", field="pull request head ref"),
        head_label=_text(record, "head_label", field="pull request head label"),
    )
    if pull_request.merged and (
        pull_request.state != "closed"
        or pull_request.merged_at is None
        or pull_request.closed_at is None
    ):
        raise ValueError("lifecycle snapshot contains inconsistent merged pull request state")
    if not pull_request.merged and pull_request.merged_at is not None:
        raise ValueError("lifecycle snapshot contains merged_at for an unmerged pull request")
    if (pull_request.state == "closed") != (pull_request.closed_at is not None):
        raise ValueError("lifecycle snapshot contains inconsistent pull request close state")
    _validate_pull_request_url(pull_request)
    return pull_request


def _parsed_review(value: object) -> PullRequestReview:
    record = _exact_object(
        value,
        field="pull request review",
        keys={
            "author",
            "author_association",
            "body",
            "html_url",
            "identifier",
            "state",
            "submitted_at",
        },
    )
    return PullRequestReview(
        identifier=_positive_integer(record, "identifier", field="review identifier"),
        author=_text(record, "author", field="review author"),
        author_association=_choice(
            record,
            "author_association",
            field="review author association",
            choices=_AUTHOR_ASSOCIATIONS,
        ),
        state=_choice(record, "state", field="review state", choices=_REVIEW_STATES),
        body=_text(record, "body", field="review body", empty=True),
        html_url=_text(record, "html_url", field="review URL"),
        submitted_at=_optional_timestamp(record, "submitted_at", field="review submission time"),
    )


def _parsed_comment(value: object) -> GitHubComment:
    record = _exact_object(
        value,
        field="pull request comment",
        keys={
            "author",
            "author_association",
            "body",
            "created_at",
            "html_url",
            "identifier",
            "updated_at",
        },
    )
    return GitHubComment(
        identifier=_positive_integer(record, "identifier", field="comment identifier"),
        author=_text(record, "author", field="comment author"),
        author_association=_choice(
            record,
            "author_association",
            field="comment author association",
            choices=_AUTHOR_ASSOCIATIONS,
        ),
        body=_text(record, "body", field="comment body", empty=True),
        html_url=_text(record, "html_url", field="comment URL"),
        created_at=_timestamp(record, "created_at", field="comment creation time"),
        updated_at=_timestamp(record, "updated_at", field="comment update time"),
    )


def _parsed_check_run(value: object) -> CheckRunDetails:
    record = _exact_object(
        value,
        field="check run",
        keys={
            "app_name",
            "completed_at",
            "conclusion",
            "details_url",
            "identifier",
            "name",
            "started_at",
            "status",
        },
    )
    status = _choice(record, "status", field="check run status", choices=_CHECK_STATUSES)
    conclusion = _optional_choice(
        record,
        "conclusion",
        field="check run conclusion",
        choices=_CHECK_CONCLUSIONS,
    )
    completed_at = _optional_timestamp(record, "completed_at", field="check completion time")
    if status == "completed" and (conclusion is None or completed_at is None):
        raise ValueError("lifecycle snapshot contains an incomplete completed check run")
    if status != "completed" and (conclusion is not None or completed_at is not None):
        raise ValueError("lifecycle snapshot contains completion data for an incomplete check run")
    return CheckRunDetails(
        identifier=_positive_integer(record, "identifier", field="check run identifier"),
        name=_text(record, "name", field="check run name"),
        status=status,
        conclusion=conclusion,
        details_url=_text(record, "details_url", field="check run details URL", empty=True),
        app_name=_text(record, "app_name", field="check run app name"),
        started_at=_optional_timestamp(record, "started_at", field="check start time"),
        completed_at=completed_at,
    )


def _parsed_commit_status(value: object) -> CommitStatusDetails:
    record = _exact_object(
        value,
        field="commit status",
        keys={
            "context",
            "created_at",
            "creator",
            "description",
            "identifier",
            "state",
            "target_url",
            "updated_at",
        },
    )
    return CommitStatusDetails(
        identifier=_positive_integer(record, "identifier", field="commit status identifier"),
        context=_text(record, "context", field="commit status context"),
        state=_choice(record, "state", field="commit status state", choices=_COMMIT_STATES),
        description=_text(record, "description", field="commit status description", empty=True),
        target_url=_text(record, "target_url", field="commit status target URL", empty=True),
        creator=_text(record, "creator", field="commit status creator"),
        created_at=_timestamp(record, "created_at", field="commit status creation time"),
        updated_at=_timestamp(record, "updated_at", field="commit status update time"),
    )


def _parsed_reference(value: object) -> PullRequestReference:
    record = _exact_object(
        value,
        field="pull request reference",
        keys={
            "created_at",
            "identifier",
            "source_body",
            "source_merged_at",
            "source_state",
            "source_title",
            "source_url",
        },
    )
    return PullRequestReference(
        identifier=_positive_integer(record, "identifier", field="reference identifier"),
        source_url=_text(record, "source_url", field="reference source URL"),
        source_title=_text(record, "source_title", field="reference source title", empty=True),
        source_body=_text(record, "source_body", field="reference source body", empty=True),
        source_state=_choice(
            record,
            "source_state",
            field="reference source state",
            choices={"open", "closed"},
        ),
        source_merged_at=_optional_timestamp(
            record,
            "source_merged_at",
            field="reference source merge time",
        ),
        created_at=_timestamp(record, "created_at", field="reference creation time"),
    )


def _validate_snapshot_shape(snapshot: PullRequestLifecycleSnapshot) -> None:
    for field, values, maximum in (
        ("reviews", snapshot.reviews, 500),
        ("issue comments", snapshot.issue_comments, 500),
        ("review comments", snapshot.review_comments, 500),
        ("check runs", snapshot.check_runs, 500),
        ("commit statuses", snapshot.commit_statuses, 500),
        ("references", snapshot.references, 1_000),
    ):
        if len(values) > maximum:
            raise ValueError(f"lifecycle snapshot {field} exceed the collection limit")
    if snapshot.pull_request.issue_comment_count != len(snapshot.issue_comments):
        raise ValueError("lifecycle snapshot issue-comment count does not match its evidence")
    if snapshot.pull_request.review_comment_count != len(snapshot.review_comments):
        raise ValueError("lifecycle snapshot review-comment count does not match its evidence")
    if snapshot.references and not snapshot.pull_request.merged:
        raise ValueError(
            "lifecycle snapshot contains revert references for an unmerged pull request"
        )
    if snapshot.reviews != tuple(sorted(snapshot.reviews, key=lambda review: review.identifier)):
        raise ValueError("lifecycle snapshot reviews are not in canonical order")
    if snapshot.issue_comments != tuple(
        sorted(snapshot.issue_comments, key=lambda comment: comment.identifier)
    ):
        raise ValueError("lifecycle snapshot issue comments are not in canonical order")
    if snapshot.review_comments != tuple(
        sorted(snapshot.review_comments, key=lambda comment: comment.identifier)
    ):
        raise ValueError("lifecycle snapshot review comments are not in canonical order")
    if snapshot.check_runs != tuple(
        sorted(
            snapshot.check_runs,
            key=lambda check: (check.app_name.casefold(), check.name, check.identifier),
        )
    ):
        raise ValueError("lifecycle snapshot check runs are not in canonical order")
    if snapshot.commit_statuses != tuple(
        sorted(
            snapshot.commit_statuses,
            key=lambda status: (
                status.context.casefold(),
                status.created_at,
                status.identifier,
            ),
        )
    ):
        raise ValueError("lifecycle snapshot commit statuses are not in canonical order")
    if snapshot.references != tuple(
        sorted(snapshot.references, key=lambda reference: reference.identifier)
    ):
        raise ValueError("lifecycle snapshot references are not in canonical order")
    for field, identifiers in (
        ("reviews", [item.identifier for item in snapshot.reviews]),
        ("issue comments", [item.identifier for item in snapshot.issue_comments]),
        ("review comments", [item.identifier for item in snapshot.review_comments]),
        ("check runs", [item.identifier for item in snapshot.check_runs]),
        ("commit statuses", [item.identifier for item in snapshot.commit_statuses]),
        ("references", [item.identifier for item in snapshot.references]),
    ):
        if len(identifiers) != len(set(identifiers)):
            raise ValueError(f"lifecycle snapshot contains duplicate {field}")


def _exact_object(value: object, *, field: str, keys: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{field} must be a JSON object")
    record = cast("dict[str, object]", value)
    if set(record) != keys:
        raise ValueError(f"{field} does not have the exact supported fields")
    return record


def _object_sequence(value: object, *, field: str) -> list[object]:
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a JSON array")
    return cast("list[object]", value)


def _text(
    record: dict[str, object],
    key: str,
    *,
    field: str,
    empty: bool = False,
) -> str:
    value = record[key]
    if (
        not isinstance(value, str)
        or "\0" in value
        or (not empty and (not value or value != value.strip()))
    ):
        qualifier = "a string" if empty else "a nonempty canonical string"
        raise ValueError(f"{field} must be {qualifier} without null bytes")
    return value


def _repository(record: dict[str, object], key: str, *, field: str) -> str:
    value = _text(record, key, field=field)
    if not _REPOSITORY_NAME.fullmatch(value) or any(
        part in {".", ".."} for part in value.split("/")
    ):
        raise ValueError(f"{field} must use canonical owner/name syntax")
    return value


def _full_sha(record: dict[str, object], key: str, *, field: str) -> str:
    value = _text(record, key, field=field)
    if not _COMMIT_SHA.fullmatch(value) or value != value.casefold():
        raise ValueError(f"{field} must be a canonical full Git SHA")
    return value


def _optional_full_sha(record: dict[str, object], key: str, *, field: str) -> str | None:
    if record[key] is None:
        return None
    return _full_sha(record, key, field=field)


def _validate_pull_request_url(pull_request: PullRequestDetails) -> None:
    try:
        parsed = urlparse(pull_request.html_url)
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("pull request URL must be canonical") from exc
    expected_path = f"/{pull_request.repository}/pull/{pull_request.number}"
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.params
        or parsed.query
        or parsed.fragment
        or parsed.path.casefold() != expected_path.casefold()
    ):
        raise ValueError("pull request URL must match its canonical repository and number")


def _boolean(record: dict[str, object], key: str, *, field: str) -> bool:
    value = record[key]
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be a boolean")
    return value


def _positive_integer(record: dict[str, object], key: str, *, field: str) -> int:
    value = record[key]
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{field} must be a positive integer")
    return value


def _nonnegative_integer(record: dict[str, object], key: str, *, field: str) -> int:
    value = record[key]
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field} must be a nonnegative integer")
    return value


def _choice(
    record: dict[str, object],
    key: str,
    *,
    field: str,
    choices: set[str] | frozenset[str],
) -> str:
    value = _text(record, key, field=field)
    if value not in choices:
        raise ValueError(f"{field} has an unsupported value")
    return value


def _optional_choice(
    record: dict[str, object],
    key: str,
    *,
    field: str,
    choices: set[str] | frozenset[str],
) -> str | None:
    if record[key] is None:
        return None
    return _choice(record, key, field=field, choices=choices)


def _timestamp(record: dict[str, object], key: str, *, field: str) -> datetime:
    return _canonical_utc_timestamp(record[key], field=field)


def _optional_timestamp(
    record: dict[str, object],
    key: str,
    *,
    field: str,
) -> datetime | None:
    if record[key] is None:
        return None
    return _canonical_utc_timestamp(record[key], field=field)


def _canonical_utc_timestamp(value: object, *, field: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a canonical UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{field} must be a canonical UTC timestamp") from exc
    normalized = _aware_utc_timestamp(parsed, field=field)
    if parsed.utcoffset() != UTC.utcoffset(parsed) or normalized.isoformat() != value:
        raise ValueError(f"{field} must be a canonical UTC timestamp")
    return normalized


def _aware_utc_timestamp(value: datetime, *, field: str) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"{field} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware")
    return value.astimezone(UTC)


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"lifecycle snapshot contains duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> NoReturn:
    raise ValueError(f"lifecycle snapshot contains invalid JSON constant: {value}")


def sync_open_pull_requests(
    github: LifecycleGitHub,
    store: LifecycleRunStore,
    *,
    max_runs: int = MAX_LIFECYCLE_RUNS,
    assert_owned: Callable[[], object] | None = None,
) -> LifecycleSyncResult:
    """Observe every durable open PR after validating the complete local target set."""

    reported_api_origin = github.api_origin
    try:
        current_api_origin = canonical_api_origin(reported_api_origin)
    except ConfigurationError as exc:
        raise StateError("Lifecycle GitHub client has an invalid API origin") from exc
    if reported_api_origin != current_api_origin:
        raise StateError("Lifecycle GitHub client returned a non-canonical API origin")
    manifests = store.list_open_pull_request_runs(limit=max_runs)
    targets: list[tuple[RunManifest, str, int, str]] = []
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
        if durable_api_origin != current_api_origin:
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
            raise StateError("Multiple durable runs refer to the same open pull request")
        seen.add(identity)
        targets.append((manifest, repository, number, commit_sha))

    observer = LifecycleObserver(github, store, assert_owned=assert_owned)
    observations: list[LifecycleRunObservation] = []
    for manifest, repository, number, commit_sha in targets:
        if assert_owned is not None:
            assert_owned()
        observation = observer.observe(
            manifest.run_id,
            repository=repository,
            number=number,
            expected_head_sha=commit_sha,
        )
        if assert_owned is not None:
            assert_owned()
        observations.append(
            LifecycleRunObservation(
                run_id=manifest.run_id,
                repository=repository,
                pull_request_number=number,
                observation=observation,
            )
        )
    return LifecycleSyncResult(observations=tuple(observations))


def classify_lifecycle(
    snapshot: PullRequestLifecycleSnapshot,
) -> tuple[LifecycleSignal, ...]:
    """Return deterministic blocking signals without model judgment or mutable state."""

    pull_request = snapshot.pull_request
    signals: list[LifecycleSignal] = []

    if pull_request.head_sha.casefold() != snapshot.expected_head_sha.casefold():
        signals.append(
            _signal(
                LifecycleSignalKind.HEAD_DRIFT,
                pull_request,
                evidence_key=pull_request.head_sha.casefold(),
                reason="Published pull-request head no longer matches the prepared commit",
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
        if _is_maintainer(review.author, review.author_association) and _requests_stop(review.body):
            review_version = _evidence_version(
                review.author,
                review.author_association,
                review.body,
                review.submitted_at,
            )
            signals.append(
                _signal(
                    LifecycleSignalKind.MAINTAINER_STOP,
                    pull_request,
                    evidence_key=(f"review-stop:{review.identifier}:{review_version}"),
                    reason=(
                        "A maintainer review explicitly asks the contribution or automation to stop"
                    ),
                    source_url=review.html_url,
                )
            )

    for comment_kind, comments in (
        ("issue-comment", snapshot.issue_comments),
        ("review-comment", snapshot.review_comments),
    ):
        for comment in comments:
            if _is_maintainer(comment.author, comment.author_association) and _requests_stop(
                comment.body
            ):
                comment_version = _evidence_version(
                    comment.author,
                    comment.author_association,
                    comment.body,
                    comment.updated_at,
                )
                signals.append(
                    _signal(
                        LifecycleSignalKind.MAINTAINER_STOP,
                        pull_request,
                        evidence_key=(f"{comment_kind}:{comment.identifier}:{comment_version}"),
                        reason=(
                            "A maintainer comment explicitly asks the contribution or automation "
                            "to stop"
                        ),
                        source_url=comment.html_url,
                    )
                )

    for check in _latest_check_runs(snapshot.check_runs):
        if check.status == "completed" and check.conclusion in _NONPASSING_CHECK_CONCLUSIONS:
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

    for reference in snapshot.references:
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

    # API ordering must never influence breaker trigger order or hashes.
    return tuple(
        sorted(
            signals,
            key=lambda signal: (signal.kind.value, signal.evidence_key, signal.source_url),
        )
    )


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


def _requests_stop(text: str) -> bool:
    # Mask only the negated directive itself. Skipping its whole sentence would also discard a
    # later, independent stop such as "Don't stop CI, but withdraw this contribution."
    without_negated_directives = _NEGATED_STOP_DIRECTIVE.sub("", text)
    return _MAINTAINER_STOP.search(without_negated_directives) is not None


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


def _observation_time(value: datetime | None) -> datetime:
    observed_at = value or datetime.now(UTC)
    if observed_at.tzinfo is None or observed_at.utcoffset() is None:
        raise ValueError("observation time must be timezone-aware")
    return observed_at.astimezone(UTC)


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
    "LifecycleGitHub",
    "LifecycleObservation",
    "LifecycleObserver",
    "LifecycleRunObservation",
    "LifecycleRunStore",
    "LifecycleSignal",
    "LifecycleSignalKind",
    "LifecycleStore",
    "LifecycleSyncResult",
    "PullRequestLifecycleSnapshot",
    "classify_lifecycle",
    "parse_lifecycle_snapshot_json",
    "parse_pull_request_url",
    "sync_open_pull_requests",
]
