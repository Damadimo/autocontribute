"""Deterministic, fail-closed gates over actual upstream pull-request outcomes.

This module deliberately has no GitHub client and performs no writes.  It consumes only
hash-chained publication/evaluation evidence and strictly parsed lifecycle snapshots.  Callers
that use a passing result to authorize publication must still hold the publication lease and bind
``corpus_cursor`` in the same transaction as their publication reservation.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final, Protocol, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator

from autocontribute.domain import Approval, RunManifest, RunStatus
from autocontribute.evaluation import (
    EvaluationRevision,
    EvaluationStore,
    EvaluationVerdict,
    evaluation_hash,
)
from autocontribute.exceptions import ConfigurationError, StateError
from autocontribute.github_origin import canonical_api_origin
from autocontribute.lifecycle import (
    PullRequestLifecycleSnapshot,
    classify_lifecycle,
    parse_lifecycle_snapshot_json,
    parse_pull_request_url,
)
from autocontribute.store import LifecycleSnapshot, RunStore

MANUAL_OUTCOME_COHORT_SIZE: Final = 20
MAX_OUTCOME_RUNS: Final = 10_000
_DECISION_DOMAIN: Final = b"autocontribute.upstream-outcome-decision.v1\x00"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_GITHUB_LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_MAINTAINER_ASSOCIATIONS = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})
_ADVERSE_CHECK_CONCLUSIONS = frozenset(
    {"action_required", "cancelled", "failure", "stale", "startup_failure", "timed_out"}
)
_ADVERSE_COMMIT_STATES = frozenset({"error", "failure"})
_CANONICAL_PR_EVENTS = frozenset(
    {
        "pull_request.created.response",
        "pull_request.discovered",
        "pull_request.reconciled",
    }
)
_PUBLICATION_ATTEMPT_EVENT_PREFIXES = (
    "approval.",
    "branch.",
    "commit.",
    "pull_request.",
)


class _OutcomeModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PublicationAuthorization(StrEnum):
    REVIEW_REQUIRED = "review_required"
    AUTO = "auto"
    AMBIGUOUS = "ambiguous"


class UpstreamOutcome(StrEnum):
    MERGED_AS_IS = "merged_as_is"
    PENDING = "pending"
    FAILED = "failed"
    UNKNOWN = "unknown"


class ExpertOutcome(StrEnum):
    ACCEPT_AS_IS = "accept_as_is"
    PENDING = "pending"
    FAILED = "failed"
    NOT_REQUIRED = "not_required"


class UpstreamPublicationScope(_OutcomeModel):
    """Exact identity of one independently calibrated publication stream."""

    deployment_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    publishing_login: str
    publishing_api_origin: str

    @field_validator("publishing_login")
    @classmethod
    def canonical_login(cls, value: str) -> str:
        canonical = value.strip().casefold()
        if value != canonical or not _GITHUB_LOGIN.fullmatch(canonical):
            raise ValueError("publishing_login must be a canonical GitHub login")
        return canonical

    @field_validator("publishing_api_origin")
    @classmethod
    def canonical_origin(cls, value: str) -> str:
        try:
            canonical = canonical_api_origin(value)
        except ConfigurationError as exc:
            raise ValueError("publishing_api_origin must be a canonical HTTPS origin") from exc
        if value != canonical:
            raise ValueError("publishing_api_origin must be a canonical HTTPS origin")
        return canonical


class UpstreamRunAssessment(_OutcomeModel):
    """One fixed-cohort or prior-automatic publication decision."""

    run_id: str
    repository: str | None
    authorization: PublicationAuthorization
    cohort_position: int | None = Field(default=None, ge=1)
    outcome: UpstreamOutcome
    expert_outcome: ExpertOutcome
    evaluation_verdict: EvaluationVerdict | None = None
    evaluation_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    publication_event_hashes: tuple[str, ...]
    lifecycle_fingerprints: tuple[str, ...]
    reasons: tuple[str, ...]

    @property
    def manual_member_passed(self) -> bool:
        return (
            self.authorization == PublicationAuthorization.REVIEW_REQUIRED
            and self.expert_outcome == ExpertOutcome.ACCEPT_AS_IS
            and self.outcome == UpstreamOutcome.MERGED_AS_IS
        )

    @property
    def automatic_member_passed(self) -> bool:
        return (
            self.authorization == PublicationAuthorization.AUTO
            and self.outcome == UpstreamOutcome.MERGED_AS_IS
        )


class UpstreamGateSummary(_OutcomeModel):
    """Combined manual-calibration and prior-automatic outcome gate."""

    scope: UpstreamPublicationScope
    corpus_cursor: str = Field(pattern=r"^[0-9a-f]{64}$")
    decision_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    required_manual_publications: int = MANUAL_OUTCOME_COHORT_SIZE
    exact_manual_publications: int = Field(ge=0)
    manual_cohort: tuple[UpstreamRunAssessment, ...]
    prior_automatic: tuple[UpstreamRunAssessment, ...]
    ambiguous: tuple[UpstreamRunAssessment, ...]
    manual_cohort_passed: bool
    prior_automatic_passed: bool
    gate_passed: bool
    gate_evidence: tuple[str, ...]


class _OutcomeStore(Protocol):
    def verify_event_chains(self, *, run_id: str | None = None) -> None: ...

    def oldest_runs(
        self,
        *,
        limit: int = 100,
        deployment_fingerprint: str | None = None,
    ) -> list[RunManifest]: ...

    def run_deployment_fingerprint(self, run_id: str) -> str | None: ...

    def events(self, run_id: str) -> list[dict[str, str]]: ...

    def lifecycle_snapshots(self, run_id: str) -> list[LifecycleSnapshot]: ...

    def publication_ledger_sequence(self, run_id: str) -> int: ...

    def upstream_outcome_corpus_cursor(
        self,
        deployment_fingerprint: str,
        publishing_login: str,
        publishing_api_origin: str,
        *,
        exclude_run_id: str | None = None,
    ) -> str: ...


class _EvaluationReader(Protocol):
    def list(self) -> list[EvaluationRevision]: ...


@dataclass(frozen=True, slots=True)
class _AuthorizationEvidence:
    authorization: PublicationAuthorization
    reason: str | None
    event_hashes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ExactHumanApproval:
    """One ledger-bound approval that authorized an exact publication intent."""

    approval_event_hash: str
    publication_intent_event_hash: str
    publication_intent_at: datetime


@dataclass(frozen=True, slots=True)
class _PublicationProof:
    repository: str
    event_hashes: tuple[str, ...]


class UpstreamOutcomeGate:
    """Evaluate actual-outcome evidence without mutating local or remote state."""

    def __init__(self, store: _OutcomeStore, evaluations: _EvaluationReader) -> None:
        self.store = store
        self.evaluations = evaluations

    @classmethod
    def for_store(cls, store: RunStore) -> UpstreamOutcomeGate:
        return cls(store, EvaluationStore(store))

    def summary(
        self,
        scope: UpstreamPublicationScope,
        *,
        exclude_run_id: str | None = None,
    ) -> UpstreamGateSummary:
        """Return one stable summary, rejecting evidence that changes during evaluation."""

        if exclude_run_id is not None:
            _run_id(exclude_run_id)
        cursor_before = self._corpus_cursor(
            scope,
            exclude_run_id=exclude_run_id,
        )
        summary = self._summary_once(
            scope,
            exclude_run_id=exclude_run_id,
            corpus_cursor=cursor_before,
        )
        cursor_after = self._corpus_cursor(
            scope,
            exclude_run_id=exclude_run_id,
        )
        if cursor_before != cursor_after:
            raise StateError("Upstream outcome corpus changed while the gate was computed")
        return summary

    def _corpus_cursor(
        self,
        scope: UpstreamPublicationScope,
        *,
        exclude_run_id: str | None,
    ) -> str:
        cursor = self.store.upstream_outcome_corpus_cursor(
            scope.deployment_fingerprint,
            scope.publishing_login,
            scope.publishing_api_origin,
            exclude_run_id=exclude_run_id,
        )
        try:
            return _event_hash(cursor, field="upstream outcome corpus cursor")
        except ValueError as exc:
            raise StateError("Store returned an invalid upstream outcome corpus cursor") from exc

    def _summary_once(
        self,
        scope: UpstreamPublicationScope,
        *,
        exclude_run_id: str | None,
        corpus_cursor: str,
    ) -> UpstreamGateSummary:
        self.store.verify_event_chains()
        latest_evaluations = self.evaluations.list()
        evaluations_by_run: dict[str, EvaluationRevision] = {}
        for evaluation in latest_evaluations:
            if evaluation.run_id in evaluations_by_run:
                raise StateError(f"Duplicate latest evaluation for run {evaluation.run_id}")
            evaluations_by_run[evaluation.run_id] = evaluation

        ordered_runs = self.store.oldest_runs(
            limit=MAX_OUTCOME_RUNS,
            deployment_fingerprint=scope.deployment_fingerprint,
        )
        manual: list[tuple[int, UpstreamRunAssessment]] = []
        automatic: list[UpstreamRunAssessment] = []
        ambiguous: list[UpstreamRunAssessment] = []
        excluded_candidate = False
        for manifest in ordered_runs:
            events = _validated_events(self.store, manifest)
            relation, relation_reason = _scope_relation(manifest, events, scope)
            if manifest.run_id == exclude_run_id:
                _validate_excluded_candidate(
                    manifest,
                    events,
                    relation=relation,
                    relation_reason=relation_reason,
                    scope=scope,
                )
                excluded_candidate = True
                continue
            if not _has_publication_evidence(manifest, events):
                continue
            if relation == "outside":
                continue
            authorization = _authorization(manifest, events, scope)
            if relation == "ambiguous" or authorization.authorization == (
                PublicationAuthorization.AMBIGUOUS
            ):
                ambiguous.append(
                    _unknown_assessment(
                        manifest,
                        authorization,
                        relation_reason
                        or authorization.reason
                        or "publication identity is ambiguous",
                    )
                )
                continue

            if authorization.authorization == PublicationAuthorization.REVIEW_REQUIRED:
                if manifest.status != RunStatus.PR_OPEN and not (
                    manifest.pull_request_url
                    or any(event["event_type"] in _CANONICAL_PR_EVENTS for event in events)
                ):
                    # An approved but not-yet-published manual run is not a published cohort member.
                    continue
                manual.append(
                    (
                        _publication_ledger_sequence(self.store, manifest.run_id),
                        _assess_published_run(
                            self.store,
                            manifest,
                            events,
                            authorization,
                            evaluations_by_run.get(manifest.run_id),
                            require_evaluation=True,
                        ),
                    )
                )
                continue

            if manifest.status != RunStatus.PR_OPEN:
                automatic.append(
                    _unknown_assessment(
                        manifest,
                        authorization,
                        "automatic publication has not reached a trustworthy PR_OPEN state",
                    )
                )
                continue
            automatic.append(
                _assess_published_run(
                    self.store,
                    manifest,
                    events,
                    authorization,
                    evaluation=None,
                    require_evaluation=False,
                )
            )

        if exclude_run_id is not None and not excluded_candidate:
            raise StateError(
                "The excluded run is not the exact in-scope pending automatic publication"
            )
        manual.sort(key=lambda item: item[0])
        if len({sequence for sequence, _assessment in manual}) != len(manual):
            raise StateError("Manual publications contain duplicate global ledger sequences")

        fixed_manual = tuple(
            assessment.model_copy(update={"cohort_position": position})
            for position, (_sequence, assessment) in enumerate(
                manual[:MANUAL_OUTCOME_COHORT_SIZE],
                start=1,
            )
        )
        automatic_members = tuple(automatic)
        ambiguous_members = tuple(ambiguous)
        manual_passed = len(fixed_manual) == MANUAL_OUTCOME_COHORT_SIZE and all(
            member.manual_member_passed for member in fixed_manual
        )
        automatic_passed = all(member.automatic_member_passed for member in automatic_members)
        gate_passed = manual_passed and automatic_passed and not ambiguous_members
        decision_digest = _decision_digest(
            scope,
            manual=fixed_manual,
            automatic=automatic_members,
            ambiguous=ambiguous_members,
        )
        evidence = (
            (
                f"fixed manual cohort: {len(fixed_manual)}/{MANUAL_OUTCOME_COHORT_SIZE} "
                "published PRs"
            ),
            (
                "manual merged-as-is and accept-as-is: "
                f"{sum(member.manual_member_passed for member in fixed_manual)}/"
                f"{MANUAL_OUTCOME_COHORT_SIZE} required"
            ),
            (
                "prior automatic merged-as-is: "
                f"{sum(member.automatic_member_passed for member in automatic_members)}/"
                f"{len(automatic_members)} required"
            ),
            f"ambiguous publications: {len(ambiguous_members)}/0 allowed",
            f"store-bound outcome corpus cursor: {corpus_cursor}",
            f"semantic decision digest: {decision_digest}",
        )
        return UpstreamGateSummary(
            scope=scope,
            corpus_cursor=corpus_cursor,
            decision_digest=decision_digest,
            exact_manual_publications=len(manual),
            manual_cohort=fixed_manual,
            prior_automatic=automatic_members,
            ambiguous=ambiguous_members,
            manual_cohort_passed=manual_passed,
            prior_automatic_passed=automatic_passed,
            gate_passed=gate_passed,
            gate_evidence=evidence,
        )


def _validated_events(
    store: _OutcomeStore,
    manifest: RunManifest,
) -> tuple[dict[str, str], ...]:
    if store.run_deployment_fingerprint(manifest.run_id) != manifest.deployment_fingerprint:
        raise StateError(f"Run {manifest.run_id} deployment fingerprint is not ledger-bound")
    raw_events = store.events(manifest.run_id)
    if not raw_events:
        raise StateError(f"Run {manifest.run_id} has no ledger events")
    events: list[dict[str, str]] = []
    for event in raw_events:
        if set(event) != {
            "occurred_at",
            "event_type",
            "details",
            "previous_hash",
            "event_hash",
        } or any(not isinstance(value, str) for value in event.values()):
            raise StateError(f"Run {manifest.run_id} contains malformed event evidence")
        _event_hash(event["previous_hash"], field="previous event hash")
        _event_hash(event["event_hash"], field="event hash")
        _event_time(event["occurred_at"], field="event time")
        if not event["event_type"] or event["event_type"] != event["event_type"].strip():
            raise StateError(f"Run {manifest.run_id} contains a non-canonical event type")
        events.append(dict(event))
    return tuple(events)


def _publication_ledger_sequence(store: _OutcomeStore, run_id: str) -> int:
    sequence = store.publication_ledger_sequence(run_id)
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise StateError(f"Run {run_id} has an invalid global publication ledger sequence")
    return sequence


def _has_publication_evidence(
    manifest: RunManifest,
    events: tuple[dict[str, str], ...],
) -> bool:
    if _is_verified_no_pr_compensation(manifest, events):
        return False
    if manifest.status in {RunStatus.SUBMITTING, RunStatus.PR_OPEN}:
        return True
    return any(
        event["event_type"].startswith(_PUBLICATION_ATTEMPT_EVENT_PREFIXES)
        or (
            event["event_type"].startswith("publication.")
            and event["event_type"] != "publication.context.bound"
        )
        for event in events
    )


def _is_verified_no_pr_compensation(
    manifest: RunManifest,
    events: tuple[dict[str, str], ...],
) -> bool:
    """Recognize only a terminal, durably proven publication absence.

    A gate hold authorizes an attempt, not a pull request.  Once the publisher has proved that
    no PR was created and that its exact remote branch is absent, that attempt must not poison the
    prior-automatic-PR cohort forever.  Every partial or conflicting compensation remains visible
    to the gate and therefore fails closed.
    """

    if (
        manifest.status != RunStatus.FAILED
        or manifest.candidate is None
        or not manifest.branch_name
        or manifest.pull_request_url is not None
        or manifest.pull_request_creation_started
        or manifest.pull_request_ready_started
        or manifest.pull_request_ready_completed
    ):
        return False
    event_types = [event["event_type"] for event in events]
    if any(event_type.startswith("pull_request.") for event_type in event_types):
        return False
    if any(
        event_type in {"branch.compensation.failed", "pull_request.compensation.failed"}
        for event_type in event_types
    ):
        return False

    compensations = [
        (index, event)
        for index, event in enumerate(events)
        if event["event_type"] == "publication.compensation.verified"
    ]
    transitions = [
        (index, event)
        for index, event in enumerate(events)
        if event["event_type"] == "run.transitioned"
        and _event_details(event, run_id=manifest.run_id).get("to") == RunStatus.FAILED.value
    ]
    if len(compensations) != 1 or len(transitions) != 1:
        return False
    compensation_index, compensation_event = compensations[0]
    transition_index, transition_event = transitions[0]
    compensation = _event_details(compensation_event, run_id=manifest.run_id)
    transition = _event_details(transition_event, run_id=manifest.run_id)
    if compensation_index >= transition_index or transition != {
        "from": RunStatus.SUBMITTING.value,
        "to": RunStatus.FAILED.value,
        "reason": compensation.get("reason", ""),
    }:
        return False

    holds = [
        (index, event)
        for index, event in enumerate(events)
        if event["event_type"] == "publication.gate.held"
    ]
    releases = [
        (index, event)
        for index, event in enumerate(events)
        if event["event_type"] == "publication.gate.released"
    ]
    if holds:
        if len(holds) != 1 or len(releases) != 1:
            return False
        hold_index, hold_event = holds[0]
        release_index, release_event = releases[0]
        hold = _event_details(hold_event, run_id=manifest.run_id)
        release = _event_details(release_event, run_id=manifest.run_id)
        if not (
            hold_index < compensation_index < transition_index < release_index
            and release
            == {
                "outcome": "verified_compensation",
                "corpus_cursor": hold.get("corpus_cursor", ""),
                "held_at": hold.get("held_at", ""),
                "deployment_fingerprint": hold.get("deployment_fingerprint", ""),
                "outcome_corpus_cursor": hold.get("outcome_corpus_cursor", ""),
            }
        ):
            return False
    elif releases:
        return False

    expected = {
        "repository": manifest.candidate.repository,
        "branch": manifest.branch_name,
        "commit_sha": manifest.commit_sha or "not_persisted",
    }
    absences = [
        (index, event)
        for index, event in enumerate(events)
        if event["event_type"] == "publication.absence.verified"
    ]
    base_moves = [
        (index, event)
        for index, event in enumerate(events)
        if event["event_type"] == "publication.base_moved_before_pull_request"
    ]
    branch_compensations = [
        (index, event)
        for index, event in enumerate(events)
        if event["event_type"] == "branch.compensated"
    ]

    absence_proved = False
    if len(absences) == 1 and not base_moves:
        absence_index, absence_event = absences[0]
        absence = _event_details(absence_event, run_id=manifest.run_id)
        absence_proved = (
            absence_index < compensation_index
            and compensation.get("pull_request") == "absent"
            and compensation.get("remote_branch") == "absent"
            and all(absence.get(field) == value for field, value in expected.items())
            and all(compensation.get(field) == value for field, value in expected.items())
        )
    elif len(base_moves) == 1 and not absences and len(branch_compensations) == 1:
        base_index, base_event = base_moves[0]
        branch_index, branch_event = branch_compensations[0]
        base_move = _event_details(base_event, run_id=manifest.run_id)
        branch = _event_details(branch_event, run_id=manifest.run_id)
        branch_expected = {
            "branch": expected["branch"],
            "commit_sha": expected["commit_sha"],
        }
        absence_proved = (
            base_index < branch_index < compensation_index
            and all(base_move.get(field) == value for field, value in branch_expected.items())
            and all(branch.get(field) == value for field, value in branch_expected.items())
            and all(compensation.get(field) == value for field, value in branch_expected.items())
        )
    return absence_proved


def _validate_excluded_candidate(
    manifest: RunManifest,
    events: tuple[dict[str, str], ...],
    *,
    relation: str,
    relation_reason: str | None,
    scope: UpstreamPublicationScope,
) -> None:
    if relation != "exact":
        reason = relation_reason or "run belongs to another publication identity"
        raise StateError(f"Excluded run is not the exact in-scope candidate: {reason}")
    if manifest.status == RunStatus.READY_FOR_APPROVAL:
        _validate_publication_context(manifest)
        context_events = [
            event for event in events if event["event_type"] == "publication.context.bound"
        ]
        expected_context = {
            "publishing_login": manifest.publishing_login,
            "publishing_api_origin": manifest.publishing_api_origin,
            "publication_draft": str(manifest.publication_draft).lower(),
            "publication_ready_for_review": str(manifest.publication_ready_for_review).lower(),
        }
        if (
            len(context_events) != 1
            or _event_details(
                context_events[0],
                run_id=manifest.run_id,
            )
            != expected_context
        ):
            raise StateError(
                "The excluded ready candidate lacks one exact durable publication context"
            )
        disallowed_events = {
            event["event_type"]
            for event in events
            if event["event_type"].startswith(("branch.", "commit.", "pull_request."))
            or event["event_type"] == "publication.intent.begun"
            or event["event_type"].startswith("publication.gate.")
        }
        if (
            disallowed_events
            or any(
                (
                    manifest.branch_name,
                    manifest.commit_sha,
                    manifest.pull_request_url,
                )
            )
            or (
                manifest.pull_request_creation_started
                or manifest.pull_request_ready_started
                or manifest.pull_request_ready_completed
            )
        ):
            raise StateError(
                "The excluded ready candidate already contains publication-attempt evidence"
            )
        return
    if manifest.status == RunStatus.SUBMITTING:
        authorization = _authorization(manifest, events, scope)
        if authorization.authorization != PublicationAuthorization.AUTO or any(
            event["event_type"] == "publication.gate.released" for event in events
        ):
            raise StateError(
                "The excluded submitting run lacks one exact automatic outcome-gate hold"
            )
        return
    raise StateError(
        "Only the exact ready candidate or its held submitting recovery may be excluded"
    )


def _scope_relation(
    manifest: RunManifest,
    events: tuple[dict[str, str], ...],
    scope: UpstreamPublicationScope,
) -> tuple[str, str | None]:
    logins = {manifest.publishing_login} if manifest.publishing_login is not None else set()
    origins = (
        {manifest.publishing_api_origin} if manifest.publishing_api_origin is not None else set()
    )
    for event in events:
        if event["event_type"] not in {
            "publication.context.bound",
            "publication.intent.begun",
        }:
            continue
        details = _event_details(event, run_id=manifest.run_id)
        login = details.get("publishing_login")
        origin = details.get("publishing_api_origin")
        if login is None or origin is None:
            return "ambiguous", "publication event is missing its publishing identity"
        logins.add(login)
        origins.add(origin)
    if not logins or not origins:
        return "ambiguous", "published run is missing its complete publication identity"
    if len(logins) != 1 or len(origins) != 1:
        return "ambiguous", "published run contains conflicting publication identities"
    login = logins.pop()
    origin = origins.pop()
    if login != login.casefold() or not _GITHUB_LOGIN.fullmatch(login):
        return "ambiguous", "published run has a non-canonical publishing login"
    try:
        canonical_origin = canonical_api_origin(origin)
    except ConfigurationError:
        return "ambiguous", "published run has an invalid publishing API origin"
    if canonical_origin != origin:
        return "ambiguous", "published run has a non-canonical publishing API origin"
    if login != scope.publishing_login or origin != scope.publishing_api_origin:
        return "outside", None
    return "exact", None


def _authorization(
    manifest: RunManifest,
    events: tuple[dict[str, str], ...],
    scope: UpstreamPublicationScope,
) -> _AuthorizationEvidence:
    modern = [event for event in events if event["event_type"] == "publication.gate.held"]
    legacy = [event for event in events if event["event_type"] == "publication.gate.legacy"]
    releases = [event for event in events if event["event_type"] == "publication.gate.released"]
    if legacy or len(modern) > 1:
        return _AuthorizationEvidence(
            PublicationAuthorization.AMBIGUOUS,
            "publication has legacy or duplicate automatic-gate evidence",
            tuple(event["event_hash"] for event in (*modern, *legacy, *releases)),
        )
    if modern:
        hold_index = next(index for index, event in enumerate(events) if event is modern[0])
        intent_indices = [
            index
            for index, event in enumerate(events)
            if event["event_type"] == "publication.intent.begun"
        ]
        if any(index <= hold_index for index in intent_indices):
            return _AuthorizationEvidence(
                PublicationAuthorization.AMBIGUOUS,
                "automatic publication gate was not held before publication intent",
                (modern[0]["event_hash"],),
            )
        details = _event_details(modern[0], run_id=manifest.run_id)
        if set(details) != {
            "corpus_cursor",
            "deployment_fingerprint",
            "held_at",
            "outcome_corpus_cursor",
        }:
            return _AuthorizationEvidence(
                PublicationAuthorization.AMBIGUOUS,
                "automatic publication gate has an unsupported evidence shape",
                (modern[0]["event_hash"],),
            )
        try:
            _event_hash(details["corpus_cursor"], field="evaluation corpus cursor")
            _event_hash(details["outcome_corpus_cursor"], field="outcome corpus cursor")
            _event_hash(details["deployment_fingerprint"], field="deployment fingerprint")
            held_at = _event_time(details["held_at"], field="publication gate hold time")
            recorded_at = _event_time(
                modern[0]["occurred_at"],
                field="publication gate event time",
            )
        except (TypeError, ValueError):
            return _AuthorizationEvidence(
                PublicationAuthorization.AMBIGUOUS,
                "automatic publication gate contains invalid values",
                (modern[0]["event_hash"],),
            )
        if held_at > recorded_at:
            return _AuthorizationEvidence(
                PublicationAuthorization.AMBIGUOUS,
                "automatic publication gate time is later than its durable event",
                (modern[0]["event_hash"],),
            )
        if (
            details["deployment_fingerprint"] != scope.deployment_fingerprint
            or details["deployment_fingerprint"] != manifest.deployment_fingerprint
        ):
            return _AuthorizationEvidence(
                PublicationAuthorization.AMBIGUOUS,
                "automatic publication gate belongs to another deployment",
                (modern[0]["event_hash"],),
            )
        return _AuthorizationEvidence(
            PublicationAuthorization.AUTO,
            None,
            (modern[0]["event_hash"],),
        )

    if releases:
        return _AuthorizationEvidence(
            PublicationAuthorization.AMBIGUOUS,
            "publication gate release lacks its automatic hold evidence",
            tuple(event["event_hash"] for event in releases),
        )
    approval = classify_exact_human_approval(manifest, events)
    if approval is None:
        return _AuthorizationEvidence(
            PublicationAuthorization.AMBIGUOUS,
            "publication is neither exact human-approved nor provably automatic",
            (),
        )
    return _AuthorizationEvidence(
        PublicationAuthorization.REVIEW_REQUIRED,
        None,
        (approval.approval_event_hash,),
    )


def classify_exact_human_approval(
    manifest: RunManifest,
    events: tuple[dict[str, str], ...],
) -> ExactHumanApproval | None:
    """Classify an approval only when the exact ledger intent follows it while live.

    Event-chain integrity remains the caller's responsibility.  Production callers must verify
    the selected run's hash chain before treating this classification as recovery authority.
    """

    if any(
        event["event_type"]
        in {
            "publication.gate.held",
            "publication.gate.legacy",
            "publication.gate.released",
        }
        for event in events
    ):
        return None
    approval = manifest.approval
    approval_events = [event for event in events if event["event_type"] == "approval.created"]
    if approval is None or len(approval_events) != 1:
        return None
    event = approval_events[0]
    try:
        details = _event_details(event, run_id=manifest.run_id)
        _validate_approval_values(approval, manifest, event, details)
        approval_index = next(index for index, item in enumerate(events) if item is event)
        intent_events = [
            (index, item)
            for index, item in enumerate(events)
            if item["event_type"] == "publication.intent.begun"
        ]
        if len(intent_events) != 1:
            return None
        intent_index, intent = intent_events[0]
        approved_at = _aware_utc(approval.approved_at, field="approval time")
        expires_at = _aware_utc(approval.expires_at, field="approval expiry")
        intent_at = _event_time(intent["occurred_at"], field="publication intent time")
        if approval_index >= intent_index or not approved_at <= intent_at < expires_at:
            return None
        approval_event_hash = _event_hash(
            event["event_hash"],
            field="approval event hash",
        )
        intent_event_hash = _event_hash(
            intent["event_hash"],
            field="publication intent event hash",
        )
    except (StateError, TypeError, ValueError):
        return None
    return ExactHumanApproval(
        approval_event_hash=approval_event_hash,
        publication_intent_event_hash=intent_event_hash,
        publication_intent_at=intent_at,
    )


def _validate_approval_values(
    approval: Approval,
    manifest: RunManifest,
    event: dict[str, str],
    details: dict[str, str],
) -> None:
    if set(details) != {"actor", "expires_at", "manifest_hash"}:
        raise ValueError("approval event has unsupported fields")
    if (
        not approval.actor.strip()
        or not approval.attestation.strip()
        or manifest.publishing_login is None
        or approval.actor != manifest.publishing_login
        or details["actor"] != approval.actor
        or details["manifest_hash"] != approval.manifest_hash
        or details["expires_at"] != approval.expires_at.isoformat()
        or not _SHA256.fullmatch(approval.manifest_hash)
    ):
        raise ValueError("approval does not match its durable event")
    approved_at = _aware_utc(approval.approved_at, field="approval time")
    expires_at = _aware_utc(approval.expires_at, field="approval expiry")
    recorded_at = _event_time(event["occurred_at"], field="approval event time")
    if not approved_at <= recorded_at < expires_at:
        raise ValueError("approval was not live when it was durably recorded")


def _assess_published_run(
    store: _OutcomeStore,
    manifest: RunManifest,
    events: tuple[dict[str, str], ...],
    authorization: _AuthorizationEvidence,
    evaluation: EvaluationRevision | None,
    *,
    require_evaluation: bool,
) -> UpstreamRunAssessment:
    reasons: list[str] = []
    try:
        publication = _publication_proof(manifest, events)
    except (StateError, TypeError, ValueError) as exc:
        return _unknown_assessment(manifest, authorization, str(exc))

    try:
        lifecycle_rows = store.lifecycle_snapshots(manifest.run_id)
        outcome, lifecycle_fingerprints, lifecycle_reasons = _lifecycle_outcome(
            manifest,
            lifecycle_rows,
        )
    except (StateError, TypeError, ValueError) as exc:
        outcome = UpstreamOutcome.UNKNOWN
        lifecycle_fingerprints = ()
        lifecycle_reasons = (f"lifecycle evidence is invalid: {exc}",)
    reasons.extend(lifecycle_reasons)

    if require_evaluation:
        expert_outcome, verdict, digest, expert_reason = _expert_outcome(evaluation)
        reasons.append(expert_reason)
    else:
        expert_outcome = ExpertOutcome.NOT_REQUIRED
        verdict = None
        digest = None
    return UpstreamRunAssessment(
        run_id=manifest.run_id,
        repository=publication.repository,
        authorization=authorization.authorization,
        outcome=outcome,
        expert_outcome=expert_outcome,
        evaluation_verdict=verdict,
        evaluation_hash=digest,
        publication_event_hashes=tuple(
            dict.fromkeys((*authorization.event_hashes, *publication.event_hashes))
        ),
        lifecycle_fingerprints=lifecycle_fingerprints,
        reasons=tuple(reasons),
    )


def _unknown_assessment(
    manifest: RunManifest,
    authorization: _AuthorizationEvidence,
    reason: str,
) -> UpstreamRunAssessment:
    return UpstreamRunAssessment(
        run_id=manifest.run_id,
        repository=_repository_hint(manifest),
        authorization=PublicationAuthorization.AMBIGUOUS,
        outcome=UpstreamOutcome.UNKNOWN,
        expert_outcome=ExpertOutcome.NOT_REQUIRED,
        publication_event_hashes=authorization.event_hashes,
        lifecycle_fingerprints=(),
        reasons=(reason,),
    )


def _repository_hint(manifest: RunManifest) -> str | None:
    values = [
        value
        for value in (
            manifest.candidate.repository if manifest.candidate is not None else None,
            manifest.repository.full_name if manifest.repository is not None else None,
        )
        if value is not None
    ]
    if not values or any(
        value != value.strip() or not _REPOSITORY.fullmatch(value) for value in values
    ):
        return None
    repositories = {value.casefold() for value in values}
    return repositories.pop() if len(repositories) == 1 else None


def _validate_publication_context(manifest: RunManifest) -> None:
    required = {
        "publishing login": manifest.publishing_login,
        "publishing API origin": manifest.publishing_api_origin,
        "commit author name": manifest.commit_author_name,
        "commit author email": manifest.commit_author_email,
        "commit committer name": manifest.commit_committer_name,
        "commit committer email": manifest.commit_committer_email,
        "publication draft intent": manifest.publication_draft,
        "publication ready intent": manifest.publication_ready_for_review,
    }
    missing = [name for name, value in required.items() if value is None]
    if missing:
        raise StateError(
            f"Run {manifest.run_id} lacks durable publication context: {', '.join(missing)}"
        )
    assert manifest.publishing_login is not None
    assert manifest.publishing_api_origin is not None
    assert manifest.commit_author_name is not None
    assert manifest.commit_author_email is not None
    assert manifest.commit_committer_name is not None
    assert manifest.commit_committer_email is not None
    assert manifest.publication_draft is not None
    assert manifest.publication_ready_for_review is not None
    if (
        manifest.publishing_login != manifest.publishing_login.casefold()
        or not _GITHUB_LOGIN.fullmatch(manifest.publishing_login)
    ):
        raise StateError(f"Run {manifest.run_id} has a non-canonical publishing login")
    try:
        origin = canonical_api_origin(manifest.publishing_api_origin)
    except ConfigurationError as exc:
        raise StateError(f"Run {manifest.run_id} has an invalid publishing API origin") from exc
    if origin != manifest.publishing_api_origin:
        raise StateError(f"Run {manifest.run_id} has a non-canonical publishing API origin")
    names = (manifest.commit_author_name, manifest.commit_committer_name)
    emails = (manifest.commit_author_email, manifest.commit_committer_email)
    if any(
        not value or len(value) > 200 or any(character in value for character in ("\0", "\r", "\n"))
        for value in names
    ) or any(
        len(value) > 320
        or "@" not in value
        or any(character in value for character in ("\0", "\r", "\n", "<", ">"))
        for value in emails
    ):
        raise StateError(f"Run {manifest.run_id} has a non-canonical durable Git identity")
    if (
        manifest.commit_author_name != manifest.commit_committer_name
        or manifest.commit_author_email != manifest.commit_committer_email
    ):
        raise StateError(f"Run {manifest.run_id} has conflicting author and committer identities")
    if manifest.publication_ready_for_review and not manifest.publication_draft:
        raise StateError(f"Run {manifest.run_id} has an invalid ready-for-review intent")
    if manifest.pull_request_ready_completed and not manifest.pull_request_ready_started:
        raise StateError(
            f"Run {manifest.run_id} completed ready-for-review without a started intent"
        )
    if not manifest.publication_ready_for_review and (
        manifest.pull_request_ready_started or manifest.pull_request_ready_completed
    ):
        raise StateError(f"Run {manifest.run_id} has unexpected ready-for-review state")


def _publication_proof(
    manifest: RunManifest,
    raw_events: tuple[dict[str, str], ...],
) -> _PublicationProof:
    if manifest.status != RunStatus.PR_OPEN:
        raise StateError(f"Run {manifest.run_id} is not durably PR_OPEN")
    required = {
        "candidate": manifest.candidate,
        "repository": manifest.repository,
        "base SHA": manifest.base_sha,
        "branch": manifest.branch_name,
        "commit SHA": manifest.commit_sha,
        "pull-request URL": manifest.pull_request_url,
    }
    missing = [name for name, value in required.items() if value is None]
    if missing:
        raise StateError(f"Run {manifest.run_id} lacks publication proof: {', '.join(missing)}")
    assert manifest.candidate is not None
    assert manifest.repository is not None
    assert manifest.base_sha is not None
    assert manifest.branch_name is not None
    assert manifest.commit_sha is not None
    assert manifest.pull_request_url is not None
    _validate_publication_context(manifest)
    assert manifest.publishing_login is not None
    assert manifest.publishing_api_origin is not None
    assert manifest.commit_author_name is not None
    assert manifest.commit_author_email is not None
    assert manifest.commit_committer_name is not None
    assert manifest.commit_committer_email is not None
    assert manifest.publication_draft is not None
    assert manifest.publication_ready_for_review is not None
    if not _GIT_SHA.fullmatch(manifest.commit_sha):
        raise StateError(f"Run {manifest.run_id} has a non-canonical contribution commit")
    if not _GIT_SHA.fullmatch(manifest.base_sha):
        raise StateError(f"Run {manifest.run_id} has a non-canonical base commit")
    if (
        not manifest.branch_name
        or len(manifest.branch_name) > 255
        or manifest.branch_name != manifest.branch_name.strip()
        or "\0" in manifest.branch_name
    ):
        raise StateError(f"Run {manifest.run_id} has a non-canonical publication branch")
    if not manifest.pull_request_creation_started:
        raise StateError(f"Run {manifest.run_id} lacks its pull-request creation marker")
    repository_hint = _repository_hint(manifest)
    if repository_hint is None:
        raise StateError(f"Run {manifest.run_id} has conflicting repository proof")
    repository, number = parse_pull_request_url(
        manifest.pull_request_url,
        api_origin=manifest.publishing_api_origin,
    )
    if repository.casefold() != repository_hint:
        raise StateError(f"Run {manifest.run_id} has conflicting repository proof")

    events = tuple(raw_events)
    intent_indices = [
        index
        for index, event in enumerate(events)
        if event["event_type"] == "publication.intent.begun"
    ]
    if len(intent_indices) != 1:
        raise StateError(f"Run {manifest.run_id} lacks one publication intent")
    intent_index = intent_indices[0]
    expected_intent = {
        "repository": repository.casefold(),
        "branch": manifest.branch_name,
        "draft": "true" if manifest.publication_draft else "false",
        "ready_for_review": "true" if manifest.publication_ready_for_review else "false",
        "publishing_login": manifest.publishing_login,
        "publishing_api_origin": manifest.publishing_api_origin,
        "commit_author_name": manifest.commit_author_name,
        "commit_author_email": manifest.commit_author_email,
        "commit_committer_name": manifest.commit_committer_name,
        "commit_committer_email": manifest.commit_committer_email,
    }
    if _event_details(events[intent_index], run_id=manifest.run_id) != expected_intent:
        raise StateError(f"Run {manifest.run_id} publication intent disagrees with its manifest")

    canonical_indices: list[int] = []
    terminal_canonical_indices: list[int] = []
    for index, event in enumerate(events):
        event_type = event["event_type"]
        if event_type not in _CANONICAL_PR_EVENTS:
            continue
        details = _event_details(event, run_id=manifest.run_id)
        if _canonical_pr_event_matches(
            event_type,
            details,
            manifest=manifest,
            repository=repository,
            number=number,
        ):
            canonical_indices.append(index)
            if details.get("state") in {"closed", "closed_unmerged", "merged"}:
                terminal_canonical_indices.append(index)
    if not canonical_indices:
        raise StateError(f"Run {manifest.run_id} lacks canonical pull-request evidence")

    ready_started = [
        index
        for index, event in enumerate(events)
        if event["event_type"] == "pull_request.ready_for_review.started"
        and _ready_for_review_event_matches(
            _event_details(event, run_id=manifest.run_id),
            manifest=manifest,
            repository=repository,
            number=number,
        )
    ]
    ready_completed = [
        index
        for index, event in enumerate(events)
        if event["event_type"] == "pull_request.ready_for_review.completed"
        and _ready_for_review_event_matches(
            _event_details(event, run_id=manifest.run_id),
            manifest=manifest,
            repository=repository,
            number=number,
        )
    ]
    all_ready_events = [
        event
        for event in events
        if event["event_type"]
        in {
            "pull_request.ready_for_review.started",
            "pull_request.ready_for_review.completed",
        }
    ]
    if manifest.publication_ready_for_review:
        if manifest.pull_request_ready_started != (len(ready_started) == 1):
            raise StateError(
                f"Run {manifest.run_id} has inconsistent ready-for-review start evidence"
            )
        if manifest.pull_request_ready_completed != (len(ready_completed) == 1):
            raise StateError(
                f"Run {manifest.run_id} has inconsistent ready-for-review completion evidence"
            )
        if len(all_ready_events) != len(ready_started) + len(ready_completed):
            raise StateError(
                f"Run {manifest.run_id} has malformed or duplicate ready-for-review evidence"
            )
        if manifest.pull_request_ready_started and not manifest.pull_request_ready_completed:
            raise StateError(f"Run {manifest.run_id} has an incomplete ready-for-review transition")
    elif all_ready_events:
        raise StateError(f"Run {manifest.run_id} has unexpected ready-for-review events")

    transition_indices: list[int] = []
    for index, event in enumerate(events):
        if event["event_type"] != "run.transitioned":
            continue
        details = _event_details(event, run_id=manifest.run_id)
        if (
            details.get("from") == RunStatus.SUBMITTING.value
            and details.get("to") == RunStatus.PR_OPEN.value
            and bool(details.get("reason"))
        ):
            transition_indices.append(index)
    selected: set[int] | None = None
    for transition_index in transition_indices:
        if not manifest.publication_ready_for_review:
            canonical_index = next(
                (index for index in canonical_indices if intent_index < index < transition_index),
                None,
            )
            if canonical_index is not None:
                selected = {intent_index, canonical_index, transition_index}
                break
        elif manifest.pull_request_ready_completed:
            proof = next(
                (
                    (canonical_index, started_index, completed_index)
                    for canonical_index in canonical_indices
                    for started_index in ready_started
                    for completed_index in ready_completed
                    if (
                        intent_index
                        < canonical_index
                        < started_index
                        < completed_index
                        < transition_index
                    )
                ),
                None,
            )
            if proof is not None:
                selected = {intent_index, *proof, transition_index}
                break
        elif not manifest.pull_request_ready_started:
            canonical_index = next(
                (
                    index
                    for index in terminal_canonical_indices
                    if intent_index < index < transition_index
                ),
                None,
            )
            if canonical_index is not None:
                selected = {intent_index, canonical_index, transition_index}
                break
    if selected is None:
        raise StateError(f"Run {manifest.run_id} publication evidence is not in ledger order")
    return _PublicationProof(
        repository=repository.casefold(),
        event_hashes=tuple(events[index]["event_hash"] for index in sorted(selected)),
    )


def _canonical_pr_event_matches(
    event_type: str,
    details: dict[str, str],
    *,
    manifest: RunManifest,
    repository: str,
    number: int,
) -> bool:
    if details.get("url") != manifest.pull_request_url:
        return False
    if event_type == "pull_request.created.response":
        return (
            details.get("repository", "").casefold() == repository.casefold()
            and details.get("number") == str(number)
            and details.get("head_sha", "").casefold() == manifest.commit_sha
            and details.get("base_sha", "").casefold() == manifest.base_sha
            and details.get("state") in {"open", "closed", "merged"}
        )
    if event_type == "pull_request.discovered":
        return (
            details.get("repository", "").casefold() == repository.casefold()
            and details.get("number") == str(number)
            and details.get("head_sha", "").casefold() == manifest.commit_sha
        )
    if event_type == "pull_request.reconciled":
        return details.get("base_sha", "").casefold() == manifest.base_sha and details.get(
            "state"
        ) in {"open", "closed_unmerged", "merged"}
    return False


def _ready_for_review_event_matches(
    details: dict[str, str],
    *,
    manifest: RunManifest,
    repository: str,
    number: int,
) -> bool:
    return details == {
        "url": manifest.pull_request_url,
        "repository": repository,
        "number": str(number),
        "head_sha": manifest.commit_sha,
    }


def _lifecycle_outcome(
    manifest: RunManifest,
    rows: list[LifecycleSnapshot],
) -> tuple[UpstreamOutcome, tuple[str, ...], tuple[str, ...]]:
    if not rows:
        return UpstreamOutcome.PENDING, (), ("no lifecycle observation is available",)
    assert manifest.commit_sha is not None
    assert manifest.pull_request_url is not None
    assert manifest.publishing_api_origin is not None
    expected_repository, expected_number = parse_pull_request_url(
        manifest.pull_request_url,
        api_origin=manifest.publishing_api_origin,
    )
    parsed: list[PullRequestLifecycleSnapshot] = []
    fingerprints: list[str] = []
    previous_updated_at: datetime | None = None
    previous_timeline_item_count: int | None = None
    terminal_identity: tuple[datetime, datetime, str | None] | None = None
    node_id: str | None = None
    prepared_commit_node_id: str | None = None
    timeline_identities: dict[str, tuple[object, ...]] = {}
    reference_identities: dict[str, tuple[object, ...]] = {}
    detected_signals: list[str] = []
    incomplete_history = False
    for row in rows:
        if row.run_id != manifest.run_id:
            raise StateError("lifecycle row belongs to another run")
        snapshot = parse_lifecycle_snapshot_json(
            row.snapshot_json,
            observed_at=row.observed_at,
        )
        if snapshot.fingerprint() != row.fingerprint:
            raise StateError("lifecycle row fingerprint is inconsistent")
        pull_request = snapshot.pull_request
        if (
            snapshot.expected_head_sha != manifest.commit_sha
            or pull_request.repository.casefold() != expected_repository.casefold()
            or pull_request.number != expected_number
            or pull_request.html_url != manifest.pull_request_url
        ):
            raise StateError("lifecycle snapshot does not identify the published pull request")
        if node_id is None:
            node_id = pull_request.node_id
        elif pull_request.node_id != node_id:
            raise StateError("pull-request node identity changed across lifecycle evidence")
        if previous_updated_at is not None and pull_request.updated_at < previous_updated_at:
            raise StateError("GitHub pull-request time regressed in ledger order")
        previous_updated_at = pull_request.updated_at
        if pull_request.closed_at is not None and pull_request.closed_at > pull_request.updated_at:
            raise StateError("pull-request close time is later than its update time")
        if pull_request.merged_at is not None and pull_request.merged_at > pull_request.updated_at:
            raise StateError("pull-request merge time is later than its update time")
        if pull_request.merged:
            assert pull_request.merged_at is not None
            assert pull_request.closed_at is not None
            identity = (
                pull_request.merged_at,
                pull_request.closed_at,
                pull_request.merge_commit_sha,
            )
            if terminal_identity is None:
                terminal_identity = identity
            elif identity != terminal_identity:
                raise StateError("merged pull-request identity changed across lifecycle evidence")
        elif terminal_identity is not None:
            raise StateError("merged pull request became unmerged in later ledger evidence")

        for review in snapshot.reviews:
            if (
                review.state == "CHANGES_REQUESTED"
                and review.author_association.upper() in _MAINTAINER_ASSOCIATIONS
                and not review.author.casefold().endswith("[bot]")
            ):
                detected_signals.append(f"historical_changes_requested:{review.identifier}")
        for check in snapshot.check_runs:
            if check.status == "completed" and check.conclusion in _ADVERSE_CHECK_CONCLUSIONS:
                detected_signals.append(
                    f"historical_ci_failure:check-run:{check.identifier}:{check.conclusion}"
                )
        for status in snapshot.commit_statuses:
            if status.state in _ADVERSE_COMMIT_STATES:
                detected_signals.append(
                    f"historical_ci_failure:commit-status:{status.identifier}:{status.state}"
                )

        signals = classify_lifecycle(snapshot)
        detected_signals.extend(f"{signal.kind.value}:{signal.evidence_key}" for signal in signals)
        parsed.append(snapshot)
        fingerprints.append(row.fingerprint)
        if not snapshot.has_complete_upstream_history:
            incomplete_history = True
            continue

        commits = snapshot.commits
        timeline_events = snapshot.timeline_events
        timeline_item_count = snapshot.timeline_item_count
        if commits is None or timeline_events is None or timeline_item_count is None:
            raise StateError("complete lifecycle snapshot omits required history")
        if (
            previous_timeline_item_count is not None
            and timeline_item_count < previous_timeline_item_count
        ):
            raise StateError("GitHub pull-request timeline count regressed in ledger order")
        previous_timeline_item_count = timeline_item_count

        commit_shas = tuple(commit.sha for commit in commits)
        if commit_shas != (manifest.commit_sha,):
            detected_signals.append(
                "commit_history:pull request does not contain only the prepared commit"
            )
        else:
            commit_node_id = commits[0].node_id
            if prepared_commit_node_id is None:
                prepared_commit_node_id = commit_node_id
            elif commit_node_id != prepared_commit_node_id:
                raise StateError("prepared commit node identity changed across lifecycle evidence")

        for event in timeline_events:
            timeline_identity = (
                event.identifier,
                event.event,
                event.actor,
                event.commit_sha,
                event.created_at,
            )
            prior_identity = timeline_identities.setdefault(event.node_id, timeline_identity)
            if prior_identity != timeline_identity:
                raise StateError("pull-request timeline identity changed across lifecycle evidence")
            if event.event == "head_ref_force_pushed":
                detected_signals.append(f"head_ref_force_pushed:{event.node_id}")
            elif event.event == "reopened":
                detected_signals.append(f"close_reopen:{event.node_id}")

        for reference in snapshot.references:
            if reference.node_id is None:
                raise StateError("complete lifecycle snapshot omits a reference node identity")
            reference_identity = (
                reference.identifier,
                reference.source_url,
                reference.created_at,
            )
            prior_identity = reference_identities.setdefault(
                reference.node_id,
                reference_identity,
            )
            if prior_identity != reference_identity:
                raise StateError(
                    "pull-request reference identity changed across lifecycle evidence"
                )

    if detected_signals:
        return (
            UpstreamOutcome.FAILED,
            tuple(fingerprints),
            ("adverse lifecycle evidence: " + ", ".join(sorted(set(detected_signals))),),
        )
    if incomplete_history:
        return (
            UpstreamOutcome.UNKNOWN,
            tuple(fingerprints),
            ("lifecycle evidence lacks complete upstream history",),
        )
    if any(snapshot.pull_request.merged for snapshot in parsed):
        return (
            UpstreamOutcome.MERGED_AS_IS,
            tuple(fingerprints),
            ("GitHub proves merge on the original prepared commit with no adverse evidence",),
        )
    return (
        UpstreamOutcome.PENDING,
        tuple(fingerprints),
        ("pull request has not reached a trustworthy merged-as-is outcome",),
    )


def _expert_outcome(
    evaluation: EvaluationRevision | None,
) -> tuple[ExpertOutcome, EvaluationVerdict | None, str | None, str]:
    if evaluation is None:
        return ExpertOutcome.PENDING, None, None, "latest anchored expert evaluation is missing"
    digest = evaluation_hash(evaluation)
    if (
        evaluation.agent_prepared
        and evaluation.verdict == EvaluationVerdict.ACCEPT_AS_IS
        and not evaluation.has_safety_failure
    ):
        return (
            ExpertOutcome.ACCEPT_AS_IS,
            evaluation.verdict,
            digest,
            "latest anchored expert verdict is accept_as_is",
        )
    return (
        ExpertOutcome.FAILED,
        evaluation.verdict,
        digest,
        f"latest anchored expert verdict is {evaluation.verdict.value}",
    )


def _decision_digest(
    scope: UpstreamPublicationScope,
    *,
    manual: tuple[UpstreamRunAssessment, ...],
    automatic: tuple[UpstreamRunAssessment, ...],
    ambiguous: tuple[UpstreamRunAssessment, ...],
) -> str:
    payload = {
        "schema_version": 1,
        "scope": scope.model_dump(mode="json"),
        "manual_cohort": [_cursor_member(member) for member in manual],
        "prior_automatic": [_cursor_member(member) for member in automatic],
        "ambiguous": [_cursor_member(member) for member in ambiguous],
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(_DECISION_DOMAIN + encoded).hexdigest()


def _cursor_member(member: UpstreamRunAssessment) -> dict[str, object]:
    return {
        "run_id": member.run_id,
        "repository": member.repository,
        "authorization": member.authorization.value,
        "cohort_position": member.cohort_position,
        "outcome": member.outcome.value,
        "expert_outcome": member.expert_outcome.value,
        "evaluation_verdict": (
            member.evaluation_verdict.value if member.evaluation_verdict is not None else None
        ),
        "evaluation_hash": member.evaluation_hash,
        "publication_event_hashes": list(member.publication_event_hashes),
        "lifecycle_fingerprints": list(member.lifecycle_fingerprints),
    }


def _event_details(event: dict[str, str], *, run_id: str) -> dict[str, str]:
    raw = event.get("details")
    if not isinstance(raw, str):
        raise StateError(f"Run {run_id} event details are not text")
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise StateError(f"Run {run_id} event details are malformed") from exc
    if not isinstance(value, dict) or any(
        not isinstance(key, str) or not isinstance(item, str) for key, item in value.items()
    ):
        raise StateError(f"Run {run_id} event details are invalid")
    details = cast("dict[str, str]", value)
    if json.dumps(details, sort_keys=True, separators=(",", ":")) != raw:
        raise StateError(f"Run {run_id} event details are not canonical")
    return details


def _event_hash(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _event_time(value: object, *, field: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a canonical UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{field} must be a canonical UTC timestamp") from exc
    normalized = _aware_utc(parsed, field=field)
    if parsed.utcoffset() != UTC.utcoffset(parsed) or normalized.isoformat() != value:
        raise ValueError(f"{field} must be a canonical UTC timestamp")
    return normalized


def _aware_utc(value: datetime, *, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware")
    return value.astimezone(UTC)


def _run_id(value: str) -> str:
    if not value or value != value.strip() or len(value) > 255 or "\0" in value:
        raise ValueError("run ID must be a bounded canonical string")
    return value


__all__ = [
    "MANUAL_OUTCOME_COHORT_SIZE",
    "ExactHumanApproval",
    "ExpertOutcome",
    "PublicationAuthorization",
    "UpstreamGateSummary",
    "UpstreamOutcome",
    "UpstreamOutcomeGate",
    "UpstreamPublicationScope",
    "UpstreamRunAssessment",
    "classify_exact_human_approval",
]
