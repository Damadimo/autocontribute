"""One fail-closed decision over every evidence-backed autonomous-rollout gate."""

from __future__ import annotations

import hashlib
import json
from typing import Final, Protocol, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from autocontribute.evaluation import EvaluationStore, EvaluationSummary
from autocontribute.exceptions import StateError
from autocontribute.store import RunStore
from autocontribute.upstream_outcomes import (
    UpstreamGateSummary,
    UpstreamOutcomeGate,
    UpstreamPublicationScope,
)

_DECISION_DOMAIN: Final = b"autocontribute.combined-rollout-decision.v1\x00"


class _RolloutStore(Protocol):
    def evaluation_corpus_cursor(self) -> str: ...

    def upstream_outcome_corpus_cursor(
        self,
        deployment_fingerprint: str,
        publishing_login: str,
        publishing_api_origin: str,
        *,
        exclude_run_id: str | None = None,
    ) -> str: ...


class _EvaluationGate(Protocol):
    def summary(self, *, deployment_fingerprint: str) -> EvaluationSummary: ...


class _UpstreamGate(Protocol):
    def summary(
        self,
        scope: UpstreamPublicationScope,
        *,
        exclude_run_id: str | None = None,
    ) -> UpstreamGateSummary: ...


class RolloutSummary(BaseModel):
    """Stable, serializable decision over shadow and actual-upstream evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scope: UpstreamPublicationScope
    excluded_run_id: str | None = Field(default=None, min_length=1, max_length=255)
    evaluation: EvaluationSummary
    upstream_outcomes: UpstreamGateSummary
    evaluation_corpus_cursor: str = Field(pattern=r"^[0-9a-f]{64}$")
    outcome_corpus_cursor: str = Field(pattern=r"^[0-9a-f]{64}$")
    decision_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    evaluation_gate_passed: bool
    manual_cohort_passed: bool
    prior_automatic_passed: bool
    upstream_outcome_gate_passed: bool
    overall_gate_passed: bool
    gate_evidence: tuple[str, ...]

    @field_validator("excluded_run_id")
    @classmethod
    def excluded_run_is_canonical(cls, value: str | None) -> str | None:
        if value is not None and (value != value.strip() or "\0" in value):
            raise ValueError("excluded_run_id must be a bounded canonical string")
        return value

    @model_validator(mode="after")
    def decision_is_internally_consistent(self) -> Self:
        if self.evaluation.deployment_fingerprint != self.scope.deployment_fingerprint:
            raise ValueError("evaluation summary belongs to a different deployment")
        if self.upstream_outcomes.scope != self.scope:
            raise ValueError("upstream outcome summary belongs to a different publication scope")
        if self.evaluation_corpus_cursor != self.evaluation.corpus_cursor:
            raise ValueError("evaluation corpus cursors disagree")
        if self.outcome_corpus_cursor != self.upstream_outcomes.corpus_cursor:
            raise ValueError("upstream outcome corpus cursors disagree")
        if not _upstream_authorization_is_safe(self.upstream_outcomes):
            raise ValueError("passing upstream outcome gate contradicts its component results")
        expected = {
            "evaluation_gate_passed": self.evaluation.shadow_gate_passed,
            "manual_cohort_passed": self.upstream_outcomes.manual_cohort_passed,
            "prior_automatic_passed": self.upstream_outcomes.prior_automatic_passed,
            "upstream_outcome_gate_passed": self.upstream_outcomes.gate_passed,
            "overall_gate_passed": (
                self.evaluation.shadow_gate_passed and self.upstream_outcomes.gate_passed
            ),
        }
        for field, value in expected.items():
            if getattr(self, field) != value:
                raise ValueError(f"{field} disagrees with the underlying gate summaries")
        expected_digest = _decision_digest(
            self.scope,
            evaluation=self.evaluation,
            upstream_outcomes=self.upstream_outcomes,
        )
        if self.decision_digest != expected_digest:
            raise ValueError("combined rollout decision digest is invalid")
        return self


class RolloutGate:
    """Compute one scoped authorization decision and detect cross-gate evidence drift."""

    def __init__(
        self,
        store: _RolloutStore,
        evaluations: _EvaluationGate,
        upstream_outcomes: _UpstreamGate,
    ) -> None:
        self.store = store
        self.evaluations = evaluations
        self.upstream_outcomes = upstream_outcomes

    @classmethod
    def for_store(cls, store: RunStore) -> RolloutGate:
        return cls(store, EvaluationStore(store), UpstreamOutcomeGate.for_store(store))

    def summary(
        self,
        scope: UpstreamPublicationScope,
        *,
        exclude_run_id: str | None = None,
    ) -> RolloutSummary:
        """Combine both gates, rejecting a result assembled across changing evidence."""

        evaluation = self.evaluations.summary(deployment_fingerprint=scope.deployment_fingerprint)
        if evaluation.deployment_fingerprint != scope.deployment_fingerprint:
            raise StateError("Evaluation gate returned a summary for a different deployment")

        upstream = self.upstream_outcomes.summary(
            scope,
            exclude_run_id=exclude_run_id,
        )
        if upstream.scope != scope:
            raise StateError("Upstream outcome gate returned a summary for a different scope")
        if not _upstream_authorization_is_safe(upstream):
            raise StateError("Passing upstream outcome gate contradicts its component results")

        current_evaluation_cursor = self.store.evaluation_corpus_cursor()
        if current_evaluation_cursor != evaluation.corpus_cursor:
            raise StateError(
                "Evaluation corpus changed while the combined rollout gate was computed"
            )
        current_outcome_cursor = self.store.upstream_outcome_corpus_cursor(
            scope.deployment_fingerprint,
            scope.publishing_login,
            scope.publishing_api_origin,
            exclude_run_id=exclude_run_id,
        )
        if current_outcome_cursor != upstream.corpus_cursor:
            raise StateError(
                "Upstream outcome corpus changed while the combined rollout gate was computed"
            )

        decision_digest = _decision_digest(
            scope,
            evaluation=evaluation,
            upstream_outcomes=upstream,
        )
        evidence = (
            f"evaluation shadow gate: {_marker(evaluation.shadow_gate_passed)}",
            f"fixed manual upstream cohort: {_marker(upstream.manual_cohort_passed)}",
            f"prior automatic upstream outcomes: {_marker(upstream.prior_automatic_passed)}",
            f"complete upstream outcome gate: {_marker(upstream.gate_passed)}",
            (
                "combined autonomous rollout gate: "
                f"{_marker(evaluation.shadow_gate_passed and upstream.gate_passed)}"
            ),
            f"evaluation corpus cursor: {evaluation.corpus_cursor}",
            f"upstream outcome corpus cursor: {upstream.corpus_cursor}",
            f"combined semantic decision digest: {decision_digest}",
        )
        return RolloutSummary(
            scope=scope,
            excluded_run_id=exclude_run_id,
            evaluation=evaluation,
            upstream_outcomes=upstream,
            evaluation_corpus_cursor=evaluation.corpus_cursor,
            outcome_corpus_cursor=upstream.corpus_cursor,
            decision_digest=decision_digest,
            evaluation_gate_passed=evaluation.shadow_gate_passed,
            manual_cohort_passed=upstream.manual_cohort_passed,
            prior_automatic_passed=upstream.prior_automatic_passed,
            upstream_outcome_gate_passed=upstream.gate_passed,
            overall_gate_passed=(evaluation.shadow_gate_passed and upstream.gate_passed),
            gate_evidence=evidence,
        )


def _decision_digest(
    scope: UpstreamPublicationScope,
    *,
    evaluation: EvaluationSummary,
    upstream_outcomes: UpstreamGateSummary,
) -> str:
    """Hash semantic inputs only; store cursors separately bind the evidence snapshot."""

    payload = {
        "schema_version": 1,
        "scope": scope.model_dump(mode="json"),
        "evaluation": {
            "total_cases": evaluation.total_cases,
            "prepared_cases": evaluation.prepared_cases,
            "accepted_as_is": evaluation.accepted_as_is,
            "correct_abstentions": evaluation.correct_abstentions,
            "incorrect_abstentions": evaluation.incorrect_abstentions,
            "safety_failures": evaluation.safety_failures,
            "accept_as_is_precision": evaluation.accept_as_is_precision,
            "shadow_gate_passed": evaluation.shadow_gate_passed,
        },
        "upstream_outcomes": {
            "decision_digest": upstream_outcomes.decision_digest,
            "manual_cohort_passed": upstream_outcomes.manual_cohort_passed,
            "prior_automatic_passed": upstream_outcomes.prior_automatic_passed,
            "gate_passed": upstream_outcomes.gate_passed,
        },
        "overall_gate_passed": (evaluation.shadow_gate_passed and upstream_outcomes.gate_passed),
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(_DECISION_DOMAIN + encoded).hexdigest()


def _marker(passed: bool) -> str:
    return "passed" if passed else "blocked"


def _upstream_authorization_is_safe(summary: UpstreamGateSummary) -> bool:
    return not summary.gate_passed or (
        summary.manual_cohort_passed and summary.prior_automatic_passed and not summary.ambiguous
    )


__all__ = ["RolloutGate", "RolloutSummary"]
