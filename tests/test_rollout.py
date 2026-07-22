from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest
from pydantic import ValidationError

from autocontribute.evaluation import EvaluationSummary
from autocontribute.exceptions import StateError
from autocontribute.rollout import RolloutGate, RolloutSummary
from autocontribute.store import RunStore
from autocontribute.upstream_outcomes import UpstreamGateSummary, UpstreamPublicationScope

DEPLOYMENT = "d" * 64
LOGIN = "octocat"
API_ORIGIN = "https://api.github.com"
EVALUATION_CURSOR = "e" * 64
OUTCOME_CURSOR = "f" * 64
OUTCOME_DECISION = "a" * 64
RUN_ID = "1234abcd"


def _scope(*, deployment: str = DEPLOYMENT) -> UpstreamPublicationScope:
    return UpstreamPublicationScope(
        deployment_fingerprint=deployment,
        publishing_login=LOGIN,
        publishing_api_origin=API_ORIGIN,
    )


def _evaluation(
    *,
    deployment: str = DEPLOYMENT,
    cursor: str = EVALUATION_CURSOR,
    passed: bool = True,
    evidence: list[str] | None = None,
) -> EvaluationSummary:
    return EvaluationSummary(
        deployment_fingerprint=deployment,
        corpus_cursor=cursor,
        total_cases=100,
        prepared_cases=20,
        accepted_as_is=20 if passed else 19,
        correct_abstentions=80,
        incorrect_abstentions=0,
        safety_failures=0,
        accept_as_is_precision=1.0 if passed else 0.95,
        shadow_gate_passed=passed,
        gate_evidence=evidence or ["evaluation evidence"],
    )


def _upstream(
    scope: UpstreamPublicationScope,
    *,
    cursor: str = OUTCOME_CURSOR,
    decision_digest: str = OUTCOME_DECISION,
    manual_passed: bool = True,
    automatic_passed: bool = True,
    gate_passed: bool | None = None,
    evidence: tuple[str, ...] = ("upstream evidence",),
) -> UpstreamGateSummary:
    effective_gate = manual_passed and automatic_passed if gate_passed is None else gate_passed
    return UpstreamGateSummary(
        scope=scope,
        corpus_cursor=cursor,
        decision_digest=decision_digest,
        exact_manual_publications=20,
        manual_cohort=(),
        prior_automatic=(),
        ambiguous=(),
        manual_cohort_passed=manual_passed,
        prior_automatic_passed=automatic_passed,
        gate_passed=effective_gate,
        gate_evidence=evidence,
    )


@dataclass
class FakeStore:
    evaluation_cursor: str = EVALUATION_CURSOR
    outcome_cursor: str = OUTCOME_CURSOR
    outcome_calls: list[tuple[str, str, str, str | None]] = field(default_factory=list)

    def evaluation_corpus_cursor(self) -> str:
        return self.evaluation_cursor

    def upstream_outcome_corpus_cursor(
        self,
        deployment_fingerprint: str,
        publishing_login: str,
        publishing_api_origin: str,
        *,
        exclude_run_id: str | None = None,
    ) -> str:
        self.outcome_calls.append(
            (
                deployment_fingerprint,
                publishing_login,
                publishing_api_origin,
                exclude_run_id,
            )
        )
        return self.outcome_cursor


@dataclass
class FakeEvaluationGate:
    result: EvaluationSummary
    deployments: list[str] = field(default_factory=list)

    def summary(self, *, deployment_fingerprint: str) -> EvaluationSummary:
        self.deployments.append(deployment_fingerprint)
        return self.result


@dataclass
class FakeUpstreamGate:
    result: UpstreamGateSummary
    calls: list[tuple[UpstreamPublicationScope, str | None]] = field(default_factory=list)

    def summary(
        self,
        scope: UpstreamPublicationScope,
        *,
        exclude_run_id: str | None = None,
    ) -> UpstreamGateSummary:
        self.calls.append((scope, exclude_run_id))
        return self.result


def _gate(
    evaluation: EvaluationSummary,
    upstream: UpstreamGateSummary,
    *,
    store: FakeStore | None = None,
) -> tuple[RolloutGate, FakeStore, FakeEvaluationGate, FakeUpstreamGate]:
    selected_store = store or FakeStore(
        evaluation_cursor=evaluation.corpus_cursor,
        outcome_cursor=upstream.corpus_cursor,
    )
    evaluation_gate = FakeEvaluationGate(evaluation)
    upstream_gate = FakeUpstreamGate(upstream)
    return (
        RolloutGate(selected_store, evaluation_gate, upstream_gate),
        selected_store,
        evaluation_gate,
        upstream_gate,
    )


def test_combined_gate_binds_exact_scope_candidate_and_both_cursors() -> None:
    scope = _scope()
    evaluation = _evaluation()
    upstream = _upstream(scope)
    gate, store, evaluation_gate, upstream_gate = _gate(evaluation, upstream)

    summary = gate.summary(scope, exclude_run_id=RUN_ID)

    assert summary.scope == scope
    assert summary.excluded_run_id == RUN_ID
    assert summary.evaluation == evaluation
    assert summary.upstream_outcomes == upstream
    assert summary.evaluation_corpus_cursor == EVALUATION_CURSOR
    assert summary.outcome_corpus_cursor == OUTCOME_CURSOR
    assert summary.evaluation_gate_passed
    assert summary.manual_cohort_passed
    assert summary.prior_automatic_passed
    assert summary.upstream_outcome_gate_passed
    assert summary.overall_gate_passed
    assert summary.decision_digest == (
        "5d4173cb2ec0eae80a7cd787d5ad55e5637d42ccfd0c38f9d6fef53524ae34e7"
    )
    assert summary.gate_evidence[-1] == (
        f"combined semantic decision digest: {summary.decision_digest}"
    )
    assert evaluation_gate.deployments == [DEPLOYMENT]
    assert upstream_gate.calls == [(scope, RUN_ID)]
    assert store.outcome_calls == [(DEPLOYMENT, LOGIN, API_ORIGIN, RUN_ID)]


def test_for_store_combines_real_empty_corpora_without_authorizing(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    scope = _scope()

    summary = RolloutGate.for_store(store).summary(scope)

    assert summary.evaluation_corpus_cursor == store.evaluation_corpus_cursor()
    assert summary.outcome_corpus_cursor == store.upstream_outcome_corpus_cursor(
        DEPLOYMENT,
        LOGIN,
        API_ORIGIN,
    )
    assert not summary.evaluation_gate_passed
    assert not summary.manual_cohort_passed
    assert summary.prior_automatic_passed
    assert not summary.upstream_outcome_gate_passed
    assert not summary.overall_gate_passed


@pytest.mark.parametrize(
    ("evaluation_passed", "manual_passed", "automatic_passed", "upstream_passed"),
    [
        (False, True, True, True),
        (True, False, True, False),
        (True, True, False, False),
        # Manual and prior-auto results alone cannot hide ambiguous upstream evidence.
        (True, True, True, False),
    ],
)
def test_semantic_failure_blocks_even_when_both_cursors_are_unchanged(
    evaluation_passed: bool,
    manual_passed: bool,
    automatic_passed: bool,
    upstream_passed: bool,
) -> None:
    scope = _scope()
    evaluation = _evaluation(passed=evaluation_passed)
    upstream = _upstream(
        scope,
        manual_passed=manual_passed,
        automatic_passed=automatic_passed,
        gate_passed=upstream_passed,
    )
    gate, *_ = _gate(evaluation, upstream)

    summary = gate.summary(scope)

    assert summary.evaluation_gate_passed is evaluation_passed
    assert summary.manual_cohort_passed is manual_passed
    assert summary.prior_automatic_passed is automatic_passed
    assert summary.upstream_outcome_gate_passed is upstream_passed
    assert not summary.overall_gate_passed
    assert summary.evaluation_corpus_cursor == EVALUATION_CURSOR
    assert summary.outcome_corpus_cursor == OUTCOME_CURSOR


def test_semantic_digest_excludes_cursors_evidence_text_and_candidate_identity() -> None:
    scope = _scope()
    first_evaluation = _evaluation(evidence=["first wording"])
    first_upstream = _upstream(scope, evidence=("first upstream wording",))
    first_gate, *_ = _gate(first_evaluation, first_upstream)
    first = first_gate.summary(scope, exclude_run_id=RUN_ID)

    second_evaluation = _evaluation(cursor="1" * 64, evidence=["second wording"])
    second_upstream = _upstream(
        scope,
        cursor="2" * 64,
        evidence=("second upstream wording",),
    )
    second_gate, *_ = _gate(second_evaluation, second_upstream)
    second = second_gate.summary(scope, exclude_run_id="ffff")

    assert first.evaluation_corpus_cursor != second.evaluation_corpus_cursor
    assert first.outcome_corpus_cursor != second.outcome_corpus_cursor
    assert first.excluded_run_id != second.excluded_run_id
    assert first.decision_digest == second.decision_digest


def test_semantic_digest_changes_with_scope_evaluation_or_outcome_decision() -> None:
    scope = _scope()
    baseline_gate, *_ = _gate(_evaluation(), _upstream(scope))
    baseline = baseline_gate.summary(scope)

    changed_evaluation = _evaluation(passed=False)
    evaluation_gate, *_ = _gate(changed_evaluation, _upstream(scope))
    changed_evaluation_summary = evaluation_gate.summary(scope)

    changed_outcome = _upstream(scope, decision_digest="b" * 64)
    outcome_gate, *_ = _gate(_evaluation(), changed_outcome)
    changed_outcome_summary = outcome_gate.summary(scope)

    other_scope = _scope(deployment="c" * 64)
    scope_gate, *_ = _gate(
        _evaluation(deployment=other_scope.deployment_fingerprint),
        _upstream(other_scope),
    )
    changed_scope_summary = scope_gate.summary(other_scope)

    assert baseline.decision_digest != changed_evaluation_summary.decision_digest
    assert baseline.decision_digest != changed_outcome_summary.decision_digest
    assert baseline.decision_digest != changed_scope_summary.decision_digest


def test_combined_gate_rejects_evaluation_drift_after_upstream_classification() -> None:
    scope = _scope()
    store = FakeStore(evaluation_cursor="0" * 64, outcome_cursor=OUTCOME_CURSOR)
    gate, *_ = _gate(_evaluation(), _upstream(scope), store=store)

    with pytest.raises(StateError, match="Evaluation corpus changed"):
        gate.summary(scope)


def test_combined_gate_rejects_outcome_drift_after_both_classifications() -> None:
    scope = _scope()
    store = FakeStore(evaluation_cursor=EVALUATION_CURSOR, outcome_cursor="0" * 64)
    gate, *_ = _gate(_evaluation(), _upstream(scope), store=store)

    with pytest.raises(StateError, match="Upstream outcome corpus changed"):
        gate.summary(scope)


def test_combined_gate_rejects_summaries_from_another_scope() -> None:
    scope = _scope()
    other_scope = _scope(deployment="c" * 64)

    wrong_evaluation_gate, *_ = _gate(
        _evaluation(deployment=other_scope.deployment_fingerprint),
        _upstream(scope),
    )
    with pytest.raises(StateError, match="different deployment"):
        wrong_evaluation_gate.summary(scope)

    wrong_upstream_gate, *_ = _gate(_evaluation(), _upstream(other_scope))
    with pytest.raises(StateError, match="different scope"):
        wrong_upstream_gate.summary(scope)


def test_combined_gate_rejects_a_passing_upstream_summary_with_failed_components() -> None:
    scope = _scope()
    contradictory = _upstream(scope, manual_passed=False, gate_passed=True)
    gate, *_ = _gate(_evaluation(), contradictory)

    with pytest.raises(StateError, match="contradicts its component results"):
        gate.summary(scope)


def test_rollout_summary_cannot_be_reconstructed_with_inconsistent_decisions() -> None:
    scope = _scope()
    gate, *_ = _gate(_evaluation(), _upstream(scope))
    summary = gate.summary(scope)
    payload = summary.model_dump(mode="python")
    payload["overall_gate_passed"] = False

    with pytest.raises(ValidationError, match="overall_gate_passed disagrees"):
        RolloutSummary.model_validate(payload)

    payload = summary.model_dump(mode="python")
    payload["decision_digest"] = "0" * 64
    with pytest.raises(ValidationError, match="decision digest is invalid"):
        RolloutSummary.model_validate(payload)
