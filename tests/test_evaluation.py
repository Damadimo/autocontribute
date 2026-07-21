from __future__ import annotations

from pathlib import Path

import pytest

from autocontribute.domain import RunStatus
from autocontribute.evaluation import EvaluationStore, EvaluationVerdict
from autocontribute.exceptions import StateError
from autocontribute.store import RunStore


def test_expert_evaluation_is_immutable_and_bound_to_run(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = store.create_run()
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
    with pytest.raises(StateError, match="already has"):
        evaluations.record(
            run.run_id,
            reviewer="second-reviewer",
            verdict=EvaluationVerdict.CORRECT_ABSTENTION,
        )


def test_prepared_run_cannot_be_graded_as_an_abstention(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = store.create_run()
    run.status = RunStatus.READY_FOR_APPROVAL
    store.save(run, event="fixture.ready", details={})

    with pytest.raises(ValueError, match="prepared-artifact verdict"):
        EvaluationStore(store).record(
            run.run_id,
            reviewer="expert",
            verdict=EvaluationVerdict.CORRECT_ABSTENTION,
        )


def test_shadow_gate_requires_volume_precision_and_zero_safety_failures(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    evaluations = EvaluationStore(store)
    for index in range(100):
        run = store.create_run()
        if index < 20:
            run.status = RunStatus.READY_FOR_APPROVAL
            store.save(run, event="fixture.ready", details={})
            verdict = EvaluationVerdict.ACCEPT_AS_IS
        else:
            store.transition(run, RunStatus.DISCOVERING, reason="fixture")
            store.transition(run, RunStatus.SKIPPED, reason="fixture")
            verdict = EvaluationVerdict.CORRECT_ABSTENTION
        evaluations.record(run.run_id, reviewer="expert", verdict=verdict)

    summary = evaluations.summary()

    assert summary.total_cases == 100
    assert summary.prepared_cases == 20
    assert summary.accept_as_is_precision == 1.0
    assert summary.shadow_gate_passed


def test_one_policy_failure_blocks_shadow_gate(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    evaluations = EvaluationStore(store)
    run = store.create_run()
    store.transition(run, RunStatus.DISCOVERING, reason="fixture")
    store.transition(run, RunStatus.SKIPPED, reason="fixture")
    evaluations.record(
        run.run_id,
        reviewer="expert",
        verdict=EvaluationVerdict.CORRECT_ABSTENTION,
        policy_failure=True,
    )

    summary = evaluations.summary()

    assert summary.safety_failures == 1
    assert not summary.shadow_gate_passed
