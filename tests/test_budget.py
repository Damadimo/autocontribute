from __future__ import annotations

import json
from datetime import timedelta
from decimal import Decimal
from pathlib import Path

import pytest

from autocontribute.budget import (
    SCOPES,
    TRANSCRIPT_SCOPES,
    RunBudget,
    daily_budget_allows_run,
)
from autocontribute.domain import RunManifest, utc_now
from autocontribute.exceptions import (
    BudgetExhaustedError,
    ModelError,
    ModelRequestError,
    ModelTimeoutError,
    PolicyError,
    StateError,
)
from autocontribute.pricing import MODELS, ModelUsage, cost, upper_bound_cost
from autocontribute.store import RunStore
from autocontribute.transcript import ToolCall, Turn

_SOL = MODELS["gpt-5.6-sol"]
_OPUS = MODELS["claude-opus-5-5"]


class _Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def store(tmp_path: Path) -> RunStore:
    return RunStore(tmp_path / "state")


@pytest.fixture
def clock() -> _Clock:
    return _Clock()


def _budget(
    store: RunStore,
    clock: _Clock,
    *,
    max_cost: str = "10",
    max_calls: int = 200,
    minutes: float = 90,
    manifest: RunManifest | None = None,
    lease_checks: list[str] | None = None,
) -> RunBudget:
    checks = lease_checks if lease_checks is not None else []
    return RunBudget(
        store,
        manifest or store.create_run(),
        max_cost_usd=Decimal(max_cost),
        max_model_calls=max_calls,
        max_run_minutes=minutes,
        assert_lease=lambda: checks.append("lease"),
        clock=clock,
    )


def _turn(usage: ModelUsage, *, stop: str = "tool_use") -> Turn:
    calls = (
        (ToolCall(call_id="call_1", name="shell", arguments={"commands": ["ls"]}),)
        if stop == "tool_use"
        else ()
    )
    return Turn.model_validate(
        {
            "stop": stop,
            "output_items": () if stop == "max_output_tokens" else ({"type": "message"},),
            "tool_calls": calls,
            "response_id": "resp_1",
            "model": _SOL.id,
            "usage": usage,
        }
    )


def _usage(input_tokens: int, output_tokens: int, cached: int = 0) -> ModelUsage:
    return ModelUsage(
        input_tokens=input_tokens,
        cached_input_tokens=cached,
        output_tokens=output_tokens,
        total_tokens=input_tokens + output_tokens,
    )


def _events(store: RunStore, run_id: str) -> list[tuple[str, dict[str, str]]]:
    return [
        (event["event_type"], json.loads(event["details"]))
        for event in store.events(run_id)
        if event["event_type"].startswith("model.")
    ]


def test_scopes_follow_the_design_shares_and_leave_the_critic_its_floor() -> None:
    assert {scope: limits.max_turns for scope, limits in SCOPES.items()} == {
        "setup": 40,
        "agent": 100,
        "critic": 40,
        "triage": 1,
    }
    capped = [limits.cap_share for limits in SCOPES.values() if limits.cap_share is not None]
    floors = [limits.floor_share for limits in SCOPES.values()]
    assert SCOPES["critic"].cap_share is None
    assert SCOPES["critic"].floor_share == Decimal("0.20")
    assert sum(capped) + sum(floors) == 1
    assert TRANSCRIPT_SCOPES["policy"] == "triage"


def test_reservation_is_saved_before_the_request_with_the_limits_it_must_use(
    store: RunStore, clock: _Clock
) -> None:
    checks: list[str] = []
    budget = _budget(store, clock, lease_checks=checks)

    reservation = budget.reserve(
        "agent",
        _SOL,
        input_tokens=50_000,
        max_output_tokens=32_000,
        min_output_tokens=4_000,
        details={"transcript": "agent-1", "turn": "1"},
    )

    expected_cost = upper_bound_cost(_SOL, input_tokens=50_000, output_tokens=32_000)
    assert reservation.output_tokens == 32_000
    assert reservation.cost_usd == expected_cost
    assert reservation.timeout_seconds == 600
    assert checks == ["lease"]
    saved = store.get(budget.manifest.run_id)
    assert saved.model_calls == 1
    assert saved.model_reservation is not None
    assert saved.model_reservation.role == "agent"
    assert saved.model_reservation.input_tokens == 50_000
    assert saved.model_reservation.cost_usd == expected_cost
    event, details = _events(store, budget.manifest.run_id)[-1]
    assert event == "model.call.started"
    assert details["transcript"] == "agent-1"
    assert details["scope"] == "agent"
    assert details["reserved_output_tokens"] == "32000"


def test_only_one_reservation_may_be_pending(store: RunStore, clock: _Clock) -> None:
    budget = _budget(store, clock)
    budget.reserve(
        "agent",
        _SOL,
        input_tokens=1_000,
        max_output_tokens=4_000,
        min_output_tokens=4_000,
        details={},
    )

    with pytest.raises(PolicyError, match="still unresolved"):
        budget.reserve(
            "agent",
            _SOL,
            input_tokens=1_000,
            max_output_tokens=4_000,
            min_output_tokens=4_000,
            details={},
        )


def test_settlement_charges_actual_usage_and_clears_the_reservation(
    store: RunStore, clock: _Clock
) -> None:
    budget = _budget(store, clock)
    reservation = budget.reserve(
        "agent",
        _SOL,
        input_tokens=20_000,
        max_output_tokens=32_000,
        min_output_tokens=4_000,
        details={},
    )
    clock.now += 12.5
    usage = _usage(9_000, 700, cached=6_000)

    charged = budget.settle(reservation, _turn(usage))

    assert charged == cost(_SOL, usage)
    saved = store.get(budget.manifest.run_id)
    assert saved.model_reservation is None
    assert saved.model_input_tokens == 9_000
    assert saved.model_output_tokens == 700
    assert saved.model_cost_usd == charged
    assert saved.model_seconds == 12.5
    assert budget.cost_left("agent") == Decimal("5.5") - charged
    assert budget.cost_left("critic") == Decimal("10") - charged
    event, details = _events(store, budget.manifest.run_id)[-1]
    assert event == "model.call.completed"
    assert details["tool_calls"] == "shell"
    assert details["cost_usd"] == str(charged)


def test_usage_above_the_reservation_is_saved_before_the_run_fails(
    store: RunStore, clock: _Clock
) -> None:
    budget = _budget(store, clock)
    reservation = budget.reserve(
        "agent",
        _SOL,
        input_tokens=1_000,
        max_output_tokens=4_000,
        min_output_tokens=4_000,
        details={},
    )

    with pytest.raises(PolicyError, match="input usage exceeded"):
        budget.settle(reservation, _turn(_usage(1_500, 100)))

    saved = store.get(budget.manifest.run_id)
    assert saved.model_input_tokens == 1_500
    assert saved.model_reservation is None
    assert _events(store, budget.manifest.run_id)[-1][0] == "model.call.budget_exceeded"


@pytest.mark.parametrize(
    ("error", "event"),
    [
        (ModelRequestError("overloaded", status_code=529), "model.call.failed"),
        (
            ModelTimeoutError(
                timeout_seconds=600,
                elapsed_seconds=600,
                term_sent=True,
                kill_sent=False,
                child_exit_code=None,
            ),
            "model.call.timed_out",
        ),
        (ModelError("Model refused the request"), "model.call.failed"),
    ],
)
def test_a_failed_request_keeps_its_reservation(
    store: RunStore, clock: _Clock, error: ModelError, event: str
) -> None:
    budget = _budget(store, clock)
    reservation = budget.reserve(
        "critic",
        _OPUS,
        input_tokens=1_000,
        max_output_tokens=4_000,
        min_output_tokens=4_000,
        details={},
    )
    clock.now += 3

    budget.record_failure(reservation, error)

    saved = store.get(budget.manifest.run_id)
    assert saved.model_reservation is not None
    assert saved.model_reservation.call == reservation.call
    assert saved.model_cost_usd == 0
    assert saved.model_seconds == 3
    assert budget.cost_left("critic") == Decimal(10) - reservation.cost_usd
    recorded, details = _events(store, budget.manifest.run_id)[-1]
    assert recorded == event
    assert details["reservation_retained"] == "true"


def test_a_retry_charges_the_failed_reservation_in_full_before_reserving_again(
    store: RunStore, clock: _Clock
) -> None:
    budget = _budget(store, clock)
    failed = budget.reserve(
        "agent",
        _SOL,
        input_tokens=10_000,
        max_output_tokens=8_000,
        min_output_tokens=4_000,
        details={},
    )
    budget.record_failure(failed, ModelRequestError("busy", status_code=503))

    budget.charge_for_retry(failed, wait_seconds=10.0, reason="HTTP 503")
    retried = budget.reserve(
        "agent",
        _SOL,
        input_tokens=10_000,
        max_output_tokens=8_000,
        min_output_tokens=4_000,
        details={},
    )

    saved = store.get(budget.manifest.run_id)
    assert saved.model_calls == 2
    assert saved.model_input_tokens == 10_000
    assert saved.model_output_tokens == 8_000
    assert saved.model_cost_usd == failed.cost_usd
    assert saved.model_reservation is not None
    assert saved.model_reservation.call == retried.call == 2
    events = [event for event, _ in _events(store, budget.manifest.run_id)]
    assert events == [
        "model.call.started",
        "model.call.failed",
        "model.call.retry_scheduled",
        "model.call.started",
    ]


def test_settling_needs_the_pending_reservation(store: RunStore, clock: _Clock) -> None:
    budget = _budget(store, clock)
    reservation = budget.reserve(
        "agent",
        _SOL,
        input_tokens=1_000,
        max_output_tokens=4_000,
        min_output_tokens=4_000,
        details={},
    )
    budget.settle(reservation, _turn(_usage(500, 10)))

    with pytest.raises(StateError, match="no pending reservation"):
        budget.settle(reservation, _turn(_usage(500, 10)))


def test_the_output_limit_shrinks_to_what_the_scope_can_still_pay_for(
    store: RunStore, clock: _Clock
) -> None:
    # The agent's share of a $1 run is $0.55: 10,000 input tokens reserve $0.0625 at the
    # cache-write rate, which leaves $0.4875 for output at $30 per million.
    budget = _budget(store, clock, max_cost="1")

    reservation = budget.reserve(
        "agent",
        _SOL,
        input_tokens=10_000,
        max_output_tokens=32_000,
        min_output_tokens=4_000,
        details={},
    )

    assert reservation.output_tokens == 16_250
    assert reservation.cost_usd == Decimal("0.55")


def test_a_scope_that_cannot_pay_for_the_minimum_output_is_refused(
    store: RunStore, clock: _Clock
) -> None:
    # Setup may spend $0.30 of a $2 run; after $0.17, 10,000 input tokens leave room for
    # only 2,250 output tokens.
    budget = _budget(store, clock, max_cost="2")
    first = budget.reserve(
        "setup",
        _SOL,
        input_tokens=10_000,
        max_output_tokens=16_000,
        min_output_tokens=4_000,
        details={},
    )
    budget.settle(first, _turn(_usage(10_000, 4_000)))

    with pytest.raises(BudgetExhaustedError, match="setup budget") as raised:
        budget.reserve(
            "setup",
            _SOL,
            input_tokens=10_000,
            max_output_tokens=16_000,
            min_output_tokens=4_000,
            details={},
        )

    assert raised.value.limit == "cost"
    # The other scopes keep their own shares.
    assert budget.cost_left("agent") == Decimal("1.10")


def test_the_critic_may_spend_what_the_capped_scopes_left(store: RunStore, clock: _Clock) -> None:
    budget = _budget(store, clock, max_cost="1")
    agent = budget.reserve(
        "agent",
        _SOL,
        input_tokens=10_000,
        max_output_tokens=32_000,
        min_output_tokens=4_000,
        details={},
    )
    budget.settle(agent, _turn(_usage(10_000, 10_000)))

    assert budget.scope_size("critic") == Decimal("0.20")
    assert budget.cost_left("critic") == Decimal("1") - Decimal("0.35")
    assert budget.cost_left("agent") == Decimal("0.55") - Decimal("0.35")


def test_the_run_call_cap_ends_the_scope(store: RunStore, clock: _Clock) -> None:
    budget = _budget(store, clock, max_calls=1)
    reservation = budget.reserve(
        "triage",
        _SOL,
        input_tokens=1_000,
        max_output_tokens=4_000,
        min_output_tokens=4_000,
        details={},
    )
    budget.settle(reservation, _turn(_usage(500, 50)))

    with pytest.raises(BudgetExhaustedError) as raised:
        budget.reserve(
            "agent",
            _SOL,
            input_tokens=1_000,
            max_output_tokens=4_000,
            min_output_tokens=4_000,
            details={},
        )

    assert raised.value.limit == "calls"


def test_the_deadline_bounds_turn_and_command_timeouts(store: RunStore, clock: _Clock) -> None:
    budget = _budget(store, clock, minutes=15)
    clock.now += 14 * 60 + 0.5

    reservation = budget.reserve(
        "agent",
        _SOL,
        input_tokens=1_000,
        max_output_tokens=4_000,
        min_output_tokens=4_000,
        details={},
    )

    assert reservation.timeout_seconds == pytest.approx(59.5)
    assert budget.command_timeout(300) == 59
    clock.now += 60
    assert budget.seconds_left() == 0
    assert budget.command_timeout(300) == 0
    budget.settle(reservation, _turn(_usage(500, 50)))
    with pytest.raises(BudgetExhaustedError) as raised:
        budget.reserve(
            "agent",
            _SOL,
            input_tokens=1_000,
            max_output_tokens=4_000,
            min_output_tokens=4_000,
            details={},
        )
    assert raised.value.limit == "time"


def test_reservations_above_the_long_context_threshold_use_its_rates(
    store: RunStore, clock: _Clock
) -> None:
    budget = _budget(store, clock, max_cost="100")

    reservation = budget.reserve(
        "agent",
        _SOL,
        input_tokens=300_000,
        max_output_tokens=4_000,
        min_output_tokens=4_000,
        details={},
    )

    # 300,000 x $12.50 + 4,000 x $45 per million: the long tier's cache-write and output rates.
    assert reservation.cost_usd == Decimal("3.93")


def test_a_tripped_circuit_breaker_refuses_new_requests(store: RunStore, clock: _Clock) -> None:
    budget = _budget(store, clock)
    store.trip_circuit_breaker(source="test", reason="operator stop", trigger_hash="a" * 64)

    with pytest.raises(StateError, match="Circuit breaker"):
        budget.reserve(
            "agent",
            _SOL,
            input_tokens=1_000,
            max_output_tokens=4_000,
            min_output_tokens=4_000,
            details={},
        )

    assert store.get(budget.manifest.run_id).model_calls == 0


def test_daily_spend_counts_settled_cost_and_pending_reservations(
    store: RunStore, clock: _Clock
) -> None:
    settled = _budget(store, clock)
    first = settled.reserve(
        "agent",
        _SOL,
        input_tokens=100_000,
        max_output_tokens=10_000,
        min_output_tokens=4_000,
        details={},
    )
    first_cost = settled.settle(first, _turn(_usage(100_000, 10_000)))
    pending = _budget(store, clock)
    open_reservation = pending.reserve(
        "agent",
        _SOL,
        input_tokens=100_000,
        max_output_tokens=10_000,
        min_output_tokens=4_000,
        details={},
    )
    now = utc_now()

    assert store.model_cost_since(now - timedelta(hours=24)) == (
        first_cost + open_reservation.cost_usd
    )
    assert store.model_cost_since(now + timedelta(hours=1)) == 0


def test_a_run_starts_only_while_the_day_leaves_a_quarter_of_the_run_cap(
    store: RunStore, clock: _Clock
) -> None:
    budget = _budget(store, clock)
    reservation = budget.reserve(
        "agent",
        _SOL,
        input_tokens=100_000,
        max_output_tokens=10_000,
        min_output_tokens=4_000,
        details={},
    )
    spent = budget.settle(reservation, _turn(_usage(100_000, 10_000)))
    per_run = Decimal(4)

    assert daily_budget_allows_run(
        store, max_cost_usd_per_day=spent + 1, max_cost_usd_per_run=per_run
    )
    assert not daily_budget_allows_run(
        store, max_cost_usd_per_day=spent + Decimal("0.99"), max_cost_usd_per_run=per_run
    )
    # Runs created more than a day ago no longer count.
    assert daily_budget_allows_run(
        store,
        max_cost_usd_per_day=Decimal(1),
        max_cost_usd_per_run=per_run,
        now=utc_now() + timedelta(hours=25),
    )
