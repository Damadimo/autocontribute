"""Per-run model budget: durable reservations, phase scopes, the run deadline and the daily cap.

The run's totals live in its manifest (``model_calls``, ``model_input_tokens``,
``model_output_tokens``, ``model_cost_usd``, ``model_seconds``) with at most one pending
``model_reservation``, and every change to them is saved with its event before the next step:

1. ``reserve`` refuses while a reservation is pending, then counts the call and saves the
   reserved input and output tokens, their worst-case cost and the request timeout
   (``model.call.started``). Only then is the request sent, with exactly that output limit and
   timeout.
2. ``settle`` charges the turn's actual usage and clears the reservation in one save
   (``model.call.completed``). Usage above the reservation or a total above the cap is saved
   first (``model.call.budget_exceeded``) and then fails the run.
3. ``record_failure`` keeps the reservation of a failed request: the provider may have billed
   anything up to it. Before a retry, ``charge_for_retry`` charges it in full.

Scopes split the run's cost cap between its phases (DESIGN §3.5). Setup, triage (with policy
classification) and the agent may each spend at most their share; the critic may spend what the
run has left, and the other caps leave it at least its floor. What each scope spent is counted in
memory: a run that crashes fails, so only the run's totals need to be durable.
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import ROUND_FLOOR, Decimal
from types import MappingProxyType
from typing import Final

from autocontribute.domain import ModelBudgetReservation, RunManifest, utc_now
from autocontribute.exceptions import (
    BudgetExhaustedError,
    ModelError,
    ModelRequestError,
    ModelTimeoutError,
    PolicyError,
    StateError,
)
from autocontribute.pricing import ModelSpec, Role, cost, tier_rates, upper_bound_cost
from autocontribute.providers import MAX_TURN_SECONDS
from autocontribute.store import RunStore
from autocontribute.transcript import TranscriptKind, Turn

_TOKENS_PER_PRICE_UNIT: Final = Decimal(1_000_000)
_DAILY_WINDOW: Final = timedelta(hours=24)
# A run starts only while the day's remaining budget holds this share of the per-run cap.
DAILY_HEADROOM_SHARE: Final = Decimal("0.25")
# Event details are bounded by the store; tool names are listed only this far.
_MAX_TOOL_NAMES_DETAIL: Final = 1_000


@dataclass(frozen=True, slots=True)
class ScopeLimits:
    """One phase's limits within a run."""

    # Turns per transcript: the agent continues one transcript through every critic round, the
    # critic starts a fresh one per round, and triage one per issue.
    max_turns: int
    # The most the phase may spend, as a share of the run's cost cap; None lets it spend what
    # the run has left.
    cap_share: Decimal | None
    # The share of the run's cost cap that the other phases' caps leave for this one.
    floor_share: Decimal = Decimal(0)


SCOPES: Final[Mapping[Role, ScopeLimits]] = MappingProxyType(
    {
        "setup": ScopeLimits(max_turns=40, cap_share=Decimal("0.15")),
        "agent": ScopeLimits(max_turns=100, cap_share=Decimal("0.55")),
        "critic": ScopeLimits(max_turns=40, cap_share=None, floor_share=Decimal("0.20")),
        "triage": ScopeLimits(max_turns=1, cap_share=Decimal("0.10")),
    }
)
# Policy classification is a one-turn transcript in the triage scope.
TRANSCRIPT_SCOPES: Final[Mapping[TranscriptKind, Role]] = MappingProxyType(
    {
        "setup": "setup",
        "agent": "agent",
        "critic": "critic",
        "triage": "triage",
        "policy": "triage",
    }
)


@dataclass(frozen=True, slots=True)
class Reservation:
    """A saved worst-case charge for one model request; send the request with these limits."""

    call: int
    scope: Role
    spec: ModelSpec
    input_tokens: int
    output_tokens: int
    cost_usd: Decimal
    timeout_seconds: float
    # The budget clock's reading when the request was reserved.
    started: float


class RunBudget:
    """The model budget and deadline of one run; create it when the run starts.

    ``assert_lease`` raises when this process no longer owns the run; it runs before every
    save, and ``reserve`` also requires a clear circuit breaker.
    """

    def __init__(
        self,
        store: RunStore,
        manifest: RunManifest,
        *,
        max_cost_usd: Decimal,
        max_model_calls: int,
        max_run_minutes: float,
        assert_lease: Callable[[], None],
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_cost_usd <= 0 or max_model_calls < 1 or max_run_minutes <= 0:
            raise ValueError("budget limits must be positive")
        self.manifest = manifest
        self.max_cost_usd = max_cost_usd
        self.max_model_calls = max_model_calls
        self._store = store
        self._assert_lease = assert_lease
        self._clock = clock
        self._deadline = clock() + max_run_minutes * 60
        self._spent: dict[Role, Decimal] = dict.fromkeys(SCOPES, Decimal(0))

    def seconds_left(self) -> float:
        """Return the time left before the run's deadline, for model and tool time alike."""

        return max(0.0, self._deadline - self._clock())

    def command_timeout(self, limit_seconds: int) -> int:
        """Return a command's timeout: ``limit_seconds`` cut to the whole seconds left."""

        return min(limit_seconds, math.floor(self.seconds_left()))

    def scope_size(self, scope: Role) -> Decimal:
        """Return the scope's cap, or for the critic its floor, in USD."""

        limits = SCOPES[scope]
        share = limits.cap_share if limits.cap_share is not None else limits.floor_share
        return share * self.max_cost_usd

    def cost_left(self, scope: Role) -> Decimal:
        """Return what the scope may still spend, in USD, counting a pending reservation."""

        pending = self.manifest.model_reservation
        left = self.max_cost_usd - self.manifest.model_cost_usd
        if pending is not None:
            left -= pending.cost_usd
        cap_share = SCOPES[scope].cap_share
        if cap_share is not None:
            left = min(left, cap_share * self.max_cost_usd - self._spent[scope])
        return max(Decimal(0), left)

    def reserve(
        self,
        scope: Role,
        spec: ModelSpec,
        *,
        input_tokens: int,
        max_output_tokens: int,
        min_output_tokens: int,
        details: Mapping[str, str],
    ) -> Reservation:
        """Save a reservation for one request and return the limits it must be sent with.

        The output limit is ``max_output_tokens``, lowered to what the scope can still pay for
        after the worst-case input; below ``min_output_tokens`` the request is refused.
        ``details`` (the transcript and turn, say) go into the event. Raises
        ``BudgetExhaustedError`` when the run's calls, the scope's cost or the run's time is
        used up.
        """

        if input_tokens < 1 or not 1 <= min_output_tokens <= max_output_tokens:
            raise ValueError("a reservation needs positive token counts")
        if max_output_tokens > spec.max_output_tokens:
            raise ValueError(f"{spec.id} returns at most {spec.max_output_tokens} output tokens")
        self._store.assert_circuit_breaker_clear()
        self._assert_lease()
        manifest = self.manifest
        if manifest.model_reservation is not None:
            raise PolicyError("A previous model-call reservation is still unresolved")
        if manifest.model_calls >= self.max_model_calls:
            raise BudgetExhaustedError(
                f"The run used all {self.max_model_calls} model calls", limit="calls"
            )
        seconds_left = self.seconds_left()
        if seconds_left < 1:
            raise BudgetExhaustedError("The run reached its time limit", limit="time")
        left = self.cost_left(scope)
        input_cost = upper_bound_cost(spec, input_tokens=input_tokens, output_tokens=0)
        affordable = (
            (left - input_cost) * _TOKENS_PER_PRICE_UNIT / tier_rates(spec, input_tokens).output
        ).to_integral_value(rounding=ROUND_FLOOR)
        output_tokens = min(max_output_tokens, int(affordable))
        if output_tokens < min_output_tokens:
            raise BudgetExhaustedError(
                f"The {scope} budget has ${left:.4f} left, too little for another request",
                limit="cost",
            )
        reserved_cost = upper_bound_cost(
            spec, input_tokens=input_tokens, output_tokens=output_tokens
        )
        timeout_seconds = min(MAX_TURN_SECONDS, seconds_left)
        manifest.model_calls += 1
        manifest.model_reservation = ModelBudgetReservation(
            call=manifest.model_calls,
            role=scope,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=reserved_cost,
            timeout_seconds=timeout_seconds,
            started_at=utc_now(),
        )
        self._store.save(
            manifest,
            event="model.call.started",
            details={
                **details,
                "scope": scope,
                "model": spec.id,
                "call": str(manifest.model_calls),
                "reserved_input_tokens": str(input_tokens),
                "reserved_output_tokens": str(output_tokens),
                "reserved_cost_usd": str(reserved_cost),
                "timeout_seconds": str(timeout_seconds),
            },
        )
        return Reservation(
            call=manifest.model_calls,
            scope=scope,
            spec=spec,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=reserved_cost,
            timeout_seconds=timeout_seconds,
            started=self._clock(),
        )

    def settle(self, reservation: Reservation, turn: Turn) -> Decimal:
        """Charge a turn's actual usage, clear its reservation, and return what it cost.

        Usage above the reservation, or a run total above the cap, is saved and then raises
        ``PolicyError``.
        """

        self._require_pending(reservation)
        self._assert_lease()
        elapsed = max(0.0, self._clock() - reservation.started)
        usage = turn.usage
        actual = cost(reservation.spec, usage)
        manifest = self.manifest
        manifest.model_input_tokens += usage.input_tokens
        manifest.model_output_tokens += usage.output_tokens
        manifest.model_cost_usd += actual
        manifest.model_seconds += elapsed
        manifest.model_reservation = None
        self._spent[reservation.scope] += actual
        violations = []
        if usage.input_tokens > reservation.input_tokens:
            violations.append("provider input usage exceeded its durable reservation")
        if usage.output_tokens > reservation.output_tokens:
            violations.append("provider output usage exceeded its durable reservation")
        if manifest.model_cost_usd > self.max_cost_usd:
            violations.append("the run's model cost exceeded its cap")
        tool_names = ",".join(call.name for call in turn.tool_calls)
        self._store.save(
            manifest,
            event="model.call.budget_exceeded" if violations else "model.call.completed",
            details={
                "scope": reservation.scope,
                "call": str(reservation.call),
                "response_id": turn.response_id,
                "model": turn.model,
                "stop": turn.stop,
                "tool_calls": tool_names[:_MAX_TOOL_NAMES_DETAIL],
                "input_tokens": str(usage.input_tokens),
                "cached_input_tokens": str(usage.cached_input_tokens),
                "cache_write_tokens": str(usage.cache_write_tokens),
                "output_tokens": str(usage.output_tokens),
                "cost_usd": str(actual),
                "elapsed_seconds": str(elapsed),
                "budget_violations": "; ".join(violations),
            },
        )
        if violations:
            raise PolicyError("; ".join(violations))
        self._store.assert_circuit_breaker_clear()
        return actual

    def record_failure(self, reservation: Reservation, error: ModelError) -> None:
        """Save a failed request. Its reservation stays pending: it may have been billed."""

        self._require_pending(reservation)
        self._assert_lease()
        elapsed = max(0.0, self._clock() - reservation.started)
        self.manifest.model_seconds += elapsed
        details = {
            "scope": reservation.scope,
            "call": str(reservation.call),
            "elapsed_seconds": str(elapsed),
            "reservation_retained": "true",
            "error": str(error)[:500],
        }
        event = "model.call.failed"
        if isinstance(error, ModelTimeoutError):
            event = "model.call.timed_out"
            details.update(
                {
                    "deadline_seconds": str(error.timeout_seconds),
                    "term_sent": str(error.term_sent).lower(),
                    "kill_sent": str(error.kill_sent).lower(),
                }
            )
        elif isinstance(error, ModelRequestError):
            details.update(
                {
                    "http_status": str(error.status_code or "none"),
                    "provider_code": error.provider_code or "none",
                }
            )
        self._store.save(self.manifest, event=event, details=details)

    def charge_for_retry(
        self, reservation: Reservation, *, wait_seconds: float, reason: str
    ) -> None:
        """Charge a failed request's reservation in full, so the retry can reserve again."""

        self._require_pending(reservation)
        self._assert_lease()
        manifest = self.manifest
        manifest.model_input_tokens += reservation.input_tokens
        manifest.model_output_tokens += reservation.output_tokens
        manifest.model_cost_usd += reservation.cost_usd
        manifest.model_reservation = None
        self._spent[reservation.scope] += reservation.cost_usd
        self._store.save(
            manifest,
            event="model.call.retry_scheduled",
            details={
                "scope": reservation.scope,
                "failed_call": str(reservation.call),
                "reason": reason,
                "reservation_settled": "charged_in_full",
                "wait_seconds": str(wait_seconds),
            },
        )

    def charge_failed_request(self, *, reason: str) -> None:
        """Charge a failed request's pending reservation in full and clear it.

        For a phase the run outlives, such as one triage question: the provider may have
        billed anything up to the reservation, so all of it counts as spent, and later requests
        can reserve again. The agent loop leaves its failed reservation pending, and the run
        fails.
        """

        pending = self.manifest.model_reservation
        if pending is None:
            return
        scope = next((name for name in SCOPES if name == pending.role), None)
        if scope is None:
            raise StateError(f"Model call {pending.call} was reserved outside the run's scopes")
        self._assert_lease()
        manifest = self.manifest
        manifest.model_input_tokens += pending.input_tokens
        manifest.model_output_tokens += pending.output_tokens
        manifest.model_cost_usd += pending.cost_usd
        manifest.model_reservation = None
        self._spent[scope] += pending.cost_usd
        self._store.save(
            manifest,
            event="model.call.failure_charged",
            details={
                "scope": scope,
                "failed_call": str(pending.call),
                "reason": reason[:500],
                "reservation_settled": "charged_in_full",
            },
        )

    def _require_pending(self, reservation: Reservation) -> None:
        pending = self.manifest.model_reservation
        if pending is None or pending.call != reservation.call:
            raise StateError(f"Model call {reservation.call} has no pending reservation")


def daily_budget_allows_run(
    store: RunStore,
    *,
    max_cost_usd_per_day: Decimal,
    max_cost_usd_per_run: Decimal,
    now: datetime | None = None,
) -> bool:
    """Return whether the last 24 hours leave room for another run.

    The spend counts every run created in that window, pending reservations included. A run
    may start while at least a quarter of the per-run cap is left; otherwise it is skipped
    with reason ``daily budget``.
    """

    since = (now or utc_now()) - _DAILY_WINDOW
    left = max_cost_usd_per_day - store.model_cost_since(since)
    return left >= max_cost_usd_per_run * DAILY_HEADROOM_SHARE


__all__ = [
    "DAILY_HEADROOM_SHARE",
    "SCOPES",
    "TRANSCRIPT_SCOPES",
    "Reservation",
    "RunBudget",
    "ScopeLimits",
    "daily_budget_allows_run",
]
