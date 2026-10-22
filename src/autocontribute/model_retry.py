"""Retry decisions for failed model requests.

The SDKs never retry (``max_retries=0``), so every attempt gets its own budget reservation; the
caller asks ``retry_decision`` whether a failed attempt is worth paying for again.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

# Billing and spend limits: retrying cannot succeed until the account owner acts.
_QUOTA_CODES: Final = frozenset(
    {
        "insufficient_quota",
        "credit_balance_exhausted",
        "organization_spend_limit_exceeded",
        "project_spend_limit_exceeded",
        "organization_usage_limit_exceeded",
    }
)
# Safety stops: OpenAI asks callers not to repeat these requests.
_POLICY_CODES: Final = frozenset({"cyber_policy", "misalignment_policy_violation"})
# The only provider error codes the model worker passes to the parent.
PROVIDER_ERROR_CODES: Final = _QUOTA_CODES | _POLICY_CODES
# 529 is Anthropic's overloaded status.
_RETRIABLE_STATUSES: Final = frozenset({408, 409, 429, 500, 502, 503, 504, 529})
_FIRST_BACKOFF_SECONDS: Final = 10.0
_BACKOFF_FACTOR: Final = 3.0
_JITTER_FRACTION: Final = 0.25
MAX_RETRY_WAIT_SECONDS: Final = 120.0


@dataclass(frozen=True, slots=True)
class RetryDecision:
    retry: bool
    wait_seconds: float
    reason: str


def retry_after_seconds(headers: Mapping[str, str]) -> float | None:
    """Return the provider's requested wait from ``retry-after-ms`` or ``retry-after``.

    HTTP-date values are ignored, which leaves the caller's backoff in charge.
    """

    for name, scale in (("retry-after-ms", 1_000.0), ("retry-after", 1.0)):
        raw_value = headers.get(name)
        if raw_value is None:
            continue
        try:
            seconds = float(raw_value) / scale
        except ValueError:
            continue
        if math.isfinite(seconds) and seconds >= 0:
            return seconds
    return None


def retry_decision(
    *,
    status_code: int | None,
    provider_code: str | None,
    retry_after: float | None,
    timed_out: bool,
    attempt: int,
    jitter: float,
) -> RetryDecision:
    """Decide whether to repeat a failed model request and how long to wait first.

    ``attempt`` is the number of failed attempts so far and sets the exponential backoff when the
    provider sent no Retry-After. ``jitter`` is a uniform sample from [0, 1) that lengthens the
    wait by up to a quarter, so parallel runs do not retry in step.
    """

    if provider_code in PROVIDER_ERROR_CODES:
        status = "" if status_code is None else f"HTTP {status_code} "
        return RetryDecision(retry=False, wait_seconds=0.0, reason=f"{status}{provider_code}")
    if timed_out:
        failure = "timeout"
    elif status_code is None:
        failure = "connection error"
    elif status_code in _RETRIABLE_STATUSES:
        failure = f"HTTP {status_code}"
    else:
        return RetryDecision(retry=False, wait_seconds=0.0, reason=f"HTTP {status_code}")
    if retry_after is None:
        delay = _FIRST_BACKOFF_SECONDS * _BACKOFF_FACTOR ** (attempt - 1)
    elif retry_after > MAX_RETRY_WAIT_SECONDS:
        return RetryDecision(
            retry=False,
            wait_seconds=0.0,
            reason=(
                f"{failure}; Retry-After {retry_after:g}s exceeds the "
                f"{MAX_RETRY_WAIT_SECONDS:g}s limit"
            ),
        )
    else:
        delay = retry_after
    wait_seconds = min(delay * (1 + _JITTER_FRACTION * jitter), MAX_RETRY_WAIT_SECONDS)
    return RetryDecision(retry=True, wait_seconds=wait_seconds, reason=failure)


__all__ = [
    "MAX_RETRY_WAIT_SECONDS",
    "PROVIDER_ERROR_CODES",
    "RetryDecision",
    "retry_after_seconds",
    "retry_decision",
]
