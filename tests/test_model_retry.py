from __future__ import annotations

import httpx
import pytest

from autocontribute.model_retry import (
    MAX_RETRY_WAIT_SECONDS,
    PROVIDER_ERROR_CODES,
    RetryDecision,
    retry_after_seconds,
    retry_decision,
)

_QUOTA_CODES = (
    "insufficient_quota",
    "credit_balance_exhausted",
    "organization_spend_limit_exceeded",
    "project_spend_limit_exceeded",
    "organization_usage_limit_exceeded",
)


def _decide(
    status_code: int | None,
    *,
    provider_code: str | None = None,
    retry_after: float | None = None,
    timed_out: bool = False,
    attempt: int = 1,
    jitter: float = 0.0,
) -> RetryDecision:
    return retry_decision(
        status_code=status_code,
        provider_code=provider_code,
        retry_after=retry_after,
        timed_out=timed_out,
        attempt=attempt,
        jitter=jitter,
    )


def test_provider_error_codes_are_the_quota_and_policy_codes() -> None:
    assert (
        frozenset({*_QUOTA_CODES, "cyber_policy", "misalignment_policy_violation"})
        == PROVIDER_ERROR_CODES
    )


@pytest.mark.parametrize("status_code", [408, 409, 429, 500, 502, 503, 504, 529])
def test_transient_statuses_are_retried(status_code: int) -> None:
    assert _decide(status_code) == RetryDecision(
        retry=True, wait_seconds=10.0, reason=f"HTTP {status_code}"
    )


@pytest.mark.parametrize("status_code", [400, 401, 402, 403, 404, 413, 422, 501, 505])
def test_other_statuses_are_not_retried(status_code: int) -> None:
    assert _decide(status_code) == RetryDecision(
        retry=False, wait_seconds=0.0, reason=f"HTTP {status_code}"
    )


@pytest.mark.parametrize("provider_code", _QUOTA_CODES)
def test_quota_and_spend_limits_are_not_retried(provider_code: str) -> None:
    decision = _decide(429, provider_code=provider_code, retry_after=1.0)

    assert decision == RetryDecision(
        retry=False, wait_seconds=0.0, reason=f"HTTP 429 {provider_code}"
    )


@pytest.mark.parametrize(
    ("status_code", "provider_code"),
    [
        (None, "cyber_policy"),
        (400, "cyber_policy"),
        (500, "cyber_policy"),
        (403, "misalignment_policy_violation"),
    ],
)
def test_safety_stops_are_not_retried(status_code: int | None, provider_code: str) -> None:
    decision = _decide(status_code, provider_code=provider_code)

    assert not decision.retry
    assert decision.reason.endswith(provider_code)


def test_timeouts_and_connection_errors_are_retried() -> None:
    assert _decide(None, timed_out=True) == RetryDecision(
        retry=True, wait_seconds=10.0, reason="timeout"
    )
    assert _decide(None) == RetryDecision(retry=True, wait_seconds=10.0, reason="connection error")


@pytest.mark.parametrize(
    ("attempt", "wait_seconds"),
    [(1, 10.0), (2, 30.0), (3, 90.0), (4, MAX_RETRY_WAIT_SECONDS)],
)
def test_backoff_grows_without_retry_after_and_stops_at_the_limit(
    attempt: int,
    wait_seconds: float,
) -> None:
    assert _decide(503, attempt=attempt).wait_seconds == wait_seconds


@pytest.mark.parametrize(
    ("retry_after", "jitter", "wait_seconds"),
    [
        (0.0, 0.9, 0.0),
        (7.0, 0.0, 7.0),
        (8.0, 0.5, 9.0),
        (110.0, 0.9, MAX_RETRY_WAIT_SECONDS),
        (MAX_RETRY_WAIT_SECONDS, 0.5, MAX_RETRY_WAIT_SECONDS),
    ],
)
def test_retry_after_is_honoured_with_jitter_below_the_limit(
    retry_after: float,
    jitter: float,
    wait_seconds: float,
) -> None:
    decision = _decide(429, retry_after=retry_after, attempt=3, jitter=jitter)

    assert decision == RetryDecision(retry=True, wait_seconds=wait_seconds, reason="HTTP 429")
    assert decision.wait_seconds >= retry_after


def test_retry_after_beyond_the_limit_is_not_waited_for() -> None:
    decision = _decide(503, retry_after=600.0)

    assert decision == RetryDecision(
        retry=False,
        wait_seconds=0.0,
        reason="HTTP 503; Retry-After 600s exceeds the 120s limit",
    )


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ({"retry-after-ms": "2500", "retry-after": "9"}, 2.5),
        ({"retry-after-ms": "soon", "retry-after": "9"}, 9.0),
        ({"retry-after": "1.5"}, 1.5),
        ({"retry-after": "0"}, 0.0),
        ({"retry-after": "-1"}, None),
        ({"retry-after": "nan"}, None),
        ({"retry-after": "inf"}, None),
        ({"retry-after": "Wed, 21 Oct 2026 07:28:00 GMT"}, None),
        ({}, None),
    ],
)
def test_retry_after_reads_milliseconds_then_seconds(
    headers: dict[str, str],
    expected: float | None,
) -> None:
    assert retry_after_seconds(headers) == expected


def test_retry_after_matches_header_names_case_insensitively() -> None:
    assert retry_after_seconds(httpx.Headers({"Retry-After": "12"})) == 12.0
