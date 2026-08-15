"""Webhook alert delivery: payload shape, retries, and credential secrecy."""

from __future__ import annotations

import json
import re
from pathlib import Path

import httpx
import pytest

from autocontribute.alerting import send_failure_alert
from autocontribute.exceptions import ConfigurationError, StateError

WEBHOOK_URL = "https://hooks.example.invalid/services/T000/B000/secret-token"
UNIT = "autocontribute-worker.service"


@pytest.fixture
def webhook_file(tmp_path: Path) -> Path:
    credential = tmp_path / "alert-webhook"
    credential.write_text(WEBHOOK_URL + "\n", encoding="ascii")
    return credential


def _transport(
    responses: list[httpx.Response | Exception],
) -> tuple[
    httpx.MockTransport,
    list[httpx.Request],
]:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        outcome = responses[min(len(requests), len(responses)) - 1]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    return httpx.MockTransport(handler), requests


def test_delivers_slack_and_discord_compatible_payload(webhook_file: Path) -> None:
    transport, requests = _transport([httpx.Response(200)])

    send_failure_alert(
        unit=UNIT,
        webhook_file=webhook_file,
        transport=transport,
        retry_delay_seconds=0.0,
    )

    assert len(requests) == 1
    request = requests[0]
    assert request.method == "POST"
    assert str(request.url) == WEBHOOK_URL
    payload = json.loads(request.content.decode("utf-8"))
    assert payload["text"] == payload["content"]
    assert payload["source"] == "autocontribute"
    assert payload["unit"] == UNIT
    assert payload["host"]
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", payload["timestamp"])
    assert payload["text"] == (
        f"Autocontribute unit failed: {UNIT} on {payload['host']} at {payload['timestamp']}"
    )


@pytest.mark.parametrize("transient_status", [429, 500, 503])
def test_retries_transient_statuses_until_success(
    webhook_file: Path,
    transient_status: int,
) -> None:
    transport, requests = _transport([httpx.Response(transient_status), httpx.Response(204)])

    send_failure_alert(
        unit=UNIT,
        webhook_file=webhook_file,
        transport=transport,
        retry_delay_seconds=0.0,
    )

    assert len(requests) == 2


def test_gives_up_after_bounded_attempts_and_reports_status_only(webhook_file: Path) -> None:
    transport, requests = _transport([httpx.Response(500)])

    with pytest.raises(StateError, match=r"delivery failed \(HTTP 500\)$") as excinfo:
        send_failure_alert(
            unit=UNIT,
            webhook_file=webhook_file,
            transport=transport,
            retry_delay_seconds=0.0,
        )

    assert len(requests) == 3
    assert WEBHOOK_URL not in str(excinfo.value)
    assert "secret-token" not in str(excinfo.value)


@pytest.mark.parametrize("permanent_status", [301, 308, 400, 404])
def test_permanent_statuses_fail_without_retry_or_redirect(
    webhook_file: Path,
    permanent_status: int,
) -> None:
    transport, requests = _transport(
        [httpx.Response(permanent_status, headers={"location": "https://elsewhere.invalid/"})]
    )

    with pytest.raises(StateError, match=rf"delivery failed \(HTTP {permanent_status}\)$"):
        send_failure_alert(
            unit=UNIT,
            webhook_file=webhook_file,
            transport=transport,
            retry_delay_seconds=0.0,
        )

    assert len(requests) == 1


def test_network_errors_never_leak_the_url(webhook_file: Path) -> None:
    transport, requests = _transport([httpx.ConnectError(f"refused connecting to {WEBHOOK_URL}")])

    with pytest.raises(StateError, match="could not be reached") as excinfo:
        send_failure_alert(
            unit=UNIT,
            webhook_file=webhook_file,
            transport=transport,
            retry_delay_seconds=0.0,
        )

    assert len(requests) == 3
    text = str(excinfo.value)
    assert WEBHOOK_URL not in text
    assert "secret-token" not in text
    assert excinfo.value.__cause__ is None


def test_network_error_then_success_recovers(webhook_file: Path) -> None:
    transport, requests = _transport([httpx.ReadTimeout("timed out"), httpx.Response(200)])

    send_failure_alert(
        unit=UNIT,
        webhook_file=webhook_file,
        transport=transport,
        retry_delay_seconds=0.0,
    )

    assert len(requests) == 2


@pytest.mark.parametrize(
    "unit",
    ["", "unit name", "unit;$(reboot)", "unit/../other", "u" * 256],
)
def test_rejects_invalid_unit_names_before_reading_the_credential(
    tmp_path: Path,
    unit: str,
) -> None:
    absent = tmp_path / "never-read"

    with pytest.raises(ConfigurationError, match="unit name is missing or invalid"):
        send_failure_alert(unit=unit, webhook_file=absent, transport=None)


def test_missing_credential_file_is_reported_without_detail(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="credential is unavailable"):
        send_failure_alert(unit=UNIT, webhook_file=tmp_path / "absent", transport=None)


def test_symlinked_credential_file_is_refused(tmp_path: Path, webhook_file: Path) -> None:
    link = tmp_path / "linked-webhook"
    link.symlink_to(webhook_file)

    with pytest.raises(ConfigurationError, match="credential is unavailable"):
        send_failure_alert(unit=UNIT, webhook_file=link, transport=None)


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"\n",
        b"http://hooks.example.invalid/plain\n",
        b"https://\n",
        b"https://hooks.example.invalid/a b\n",
        b"https://hooks.example.invalid/one\nhttps://hooks.example.invalid/two\n",
        b"https://hooks.example.invalid/\xc3\xa9\n",
        b"https://hooks.example.invalid/" + b"a" * 2048 + b"\n",
        b"https://hooks.example.invalid/\x07bell\n",
    ],
)
def test_rejects_malformed_webhook_credentials_without_echoing_them(
    tmp_path: Path,
    content: bytes,
) -> None:
    credential = tmp_path / "alert-webhook"
    credential.write_bytes(content)

    with pytest.raises(ConfigurationError) as excinfo:
        send_failure_alert(unit=UNIT, webhook_file=credential, transport=None)

    message = str(excinfo.value)
    assert message == "The alert webhook URL must be a single https:// line"
    assert "hooks.example.invalid" not in message


def test_accepts_url_without_trailing_newline(tmp_path: Path) -> None:
    credential = tmp_path / "alert-webhook"
    credential.write_text(WEBHOOK_URL, encoding="ascii")
    transport, requests = _transport([httpx.Response(200)])

    send_failure_alert(
        unit=UNIT,
        webhook_file=credential,
        transport=transport,
        retry_delay_seconds=0.0,
    )

    assert str(requests[0].url) == WEBHOOK_URL
