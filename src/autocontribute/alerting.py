"""Deliver unit-failure notifications to an operator-configured webhook."""

from __future__ import annotations

import os
import re
import socket
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from autocontribute.exceptions import ConfigurationError, StateError

__all__ = ["send_failure_alert"]

_UNIT_NAME = re.compile(r"^[A-Za-z0-9@_.-]{1,255}$")
_MAX_WEBHOOK_URL_BYTES = 2048
_REQUEST_TIMEOUT_SECONDS = 10.0
_DELIVERY_ATTEMPTS = 3


def send_failure_alert(
    *,
    unit: str,
    webhook_file: Path,
    transport: httpx.BaseTransport | None = None,
    retry_delay_seconds: float = 2.0,
) -> None:
    """POST one failure notification for ``unit`` to the configured webhook.

    The webhook URL embeds a bearer-like secret, so no error raised here may
    ever contain the URL or any part of the credential file's contents.
    """

    if not _UNIT_NAME.fullmatch(unit):
        raise ConfigurationError("The alert unit name is missing or invalid")
    url = _read_webhook_url(webhook_file)
    timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    host = socket.gethostname()
    message = f"Autocontribute unit failed: {unit} on {host} at {timestamp}"
    payload = {
        # Slack-compatible and Discord-compatible bodies plus structured fields
        # so one endpoint shape serves common chat webhooks and custom sinks.
        "text": message,
        "content": message,
        "source": "autocontribute",
        "unit": unit,
        "host": host,
        "timestamp": timestamp,
    }

    last_status: int | None = None
    with httpx.Client(
        timeout=_REQUEST_TIMEOUT_SECONDS,
        transport=transport,
        follow_redirects=False,
    ) as client:
        for attempt in range(1, _DELIVERY_ATTEMPTS + 1):
            try:
                response = client.post(url, json=payload)
            except httpx.HTTPError:
                # httpx error text can embed the request URL; never propagate it.
                last_status = None
            else:
                if 200 <= response.status_code < 300:
                    return
                last_status = response.status_code
                if response.status_code < 500 and response.status_code != 429:
                    break
            if attempt < _DELIVERY_ATTEMPTS:
                time.sleep(retry_delay_seconds)
    if last_status is None:
        raise StateError("The alert webhook could not be reached")
    raise StateError(f"The alert webhook delivery failed (HTTP {last_status})")


def _read_webhook_url(webhook_file: Path) -> str:
    try:
        fd = os.open(webhook_file, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise ConfigurationError("The alert webhook credential is unavailable") from exc
    try:
        with os.fdopen(fd, "rb") as handle:
            raw = handle.read(_MAX_WEBHOOK_URL_BYTES + 1)
    except OSError as exc:
        raise ConfigurationError("The alert webhook credential is unavailable") from exc
    if len(raw) > _MAX_WEBHOOK_URL_BYTES:
        raise ConfigurationError("The alert webhook URL must be a single https:// line")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ConfigurationError("The alert webhook URL must be a single https:// line") from exc
    url = text.removesuffix("\n")
    if not url or "\n" in url or any(character.isspace() for character in url):
        raise ConfigurationError("The alert webhook URL must be a single https:// line")
    if any(not character.isprintable() for character in url):
        raise ConfigurationError("The alert webhook URL must be a single https:// line")
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise ConfigurationError("The alert webhook URL must be a single https:// line")
    return url
