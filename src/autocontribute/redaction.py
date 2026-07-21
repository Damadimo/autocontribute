"""Best-effort artifact scrubbing; credentials should never enter the sandbox at all."""

from __future__ import annotations

import os
import re
from collections.abc import Iterable

_TOKEN_PATTERNS = (
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
)


def redact_text(text: str, *, secret_env_names: Iterable[str] = ()) -> str:
    redacted = text
    for name in secret_env_names:
        value = os.environ.get(name)
        if value and len(value) >= 8:
            redacted = redacted.replace(value, f"[REDACTED:{name}]")
    for pattern in _TOKEN_PATTERNS:
        redacted = pattern.sub("[REDACTED:CREDENTIAL]", redacted)
    return redacted


def truncate_artifact(text: str, *, limit: int = 100_000) -> str:
    if len(text) <= limit:
        return text
    omitted = len(text) - limit
    return f"{text[:limit]}\n\n[truncated {omitted} characters]"


__all__ = ["redact_text", "truncate_artifact"]
