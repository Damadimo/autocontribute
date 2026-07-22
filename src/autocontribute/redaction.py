"""Best-effort credential scrubbing for artifacts and model-bound text."""

from __future__ import annotations

import os
import re
from collections.abc import Iterable
from pathlib import PurePosixPath

MODEL_INPUT_REDACTION = "[REDACTED:SENSITIVE_MODEL_INPUT]"
SENSITIVE_FILE_REDACTION = "[REDACTED:SENSITIVE_FILE_CONTENT]"

_TOKEN_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
)
_AUTHORIZATION_VALUE = re.compile(
    r"(?im)(?P<prefix>\bAuthorization\s*:\s*(?:Bearer|Basic)\s+)"
    r"(?P<value>[^\s\\\"']{8,})"
)
_URL_PASSWORD = re.compile(
    r"(?i)(?P<prefix>\b[a-z][a-z0-9+.-]*://[^/\s:@]+:)"
    r"(?P<value>[^@\s/]+)(?P<suffix>@)"
)
_GENERIC_SECRET_ASSIGNMENT = re.compile(
    r"(?ix)"
    r"(?P<prefix>\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|"
    r"client[_-]?secret|private[_-]?key|secret[_-]?key)\b\s*(?::|=|=>)\s*"
    r"(?:\\?[\"'])?)"
    r"(?P<value>[A-Za-z0-9_./+=:@-]{12,})"
    r"(?P<suffix>(?:\\?[\"'])?)"
)
_SENSITIVE_ENV_NAME = re.compile(
    r"(?i)(?:^|_)(?:api[_-]?key|token|secret|password|passwd|credential|private[_-]?key)(?:_|$)"
)
_OBVIOUS_PLACEHOLDER = re.compile(
    r"(?i)(?:example|dummy|placeholder|change[-_]?me|not[-_]?a[-_]?secret|redacted|"
    r"test[-_]?only|fake|your[-_])"
)
_SENSITIVE_FILE_NAMES = {
    ".env",
    ".netrc",
    ".pypirc",
    "credentials.json",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "service-account.json",
}
_SENSITIVE_FILE_SUFFIXES = {".jks", ".key", ".keystore", ".p12", ".pem", ".pfx"}


def redact_text(text: str, *, secret_env_names: Iterable[str] = ()) -> str:
    redacted = text
    for name in secret_env_names:
        value = os.environ.get(name)
        if value and len(value) >= 8:
            redacted = redacted.replace(value, f"[REDACTED:{name}]")
    for pattern in _TOKEN_PATTERNS:
        redacted = pattern.sub("[REDACTED:CREDENTIAL]", redacted)
    redacted = _AUTHORIZATION_VALUE.sub(_redact_named_value, redacted)
    redacted = _URL_PASSWORD.sub(_redact_named_value, redacted)
    redacted = _GENERIC_SECRET_ASSIGNMENT.sub(_redact_named_value, redacted)
    return redacted


def contains_credential_material(
    text: str,
    *,
    secret_env_names: Iterable[str] = (),
) -> bool:
    """Return whether text matches a credential pattern or a configured secret value."""

    return redact_text(text, secret_env_names=secret_env_names) != text


def redact_model_input(
    text: str,
    *,
    source_path: str | None = None,
    secret_env_names: Iterable[str] = (),
) -> str:
    """Remove likely secrets immediately before text is sent to a model.

    Explicit and conventionally named secret environment variables are replaced by value. Files
    that conventionally contain private key material or live credentials are withheld wholesale;
    example environment files remain available after ordinary value-level scrubbing.
    """

    if source_path is not None and is_sensitive_path(source_path):
        return SENSITIVE_FILE_REDACTION

    redacted = text
    names = set(secret_env_names)
    names.update(name for name in os.environ if _SENSITIVE_ENV_NAME.search(name))
    for name in names:
        value = os.environ.get(name)
        if value and len(value) >= 8:
            redacted = redacted.replace(value, MODEL_INPUT_REDACTION)
    return redact_text(redacted)


def _redact_named_value(match: re.Match[str]) -> str:
    value = match.group("value")
    if _OBVIOUS_PLACEHOLDER.search(value) or value.startswith(("${", "{{")):
        return match.group(0)
    suffix = match.groupdict().get("suffix", "") or ""
    return f"{match.group('prefix')}{MODEL_INPUT_REDACTION}{suffix}"


def is_sensitive_path(path: str) -> bool:
    """Return whether a repository path conventionally contains live credentials."""

    normalized = path.replace("\\", "/").casefold()
    name = PurePosixPath(normalized).name
    if name in _SENSITIVE_FILE_NAMES:
        return True
    if name.startswith(".env.") and name not in {
        ".env.dist",
        ".env.example",
        ".env.sample",
        ".env.template",
    }:
        return True
    return PurePosixPath(name).suffix in _SENSITIVE_FILE_SUFFIXES


def truncate_artifact(text: str, *, limit: int = 100_000) -> str:
    if len(text) <= limit:
        return text
    omitted = len(text) - limit
    return f"{text[:limit]}\n\n[truncated {omitted} characters]"


__all__ = [
    "MODEL_INPUT_REDACTION",
    "SENSITIVE_FILE_REDACTION",
    "contains_credential_material",
    "is_sensitive_path",
    "redact_model_input",
    "redact_text",
    "truncate_artifact",
]
