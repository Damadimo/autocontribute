"""Best-effort credential scrubbing for artifacts and model-bound text.

``scrub_for_model`` replaces exact host secret values and high-confidence token patterns.
``redact_text``, for artifacts and logs, also replaces URL credentials, authorization headers and
password-style assignments.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Mapping
from pathlib import PurePosixPath
from typing import Final

MODEL_INPUT_REDACTION = "[REDACTED:SENSITIVE_MODEL_INPUT]"
SENSITIVE_FILE_REDACTION = "[REDACTED:SENSITIVE_FILE_CONTENT]"
MAX_ARTIFACT_CHARACTERS: Final = 100_000
# Shorter environment values match ordinary text too often to be treated as secrets.
_MIN_SECRET_VALUE_LENGTH: Final = 8

# The credential patterns shared by model-input scrubbing, artifact redaction and publication
# checks. The diff scanner keeps its own set while any of its hits trips the global breaker.
HIGH_CONFIDENCE_TOKEN_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    (
        "GitHub token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    ),
    ("OpenAI API key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Stripe live key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b")),
    (
        "JSON Web Token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
    # A whole key block when its end marker is present, otherwise the header alone.
    (
        "private key",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
            r"(?:.*?-----END [A-Z0-9 ]*PRIVATE KEY-----)?",
            re.S,
        ),
    ),
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


def host_secret_values(env_names: Iterable[str], environ: Mapping[str, str]) -> frozenset[str]:
    """Return the values of the named variables and of every variable with a secret-like name."""

    names = {*env_names, *(name for name in environ if _SENSITIVE_ENV_NAME.search(name))}
    return frozenset(
        value for name in names if len(value := environ.get(name, "")) >= _MIN_SECRET_VALUE_LENGTH
    )


def scrub_for_model(text: str, host_values: frozenset[str]) -> str:
    """Replace exact host secret values and high-confidence tokens in text bound for a model.

    URL credentials and password assignments in repository content and tool output are almost
    always fixtures; rewriting them would change code the model has to read and edit exactly.
    """

    scrubbed = _replace_host_values(text, host_values)
    for _label, pattern in HIGH_CONFIDENCE_TOKEN_PATTERNS:
        scrubbed = pattern.sub(MODEL_INPUT_REDACTION, scrubbed)
    return scrubbed


def contains_host_secret(text: str, host_values: frozenset[str]) -> bool:
    return any(value in text for value in host_values)


def contains_high_confidence_token(text: str) -> bool:
    return any(pattern.search(text) for _label, pattern in HIGH_CONFIDENCE_TOKEN_PATTERNS)


def redact_text(text: str, *, secret_env_names: Iterable[str] = ()) -> str:
    redacted = text
    for name in secret_env_names:
        value = os.environ.get(name)
        if value and len(value) >= _MIN_SECRET_VALUE_LENGTH:
            redacted = redacted.replace(value, f"[REDACTED:{name}]")
    for _label, pattern in HIGH_CONFIDENCE_TOKEN_PATTERNS:
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

    redacted = _replace_host_values(text, host_secret_values(secret_env_names, os.environ))
    return redact_text(redacted)


def _replace_host_values(text: str, host_values: frozenset[str]) -> str:
    # Longest first, so a value that contains another is replaced whole.
    for value in sorted(host_values, key=lambda value: (-len(value), value)):
        text = text.replace(value, MODEL_INPUT_REDACTION)
    return text


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


def truncate_artifact(text: str, *, limit: int = MAX_ARTIFACT_CHARACTERS) -> str:
    if len(text) <= limit:
        return text
    omitted = len(text) - limit
    return f"{text[:limit]}\n\n[truncated {omitted} characters]"


__all__ = [
    "HIGH_CONFIDENCE_TOKEN_PATTERNS",
    "MAX_ARTIFACT_CHARACTERS",
    "MODEL_INPUT_REDACTION",
    "SENSITIVE_FILE_REDACTION",
    "contains_credential_material",
    "contains_high_confidence_token",
    "contains_host_secret",
    "host_secret_values",
    "is_sensitive_path",
    "redact_model_input",
    "redact_text",
    "scrub_for_model",
    "truncate_artifact",
]
