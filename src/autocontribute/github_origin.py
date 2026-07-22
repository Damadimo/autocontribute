"""Canonical GitHub API identity and credential-safe web URL derivation."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from autocontribute.exceptions import ConfigurationError

_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def canonical_api_origin(value: object) -> str:
    """Return the HTTPS origin for a GitHub API base URL, excluding its API path."""

    raw = str(value)
    try:
        parsed = urlparse(raw)
        port = parsed.port
    except ValueError as exc:
        raise ConfigurationError("GitHub API URL has an invalid authority") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise ConfigurationError("GitHub API URL must have a credential-free HTTPS origin")
    host = parsed.hostname.casefold()
    if ":" in host:
        host = f"[{host}]"
    return f"https://{host}" + (f":{port}" if port is not None else "")


def web_origin_for_api(value: object) -> str:
    """Map GitHub.com or GHES API configuration to its HTTPS web origin."""

    api_origin = canonical_api_origin(value)
    parsed = urlparse(api_origin)
    if parsed.hostname == "api.github.com":
        if parsed.port is not None:
            raise ConfigurationError("api.github.com does not support a custom API port")
        return "https://github.com"
    return api_origin


def git_push_url(value: object, repository: str) -> str:
    """Build one credential-free HTTPS Git URL on the configured GitHub web host."""

    if (
        not isinstance(repository, str)
        or not _REPOSITORY.fullmatch(repository)
        or any(part in {".", ".."} for part in repository.split("/"))
    ):
        raise ConfigurationError("Git push repository must use owner/name syntax")
    return f"{web_origin_for_api(value)}/{repository}.git"


__all__ = ["canonical_api_origin", "git_push_url", "web_origin_for_api"]
