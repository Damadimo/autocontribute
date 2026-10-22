"""Operator network settings that trusted host processes inherit."""

from __future__ import annotations

import os
from typing import Final

# Host git, the model worker, and the setup egress proxy reach the network through the
# operator's proxy and trust store. Repository containers never receive these values.
_PROXY_ENVIRONMENT_NAMES: Final = (
    "ALL_PROXY",
    "GIT_SSL_CAINFO",
    "GIT_SSL_CAPATH",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "REQUESTS_CA_BUNDLE",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "all_proxy",
    "http_proxy",
    "https_proxy",
    "no_proxy",
)


def proxy_environment() -> dict[str, str]:
    """Return the operator's proxy and CA variables that are set in this process."""

    return {
        name: value
        for name in _PROXY_ENVIRONMENT_NAMES
        if (value := os.environ.get(name)) is not None
    }


__all__ = ["proxy_environment"]
