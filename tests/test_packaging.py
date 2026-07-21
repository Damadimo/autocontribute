from __future__ import annotations

import tomllib
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlsplit

_PUBLIC_PACKAGE_HOSTS = {"files.pythonhosted.org", "pypi.org"}


def _urls(value: object) -> Iterator[str]:
    if isinstance(value, dict):
        for nested in value.values():
            yield from _urls(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _urls(nested)
    elif isinstance(value, str) and value.startswith(("http://", "https://")):
        yield value


def test_lockfile_uses_only_portable_public_sources() -> None:
    project_root = Path(__file__).resolve().parents[1]
    lock = tomllib.loads((project_root / "uv.lock").read_text(encoding="utf-8"))
    unexpected = []
    for url in sorted(set(_urls(lock))):
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.hostname not in _PUBLIC_PACKAGE_HOSTS:
            unexpected.append(url)

    assert not unexpected, f"uv.lock contains non-public package URLs: {unexpected}"


if __name__ == "__main__":
    test_lockfile_uses_only_portable_public_sources()
