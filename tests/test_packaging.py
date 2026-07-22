from __future__ import annotations

import hashlib
import json
import tomllib
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
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


def test_dependency_snapshot_is_locked_and_at_least_seven_days_old() -> None:
    project_root = Path(__file__).resolve().parents[1]
    project = tomllib.loads((project_root / "pyproject.toml").read_text(encoding="utf-8"))
    lock = tomllib.loads((project_root / "uv.lock").read_text(encoding="utf-8"))
    cutoff_text = project["tool"]["uv"]["exclude-newer"]

    assert isinstance(cutoff_text, str)
    assert lock["options"]["exclude-newer"] == cutoff_text
    cutoff = datetime.fromisoformat(cutoff_text.replace("Z", "+00:00"))
    assert cutoff.tzinfo is not None
    assert datetime.now(UTC) - cutoff.astimezone(UTC) >= timedelta(days=7)


def test_build_backend_is_exactly_pinned_in_the_lockfile() -> None:
    project_root = Path(__file__).resolve().parents[1]
    project = tomllib.loads((project_root / "pyproject.toml").read_text(encoding="utf-8"))
    lock = tomllib.loads((project_root / "uv.lock").read_text(encoding="utf-8"))

    assert project["build-system"]["requires"] == ["hatchling==1.27.0"]
    assert "hatchling==1.27.0" in project["project"]["optional-dependencies"]["dev"]
    locked_versions = {
        package["name"]: package["version"] for package in lock["package"] if "version" in package
    }
    assert locked_versions["hatchling"] == "1.27.0"


def test_packaged_build_identity_matches_project_material() -> None:
    project_root = Path(__file__).resolve().parents[1]
    manifest_path = project_root / "src" / "autocontribute" / "_build_identity.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert manifest == {
        "project": "autocontribute",
        "pyproject_sha256": hashlib.sha256(
            (project_root / "pyproject.toml").read_bytes()
        ).hexdigest(),
        "schema_version": 1,
        "uv_lock_sha256": hashlib.sha256((project_root / "uv.lock").read_bytes()).hexdigest(),
    }


if __name__ == "__main__":
    test_lockfile_uses_only_portable_public_sources()
    test_dependency_snapshot_is_locked_and_at_least_seven_days_old()
    test_build_backend_is_exactly_pinned_in_the_lockfile()
    test_packaged_build_identity_matches_project_material()
