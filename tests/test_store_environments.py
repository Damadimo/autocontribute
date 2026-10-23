from __future__ import annotations

import sqlite3
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from autocontribute.domain import utc_now
from autocontribute.environments import EnvironmentBaseline, EnvironmentRecipe
from autocontribute.exceptions import StateError
from autocontribute.store import RunStore

_KEY = "c" * 64


def _recipe(**changes: Any) -> EnvironmentRecipe:
    fields: dict[str, Any] = {
        "repository": "Acme/Demo",
        "language": "python",
        "base_image": "python:3.13-bookworm",
        "system_packages": ["git"],
        "setup_commands": ["uv sync --locked"],
        "build_commands": [],
        "test_command": "python -m pytest --junitxml=/tmp/ac-report.xml",
        "test_framework": "pytest",
        "test_report": "/tmp/ac-report.xml",
        "env": {"PATH": "/opt/ac/venv/bin:/usr/bin:/bin"},
        "offline_env": {},
        "fetch_tags": False,
        "fetch_submodules": False,
        "source": "detected",
        "dependency_digest": "b" * 64,
    }
    return EnvironmentRecipe.model_validate({**fields, **changes})


def _baseline() -> EnvironmentBaseline:
    return EnvironmentBaseline(
        base_sha="a" * 40,
        exit_codes=[1, 1],
        durations_seconds=[3.5, 3.25],
        per_test=True,
        timed_out=False,
        collected=3,
        pass_stable=["tests.test_a::test_ok"],
        fail_before=["tests.test_a::test_net"],
        flaky=[],
        skip=["tests.test_a::test_skip"],
        test_durations={"tests.test_a::test_ok": 0.5},
    )


def test_an_accepted_recipe_round_trips_and_is_found_case_insensitively(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    assert store.environment("acme/demo") is None

    store.save_environment(_recipe(), cache_key=_KEY, baseline=_baseline())
    stored = store.environment("acme/DEMO")

    assert stored is not None
    assert stored.repository == "Acme/Demo"
    assert stored.status == "ok"
    assert stored.cache_key == _KEY
    assert stored.recipe == _recipe()
    assert stored.baseline == _baseline()
    assert stored.failure_reason is None
    assert store.environment_block("acme/demo") is None


def test_a_failed_environment_blocks_the_repository_for_seven_days(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    store.save_environment(_recipe(), cache_key=_KEY, baseline=_baseline())

    store.mark_environment_failed(
        "acme/demo", reason="  only 3 of 40 tests passed  ", recipe=_recipe()
    )
    stored = store.environment("acme/demo")

    assert stored is not None
    assert stored.status == "failed"
    assert stored.cache_key is None
    assert stored.repository == "acme/demo"
    assert stored.recipe == _recipe()
    assert stored.baseline is None
    assert stored.failure_reason == "only 3 of 40 tests passed"
    now = utc_now()
    assert store.environment_block("acme/demo", now=now) == "only 3 of 40 tests passed"
    assert store.environment_block("acme/demo", now=now + timedelta(days=6, hours=23)) == (
        "only 3 of 40 tests passed"
    )
    assert store.environment_block("acme/demo", now=now + timedelta(days=7, minutes=1)) is None

    store.mark_environment_failed("other/repo", reason="No Python, JavaScript, Go or Rust project")
    other = store.environment("other/repo")
    assert other is not None and other.cache_key is None and other.recipe is None


def test_environment_records_are_validated(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")

    with pytest.raises(ValueError, match="owner/name"):
        store.environment("not-a-repository")
    with pytest.raises(ValueError, match="SHA-256"):
        store.save_environment(_recipe(), cache_key="sha256:" + _KEY, baseline=_baseline())
    with pytest.raises(ValueError, match="1-2000"):
        store.mark_environment_failed("acme/demo", reason=" ")

    store.save_environment(_recipe(), cache_key=_KEY, baseline=_baseline())
    with sqlite3.connect(store.database_path) as connection:
        connection.execute("UPDATE environment_recipes SET recipe_json = '{}'")
    with pytest.raises(StateError, match="Stored environment of Acme/Demo is invalid"):
        store.environment("acme/demo")
    with (
        sqlite3.connect(store.database_path) as connection,
        pytest.raises(sqlite3.IntegrityError),
    ):
        connection.execute("UPDATE environment_recipes SET status = 'ok', baseline_json = NULL")
