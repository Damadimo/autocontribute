from __future__ import annotations

import os
import subprocess
from collections.abc import Collection, Iterator
from contextlib import contextmanager
from decimal import Decimal
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import JsonValue
from test_agent_loop import FakeSession, ScriptedProvider, Shell, Submit, turn

import autocontribute.setup_agent as setup_agent
from autocontribute.budget import RunBudget
from autocontribute.config import SandboxConfig
from autocontribute.environment_builder import FailedAttempt
from autocontribute.environment_signals import read_signals
from autocontribute.environments import EnvironmentRecipe
from autocontribute.exceptions import EnvironmentSetupError, ModelError, SandboxError
from autocontribute.pricing import Provider
from autocontribute.repository import RepositoryWorkspace
from autocontribute.sandbox import ImageIdentity, SessionContainer
from autocontribute.setup_agent import ModelSetupAgent
from autocontribute.store import RunStore

_MODELS: dict[Provider, str] = {"openai": "gpt-5.6-terra", "anthropic": "claude-sonnet-5-5"}
_BASE = ImageIdentity("sha256:" + "1" * 64, "sha256:" + "2" * 64, {}, "linux/arm64")
_PROXY = "http://ac-run1-proxy-1:3128"


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


def _recipe() -> EnvironmentRecipe:
    return EnvironmentRecipe(
        repository="acme/calc",
        language="python",
        base_image="python:3.12-bookworm",
        system_packages=["git"],
        setup_commands=["python -m pip install -e .[test]"],
        build_commands=[],
        test_command="python -m pytest --junitxml=/tmp/ac-report.xml",
        test_framework="pytest",
        test_report="/tmp/ac-report.xml",
        env={"PATH": "/opt/ac/venv/bin:/usr/bin:/bin"},
        offline_env={"PIP_NO_INDEX": "1"},
        fetch_tags=False,
        fetch_submodules=False,
        source="detected",
        dependency_digest="b" * 64,
    )


def _answer(**changes: JsonValue) -> dict[str, JsonValue]:
    return {
        "base_image": "python:3.11-bookworm",
        "system_packages": ["libxml2-dev", "git", "git"],
        "setup_commands": ["python -m pip install -e ."],
        "build_commands": [],
        "test_command": "python -m pytest -q tests",
        "test_framework": "pytest",
        **changes,
    }


class FakeSetup:
    """Stands in for EnvironmentSetup: a session on the workspace, or a failed bootstrap."""

    def __init__(self) -> None:
        self.sessions: list[tuple[EnvironmentRecipe, ImageIdentity, Collection[str]]] = []
        self.bootstrap_fails = False
        # What the session reports after each command, as a stopped container would.
        self.failure: str | None = None

    @contextmanager
    def session(
        self,
        workspace: RepositoryWorkspace,
        recipe: EnvironmentRecipe,
        *,
        base: ImageIdentity,
        allow_hosts: Collection[str],
    ) -> Iterator[tuple[SessionContainer, dict[str, str]]]:
        if self.bootstrap_fails:
            raise EnvironmentSetupError("Setup step the root bootstrap exited with 100")
        self.sessions.append((recipe, base, allow_hosts))
        environment = {**recipe.env, "HOME": "/opt/ac/home", "HTTPS_PROXY": _PROXY}
        session = FakeSession(workspace.path)
        session.infrastructure_failure = self.failure
        yield cast(SessionContainer, session), environment


class Harness:
    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, provider: Provider) -> None:
        source = tmp_path / "source"
        source.mkdir()
        _git(source, "init", "-q")
        (source / "pyproject.toml").write_text(
            "[project]\nname = 'calc'\ndependencies = []\n", encoding="utf-8"
        )
        (source / ".gitignore").write_text(".venv/\n", encoding="utf-8")
        _git(source, "add", ".")
        _git(source, "commit", "-qm", "base")
        self.workspace = RepositoryWorkspace.clone(
            str(source), _git(source, "rev-parse", "HEAD"), tmp_path / "W", allow_local_source=True
        )
        self.store = RunStore(tmp_path / "state")
        self.budget = RunBudget(
            self.store,
            self.store.create_run(),
            max_cost_usd=Decimal(10),
            max_model_calls=200,
            max_run_minutes=90,
            assert_lease=lambda: None,
        )
        self.setup = FakeSetup()
        self.inspected: list[str] = []
        monkeypatch.setattr(setup_agent, "EnvironmentSetup", lambda *args, **kwargs: self.setup)
        monkeypatch.setattr(
            setup_agent,
            "inspect_image",
            lambda reference: self.inspected.append(reference) or _BASE,
        )
        self.provider = provider
        self.script = ScriptedProvider()
        self.agent = ModelSetupAgent(
            self.workspace,
            SandboxConfig(command_timeout_seconds=600),
            provider=self.script,
            model=_MODELS[provider],
            budget=self.budget,
            store=self.store,
            host_values=frozenset(),
            allow_hosts=["mirror.example.org"],
        )

    def propose(self, *steps: Any) -> EnvironmentRecipe | None:
        self.script.steps = list(steps)
        failed = FailedAttempt(
            _recipe(),
            "Setup step python -m pip install -e .[test] exited with 1",
            "ERROR: no extra test",
        )
        return self.agent.propose_recipe(read_signals(self.workspace), failed)


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
def test_the_setup_agent_proposes_a_recipe_the_policy_accepts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, provider: Provider
) -> None:
    harness = Harness(tmp_path, monkeypatch, provider)
    (harness.workspace.path / ".venv").mkdir()
    (harness.workspace.path / "pyproject.toml").write_text("changed\n", encoding="utf-8")

    def check_clean_start(transcript: Any) -> Any:
        assert not (harness.workspace.path / ".venv").exists()
        assert "[project]" in (harness.workspace.path / "pyproject.toml").read_text()
        return turn(provider, Shell("python -m pip install -e ."))

    recipe = harness.propose(
        check_clean_start,
        turn(
            provider, Submit(_answer(setup_commands=["pip install evilpkg"]), name="submit_setup")
        ),
        turn(provider, Submit(_answer(), name="submit_setup")),
    )

    assert recipe is not None
    assert recipe.source == "agent" and recipe.base_image == "python:3.11-bookworm"
    assert recipe.system_packages == ["git", "libxml2-dev"]
    assert recipe.setup_commands == ["python -m pip install -e ."]
    assert recipe.test_command.startswith("python -m pytest -q tests ")
    assert recipe.test_report == "/tmp/ac-report.xml" and recipe.test_framework == "pytest"
    assert recipe.env == _recipe().env and recipe.offline_env == _recipe().offline_env
    ((started_from, base, hosts),) = harness.setup.sessions
    assert started_from == _recipe() and base == _BASE
    assert set(hosts) == {"mirror.example.org"}
    assert harness.inspected == ["python:3.12-bookworm"]
    artifact = harness.store.runs_dir / harness.budget.manifest.run_id / "setup-1.jsonl"
    text = artifact.read_text(encoding="utf-8")
    assert "installs evilpkg, which the repository does not declare" in text
    assert "mirror.example.org" in text and "ERROR: no extra test" in text


def test_an_invalid_recipe_goes_back_to_the_agent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = Harness(tmp_path, monkeypatch, "openai")

    recipe = harness.propose(
        turn("openai", Submit(_answer(system_packages=["Not A Package"]), name="submit_setup")),
        turn("openai", Submit(_answer(), name="submit_setup")),
    )

    assert recipe is not None
    artifact = harness.store.runs_dir / harness.budget.manifest.run_id / "setup-1.jsonl"
    assert "The recipe is not valid" in artifact.read_text(encoding="utf-8")


def test_no_recipe_when_the_agent_does_not_finish_or_cannot_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = Harness(tmp_path, monkeypatch, "openai")

    assert harness.propose(turn("openai"), turn("openai"), turn("openai")) is None

    harness.setup.bootstrap_fails = True
    assert harness.propose() is None


def test_a_provider_failure_is_raised(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    harness = Harness(tmp_path, monkeypatch, "openai")

    with pytest.raises(ModelError, match="refused"):
        harness.propose(ModelError("The model refused the request"))


def test_a_sandbox_failure_is_raised(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    harness = Harness(tmp_path, monkeypatch, "openai")
    harness.setup.failure = "the sandbox container stopped"

    with pytest.raises(SandboxError, match="container stopped"):
        harness.propose(turn("openai", Shell("true")))
