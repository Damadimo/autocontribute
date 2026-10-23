from __future__ import annotations

import os
import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, ClassVar

import pytest

import autocontribute.environment_setup as environment_setup
from autocontribute.config import SandboxConfig
from autocontribute.domain import CommandResult
from autocontribute.environment_setup import (
    DEFAULT_ALLOWED_HOSTS,
    IMAGE_LABEL,
    EnvironmentImage,
    EnvironmentSetup,
    bootstrap_script,
    environment_label,
    image_tag,
    proxy_variables,
    python_distribution,
)
from autocontribute.environment_signals import RepositorySignals
from autocontribute.environments import EnvironmentRecipe
from autocontribute.exceptions import EnvironmentSetupError, RepositoryError
from autocontribute.repository import RepositoryWorkspace
from autocontribute.sandbox import SETUP_CAPABILITIES, ImageIdentity, SessionCommandResult

_KEY = "d" * 64
_BASE = ImageIdentity("sha256:" + "1" * 64, "sha256:" + "2" * 64, {}, "linux/arm64")
_COMMITTED = "sha256:" + "3" * 64
_BOOTSTRAPPED = "sha256:" + "5" * 64


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
    source.mkdir()
    _git(source, "init", "-q")
    (source / ".gitignore").write_text("node_modules/\n", encoding="utf-8")
    (source / "package-lock.json").write_text("{}\n", encoding="utf-8")
    _git(source, "add", ".")
    _git(source, "commit", "-qm", "base")
    return RepositoryWorkspace.clone(
        str(source), _git(source, "rev-parse", "HEAD"), tmp_path / "W", allow_local_source=True
    )


def _recipe(**changes: Any) -> EnvironmentRecipe:
    fields: dict[str, Any] = {
        "repository": "Acme/Demo",
        "language": "javascript",
        "base_image": "node:24-bookworm",
        "system_packages": ["git", "less"],
        "setup_commands": ["npm ci"],
        "build_commands": [],
        "test_command": "jest --ci --json --outputFile=/tmp/ac-report.json",
        "test_framework": "jest",
        "test_report": "/tmp/ac-report.json",
        "env": {"PATH": "/workspace/node_modules/.bin:/usr/bin:/bin", "LANG": "C.UTF-8"},
        "offline_env": {"npm_config_offline": "true"},
        "fetch_tags": False,
        "fetch_submodules": False,
        "source": "detected",
        "dependency_digest": "b" * 64,
    }
    return EnvironmentRecipe.model_validate({**fields, **changes})


def _result(exit_code: int = 0, output: str = "") -> SessionCommandResult:
    return SessionCommandResult(
        CommandResult(
            command="", exit_code=exit_code, duration_seconds=1.0, stdout=output, stderr=""
        ),
        None,
        restarted=False,
    )


class _FakeNetwork:
    instances: ClassVar[list[_FakeNetwork]] = []

    def __init__(self, *, allowed_hosts: set[str], **options: Any) -> None:
        self.allowed_hosts = allowed_hosts
        self.options = options
        self.network = "ac-run1-net-1"
        self.proxy_url = "http://ac-run1-proxy-1:3128"
        self.removed = False
        _FakeNetwork.instances.append(self)

    def __enter__(self) -> _FakeNetwork:
        return self

    def __exit__(self, *_exception: object) -> None:
        self.removed = True

    def refused_requests(self) -> list[str]:
        return ["deny CONNECT evil.example:443: the host is not on the setup allowlist"]


class _FakeContainer:
    instances: ClassVar[list[_FakeContainer]] = []
    # Side effects and results of commands, by command text.
    effects: ClassVar[dict[str, Callable[[Path], SessionCommandResult]]] = {}
    # Whether piping the ignored files into the image archive works.
    archives: ClassVar[bool] = True

    def __init__(self, config: SandboxConfig, **options: Any) -> None:
        self.config = config
        self.options = options
        self.command_user = "1000:1000"
        self.execs: list[tuple[str, Mapping[str, str], bool]] = []
        self.pipes: list[tuple[str, str]] = []
        self.labels: Mapping[str, str] | None = None
        self.removed = False
        _FakeContainer.instances.append(self)

    def __enter__(self) -> _FakeContainer:
        return self

    def __exit__(self, *_exception: object) -> None:
        self.removed = True

    def exec(
        self,
        command: str,
        *,
        timeout_seconds: int,
        environment: Mapping[str, str] | None = None,
        as_root: bool = False,
    ) -> SessionCommandResult:
        self.execs.append((command, dict(environment or {}), as_root))
        effect = _FakeContainer.effects.get(command)
        return _result() if effect is None else effect(self.options["workspace"])

    def pipe(self, command: str, text: str, *, timeout_seconds: int) -> bool:
        self.pipes.append((command, text))
        return _FakeContainer.archives

    def commit(self, labels: Mapping[str, str]) -> str:
        self.labels = labels
        return _BOOTSTRAPPED if self.options.get("capabilities") else _COMMITTED


@pytest.fixture
def docker(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[Any]]:
    _FakeNetwork.instances = []
    _FakeContainer.instances = []
    _FakeContainer.effects = {}
    _FakeContainer.archives = True
    calls: dict[str, list[Any]] = {"tag": [], "inspect": [], "removed": []}
    monkeypatch.setattr(environment_setup, "EgressNetwork", _FakeNetwork)
    monkeypatch.setattr(environment_setup, "SessionContainer", _FakeContainer)
    monkeypatch.setattr(environment_setup, "detect_docker_daemon_mode", lambda *_: "rootful")
    monkeypatch.setattr(environment_setup, "docker_container_identity", lambda _: (1000, 1000))
    monkeypatch.setattr(
        environment_setup,
        "tag_image",
        lambda image_id, tag, **_: calls["tag"].append((image_id, tag)),
    )
    monkeypatch.setattr(
        environment_setup,
        "inspect_image",
        lambda reference, **_: calls["inspect"].append(reference) or None,
    )
    monkeypatch.setattr(
        environment_setup,
        "remove_image",
        lambda image_id, **_: calls["removed"].append(image_id),
    )
    return calls


def _setup(tmp_path: Path) -> EnvironmentSetup:
    return EnvironmentSetup(
        SandboxConfig(pids_limit=256, command_timeout_seconds=600),
        run_id="run1",
        store_root=tmp_path / "state",
    )


def test_setup_runs_behind_the_proxy_undoes_tracked_changes_and_commits(
    tmp_path: Path, workspace: RepositoryWorkspace, docker: dict[str, list[Any]]
) -> None:
    def npm_ci(root: Path) -> SessionCommandResult:
        (root / "node_modules").mkdir()
        (root / "node_modules" / "left-pad.js").write_text("module.exports = 1\n", "utf-8")
        (root / "package-lock.json").write_text('{"rewritten": true}\n', encoding="utf-8")
        (root / "generated.txt").write_text("stray\n", encoding="utf-8")
        return _result(output="added 1 package")

    _FakeContainer.effects["npm ci"] = npm_ci

    image, recipe = _setup(tmp_path).build(
        workspace,
        _recipe(),
        base=_BASE,
        cache_key=_KEY,
        allow_hosts=["npm.example.org"],
        distribution=None,
    )

    network = _FakeNetwork.instances[0]
    assert network.allowed_hosts == DEFAULT_ALLOWED_HOSTS | {"npm.example.org"}
    assert network.removed
    # Only the root bootstrap's container gets capabilities, and it runs nothing else.
    bootstrap, container = _FakeContainer.instances
    assert bootstrap.removed
    assert bootstrap.options["image"] == _BASE.image_id
    assert bootstrap.options["network"] == "ac-run1-net-1"
    assert bootstrap.options["writable_root"] is True
    assert bootstrap.options["capabilities"] == SETUP_CAPABILITIES
    ((script, environment, as_root),) = bootstrap.execs
    assert as_root
    assert "apt-get install" in script
    assert environment["HTTPS_PROXY"] == "http://ac-run1-proxy-1:3128"
    assert bootstrap.labels == {}
    assert container.removed
    assert container.config.pids_limit == 4_096
    assert container.options["image"] == _BOOTSTRAPPED
    assert container.options["network"] == "ac-run1-net-1"
    assert container.options["writable_root"] is True
    assert "capabilities" not in container.options
    (install,) = container.execs
    assert install == (
        "npm ci",
        {
            "PATH": "/workspace/node_modules/.bin:/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "HOME": "/opt/ac/home",
            **proxy_variables("http://ac-run1-proxy-1:3128"),
        },
        False,
    )
    assert recipe.setup_dirty_paths == ["generated.txt", "package-lock.json"]
    assert (workspace.path / "package-lock.json").read_text(encoding="utf-8") == "{}\n"
    assert not (workspace.path / "generated.txt").exists()
    assert (workspace.path / "node_modules" / "left-pad.js").is_file()
    assert container.pipes == [
        ("tar -cf /opt/ac/workspace-setup.tar -C /workspace -T -", "./node_modules\n")
    ]
    label = environment_label(_recipe(), cache_key=_KEY, command_user="1000:1000")
    assert container.labels == {IMAGE_LABEL: label}
    tag = "autocontribute-env/acme__demo:dddddddddddd"
    assert docker["tag"] == [(_COMMITTED, tag)]
    assert docker["removed"] == []
    assert image == EnvironmentImage(
        _COMMITTED, tag, "node:24-bookworm", _BASE.digest, _KEY, reused=False
    )


def test_python_setup_checks_where_the_project_imports_from(
    tmp_path: Path, workspace: RepositoryWorkspace, docker: dict[str, list[Any]]
) -> None:
    recipe = _recipe(language="python", system_packages=[], setup_commands=["uv sync"])

    _setup(tmp_path).build(
        workspace, recipe, base=_BASE, cache_key=_KEY, allow_hosts=(), distribution="demo-pkg"
    )

    bootstrap, container = _FakeContainer.instances
    assert bootstrap.options["capabilities"] == {"CHOWN"}
    probe, environment, as_root = container.execs[-1]
    assert probe.startswith("python -c ") and probe.endswith(" demo-pkg")
    assert environment == recipe.env
    assert not as_root


def test_a_failed_setup_step_reports_its_output_and_refused_hosts(
    tmp_path: Path, workspace: RepositoryWorkspace, docker: dict[str, list[Any]]
) -> None:
    _FakeContainer.effects["npm ci"] = lambda _root: _result(1, "npm ERR! 403 Forbidden")

    with pytest.raises(EnvironmentSetupError, match="Setup step npm ci exited with 1") as error:
        _setup(tmp_path).build(
            workspace, _recipe(), base=_BASE, cache_key=_KEY, allow_hosts=(), distribution=None
        )

    assert error.value.log_tail == (
        "npm ERR! 403 Forbidden\n"
        "deny CONNECT evil.example:443: the host is not on the setup allowlist"
    )
    assert _FakeNetwork.instances[0].removed
    assert all(container.removed for container in _FakeContainer.instances)
    assert docker["tag"] == []
    assert docker["removed"] == [_BOOTSTRAPPED]


def test_a_matching_local_image_is_reused_with_its_workspace_output(
    tmp_path: Path,
    workspace: RepositoryWorkspace,
    docker: dict[str, list[Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    label = environment_label(_recipe(), cache_key=_KEY, command_user="1000:1000")
    found = ImageIdentity(_COMMITTED, _COMMITTED, {IMAGE_LABEL: label}, "linux/arm64")
    monkeypatch.setattr(environment_setup, "inspect_image", lambda reference, **_: found)

    image = _setup(tmp_path).reuse(workspace, _recipe(), base=_BASE, cache_key=_KEY)

    assert image == EnvironmentImage(
        _COMMITTED,
        "autocontribute-env/acme__demo:dddddddddddd",
        "node:24-bookworm",
        _BASE.digest,
        _KEY,
        reused=True,
    )
    container = _FakeContainer.instances[0]
    assert container.options["image"] == _COMMITTED
    assert "network" not in container.options
    assert container.execs == [
        (
            "if [ -f /opt/ac/workspace-setup.tar ]; then "
            "tar -xf /opt/ac/workspace-setup.tar -C /workspace; fi",
            {},
            False,
        )
    ]
    assert _FakeNetwork.instances == []

    changed = _recipe(setup_commands=["npm ci --ignore-scripts"])
    assert _setup(tmp_path).reuse(workspace, changed, base=_BASE, cache_key=_KEY) is None


def _build(tmp_path: Path, workspace: RepositoryWorkspace, recipe: EnvironmentRecipe) -> None:
    _setup(tmp_path).build(
        workspace, recipe, base=_BASE, cache_key=_KEY, allow_hosts=(), distribution=None
    )


def test_tags_and_submodules_are_fetched_before_setup_starts(
    tmp_path: Path,
    workspace: RepositoryWorkspace,
    docker: dict[str, list[Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # setuptools-scm projects such as pytest install only with their tags.
    fetched: list[tuple[str, int]] = []

    def fetch(kind: str) -> Callable[..., None]:
        return lambda _workspace, **_options: fetched.append((kind, len(_FakeNetwork.instances)))

    monkeypatch.setattr(RepositoryWorkspace, "fetch_tags", fetch("tags"))
    monkeypatch.setattr(RepositoryWorkspace, "fetch_submodules", fetch("submodules"))

    _build(tmp_path, workspace, _recipe(fetch_tags=True, fetch_submodules=True))
    assert fetched == [("tags", 0), ("submodules", 0)]

    fetched.clear()
    _build(tmp_path, workspace, _recipe())
    assert fetched == []

    def unreachable(_workspace: RepositoryWorkspace, **_options: object) -> None:
        raise RepositoryError("Git operation failed: could not read from remote")

    monkeypatch.setattr(RepositoryWorkspace, "fetch_submodules", unreachable)
    started = len(_FakeContainer.instances)
    with pytest.raises(EnvironmentSetupError, match="Fetching Git tags or submodules failed"):
        _build(tmp_path, workspace, _recipe(fetch_submodules=True))
    assert len(_FakeContainer.instances) == started


@pytest.mark.parametrize(
    ("outcome", "reason"),
    [
        # The container failed although the step exited 0.
        (
            SessionCommandResult(
                CommandResult(command="", exit_code=0, duration_seconds=1.0, stdout="", stderr=""),
                "the sandbox ran out of memory (limit 6g)",
                restarted=True,
            ),
            "Setup step npm ci the sandbox ran out of memory (limit 6g)",
        ),
        (
            SessionCommandResult(
                CommandResult(
                    command="",
                    exit_code=124,
                    duration_seconds=600.0,
                    stdout="",
                    stderr="",
                    timed_out=True,
                ),
                None,
                restarted=True,
            ),
            "Setup step npm ci timed out after 600 s",
        ),
    ],
)
def test_container_failures_and_timeouts_fail_the_step(
    tmp_path: Path,
    workspace: RepositoryWorkspace,
    docker: dict[str, list[Any]],
    outcome: SessionCommandResult,
    reason: str,
) -> None:
    _FakeContainer.effects["npm ci"] = lambda _root: outcome

    with pytest.raises(EnvironmentSetupError) as error:
        _build(tmp_path, workspace, _recipe())

    assert str(error.value) == reason
    assert docker["tag"] == []


def test_setup_changes_that_cannot_be_undone_fail_the_recipe(
    tmp_path: Path,
    workspace: RepositoryWorkspace,
    docker: dict[str, list[Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def stuck(_workspace: RepositoryWorkspace) -> list[str]:
        raise RepositoryError("Could not delete vendor: Operation not permitted")

    monkeypatch.setattr(RepositoryWorkspace, "restore_base", stuck)

    with pytest.raises(EnvironmentSetupError, match="Setup left changes that cannot be undone"):
        _build(tmp_path, workspace, _recipe())
    assert docker["removed"] == [_BOOTSTRAPPED]


def test_an_image_without_its_workspace_output_is_never_labelled_for_reuse(
    tmp_path: Path, workspace: RepositoryWorkspace, docker: dict[str, list[Any]]
) -> None:
    def npm_ci(root: Path) -> SessionCommandResult:
        (root / "node_modules").mkdir()
        return _result()

    _FakeContainer.effects["npm ci"] = npm_ci
    _FakeContainer.archives = False

    _build(tmp_path, workspace, _recipe())

    assert _FakeContainer.instances[-1].labels == {}


def test_reuse_fails_over_to_a_build_when_its_output_cannot_be_put_back(
    tmp_path: Path,
    workspace: RepositoryWorkspace,
    docker: dict[str, list[Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    label = environment_label(_recipe(), cache_key=_KEY, command_user="1000:1000")
    found = ImageIdentity(_COMMITTED, _COMMITTED, {IMAGE_LABEL: label}, "linux/arm64")
    monkeypatch.setattr(environment_setup, "inspect_image", lambda reference, **_: found)
    extraction = (
        "if [ -f /opt/ac/workspace-setup.tar ]; then "
        "tar -xf /opt/ac/workspace-setup.tar -C /workspace; fi"
    )

    def broken_archive(root: Path) -> SessionCommandResult:
        (root / "package-lock.json").write_text("overwritten\n", encoding="utf-8")
        return _result(2, "tar: unexpected end of file")

    _FakeContainer.effects[extraction] = broken_archive

    assert _setup(tmp_path).reuse(workspace, _recipe(), base=_BASE, cache_key=_KEY) is None
    assert (workspace.path / "package-lock.json").read_text(encoding="utf-8") == "{}\n"

    def stuck(_workspace: RepositoryWorkspace) -> list[str]:
        raise RepositoryError("Could not delete nested: Operation not permitted")

    monkeypatch.setattr(RepositoryWorkspace, "restore_base", stuck)
    with pytest.raises(EnvironmentSetupError, match="reused image left changes"):
        _setup(tmp_path).reuse(workspace, _recipe(), base=_BASE, cache_key=_KEY)


def test_no_image_means_no_reuse(
    tmp_path: Path, workspace: RepositoryWorkspace, docker: dict[str, list[Any]]
) -> None:
    assert _setup(tmp_path).reuse(workspace, _recipe(), base=_BASE, cache_key=_KEY) is None
    assert docker["inspect"] == ["autocontribute-env/acme__demo:dddddddddddd"]
    assert _FakeContainer.instances == []


def test_the_bootstrap_script_is_valid_shell_and_owns_the_tool_root() -> None:
    script = bootstrap_script(["git", "liblz4-tool"], "1000:20")

    subprocess.run(["sh", "-n"], input=script, text=True, check=True)
    assert "for package in git liblz4-tool; do" in script
    assert "chown -R 1000:20 /opt/ac" in script
    assert "autocontribute:x:1000:20::/opt/ac/home:/bin/sh" in script
    assert "skipping unknown system package" in script
    subprocess.run(["sh", "-n"], input=bootstrap_script([], "0:0"), text=True, check=True)
    with pytest.raises(ValueError, match="numeric"):
        bootstrap_script([], "root")


def test_environment_label_tracks_setup_but_not_the_test_command() -> None:
    label = environment_label(_recipe(), cache_key=_KEY, command_user="1000:1000")

    assert label.startswith("sha256:") and len(label) == 71
    assert label == environment_label(
        _recipe(test_command="npx jest", source="cached"), cache_key=_KEY, command_user="1000:1000"
    )
    assert label != environment_label(_recipe(), cache_key="e" * 64, command_user="1000:1000")
    assert label != environment_label(_recipe(), cache_key=_KEY, command_user="1001:1001")
    assert label != environment_label(
        _recipe(system_packages=["git"]), cache_key=_KEY, command_user="1000:1000"
    )


def test_image_tags_are_valid_docker_names() -> None:
    assert image_tag("Acme.Corp/My_Repo", _KEY) == (
        "autocontribute-env/acme-corp__my-repo:dddddddddddd"
    )
    assert image_tag("a/.github", _KEY) == "autocontribute-env/a__github:dddddddddddd"


@pytest.mark.parametrize(
    ("files", "name"),
    [
        ({"pyproject.toml": '[project]\nname = "click"\n'}, "click"),
        ({"pyproject.toml": '[tool.poetry]\nname = "typer-cli"\n'}, "typer-cli"),
        ({"setup.cfg": "[metadata]\nname = requests\n"}, "requests"),
        ({"pyproject.toml": "not toml ["}, None),
        ({"setup.py": "setup(name='x')"}, None),
    ],
)
def test_the_python_project_name_comes_from_its_metadata(
    files: dict[str, str], name: str | None
) -> None:
    signals = RepositorySignals(frozenset(files), files, ())

    assert python_distribution(signals) == name
