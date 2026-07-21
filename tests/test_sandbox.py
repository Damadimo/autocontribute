from __future__ import annotations

import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from autocontribute.config import SandboxConfig
from autocontribute.exceptions import SandboxError
from autocontribute.sandbox import DockerSandbox, SandboxRunner


def test_docker_command_enforces_isolation_and_clears_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    (workspace / ".git").mkdir(parents=True)
    cidfile = tmp_path / "container.cid"
    config = SandboxConfig(
        backend="docker",
        image=(
            "python:3.12-bookworm@"
            "sha256:9bed8554e926c07c6f908841d5ee88c33e8df9236b191526bbce81a9062ab43a"
        ),
        network="none",
        memory="2g",
        cpus=1.5,
        pids_limit=64,
    )
    runner = SandboxRunner(config)
    monkeypatch.setenv("VERY_SECRET_TOKEN", "do-not-inherit")

    arguments = runner.docker_command(workspace, "python -m pytest", cidfile)
    rendered = "\n".join(arguments)

    assert "--network=none" in arguments
    assert "--read-only" in arguments
    assert "--cap-drop=ALL" in arguments
    assert "--security-opt=no-new-privileges" in arguments
    assert "--memory=2g" in arguments
    assert "--memory-swap=2g" in arguments
    assert "--cpus=1.5" in arguments
    assert "--pids-limit=64" in arguments
    assert "--pull=never" in arguments
    assert "--entrypoint=/usr/bin/env" in arguments
    assert "-i" in arguments
    assert "VERY_SECRET_TOKEN" not in rendered
    assert "do-not-inherit" not in rendered
    user = next(value for value in arguments if value.startswith("--user="))
    assert not user.startswith("--user=0:")
    assert any(value.endswith("dst=/workspace/.git,readonly") for value in arguments)


def test_local_backend_requires_explicit_opt_in() -> None:
    with pytest.raises(ValidationError, match="allow_unsafe_local"):
        SandboxConfig(backend="local")


def test_local_backend_runs_only_after_explicit_opt_in(tmp_path: Path) -> None:
    config = SandboxConfig(
        backend="local",
        allow_unsafe_local=True,
        command_timeout_seconds=10,
    )
    runner = SandboxRunner(config)

    result = runner.run(tmp_path, "printf 'validated'")

    assert result.passed
    assert result.stdout == "validated"
    assert result.stderr == ""
    assert result.timed_out is False


def test_command_budget_is_enforced(tmp_path: Path) -> None:
    config = SandboxConfig(
        backend="local",
        allow_unsafe_local=True,
        command_timeout_seconds=10,
        max_commands=1,
    )
    runner = SandboxRunner(config)
    assert runner.run(tmp_path, "true").passed

    with pytest.raises(SandboxError, match="budget exhausted"):
        runner.run(tmp_path, "true")


def test_workspace_symlink_is_rejected(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    link = tmp_path / "link"
    link.symlink_to(workspace, target_is_directory=True)
    runner = DockerSandbox(SandboxConfig())

    with pytest.raises(SandboxError, match="symlink"):
        runner.docker_command(link, "true", tmp_path / "cid")


def test_invalid_image_and_command_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="image"):
        SandboxConfig(image="--privileged")
    with pytest.raises(ValueError, match="pinned"):
        SandboxConfig(image="python:3.12-bookworm")
    with pytest.raises(SandboxError, match="NUL"):
        SandboxRunner(SandboxConfig()).run(tmp_path, "echo\0bad")


def test_docker_invocation_does_not_depend_on_host_identity(tmp_path: Path) -> None:
    runner = SandboxRunner(SandboxConfig())
    arguments = runner.docker_command(tmp_path, "id -u", tmp_path / "cid")
    user_argument = next(value for value in arguments if value.startswith("--user="))
    uid, gid = user_argument.removeprefix("--user=").split(":")

    assert int(uid) != 0
    assert int(gid) != 0
    assert str(os.environ.get("HOME", "")) not in arguments
