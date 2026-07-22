from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from pydantic import ValidationError

import autocontribute.sandbox as sandbox
from autocontribute.config import SandboxConfig
from autocontribute.exceptions import SandboxError
from autocontribute.sandbox import DockerSandbox, SandboxRunner


def _docker_runtime_info(
    security_options: list[object] | None = None,
    **overrides: object,
) -> str:
    information: dict[str, object] = {
        "security_options": security_options or ["name=seccomp,profile=builtin", "name=cgroupns"],
        "cgroup_version": "2",
        "cgroup_driver": "systemd",
        "memory_limit": True,
        "swap_limit": True,
        "cpu_cfs_period": True,
        "cpu_cfs_quota": True,
        "pids_limit": True,
    }
    information.update(overrides)
    return json.dumps(information)


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
    monkeypatch.setattr(sandbox, "detect_docker_daemon_mode", lambda *_args, **_kwargs: "rootful")
    monkeypatch.setattr(sandbox.os, "getuid", lambda: 1000)
    monkeypatch.setattr(sandbox.os, "getgid", lambda: 1000)
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
    assert "--log-driver=none" in arguments
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


def test_isolated_command_cannot_mutate_authoritative_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    tracked = workspace / "tracked.txt"
    tracked.write_text("authoritative\n", encoding="utf-8")
    runner = SandboxRunner(
        SandboxConfig(
            backend="local",
            allow_unsafe_local=True,
            command_timeout_seconds=10,
        )
    )

    result = runner.run_isolated(
        workspace,
        "printf 'mutated\\n' > tracked.txt; printf 'generated\\n' > untracked.txt",
    )

    assert result.passed
    assert tracked.read_text(encoding="utf-8") == "authoritative\n"
    assert not (workspace / "untracked.txt").exists()


def test_each_isolated_command_receives_a_fresh_workspace_copy(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    runner = SandboxRunner(
        SandboxConfig(
            backend="local",
            allow_unsafe_local=True,
            command_timeout_seconds=10,
        )
    )

    results = runner.run_all_isolated(
        workspace,
        ["touch command-one-generated", "test ! -e command-one-generated"],
        stop_on_failure=False,
    )

    assert all(result.passed for result in results)
    assert not (workspace / "command-one-generated").exists()


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


def test_rootful_docker_invocation_uses_a_non_root_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sandbox, "detect_docker_daemon_mode", lambda *_args, **_kwargs: "rootful")
    monkeypatch.setattr(sandbox.os, "getuid", lambda: 1000)
    monkeypatch.setattr(sandbox.os, "getgid", lambda: 1000)
    runner = SandboxRunner(SandboxConfig())
    arguments = runner.docker_command(tmp_path, "id -u", tmp_path / "cid")
    user_argument = next(value for value in arguments if value.startswith("--user="))
    uid, gid = user_argument.removeprefix("--user=").split(":")

    assert int(uid) != 0
    assert int(gid) != 0
    assert str(os.environ.get("HOME", "")) not in arguments


def test_verified_rootless_daemon_uses_namespace_root_without_relaxing_boundaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sandbox, "detect_docker_daemon_mode", lambda *_args, **_kwargs: "rootless")
    runner = SandboxRunner(SandboxConfig())

    arguments = runner.docker_command(tmp_path, "id -u", tmp_path / "cid")

    assert "--user=0:0" in arguments
    assert "--network=none" in arguments
    assert "--read-only" in arguments
    assert "--cap-drop=ALL" in arguments
    assert "--security-opt=no-new-privileges" in arguments
    assert "--pids-limit=256" in arguments
    assert "--memory=4g" in arguments
    assert "--memory-swap=4g" in arguments


def test_rootful_daemon_rejects_a_host_root_caller(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sandbox, "detect_docker_daemon_mode", lambda *_args, **_kwargs: "rootful")
    monkeypatch.setattr(sandbox.os, "getuid", lambda: 0)
    monkeypatch.setattr(sandbox.os, "getgid", lambda: 0)

    with pytest.raises(SandboxError, match="host root"):
        SandboxRunner(SandboxConfig()).docker_command(tmp_path, "true", tmp_path / "cid")


def test_container_identity_rejects_an_unknown_daemon_mode() -> None:
    with pytest.raises(SandboxError, match="mode is invalid"):
        sandbox.docker_container_identity(cast(sandbox.DockerDaemonMode, "unknown"))


@pytest.mark.parametrize(
    ("security_options", "expected"),
    [
        (["name=seccomp,profile=builtin", "name=cgroupns"], "rootful"),
        (["name=not-rootless", "prefix=name=rootless"], "rootful"),
        (["name=seccomp,profile=builtin", "name=rootless"], "rootless"),
    ],
)
def test_docker_daemon_mode_requires_an_exact_rootless_security_option(
    monkeypatch: pytest.MonkeyPatch,
    security_options: list[str],
    expected: str,
) -> None:
    observed: dict[str, object] = {}

    def fake_run(command: list[str], **kwargs: object) -> SimpleNamespace:
        observed["command"] = command
        observed["environment"] = kwargs.get("env")
        return SimpleNamespace(returncode=0, stdout=_docker_runtime_info(security_options))

    monkeypatch.setattr(sandbox.subprocess, "run", fake_run)
    environment = {"PATH": "/bin", "DOCKER_HOST": "unix:///private/docker.sock"}

    assert sandbox.detect_docker_daemon_mode("docker", environment=environment) == expected
    assert observed["command"] == [
        "docker",
        "info",
        "--format",
        sandbox._DOCKER_RUNTIME_INFO_FORMAT,
    ]
    assert observed["environment"] is environment


@pytest.mark.parametrize(
    "output",
    [
        "not-json",
        '{"name": "rootless"}',
        _docker_runtime_info(["name=rootless", 1]),
        _docker_runtime_info(["name=rootless", "name=rootless"]),
    ],
)
def test_docker_daemon_mode_fails_closed_on_malformed_or_ambiguous_output(
    monkeypatch: pytest.MonkeyPatch,
    output: str,
) -> None:
    monkeypatch.setattr(
        sandbox.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=output),
    )

    with pytest.raises(SandboxError, match=r"malformed|ambiguous"):
        sandbox.detect_docker_daemon_mode()


def test_docker_daemon_mode_rejects_userns_remapping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        sandbox.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout=_docker_runtime_info(["name=seccomp,profile=builtin", "name=userns"]),
        ),
    )

    with pytest.raises(SandboxError, match="remapping is unsupported"):
        sandbox.detect_docker_daemon_mode()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("cgroup_version", "1"),
        ("cgroup_driver", ""),
        ("cgroup_driver", "none"),
        ("memory_limit", False),
        ("swap_limit", False),
        ("cpu_cfs_period", False),
        ("cpu_cfs_quota", False),
        ("pids_limit", False),
    ],
)
def test_docker_daemon_mode_requires_enforced_cgroup_v2_resource_controls(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
) -> None:
    monkeypatch.setattr(
        sandbox.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout=_docker_runtime_info(**{field: value}),
        ),
    )

    with pytest.raises(SandboxError, match="required cgroup v2 resource controls"):
        sandbox.detect_docker_daemon_mode()


def test_docker_daemon_probe_failure_does_not_echo_raw_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    leaked = "daemon-output-must-not-be-rendered"
    monkeypatch.setattr(
        sandbox.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=1,
            stdout=leaked,
            stderr=leaked,
        ),
    )

    with pytest.raises(SandboxError) as error:
        sandbox.detect_docker_daemon_mode()

    assert leaked not in str(error.value)


def test_runner_rechecks_daemon_mode_for_each_command_on_one_endpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, str]] = []

    modes: list[sandbox.DockerDaemonMode] = ["rootless", "rootful"]

    def detect(_binary: str, *, environment: dict[str, str]) -> sandbox.DockerDaemonMode:
        calls.append(environment)
        return modes.pop(0)

    monkeypatch.setattr(sandbox, "detect_docker_daemon_mode", detect)
    monkeypatch.setattr(sandbox.os, "getuid", lambda: 1000)
    monkeypatch.setattr(sandbox.os, "getgid", lambda: 1000)
    monkeypatch.setenv("DOCKER_HOST", "unix:///private/changed-after-construction.sock")
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-reach-docker-client")
    runner = SandboxRunner(SandboxConfig())
    monkeypatch.setenv("DOCKER_HOST", "unix:///private/different.sock")

    first = runner.docker_command(tmp_path, "true", tmp_path / "first.cid")
    second = runner.docker_command(tmp_path, "true", tmp_path / "second.cid")

    assert "--user=0:0" in first
    assert "--user=0:0" not in second
    assert any(argument.startswith("--user=") for argument in second)
    assert len(calls) == 2
    assert calls[0]["DOCKER_HOST"] == "unix:///private/changed-after-construction.sock"
    assert calls[1]["DOCKER_HOST"] == "unix:///private/changed-after-construction.sock"
    assert "OPENAI_API_KEY" not in calls[0]
