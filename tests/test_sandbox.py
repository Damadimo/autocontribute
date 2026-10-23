from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from pydantic import ValidationError

import autocontribute.sandbox as sandbox
from autocontribute.config import SandboxConfig
from autocontribute.domain import CommandResult
from autocontribute.exceptions import SandboxError
from autocontribute.sandbox import DockerSandbox, SandboxRunner, SessionContainer

_SESSION_IMAGE = "alpine@sha256:d406446bc05b82480756ce8f1287964d28768c23955fa9480d2a74a2eae7a654"
_RUN_ID = "0123456789abcdef"


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
        memory="2g",
        cpus=1.5,
        pids_limit=64,
    )
    runner = SandboxRunner(config)
    monkeypatch.setattr(sandbox, "detect_docker_daemon_mode", lambda *_args, **_kwargs: "rootful")
    monkeypatch.setattr(sandbox.os, "getuid", lambda: 1000)
    monkeypatch.setattr(sandbox.os, "getgid", lambda: 1000)
    monkeypatch.setenv("VERY_SECRET_TOKEN", "do-not-inherit")
    monkeypatch.setenv("HTTPS_PROXY", "http://operator:proxy-secret@proxy.example.test:3128")

    arguments = runner.docker_command(workspace, "python -m pytest", cidfile)
    rendered = "\n".join(arguments)
    image_index = arguments.index(config.image)

    assert "--network=none" in arguments
    assert "--read-only" in arguments
    assert "--cap-drop=ALL" in arguments
    assert "--security-opt=no-new-privileges" in arguments
    assert "--ipc=private" in arguments
    assert "--shm-size=256m" in arguments
    assert "--memory=2g" in arguments
    assert "--memory-swap=2g" in arguments
    assert "--cpus=1.5" in arguments
    assert "--pids-limit=64" in arguments
    assert "--pull=never" in arguments
    assert "--log-driver=none" in arguments
    assert "--entrypoint=/usr/bin/env" in arguments
    assert "--tmpfs=/tmp:rw,exec,nosuid,nodev,size=512m,mode=1777" in arguments
    for name in (
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
        "FTP_PROXY",
        "ftp_proxy",
    ):
        assert arguments.index(f"--env={name}=") < image_index
    assert arguments[image_index + 1] == "-i"
    assert arguments[-3:] == ["/bin/sh", "-c", "python -m pytest"]
    assert "-lc" not in arguments
    assert "VERY_SECRET_TOKEN" not in rendered
    assert "do-not-inherit" not in rendered
    assert "proxy-secret" not in rendered
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
    )

    assert all(result.passed for result in results)
    assert not (workspace / "command-one-generated").exists()


def _record_client_kills(
    monkeypatch: pytest.MonkeyPatch,
    events: list[str],
) -> None:
    kill_process_group = sandbox._kill_process_group

    def recording_kill(process: subprocess.Popen[bytes]) -> None:
        events.append("kill client")
        kill_process_group(process)

    monkeypatch.setattr(sandbox, "_kill_process_group", recording_kill)


def test_timed_out_command_stops_its_sandbox_before_the_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    _record_client_kills(monkeypatch, events)

    result = sandbox._execute(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        command="sleep 30",
        cwd=tmp_path,
        timeout_seconds=1,
        environment=None,
        cleanup=lambda: events.append("stop sandbox"),
    )

    assert result.timed_out
    assert result.exit_code == 124
    assert events == ["stop sandbox", "kill client"]


def test_interrupted_command_stops_its_sandbox_and_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    _record_client_kills(monkeypatch, events)
    clients: list[subprocess.Popen[bytes]] = []

    class InterruptedPopen(subprocess.Popen[bytes]):
        def wait(self, timeout: float | None = None) -> int:
            if not clients:
                clients.append(self)
                raise KeyboardInterrupt
            return super().wait(timeout)

    monkeypatch.setattr(sandbox.subprocess, "Popen", InterruptedPopen)

    with pytest.raises(KeyboardInterrupt):
        sandbox._execute(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            command="sleep 30",
            cwd=tmp_path,
            timeout_seconds=30,
            environment=None,
            cleanup=lambda: events.append("stop sandbox"),
        )

    assert events == ["stop sandbox", "kill client"]
    assert clients[0].returncode == -signal.SIGKILL


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


class _ScriptedDocker:
    """Answers Docker management commands and records every call a session makes."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.inputs: list[str | None] = []
        self.commands: list[list[str]] = []
        # Queued answers; once a queue is empty the container is healthy and clean.
        self.states: list[str] = []
        self.leftovers: list[str] = []
        self.start_exit_code = 0
        self.run_failure: str | None = None
        self.command_times_out = False

    def control(
        self,
        _docker_binary: str,
        arguments: Sequence[str],
        _environment: dict[str, str],
        *,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        call = list(arguments)
        self.calls.append(call)
        self.inputs.append(input_text)
        if call[0] == "run" and self.run_failure is not None:
            return subprocess.CompletedProcess(call, 125, "", self.run_failure)
        if call[0] == "inspect":
            state = self.states.pop(0) if self.states else "true false"
            return subprocess.CompletedProcess(call, 0, f"{state}\n", "")
        if call[0] == "top":
            leftover = self.leftovers.pop(0) if self.leftovers else ""
            table = "PID    UID\n4101   65534\n4102   65534\n"
            return subprocess.CompletedProcess(call, 0, table + leftover, "")
        if call[0] == "start":
            return subprocess.CompletedProcess(call, self.start_exit_code, "", "")
        return subprocess.CompletedProcess(call, 0, "", "")

    def execute(
        self,
        arguments: list[str],
        *,
        command: str,
        cwd: Path,
        timeout_seconds: int,
        environment: dict[str, str] | None,
        cleanup: Callable[[], None] | None,
    ) -> CommandResult:
        self.commands.append(arguments)
        if self.command_times_out:
            assert cleanup is not None
            cleanup()
            return CommandResult(
                command=command,
                exit_code=124,
                duration_seconds=float(timeout_seconds),
                stdout="",
                stderr="",
                timed_out=True,
            )
        return CommandResult(
            command=command, exit_code=0, duration_seconds=0.1, stdout="ok\n", stderr=""
        )


def _session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    docker: _ScriptedDocker,
    *,
    mode: sandbox.DockerDaemonMode = "rootful",
) -> SessionContainer:
    workspace = tmp_path / "workspace"
    (workspace / ".git").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(sandbox, "detect_docker_daemon_mode", lambda *_args, **_kwargs: mode)
    monkeypatch.setattr(sandbox.os, "getuid", lambda: 1000)
    monkeypatch.setattr(sandbox.os, "getgid", lambda: 1000)
    monkeypatch.setattr(sandbox, "_docker_control", docker.control)
    monkeypatch.setattr(sandbox, "_execute", docker.execute)
    return SessionContainer(
        SandboxConfig(memory="2g", cpus=1.5, pids_limit=64),
        image=_SESSION_IMAGE,
        workspace=workspace,
        run_id=_RUN_ID,
        store_root=tmp_path / "state",
    )


def test_session_container_starts_hardened_labelled_and_detached(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    docker = _ScriptedDocker()
    session = _session(tmp_path, monkeypatch, docker)
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-reach-the-container")
    workspace = (tmp_path / "workspace").resolve()
    store_hash = hashlib.sha256(os.fsencode((tmp_path / "state").resolve())).hexdigest()[:16]

    session.start()

    run = docker.calls[0]
    assert run[:2] == ["run", "--detach"]
    assert run[2] == f"--name={session.name}"
    assert session.name.startswith(f"ac-{_RUN_ID}-")
    for flag in (
        f"--label=org.autocontribute.run={_RUN_ID}",
        f"--label=org.autocontribute.store={store_hash}",
        "--pull=never",
        "--log-driver=none",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--ipc=private",
        "--shm-size=256m",
        "--user=65534:65534",
        "--memory=2g",
        "--memory-swap=2g",
        "--cpus=1.5",
        "--pids-limit=64",
        "--ulimit=nofile=1024:1024",
        "--ulimit=core=0:0",
        "--init",
        "--entrypoint=/usr/bin/env",
        "--workdir=/workspace",
        "--tmpfs=/tmp:rw,exec,nosuid,nodev,size=1g,mode=1777",
        f"--mount=type=bind,src={workspace},dst=/workspace",
        f"--mount=type=bind,src={workspace / '.git'},dst=/workspace/.git,readonly",
        "--env=HTTP_PROXY=",
        "--env=https_proxy=",
    ):
        assert flag in run
    assert "--rm" not in run
    assert run[-5:] == [_SESSION_IMAGE, "-i", "PATH=/usr/bin:/bin", "/bin/sleep", "infinity"]
    assert "must-not-reach-the-container" not in "\n".join(run)
    assert docker.calls[1] == [
        "inspect",
        "--format",
        "{{.State.Running}} {{.State.OOMKilled}}",
        session.name,
    ]


def test_session_command_gets_only_the_allowlisted_environment_and_a_plain_shell(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    docker = _ScriptedDocker()
    session = _session(tmp_path, monkeypatch, docker)
    monkeypatch.setenv("AUTOCONTRIBUTE_GITHUB_TOKEN", "must-not-reach-the-command")
    session.start()

    outcome = session.exec(
        "python -m pytest -q",
        timeout_seconds=30,
        workdir="/workspace/pkg",
        environment={"PATH": "/opt/ac/venv/bin:/usr/bin:/bin", "PIP_NO_INDEX": "1"},
    )

    assert docker.commands == [
        [
            "docker",
            "exec",
            "--user=1000:1000",
            "--workdir=/workspace/pkg",
            session.name,
            "/usr/bin/env",
            "-i",
            "HOME=/tmp/home",
            "TMPDIR=/tmp",
            "PATH=/opt/ac/venv/bin:/usr/bin:/bin",
            "CI=1",
            "NO_COLOR=1",
            "PAGER=cat",
            "GIT_PAGER=cat",
            "GIT_TERMINAL_PROMPT=0",
            "AUTOCONTRIBUTE_SANDBOX=1",
            "PIP_NO_INDEX=1",
            "/bin/sh",
            "-c",
            'mkdir -p "$HOME" || exit\npython -m pytest -q',
        ]
    ]
    assert outcome.result.passed
    assert outcome.result.command == "python -m pytest -q"
    assert outcome.infrastructure_failure is None
    assert not outcome.restarted


def test_session_saves_full_output_where_the_agent_can_search_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    docker = _ScriptedDocker()
    session = _session(tmp_path, monkeypatch, docker)
    session.start()

    path = session.save_output(3, "line\n" * 5_000)

    assert path == "/tmp/ac-out/3.log"
    assert docker.calls[-1] == [
        "exec",
        "--interactive",
        "--user=1000:1000",
        session.name,
        "/usr/bin/env",
        "-i",
        "PATH=/usr/bin:/bin",
        "/bin/sh",
        "-c",
        "mkdir -p /tmp/ac-out && cat > /tmp/ac-out/3.log",
    ]
    assert docker.inputs[-1] == "line\n" * 5_000
    with pytest.raises(SandboxError, match="start at 1"):
        session.save_output(0, "output")

    monkeypatch.setattr(
        sandbox,
        "_docker_control",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 1, "", "no space left"),
    )
    assert session.save_output(4, "output") is None


def test_session_kills_leftover_processes_after_every_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    docker = _ScriptedDocker()
    session = _session(tmp_path, monkeypatch, docker)
    session.start()
    started_calls = len(docker.calls)

    session.exec("make test &", timeout_seconds=30)

    assert docker.calls[started_calls:] == [
        ["inspect", "--format", "{{.State.Running}} {{.State.OOMKilled}}", session.name],
        ["exec", "--user=1000:1000", session.name, "/bin/sh", "-c", "kill -KILL -1"],
        ["top", session.name, "-o", "pid,uid"],
    ]


def test_session_restarts_the_container_when_processes_survive_the_kill(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    docker = _ScriptedDocker()
    session = _session(tmp_path, monkeypatch, docker)
    session.start()
    name = session.name
    docker.leftovers = ["4200   1000\n"] * 3
    started_calls = len(docker.calls)

    outcome = session.exec("make test", timeout_seconds=30)

    calls = docker.calls[started_calls:]
    assert calls.count(["exec", "--user=1000:1000", name, "/bin/sh", "-c", "kill -KILL -1"]) == 3
    assert calls[-3:] == [
        ["kill", name],
        ["start", name],
        ["inspect", "--format", "{{.State.Running}} {{.State.OOMKilled}}", name],
    ]
    assert outcome.restarted
    assert outcome.infrastructure_failure is None
    assert session.name == name


def test_session_timeout_stops_the_command_before_the_client_and_reports_124(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    docker = _ScriptedDocker()
    session = _session(tmp_path, monkeypatch, docker)
    session.start()
    docker.command_times_out = True
    started_calls = len(docker.calls)

    outcome = session.exec("sleep 600", timeout_seconds=5)

    assert docker.calls[started_calls:][0] == [
        "exec",
        "--user=1000:1000",
        session.name,
        "/bin/sh",
        "-c",
        "kill -KILL -1",
    ]
    assert outcome.result.timed_out
    assert outcome.result.exit_code == 124
    assert outcome.infrastructure_failure is None
    assert not outcome.restarted


@pytest.mark.parametrize(
    ("state", "failure"),
    [
        ("false false", "the sandbox container stopped"),
        ("true true", "the sandbox ran out of memory (limit 2g)"),
        ("false true", "the sandbox ran out of memory (limit 2g)"),
    ],
)
def test_session_classifies_container_failures_as_infrastructure_and_restarts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    state: str,
    failure: str,
) -> None:
    docker = _ScriptedDocker()
    session = _session(tmp_path, monkeypatch, docker)
    session.start()
    docker.states = [state]

    outcome = session.exec("python -m pytest", timeout_seconds=30)

    assert outcome.infrastructure_failure == failure
    assert outcome.restarted
    assert ["start", session.name] in docker.calls


def test_session_replaces_a_container_that_does_not_start_again(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    docker = _ScriptedDocker()
    session = _session(tmp_path, monkeypatch, docker)
    session.start()
    old_name = session.name
    docker.states = ["false false"]
    docker.start_exit_code = 1

    outcome = session.exec("true", timeout_seconds=30)

    assert ["rm", "--force", "--volumes", old_name] in docker.calls
    assert docker.calls[-2][:3] == ["run", "--detach", f"--name={session.name}"]
    assert session.name != old_name
    assert outcome.restarted


def test_session_start_failure_removes_the_container_and_names_the_docker_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    docker = _ScriptedDocker()
    session = _session(tmp_path, monkeypatch, docker)
    docker.run_failure = (
        'docker: Error response from daemon: invalid mount config for type "bind": '
        "bind source path does not exist: /private/tmp/workspace\n"
        "Run 'docker run --help' for more information\n"
    )

    with pytest.raises(SandboxError, match="bind source path does not exist"):
        session.start()

    name = docker.calls[0][2].removeprefix("--name=")
    assert docker.calls[-1] == ["rm", "--force", "--volumes", name]
    with pytest.raises(SandboxError, match="not started"):
        _ = session.name


def test_session_is_removed_when_the_run_is_interrupted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    docker = _ScriptedDocker()
    session = _session(tmp_path, monkeypatch, docker)
    names: list[str] = []

    with pytest.raises(KeyboardInterrupt), session:
        names.append(session.name)
        raise KeyboardInterrupt

    assert docker.calls[-1] == ["rm", "--force", "--volumes", names[0]]
    session.remove()
    assert docker.calls[-1] == ["rm", "--force", "--volumes", names[0]]


def test_rootless_session_runs_and_reaps_commands_as_namespace_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    docker = _ScriptedDocker()
    session = _session(tmp_path, monkeypatch, docker, mode="rootless")
    session.start()
    docker.leftovers = ["4200   0\n"]

    outcome = session.exec("true", timeout_seconds=30)

    assert docker.commands[0][2] == "--user=0:0"
    assert ["exec", "--user=0:0", session.name, "/bin/sh", "-c", "kill -KILL -1"] in docker.calls
    assert docker.calls.count(["top", session.name, "-o", "pid,uid"]) == 2
    assert not outcome.restarted


def test_session_refuses_commands_that_would_share_the_main_process_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    docker = _ScriptedDocker()
    session = _session(tmp_path, monkeypatch, docker)
    monkeypatch.setattr(sandbox.os, "getuid", lambda: 65_534)

    with pytest.raises(SandboxError, match="main process identity"):
        session.start()

    assert docker.calls == []


@pytest.mark.parametrize(
    ("workdir", "environment"),
    [
        ("workspace", None),
        ("/workspace/../etc", None),
        ("/workspace\nother", None),
        ("/workspace", {"BAD-NAME": "1"}),
        ("/workspace", {"PATH": "/usr/bin\0/bin"}),
    ],
)
def test_session_rejects_unsafe_command_settings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    workdir: str,
    environment: dict[str, str] | None,
) -> None:
    docker = _ScriptedDocker()
    session = _session(tmp_path, monkeypatch, docker)
    session.start()

    with pytest.raises(SandboxError):
        session.exec("true", timeout_seconds=30, workdir=workdir, environment=environment)

    assert docker.commands == []


def test_session_requires_a_real_git_directory_and_a_safe_run_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    docker = _ScriptedDocker()
    session = _session(tmp_path, monkeypatch, docker)
    git_dir = tmp_path / "workspace" / ".git"
    git_dir.rmdir()
    git_dir.symlink_to(tmp_path, target_is_directory=True)

    with pytest.raises(SandboxError, match=r"real \.git directory"):
        session.start()
    with pytest.raises(SandboxError, match="Run identifier"):
        SessionContainer(
            SandboxConfig(),
            image=_SESSION_IMAGE,
            workspace=tmp_path / "workspace",
            run_id="../other",
            store_root=tmp_path / "state",
        )
    assert docker.calls == []


def test_leftover_sweep_removes_finished_or_unknown_runs_of_this_store_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    containers = {"running": "a" * 64, "finished": "b" * 64, "unlabelled": "c" * 64}
    networks = {"finished": "d" * 64, "running": "e" * 64}
    calls: list[list[str]] = []

    def control(
        _docker_binary: str,
        arguments: Sequence[str],
        _environment: dict[str, str],
    ) -> subprocess.CompletedProcess[str]:
        call = list(arguments)
        calls.append(call)
        if call[0] == "ps":
            rows = (
                f"{containers['running']} run-active\n"
                f"{containers['finished']} run-done\n"
                f"{containers['unlabelled']} \n"
            )
            return subprocess.CompletedProcess(call, 0, rows, "")
        if call[:2] == ["network", "ls"]:
            rows = f"{networks['finished']} run-done\n{networks['running']} run-active\n"
            return subprocess.CompletedProcess(call, 0, rows, "")
        return subprocess.CompletedProcess(call, 0, "", "")

    monkeypatch.setattr(sandbox, "_docker_control", control)
    store_hash = hashlib.sha256(os.fsencode((tmp_path / "state").resolve())).hexdigest()[:16]
    selection = [
        "--filter",
        f"label=org.autocontribute.store={store_hash}",
        "--format",
        '{{.ID}} {{.Label "org.autocontribute.run"}}',
    ]

    sandbox.remove_leftover_containers(tmp_path / "state", {"run-active", "run-queued"})

    assert calls == [
        ["ps", "--all", "--no-trunc", *selection],
        ["rm", "--force", "--volumes", containers["finished"]],
        ["rm", "--force", "--volumes", containers["unlabelled"]],
        ["network", "ls", "--no-trunc", *selection],
        ["network", "rm", networks["finished"]],
    ]


def test_leftover_sweep_fails_closed_when_docker_cannot_list(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sandbox, "_docker_control", lambda *_args: None)

    with pytest.raises(SandboxError, match="Could not list leftover"):
        sandbox.remove_leftover_containers(tmp_path / "state", set())
