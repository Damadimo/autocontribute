"""Opt-in integration tests that exercise a real Docker daemon.

The normal unit suite never starts repository code.  This module is enabled by the
dedicated security-integration workflow so changes to the Docker invocation are
also checked against the daemon rather than only against an argv snapshot.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import subprocess
import tempfile
import time
from collections.abc import Iterator, Mapping
from pathlib import Path

import pytest

from autocontribute.config import SandboxConfig
from autocontribute.edit_tools import apply_patch_operation, run_text_editor, syntax_check
from autocontribute.sandbox import (
    DockerSandbox,
    SessionContainer,
    detect_docker_daemon_mode,
    docker_client_environment,
    docker_container_identity,
    remove_leftover_containers,
)
from autocontribute.workspace_files import WorkspaceFiles

pytestmark = pytest.mark.skipif(
    os.environ.get("AUTOCONTRIBUTE_RUN_DOCKER_TESTS") != "1",
    reason="set AUTOCONTRIBUTE_RUN_DOCKER_TESTS=1 to run live Docker isolation tests",
)

# Busybox provides sh, setsid and `sleep infinity`, which is all the session tests need.
_ALPINE = "alpine@sha256:d406446bc05b82480756ce8f1287964d28768c23955fa9480d2a74a2eae7a654"
# The smallest official Python image, for the syntax check.
_PYTHON = "python@sha256:e32be0e55814a08977501ca863271d9bd02443710db8f2afaf8372e2c4508530"
_SESSION_CONFIG = SandboxConfig(memory="512m", cpus=1.0, pids_limit=64)
_MAIN_UID = "65534"
_PROXY_NAMES = (
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
)


def _docker(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *arguments],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
        env=docker_client_environment(),
    )


def _pinned_image(image: str) -> Iterator[str]:
    if shutil.which("docker") is None:
        pytest.fail("live Docker isolation was requested but Docker is not installed")
    present = _docker("image", "inspect", image).returncode == 0
    if not present:
        pulled = _docker("pull", "--quiet", image)
        assert pulled.returncode == 0, pulled.stderr
    try:
        yield image
    finally:
        if not present:
            _docker("image", "rm", image)


@pytest.fixture(scope="module")
def alpine_image() -> Iterator[str]:
    yield from _pinned_image(_ALPINE)


@pytest.fixture(scope="module")
def python_image() -> Iterator[str]:
    yield from _pinned_image(_PYTHON)


@pytest.fixture
def live_root() -> Iterator[Path]:
    # Colima shares only $HOME with its VM, and pytest's tmp_path is outside it on macOS.
    with tempfile.TemporaryDirectory(
        prefix=".autocontribute-live-", dir=Path(__file__).resolve().parents[1]
    ) as temporary:
        yield Path(temporary)


def _workspace(root: Path) -> Path:
    workspace = root / "workspace"
    (workspace / ".git").mkdir(parents=True, exist_ok=True)
    workspace.chmod(0o700)
    return workspace


def _session(root: Path, image: str, *, run_prefix: str = "live") -> SessionContainer:
    return SessionContainer(
        _SESSION_CONFIG,
        image=image,
        workspace=_workspace(root),
        run_id=f"{run_prefix}-{secrets.token_hex(4)}",
        store_root=root / "state",
    )


@pytest.fixture
def session(live_root: Path, alpine_image: str) -> Iterator[SessionContainer]:
    with _session(live_root, alpine_image) as started:
        name = started.name
        yield started
    assert _docker("container", "inspect", name).returncode != 0, "session was not removed"


def _command_processes(session: SessionContainer) -> list[str]:
    listed = _docker("top", session.name, "-o", "pid,uid")
    assert listed.returncode == 0, listed.stderr
    rows = [line.split() for line in listed.stdout.splitlines()[1:] if line.strip()]
    assert any(uid == _MAIN_UID for _, uid in rows), "the main process is gone"
    return [pid for pid, uid in rows if uid != _MAIN_UID]


def _running(session: SessionContainer) -> bool:
    inspected = _docker("container", "inspect", "--format", "{{.State.Running}}", session.name)
    return inspected.stdout.strip() == "true"


def _passed(
    session: SessionContainer,
    command: str,
    environment: Mapping[str, str] | None = None,
) -> str:
    outcome = session.exec(command, timeout_seconds=30, environment=environment)
    assert outcome.result.passed, outcome.result.stderr
    assert outcome.infrastructure_failure is None
    assert not outcome.restarted
    return outcome.result.stdout


def test_live_container_cannot_reach_network_credentials_or_git_metadata(
    live_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if shutil.which("docker") is None:
        pytest.fail("live Docker isolation was requested but Docker is not installed")

    workspace = live_root / "untrusted-repository"
    (workspace / ".git").mkdir(parents=True)
    (workspace / "README.md").write_text("fixture\n", encoding="utf-8")
    workspace.chmod(0o700)
    host_secret = "must-not-cross-the-sandbox-boundary"
    monkeypatch.setenv("AUTOCONTRIBUTE_HOST_SECRET", host_secret)
    runner = DockerSandbox(SandboxConfig(command_timeout_seconds=30))
    daemon_mode = runner.docker_daemon_mode
    uid_assertion = (
        'assert os.getuid() == 0, "rootless namespace root was not selected"'
        if daemon_mode == "rootless"
        else 'assert os.getuid() != 0, "repository code ran as root on a rootful daemon"'
    )

    command = f"""
python - <<'PY'
import os
import socket
from pathlib import Path

{uid_assertion}
assert "AUTOCONTRIBUTE_HOST_SECRET" not in os.environ, "host environment leaked"
assert Path("README.md").read_text() == "fixture\\n", "private bind was not readable"
os.umask(0o077)
Path("container-output").write_text("container-to-host\\n")

cgroup = Path("/sys/fs/cgroup")
assert (cgroup / "memory.max").read_text().strip() == "4294967296", (
    "memory limit was not enforced"
)
assert (cgroup / "memory.swap.max").read_text().strip() == "0", (
    "memory-swap limit was not enforced"
)
assert (cgroup / "pids.max").read_text().strip() == "256", "PID limit was not enforced"
cpu_quota, cpu_period = (cgroup / "cpu.max").read_text().split()
assert cpu_quota != "max" and int(cpu_quota) == 2 * int(cpu_period), (
    "CPU quota was not enforced"
)

status = dict(
    line.split(":", 1)
    for line in Path("/proc/self/status").read_text().splitlines()
    if ":" in line
)
for capability_name in ("CapEff", "CapPrm", "CapBnd", "CapAmb"):
    assert int(status[capability_name].strip(), 16) == 0, (
        f"container retained {{capability_name}} capabilities"
    )
assert status["NoNewPrivs"].strip() == "1", "no-new-privileges was not enforced"

try:
    socket.create_connection(("1.1.1.1", 53), timeout=1)
except OSError:
    pass
else:
    raise AssertionError("sandbox unexpectedly reached the network")

try:
    Path("/.autocontribute-root-write-probe").write_text("unsafe")
except OSError:
    pass
else:
    raise AssertionError("container root filesystem was writable")

try:
    Path(".git/autocontribute-write-probe").write_text("unsafe")
except OSError:
    pass
else:
    raise AssertionError("Git metadata mount was writable")

print("sandbox-isolation-ok")
PY
"""

    result = runner.run(workspace, command)

    assert result.passed, result.stderr
    assert result.stdout.strip() == "sandbox-isolation-ok"
    assert host_secret not in result.stdout
    assert host_secret not in result.stderr
    assert not (workspace / ".git" / "autocontribute-write-probe").exists()
    output = workspace / "container-output"
    output_stat = output.stat()
    assert output.read_text(encoding="utf-8") == "container-to-host\n"
    assert output_stat.st_uid == os.getuid()
    assert output_stat.st_gid == os.getgid()
    assert output_stat.st_mode & 0o777 == 0o600


def test_live_validation_container_keeps_path_and_has_executable_tmp_and_dev_shm(
    live_root: Path,
    alpine_image: str,
) -> None:
    runner = DockerSandbox(SandboxConfig(image=alpine_image, command_timeout_seconds=30))

    result = runner.run_isolated(
        _workspace(live_root),
        'echo "$PATH"\n'
        "printf '#!/bin/sh\\necho exec-from-tmp\\n' > /tmp/probe && chmod +x /tmp/probe\n"
        "/tmp/probe\n"
        "echo shared > /dev/shm/probe && cat /dev/shm/probe",
    )

    assert result.passed, result.stderr
    assert result.stdout.splitlines() == [
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "exec-from-tmp",
        "shared",
    ]


def test_live_session_commands_keep_every_boundary(session: SessionContainer) -> None:
    status = dict(
        line.split(":", 1) for line in _passed(session, "cat /proc/self/status").splitlines()
    )
    for capability in ("CapEff", "CapPrm", "CapBnd", "CapAmb"):
        assert int(status[capability], 16) == 0, f"commands kept {capability}"
    assert status["NoNewPrivs"].strip() == "1"
    assert _passed(session, "ls /sys/class/net").split() == ["lo"]
    limits = _passed(
        session, "cd /sys/fs/cgroup && cat memory.max memory.swap.max pids.max cpu.max"
    ).split()
    assert limits[:3] == ["536870912", "0", "64"]
    assert int(limits[3]) == int(limits[4])
    uid, gid = docker_container_identity(detect_docker_daemon_mode())
    assert _passed(session, "id -u; id -g").split() == [str(uid), str(gid)]

    probes = _passed(
        session,
        "touch .git/probe 2>/dev/null && echo git-writable\n"
        "touch /probe 2>/dev/null && echo root-writable\n"
        "echo from-container > output && echo workspace-writable",
    )

    assert probes.split() == ["workspace-writable"]
    assert (session.workspace / "output").read_text(encoding="utf-8") == "from-container\n"


def test_live_session_commands_cannot_kill_or_read_the_main_process(
    session: SessionContainer,
) -> None:
    probes = _passed(
        session,
        "for status in /proc/[0-9]*/status; do\n"
        "  grep -q '^Uid:[[:space:]]*65534[[:space:]]' \"$status\" || continue\n"
        '  pid=${status#/proc/}; pid=${pid%/status}; echo "main $pid"\n'
        '  kill -KILL "$pid" 2>/dev/null && echo "killed $pid"\n'
        '  cat "/proc/$pid/environ" >/dev/null 2>&1 && echo "read $pid"\n'
        "done",
    )

    assert "main 1" in probes.splitlines()
    assert len(probes.splitlines()) == 2, probes
    assert _running(session)
    assert _command_processes(session) == []


def test_live_session_gets_the_recipe_path_an_executable_tmp_and_dev_shm(
    session: SessionContainer,
) -> None:
    output = _passed(
        session,
        'echo "$PATH"; echo "$HOME"; test -d "$HOME" && echo home-created\n'
        "printf '#!/bin/sh\\necho exec-from-tmp\\n' > /tmp/probe && chmod +x /tmp/probe\n"
        "/tmp/probe\n"
        "echo shared > /dev/shm/probe && cat /dev/shm/probe\n"
        "grep ' /dev/shm ' /proc/mounts",
        environment={"PATH": "/opt/recipe/bin:/usr/bin:/bin"},
    )

    lines = output.splitlines()
    assert lines[:5] == [
        "/opt/recipe/bin:/usr/bin:/bin",
        "/tmp/home",
        "home-created",
        "exec-from-tmp",
        "shared",
    ]
    assert "size=262144k" in lines[5]


def test_live_session_reaps_background_writers_before_returning(
    session: SessionContainer,
) -> None:
    ticks = session.workspace / "ticks"

    _passed(
        session,
        "(while :; do echo tick >> ticks; sleep 0.1; done) >/dev/null 2>&1 &\nsleep 1",
    )
    written = ticks.stat().st_size
    time.sleep(0.5)

    assert written > 0
    assert ticks.stat().st_size == written
    assert _command_processes(session) == []


def test_live_session_timeout_kills_setsid_children(session: SessionContainer) -> None:
    started = time.monotonic()

    outcome = session.exec(
        "setsid sh -c 'exec sleep 600' >/dev/null 2>&1 &\nsleep 600",
        timeout_seconds=2,
    )

    assert outcome.result.timed_out
    assert outcome.result.exit_code == 124
    assert outcome.infrastructure_failure is None
    assert not outcome.restarted
    assert time.monotonic() - started < 15
    assert _command_processes(session) == []


def test_live_session_reaps_a_fork_loop_that_holds_the_pids_limit(
    session: SessionContainer,
) -> None:
    # A shell exits when a fork fails, so the outer loop starts a new forking subshell
    # each time and the limit stays held. `read` and `[` are builtins: waiting never forks.
    output = _passed(
        session,
        "(while :; do (while :; do sleep 600 & done); done) >/dev/null 2>&1 &\n"
        'while read -r count < /sys/fs/cgroup/pids.current && [ "$count" -lt 60 ]; do :; done\n'
        "echo saturated",
    )

    assert output == "saturated\n"
    assert _command_processes(session) == []
    assert _passed(session, "echo alive") == "alive\n"


def test_live_session_restart_keeps_the_workspace_and_empties_tmp(
    session: SessionContainer,
) -> None:
    name = session.name
    _passed(session, "echo kept > kept; echo gone > /tmp/gone")

    session.restart()

    assert session.name == name
    assert _running(session)
    assert _passed(session, "cat kept; test -e /tmp/gone || echo tmp-emptied") == (
        "kept\ntmp-emptied\n"
    )
    assert _command_processes(session) == []


def test_live_session_classifies_a_stopped_container_as_infrastructure(
    session: SessionContainer,
) -> None:
    assert _docker("kill", session.name).returncode == 0

    outcome = session.exec("echo hello", timeout_seconds=30)

    assert not outcome.result.passed
    assert outcome.infrastructure_failure == "the sandbox container stopped"
    assert outcome.restarted
    assert _passed(session, "echo back") == "back\n"


def test_live_session_classifies_running_out_of_memory_and_recovers(
    session: SessionContainer,
) -> None:
    # The /tmp tmpfs counts against the memory limit and cannot be swapped out.
    outcome = session.exec("head -c 600m /dev/zero > /tmp/fill", timeout_seconds=60)

    assert not outcome.result.passed
    assert outcome.infrastructure_failure == "the sandbox ran out of memory (limit 512m)"
    assert outcome.restarted
    # Docker's OOMKilled flag is sticky until a restart, so this also proves it was cleared.
    assert _passed(session, "test -e /tmp/fill || echo tmp-emptied") == "tmp-emptied\n"


def test_live_docker_cli_proxies_are_blank_in_every_container(
    live_root: Path,
    alpine_image: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A private client config replaces the operator's, so pin the endpoint it names first.
    endpoint = _docker("context", "inspect", "--format", "{{.Endpoints.docker.Host}}")
    assert endpoint.returncode == 0, endpoint.stderr
    secret = f"proxy-secret-{secrets.token_hex(4)}"
    proxy = f"http://operator:{secret}@proxy.invalid:3128"
    client_config = live_root / "docker-config"
    client_config.mkdir()
    (client_config / "config.json").write_text(
        json.dumps(
            {
                "proxies": {
                    "default": {
                        "httpProxy": proxy,
                        "httpsProxy": proxy,
                        "ftpProxy": proxy,
                        "allProxy": proxy,
                        "noProxy": f"{secret}.invalid",
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("DOCKER_HOST", os.environ.get("DOCKER_HOST") or endpoint.stdout.strip())
    monkeypatch.delenv("DOCKER_CONTEXT", raising=False)
    monkeypatch.setenv("DOCKER_CONFIG", str(client_config))
    blank = [f"{name}=" for name in _PROXY_NAMES]
    runner = DockerSandbox(SandboxConfig(image=alpine_image, command_timeout_seconds=30))

    # PID 1 of a validation container runs as the command's own uid, so it can read this.
    validation = runner.run(_workspace(live_root), "tr '\\0' '\\n' < /proc/1/environ")

    assert validation.passed, validation.stderr
    assert secret not in validation.stdout
    assert set(blank) <= set(validation.stdout.splitlines())
    with _session(live_root, alpine_image) as session:
        inspected = _docker(
            "container", "inspect", "--format", "{{json .Config.Env}}", session.name
        )
        command_environment = _passed(session, "env")
    assert secret not in inspected.stdout
    assert set(blank) <= set(json.loads(inspected.stdout))
    assert secret not in command_environment
    assert "PROXY" not in command_environment.upper()


def test_live_leftover_sweep_removes_only_finished_or_unknown_runs(
    live_root: Path,
    alpine_image: str,
) -> None:
    store_root = live_root / "state"
    store_label = hashlib.sha256(os.fsencode(store_root.resolve())).hexdigest()[:16]
    active = _session(live_root, alpine_image, run_prefix="live-active")
    abandoned = _session(live_root, alpine_image, run_prefix="live-abandoned")
    network = f"ac-live-{secrets.token_hex(4)}"
    try:
        active.start()
        abandoned.start()
        created = _docker(
            "network",
            "create",
            "--internal",
            f"--label=org.autocontribute.store={store_label}",
            f"--label=org.autocontribute.run={abandoned.run_id}",
            network,
        )
        assert created.returncode == 0, created.stderr

        remove_leftover_containers(store_root, {active.run_id})

        assert _running(active)
        assert _docker("container", "inspect", abandoned.name).returncode != 0
        assert _docker("network", "inspect", network).returncode != 0
    finally:
        active.remove()
        abandoned.remove()
        _docker("network", "rm", network)


def test_live_session_saves_full_output_the_agent_can_search(session: SessionContainer) -> None:
    output = "".join(f"line {number}\n" for number in range(20_000))

    path = session.save_output(1, output)

    assert path == "/tmp/ac-out/1.log"
    assert _passed(session, f"grep -c '^line' {path}") == "20000\n"
    assert _passed(session, f"tail -n 1 {path}") == "line 19999\n"


def test_live_host_file_tools_refuse_symlinks_a_command_planted(
    live_root: Path, session: SessionContainer
) -> None:
    outside = live_root / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("host secret\n", encoding="utf-8")
    # Targets are host paths: inside the container they dangle, on the host they resolve.
    _passed(
        session,
        f"ln -s {outside} /workspace/escape && ln -s {outside}/secret.txt /workspace/secret.py",
    )
    files = WorkspaceFiles(session.workspace)

    results = [
        run_text_editor(files, {"command": "view", "path": "/workspace/escape/secret.txt"}),
        run_text_editor(
            files, {"command": "create", "path": "escape/planted.txt", "file_text": "x\n"}
        ),
        run_text_editor(
            files,
            {"command": "str_replace", "path": "secret.py", "old_str": "host", "new_str": "x"},
        ),
        apply_patch_operation(
            files, {"type": "update_file", "path": "secret.py", "diff": "-host secret\n+owned\n"}
        ),
        apply_patch_operation(files, {"type": "delete_file", "path": "secret.py"}),
    ]

    assert [result.status for result in results] == ["failed"] * len(results)
    assert all("symlink" in result.output for result in results)
    assert sorted(path.name for path in outside.iterdir()) == ["secret.txt"]
    assert (outside / "secret.txt").read_text(encoding="utf-8") == "host secret\n"


def test_live_syntax_check_reports_errors_and_writes_no_bytecode(
    live_root: Path, python_image: str, session: SessionContainer
) -> None:
    (session.workspace / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    # Alpine has no Python, so the check has nothing to say.
    assert syntax_check(session, "broken.py") is None

    with _session(live_root / "python", python_image) as python_session:
        workspace = python_session.workspace
        (workspace / "good.py").write_text("value = 1\n", encoding="utf-8")
        (workspace / "broken.py").write_text("def broken(:\n", encoding="utf-8")

        assert syntax_check(python_session, "good.py") is None
        message = syntax_check(python_session, "broken.py")
        assert syntax_check(python_session, "deleted.py") is None

    assert message is not None
    assert 'File "/workspace/broken.py", line 1' in message
    assert "SyntaxError" in message
    assert not list(workspace.rglob("__pycache__"))
