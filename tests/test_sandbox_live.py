"""Opt-in integration tests that exercise a real Docker daemon.

The normal unit suite never starts repository code.  This module is enabled by the
dedicated security-integration workflow so changes to the Docker invocation are
also checked against the daemon rather than only against an argv snapshot.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from autocontribute.config import SandboxConfig
from autocontribute.sandbox import DockerSandbox


def _live_docker_enabled() -> bool:
    return os.environ.get("AUTOCONTRIBUTE_RUN_DOCKER_TESTS") == "1"


@pytest.mark.skipif(
    not _live_docker_enabled(),
    reason="set AUTOCONTRIBUTE_RUN_DOCKER_TESTS=1 to run live Docker isolation tests",
)
def test_live_container_cannot_reach_network_credentials_or_git_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if shutil.which("docker") is None:
        pytest.fail("live Docker isolation was requested but Docker is not installed")

    workspace = tmp_path / "untrusted-repository"
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
