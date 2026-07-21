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
        pytest.skip("Docker is not installed")

    workspace = tmp_path / "untrusted-repository"
    (workspace / ".git").mkdir(parents=True)
    (workspace / "README.md").write_text("fixture\n", encoding="utf-8")
    host_secret = "must-not-cross-the-sandbox-boundary"
    monkeypatch.setenv("AUTOCONTRIBUTE_HOST_SECRET", host_secret)

    command = r"""
python - <<'PY'
import os
import socket
from pathlib import Path

assert os.getuid() != 0, "repository code ran as root"
assert "AUTOCONTRIBUTE_HOST_SECRET" not in os.environ, "host environment leaked"

capability = next(
    line.split(":", 1)[1].strip()
    for line in Path("/proc/self/status").read_text().splitlines()
    if line.startswith("CapEff:")
)
assert int(capability, 16) == 0, "container retained Linux capabilities"

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

    result = DockerSandbox(SandboxConfig(command_timeout_seconds=30)).run(workspace, command)

    assert result.passed, result.stderr
    assert result.stdout.strip() == "sandbox-isolation-ok"
    assert host_secret not in result.stdout
    assert host_secret not in result.stderr
    assert not (workspace / ".git" / "autocontribute-write-probe").exists()
