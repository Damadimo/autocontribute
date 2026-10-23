"""Opt-in tests of environment setup, the egress proxy and baselines against a real daemon.

They pull python:3.12-alpine for the proxy and use python:3.13-slim-bookworm as the base
image, both only when missing, and remove what they pulled or built. Setup downloads a few
packages from pypi.org and deb.debian.org through the proxy.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from autocontribute.config import SandboxConfig
from autocontribute.environment_setup import EnvironmentSetup, image_tag
from autocontribute.environments import EnvironmentRecipe
from autocontribute.repository import RepositoryWorkspace
from autocontribute.sandbox import (
    EgressNetwork,
    docker_client_environment,
    inspect_image,
    remove_leftover_containers,
)
from autocontribute.suite_runs import acceptance_failure, run_baseline
from autocontribute.workspace_copies import copy_workspace

pytestmark = pytest.mark.skipif(
    os.environ.get("AUTOCONTRIBUTE_RUN_DOCKER_TESTS") != "1",
    reason="set AUTOCONTRIBUTE_RUN_DOCKER_TESTS=1 to run live Docker environment tests",
)

_PROXY_IMAGE = (
    "python:3.12-alpine@sha256:b658b05ce9c4eb97ec6fc19424818a1f31993659c2b505a532f470e83807815d"
)
_BASE_IMAGE = "python@sha256:e32be0e55814a08977501ca863271d9bd02443710db8f2afaf8372e2c4508530"
_CONFIG = SandboxConfig(memory="1g", cpus=2.0, pids_limit=256, command_timeout_seconds=600)
_PROXY_NAMES = {"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"}
_FETCH = """
import sys, urllib.request
try:
    print(urllib.request.urlopen(sys.argv[1], timeout=20).status)
except Exception as error:
    print(type(error).__name__, error)
"""


def _docker(*arguments: str, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *arguments],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
        env=docker_client_environment(),
    )


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


def _present_or_pulled(image: str) -> Iterator[str]:
    if shutil.which("docker") is None:
        pytest.fail("live Docker tests were requested but Docker is not installed")
    present = _docker("image", "inspect", image).returncode == 0
    if not present:
        pulled = _docker("pull", "--quiet", image, timeout=900)
        assert pulled.returncode == 0, pulled.stderr
    try:
        yield image
    finally:
        if not present:
            _docker("image", "rm", image)


@pytest.fixture(scope="module")
def proxy_image() -> Iterator[str]:
    yield from _present_or_pulled(_PROXY_IMAGE)


@pytest.fixture(scope="module")
def base_image() -> Iterator[str]:
    yield from _present_or_pulled(_BASE_IMAGE)


@pytest.fixture
def live_root() -> Iterator[Path]:
    # Colima shares only $HOME with its VM, and pytest's tmp_path is outside it on macOS.
    with tempfile.TemporaryDirectory(
        prefix=".autocontribute-live-", dir=Path(__file__).resolve().parents[1]
    ) as temporary:
        root = Path(temporary)
        try:
            yield root
        finally:
            remove_leftover_containers(root / "state", ())


def test_live_egress_proxy_allows_listed_hosts_and_refuses_others(
    live_root: Path, proxy_image: str
) -> None:
    with EgressNetwork(
        allowed_hosts=["pypi.org"], run_id="live-proxy", store_root=live_root / "state"
    ) as network:

        def fetch(url: str, *, proxied: bool = True) -> str:
            proxy = [f"--env=HTTPS_PROXY={network.proxy_url}"] if proxied else []
            completed = _docker(
                "run",
                "--rm",
                f"--network={network.network}",
                *proxy,
                proxy_image,
                "python3",
                "-c",
                _FETCH,
                url,
            )
            return completed.stdout.strip()

        assert fetch("https://pypi.org/simple/") == "200"
        assert "403" in fetch("https://example.com/")
        assert "403" in fetch("https://1.1.1.1/")
        # Without the proxy the internal network has no route and no external names.
        assert fetch("https://pypi.org/simple/", proxied=False).startswith("URLError")
        assert network.refused_requests() == [
            "deny CONNECT example.com:443: the host is not on the setup allowlist",
            "deny CONNECT 1.1.1.1:443: IP addresses are refused; use a host name",
        ]
        proxy, net = network.proxy, network.network

    assert _docker("container", "inspect", proxy).returncode != 0
    assert _docker("network", "inspect", net).returncode != 0


def _synthetic_repository(root: Path) -> RepositoryWorkspace:
    source = root / "source"
    (source / "src" / "acdemo").mkdir(parents=True)
    (source / "tests").mkdir()
    (source / "pyproject.toml").write_text(
        '[build-system]\nrequires = ["setuptools>=69"]\nbuild-backend = "setuptools.build_meta"\n'
        '[project]\nname = "acdemo"\nversion = "0.1.0"\n',
        encoding="utf-8",
    )
    (source / ".gitignore").write_text("*.egg-info/\nbuild/\n", encoding="utf-8")
    (source / "src" / "acdemo" / "__init__.py").write_text(
        "def add(a, b):\n    return a + b\n", encoding="utf-8"
    )
    (source / "tests" / "test_acdemo.py").write_text(
        "import urllib.request\n\nimport pytest\n\nfrom acdemo import add\n\n\n"
        "@pytest.mark.parametrize('n', range(10))\n"
        "def test_adds(n):\n    assert add(n, 1) == n + 1\n\n\n"
        "def test_known_bug():\n    assert add(0.1, 0.2) == 0.3\n\n\n"
        "def test_needs_network():\n"
        "    urllib.request.urlopen('https://pypi.org/simple/', timeout=5)\n",
        encoding="utf-8",
    )
    _git(source, "init", "-q")
    _git(source, "add", ".")
    _git(source, "commit", "-qm", "base")
    return RepositoryWorkspace.clone(
        str(source), _git(source, "rev-parse", "HEAD"), root / "W", allow_local_source=True
    )


def _recipe() -> EnvironmentRecipe:
    path = "/opt/ac/venv/bin:/usr/local/bin:/usr/bin:/bin"
    return EnvironmentRecipe(
        repository="acme/acdemo",
        language="python",
        base_image=_BASE_IMAGE,
        # Missing from the slim image, so the bootstrap runs apt through the proxy.
        system_packages=["less", "no-such-package-in-debian"],
        setup_commands=[
            # Setup sees .git read-only, like every container that mounts the workspace.
            "! touch .git/probe 2>/dev/null",
            "python -m venv /opt/ac/venv",
            "pip install --no-cache-dir --disable-pip-version-check -e . pytest",
            # Left behind on purpose: setup must undo it before the snapshot.
            "echo generated > stray.txt",
        ],
        build_commands=[],
        test_command="python -m pytest -p no:cacheprovider --junitxml=/tmp/ac-report.xml",
        test_framework="pytest",
        test_report="/tmp/ac-report.xml",
        env={"PATH": path, "VIRTUAL_ENV": "/opt/ac/venv", "LANG": "C.UTF-8"},
        offline_env={"PIP_NO_INDEX": "1"},
        fetch_tags=False,
        fetch_submodules=False,
        source="config",
        dependency_digest="b" * 64,
    )


def test_live_environment_is_built_through_the_proxy_baselined_offline_and_reused(
    live_root: Path, proxy_image: str, base_image: str
) -> None:
    state = live_root / "state"
    workspace = _synthetic_repository(live_root)
    setup = EnvironmentSetup(_CONFIG, run_id="live-env", store_root=state)
    base = inspect_image(base_image)
    assert base is not None
    key = "c" * 64
    tag = image_tag("acme/acdemo", key)
    try:
        image, recipe = setup.build(
            workspace,
            _recipe(),
            base=base,
            cache_key=key,
            allow_hosts=(),
            distribution="acdemo",
        )

        assert recipe.setup_dirty_paths == ["stray.txt"]
        assert not (workspace.path / "stray.txt").exists()
        assert workspace.changed_paths() == []
        assert workspace.ignored_paths() == ["src/acdemo.egg-info/"]
        details = json.loads(_docker("image", "inspect", image.image_id).stdout)[0]
        config = details["Config"]
        assert config["Cmd"] == ["-i", "PATH=/usr/bin:/bin", "/bin/sleep", "infinity"]
        assert config["Labels"]["org.autocontribute.environment"].startswith("sha256:")
        leaked = [
            entry
            for entry in config["Env"] or []
            if entry.split("=", 1)[0] in _PROXY_NAMES and entry.split("=", 1)[1]
        ]
        assert leaked == []
        assert _docker("image", "inspect", tag).returncode == 0
        # apt ran through the proxy, and the command uid owns /opt/ac and has a passwd entry.
        probe = _docker(
            "run",
            "--rm",
            "--network=none",
            "--entrypoint=/bin/sh",
            image.image_id,
            "-c",
            f"command -v less && stat -c %u /opt/ac/venv && getent passwd {os.getuid()}",
        )
        assert probe.returncode == 0, probe.stderr
        assert probe.stdout.splitlines()[:2] == ["/usr/bin/less", str(os.getuid())]

        snapshot = workspace.path.with_name("W.snapshot")
        copy_workspace(workspace.path, snapshot)
        baseline, runs = run_baseline(
            _CONFIG,
            image_id=image.image_id,
            recipe=recipe,
            snapshot=snapshot,
            base_sha=workspace.base_sha,
            run_id="live-env",
            store_root=state,
        )

        assert len(runs) == 2
        assert baseline.collected == 12
        assert baseline.pass_stable == [f"tests.test_acdemo::test_adds[{n}]" for n in range(10)]
        assert baseline.fail_before == [
            "tests.test_acdemo::test_known_bug",
            "tests.test_acdemo::test_needs_network",
        ]
        assert baseline.flaky == [] and baseline.skip == []
        assert acceptance_failure(baseline, runs) is None
        offline = runs[0].results["tests.test_acdemo::test_needs_network"].message
        assert "URLError" in offline or "unreachable" in offline.lower()

        fresh = _synthetic_repository(live_root / "again")
        reused = setup.reuse(fresh, recipe, base=base, cache_key=key)
        assert reused is not None and reused.reused and reused.image_id == image.image_id
        assert fresh.ignored_paths() == ["src/acdemo.egg-info/"]
        assert fresh.changed_paths() == []
    finally:
        _docker("image", "rm", "--force", tag)
