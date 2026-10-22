"""Resource-capped command execution for repository validation."""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Sequence
from contextlib import suppress
from pathlib import Path
from typing import Final, Literal

from autocontribute.config import SandboxConfig
from autocontribute.domain import CommandResult
from autocontribute.exceptions import SandboxError
from autocontribute.repository import RepositoryWorkspace

_CONTAINER_WORKSPACE: Final = "/workspace"
_SHM_SIZE: Final = "256m"
_MAX_CAPTURE_BYTES: Final = 2_000_000
_TRUNCATED_MARKER: Final = b"\n[output truncated by autocontribute]\n"
_SAFE_CONTAINER_PATH: Final = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
_DOCKER_RUNTIME_INFO_FORMAT: Final = (
    '{"security_options":{{json .SecurityOptions}},'
    '"cgroup_version":{{json .CgroupVersion}},'
    '"cgroup_driver":{{json .CgroupDriver}},'
    '"memory_limit":{{json .MemoryLimit}},'
    '"swap_limit":{{json .SwapLimit}},'
    '"cpu_cfs_period":{{json .CPUCfsPeriod}},'
    '"cpu_cfs_quota":{{json .CPUCfsQuota}},'
    '"pids_limit":{{json .PidsLimit}}}'
)
_DOCKER_RUNTIME_INFO_KEYS: Final = frozenset(
    {
        "security_options",
        "cgroup_version",
        "cgroup_driver",
        "memory_limit",
        "swap_limit",
        "cpu_cfs_period",
        "cpu_cfs_quota",
        "pids_limit",
    }
)
_DOCKER_RESOURCE_CAPABILITIES: Final = (
    "memory_limit",
    "swap_limit",
    "cpu_cfs_period",
    "cpu_cfs_quota",
    "pids_limit",
)
_DOCKER_CLIENT_ENV_NAMES: Final = (
    "DOCKER_API_VERSION",
    "DOCKER_CERT_PATH",
    "DOCKER_CONFIG",
    "DOCKER_CONTEXT",
    "DOCKER_HOST",
    "DOCKER_TLS_VERIFY",
    "HOME",
    "LANG",
    "LC_ALL",
    "XDG_CONFIG_HOME",
    "XDG_RUNTIME_DIR",
)
# The Docker CLI copies the `proxies` block of its config.json, credentials included,
# into every container it starts unless the variable is already set.
_DOCKER_CLI_PROXY_NAMES: Final = (
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

DockerDaemonMode = Literal["rootful", "rootless"]


class SandboxRunner:
    """Run validation commands in Docker, or explicitly opt into unsafe local use."""

    def __init__(self, config: SandboxConfig, *, docker_binary: str = "docker") -> None:
        self.config = config
        self.docker_binary = docker_binary
        self._commands_run = 0
        # Keep daemon discovery, container launch, and timeout cleanup on the same
        # Docker endpoint even if the parent process mutates its environment later.
        self._docker_environment = docker_client_environment()
        if config.backend == "local" and not config.allow_unsafe_local:
            raise SandboxError("Local execution requires allow_unsafe_local=true")
        if not docker_binary or "\0" in docker_binary:
            raise SandboxError("Docker binary is invalid")

    def run(
        self,
        workspace: RepositoryWorkspace | Path,
        command: str,
    ) -> CommandResult:
        """Run one bounded shell command and capture a size-limited result."""

        root = _workspace_path(workspace)
        _validate_command(command)
        if self._commands_run >= self.config.max_commands:
            raise SandboxError(
                f"Sandbox command budget exhausted ({self.config.max_commands} commands)"
            )
        self._commands_run += 1

        if self.config.backend == "local":
            return self._run_local(root, command)
        if self.config.backend != "docker":  # defensive against non-Pydantic construction
            raise SandboxError(f"Unsupported sandbox backend: {self.config.backend}")
        return self._run_docker(root, command)

    @property
    def remaining_commands(self) -> int:
        """Return the unused per-run command budget."""

        return max(0, self.config.max_commands - self._commands_run)

    @property
    def docker_daemon_mode(self) -> DockerDaemonMode:
        """Return the verified Docker daemon mode used by this runner."""

        if self.config.backend != "docker":
            raise SandboxError("Docker daemon mode is unavailable for the local backend")
        # Re-probe immediately before every launch. A long validation run must
        # never retain rootless UID 0 if its endpoint is replaced by a rootful daemon.
        return detect_docker_daemon_mode(
            self.docker_binary,
            environment=self._docker_environment,
        )

    def run_isolated(
        self,
        workspace: RepositoryWorkspace | Path,
        command: str,
    ) -> CommandResult:
        """Run one command against a disposable copy of the exact working tree."""

        root = _workspace_path(workspace)
        with tempfile.TemporaryDirectory(
            prefix=".autocontribute-validation-", dir=root.parent
        ) as temporary:
            isolated = Path(temporary) / "workspace"
            try:
                shutil.copytree(root, isolated, symlinks=True)
            except (OSError, shutil.Error) as exc:
                raise SandboxError("Could not create an isolated validation workspace") from exc
            return self.run(isolated, command)

    def run_all_isolated(
        self,
        workspace: RepositoryWorkspace | Path,
        commands: Sequence[str],
    ) -> list[CommandResult]:
        """Run each command on a fresh copy, stopping at the first failure."""

        if len(commands) > self.config.max_commands - self._commands_run:
            raise SandboxError(
                f"Validation requested more than the {self.config.max_commands}-command budget"
            )
        results: list[CommandResult] = []
        for command in commands:
            result = self.run_isolated(workspace, command)
            results.append(result)
            if not result.passed:
                break
        return results

    def docker_command(self, workspace: Path, command: str, cidfile: Path) -> list[str]:
        """Build the auditable ``docker run`` invocation used by :meth:`run`."""

        root = _workspace_path(workspace)
        _validate_command(command)
        _validate_image(self.config.image)
        mounts = _workspace_mounts(root)
        if cidfile.exists() and cidfile.is_symlink():
            raise SandboxError("Docker cidfile cannot be a symlink")

        uid, gid = docker_container_identity(self.docker_daemon_mode)
        return [
            self.docker_binary,
            "run",
            "--rm",
            f"--cidfile={cidfile}",
            "--stop-timeout=2",
            *docker_isolation_arguments(self.config, user=f"{uid}:{gid}", tmp_size="512m"),
            f"--workdir={_CONTAINER_WORKSPACE}",
            *mounts,
            self.config.image,
            # `env -i` clears both the Docker image's ENV values and any
            # future runtime defaults. Only this explicit non-secret set
            # reaches repository code.
            "-i",
            "HOME=/tmp",
            "TMPDIR=/tmp",
            f"PATH={_SAFE_CONTAINER_PATH}",
            "CI=1",
            "NO_COLOR=1",
            "GIT_TERMINAL_PROMPT=0",
            "AUTOCONTRIBUTE_SANDBOX=1",
            # A login shell (-l) would source /etc/profile, which resets PATH.
            "/bin/sh",
            "-c",
            command,
        ]

    def _run_docker(self, workspace: Path, command: str) -> CommandResult:
        with tempfile.TemporaryDirectory(prefix="autocontribute-docker-") as temporary:
            cidfile = Path(temporary) / "container.cid"
            arguments = self.docker_command(workspace, command, cidfile)

            def cleanup() -> None:
                container_id = _read_container_id(cidfile)
                if container_id is None:
                    return
                with suppress(OSError, subprocess.TimeoutExpired):
                    subprocess.run(
                        [self.docker_binary, "rm", "--force", container_id],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        check=False,
                        timeout=10,
                        env=self._docker_environment,
                    )
                # The original timeout/result remains the useful failure;
                # Docker's --rm and daemon cleanup are the final fallback.

            return _execute(
                arguments,
                command=command,
                cwd=workspace,
                timeout_seconds=self.config.command_timeout_seconds,
                environment=self._docker_environment,
                timeout_cleanup=cleanup,
            )

    def _run_local(self, workspace: Path, command: str) -> CommandResult:
        if not self.config.allow_unsafe_local:
            raise SandboxError("Local execution requires explicit unsafe opt-in")
        shell = "/bin/sh"
        if not Path(shell).is_file():
            raise SandboxError("Local sandbox requires /bin/sh")
        environment = {
            "PATH": os.environ.get("PATH", _SAFE_CONTAINER_PATH),
            "HOME": str(workspace),
            "TMPDIR": tempfile.gettempdir(),
            "CI": "1",
            "NO_COLOR": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "AUTOCONTRIBUTE_SANDBOX": "unsafe-local",
        }
        return _execute(
            [shell, "-lc", command],
            command=command,
            cwd=workspace,
            timeout_seconds=self.config.command_timeout_seconds,
            environment=environment,
            timeout_cleanup=None,
        )


class DockerSandbox(SandboxRunner):
    """Compatibility wrapper that refuses non-Docker configuration."""

    def __init__(self, config: SandboxConfig, *, docker_binary: str = "docker") -> None:
        if config.backend != "docker":
            raise SandboxError("DockerSandbox requires backend=docker")
        super().__init__(config, docker_binary=docker_binary)


def _execute(
    arguments: list[str],
    *,
    command: str,
    cwd: Path,
    timeout_seconds: int,
    environment: dict[str, str] | None,
    timeout_cleanup: Callable[[], None] | None,
) -> CommandResult:
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            arguments,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as exc:
        executable = arguments[0]
        raise SandboxError(f"Could not start sandbox executable {executable!r}: {exc}") from exc

    assert process.stdout is not None and process.stderr is not None
    stdout = _BoundedCapture()
    stderr = _BoundedCapture()
    stdout_thread = threading.Thread(target=stdout.consume, args=(process.stdout,), daemon=True)
    stderr_thread = threading.Thread(target=stderr.consume, args=(process.stderr,), daemon=True)
    stdout_thread.start()
    stderr_thread.start()

    timed_out = False
    try:
        exit_code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        if timeout_cleanup is not None:
            timeout_cleanup()
        _kill_process_group(process)
        try:
            exit_code = process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            exit_code = process.wait()
        exit_code = 124
    finally:
        stdout_thread.join(timeout=5)
        stderr_thread.join(timeout=5)
        process.stdout.close()
        process.stderr.close()

    duration = time.monotonic() - started
    return CommandResult(
        command=command,
        exit_code=exit_code,
        duration_seconds=duration,
        stdout=stdout.text(),
        stderr=stderr.text(),
        timed_out=timed_out,
    )


class _BoundedCapture:
    def __init__(self, limit: int = _MAX_CAPTURE_BYTES) -> None:
        self.limit = limit
        self.data = bytearray()
        self.truncated = False

    def consume(self, stream: object) -> None:
        reader = getattr(stream, "read", None)
        if reader is None:
            return
        while True:
            chunk = reader(64 * 1_024)
            if not chunk:
                break
            remaining = self.limit - len(self.data)
            if remaining > 0:
                self.data.extend(chunk[:remaining])
            if len(chunk) > remaining:
                self.truncated = True

    def text(self) -> str:
        output = bytes(self.data)
        if self.truncated:
            output += _TRUNCATED_MARKER
        return output.decode("utf-8", errors="replace")


def docker_isolation_arguments(config: SandboxConfig, *, user: str, tmp_size: str) -> list[str]:
    """Return the ``docker run`` flags that every repository container shares."""

    return [
        "--pull=never",
        "--log-driver=none",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        # A private IPC namespace that still has /dev/shm; --ipc=none breaks
        # multiprocessing locks and process pools.
        "--ipc=private",
        f"--shm-size={_SHM_SIZE}",
        f"--user={user}",
        f"--memory={config.memory}",
        f"--memory-swap={config.memory}",
        f"--cpus={config.cpus}",
        f"--pids-limit={config.pids_limit}",
        "--ulimit=nofile=1024:1024",
        "--ulimit=core=0:0",
        "--init",
        "--entrypoint=/usr/bin/env",
        # Docker mounts a tmpfs noexec unless told otherwise, and Go test binaries
        # and extracted native libraries run from /tmp.
        f"--tmpfs=/tmp:rw,exec,nosuid,nodev,size={tmp_size},mode=1777",
        *(f"--env={name}=" for name in _DOCKER_CLI_PROXY_NAMES),
    ]


def _workspace_mounts(root: Path) -> list[str]:
    if "," in str(root) or "\n" in str(root):
        raise SandboxError("Workspace path cannot be represented safely as a Docker mount")
    mounts = [f"--mount=type=bind,src={root},dst={_CONTAINER_WORKSPACE}"]
    git_dir = root / ".git"
    if git_dir.is_dir() and not git_dir.is_symlink():
        # Host git reads .git/config, so a writable one would let repository code
        # choose commands that run on the host.
        mounts.append(f"--mount=type=bind,src={git_dir},dst={_CONTAINER_WORKSPACE}/.git,readonly")
    return mounts


def _workspace_path(workspace: RepositoryWorkspace | Path) -> Path:
    candidate = workspace.path if isinstance(workspace, RepositoryWorkspace) else workspace
    if not isinstance(candidate, Path):
        raise SandboxError("Sandbox workspace must be a Path or RepositoryWorkspace")
    if candidate.is_symlink():
        raise SandboxError("Sandbox workspace cannot be a symlink")
    root = candidate.expanduser().resolve()
    if not root.is_dir():
        raise SandboxError(f"Sandbox workspace is not a directory: {root}")
    return root


def _validate_command(command: str) -> None:
    if not isinstance(command, str) or not command.strip() or "\0" in command:
        raise SandboxError("Validation command must be a non-empty string without NUL bytes")
    if len(command) > 20_000:
        raise SandboxError("Validation command exceeds the 20,000-character safety limit")


def _validate_image(image: str) -> None:
    if not image or image.startswith("-") or any(character.isspace() for character in image):
        raise SandboxError("Docker image reference is invalid")
    if "\0" in image:
        raise SandboxError("Docker image reference is invalid")


def _non_root_identity() -> tuple[int, int]:
    getuid = getattr(os, "getuid", None)
    getgid = getattr(os, "getgid", None)
    uid = getuid() if getuid is not None else 65_532
    gid = getgid() if getgid is not None else 65_532
    if uid == 0 or gid == 0:
        raise SandboxError("Rootful Docker sandbox cannot be launched by host root")
    return uid, gid


def docker_container_identity(mode: DockerDaemonMode) -> tuple[int, int]:
    """Return the safe in-container identity for a verified daemon mode."""

    if mode == "rootless":
        # Root in a rootless daemon's user namespace maps to the unprivileged
        # daemon owner on the host. That mapping is required to access private
        # service-owned bind mounts. The sandbox still drops every capability,
        # sets no-new-privileges, and keeps the container root filesystem read-only.
        return 0, 0
    if mode == "rootful":
        return _non_root_identity()
    raise SandboxError("Docker daemon mode is invalid")


def detect_docker_daemon_mode(
    docker_binary: str = "docker",
    *,
    environment: dict[str, str] | None = None,
) -> DockerDaemonMode:
    """Classify a daemon that proves the required identity and resource boundaries."""

    if not docker_binary or "\0" in docker_binary:
        raise SandboxError("Docker binary is invalid")
    client_environment = docker_client_environment() if environment is None else environment
    try:
        result = subprocess.run(
            [docker_binary, "info", "--format", _DOCKER_RUNTIME_INFO_FORMAT],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
            env=client_environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SandboxError("Could not verify Docker daemon runtime information") from exc
    if result.returncode != 0:
        raise SandboxError("Could not verify Docker daemon runtime information")
    try:
        runtime_info = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError) as exc:
        raise SandboxError("Docker daemon returned malformed runtime information") from exc
    if not isinstance(runtime_info, dict) or set(runtime_info) != _DOCKER_RUNTIME_INFO_KEYS:
        raise SandboxError("Docker daemon returned malformed runtime information")
    options = runtime_info["security_options"]
    if not isinstance(options, list) or not all(isinstance(option, str) for option in options):
        raise SandboxError("Docker daemon returned malformed runtime information")
    cgroup_driver = runtime_info["cgroup_driver"]
    if (
        runtime_info["cgroup_version"] != "2"
        or not isinstance(cgroup_driver, str)
        or not cgroup_driver
        or cgroup_driver.casefold() == "none"
        or any(runtime_info[name] is not True for name in _DOCKER_RESOURCE_CAPABILITIES)
    ):
        raise SandboxError("Docker daemon does not enforce required cgroup v2 resource controls")
    rootless_count = sum(option == "name=rootless" for option in options)
    if rootless_count > 1:
        raise SandboxError("Docker daemon returned ambiguous rootless security options")
    if any(option == "name=userns" for option in options):
        raise SandboxError("Docker daemon user namespace remapping is unsupported")
    return "rootless" if rootless_count == 1 else "rootful"


def docker_client_environment() -> dict[str, str]:
    """Copy only Docker endpoint and boundary settings, never provider credentials."""

    environment = {"PATH": os.environ.get("PATH", "")}
    for name in _DOCKER_CLIENT_ENV_NAMES:
        if value := os.environ.get(name):
            environment[name] = value
    return environment


def _read_container_id(cidfile: Path) -> str | None:
    try:
        value = cidfile.read_text(encoding="ascii").strip()
    except (FileNotFoundError, OSError, UnicodeError):
        return None
    if value and all(character in "0123456789abcdefABCDEF" for character in value):
        return value
    return None


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        with suppress(OSError):
            process.kill()


__all__ = [
    "DockerDaemonMode",
    "DockerSandbox",
    "SandboxRunner",
    "detect_docker_daemon_mode",
    "docker_client_environment",
    "docker_container_identity",
    "docker_isolation_arguments",
]
