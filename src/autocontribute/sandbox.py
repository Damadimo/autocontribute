"""Resource-capped command execution for repository validation."""

from __future__ import annotations

import hashlib
import importlib.resources
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Collection, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final, Literal

from autocontribute.config import SandboxConfig
from autocontribute.domain import CommandResult
from autocontribute.egress_proxy import LISTEN_PORT, READY_MESSAGE
from autocontribute.exceptions import SandboxError
from autocontribute.host_environment import proxy_environment
from autocontribute.repository import RepositoryWorkspace

_CONTAINER_WORKSPACE: Final = "/workspace"
_SHM_SIZE: Final = "256m"
_MAX_CAPTURE_BYTES: Final = 2_000_000
_TRUNCATED_MARKER: Final = b"\n[output truncated by autocontribute]\n"
_SAFE_CONTAINER_PATH: Final = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
_SESSION_SHELL: Final = "/bin/sh"
_SESSION_TMP_SIZE: Final = "1g"
_SESSION_MAIN_UID: Final = 65_534
_SESSION_OUTPUT_DIRECTORY: Final = "/tmp/ac-out"
_SESSION_ENVIRONMENT: Final = (
    ("HOME", "/tmp/home"),
    ("TMPDIR", "/tmp"),
    ("PATH", _SAFE_CONTAINER_PATH),
    ("CI", "1"),
    ("NO_COLOR", "1"),
    ("PAGER", "cat"),
    ("GIT_PAGER", "cat"),
    ("GIT_TERMINAL_PROMPT", "0"),
    ("AUTOCONTRIBUTE_SANDBOX", "1"),
)
_RUN_LABEL: Final = "org.autocontribute.run"
_STORE_LABEL: Final = "org.autocontribute.store"
_RUN_ID: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_ENVIRONMENT_NAME: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_DOCKER_OBJECT_ID: Final = re.compile(r"^[0-9a-f]{12,64}$")
_DOCKER_CONTROL_TIMEOUT_SECONDS: Final = 30
_REAP_ATTEMPTS: Final = 3
_REAP_SETTLE_SECONDS: Final = 0.05
_ROOT_USER: Final = "0:0"
_DOCKER_NAME: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_IMAGE_ID: Final = re.compile(r"^sha256:[0-9a-f]{64}$")
_LABEL_NAME: Final = re.compile(r"^[a-z0-9][a-z0-9.-]{0,127}$")
_LABEL_VALUE: Final = re.compile(r"^[A-Za-z0-9._:/@-]{0,256}$")
_ALLOWED_HOST: Final = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_IMAGE_PULL_TIMEOUT_SECONDS: Final = 1_800
_EGRESS_PROXY_IMAGE: Final = (
    "python:3.12-alpine@sha256:b658b05ce9c4eb97ec6fc19424818a1f31993659c2b505a532f470e83807815d"
)
_EGRESS_PROXY_READY_SECONDS: Final = 30
_EGRESS_PROXY_POLL_SECONDS: Final = 0.1
# What a setup container's root bootstrap may need: CHOWN to give /opt/ac to the command
# user, and for apt, writing and chmod-ing files it does not own and dropping to `_apt`.
SETUP_CAPABILITIES: Final = frozenset({"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"})
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
                cleanup=cleanup,
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
            cleanup=None,
        )


class DockerSandbox(SandboxRunner):
    """Compatibility wrapper that refuses non-Docker configuration."""

    def __init__(self, config: SandboxConfig, *, docker_binary: str = "docker") -> None:
        if config.backend != "docker":
            raise SandboxError("DockerSandbox requires backend=docker")
        super().__init__(config, docker_binary=docker_binary)


@dataclass(frozen=True, slots=True)
class SessionCommandResult:
    """One session command's result and what the session did to stay usable afterwards."""

    result: CommandResult
    # Set when the container failed rather than the command: it stopped, could not be
    # inspected, or ran out of memory. The command's exit code then says little.
    infrastructure_failure: str | None
    # The container was restarted after the command, which empties /tmp.
    restarted: bool


class SessionContainer:
    """A long-lived, network-less container whose commands run through ``docker exec``.

    The main process runs as 65534, so commands can neither signal it nor read its
    environment. After every command the session kills whatever the command left running,
    so no process writes to the workspace while host-side tools read or edit it.

    A setup container (DESIGN §5.2) is the same with a writable root filesystem, the setup
    network instead of none, and the capabilities its root bootstrap needs. ``volumes`` get a
    fresh volume each, filled from the image, so an environment image's tool homes and caches
    under /opt/ac stay writable while the rest of the root is read-only.
    """

    def __init__(
        self,
        config: SandboxConfig,
        *,
        image: str,
        workspace: Path,
        run_id: str,
        store_root: Path,
        docker_binary: str = "docker",
        network: str = "none",
        writable_root: bool = False,
        capabilities: Collection[str] = (),
        volumes: Sequence[str] = (),
    ) -> None:
        _validate_image(image)
        if not _RUN_ID.fullmatch(run_id):
            raise SandboxError("Run identifier cannot label a sandbox container")
        if not docker_binary or "\0" in docker_binary:
            raise SandboxError("Docker binary is invalid")
        if not _DOCKER_NAME.fullmatch(network):
            raise SandboxError("Sandbox network name is invalid")
        if not set(capabilities) <= SETUP_CAPABILITIES:
            raise SandboxError("Sandbox containers may regain only the setup capabilities")
        if any("," in path for path in volumes):
            raise SandboxError("Volume paths cannot be represented safely as Docker mounts")
        self.config = config
        self.image = image
        self.workspace = _workspace_path(workspace)
        self.run_id = run_id
        self.docker_binary = docker_binary
        self.network = network
        self.writable_root = writable_root
        self.capabilities = tuple(sorted(capabilities))
        self.volumes = tuple(_container_directory(path) for path in volumes)
        self._store_label = _store_label(store_root)
        # One Docker endpoint for the whole session, as in SandboxRunner.
        self._docker_environment = docker_client_environment()
        self._command_user = ""
        self._name: str | None = None

    def __enter__(self) -> SessionContainer:
        self.start()
        return self

    def __exit__(self, *_exception: object) -> None:
        self.remove()

    @property
    def name(self) -> str:
        """Return the name of the started container."""

        if self._name is None:
            raise SandboxError("Sandbox session is not started")
        return self._name

    def start(self) -> None:
        """Create and start the container; :meth:`remove` tears it down."""

        if self._name is not None:
            raise SandboxError("Sandbox session is already started")
        mode = detect_docker_daemon_mode(self.docker_binary, environment=self._docker_environment)
        uid, gid = docker_container_identity(mode)
        if uid == _SESSION_MAIN_UID:
            raise SandboxError("Sandbox commands cannot share the main process identity 65534")
        self._command_user = f"{uid}:{gid}"
        self._create()

    def exec(
        self,
        command: str,
        *,
        timeout_seconds: int,
        workdir: str = _CONTAINER_WORKSPACE,
        environment: Mapping[str, str] | None = None,
        as_root: bool = False,
    ) -> SessionCommandResult:
        """Run one command in a fresh shell, then kill whatever it left running.

        ``as_root`` runs it as uid 0, for a setup container's bootstrap. Without CAP_KILL,
        root can signal only its own processes, so the main process still survives it.
        """

        _validate_command(command)
        if timeout_seconds < 1:
            raise SandboxError("Sandbox command timeout must be at least one second")
        user = _ROOT_USER if as_root else self.command_user
        arguments = [
            self.docker_binary,
            "exec",
            f"--user={user}",
            f"--workdir={_container_directory(workdir)}",
            self.name,
            "/usr/bin/env",
            "-i",
            *_session_environment(environment),
            _SESSION_SHELL,
            "-c",
            # On its own line, so the command parses exactly as it would alone.
            f'mkdir -p "$HOME" || exit\n{command}',
        ]
        result = _execute(
            arguments,
            command=command,
            cwd=self.workspace,
            timeout_seconds=timeout_seconds,
            environment=self._docker_environment,
            cleanup=lambda: self._signal_processes(user),
        )
        # Checked after every command: a process can be killed for memory inside a
        # command that still exits 0.
        failure = self._infrastructure_failure()
        if failure is None and self._reap(user):
            return SessionCommandResult(result, None, restarted=False)
        self.restart()
        return SessionCommandResult(result, failure, restarted=True)

    @property
    def command_user(self) -> str:
        """Return the uid:gid that commands run as."""

        if not self._command_user:
            raise SandboxError("Sandbox session is not started")
        return self._command_user

    def pipe(self, command: str, text: str, *, timeout_seconds: int) -> bool:
        """Run one short command as the command user with ``text`` on its standard input.

        Unlike :meth:`exec`, nothing is reaped afterwards, so the command must not leave
        processes behind. Returns whether it exited 0.
        """

        _validate_command(command)
        completed = _docker_control(
            self.docker_binary,
            [
                "exec",
                "--interactive",
                f"--user={self.command_user}",
                self.name,
                "/usr/bin/env",
                "-i",
                "PATH=/usr/bin:/bin",
                _SESSION_SHELL,
                "-c",
                command,
            ],
            self._docker_environment,
            input_text=text,
            timeout_seconds=timeout_seconds,
        )
        return completed is not None and completed.returncode == 0

    def read_file(self, path: str, *, max_bytes: int) -> bytes | None:
        """Return a file from the container, or ``None`` if it is missing or over ``max_bytes``."""

        arguments = [
            self.docker_binary,
            "exec",
            f"--user={self.command_user}",
            self.name,
            "/bin/cat",
            "--",
            _container_directory(path),
        ]
        try:
            process = subprocess.Popen(
                arguments,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=self._docker_environment,
            )
        except OSError:
            return None
        assert process.stdout is not None
        capture = _BoundedCapture(limit=max_bytes)
        reader = threading.Thread(target=capture.consume, args=(process.stdout,), daemon=True)
        reader.start()
        try:
            exit_code: int | None = process.wait(timeout=_DOCKER_CONTROL_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            exit_code = None
        reader.join(timeout=5)
        process.stdout.close()
        if exit_code != 0 or capture.truncated:
            return None
        return bytes(capture.data)

    def commit(self, labels: Mapping[str, str]) -> str:
        """Save the container as an image that differs from it only by ``labels``.

        Every step ran through ``docker exec``, so the image keeps the neutral ``sleep``
        command and an environment without proxy values. Returns the image ID.
        """

        changes: list[str] = []
        for name, value in labels.items():
            if not _LABEL_NAME.fullmatch(name) or not _LABEL_VALUE.fullmatch(value):
                raise SandboxError(f"Image label {name!r} is not a plain name and value")
            changes.append(f"--change=LABEL {name}={value}")
        committed = _docker_control(
            self.docker_binary,
            ["commit", *changes, self.name],
            self._docker_environment,
            timeout_seconds=self.config.command_timeout_seconds,
        )
        image_id = committed.stdout.strip() if committed is not None else ""
        if committed is None or committed.returncode != 0 or not _IMAGE_ID.fullmatch(image_id):
            detail = _first_line(committed.stderr) if committed is not None else ""
            raise SandboxError(f"Could not commit the setup container: {detail or 'no image ID'}")
        return image_id

    def save_output(self, number: int, text: str) -> str | None:
        """Write a command's full output into the container for the agent to search.

        Returns the container path ``/tmp/ac-out/<number>.log``, or ``None`` when it could
        not be written. A restart empties /tmp, and the saved logs with it.
        """

        if number < 1:
            raise SandboxError("Output log numbers start at 1")
        path = f"{_SESSION_OUTPUT_DIRECTORY}/{number}.log"
        written = self.pipe(
            f"mkdir -p {_SESSION_OUTPUT_DIRECTORY} && cat > {path}",
            text,
            timeout_seconds=_DOCKER_CONTROL_TIMEOUT_SECONDS,
        )
        return path if written else None

    def restart(self) -> None:
        """Kill every process and start the container again.

        The workspace persists and /tmp is emptied. A container that does not come back is
        replaced by a new one.
        """

        name = self.name
        self._docker("kill", name)
        started = self._docker("start", name)
        if (
            started is not None
            and started.returncode == 0
            and self._infrastructure_failure() is None
        ):
            return
        self._remove_container(name)
        self._create()

    def remove(self) -> None:
        """Remove the container and its anonymous volumes; safe to call again."""

        if self._name is not None:
            self._remove_container(self._name)
            self._name = None

    def _create(self) -> None:
        name = f"ac-{self.run_id}-{secrets.token_hex(4)}"
        arguments = self._run_arguments(name)
        self._name = name
        try:
            failure = self._start_failure(self._docker(*arguments))
        except BaseException:
            self.remove()
            raise
        if failure is not None:
            self.remove()
            raise SandboxError(f"Could not start the sandbox container: {failure}")

    def _start_failure(self, created: subprocess.CompletedProcess[str] | None) -> str | None:
        if created is None:
            return "Docker did not answer"
        if created.returncode != 0:
            return _first_line(created.stderr) or f"docker run exited with {created.returncode}"
        return self._infrastructure_failure()

    def _run_arguments(self, name: str) -> list[str]:
        git_dir = self.workspace / ".git"
        if git_dir.is_symlink() or not git_dir.is_dir():
            # The read-only .git mount is what keeps commands from planting Git
            # configuration that host git would execute.
            raise SandboxError("Sandbox session workspace needs a real .git directory")
        return [
            "run",
            "--detach",
            f"--name={name}",
            f"--label={_RUN_LABEL}={self.run_id}",
            f"--label={_STORE_LABEL}={self._store_label}",
            *docker_isolation_arguments(
                self.config,
                user=f"{_SESSION_MAIN_UID}:{_SESSION_MAIN_UID}",
                tmp_size=_SESSION_TMP_SIZE,
                network=self.network,
                read_only=not self.writable_root,
                capabilities=self.capabilities,
            ),
            f"--workdir={_CONTAINER_WORKSPACE}",
            *_workspace_mounts(self.workspace),
            *(f"--mount=type=volume,dst={path}" for path in self.volumes),
            self.image,
            "-i",
            "PATH=/usr/bin:/bin",
            "/bin/sleep",
            "infinity",
        ]

    def _signal_processes(self, user: str) -> None:
        # The shell builtin forks nothing, so it runs even when leftovers hold every
        # slot under the pids limit.
        self._docker("exec", f"--user={user}", self.name, _SESSION_SHELL, "-c", "kill -KILL -1")

    def _reap(self, user: str) -> bool:
        uid = user.partition(":")[0]
        for _ in range(_REAP_ATTEMPTS):
            self._signal_processes(user)
            listed = self._docker("top", self.name, "-o", "pid,uid")
            if listed is None or listed.returncode != 0:
                return False
            uids = {line.split()[-1] for line in listed.stdout.splitlines()[1:] if line.strip()}
            if uid not in uids:
                return True
            # Killed processes stay listed until docker-init reaps them.
            time.sleep(_REAP_SETTLE_SECONDS)
        return False

    def _infrastructure_failure(self) -> str | None:
        inspected = self._docker(
            "inspect", "--format", "{{.State.Running}} {{.State.OOMKilled}}", self.name
        )
        if inspected is None or inspected.returncode != 0:
            return "the sandbox container could not be inspected"
        running, _, out_of_memory = inspected.stdout.strip().partition(" ")
        if out_of_memory == "true":
            # Docker keeps this flag until the next start, so the restart that follows
            # keeps it from blaming later commands.
            return f"the sandbox ran out of memory (limit {self.config.memory})"
        if running != "true":
            return "the sandbox container stopped"
        return None

    def _remove_container(self, name: str) -> None:
        # Best effort: remove_leftover_containers finds a survivor by its labels.
        self._docker("rm", "--force", "--volumes", name)

    def _docker(self, *arguments: str) -> subprocess.CompletedProcess[str] | None:
        return _docker_control(self.docker_binary, arguments, self._docker_environment)


def remove_leftover_containers(
    store_root: Path,
    unfinished_run_ids: Collection[str],
    *,
    docker_binary: str = "docker",
) -> None:
    """Remove this store's containers and networks whose run is finished or unknown.

    Teardown removes them normally; this catches what a killed process left behind.
    """

    if not docker_binary or "\0" in docker_binary:
        raise SandboxError("Docker binary is invalid")
    environment = docker_client_environment()
    store_filter = f"label={_STORE_LABEL}={_store_label(store_root)}"
    row_format = '{{.ID}} {{.Label "' + _RUN_LABEL + '"}}'
    # Containers first: Docker refuses to remove a network that a container still uses.
    for listing, removal in (
        (("ps", "--all", "--no-trunc"), ("rm", "--force", "--volumes")),
        (("network", "ls", "--no-trunc"), ("network", "rm")),
    ):
        listed = _docker_control(
            docker_binary,
            [*listing, "--filter", store_filter, "--format", row_format],
            environment,
        )
        if listed is None or listed.returncode != 0:
            raise SandboxError("Could not list leftover sandbox containers and networks")
        for line in listed.stdout.splitlines():
            object_id, _, run_id = line.strip().partition(" ")
            if _DOCKER_OBJECT_ID.fullmatch(object_id) and run_id not in unfinished_run_ids:
                # Best effort, like workspace cleanup: the next sweep retries.
                _docker_control(docker_binary, [*removal, object_id], environment)


class EgressNetwork:
    """An internal Docker network whose only way out is the allowlisting egress proxy.

    Setup containers join the network and reach the proxy by name (DESIGN §5.2). The proxy
    container alone is also on the default bridge, and it alone receives the operator's
    upstream proxy; it runs the standard-library proxy from ``egress_proxy.py`` in a pinned
    python:3.12-alpine image.
    """

    def __init__(
        self,
        *,
        allowed_hosts: Collection[str],
        run_id: str,
        store_root: Path,
        docker_binary: str = "docker",
    ) -> None:
        if not _RUN_ID.fullmatch(run_id):
            raise SandboxError("Run identifier cannot label a sandbox network")
        if not docker_binary or "\0" in docker_binary:
            raise SandboxError("Docker binary is invalid")
        invalid = sorted(host for host in allowed_hosts if not _ALLOWED_HOST.fullmatch(host))
        if invalid:
            raise SandboxError(f"Egress allowlist entries must be host names: {invalid}")
        self.allowed_hosts = tuple(sorted(set(allowed_hosts)))
        self.docker_binary = docker_binary
        self._labels = (
            f"--label={_RUN_LABEL}={run_id}",
            f"--label={_STORE_LABEL}={_store_label(store_root)}",
        )
        suffix = secrets.token_hex(4)
        self.network = f"ac-{run_id}-net-{suffix}"
        self.proxy = f"ac-{run_id}-proxy-{suffix}"
        self._docker_environment = docker_client_environment()
        self._started = False

    def __enter__(self) -> EgressNetwork:
        self.start()
        return self

    def __exit__(self, *_exception: object) -> None:
        self.remove()

    @property
    def proxy_url(self) -> str:
        return f"http://{self.proxy}:{LISTEN_PORT}"

    def start(self) -> None:
        """Create the network and start the proxy on it; :meth:`remove` tears both down."""

        if self._started:
            raise SandboxError("Egress network is already started")
        pull_image(_EGRESS_PROXY_IMAGE, docker_binary=self.docker_binary)
        self._started = True
        try:
            self._require(
                ("network", "create", "--internal", *self._labels, self.network),
                "create the setup network",
            )
            self._start_proxy()
            self._require(
                ("network", "connect", self.network, self.proxy),
                "attach the egress proxy to the setup network",
            )
            self._wait_until_ready()
        except BaseException:
            self.remove()
            raise

    def refused_requests(self) -> list[str]:
        """Return the proxy's log lines for requests it refused."""

        logs = self._docker("logs", self.proxy)
        if logs is None:
            return []
        return [line for line in logs.stdout.splitlines() if line.startswith("deny ")]

    def remove(self) -> None:
        """Remove the proxy and the network; safe to call again."""

        if not self._started:
            return
        # Best effort: remove_leftover_containers finds survivors by their labels.
        self._docker("rm", "--force", "--volumes", self.proxy)
        self._docker("network", "rm", self.network)
        self._started = False

    def _start_proxy(self) -> None:
        source = importlib.resources.files("autocontribute").joinpath("egress_proxy.py")
        upstream = {
            name: value
            for name, value in proxy_environment().items()
            if name in _DOCKER_CLI_PROXY_NAMES and value
        }
        arguments = [
            "run",
            "--detach",
            f"--name={self.proxy}",
            *self._labels,
            "--pull=never",
            # Readiness and refused requests are read from the proxy's own log.
            "--log-driver=json-file",
            "--log-opt=max-size=10m",
            "--network=bridge",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--user=65534:65534",
            "--memory=256m",
            "--memory-swap=256m",
            "--cpus=1",
            "--pids-limit=64",
            "--ulimit=nofile=4096:4096",
            "--init",
            # A bare name takes the operator's value from the client's environment, so the
            # credentials never appear on a command line. Blank values keep the Docker CLI
            # from injecting the proxies of its own configuration.
            *(
                f"--env={name}" if name in upstream else f"--env={name}="
                for name in _DOCKER_CLI_PROXY_NAMES
            ),
            _EGRESS_PROXY_IMAGE,
            "python3",
            "-u",
            "-c",
            source.read_text(encoding="utf-8"),
            *(f"--allow={host}" for host in self.allowed_hosts),
        ]
        started = _docker_control(
            self.docker_binary, arguments, {**self._docker_environment, **upstream}
        )
        self._check(started, "start the egress proxy")

    def _wait_until_ready(self) -> None:
        deadline = time.monotonic() + _EGRESS_PROXY_READY_SECONDS
        while True:
            logs = self._docker("logs", self.proxy)
            if logs is not None and READY_MESSAGE in logs.stdout:
                return
            running = self._docker("inspect", "--format", "{{.State.Running}}", self.proxy)
            if running is None or running.stdout.strip() != "true" or time.monotonic() > deadline:
                errors = logs.stderr.strip().splitlines() if logs is not None else []
                detail = f": {errors[-1][:300]}" if errors else ""
                raise SandboxError(f"The egress proxy did not start{detail}")
            time.sleep(_EGRESS_PROXY_POLL_SECONDS)

    def _require(self, arguments: Sequence[str], action: str) -> None:
        self._check(self._docker(*arguments), action)

    @staticmethod
    def _check(completed: subprocess.CompletedProcess[str] | None, action: str) -> None:
        if completed is None or completed.returncode != 0:
            detail = _first_line(completed.stderr) if completed is not None else ""
            raise SandboxError(f"Could not {action}: {detail or 'Docker did not answer'}")

    def _docker(self, *arguments: str) -> subprocess.CompletedProcess[str] | None:
        return _docker_control(self.docker_binary, arguments, self._docker_environment)


@dataclass(frozen=True, slots=True)
class ImageIdentity:
    """A local image: what ``--pull=never`` runs, and what identifies it across machines."""

    image_id: str
    # The registry digest of the reference when the image came from a registry; otherwise
    # the image ID, which identifies a locally built or committed image.
    digest: str
    labels: Mapping[str, str]
    # os/architecture[/variant], such as linux/arm64; environment caches are kept per platform.
    platform: str


def inspect_image(reference: str, *, docker_binary: str = "docker") -> ImageIdentity | None:
    """Return a local image's identity, or ``None`` when it is not present."""

    _validate_image(reference)
    inspected = _docker_control(
        docker_binary,
        ["image", "inspect", "--format", "{{json .}}", reference],
        docker_client_environment(),
    )
    if inspected is None or inspected.returncode != 0:
        return None
    try:
        details = json.loads(inspected.stdout)
    except json.JSONDecodeError as exc:
        raise SandboxError("Docker returned malformed image details") from exc
    image_id = details.get("Id") if isinstance(details, dict) else None
    if not isinstance(image_id, str) or not _IMAGE_ID.fullmatch(image_id):
        raise SandboxError("Docker returned malformed image details")
    labels = (details.get("Config") or {}).get("Labels") or {}
    repository_digests = details.get("RepoDigests") or []
    platform = "/".join(
        str(part).lower()
        for part in (details.get("Os"), details.get("Architecture"), details.get("Variant"))
        if part
    )
    return ImageIdentity(
        image_id,
        _registry_digest(reference, repository_digests) or image_id,
        {str(name): str(value) for name, value in labels.items()},
        platform,
    )


def pull_image(reference: str, *, docker_binary: str = "docker") -> ImageIdentity:
    """Make an image present locally and return its identity.

    A reference pinned by digest is pulled only when missing. A tag is pulled every time, so
    a moved tag is noticed; when the registry cannot be reached, a local copy is used.
    """

    present = inspect_image(reference, docker_binary=docker_binary)
    if present is not None and "@sha256:" in reference:
        return present
    pulled = _docker_control(
        docker_binary,
        ["pull", "--quiet", reference],
        docker_client_environment(),
        timeout_seconds=_IMAGE_PULL_TIMEOUT_SECONDS,
    )
    if pulled is not None and pulled.returncode == 0:
        present = inspect_image(reference, docker_binary=docker_binary)
    if present is None:
        detail = _first_line(pulled.stderr) if pulled is not None else ""
        raise SandboxError(f"Could not pull image {reference}: {detail or 'Docker did not answer'}")
    return present


def tag_image(image_id: str, tag: str, *, docker_binary: str = "docker") -> None:
    """Tag an image so pruning keeps it, and drop the repository's other tags.

    Removing an old tag deletes its image unless a container still uses it, so each
    repository keeps one environment image.
    """

    if not _IMAGE_ID.fullmatch(image_id):
        raise SandboxError("Image ID must be sha256:<64 hex digits>")
    _validate_image(tag)
    environment = docker_client_environment()
    tagged = _docker_control(docker_binary, ["tag", image_id, tag], environment)
    if tagged is None or tagged.returncode != 0:
        detail = _first_line(tagged.stderr) if tagged is not None else ""
        raise SandboxError(f"Could not tag image {image_id}: {detail or 'Docker did not answer'}")
    repository = tag.rpartition(":")[0]
    listed = _docker_control(
        docker_binary,
        ["image", "ls", "--format", "{{.Repository}}:{{.Tag}}", repository],
        environment,
    )
    for line in [] if listed is None or listed.returncode != 0 else listed.stdout.splitlines():
        if line.strip() and line.strip() != tag:
            # Best effort, like container cleanup: an image in use stays until next time.
            _docker_control(docker_binary, ["image", "rm", line.strip()], environment)


def _registry_digest(reference: str, repository_digests: object) -> str | None:
    name, _, pinned = reference.partition("@")
    if pinned:
        return pinned if _IMAGE_ID.fullmatch(pinned) else None
    last_component = name.rpartition("/")[2]
    repository = name.rpartition(":")[0] if ":" in last_component else name
    if not isinstance(repository_digests, list):
        return None
    for entry in repository_digests:
        entry_repository, _, digest = str(entry).partition("@")
        if entry_repository == repository and _IMAGE_ID.fullmatch(digest):
            return digest
    return None


def _execute(
    arguments: list[str],
    *,
    command: str,
    cwd: Path,
    timeout_seconds: int,
    environment: dict[str, str] | None,
    cleanup: Callable[[], None] | None,
) -> CommandResult:
    """Run one bounded command; ``cleanup`` stops its sandbox when it is abandoned."""

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
        _abandon(process, cleanup)
        exit_code = 124
    except BaseException:
        # Ctrl-C or a termination signal must not leave the command running.
        _abandon(process, cleanup)
        raise
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


def docker_isolation_arguments(
    config: SandboxConfig,
    *,
    user: str,
    tmp_size: str,
    network: str = "none",
    read_only: bool = True,
    capabilities: Collection[str] = (),
) -> list[str]:
    """Return the ``docker run`` flags that every repository container shares."""

    return [
        "--pull=never",
        "--log-driver=none",
        f"--network={network}",
        *(["--read-only"] if read_only else []),
        "--cap-drop=ALL",
        *(f"--cap-add={capability}" for capability in sorted(capabilities)),
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


def _docker_control(
    docker_binary: str,
    arguments: Sequence[str],
    environment: dict[str, str],
    *,
    input_text: str | None = None,
    timeout_seconds: int = _DOCKER_CONTROL_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[str] | None:
    """Run one Docker management command; ``None`` means it did not finish."""

    try:
        return subprocess.run(
            [docker_binary, *arguments],
            input=input_text,
            stdin=None if input_text is not None else subprocess.DEVNULL,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=timeout_seconds,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def _store_label(store_root: Path) -> str:
    return hashlib.sha256(os.fsencode(store_root.expanduser().resolve())).hexdigest()[:16]


def _session_environment(environment: Mapping[str, str] | None) -> list[str]:
    values = dict(_SESSION_ENVIRONMENT)
    for name, value in (environment or {}).items():
        if not _ENVIRONMENT_NAME.fullmatch(name) or "\0" in value:
            raise SandboxError("Sandbox environment names must be identifiers without NUL values")
        values[name] = value
    return [f"{name}={value}" for name, value in values.items()]


def _container_directory(path: str) -> str:
    candidate = PurePosixPath(path)
    if not candidate.is_absolute() or ".." in candidate.parts or any(c in path for c in "\0\n\r"):
        raise SandboxError("Sandbox working directory must be an absolute container path")
    return str(candidate)


def _first_line(text: str) -> str:
    return next((line.strip()[:300] for line in text.splitlines() if line.strip()), "")


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


def _abandon(process: subprocess.Popen[bytes], cleanup: Callable[[], None] | None) -> None:
    # Killing the Docker client alone leaves the command running in the container.
    try:
        if cleanup is not None:
            cleanup()
    finally:
        _kill_process_group(process)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        with suppress(OSError):
            process.kill()


__all__ = [
    "SETUP_CAPABILITIES",
    "DockerDaemonMode",
    "DockerSandbox",
    "EgressNetwork",
    "ImageIdentity",
    "SandboxRunner",
    "SessionCommandResult",
    "SessionContainer",
    "detect_docker_daemon_mode",
    "docker_client_environment",
    "docker_container_identity",
    "docker_isolation_arguments",
    "inspect_image",
    "pull_image",
    "remove_leftover_containers",
    "tag_image",
]
