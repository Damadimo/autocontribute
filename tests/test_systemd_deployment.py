from __future__ import annotations

import os
import re
import socket
import stat
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[1]
SYSTEMD = ROOT / "deploy" / "systemd"
LOCK_PATH = "/var/lib/autocontribute/operation.lock"
ROOTLESS_CHECK = SYSTEMD / "libexec" / "autocontribute-rootless-docker-check"
ROOTLESS_SUPERVISOR = SYSTEMD / "libexec" / "autocontribute-rootless-docker"
STORAGE_CAPACITY_CHECK = SYSTEMD / "libexec" / "autocontribute-storage-capacity-check"
DOCKER_DATA_CHECK = SYSTEMD / "libexec" / "autocontribute-docker-data-check"
WORKSPACE_QUOTA_CHECK = SYSTEMD / "libexec" / "autocontribute-workspace-quota-check"


def _directives(path: Path) -> dict[tuple[str, str], list[str]]:
    result: dict[tuple[str, str], list[str]] = defaultdict(list)
    section = ""
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        key, separator, value = line.partition("=")
        assert section and separator, f"invalid unit line in {path}: {raw_line}"
        result[(section, key)].append(value)
    return dict(result)


def _one(directives: dict[tuple[str, str], list[str]], section: str, key: str) -> str:
    values = directives[(section, key)]
    assert len(values) == 1
    return values[0]


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def _run_rootless_check(
    case_directory: Path,
    *,
    runtime_owner: int | None = None,
    runtime_group: int | None = None,
    runtime_mode: str = "700",
    socket_owner: int | None = None,
    socket_group: int | None = None,
    socket_mode: str = "660",
    group_names: str = "autocontribute",
    docker_output: str = "name=seccomp\nname=rootless\nname=cgroupns\n",
    docker_exit: int = 0,
    accessible_rootful_socket: bool = False,
    legacy_socket_kind: str = "absent",
    unit_only: bool = False,
    unit_load_state: str = "loaded",
    unit_need_daemon_reload: str = "no",
    unit_fragment_path: str | None = None,
    unit_dropin_paths: str = "",
    unit_active_state: str = "active",
    unit_sub_state: str = "running",
    unit_failure_property: str = "",
    fragment_owner: int = 0,
    fragment_group: int = 0,
    fragment_mode: str = "644",
) -> tuple[subprocess.CompletedProcess[str], str | None]:
    case_directory.mkdir()
    short_alias = Path(tempfile.mkdtemp(prefix="ac-systemd-", dir="/tmp"))
    short_alias.rmdir()
    short_alias.symlink_to(case_directory, target_is_directory=True)
    runtime = short_alias / "runtime"
    runtime.mkdir(mode=0o700)
    docker_socket = runtime / "docker.sock"
    rootful_socket = short_alias / "rootful-docker.sock"
    fake_bin = case_directory / "bin"
    fake_bin.mkdir()
    probe_environment = case_directory / "probe-environment"
    fragment_path = case_directory / "policy" / "docker.service"
    fragment_path.parent.mkdir()
    fragment_path.write_text("[Service]\nExecStart=/usr/bin/false\n", encoding="utf-8")
    fragment_path.chmod(0o644)
    rootless_check = case_directory / "autocontribute-rootless-docker-check"
    helper_text = ROOTLESS_CHECK.read_text(encoding="utf-8")
    production_fragment = '/etc/systemd/system/autocontribute-rootless-docker.service"'
    assert production_fragment in helper_text
    helper_text = helper_text.replace(
        production_fragment,
        f'{fragment_path}"',
        1,
    )
    legacy_socket = short_alias / "legacy-docker.sock"
    production_legacy_socket = 'readonly legacy_rootless_socket="/run/user/$UID/docker.sock"'
    assert production_legacy_socket in helper_text
    helper_text = helper_text.replace(
        production_legacy_socket,
        f'readonly legacy_rootless_socket="{legacy_socket}"',
        1,
    )
    _write_executable(rootless_check, helper_text)

    uid = os.getuid()
    gid = os.getgid()
    values = {
        "TEST_RUNTIME_OWNER": str(uid if runtime_owner is None else runtime_owner),
        "TEST_RUNTIME_GROUP": str(gid if runtime_group is None else runtime_group),
        "TEST_RUNTIME_MODE": runtime_mode,
        "TEST_SOCKET_OWNER": str(uid if socket_owner is None else socket_owner),
        "TEST_SOCKET_GROUP": str(gid if socket_group is None else socket_group),
        "TEST_SOCKET_MODE": socket_mode,
        "TEST_FRAGMENT_OWNER": str(fragment_owner),
        "TEST_FRAGMENT_GROUP": str(fragment_group),
        "TEST_FRAGMENT_MODE": fragment_mode,
    }
    _write_executable(
        fake_bin / "stat",
        """#!/bin/sh
set -eu
format=$1
path=$3
if [ "$path" = "$TEST_RUNTIME_DIRECTORY" ]; then
  case "$format" in
    --format=%u) printf '%s\\n' "$TEST_RUNTIME_OWNER" ;;
    --format=%g) printf '%s\\n' "$TEST_RUNTIME_GROUP" ;;
    --format=%a) printf '%s\\n' "$TEST_RUNTIME_MODE" ;;
    *) exit 90 ;;
  esac
elif [ "$path" = "$TEST_DOCKER_SOCKET" ]; then
  case "$format" in
    --format=%u) printf '%s\\n' "$TEST_SOCKET_OWNER" ;;
    --format=%g) printf '%s\\n' "$TEST_SOCKET_GROUP" ;;
    --format=%a) printf '%s\\n' "$TEST_SOCKET_MODE" ;;
    *) exit 91 ;;
  esac
elif [ "$path" = "$TEST_FRAGMENT_PATH" ]; then
  case "$format" in
    --format=%u) printf '%s\\n' "$TEST_FRAGMENT_OWNER" ;;
    --format=%g) printf '%s\\n' "$TEST_FRAGMENT_GROUP" ;;
    --format=%a) printf '%s\\n' "$TEST_FRAGMENT_MODE" ;;
    *) exit 92 ;;
  esac
else
  exit 93
fi
""",
    )
    _write_executable(
        fake_bin / "id",
        """#!/bin/sh
set -eu
case "$*" in
  --group) printf '%s\\n' "$TEST_SERVICE_GID" ;;
  '--groups --name') printf '%s\\n' "$TEST_GROUP_NAMES" ;;
  *) exit 94 ;;
esac
""",
    )
    _write_executable(
        fake_bin / "timeout",
        """#!/bin/sh
set -eu
[ "$1" = '--kill-after=5s' ]
shift
[ "$1" = '30s' ]
shift
exec "$@"
""",
    )
    _write_executable(
        fake_bin / "systemctl",
        """#!/bin/sh
set -eu
[ "$1" = 'show' ]
[ "$2" = 'autocontribute-rootless-docker.service' ]
[ "$4" = '--value' ]
property=${3#--property=}
if [ "$property" = "$TEST_SYSTEMCTL_FAILURE_PROPERTY" ]; then
  exit 95
fi
case "$property" in
  LoadState) printf '%s' "$TEST_UNIT_LOAD_STATE" ;;
  NeedDaemonReload) printf '%s' "$TEST_UNIT_NEED_DAEMON_RELOAD" ;;
  FragmentPath) printf '%s' "$TEST_UNIT_FRAGMENT_PATH" ;;
  DropInPaths) printf '%s' "$TEST_UNIT_DROPIN_PATHS" ;;
  ActiveState) printf '%s' "$TEST_UNIT_ACTIVE_STATE" ;;
  SubState) printf '%s' "$TEST_UNIT_SUB_STATE" ;;
  *) exit 96 ;;
esac
""",
    )
    _write_executable(
        fake_bin / "docker",
        """#!/bin/sh
set -eu
[ "$1" = '--host' ]
[ "$2" = "$DOCKER_HOST" ]
[ "$3" = 'info' ]
[ "$4" = '--format' ]
[ "$5" = '{{range .SecurityOptions}}{{println .}}{{end}}' ]
printf '%s\\n%s\\n%s\\n' \
  "$DOCKER_HOST" "$XDG_RUNTIME_DIR" "${DOCKER_CONTEXT-unset}" \
  > "$TEST_PROBE_ENVIRONMENT"
printf '%s' "$TEST_DOCKER_OUTPUT"
exit "$TEST_DOCKER_EXIT"
""",
    )

    environment = {
        **os.environ,
        **values,
        "PATH": f"{fake_bin}:/usr/bin:/bin",
        "DOCKER_CONTEXT": "must-be-cleared",
        "TEST_DOCKER_EXIT": str(docker_exit),
        "TEST_DOCKER_OUTPUT": docker_output,
        "TEST_DOCKER_SOCKET": os.fspath(docker_socket),
        "TEST_FRAGMENT_PATH": os.fspath(fragment_path),
        "TEST_GROUP_NAMES": group_names,
        "TEST_PROBE_ENVIRONMENT": os.fspath(probe_environment),
        "TEST_RUNTIME_DIRECTORY": os.fspath(runtime),
        "TEST_SERVICE_GID": str(gid),
        "TEST_SYSTEMCTL_FAILURE_PROPERTY": unit_failure_property,
        "TEST_UNIT_ACTIVE_STATE": unit_active_state,
        "TEST_UNIT_DROPIN_PATHS": unit_dropin_paths,
        "TEST_UNIT_FRAGMENT_PATH": (
            os.fspath(fragment_path) if unit_fragment_path is None else unit_fragment_path
        ),
        "TEST_UNIT_LOAD_STATE": unit_load_state,
        "TEST_UNIT_NEED_DAEMON_RELOAD": unit_need_daemon_reload,
        "TEST_UNIT_SUB_STATE": unit_sub_state,
    }
    rootful_listener: socket.socket | None = None
    if accessible_rootful_socket:
        rootful_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        rootful_listener.bind(os.fspath(rootful_socket))
    legacy_listener: socket.socket | None = None
    if legacy_socket_kind == "socket":
        legacy_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        legacy_listener.bind(os.fspath(legacy_socket))
    elif legacy_socket_kind == "symlink":
        legacy_socket.symlink_to(docker_socket)
    elif legacy_socket_kind != "absent":
        raise AssertionError(f"unknown legacy socket kind: {legacy_socket_kind}")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(os.fspath(docker_socket))
        try:
            docker_socket.chmod(0o660)
            arguments = (
                ["--unit-only"]
                if unit_only
                else [
                    os.fspath(runtime),
                    os.fspath(docker_socket),
                    os.fspath(rootful_socket),
                ]
            )
            result = subprocess.run(
                ["bash", os.fspath(rootless_check), *arguments],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )
        finally:
            if rootful_listener is not None:
                rootful_listener.close()
            if legacy_listener is not None:
                legacy_listener.close()
    observed_environment = (
        probe_environment.read_text(encoding="utf-8") if probe_environment.exists() else None
    )
    short_alias.unlink()
    return result, observed_environment


def _run_rootless_supervisor_reload(
    case_directory: Path,
    *,
    home_owner: int = 0,
    home_group: int | None = None,
    home_mode: str = "750",
    runtime_owner: int | None = None,
    runtime_group: int | None = None,
    runtime_mode: str = "700",
    bus_owner: int | None = None,
    bus_group: int | None = None,
    manager_ready: bool = True,
    manager_readiness_timeout_seconds: int = 120,
    manager_active_state: str = "active",
    manager_sub_state: str = "running",
    manager_load_state: str = "loaded",
    manager_need_daemon_reload: str = "no",
    manager_dropin_path: str | None = None,
    manager_dropin_count: int = 1,
    manager_extra_dropin: str | None = None,
    manager_delegate: str = "yes",
    manager_transient: str = "no",
    manager_control_group: str | None = None,
    manager_environment: str | None = None,
    manager_unit_path: str | None = None,
    manager_fragment_path: str | None = None,
    manager_fragment_canonical: str | None = None,
    manager_fragment_owner: int = 0,
    manager_fragment_group: int = 0,
    manager_fragment_mode: str = "644",
    manager_dropin_owner: int = 0,
    manager_dropin_group: int = 0,
    manager_dropin_mode: str = "644",
    vendor_dropin_owner: int = 0,
    vendor_dropin_group: int = 0,
    vendor_dropin_mode: str = "644",
    manager_main_pid: str = "4242",
    manager_failure_property: str = "",
    bus_response: str | None = None,
    bus_exit: int = 0,
    process_uid: int | None = None,
    process_gid: int | None = None,
    process_cgroup: str | None = None,
    process_unit_path: str | None = None,
    executable_owner: int = 0,
    executable_group: int = 0,
    executable_mode: str = "755",
    controller_values: str = "cpu cpuset io memory pids\n",
    user_load_state: str = "loaded",
    user_need_daemon_reload: str = "no",
    user_fragment_path: str | None = None,
    user_dropin_paths: str = "",
    user_active_state: str = "active",
    user_sub_state: str = "running",
    user_transient: str = "no",
    user_failure_property: str = "",
    fragment_owner: int = 0,
    fragment_group: int = 0,
    fragment_mode: str = "644",
    legacy_socket_kind: str = "absent",
) -> tuple[subprocess.CompletedProcess[str], str]:
    case_directory.mkdir()
    short_alias = Path(tempfile.mkdtemp(prefix="ac-supervisor-", dir="/tmp"))
    short_alias.rmdir()
    short_alias.symlink_to(case_directory, target_is_directory=True)
    fake_bin = case_directory / "bin"
    fake_bin.mkdir()
    service_home = short_alias / "home"
    service_home.mkdir(mode=0o750)
    user_runtime = short_alias / "user-runtime"
    user_runtime.mkdir(mode=0o700)
    user_bus = user_runtime / "bus"
    policy = case_directory / "policy"
    policy.mkdir()
    user_fragment = policy / "autocontribute-rootless-docker-daemon.service"
    user_fragment.write_text("[Service]\nExecStart=/usr/bin/false\n", encoding="utf-8")
    user_fragment.chmod(0o644)
    manager_dropin = policy / "50-autocontribute.conf"
    manager_dropin.write_text("[Service]\nDelegate=yes\n", encoding="utf-8")
    manager_dropin.chmod(0o644)
    manager_fragment = policy / "user@.service"
    manager_fragment.write_text(
        "[Service]\nExecStart=/usr/lib/systemd/systemd --user\n", encoding="utf-8"
    )
    manager_fragment.chmod(0o644)
    vendor_dropin_directory = policy / "user@.service.d"
    vendor_dropin_directory.mkdir()
    vendor_dropin_one = vendor_dropin_directory / "10-login-barrier.conf"
    vendor_dropin_one.write_text("[Unit]\nAfter=systemd-user-sessions.service\n", encoding="utf-8")
    vendor_dropin_one.chmod(0o644)
    vendor_dropin_two = vendor_dropin_directory / "timeout.conf"
    vendor_dropin_two.write_text("[Service]\nTimeoutStopSec=120s\n", encoding="utf-8")
    vendor_dropin_two.chmod(0o644)
    manager_executable = fake_bin / "systemd"
    _write_executable(manager_executable, "#!/bin/sh\nexit 0\n")
    process_metadata = case_directory / "manager-process"
    process_metadata.mkdir()
    controllers = case_directory / "cgroup.controllers"
    controllers.write_text(controller_values, encoding="utf-8")
    calls = case_directory / "systemctl-calls"

    uid = os.getuid()
    gid = os.getgid()
    control_group = (
        f"/user.slice/user-{uid}.slice/user@{uid}.service"
        if manager_control_group is None
        else manager_control_group
    )
    unit_path = (
        "/etc/systemd/user:/run/systemd/user:/usr/local/lib/systemd/user:/usr/lib/systemd/user"
    )
    unit_path_property = (
        "/etc/systemd/user /run/systemd/user /usr/local/lib/systemd/user /usr/lib/systemd/user"
    )
    effective_process_uid = uid if process_uid is None else process_uid
    effective_process_gid = gid if process_gid is None else process_gid
    expected_process_cgroup = f"0::{control_group}/init.scope"
    (process_metadata / "status").write_text(
        f"Uid:\t{effective_process_uid}\t{effective_process_uid}\t"
        f"{effective_process_uid}\t{effective_process_uid}\n"
        f"Gid:\t{effective_process_gid}\t{effective_process_gid}\t"
        f"{effective_process_gid}\t{effective_process_gid}\n",
        encoding="utf-8",
    )
    (process_metadata / "cgroup").write_text(
        f"{expected_process_cgroup if process_cgroup is None else process_cgroup}\n",
        encoding="utf-8",
    )
    effective_process_unit_path = unit_path if process_unit_path is None else process_unit_path
    (process_metadata / "environ").write_bytes(
        f"SYSTEMD_UNIT_PATH={effective_process_unit_path}\0PATH=/usr/bin\0".encode()
    )
    supervisor = case_directory / "autocontribute-rootless-docker"
    helper_text = ROOTLESS_SUPERVISOR.read_text(encoding="utf-8")
    replacements = (
        (
            "readonly expected_fragment=/etc/systemd/user/"
            "autocontribute-rootless-docker-daemon.service",
            f"readonly expected_fragment={user_fragment}",
        ),
        (
            'readonly expected_manager_dropin="/etc/systemd/system/'
            'user@${service_uid}.service.d/50-autocontribute.conf"',
            f'readonly expected_manager_dropin="{manager_dropin}"',
        ),
        (
            "readonly expected_manager_fragment=/usr/lib/systemd/system/user@.service",
            f"readonly expected_manager_fragment={manager_fragment}",
        ),
        (
            "readonly expected_vendor_dropin_directory=/usr/lib/systemd/system/user@.service.d",
            f"readonly expected_vendor_dropin_directory={vendor_dropin_directory}",
        ),
        (
            'readonly user_runtime_directory="/run/user/$service_uid"',
            f'readonly user_runtime_directory="{user_runtime}"',
        ),
        (
            "readonly service_home=/var/lib/autocontribute",
            f"readonly service_home={service_home}",
        ),
        (
            "readonly manager_readiness_timeout_seconds=120",
            f"readonly manager_readiness_timeout_seconds={manager_readiness_timeout_seconds}",
        ),
        (
            'controller_file="/sys/fs/cgroup${expected_user_manager_cgroup}/cgroup.controllers"',
            f'controller_file="{controllers}"',
        ),
    )
    for production, replacement in replacements:
        assert production in helper_text
        helper_text = helper_text.replace(production, replacement, 1)
    production_process_path = "/proc/$main_pid_before"
    assert production_process_path in helper_text
    helper_text = helper_text.replace(production_process_path, os.fspath(process_metadata))
    assert production_process_path not in helper_text
    _write_executable(supervisor, helper_text)

    _write_executable(
        fake_bin / "id",
        """#!/bin/sh
set -eu
case "$*" in
  '--user --name') printf '%s\n' autocontribute ;;
  --user) printf '%s\n' "$TEST_UID" ;;
  --group) printf '%s\n' "$TEST_GID" ;;
  *) exit 90 ;;
esac
""",
    )
    _write_executable(
        fake_bin / "stat",
        """#!/bin/sh
set -eu
format=$1
path=$3
case "$path" in
  "$TEST_SERVICE_HOME")
    case "$format" in
      --format=%u) printf '%s\n' "$TEST_HOME_OWNER" ;;
      --format=%g) printf '%s\n' "$TEST_HOME_GROUP" ;;
      --format=%a) printf '%s\n' "$TEST_HOME_MODE" ;;
      *) exit 91 ;;
    esac
    ;;
  "$TEST_USER_RUNTIME")
    case "$format" in
      --format=%u) printf '%s\n' "$TEST_RUNTIME_OWNER" ;;
      --format=%g) printf '%s\n' "$TEST_RUNTIME_GROUP" ;;
      --format=%a) printf '%s\n' "$TEST_RUNTIME_MODE" ;;
      *) exit 92 ;;
    esac
    ;;
  "$TEST_USER_BUS")
    case "$format" in
      --format=%u) printf '%s\n' "$TEST_BUS_OWNER" ;;
      --format=%g) printf '%s\n' "$TEST_BUS_GROUP" ;;
      *) exit 93 ;;
    esac
    ;;
  "$TEST_USER_FRAGMENT")
    case "$format" in
      --format=%u) printf '%s\n' "$TEST_FRAGMENT_OWNER" ;;
      --format=%g) printf '%s\n' "$TEST_FRAGMENT_GROUP" ;;
      --format=%a) printf '%s\n' "$TEST_FRAGMENT_MODE" ;;
      *) exit 94 ;;
    esac
    ;;
  "$TEST_MANAGER_FRAGMENT")
    case "$format" in
      --format=%u) printf '%s\n' "$TEST_MANAGER_FRAGMENT_OWNER" ;;
      --format=%g) printf '%s\n' "$TEST_MANAGER_FRAGMENT_GROUP" ;;
      --format=%a) printf '%s\n' "$TEST_MANAGER_FRAGMENT_MODE" ;;
      *) exit 95 ;;
    esac
    ;;
  "$TEST_MANAGER_DROPIN")
    case "$format" in
      --format=%u) printf '%s\n' "$TEST_MANAGER_DROPIN_OWNER" ;;
      --format=%g) printf '%s\n' "$TEST_MANAGER_DROPIN_GROUP" ;;
      --format=%a) printf '%s\n' "$TEST_MANAGER_DROPIN_MODE" ;;
      *) exit 96 ;;
    esac
    ;;
  "$TEST_VENDOR_DROPIN_ONE"|"$TEST_VENDOR_DROPIN_TWO")
    case "$format" in
      --format=%u) printf '%s\n' "$TEST_VENDOR_DROPIN_OWNER" ;;
      --format=%g) printf '%s\n' "$TEST_VENDOR_DROPIN_GROUP" ;;
      --format=%a) printf '%s\n' "$TEST_VENDOR_DROPIN_MODE" ;;
      *) exit 97 ;;
    esac
    ;;
  "$TEST_MANAGER_EXECUTABLE")
    case "$format" in
      --format=%u) printf '%s\n' "$TEST_EXECUTABLE_OWNER" ;;
      --format=%g) printf '%s\n' "$TEST_EXECUTABLE_GROUP" ;;
      --format=%a) printf '%s\n' "$TEST_EXECUTABLE_MODE" ;;
      *) exit 98 ;;
    esac
    ;;
  *) exit 99 ;;
esac
""",
    )
    _write_executable(
        fake_bin / "timeout",
        """#!/bin/sh
set -eu
case "$1" in --kill-after=*) ;; *) exit 96 ;; esac
shift
case "$1" in *s) ;; *) exit 97 ;; esac
shift
exec "$@"
""",
    )
    _write_executable(
        fake_bin / "busctl",
        """#!/bin/sh
set -eu
printf 'busctl %s\n' "$*" >> "$TEST_SYSTEMCTL_CALLS"
[ "$1" = '--user' ]
[ "$2" = '--no-pager' ]
[ "$3" = 'call' ]
[ "$4" = 'org.freedesktop.DBus' ]
[ "$5" = '/org/freedesktop/DBus' ]
[ "$6" = 'org.freedesktop.DBus' ]
[ "$7" = 'GetConnectionUnixProcessID' ]
[ "$8" = 's' ]
[ "$9" = 'org.freedesktop.systemd1' ]
printf '%s\n' "$TEST_BUS_RESPONSE"
exit "$TEST_BUS_EXIT"
""",
    )
    _write_executable(
        fake_bin / "readlink",
        """#!/bin/sh
set -eu
[ "$1" = '--canonicalize-existing' ]
[ "$2" = '--' ]
case "$3" in
  "$TEST_MANAGER_EXE_LINK") printf '%s\n' "$TEST_MANAGER_EXECUTABLE" ;;
  "$TEST_MANAGER_FRAGMENT") printf '%s\n' "$TEST_MANAGER_FRAGMENT_CANONICAL" ;;
  "$TEST_MANAGER_DROPIN"|"$TEST_VENDOR_DROPIN_ONE"|"$TEST_VENDOR_DROPIN_TWO")
    printf '%s\n' "$3"
    ;;
  *) exit 100 ;;
esac
""",
    )
    _write_executable(
        fake_bin / "systemctl",
        """#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$TEST_SYSTEMCTL_CALLS"
if [ "$1" = '--user' ] && [ "$2" = 'show-environment' ]; then
  exit "$TEST_MANAGER_READY_EXIT"
fi
if [ "$1" = '--user' ] && [ "$2" = '--no-pager' ]; then
  [ "$3" = 'show' ]
  [ "$5" = '--value' ]
  property=${4#--property=}
  case "$property" in
    UnitPath) printf '%s' "$TEST_MANAGER_UNIT_PATH" ;;
    *) exit 98 ;;
  esac
  exit 0
fi
manager_value() {
  property=$1
  if [ "$property" = "$TEST_MANAGER_FAILURE_PROPERTY" ]; then
    exit 98
  fi
  case "$property" in
    ActiveState) printf '%s' "$TEST_MANAGER_ACTIVE_STATE" ;;
    SubState) printf '%s' "$TEST_MANAGER_SUB_STATE" ;;
    LoadState) printf '%s' "$TEST_MANAGER_LOAD_STATE" ;;
    NeedDaemonReload) printf '%s' "$TEST_MANAGER_NEED_DAEMON_RELOAD" ;;
    DropInPaths) printf '%s' "$TEST_MANAGER_DROPIN_PATH" ;;
    Delegate) printf '%s' "$TEST_MANAGER_DELEGATE" ;;
    ControlGroup) printf '%s' "$TEST_MANAGER_CONTROL_GROUP" ;;
    Environment) printf '%s' "$TEST_MANAGER_ENVIRONMENT" ;;
    FragmentPath) printf '%s' "$TEST_MANAGER_FRAGMENT_PATH" ;;
    MainPID) printf '%s' "$TEST_MANAGER_MAIN_PID" ;;
    Transient) printf '%s' "$TEST_MANAGER_TRANSIENT" ;;
    *) exit 99 ;;
  esac
}
if [ "$1" = 'show' ]; then
  [ "$2" = "user@${TEST_UID}.service" ]
  shift 2
  values_only=0
  for argument in "$@"; do
    if [ "$argument" = '--value' ]; then
      values_only=1
    fi
  done
  for argument in "$@"; do
    case "$argument" in
      --property=*)
        property=${argument#--property=}
        value=$(manager_value "$property")
        if [ "$values_only" -eq 1 ]; then
          printf '%s\n' "$value"
        else
          printf '%s=%s\n' "$property" "$value"
        fi
        ;;
      --no-pager|--value) ;;
      *) exit 99 ;;
    esac
  done
  exit 0
fi
[ "$1" = '--user' ]
case "$2" in
  show)
    [ "$3" = 'autocontribute-rootless-docker-daemon.service' ]
    shift 3
    for argument in "$@"; do
      case "$argument" in
        --property=*)
          property=${argument#--property=}
          if [ "$property" = "$TEST_USER_FAILURE_PROPERTY" ]; then
            exit 100
          fi
          case "$property" in
            LoadState) value=$TEST_USER_LOAD_STATE ;;
            NeedDaemonReload) value=$TEST_USER_NEED_DAEMON_RELOAD ;;
            FragmentPath) value=$TEST_USER_FRAGMENT_PATH ;;
            DropInPaths) value=$TEST_USER_DROPIN_PATHS ;;
            ActiveState) value=$TEST_USER_ACTIVE_STATE ;;
            SubState) value=$TEST_USER_SUB_STATE ;;
            Transient) value=$TEST_USER_TRANSIENT ;;
            *) exit 101 ;;
          esac
          printf '%s=%s\n' "$property" "$value"
          ;;
        --no-pager) ;;
        *) exit 101 ;;
      esac
    done
    ;;
  reload)
    [ "$3" = 'autocontribute-rootless-docker-daemon.service' ]
    ;;
  *) exit 102 ;;
esac
""",
    )
    environment = {
        **os.environ,
        "PATH": f"{fake_bin}:/usr/bin:/bin",
        "TEST_BUS_EXIT": str(bus_exit),
        "TEST_BUS_GROUP": str(gid if bus_group is None else bus_group),
        "TEST_BUS_OWNER": str(uid if bus_owner is None else bus_owner),
        "TEST_BUS_RESPONSE": (f"u {manager_main_pid}" if bus_response is None else bus_response),
        "TEST_EXECUTABLE_GROUP": str(executable_group),
        "TEST_EXECUTABLE_MODE": executable_mode,
        "TEST_EXECUTABLE_OWNER": str(executable_owner),
        "TEST_FRAGMENT_GROUP": str(fragment_group),
        "TEST_FRAGMENT_MODE": fragment_mode,
        "TEST_FRAGMENT_OWNER": str(fragment_owner),
        "TEST_GID": str(gid),
        "TEST_HOME_GROUP": str(gid if home_group is None else home_group),
        "TEST_HOME_MODE": home_mode,
        "TEST_HOME_OWNER": str(home_owner),
        "TEST_MANAGER_ACTIVE_STATE": manager_active_state,
        "TEST_MANAGER_CONTROL_GROUP": control_group,
        "TEST_MANAGER_DELEGATE": manager_delegate,
        "TEST_MANAGER_DROPIN_PATH": (
            " ".join(
                [os.fspath(manager_dropin)] * manager_dropin_count
                + [os.fspath(vendor_dropin_one), os.fspath(vendor_dropin_two)]
                + ([manager_extra_dropin] if manager_extra_dropin is not None else [])
            )
            if manager_dropin_path is None
            else manager_dropin_path
        ),
        "TEST_MANAGER_DROPIN": os.fspath(manager_dropin),
        "TEST_MANAGER_DROPIN_GROUP": str(manager_dropin_group),
        "TEST_MANAGER_DROPIN_MODE": manager_dropin_mode,
        "TEST_MANAGER_DROPIN_OWNER": str(manager_dropin_owner),
        "TEST_MANAGER_ENVIRONMENT": (
            f"SYSTEMD_UNIT_PATH={unit_path}" if manager_environment is None else manager_environment
        ),
        "TEST_MANAGER_FAILURE_PROPERTY": manager_failure_property,
        "TEST_MANAGER_EXE_LINK": os.fspath(process_metadata / "exe"),
        "TEST_MANAGER_EXECUTABLE": os.fspath(manager_executable),
        "TEST_MANAGER_FRAGMENT": os.fspath(manager_fragment),
        "TEST_MANAGER_FRAGMENT_CANONICAL": (
            os.fspath(manager_fragment)
            if manager_fragment_canonical is None
            else manager_fragment_canonical
        ),
        "TEST_MANAGER_FRAGMENT_GROUP": str(manager_fragment_group),
        "TEST_MANAGER_FRAGMENT_MODE": manager_fragment_mode,
        "TEST_MANAGER_FRAGMENT_OWNER": str(manager_fragment_owner),
        "TEST_MANAGER_FRAGMENT_PATH": (
            os.fspath(manager_fragment) if manager_fragment_path is None else manager_fragment_path
        ),
        "TEST_MANAGER_LOAD_STATE": manager_load_state,
        "TEST_MANAGER_MAIN_PID": manager_main_pid,
        "TEST_MANAGER_NEED_DAEMON_RELOAD": manager_need_daemon_reload,
        "TEST_MANAGER_READY_EXIT": "0" if manager_ready else "1",
        "TEST_MANAGER_SUB_STATE": manager_sub_state,
        "TEST_MANAGER_TRANSIENT": manager_transient,
        "TEST_MANAGER_UNIT_PATH": (
            unit_path_property if manager_unit_path is None else manager_unit_path
        ),
        "TEST_RUNTIME_GROUP": str(gid if runtime_group is None else runtime_group),
        "TEST_RUNTIME_MODE": runtime_mode,
        "TEST_RUNTIME_OWNER": str(uid if runtime_owner is None else runtime_owner),
        "TEST_SERVICE_HOME": os.fspath(service_home),
        "TEST_SYSTEMCTL_CALLS": os.fspath(calls),
        "TEST_UID": str(uid),
        "TEST_USER_ACTIVE_STATE": user_active_state,
        "TEST_USER_BUS": os.fspath(user_bus),
        "TEST_USER_DROPIN_PATHS": user_dropin_paths,
        "TEST_USER_FAILURE_PROPERTY": user_failure_property,
        "TEST_USER_FRAGMENT": os.fspath(user_fragment),
        "TEST_USER_FRAGMENT_PATH": (
            os.fspath(user_fragment) if user_fragment_path is None else user_fragment_path
        ),
        "TEST_USER_LOAD_STATE": user_load_state,
        "TEST_USER_NEED_DAEMON_RELOAD": user_need_daemon_reload,
        "TEST_USER_RUNTIME": os.fspath(user_runtime),
        "TEST_USER_SUB_STATE": user_sub_state,
        "TEST_USER_TRANSIENT": user_transient,
        "TEST_VENDOR_DROPIN_GROUP": str(vendor_dropin_group),
        "TEST_VENDOR_DROPIN_MODE": vendor_dropin_mode,
        "TEST_VENDOR_DROPIN_ONE": os.fspath(vendor_dropin_one),
        "TEST_VENDOR_DROPIN_OWNER": str(vendor_dropin_owner),
        "TEST_VENDOR_DROPIN_TWO": os.fspath(vendor_dropin_two),
    }
    legacy_socket = user_runtime / "docker.sock"
    legacy_listener: socket.socket | None = None
    if legacy_socket_kind == "socket":
        legacy_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        legacy_listener.bind(os.fspath(legacy_socket))
    elif legacy_socket_kind == "symlink":
        legacy_socket.symlink_to(user_fragment)
    elif legacy_socket_kind != "absent":
        raise AssertionError(f"unknown legacy socket kind: {legacy_socket_kind}")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as bus_listener:
        bus_listener.bind(os.fspath(user_bus))
        try:
            result = subprocess.run(
                ["bash", os.fspath(supervisor), "--reload"],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
                timeout=10,
            )
        finally:
            if legacy_listener is not None:
                legacy_listener.close()
    observed_calls = calls.read_text(encoding="utf-8") if calls.exists() else ""
    short_alias.unlink()
    return result, observed_calls


def _run_workspace_quota_check(
    case_directory: Path,
    *,
    check_mode: str = "--headroom",
    mount_target: str | None = None,
    mount_device: str = "253:7",
    filesystem_type: str = "ext4",
    filesystem_root: str = "/",
    mount_options: str = "rw,nosuid,nodev,relatime",
    mount_records: str | None = None,
    mount_table: str | None = None,
    workspace_owner: int | None = None,
    workspace_group: int | None = None,
    workspace_mode: str = "700",
    workspace_stat_device: str = "2049",
    parent_device: str = "2048",
    block_size: str = "4096",
    total_blocks: str = "4194304",
    total_inodes: str = "262144",
    available_blocks: str = "3145728",
    available_inodes: str = "196608",
) -> subprocess.CompletedProcess[str]:
    case_directory.mkdir()
    workspace = case_directory / "workspace"
    workspace.mkdir(mode=0o700)
    fake_bin = case_directory / "bin"
    fake_bin.mkdir()
    uid = os.getuid()
    gid = os.getgid()
    resolved_target = mount_target or os.fspath(workspace)
    resolved_mount_records = (
        mount_records
        if mount_records is not None
        else "{target} {filesystem} {root} {options} {device}\n"
    ).format(
        target=resolved_target,
        workspace=resolved_target,
        filesystem=filesystem_type,
        root=filesystem_root,
        options=mount_options,
        device=mount_device,
    )
    resolved_mount_table = (mount_table or "0:1 /\n{device} {workspace}\n0:2 /proc\n").format(
        device=mount_device,
        workspace=workspace,
    )

    _write_executable(
        fake_bin / "id",
        """#!/bin/sh
set -eu
[ "$*" = '--group' ]
printf '%s\n' "$TEST_SERVICE_GID"
""",
    )
    _write_executable(
        fake_bin / "findmnt",
        """#!/bin/sh
set -eu
if [ "$1" = '--noheadings' ] && [ "$2" = '--raw' ] && [ "$3" = '--mountpoint' ]; then
  [ "$4" = "$TEST_WORKSPACE" ]
  [ "$5" = '--output' ]
  [ "$6" = 'TARGET,FSTYPE,FSROOT,OPTIONS,MAJ:MIN' ]
  printf '%s' "$TEST_MOUNT_RECORDS"
elif [ "$1" = '--noheadings' ] && [ "$2" = '--raw' ] && [ "$3" = '--output' ]; then
  [ "$4" = 'MAJ:MIN,TARGET' ]
  printf '%s' "$TEST_MOUNT_TABLE"
else
  exit 81
fi
""",
    )
    _write_executable(
        fake_bin / "stat",
        """#!/bin/sh
set -eu
if [ "$1" = '--file-system' ]; then
  [ "$2" = '--format=%S:%b:%c:%a:%d' ]
  [ "$3" = '--' ]
  [ "$4" = "$TEST_WORKSPACE" ]
  printf '%s:%s:%s:%s:%s\n' \
    "$TEST_BLOCK_SIZE" "$TEST_TOTAL_BLOCKS" "$TEST_TOTAL_INODES" \
    "$TEST_AVAILABLE_BLOCKS" "$TEST_AVAILABLE_INODES"
  exit 0
fi
[ "$2" = '--' ]
path=$3
case "$1:$path" in
  --format=%u:"$TEST_WORKSPACE") printf '%s\n' "$TEST_WORKSPACE_OWNER" ;;
  --format=%g:"$TEST_WORKSPACE") printf '%s\n' "$TEST_WORKSPACE_GROUP" ;;
  --format=%a:"$TEST_WORKSPACE") printf '%s\n' "$TEST_WORKSPACE_MODE" ;;
  --format=%d:"$TEST_WORKSPACE") printf '%s\n' "$TEST_WORKSPACE_DEVICE" ;;
  --format=%d:"$TEST_WORKSPACE_PARENT") printf '%s\n' "$TEST_PARENT_DEVICE" ;;
  *) exit 82 ;;
esac
""",
    )

    environment = {
        **os.environ,
        "TEST_AVAILABLE_BLOCKS": available_blocks,
        "TEST_AVAILABLE_INODES": available_inodes,
        "PATH": f"{fake_bin}:/usr/bin:/bin",
        "TEST_BLOCK_SIZE": block_size,
        "TEST_FILESYSTEM_ROOT": filesystem_root,
        "TEST_FILESYSTEM_TYPE": filesystem_type,
        "TEST_MOUNT_OPTIONS": mount_options,
        "TEST_MOUNT_DEVICE": mount_device,
        "TEST_MOUNT_RECORDS": resolved_mount_records,
        "TEST_MOUNT_TABLE": resolved_mount_table,
        "TEST_MOUNT_TARGET": resolved_target,
        "TEST_PARENT_DEVICE": parent_device,
        "TEST_SERVICE_GID": str(gid),
        "TEST_TOTAL_BLOCKS": total_blocks,
        "TEST_TOTAL_INODES": total_inodes,
        "TEST_WORKSPACE": os.fspath(workspace),
        "TEST_WORKSPACE_DEVICE": workspace_stat_device,
        "TEST_WORKSPACE_GROUP": str(gid if workspace_group is None else workspace_group),
        "TEST_WORKSPACE_MODE": workspace_mode,
        "TEST_WORKSPACE_OWNER": str(uid if workspace_owner is None else workspace_owner),
        "TEST_WORKSPACE_PARENT": os.fspath(workspace.parent),
    }
    test_script = case_directory / "workspace-quota-check"
    _write_executable(test_script, WORKSPACE_QUOTA_CHECK.read_text(encoding="utf-8"))
    return subprocess.run(
        [
            "bash",
            os.fspath(test_script),
            check_mode,
            os.fspath(workspace),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )


def _run_storage_capacity_check(
    case_directory: Path,
    *,
    state_mount_device: str = "253:8",
    backup_mount_device: str = "253:9",
    state_mount_options: str = "rw,nosuid,nodev,noexec,relatime",
    backup_mount_options: str = "rw,nosuid,nodev,noexec,relatime",
    state_mount_target: str | None = None,
    backup_mount_target: str | None = None,
    state_filesystem_type: str = "ext4",
    backup_filesystem_type: str = "ext4",
    state_filesystem_root: str = "/",
    backup_filesystem_root: str = "/",
    state_mount_records: str | None = None,
    backup_mount_records: str | None = None,
    mount_table: str | None = None,
    state_owner: int | None = None,
    backup_owner: int | None = None,
    state_group: int | None = None,
    backup_group: int | None = None,
    state_mode: str = "700",
    backup_mode: str = "700",
    state_stat_device: str = "2050",
    backup_stat_device: str = "2051",
    state_parent_device: str = "2048",
    backup_parent_device: str = "2049",
    state_block_size: str = "4096",
    state_total_blocks: str = "1572864",
    state_available_blocks: str = "524288",
    state_total_inodes: str = "131072",
    state_free_inodes: str = "65536",
    backup_block_size: str = "4096",
    backup_total_blocks: str = "12582912",
    backup_available_blocks: str = "6291456",
    backup_total_inodes: str = "393216",
    backup_free_inodes: str = "300000",
    access_mode: str = "--writable",
    state_effectively_writable: bool | None = None,
    backup_effectively_writable: bool | None = None,
) -> subprocess.CompletedProcess[str]:
    case_directory.mkdir()
    state = case_directory / "state-parent" / "state"
    backup = case_directory / "backup-parent" / "backup"
    state.mkdir(mode=0o700, parents=True)
    backup.mkdir(mode=0o700, parents=True)
    if state_effectively_writable is None:
        state_effectively_writable = access_mode != "--read-only"
    if backup_effectively_writable is None:
        backup_effectively_writable = access_mode == "--writable"
    if not state_effectively_writable:
        state.chmod(0o500)
    if not backup_effectively_writable:
        backup.chmod(0o500)
    fake_bin = case_directory / "bin"
    fake_bin.mkdir()
    uid = os.getuid()
    gid = os.getgid()
    resolved_state_mount_target = state_mount_target or os.fspath(state)
    resolved_backup_mount_target = backup_mount_target or os.fspath(backup)
    resolved_state_mount_records = (
        state_mount_records
        if state_mount_records is not None
        else "{target} {filesystem} {root} {options} {device}\n"
    ).format(
        target=resolved_state_mount_target,
        state=state,
        backup=backup,
        filesystem=state_filesystem_type,
        root=state_filesystem_root,
        options=state_mount_options,
        device=state_mount_device,
    )
    resolved_backup_mount_records = (
        backup_mount_records
        if backup_mount_records is not None
        else "{target} {filesystem} {root} {options} {device}\n"
    ).format(
        target=resolved_backup_mount_target,
        state=state,
        backup=backup,
        filesystem=backup_filesystem_type,
        root=backup_filesystem_root,
        options=backup_mount_options,
        device=backup_mount_device,
    )
    resolved_mount_table = (
        mount_table or "0:1 /\n{state_device} {state}\n{backup_device} {backup}\n0:2 /proc\n"
    ).format(
        state_device=state_mount_device,
        backup_device=backup_mount_device,
        state=state,
        backup=backup,
    )

    _write_executable(
        fake_bin / "id",
        """#!/bin/sh
set -eu
[ "$*" = '--group' ]
printf '%s\n' "$TEST_SERVICE_GID"
""",
    )
    _write_executable(
        fake_bin / "findmnt",
        """#!/bin/sh
set -eu
if [ "$1" = '--noheadings' ] && [ "$2" = '--raw' ] && [ "$3" = '--mountpoint' ]; then
  path=$4
  [ "$5" = '--output' ]
  [ "$6" = 'TARGET,FSTYPE,FSROOT,OPTIONS,MAJ:MIN' ]
  case "$path" in
    "$TEST_STATE") printf '%s' "$TEST_STATE_MOUNT_RECORDS" ;;
    "$TEST_BACKUP") printf '%s' "$TEST_BACKUP_MOUNT_RECORDS" ;;
    *) exit 80 ;;
  esac
elif [ "$1" = '--noheadings' ] && [ "$2" = '--raw' ] && [ "$3" = '--output' ]; then
  [ "$4" = 'MAJ:MIN,TARGET' ]
  printf '%s' "$TEST_MOUNT_TABLE"
else
  exit 81
fi
""",
    )
    _write_executable(
        fake_bin / "stat",
        """#!/bin/sh
set -eu
if [ "$1" = '--file-system' ]; then
  [ "$2" = '--format=%S:%b:%a:%c:%d' ]
  [ "$3" = '--' ]
  case "$4" in
    "$TEST_STATE") printf '%s:%s:%s:%s:%s\n' \
      "$TEST_STATE_BLOCK_SIZE" "$TEST_STATE_TOTAL_BLOCKS" \
      "$TEST_STATE_AVAILABLE_BLOCKS" "$TEST_STATE_TOTAL_INODES" \
      "$TEST_STATE_FREE_INODES" ;;
    "$TEST_BACKUP") printf '%s:%s:%s:%s:%s\n' \
      "$TEST_BACKUP_BLOCK_SIZE" "$TEST_BACKUP_TOTAL_BLOCKS" \
      "$TEST_BACKUP_AVAILABLE_BLOCKS" "$TEST_BACKUP_TOTAL_INODES" \
      "$TEST_BACKUP_FREE_INODES" ;;
    *) exit 82 ;;
  esac
  exit 0
fi
[ "$2" = '--' ]
path=$3
case "$1:$path" in
  --format=%u:"$TEST_STATE") printf '%s\n' "$TEST_STATE_OWNER" ;;
  --format=%g:"$TEST_STATE") printf '%s\n' "$TEST_STATE_GROUP" ;;
  --format=%a:"$TEST_STATE") printf '%s\n' "$TEST_STATE_MODE" ;;
  --format=%d:"$TEST_STATE") printf '%s\n' "$TEST_STATE_DEVICE" ;;
  --format=%u:"$TEST_BACKUP") printf '%s\n' "$TEST_BACKUP_OWNER" ;;
  --format=%g:"$TEST_BACKUP") printf '%s\n' "$TEST_BACKUP_GROUP" ;;
  --format=%a:"$TEST_BACKUP") printf '%s\n' "$TEST_BACKUP_MODE" ;;
  --format=%d:"$TEST_BACKUP") printf '%s\n' "$TEST_BACKUP_DEVICE" ;;
  --format=%d:"$TEST_STATE_PARENT") printf '%s\n' "$TEST_STATE_PARENT_DEVICE" ;;
  --format=%d:"$TEST_BACKUP_PARENT") printf '%s\n' "$TEST_BACKUP_PARENT_DEVICE" ;;
  *) exit 83 ;;
esac
""",
    )

    environment = {
        **os.environ,
        "PATH": f"{fake_bin}:/usr/bin:/bin",
        "TEST_BACKUP": os.fspath(backup),
        "TEST_BACKUP_AVAILABLE_BLOCKS": backup_available_blocks,
        "TEST_BACKUP_BLOCK_SIZE": backup_block_size,
        "TEST_BACKUP_DEVICE": backup_stat_device,
        "TEST_BACKUP_FILESYSTEM_ROOT": backup_filesystem_root,
        "TEST_BACKUP_FILESYSTEM_TYPE": backup_filesystem_type,
        "TEST_BACKUP_FREE_INODES": backup_free_inodes,
        "TEST_BACKUP_GROUP": str(gid if backup_group is None else backup_group),
        "TEST_BACKUP_MODE": backup_mode,
        "TEST_BACKUP_MOUNT_DEVICE": backup_mount_device,
        "TEST_BACKUP_MOUNT_OPTIONS": backup_mount_options,
        "TEST_BACKUP_MOUNT_RECORDS": resolved_backup_mount_records,
        "TEST_BACKUP_MOUNT_TARGET": resolved_backup_mount_target,
        "TEST_BACKUP_OWNER": str(uid if backup_owner is None else backup_owner),
        "TEST_BACKUP_PARENT": os.fspath(backup.parent),
        "TEST_BACKUP_PARENT_DEVICE": backup_parent_device,
        "TEST_BACKUP_TOTAL_BLOCKS": backup_total_blocks,
        "TEST_BACKUP_TOTAL_INODES": backup_total_inodes,
        "TEST_MOUNT_TABLE": resolved_mount_table,
        "TEST_SERVICE_GID": str(gid),
        "TEST_STATE": os.fspath(state),
        "TEST_STATE_AVAILABLE_BLOCKS": state_available_blocks,
        "TEST_STATE_BLOCK_SIZE": state_block_size,
        "TEST_STATE_DEVICE": state_stat_device,
        "TEST_STATE_FILESYSTEM_ROOT": state_filesystem_root,
        "TEST_STATE_FILESYSTEM_TYPE": state_filesystem_type,
        "TEST_STATE_FREE_INODES": state_free_inodes,
        "TEST_STATE_GROUP": str(gid if state_group is None else state_group),
        "TEST_STATE_MODE": state_mode,
        "TEST_STATE_MOUNT_DEVICE": state_mount_device,
        "TEST_STATE_MOUNT_OPTIONS": state_mount_options,
        "TEST_STATE_MOUNT_RECORDS": resolved_state_mount_records,
        "TEST_STATE_MOUNT_TARGET": resolved_state_mount_target,
        "TEST_STATE_OWNER": str(uid if state_owner is None else state_owner),
        "TEST_STATE_PARENT": os.fspath(state.parent),
        "TEST_STATE_PARENT_DEVICE": state_parent_device,
        "TEST_STATE_TOTAL_BLOCKS": state_total_blocks,
        "TEST_STATE_TOTAL_INODES": state_total_inodes,
    }
    test_script = case_directory / "storage-capacity-check"
    _write_executable(test_script, STORAGE_CAPACITY_CHECK.read_text(encoding="utf-8"))
    return subprocess.run(
        [
            "bash",
            os.fspath(test_script),
            os.fspath(state),
            os.fspath(backup),
            access_mode,
        ],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )


def _run_docker_data_check(
    case_directory: Path,
    *,
    check_mode: str = "--daemon",
    docker_root_output: str | None = None,
    docker_exit: int = 0,
    mount_target: str | None = None,
    mount_device: str = "253:8",
    filesystem_type: str = "ext4",
    filesystem_root: str = "/",
    mount_options: str = "rw,nosuid,nodev,relatime",
    mount_rows: str | None = None,
    effective_mount_row: str | None = None,
    mount_table: str | None = None,
    data_owner: int | None = None,
    data_group: int | None = None,
    data_mode: str = "710",
    data_stat_device: str = "2050",
    parent_device: str = "2048",
    block_size: str = "4096",
    total_blocks: str = "6291456",
    total_inodes: str = "524288",
    available_blocks: str = "2097152",
    available_inodes: str = "262144",
) -> tuple[subprocess.CompletedProcess[str], str | None]:
    case_directory.mkdir()
    data_root = case_directory / "docker"
    data_root.mkdir(mode=0o710)
    fake_bin = case_directory / "bin"
    fake_bin.mkdir()
    probe_environment = case_directory / "docker-probe-environment"
    uid = os.getuid()
    gid = os.getgid()
    resolved_target = mount_target or os.fspath(data_root)
    mount_row_template = "{target} {filesystem_type} {filesystem_root} {mount_options} {device}\n"
    base_mount_row = mount_row_template.format(
        data_root=data_root,
        device=mount_device,
        filesystem_root=filesystem_root,
        filesystem_type=filesystem_type,
        mount_options=mount_options,
        target=resolved_target,
    )
    readonly_options = ",".join(
        "ro" if option == "rw" else option for option in mount_options.split(",")
    )
    readonly_mount_row = mount_row_template.format(
        data_root=data_root,
        device=mount_device,
        filesystem_root=filesystem_root,
        filesystem_type=filesystem_type,
        mount_options=readonly_options,
        target=resolved_target,
    )
    if mount_rows is None:
        resolved_mount_rows = base_mount_row
        if check_mode != "--mount-only":
            resolved_mount_rows += readonly_mount_row
    else:
        resolved_mount_rows = mount_rows.format(
            data_root=data_root,
            device=mount_device,
            filesystem_root=filesystem_root,
            filesystem_type=filesystem_type,
            mount_options=mount_options,
            target=resolved_target,
        )
    resolved_effective_mount_row = (effective_mount_row or readonly_mount_row).format(
        data_root=data_root,
        device=mount_device,
        filesystem_root=filesystem_root,
        filesystem_type=filesystem_type,
        mount_options=mount_options,
        target=resolved_target,
    )
    resolved_mount_table = (mount_table or "0:1 /\n{device} {data_root}\n0:2 /proc\n").format(
        device=mount_device,
        data_root=data_root,
    )
    resolved_docker_output = (
        docker_root_output if docker_root_output is not None else f'"{os.fspath(data_root)}"\n'
    )

    _write_executable(
        fake_bin / "id",
        """#!/bin/sh
set -eu
[ "$*" = '--group' ]
printf '%s\n' "$TEST_SERVICE_GID"
""",
    )
    _write_executable(
        fake_bin / "findmnt",
        """#!/bin/sh
set -eu
if [ "$1" = '--noheadings' ] && [ "$2" = '--raw' ] && [ "$3" = '--mountpoint' ]; then
  [ "$4" = "$TEST_DOCKER_DATA_ROOT" ]
  [ "$5" = '--output' ]
  [ "$6" = 'TARGET,FSTYPE,FSROOT,OPTIONS,MAJ:MIN' ]
  printf '%s' "$TEST_MOUNT_ROWS"
elif [ "$1" = '--noheadings' ] && [ "$2" = '--raw' ] && [ "$3" = '--target' ]; then
  [ "$4" = "$TEST_DOCKER_DATA_ROOT" ]
  [ "$5" = '--output' ]
  [ "$6" = 'TARGET,FSTYPE,FSROOT,OPTIONS,MAJ:MIN' ]
  printf '%s' "$TEST_EFFECTIVE_MOUNT_ROW"
elif [ "$1" = '--noheadings' ] && [ "$2" = '--raw' ] && [ "$3" = '--output' ]; then
  [ "$4" = 'MAJ:MIN,TARGET' ]
  printf '%s' "$TEST_MOUNT_TABLE"
else
  exit 81
fi
""",
    )
    _write_executable(
        fake_bin / "stat",
        """#!/bin/sh
set -eu
if [ "$1" = '--file-system' ]; then
  [ "$2" = '--format=%S:%b:%c:%a:%d' ]
  [ "$3" = '--' ]
  [ "$4" = "$TEST_DOCKER_DATA_ROOT" ]
  printf '%s:%s:%s:%s:%s\n' \
    "$TEST_BLOCK_SIZE" "$TEST_TOTAL_BLOCKS" "$TEST_TOTAL_INODES" \
    "$TEST_AVAILABLE_BLOCKS" "$TEST_AVAILABLE_INODES"
  exit 0
fi
[ "$2" = '--' ]
path=$3
case "$1:$path" in
  --format=%u:"$TEST_DOCKER_DATA_ROOT") printf '%s\n' "$TEST_DATA_OWNER" ;;
  --format=%g:"$TEST_DOCKER_DATA_ROOT") printf '%s\n' "$TEST_DATA_GROUP" ;;
  --format=%a:"$TEST_DOCKER_DATA_ROOT") printf '%s\n' "$TEST_DATA_MODE" ;;
  --format=%d:"$TEST_DOCKER_DATA_ROOT") printf '%s\n' "$TEST_DATA_DEVICE" ;;
  --format=%d:"$TEST_DOCKER_DATA_PARENT") printf '%s\n' "$TEST_PARENT_DEVICE" ;;
  *) exit 82 ;;
esac
""",
    )
    _write_executable(
        fake_bin / "timeout",
        """#!/bin/sh
set -eu
[ "$1" = '--kill-after=5s' ]
shift
[ "$1" = '30s' ]
shift
exec "$@"
""",
    )
    _write_executable(
        fake_bin / "docker",
        """#!/bin/sh
set -eu
[ "$1" = '--host' ]
[ "$2" = "$DOCKER_HOST" ]
[ "$3" = 'info' ]
[ "$4" = '--format' ]
[ "$5" = '{{json .DockerRootDir}}' ]
printf '%s\n%s\n' "$DOCKER_HOST" "${DOCKER_CONTEXT-unset}" > "$TEST_PROBE_ENVIRONMENT"
printf '%s' "$TEST_DOCKER_OUTPUT"
exit "$TEST_DOCKER_EXIT"
""",
    )

    environment = {
        **os.environ,
        "TEST_AVAILABLE_BLOCKS": available_blocks,
        "TEST_AVAILABLE_INODES": available_inodes,
        "DOCKER_CONTEXT": "must-be-cleared",
        "DOCKER_HOST": "unix:///run/autocontribute/docker.sock",
        "PATH": f"{fake_bin}:/usr/bin:/bin",
        "TEST_BLOCK_SIZE": block_size,
        "TEST_DATA_DEVICE": data_stat_device,
        "TEST_DATA_GROUP": str(gid if data_group is None else data_group),
        "TEST_DATA_MODE": data_mode,
        "TEST_DATA_OWNER": str(uid if data_owner is None else data_owner),
        "TEST_DOCKER_DATA_PARENT": os.fspath(data_root.parent),
        "TEST_DOCKER_DATA_ROOT": os.fspath(data_root),
        "TEST_DOCKER_EXIT": str(docker_exit),
        "TEST_DOCKER_OUTPUT": resolved_docker_output,
        "TEST_EFFECTIVE_MOUNT_ROW": resolved_effective_mount_row,
        "TEST_FILESYSTEM_ROOT": filesystem_root,
        "TEST_FILESYSTEM_TYPE": filesystem_type,
        "TEST_MOUNT_DEVICE": mount_device,
        "TEST_MOUNT_OPTIONS": mount_options,
        "TEST_MOUNT_ROWS": resolved_mount_rows,
        "TEST_MOUNT_TABLE": resolved_mount_table,
        "TEST_MOUNT_TARGET": resolved_target,
        "TEST_PARENT_DEVICE": parent_device,
        "TEST_PROBE_ENVIRONMENT": os.fspath(probe_environment),
        "TEST_SERVICE_GID": str(gid),
        "TEST_TOTAL_BLOCKS": total_blocks,
        "TEST_TOTAL_INODES": total_inodes,
    }
    result = subprocess.run(
        ["bash", os.fspath(DOCKER_DATA_CHECK), check_mode, os.fspath(data_root)],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    observed_environment = (
        probe_environment.read_text(encoding="utf-8") if probe_environment.exists() else None
    )
    return result, observed_environment


def test_systemd_bundle_contains_expected_units_and_executable_helpers() -> None:
    expected = {
        "autocontribute-backup.service",
        "autocontribute-backup.timer",
        "autocontribute-doctor.service",
        "autocontribute-failure@.service",
        "autocontribute-health.service",
        "autocontribute-health.timer",
        "autocontribute-rootless-docker.service",
        "autocontribute-user-manager.conf",
        "autocontribute-worker.service",
        "autocontribute-worker.timer",
        "autocontribute.journald.conf.example",
        "autocontribute.tmpfiles.conf",
    }
    assert {path.name for path in SYSTEMD.iterdir() if path.is_file()} == expected
    assert not (SYSTEMD / "rootless-docker.service.d" / "10-autocontribute-data-root.conf").exists()

    helpers = sorted((SYSTEMD / "libexec").iterdir())
    assert {path.name for path in helpers} == {
        "autocontribute-backup",
        "autocontribute-docker-data-check",
        "autocontribute-healthcheck",
        "autocontribute-record-failure",
        "autocontribute-rootless-docker",
        "autocontribute-rootless-docker-check",
        "autocontribute-rootless-dockerd",
        "autocontribute-storage-capacity-check",
        "autocontribute-worker",
        "autocontribute-workspace-quota-check",
    }
    for helper in helpers:
        assert stat.S_IMODE(helper.stat().st_mode) == 0o755
        result = subprocess.run(
            ["bash", "-n", os.fspath(helper)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr

    user_units = sorted((SYSTEMD / "user").iterdir())
    assert {path.name for path in user_units} == {"autocontribute-rootless-docker-daemon.service"}
    for user_unit in user_units:
        assert stat.S_IMODE(user_unit.stat().st_mode) == 0o644


def test_operational_units_fail_closed_on_release_asset_mismatch() -> None:
    verifier = (
        "/opt/autocontribute/current/.venv/bin/autocontribute deployment verify-systemd-assets"
    )
    for name in (
        "autocontribute-worker.service",
        "autocontribute-doctor.service",
        "autocontribute-backup.service",
        "autocontribute-health.service",
        "autocontribute-rootless-docker.service",
    ):
        unit = _directives(SYSTEMD / name)
        assert verifier in unit[("Service", "ExecStartPre")]
    user_daemon = _directives(SYSTEMD / "user" / "autocontribute-rootless-docker-daemon.service")
    assert verifier in user_daemon[("Service", "ExecStartPre")]

    for name in ("autocontribute-worker.service", "autocontribute-doctor.service"):
        unit = _directives(SYSTEMD / name)
        assert "AUTOCONTRIBUTE_REQUIRE_SYSTEMD_ASSETS=1" in unit[("Service", "Environment")]

    failure = (SYSTEMD / "autocontribute-failure@.service").read_text(encoding="utf-8")
    assert "verify-systemd-assets" not in failure

    worker = (SYSTEMD / "libexec" / "autocontribute-worker").read_text(encoding="utf-8")
    backup = (SYSTEMD / "libexec" / "autocontribute-backup").read_text(encoding="utf-8")
    verifier_call = '"$executable" deployment verify-systemd-assets'
    assert worker.index(verifier_call) < worker.index('if [[ ! -r "$config" ]]')
    assert worker.index(verifier_call) < worker.index('credential_value="$(<"$credential_path")"')
    assert backup.index(verifier_call) < backup.index('"$storage_capacity_check"')


@pytest.mark.parametrize(
    ("wrapper_name", "arguments"),
    [
        ("autocontribute-worker", ["run"]),
        ("autocontribute-backup", []),
    ],
)
def test_worker_and_backup_abort_when_release_asset_verification_fails(
    tmp_path: Path,
    wrapper_name: str,
    arguments: list[str],
) -> None:
    executable = tmp_path / "autocontribute"
    calls = tmp_path / "calls"
    downstream = tmp_path / "downstream"
    config = tmp_path / "autocontribute.yml"
    config.write_text("publishing:\n  mode: review_required\n", encoding="utf-8")
    _write_executable(
        executable,
        """#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$AUTOCONTRIBUTE_TEST_CALLS"
if [ "$#" -eq 2 ] && [ "$1" = deployment ] && [ "$2" = verify-systemd-assets ]; then
  exit 73
fi
: > "$AUTOCONTRIBUTE_TEST_DOWNSTREAM"
""",
    )
    environment = {
        **os.environ,
        "AUTOCONTRIBUTE_CONFIG": os.fspath(config),
        "AUTOCONTRIBUTE_EXECUTABLE": os.fspath(executable),
        "AUTOCONTRIBUTE_TEST_CALLS": os.fspath(calls),
        "AUTOCONTRIBUTE_TEST_DOWNSTREAM": os.fspath(downstream),
        "AUTOCONTRIBUTE_CREDENTIAL_NAMES": "SENTINEL_SECRET",
        "CREDENTIALS_DIRECTORY": os.fspath(tmp_path / "credentials"),
    }

    result = subprocess.run(
        ["bash", os.fspath(SYSTEMD / "libexec" / wrapper_name), *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env=environment,
    )

    assert result.returncode == 73, result.stderr
    assert calls.read_text(encoding="utf-8") == "deployment verify-systemd-assets\n"
    assert not downstream.exists()


def test_ci_runs_real_version_controlled_systemd_validation() -> None:
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    job = workflow["jobs"]["systemd-deployment"]

    assert job["runs-on"] == "ubuntu-24.04"
    steps = job["steps"]
    baseline = next(
        step for step in steps if step["name"] == "Require the controlled systemd baseline"
    )
    helper_install = next(
        step
        for step in steps
        if step["name"] == "Make packaged helpers available to executable validation"
    )
    storage_smoke = next(
        step
        for step in steps
        if step["name"] == "Exercise durable storage preflight in a hardened service"
    )
    docker_smoke = next(
        step
        for step in steps
        if step["name"] == "Exercise bounded Docker data-root preflight in a hardened service"
    )
    verify = next(
        step for step in steps if step["name"] == "Verify system, timer, and protected user units"
    )
    security = next(
        step for step in steps if step["name"] == "Enforce service hardening exposure ceilings"
    )

    assert '[[ "$systemd_major" != "255" ]]' in baseline["run"]
    assert "/opt/autocontribute/current/.venv/bin/autocontribute" in helper_install["run"]
    assert "/usr/bin/true" in helper_install["run"]
    assert "systemd-run" in storage_smoke["run"]
    assert "autocontribute-storage-capacity-check" in storage_smoke["run"]
    assert "truncate --size 24G" in storage_smoke["run"]
    assert "Production storage" in storage_smoke["run"]
    assert '--property="ReadWritePaths=$state_parent $backup_mount"' in storage_smoke["run"]
    assert '--property="ReadWritePaths=$state_parent"' in storage_smoke["run"]
    assert '--property="ReadOnlyPaths=$backup_mount"' in storage_smoke["run"]
    assert '"$state_mount" "$backup_mount" --state-writable' in storage_smoke["run"]
    assert '--property="ReadOnlyPaths=$state_mount $backup_mount"' in storage_smoke["run"]
    assert '"$state_mount" "$backup_mount" --read-only' in storage_smoke["run"]
    assert "autocontribute-docker-data-check" in docker_smoke["run"]
    assert "fallocate --length 2G" in docker_smoke["run"]
    assert "--mount-only" in docker_smoke["run"]
    assert "--read-only-health" in docker_smoke["run"]
    assert '--property="ReadWritePaths=$smoke_root"' in docker_smoke["run"]
    assert '--property="ReadOnlyPaths=$docker_data_mount"' in docker_smoke["run"]
    assert "systemd-analyze verify" in verify["run"]
    assert "--recursive-errors=no" in verify["run"]
    assert "autocontribute-rootless-docker-daemon.service" in verify["run"]
    assert "systemd-analyze security" in security["run"]
    assert "--offline=yes" in security["run"]
    assert "[autocontribute-worker.service]=40" in security["run"]
    assert "[autocontribute-doctor.service]=40" in security["run"]
    assert "[autocontribute-backup.service]=30" in security["run"]
    assert "[autocontribute-health.service]=30" in security["run"]
    assert "[autocontribute-failure@.service]=30" in security["run"]


def test_worker_is_twice_daily_persistent_and_uses_rootless_docker() -> None:
    timer = _directives(SYSTEMD / "autocontribute-worker.timer")
    assert _one(timer, "Timer", "OnCalendar") == "*-*-* 09,21:17:00 UTC"
    assert _one(timer, "Timer", "Persistent") == "yes"
    assert _one(timer, "Timer", "Unit") == "autocontribute-worker.service"

    unit_text = (SYSTEMD / "autocontribute-worker.service").read_text(encoding="utf-8")
    assert "User=autocontribute" in unit_text
    assert "/var/run/docker.sock" not in unit_text
    assert "LoadCredentialEncrypted=OPENAI_API_KEY:" in unit_text
    assert "LoadCredentialEncrypted=AUTOCONTRIBUTE_GITHUB_TOKEN:" in unit_text
    assert "EnvironmentFile=" not in unit_text
    assert "RequiresMountsFor=/var/lib/autocontribute/state/workspaces" in unit_text
    assert "RequiresMountsFor=/var/lib/autocontribute/docker" in unit_text

    doctor_unit_text = (SYSTEMD / "autocontribute-doctor.service").read_text(encoding="utf-8")
    assert "RequiresMountsFor=/var/lib/autocontribute/state/workspaces" in doctor_unit_text
    assert "RequiresMountsFor=/var/lib/autocontribute/docker" in doctor_unit_text
    readonly_paths = (
        "ReadOnlyPaths=/etc/autocontribute /opt/autocontribute /var/lib/autocontribute/docker"
    )
    assert readonly_paths in unit_text
    assert readonly_paths in doctor_unit_text
    assert "ReadWritePaths=/var/lib/autocontribute" in unit_text
    assert "ReadWritePaths=/var/lib/autocontribute" in doctor_unit_text
    for service_name in (
        "autocontribute-worker.service",
        "autocontribute-doctor.service",
    ):
        service = _directives(SYSTEMD / service_name)
        assert _one(service, "Unit", "Requires") == "autocontribute-rootless-docker.service"
        assert "autocontribute-rootless-docker.service" in _one(service, "Unit", "After").split()

    helper = (SYSTEMD / "libexec" / "autocontribute-worker").read_text(encoding="utf-8")
    assert 'run --scheduled --config "$config"' in helper
    assert "state gc-workspaces" in helper
    assert "--older-than-days 7" in helper
    assert "--limit 25" in helper
    assert "--execute" in helper
    gc_call = helper.index("state gc-workspaces")
    run_call = helper.index('run --scheduled --config "$config"')
    credential_read = helper.index('credential_value="$(<"$credential_path")"')
    structural_call = '"$workspace_quota_check" --structural "$workspace_root"'
    headroom_call = '"$workspace_quota_check" --headroom "$workspace_root"'
    marker_export = 'export AUTOCONTRIBUTE_REQUIRED_WORKSPACE_ROOT="$workspace_root"'
    assert structural_call in helper
    assert headroom_call in helper
    assert helper.index(structural_call) < helper.index(marker_export) < gc_call
    assert gc_call < helper.index(headroom_call) < credential_read < run_call
    assert 'runtime_directory="/run/autocontribute"' in helper
    assert 'export DOCKER_HOST="unix://$docker_socket"' in helper
    assert (
        'rootless_docker_check="/usr/local/libexec/autocontribute-rootless-docker-check"' in helper
    )
    assert (
        '"$rootless_docker_check" "$runtime_directory" "$docker_socket" '
        '"$rootful_docker_socket"' in helper
    )
    check_call = (
        '"$rootless_docker_check" "$runtime_directory" "$docker_socket" "$rootful_docker_socket"'
    )
    data_call = '"$docker_data_check" --daemon "$docker_data_root"'
    assert data_call in helper
    assert helper.index(check_call) < helper.index(data_call) < credential_read
    assert 'export AUTOCONTRIBUTE_REQUIRED_DOCKER_ROOT="$docker_data_root"' in helper
    assert "AUTOCONTRIBUTE_REQUIRED_DOCKER_ROOT" in helper
    assert helper.index(check_call) < helper.index('credential_value="$(<"$credential_path")"')
    assert "DOCKER_*" in helper
    assert "credential_value" in helper
    assert "set -euo pipefail" in helper
    assert helper.index(headroom_call) < helper.index(check_call)
    assert helper.index(headroom_call) < credential_read
    storage_call = '"$storage_capacity_check" "$state_root" "$backup_root" --state-writable'
    assert storage_call in helper
    assert helper.index(storage_call) < helper.index(structural_call)
    assert helper.index(storage_call) < helper.index('credential_value="$(<"$credential_path")"')
    assert helper.index(structural_call) < helper.index(check_call)
    assert helper.index(structural_call) < helper.index('credential_value="$(<"$credential_path")"')
    assert 'export AUTOCONTRIBUTE_REQUIRED_WORKSPACE_ROOT="$workspace_root"' in helper
    assert 'export AUTOCONTRIBUTE_REQUIRED_STORAGE_ROOT="$state_root"' in helper


def test_workspace_quota_check_accepts_bounded_dedicated_ext4_mount(tmp_path: Path) -> None:
    result = _run_workspace_quota_check(tmp_path / "valid")

    assert result.returncode == 0, result.stderr


def test_workspace_quota_check_accepts_same_target_namespace_layers(tmp_path: Path) -> None:
    result = _run_workspace_quota_check(
        tmp_path / "same-target-layers",
        mount_records=(
            "{workspace} ext4 / rw,nosuid,nodev,relatime 253:7\n"
            "{workspace} ext4 / rw,nosuid,nodev,relatime 253:7\n"
            "{workspace} ext4 / rw,nosuid,nodev,relatime 253:7\n"
        ),
        mount_table=("253:7 {workspace}\n253:7 {workspace}\n253:7 {workspace}\n"),
    )

    assert result.returncode == 0, result.stderr


def test_workspace_structural_check_allows_cleanup_below_headroom_floor(tmp_path: Path) -> None:
    structural = _run_workspace_quota_check(
        tmp_path / "structural-low-headroom",
        check_mode="--structural",
        available_blocks="0",
        available_inodes="0",
    )
    headroom = _run_workspace_quota_check(
        tmp_path / "headroom-low-headroom",
        available_blocks="0",
        available_inodes="0",
    )

    assert structural.returncode == 0, structural.stderr
    assert headroom.returncode != 0
    assert "available-byte floor" in headroom.stderr


@pytest.mark.parametrize(
    ("name", "overrides", "message"),
    (
        ("wrong-target", {"mount_target": "/var/lib/autocontribute"}, "exact dedicated mount"),
        ("invalid-device", {"mount_device": "not-a-device"}, "invalid device number"),
        ("subdirectory", {"filesystem_root": "/subdir"}, "whole filesystem"),
        ("wrong-filesystem", {"filesystem_type": "xfs"}, "must use ext4"),
        ("read-only", {"mount_options": "ro,nosuid,nodev"}, "not writable"),
        ("missing-nodev", {"mount_options": "rw,nosuid"}, "must use nodev"),
        ("missing-nosuid", {"mount_options": "rw,nodev"}, "must use nosuid"),
        ("bind", {"mount_options": "rw,nodev,nosuid,bind"}, "cannot be a bind"),
        (
            "layered-other-device",
            {
                "mount_records": (
                    "{workspace} ext4 / rw,nodev,nosuid 253:7\n"
                    "{workspace} ext4 / rw,nodev,nosuid 253:8\n"
                )
            },
            "layered over another device",
        ),
        (
            "hidden-device-layer",
            {"mount_table": ("253:7 {workspace}\n253:8 {workspace}\n")},
            "layered over another device",
        ),
        (
            "alias-second-target",
            {"mount_table": ("0:1 /\n253:7 {workspace}\n253:7 /mnt/same-device-via-uuid-alias\n")},
            "another host path",
        ),
        ("same-device", {"parent_device": "2049"}, "separate filesystem"),
        ("too-many-blocks", {"total_blocks": "5242881"}, "byte ceiling"),
        ("too-many-inodes", {"total_inodes": "524289"}, "inode ceiling"),
        (
            "too-few-available-blocks",
            {"available_blocks": "1048575"},
            "4 GiB available-byte floor",
        ),
        (
            "too-few-available-inodes",
            {"available_inodes": "65535"},
            "65,536 free-inode floor",
        ),
        (
            "impossible-available-blocks",
            {"available_blocks": "4194305"},
            "invalid availability",
        ),
        (
            "impossible-available-inodes",
            {"available_inodes": "262145"},
            "invalid availability",
        ),
        ("leading-zero-block-size", {"block_size": "04096"}, "invalid limits"),
        ("leading-zero-total-blocks", {"total_blocks": "04194304"}, "invalid limits"),
        ("leading-zero-total-inodes", {"total_inodes": "0262144"}, "invalid limits"),
        (
            "leading-zero-available-blocks",
            {"available_blocks": "03145728"},
            "invalid limits",
        ),
        (
            "leading-zero-available-inodes",
            {"available_inodes": "0196608"},
            "invalid limits",
        ),
        ("long-block-size", {"block_size": "123456789012"}, "invalid limits"),
        ("long-total-blocks", {"total_blocks": "123456789012"}, "invalid limits"),
        ("long-total-inodes", {"total_inodes": "12345678"}, "invalid limits"),
        (
            "long-available-blocks",
            {"available_blocks": "123456789012"},
            "invalid limits",
        ),
        (
            "long-available-inodes",
            {"available_inodes": "12345678"},
            "invalid limits",
        ),
        ("invalid-mode", {"check_mode": "--unknown"}, "invalid mode"),
        ("invalid-limits", {"block_size": "not-a-number"}, "invalid limits"),
    ),
)
def test_workspace_quota_check_rejects_unenforced_boundaries(
    tmp_path: Path,
    name: str,
    overrides: dict[str, str],
    message: str,
) -> None:
    result = _run_workspace_quota_check(tmp_path / name, **overrides)

    assert result.returncode != 0
    assert message in result.stderr


def test_workspace_quota_check_rejects_unsafe_mount_metadata(tmp_path: Path) -> None:
    cases: tuple[tuple[str, dict[str, int | str]], ...] = (
        ("owner", {"workspace_owner": os.getuid() + 1}),
        ("group", {"workspace_group": os.getgid() + 1}),
        ("mode", {"workspace_mode": "750"}),
    )
    for name, overrides in cases:
        result = _run_workspace_quota_check(
            tmp_path / name,
            **overrides,  # type: ignore[arg-type]
        )
        assert result.returncode != 0
        assert "unsafe ownership or permissions" in result.stderr


def test_storage_capacity_check_accepts_isolated_bounded_mounts(tmp_path: Path) -> None:
    result = _run_storage_capacity_check(tmp_path / "valid")

    assert result.returncode == 0, result.stderr
    assert "capacity are safe" in result.stdout


def test_storage_capacity_check_accepts_read_only_monitor_namespace(tmp_path: Path) -> None:
    result = _run_storage_capacity_check(
        tmp_path / "read-only",
        state_mount_records=(
            "{state} ext4 / rw,nosuid,nodev,noexec,relatime 253:8\n"
            "{state} ext4 / ro,nosuid,nodev,noexec,relatime 253:8\n"
        ),
        backup_mount_records=(
            "{backup} ext4 / rw,nosuid,nodev,noexec,relatime 253:9\n"
            "{backup} ext4 / ro,nosuid,nodev,noexec,relatime 253:9\n"
        ),
        access_mode="--read-only",
    )

    assert result.returncode == 0, result.stderr


def test_storage_capacity_check_accepts_worker_namespace(tmp_path: Path) -> None:
    result = _run_storage_capacity_check(
        tmp_path / "worker",
        backup_mount_records=(
            "{backup} ext4 / rw,nosuid,nodev,noexec,relatime 253:9\n"
            "{backup} ext4 / ro,nosuid,nodev,noexec,relatime 253:9\n"
        ),
        access_mode="--state-writable",
    )

    assert result.returncode == 0, result.stderr


def test_storage_capacity_check_requires_writable_state_for_worker(tmp_path: Path) -> None:
    result = _run_storage_capacity_check(
        tmp_path / "worker-read-only-state",
        state_mount_records=(
            "{state} ext4 / rw,nosuid,nodev,noexec,relatime 253:8\n"
            "{state} ext4 / ro,nosuid,nodev,noexec,relatime 253:8\n"
        ),
        backup_mount_records=(
            "{backup} ext4 / rw,nosuid,nodev,noexec,relatime 253:9\n"
            "{backup} ext4 / ro,nosuid,nodev,noexec,relatime 253:9\n"
        ),
        access_mode="--state-writable",
    )

    assert result.returncode != 0
    assert "state storage mount is not writable" in result.stderr


def test_storage_capacity_check_rejects_writable_worker_backup_namespace(
    tmp_path: Path,
) -> None:
    result = _run_storage_capacity_check(
        tmp_path / "worker-writable-backup",
        access_mode="--state-writable",
        backup_effectively_writable=True,
    )

    assert result.returncode != 0
    assert "backup storage is writable in a read-only service namespace" in result.stderr


def test_storage_capacity_check_rejects_worker_backup_without_read_only_layer(
    tmp_path: Path,
) -> None:
    result = _run_storage_capacity_check(
        tmp_path / "worker-missing-read-only-layer",
        access_mode="--state-writable",
    )

    assert result.returncode != 0
    assert "backup storage lacks a read-only service namespace layer" in result.stderr


def test_storage_capacity_check_rejects_read_only_mount_without_writable_backing(
    tmp_path: Path,
) -> None:
    result = _run_storage_capacity_check(
        tmp_path / "read-only-without-backing",
        state_mount_options="ro,nosuid,nodev,noexec,relatime",
        backup_mount_records=(
            "{backup} ext4 / rw,nosuid,nodev,noexec,relatime 253:9\n"
            "{backup} ext4 / ro,nosuid,nodev,noexec,relatime 253:9\n"
        ),
        access_mode="--read-only",
    )

    assert result.returncode != 0
    assert "state storage mount has no writable backing layer" in result.stderr


def test_storage_capacity_check_accepts_same_target_namespace_layers(tmp_path: Path) -> None:
    result = _run_storage_capacity_check(
        tmp_path / "same-target-layers",
        state_mount_records=(
            "{state} ext4 / rw,nosuid,nodev,noexec,relatime 253:8\n"
            "{state} ext4 / rw,nosuid,nodev,noexec,relatime 253:8\n"
        ),
        backup_mount_records=(
            "{backup} ext4 / rw,nosuid,nodev,noexec,relatime 253:9\n"
            "{backup} ext4 / rw,nosuid,nodev,noexec,relatime 253:9\n"
        ),
        mount_table=("253:8 {state}\n253:8 {state}\n253:9 {backup}\n253:9 {backup}\n"),
    )

    assert result.returncode == 0, result.stderr


def test_storage_capacity_check_accepts_exact_ceiling_and_headroom_boundaries(
    tmp_path: Path,
) -> None:
    result = _run_storage_capacity_check(
        tmp_path / "exact-boundaries",
        state_total_blocks="2097152",
        state_available_blocks="262144",
        state_total_inodes="262144",
        state_free_inodes="32768",
        backup_total_blocks="16777216",
        backup_available_blocks="5242880",
        backup_total_inodes="524288",
        backup_free_inodes="262144",
    )

    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    ("name", "overrides", "message"),
    (
        (
            "state-byte-ceiling",
            {"state_total_blocks": "2097153"},
            "state storage filesystem exceeds the byte ceiling",
        ),
        (
            "backup-byte-ceiling",
            {"backup_total_blocks": "16777217"},
            "backup storage filesystem exceeds the byte ceiling",
        ),
        (
            "state-inode-ceiling",
            {"state_total_inodes": "262145"},
            "state storage filesystem exceeds the inode ceiling",
        ),
        (
            "backup-inode-ceiling",
            {"backup_total_inodes": "524289"},
            "backup storage filesystem exceeds the inode ceiling",
        ),
        (
            "state-byte-headroom",
            {"state_available_blocks": "262143"},
            "state storage has less than the required byte headroom",
        ),
        (
            "backup-byte-headroom",
            {"backup_available_blocks": "5242879"},
            "backup storage has less than the required byte headroom",
        ),
        (
            "state-inode-headroom",
            {"state_free_inodes": "32767"},
            "state storage has less than the required inode headroom",
        ),
        (
            "backup-inode-headroom",
            {"backup_free_inodes": "262143"},
            "backup storage has less than the required inode headroom",
        ),
        (
            "overlong-statfs-field",
            {"state_total_blocks": "999999999999999999999999"},
            "state storage filesystem reported invalid limits",
        ),
        (
            "noncanonical-statfs-field",
            {"backup_available_blocks": "0006291456"},
            "backup storage filesystem reported invalid limits",
        ),
    ),
)
def test_storage_capacity_check_enforces_fixed_ceilings_and_headroom(
    tmp_path: Path,
    name: str,
    overrides: dict[str, str],
    message: str,
) -> None:
    result = _run_storage_capacity_check(tmp_path / name, **overrides)

    assert result.returncode != 0
    assert message in result.stderr


@pytest.mark.parametrize(
    ("name", "overrides", "message"),
    (
        (
            "shared-filesystem",
            {"backup_mount_device": "253:8"},
            "state storage device is mounted at another host path",
        ),
        (
            "state-parent-filesystem",
            {"state_stat_device": "2048"},
            "state storage is not isolated on a separate filesystem",
        ),
        (
            "backup-parent-filesystem",
            {"backup_stat_device": "2049"},
            "backup storage is not isolated on a separate filesystem",
        ),
        (
            "state-wrong-target",
            {"state_mount_target": "/var/lib/autocontribute"},
            "state storage is not an exact dedicated mount",
        ),
        (
            "state-second-target",
            {"mount_table": ("253:8 {state}\n253:8 /mnt/state-alias\n253:9 {backup}\n")},
            "state storage device is mounted at another host path",
        ),
        (
            "state-layered-other-device",
            {
                "state_mount_records": (
                    "{state} ext4 / rw,nosuid,nodev,noexec 253:8\n"
                    "{state} ext4 / rw,nosuid,nodev,noexec 253:10\n"
                )
            },
            "state storage mount is layered over another device",
        ),
        (
            "state-hidden-device-layer",
            {"mount_table": ("253:8 {state}\n253:10 {state}\n253:9 {backup}\n")},
            "state storage mount is layered over another device",
        ),
        (
            "unsafe-inner-layer",
            {
                "state_mount_records": (
                    "{state} ext4 / rw,nosuid,nodev,noexec 253:8\n"
                    "{state} ext4 / rw,nosuid,nodev 253:8\n"
                )
            },
            "state storage mount must use noexec",
        ),
        (
            "backup-bind",
            {"backup_mount_options": "rw,nosuid,nodev,noexec,bind"},
            "backup storage cannot be a bind mount",
        ),
        (
            "missing-noexec",
            {"state_mount_options": "rw,nosuid,nodev"},
            "state storage mount must use noexec",
        ),
        (
            "wrong-filesystem",
            {"backup_filesystem_type": "xfs"},
            "backup storage must use ext4",
        ),
        (
            "read-only-operation",
            {"state_mount_options": "ro,nosuid,nodev,noexec"},
            "state storage mount is not writable",
        ),
        (
            "ambiguous-access",
            {"state_mount_options": "rw,ro,nosuid,nodev,noexec"},
            "state storage mount has ambiguous access options",
        ),
    ),
)
def test_storage_capacity_check_rejects_unenforced_storage_boundaries(
    tmp_path: Path,
    name: str,
    overrides: dict[str, str],
    message: str,
) -> None:
    result = _run_storage_capacity_check(tmp_path / name, **overrides)

    assert result.returncode != 0
    assert message in result.stderr


def test_storage_capacity_check_rejects_unsafe_mount_metadata(tmp_path: Path) -> None:
    cases: tuple[tuple[str, dict[str, int | str]], ...] = (
        ("state-owner", {"state_owner": os.getuid() + 1}),
        ("backup-group", {"backup_group": os.getgid() + 1}),
        ("state-mode", {"state_mode": "750"}),
        ("backup-mode", {"backup_mode": "770"}),
    )
    for name, overrides in cases:
        result = _run_storage_capacity_check(
            tmp_path / name,
            **overrides,  # type: ignore[arg-type]
        )
        assert result.returncode != 0
        assert "unsafe ownership or permissions" in result.stderr


def test_rootless_docker_check_accepts_only_the_exact_option_and_clears_context(
    tmp_path: Path,
) -> None:
    result, observed_environment = _run_rootless_check(tmp_path / "valid")

    assert result.returncode == 0, result.stderr
    assert observed_environment is not None
    docker_host, runtime, docker_context = observed_environment.splitlines()
    assert docker_host == f"unix://{runtime}/docker.sock"
    assert docker_context == "unset"


def test_rootless_docker_unit_only_check_accepts_exact_effective_policy(
    tmp_path: Path,
) -> None:
    result, observed_environment = _run_rootless_check(
        tmp_path / "valid-unit-only",
        unit_only=True,
        docker_exit=99,
    )

    assert result.returncode == 0, result.stderr
    assert observed_environment is None


@pytest.mark.parametrize(
    ("name", "overrides", "message"),
    [
        ("not-loaded", {"unit_load_state": "not-found"}, "is not loaded"),
        ("reload-pending", {"unit_need_daemon_reload": "yes"}, "requires a daemon reload"),
        ("shadow-fragment", {"unit_fragment_path": "/tmp/docker.service"}, "unexpected fragment"),
        (
            "shadow-dropin",
            {"unit_dropin_paths": "/tmp/10-autocontribute-data-root.conf"},
            "unexpected effective drop-in",
        ),
        (
            "extra-reset-dropin",
            {"unit_dropin_paths": "/etc/expected.conf /tmp/99-reset.conf"},
            "unexpected effective drop-in",
        ),
        ("inactive", {"unit_active_state": "inactive"}, "is not running"),
        ("dead", {"unit_sub_state": "dead"}, "is not running"),
        ("fragment-owner", {"fragment_owner": 1000}, "fragment has unsafe ownership"),
        ("fragment-group", {"fragment_group": 1000}, "fragment has unsafe ownership"),
        ("fragment-mode", {"fragment_mode": "664"}, "fragment has unsafe ownership"),
        (
            "property-probe-failure",
            {"unit_failure_property": "FragmentPath"},
            "could not inspect the rootless Docker system unit",
        ),
        (
            "ambiguous-property",
            {"unit_load_state": "loaded\nmasked"},
            "has an ambiguous property",
        ),
    ],
)
def test_rootless_docker_check_rejects_unsafe_effective_system_unit(
    tmp_path: Path,
    name: str,
    overrides: dict[str, object],
    message: str,
) -> None:
    result, observed_environment = _run_rootless_check(
        tmp_path / name,
        **overrides,  # type: ignore[arg-type]
    )

    assert result.returncode != 0
    assert message in result.stderr
    assert observed_environment is None


def test_rootless_docker_check_rejects_missing_substring_and_duplicate_options(
    tmp_path: Path,
) -> None:
    outputs = {
        "missing": "name=seccomp\nname=cgroupns\n",
        "substring": "name=not-rootless\n",
        "embedded": "prefix=name=rootless\n",
        "duplicate": "name=rootless\nname=rootless\n",
    }
    for name, output in outputs.items():
        result, _ = _run_rootless_check(
            tmp_path / name,
            docker_output=output,
        )
        assert result.returncode != 0
        assert "exact rootless security option" in result.stderr
        assert output.strip() not in result.stderr


def test_rootless_docker_check_rejects_failed_probe(tmp_path: Path) -> None:
    result, _ = _run_rootless_check(
        tmp_path / "failed-probe",
        docker_output="name=rootless\n",
        docker_exit=28,
    )

    assert result.returncode != 0
    assert "could not verify the rootless Docker daemon" in result.stderr
    assert "name=rootless" not in result.stderr


def test_rootless_docker_check_rejects_unsafe_metadata_before_probe(tmp_path: Path) -> None:
    cases: tuple[tuple[str, dict[str, int | str]], ...] = (
        ("runtime-owner", {"runtime_owner": os.getuid() + 1}),
        ("runtime-group", {"runtime_group": os.getgid() + 1}),
        ("runtime-mode", {"runtime_mode": "750"}),
        ("socket-owner", {"socket_owner": os.getuid() + 1}),
        ("socket-group", {"socket_group": os.getgid() + 1}),
        ("socket-mode", {"socket_mode": "666"}),
    )
    for name, overrides in cases:
        result, observed_environment = _run_rootless_check(
            tmp_path / name,
            **overrides,  # type: ignore[arg-type]
        )
        assert result.returncode != 0
        assert "unsafe" in result.stderr or "not owned" in result.stderr
        assert observed_environment is None


def test_rootless_docker_check_rejects_exact_docker_group_before_probe(tmp_path: Path) -> None:
    result, observed_environment = _run_rootless_check(
        tmp_path / "docker-group",
        group_names="autocontribute docker docker-builders",
    )

    assert result.returncode != 0
    assert "must not belong to the docker group" in result.stderr
    assert observed_environment is None

    allowed, _ = _run_rootless_check(
        tmp_path / "similar-group",
        group_names="autocontribute docker-builders",
    )
    assert allowed.returncode == 0, allowed.stderr


def test_rootless_docker_check_rejects_accessible_host_socket_before_probe(tmp_path: Path) -> None:
    result, observed_environment = _run_rootless_check(
        tmp_path / "rootful-socket",
        accessible_rootful_socket=True,
    )

    assert result.returncode != 0
    assert "can access the host Docker socket" in result.stderr
    assert observed_environment is None


@pytest.mark.parametrize("legacy_socket_kind", ["socket", "symlink"])
def test_rootless_docker_check_rejects_legacy_user_runtime_socket_before_probe(
    tmp_path: Path,
    legacy_socket_kind: str,
) -> None:
    result, observed_environment = _run_rootless_check(
        tmp_path / legacy_socket_kind,
        legacy_socket_kind=legacy_socket_kind,
    )

    assert result.returncode != 0
    assert "legacy rootless Docker socket outside the managed runtime" in result.stderr
    assert observed_environment is None


def test_rootless_docker_supervisor_reload_accepts_exact_delegated_policy(
    tmp_path: Path,
) -> None:
    result, calls = _run_rootless_supervisor_reload(tmp_path / "valid-supervisor")

    assert result.returncode == 0, result.stderr
    assert "show-environment" in calls
    assert "show user@" in calls
    assert "--user show autocontribute-rootless-docker-daemon.service" in calls
    assert "--user reload autocontribute-rootless-docker-daemon.service" in calls
    assert calls.count("busctl --user --no-pager call") == 2
    assert calls.count("--property=MainPID") == 6
    assert calls.count("--property=Transient") == 4
    assert calls.count("--property=ActiveState") == 3


def test_rootless_docker_supervisor_bounds_manager_readiness_as_one_deadline(
    tmp_path: Path,
) -> None:
    result, calls = _run_rootless_supervisor_reload(
        tmp_path / "manager-not-ready",
        manager_ready=False,
        manager_readiness_timeout_seconds=3,
    )

    assert result.returncode != 0
    assert "user manager is unavailable" in result.stderr
    assert calls.count("--user show-environment") <= 2
    assert "show user@" not in calls


@pytest.mark.parametrize(
    ("name", "overrides", "message"),
    [
        ("home-owner", {"home_owner": 1000}, "service home has unsafe ownership"),
        ("home-mode", {"home_mode": "770"}, "service home has unsafe ownership"),
        (
            "runtime-owner",
            {"runtime_owner": os.getuid() + 1},
            "user-manager runtime has unsafe metadata",
        ),
        (
            "bus-group",
            {"bus_group": os.getgid() + 1},
            "user-manager runtime has unsafe metadata",
        ),
        (
            "manager-dropin",
            {"manager_dropin_path": "/tmp/99-reset.conf"},
            "user manager has an unexpected effective drop-in",
        ),
        (
            "manager-global-project-dropin",
            {
                "manager_extra_dropin": (
                    "/etc/systemd/system/user@.service.d/50-autocontribute.conf"
                )
            },
            "user manager has an unexpected effective drop-in",
        ),
        (
            "manager-runtime-dropin",
            {"manager_extra_dropin": "/run/systemd/system/user@501.service.d/99-reset.conf"},
            "user manager has an unexpected effective drop-in",
        ),
        (
            "manager-local-vendor-dropin",
            {
                "manager_extra_dropin": (
                    "/usr/local/lib/systemd/system/user@.service.d/99-reset.conf"
                )
            },
            "user manager has an unexpected effective drop-in",
        ),
        (
            "manager-dropin-missing",
            {"manager_dropin_count": 0},
            "user manager omitted its protected drop-in",
        ),
        (
            "manager-dropin-duplicate",
            {"manager_dropin_count": 2},
            "user manager omitted its protected drop-in",
        ),
        (
            "manager-dropin-mode",
            {"manager_dropin_mode": "664"},
            "user-manager drop-in has unsafe metadata",
        ),
        (
            "vendor-dropin-owner",
            {"vendor_dropin_owner": 1000},
            "user-manager drop-in has unsafe metadata",
        ),
        (
            "manager-delegate",
            {"manager_delegate": "no"},
            "user manager is not safely delegated",
        ),
        (
            "manager-transient",
            {"manager_transient": "yes"},
            "user manager is not safely delegated",
        ),
        (
            "manager-environment",
            {"manager_environment": "SYSTEMD_UNIT_PATH=/tmp"},
            "user manager is not safely delegated",
        ),
        (
            "manager-unit-path",
            {"manager_unit_path": "/tmp"},
            "user manager is not safely delegated",
        ),
        (
            "manager-fragment-shadow",
            {"manager_fragment_path": "/etc/systemd/system/user@.service"},
            "user manager is not safely delegated",
        ),
        (
            "manager-fragment-alias",
            {"manager_fragment_canonical": "/tmp/user@.service"},
            "user-manager fragment has unsafe metadata",
        ),
        (
            "manager-fragment-owner",
            {"manager_fragment_owner": 1000},
            "user-manager fragment has unsafe metadata",
        ),
        (
            "manager-main-pid",
            {"manager_main_pid": "0"},
            "user manager is not safely delegated",
        ),
        (
            "manager-probe",
            {"manager_failure_property": "ControlGroup"},
            "could not inspect Docker user-manager delegation",
        ),
        (
            "manager-bus-probe",
            {"bus_exit": 1},
            "could not bind the Docker user-manager bus",
        ),
        (
            "manager-bus-owner",
            {"bus_response": "u 9999"},
            "user-manager bus has an unexpected owner",
        ),
        (
            "manager-process-uid",
            {"process_uid": os.getuid() + 1},
            "process has an unexpected identity",
        ),
        (
            "manager-process-gid",
            {"process_gid": os.getgid() + 1},
            "process has an unexpected identity",
        ),
        (
            "manager-process-cgroup",
            {"process_cgroup": "0::/system.slice/user@501.service"},
            "process has an unexpected cgroup",
        ),
        (
            "manager-process-unit-path",
            {"process_unit_path": "/tmp"},
            "process has an unsafe unit path",
        ),
        (
            "manager-executable-owner",
            {"executable_owner": 1000},
            "executable has unsafe metadata",
        ),
        (
            "manager-executable-mode",
            {"executable_mode": "775"},
            "executable has unsafe metadata",
        ),
        (
            "controllers",
            {"controller_values": "cpu cpuset io memory\n"},
            "controller delegation is incomplete",
        ),
        (
            "duplicate-controller",
            {"controller_values": "cpu cpuset io memory pids pids\n"},
            "controller delegation is incomplete",
        ),
        (
            "user-fragment",
            {"user_fragment_path": "/tmp/docker.service"},
            "user unit has unexpected effective policy",
        ),
        (
            "user-dropin",
            {"user_dropin_paths": "/tmp/99-reset.conf"},
            "user unit has unexpected effective policy",
        ),
        (
            "user-fragment-owner",
            {"fragment_owner": 1000},
            "user unit fragment has unsafe metadata",
        ),
        (
            "user-fragment-mode",
            {"fragment_mode": "664"},
            "user unit fragment has unsafe metadata",
        ),
        (
            "user-transient",
            {"user_transient": "yes"},
            "user unit is not safely loaded",
        ),
        (
            "user-probe",
            {"user_failure_property": "FragmentPath"},
            "could not inspect the rootless Docker user unit",
        ),
    ],
)
def test_rootless_docker_supervisor_reload_rejects_unsafe_delegated_policy(
    tmp_path: Path,
    name: str,
    overrides: dict[str, object],
    message: str,
) -> None:
    result, _ = _run_rootless_supervisor_reload(
        tmp_path / name,
        **overrides,  # type: ignore[arg-type]
    )

    assert result.returncode != 0
    assert message in result.stderr


@pytest.mark.parametrize("legacy_socket_kind", ["socket", "symlink"])
def test_rootless_docker_supervisor_reload_rejects_legacy_user_runtime_socket(
    tmp_path: Path,
    legacy_socket_kind: str,
) -> None:
    result, _ = _run_rootless_supervisor_reload(
        tmp_path / f"legacy-{legacy_socket_kind}",
        legacy_socket_kind=legacy_socket_kind,
    )

    assert result.returncode != 0
    assert "legacy Docker socket outside the managed runtime" in result.stderr


def test_worker_and_doctor_have_matching_credential_override_surfaces() -> None:
    worker = _directives(SYSTEMD / "autocontribute-worker.service")
    doctor = _directives(SYSTEMD / "autocontribute-doctor.service")

    for key in ("LoadCredentialEncrypted", "Environment"):
        assert worker[("Service", key)] == doctor[("Service", key)]


def test_worker_doctor_and_complete_backup_share_one_exclusive_lock() -> None:
    for name in (
        "autocontribute-worker.service",
        "autocontribute-doctor.service",
        "autocontribute-backup.service",
    ):
        directives = _directives(SYSTEMD / name)
        command = _one(directives, "Service", "ExecStart")
        assert "/usr/bin/flock --exclusive" in command
        assert LOCK_PATH in command

    backup = (SYSTEMD / "libexec" / "autocontribute-backup").read_text(encoding="utf-8")
    assert '"$executable" state backup' in backup
    assert "--complete" in backup
    assert "--output" in backup
    assert "--overwrite" not in backup
    assert "date --utc +%Y%m%dT%H%M%S.%NZ" in backup
    assert 'chmod 0400 -- "$destination"' in backup
    backup_capacity_call = '"$storage_capacity_check" "$state_root" "$backup_directory" --writable'
    assert backup_capacity_call in backup
    assert backup.index(backup_capacity_call) < backup.index('"$executable" state backup')
    assert 'export AUTOCONTRIBUTE_REQUIRED_STORAGE_ROOT="$state_root"' in backup

    health = (SYSTEMD / "libexec" / "autocontribute-healthcheck").read_text(encoding="utf-8")
    health_capacity_call = '"$storage_capacity_check" "$state_root" "$backup_root" --read-only'
    assert health_capacity_call in health
    assert health.index(health_capacity_call) < health.index("check_stamp worker")

    backup_unit = (SYSTEMD / "autocontribute-backup.service").read_text(encoding="utf-8")
    assert "PrivateNetwork=yes" in backup_unit
    assert "LoadCredential" not in backup_unit
    assert "ReadWritePaths=/var/backups/autocontribute /var/lib/autocontribute" in backup_unit

    for name in (
        "autocontribute-worker.service",
        "autocontribute-doctor.service",
        "autocontribute-backup.service",
        "autocontribute-health.service",
    ):
        storage_unit = (SYSTEMD / name).read_text(encoding="utf-8")
        assert (
            "RequiresMountsFor=/var/lib/autocontribute/state /var/backups/autocontribute"
            in storage_unit
        )

    for name in ("autocontribute-health.service", "autocontribute-failure@.service"):
        signal_unit = (SYSTEMD / name).read_text(encoding="utf-8")
        assert "LoadCredential" not in signal_unit
        assert "EnvironmentFile=" not in signal_unit

    health_unit = _directives(SYSTEMD / "autocontribute-health.service")
    assert "/var/lib/autocontribute/docker" in health_unit[("Unit", "RequiresMountsFor")]
    assert (
        "/usr/local/libexec/autocontribute-docker-data-check "
        "--read-only-health /var/lib/autocontribute/docker"
        in health_unit[("Service", "ExecStartPre")]
    )
    assert "/var/lib/autocontribute/docker" in _one(health_unit, "Service", "ReadOnlyPaths")


def test_services_have_failure_signaling_and_core_hardening() -> None:
    for name in (
        "autocontribute-worker.service",
        "autocontribute-doctor.service",
        "autocontribute-backup.service",
        "autocontribute-health.service",
    ):
        unit = (SYSTEMD / name).read_text(encoding="utf-8")
        assert "OnFailure=autocontribute-failure@%n.service" in unit
        assert "NoNewPrivileges=yes" in unit
        assert re.search(r"(?m)^CapabilityBoundingSet=$", unit)
        assert "ProtectSystem=strict" in unit
        assert "PrivateDevices=yes" in unit
        assert "RestrictSUIDSGID=yes" in unit
        assert "UMask=0077" in unit

    health_timer = _directives(SYSTEMD / "autocontribute-health.timer")
    assert _one(health_timer, "Timer", "OnUnitInactiveSec") == "15m"
    failure = (SYSTEMD / "libexec" / "autocontribute-record-failure").read_text(encoding="utf-8")
    assert "last-failure" in failure
    failure_unit = _directives(SYSTEMD / "autocontribute-failure@.service")
    assert _one(failure_unit, "Service", "SyslogLevel") == "err"


def test_no_unit_embeds_secret_values_or_enables_automatic_publication() -> None:
    unit_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(SYSTEMD.rglob("*.*"))
        if path.suffix in {".service", ".timer"}
    )
    embedded_secret = r"(?m)^Environment=(?:OPENAI_API_KEY|AUTOCONTRIBUTE_GITHUB_TOKEN)="
    assert not re.search(embedded_secret, unit_text)
    assert "AUTOCONTRIBUTE_ALLOW_AUTO_PUBLISH=1" not in unit_text
    assert "EnvironmentFile=" not in unit_text


def test_tmpfiles_keeps_state_private_and_docs_cover_safe_recovery() -> None:
    tmpfiles = (SYSTEMD / "autocontribute.tmpfiles.conf").read_text(encoding="utf-8")
    assert "d /var/lib/autocontribute 0750 root autocontribute -" in tmpfiles
    assert (
        "f /var/lib/autocontribute/operation.lock 0600 autocontribute autocontribute -" in tmpfiles
    )
    assert "d /var/lib/autocontribute/state 0700 autocontribute autocontribute -" in tmpfiles
    assert (
        "d /var/lib/autocontribute/state/workspaces 0700 autocontribute autocontribute -"
        in tmpfiles
    )
    assert "d /var/backups/autocontribute 0700 autocontribute autocontribute -" in tmpfiles
    assert "d /var/lib/autocontribute/docker 0710 autocontribute autocontribute -" in tmpfiles

    guide = (ROOT / "docs" / "systemd-deployment.md").read_text(encoding="utf-8")
    assert "state restore --complete" in guide
    assert "restore into an absent" in guide
    assert "Never restart an old binary against state opened by a" in guide
    assert "off-host" in guide
    assert "AUTOCONTRIBUTE_ALLOW_AUTO_PUBLISH=1" in guide
    assert "sudo useradd --system" in guide
    assert "--home-dir /var/lib/autocontribute" in guide
    assert "--shell /usr/sbin/nologin autocontribute" in guide
    assert "--user-group" in guide
    assert "21,474,836,480 bytes" in guide
    assert "524,288 inodes" in guide
    assert "34,359,738,368 bytes" in guide
    assert "1,048,576 fixed inodes" in guide
    assert "1,073,741,824 bytes" in guide
    assert "rw,nodev,nosuid" in guide
    assert "state filesystem is capped at 8 GiB and 262,144 inodes" in guide
    assert "backup filesystem is capped" in guide
    assert "64 GiB and 524,288 inodes" in guide
    assert "at least 20 GiB and 262,144 inodes available" in guide
    assert "at most 32 GiB" in guide
    assert "at least 1 GiB" in guide
    assert "16,384 inodes" in guide
    assert "never a timer action" in guide
    assert "SHA-256 digest" in guide
    assert "provider-specific replication/receipt protocol" in guide
    assert "AUTOCONTRIBUTE_REQUIRED_WORKSPACE_ROOT" not in guide
    assert "AUTOCONTRIBUTE_REQUIRED_STORAGE_ROOT" not in guide


def test_docs_apply_sensitive_dropins_to_both_execution_services() -> None:
    guide = (ROOT / "docs" / "systemd-deployment.md").read_text(encoding="utf-8")
    normalized_guide = " ".join(guide.split())
    provider_worker = (
        "/etc/systemd/system/autocontribute-worker.service.d/40-provider-credentials.conf"
    )
    provider_doctor = (
        "/etc/systemd/system/autocontribute-doctor.service.d/40-provider-credentials.conf"
    )
    auto_worker = "/etc/systemd/system/autocontribute-worker.service.d/50-auto-publish.conf"
    auto_doctor = "/etc/systemd/system/autocontribute-doctor.service.d/50-auto-publish.conf"

    assert provider_worker in guide
    assert provider_doctor in guide
    assert auto_worker in guide
    assert auto_doctor in guide
    assert "Put this identical content in each file" in guide
    assert "The doctor makes no repository or GitHub writes and cannot publish" in normalized_guide
    assert "opening the store can migrate or repair local durable" in normalized_guide
    assert "Environment=AUTOCONTRIBUTE_ALLOW_AUTO_PUBLISH=1" in guide
    assert guide.count("sudo cmp --silent --") == 2
    assert guide.count("sudo systemctl daemon-reload") >= 2


def test_docs_preserve_quiescence_query_failures_and_privileged_bus_probe() -> None:
    guide = (ROOT / "docs" / "systemd-deployment.md").read_text(encoding="utf-8")

    assert 'test -z "$(sudo systemctl list-units' not in guide
    assert guide.count('active_units="$(sudo systemctl list-units') == 2
    assert guide.count('test -z "$active_units"') == 2
    assert guide.count("unset active_units") == 2
    assert 'if sudo test -S "/run/user/${autocontribute_uid}/bus"; then' in guide


@pytest.mark.parametrize("data_mode", ["700", "710"])
def test_docker_data_check_accepts_bounded_dedicated_ext4_mount_and_exact_daemon_root(
    tmp_path: Path,
    data_mode: str,
) -> None:
    result, observed_environment = _run_docker_data_check(
        tmp_path / f"valid-{data_mode}",
        data_mode=data_mode,
    )

    assert result.returncode == 0, result.stderr
    assert observed_environment is not None
    docker_host, docker_context = observed_environment.splitlines()
    assert docker_host == "unix:///run/autocontribute/docker.sock"
    assert docker_context == "unset"


def test_docker_data_mount_only_check_does_not_contact_the_daemon(tmp_path: Path) -> None:
    result, observed_environment = _run_docker_data_check(
        tmp_path / "mount-only",
        check_mode="--mount-only",
        docker_exit=99,
    )

    assert result.returncode == 0, result.stderr
    assert observed_environment is None


def test_docker_data_read_only_health_check_accepts_namespace_layer_without_daemon(
    tmp_path: Path,
) -> None:
    result, observed_environment = _run_docker_data_check(
        tmp_path / "read-only-health",
        check_mode="--read-only-health",
        docker_exit=99,
        mount_rows=(
            "{data_root} ext4 / rw,nosuid,nodev,relatime 253:8\n"
            "{data_root} ext4 / ro,nosuid,nodev,relatime 253:8\n"
        ),
        mount_table="253:8 {data_root}\n253:8 {data_root}\n",
    )

    assert result.returncode == 0, result.stderr
    assert observed_environment is None


@pytest.mark.parametrize(
    ("name", "mount_rows", "message"),
    (
        (
            "only-read-only",
            "{data_root} ext4 / ro,nosuid,nodev,relatime 253:8\n",
            "did not prove writable and read-only layers",
        ),
        (
            "only-writable",
            "{data_root} ext4 / rw,nosuid,nodev,relatime 253:8\n",
            "did not prove writable and read-only layers",
        ),
        (
            "read-only-layer-missing-nodev",
            (
                "{data_root} ext4 / rw,nosuid,nodev,relatime 253:8\n"
                "{data_root} ext4 / ro,nosuid,relatime 253:8\n"
            ),
            "must use nodev",
        ),
        (
            "read-only-layer-on-another-device",
            (
                "{data_root} ext4 / rw,nosuid,nodev,relatime 253:8\n"
                "{data_root} ext4 / ro,nosuid,nodev,relatime 253:9\n"
            ),
            "another device layered",
        ),
        (
            "ambiguous-read-only-layer",
            (
                "{data_root} ext4 / rw,nosuid,nodev,relatime 253:8\n"
                "{data_root} ext4 / rw,ro,nosuid,nodev,relatime 253:8\n"
            ),
            "ambiguous access options",
        ),
    ),
)
def test_docker_data_read_only_health_check_rejects_unproved_namespace_layers(
    tmp_path: Path,
    name: str,
    mount_rows: str,
    message: str,
) -> None:
    result, observed_environment = _run_docker_data_check(
        tmp_path / name,
        check_mode="--read-only-health",
        docker_exit=99,
        mount_rows=mount_rows,
    )

    assert result.returncode != 0
    assert message in result.stderr
    assert observed_environment is None


@pytest.mark.parametrize(
    ("name", "effective_mount_row", "message"),
    (
        (
            "writable",
            "{data_root} ext4 / rw,nosuid,nodev,relatime 253:8\n",
            "effective service view is not read-only",
        ),
        (
            "other-device",
            "{data_root} ext4 / ro,nosuid,nodev,relatime 253:9\n",
            "does not match the safe mount",
        ),
        (
            "missing-nodev",
            "{data_root} ext4 / ro,nosuid,relatime 253:8\n",
            "effective service view must use nodev",
        ),
        (
            "ambiguous",
            (
                "{data_root} ext4 / ro,nosuid,nodev,relatime 253:8\n"
                "{data_root} ext4 / ro,nosuid,nodev,relatime 253:8\n"
            ),
            "effective service view is ambiguous",
        ),
    ),
)
def test_docker_data_read_only_service_check_rejects_unsafe_effective_layer(
    tmp_path: Path,
    name: str,
    effective_mount_row: str,
    message: str,
) -> None:
    result, observed_environment = _run_docker_data_check(
        tmp_path / f"{name}-effective-layer",
        check_mode="--read-only-health",
        docker_exit=99,
        mount_rows=(
            "{data_root} ext4 / ro,nosuid,nodev,relatime 253:8\n"
            "{data_root} ext4 / rw,nosuid,nodev,relatime 253:8\n"
        ),
        effective_mount_row=effective_mount_row,
    )

    assert result.returncode != 0
    assert message in result.stderr
    assert observed_environment is None


def test_docker_data_check_accepts_same_target_namespace_layers(tmp_path: Path) -> None:
    result, _ = _run_docker_data_check(
        tmp_path / "same-target-layers",
        mount_rows=(
            "{data_root} ext4 / rw,nosuid,nodev,relatime 253:8\n"
            "{data_root} ext4 / rw,nosuid,nodev,relatime 253:8\n"
            "{data_root} ext4 / ro,nosuid,nodev,relatime 253:8\n"
        ),
        mount_table="253:8 {data_root}\n253:8 {data_root}\n253:8 {data_root}\n",
    )

    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    ("name", "overrides", "message"),
    (
        ("wrong-target", {"mount_target": "/var/lib/autocontribute"}, "exact dedicated mount"),
        ("invalid-device", {"mount_device": "not-a-device"}, "invalid device number"),
        ("subdirectory", {"filesystem_root": "/subdir"}, "whole filesystem"),
        ("wrong-filesystem", {"filesystem_type": "xfs"}, "must use ext4"),
        (
            "read-only",
            {"mount_options": "ro,nosuid,nodev"},
            "did not prove writable and read-only layers",
        ),
        ("missing-nodev", {"mount_options": "rw,nosuid"}, "must use nodev"),
        ("missing-nosuid", {"mount_options": "rw,nodev"}, "must use nosuid"),
        ("bind", {"mount_options": "rw,nodev,nosuid,bind"}, "cannot be a bind"),
        (
            "alias-second-target",
            {
                "mount_table": (
                    "0:1 /\n253:8 {data_root}\n253:8 /mnt/same-device-via-source-alias\n"
                )
            },
            "another host path",
        ),
        (
            "different-layered-device",
            {
                "mount_rows": (
                    "{data_root} ext4 / rw,nodev,nosuid 253:8\n"
                    "{data_root} ext4 / rw,nodev,nosuid 253:9\n"
                ),
                "mount_table": "253:8 {data_root}\n253:9 {data_root}\n",
            },
            "another device layered",
        ),
        ("same-device", {"parent_device": "2050"}, "separate filesystem"),
        ("too-many-blocks", {"total_blocks": "8388609"}, "byte ceiling"),
        ("too-many-inodes", {"total_inodes": "1048577"}, "inode ceiling"),
        ("insufficient-free-bytes", {"available_blocks": "262143"}, "free byte headroom"),
        ("insufficient-free-inodes", {"available_inodes": "16383"}, "free inode headroom"),
        ("available-blocks-exceed-total", {"available_blocks": "6291457"}, "invalid limits"),
        ("invalid-limits", {"block_size": "not-a-number"}, "invalid limits"),
        (
            "overflowing-limits",
            {"total_blocks": "999999999999999999999999"},
            "invalid limits",
        ),
    ),
)
def test_docker_data_check_rejects_unenforced_mount_boundaries(
    tmp_path: Path,
    name: str,
    overrides: dict[str, str],
    message: str,
) -> None:
    result, observed_environment = _run_docker_data_check(tmp_path / name, **overrides)

    assert result.returncode != 0
    assert message in result.stderr
    assert observed_environment is None


def test_docker_data_check_rejects_unsafe_mount_metadata_before_daemon_probe(
    tmp_path: Path,
) -> None:
    cases: tuple[tuple[str, dict[str, int | str]], ...] = (
        ("owner", {"data_owner": os.getuid() + 1}),
        ("group", {"data_group": os.getgid() + 1}),
        ("group-write", {"data_mode": "770"}),
        ("other-access", {"data_mode": "711"}),
    )
    for name, overrides in cases:
        result, observed_environment = _run_docker_data_check(
            tmp_path / name,
            **overrides,  # type: ignore[arg-type]
        )
        assert result.returncode != 0
        assert "unsafe ownership or permissions" in result.stderr
        assert observed_environment is None


def test_docker_data_check_rejects_daemon_root_alias_or_probe_failure(tmp_path: Path) -> None:
    alias_result, _ = _run_docker_data_check(
        tmp_path / "daemon-alias",
        docker_root_output='"/var/lib/autocontribute/../autocontribute/docker"\n',
    )
    failed_result, _ = _run_docker_data_check(
        tmp_path / "failed-daemon-probe",
        docker_root_output='"/var/lib/autocontribute/docker"\n',
        docker_exit=28,
    )

    assert alias_result.returncode != 0
    assert "exact bounded data-root mount" in alias_result.stderr
    assert failed_result.returncode != 0
    assert "could not verify the Docker daemon data root" in failed_result.stderr


def test_rootless_docker_system_service_supervises_attested_user_daemon() -> None:
    system_unit = _directives(SYSTEMD / "autocontribute-rootless-docker.service")
    system_preflight = system_unit[("Service", "ExecStartPre")]
    user_unit = _directives(SYSTEMD / "user" / "autocontribute-rootless-docker-daemon.service")
    user_preflight = user_unit[("Service", "ExecStartPre")]
    release_check = (
        "/opt/autocontribute/current/.venv/bin/autocontribute deployment verify-systemd-assets"
    )
    unit_check = "/usr/local/libexec/autocontribute-rootless-docker-check --unit-only"
    mount_check = (
        "/usr/local/libexec/autocontribute-docker-data-check "
        "--mount-only /var/lib/autocontribute/docker"
    )

    assert release_check in system_preflight
    assert unit_check in system_preflight
    assert mount_check not in system_preflight
    assert system_preflight.index(release_check) < system_preflight.index(unit_check)
    assert _one(system_unit, "Service", "User") == "autocontribute"
    assert _one(system_unit, "Service", "Type") == "notify"
    assert _one(system_unit, "Service", "ExecStart") == (
        "/usr/local/libexec/autocontribute-rootless-docker"
    )
    assert _one(system_unit, "Service", "ExecReload") == (
        "/usr/local/libexec/autocontribute-rootless-docker --reload"
    )
    assert _one(system_unit, "Service", "RuntimeDirectory") == "autocontribute"
    assert _one(system_unit, "Service", "RuntimeDirectoryMode") == "0700"
    assert _one(system_unit, "Service", "RuntimeDirectoryPreserve") == "restart"
    assert _one(system_unit, "Service", "TimeoutStartSec") == "15m"
    assert _one(system_unit, "Service", "TimeoutStopSec") == "3m"
    assert _one(system_unit, "Service", "PrivateNetwork") == "yes"
    assert _one(system_unit, "Service", "RestrictAddressFamilies") == "AF_UNIX"
    assert ("Service", "Delegate") not in system_unit
    assert _one(system_unit, "Install", "WantedBy") == "multi-user.target"

    assert release_check in user_preflight
    assert mount_check in user_preflight
    assert user_preflight.index(release_check) < user_preflight.index(mount_check)
    assert _one(user_unit, "Service", "Type") == "notify"
    assert _one(user_unit, "Service", "TimeoutStartSec") == "2m"
    assert _one(user_unit, "Service", "TimeoutStopSec") == "90s"
    assert "XDG_RUNTIME_DIR=/run/autocontribute" in user_unit[("Service", "Environment")]
    assert (
        "DOCKER_HOST=unix:///run/autocontribute/docker.sock"
        in user_unit[("Service", "Environment")]
    )
    assert _one(user_unit, "Service", "ExecStart") == (
        "/usr/local/libexec/autocontribute-rootless-dockerd"
    )
    assert _one(user_unit, "Service", "Delegate") == "yes"
    assert any("/usr/sbin:/sbin" in value for value in user_unit[("Service", "Environment")])
    assert ("Install", "WantedBy") not in user_unit
    user_unit_lines = (
        (SYSTEMD / "user" / "autocontribute-rootless-docker-daemon.service")
        .read_text(encoding="utf-8")
        .splitlines()
    )
    namespace_directive_prefixes = (
        "PrivateTmp=",
        "PrivateDevices=",
        "Protect",
        "ReadOnlyPaths=",
        "ReadWritePaths=",
        "InaccessiblePaths=",
        "ExecPaths=",
        "NoExecPaths=",
        "BindPaths=",
        "BindReadOnlyPaths=",
        "TemporaryFileSystem=",
        "RootDirectory=",
        "RootImage=",
    )
    assert not any(line.startswith(namespace_directive_prefixes) for line in user_unit_lines)


def test_rootless_docker_user_manager_policy_is_fixed_and_delegated() -> None:
    policy = _directives(SYSTEMD / "autocontribute-user-manager.conf")

    assert _one(policy, "Service", "Delegate") == "cpu cpuset io memory pids"
    assert _one(policy, "Service", "Environment") == (
        "SYSTEMD_UNIT_PATH=/etc/systemd/user:/run/systemd/user:"
        "/usr/local/lib/systemd/user:/usr/lib/systemd/user"
    )


def test_rootless_docker_supervisor_monitors_only_the_attested_user_unit() -> None:
    supervisor = (SYSTEMD / "libexec" / "autocontribute-rootless-docker").read_text(
        encoding="utf-8"
    )

    assert "readonly daemon_account=autocontribute" in supervisor
    assert "readonly daemon_unit=autocontribute-rootless-docker-daemon.service" in supervisor
    assert (
        "readonly expected_fragment=/etc/systemd/user/"
        "autocontribute-rootless-docker-daemon.service" in supervisor
    )
    assert (
        'readonly expected_manager_dropin="/etc/systemd/system/'
        'user@${service_uid}.service.d/50-autocontribute.conf"' in supervisor
    )
    assert "readonly expected_manager_fragment=/usr/lib/systemd/system/user@.service" in supervisor
    assert (
        "readonly expected_vendor_dropin_directory=/usr/lib/systemd/system/"
        "user@.service.d" in supervisor
    )
    assert "/etc/systemd/system/user@.service.d/50-autocontribute.conf" not in supervisor
    assert "manager_unit_properties" in supervisor
    assert "user_unit_properties" in supervisor
    assert "manager_property UnitPath" in supervisor
    assert "GetConnectionUnixProcessID" in supervisor
    assert '"/proc/$main_pid_before/status"' in supervisor
    assert '"/proc/$main_pid_before/cgroup"' in supervisor
    assert '"/proc/$main_pid_before/environ"' in supervisor
    assert '"/proc/$main_pid_before/exe"' in supervisor
    assert "cpu cpuset io memory pids" in supervisor
    assert 'systemctl --user show "$daemon_unit"' in supervisor
    assert 'systemctl --user start "$daemon_unit"' in supervisor
    assert 'systemctl --user stop "$daemon_unit"' in supervisor
    assert "readonly manager_readiness_timeout_seconds=120" in supervisor
    assert "readonly daemon_stop_client_timeout_seconds=120" in supervisor
    assert "readonly daemon_start_client_timeout_seconds=150" in supervisor
    assert (
        "manager_readiness_deadline=$((SECONDS + manager_readiness_timeout_seconds))" in supervisor
    )
    assert "for _attempt in {1..120}" not in supervisor
    assert '"${daemon_stop_client_timeout_seconds}s"' in supervisor
    assert '"${daemon_start_client_timeout_seconds}s"' in supervisor
    assert "systemd-notify --ready" in supervisor
    assert "while sleep 30" in supervisor
    assert "dockerd-rootless.sh" not in supervisor


def test_rootless_dockerd_launcher_keeps_socket_outside_user_runtime() -> None:
    launcher = (SYSTEMD / "libexec" / "autocontribute-rootless-dockerd").read_text(encoding="utf-8")

    assert "readonly daemon=/usr/bin/dockerd-rootless.sh" in launcher
    assert "readonly runtime_directory=/run/autocontribute" in launcher
    assert 'readonly docker_socket="$runtime_directory/docker.sock"' in launcher
    assert 'readonly docker_host="unix://$docker_socket"' in launcher
    assert 'readonly user_runtime_directory="/run/user/${service_uid}"' in launcher
    assert 'readonly user_bus="$user_runtime_directory/bus"' in launcher
    assert 'daemon_resolved="$(readlink --canonicalize-existing -- "$daemon")"' in launcher
    assert 'config_resolved="$(readlink --canonicalize-existing -- "$daemon_config")"' in launcher
    assert '"$config_owner" != 0' in launcher
    assert '"$config_group" != "$service_gid"' in launcher
    assert '"$config_mode" != 640' in launcher
    assert '"$config_directory_mode" != 750' in launcher
    assert '"$runtime_mode" != 700' in launcher
    assert '"$user_runtime_mode" != 700' in launcher
    assert '"$bus_owner" != "$service_uid"' in launcher
    assert '"$bus_group" != "$service_gid"' in launcher
    assert '[[ -e "$docker_socket" || -L "$docker_socket" ]]' in launcher
    assert 'export DBUS_SESSION_BUS_ADDRESS="unix:path=$user_bus"' in launcher
    assert 'export XDG_RUNTIME_DIR="$runtime_directory"' in launcher
    assert 'export DOCKER_HOST="$docker_host"' in launcher
    assert 'exec "$daemon"' in launcher
    assert '--config-file="$daemon_config"' in launcher
    assert '--data-root="$data_root"' in launcher
    assert "--exec-opt=native.cgroupdriver=systemd" in launcher
    assert '--host="$docker_host"' in launcher
    assert "/run/user/${service_uid}/docker.sock" not in launcher
    assert "dockerd-rootless-setuptool.sh" not in launcher
