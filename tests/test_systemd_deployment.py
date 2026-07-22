from __future__ import annotations

import os
import re
import socket
import stat
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).parents[1]
SYSTEMD = ROOT / "deploy" / "systemd"
LOCK_PATH = "/var/lib/autocontribute/operation.lock"
ROOTLESS_CHECK = SYSTEMD / "libexec" / "autocontribute-rootless-docker-check"


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

    uid = os.getuid()
    gid = os.getgid()
    values = {
        "TEST_RUNTIME_OWNER": str(uid if runtime_owner is None else runtime_owner),
        "TEST_RUNTIME_GROUP": str(gid if runtime_group is None else runtime_group),
        "TEST_RUNTIME_MODE": runtime_mode,
        "TEST_SOCKET_OWNER": str(uid if socket_owner is None else socket_owner),
        "TEST_SOCKET_GROUP": str(gid if socket_group is None else socket_group),
        "TEST_SOCKET_MODE": socket_mode,
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
else
  exit 92
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
  *) exit 93 ;;
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
        "TEST_GROUP_NAMES": group_names,
        "TEST_PROBE_ENVIRONMENT": os.fspath(probe_environment),
        "TEST_RUNTIME_DIRECTORY": os.fspath(runtime),
        "TEST_SERVICE_GID": str(gid),
    }
    rootful_listener: socket.socket | None = None
    if accessible_rootful_socket:
        rootful_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        rootful_listener.bind(os.fspath(rootful_socket))
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(os.fspath(docker_socket))
        try:
            docker_socket.chmod(0o660)
            result = subprocess.run(
                [
                    "bash",
                    os.fspath(ROOTLESS_CHECK),
                    os.fspath(runtime),
                    os.fspath(docker_socket),
                    os.fspath(rootful_socket),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )
        finally:
            if rootful_listener is not None:
                rootful_listener.close()
    observed_environment = (
        probe_environment.read_text(encoding="utf-8") if probe_environment.exists() else None
    )
    short_alias.unlink()
    return result, observed_environment


def test_systemd_bundle_contains_expected_units_and_executable_helpers() -> None:
    expected = {
        "autocontribute-backup.service",
        "autocontribute-backup.timer",
        "autocontribute-doctor.service",
        "autocontribute-failure@.service",
        "autocontribute-health.service",
        "autocontribute-health.timer",
        "autocontribute-worker.service",
        "autocontribute-worker.timer",
        "autocontribute.journald.conf.example",
        "autocontribute.tmpfiles.conf",
    }
    assert {path.name for path in SYSTEMD.iterdir() if path.is_file()} == expected

    helpers = sorted((SYSTEMD / "libexec").iterdir())
    assert {path.name for path in helpers} == {
        "autocontribute-backup",
        "autocontribute-healthcheck",
        "autocontribute-record-failure",
        "autocontribute-rootless-docker-check",
        "autocontribute-worker",
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

    helper = (SYSTEMD / "libexec" / "autocontribute-worker").read_text(encoding="utf-8")
    assert 'run --scheduled --config "$config"' in helper
    assert 'runtime_directory="/run/user/$UID"' in helper
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
    assert helper.index(check_call) < helper.index('credential_value="$(<"$credential_path")"')
    assert "DOCKER_*" in helper
    assert "credential_value" in helper
    assert "set -euo pipefail" in helper


def test_rootless_docker_check_accepts_only_the_exact_option_and_clears_context(
    tmp_path: Path,
) -> None:
    result, observed_environment = _run_rootless_check(tmp_path / "valid")

    assert result.returncode == 0, result.stderr
    assert observed_environment is not None
    docker_host, runtime, docker_context = observed_environment.splitlines()
    assert docker_host == f"unix://{runtime}/docker.sock"
    assert docker_context == "unset"


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

    backup_unit = (SYSTEMD / "autocontribute-backup.service").read_text(encoding="utf-8")
    assert "PrivateNetwork=yes" in backup_unit
    assert "LoadCredential" not in backup_unit
    assert "ReadWritePaths=/var/backups/autocontribute /var/lib/autocontribute" in backup_unit

    for name in ("autocontribute-health.service", "autocontribute-failure@.service"):
        signal_unit = (SYSTEMD / name).read_text(encoding="utf-8")
        assert "LoadCredential" not in signal_unit
        assert "EnvironmentFile=" not in signal_unit


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
        for path in sorted(SYSTEMD.glob("*.*"))
        if path.suffix in {".service", ".timer"}
    )
    embedded_secret = r"(?m)^Environment=(?:OPENAI_API_KEY|AUTOCONTRIBUTE_GITHUB_TOKEN)="
    assert not re.search(embedded_secret, unit_text)
    assert "AUTOCONTRIBUTE_ALLOW_AUTO_PUBLISH=1" not in unit_text
    assert "EnvironmentFile=" not in unit_text


def test_tmpfiles_keeps_state_private_and_docs_cover_safe_recovery() -> None:
    tmpfiles = (SYSTEMD / "autocontribute.tmpfiles.conf").read_text(encoding="utf-8")
    assert "d /var/lib/autocontribute/state 0700 autocontribute autocontribute -" in tmpfiles
    assert "d /var/backups/autocontribute 0700 autocontribute autocontribute -" in tmpfiles

    guide = (ROOT / "docs" / "systemd-deployment.md").read_text(encoding="utf-8")
    assert "state restore --complete" in guide
    assert "restore into an absent" in guide
    assert "Never restart an old binary against state opened by a" in guide
    assert "off-host" in guide
    assert "AUTOCONTRIBUTE_ALLOW_AUTO_PUBLISH=1" in guide
    assert "useradd --system --create-home" in guide
    assert "--user-group" in guide


def test_docs_apply_sensitive_dropins_to_both_execution_services() -> None:
    guide = (ROOT / "docs" / "systemd-deployment.md").read_text(encoding="utf-8")
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
    assert "The doctor is non-mutating and" in guide
    assert "Environment=AUTOCONTRIBUTE_ALLOW_AUTO_PUBLISH=1" in guide
    assert guide.count("sudo cmp --silent --") == 2
    assert guide.count("sudo systemctl daemon-reload") >= 2
