from __future__ import annotations

import os
import re
import stat
import subprocess
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).parents[1]
SYSTEMD = ROOT / "deploy" / "systemd"
LOCK_PATH = "/var/lib/autocontribute/operation.lock"


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
    assert '! -S "$docker_socket"' in helper
    assert 'docker_socket_owner="$(stat --format=%u -- "$docker_socket")"' in helper
    assert "credential_value" in helper
    assert "set -euo pipefail" in helper


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
