from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "tests" / "acceptance" / "ubuntu_24_04_deployment_recovery.sh"


def test_acceptance_script_is_executable_and_parses() -> None:
    assert stat.S_IMODE(SCRIPT.stat().st_mode) == 0o755

    result = subprocess.run(
        ["bash", "-n", os.fspath(SCRIPT)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def test_acceptance_script_exercises_fail_closed_install_and_recovery() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert '[[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "24.04" ]]' in script
    assert '[[ "$systemd_major" == "255" ]]' in script
    assert 'require_absent "$application_root"' in script
    assert 'require_absent "$service_home"' in script
    assert 'require_absent "/etc/systemd/system/user@${service_uid}.service.d"' in script
    assert 'sudo mountpoint --quiet -- "$backup_root"' in script
    assert 'sudo mountpoint --quiet -- "$state_root"' in script
    assert 'elif [[ "$backup_mount_status" -eq 32 ]]; then' in script
    assert 'elif [[ "$state_mount_status" -eq 32 ]]; then' in script
    assert "Acceptance backup mount existed without recorded ownership" in script
    assert "Could not inspect the acceptance backup mountpoint" in script
    assert "Refusing to unmount unexpected backup storage" in script
    assert "Refusing to detach an unexpected state loop device" in script
    assert "Refusing to remove a mounted acceptance backup root" in script
    assert "Refusing to remove an unverified acceptance backup root" in script
    assert "Refusing to remove a service home containing mounted acceptance state" in script
    assert "Refusing to remove storage still used by acceptance resources" in script
    assert 'git -C "$source_root" archive --format=tar HEAD' in script
    assert "--source-root ABSOLUTE_EXTRACTED_SDIST_ROOT" in script
    assert '[[ -f "$source_root/PKG-INFO"' in script
    assert "release build identity does not match its project and lock material" in script
    assert "release source uses the reserved acceptance cleanup marker" in script
    assert 'tar --create --file=- --directory "$source_root" .' in script
    assert script.count("deployment verify-systemd-assets") >= 2
    assert "installed asset verification accepted a drifted helper mode" in script
    assert "sudo systemctl start autocontribute-backup.service" in script
    assert 'timer_state="$(sudo systemctl is-enabled "$timer"' in script
    assert "/usr/bin/env -i" in script
    assert "state restore --complete" in script
    assert "a tampered complete bundle was restored" in script
    assert "restore replaced an existing state generation" in script
    assert "OPENAI_API_KEY" not in script
    assert "AUTOCONTRIBUTE_GITHUB_TOKEN" not in script


def test_ci_runs_the_host_level_acceptance_on_the_supported_baseline() -> None:
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    job = workflow["jobs"]["ubuntu-deployment-recovery"]

    assert job["name"] == "Ubuntu 24.04 deployment/recovery acceptance"
    assert job["runs-on"] == "ubuntu-24.04"
    assert job["timeout-minutes"] == 20
    steps = job["steps"]
    checkout = next(step for step in steps if step["name"] == "Check out source")
    setup = next(step for step in steps if step["name"] == "Install uv and Python")
    acceptance = next(
        step for step in steps if step["name"] == "Exercise installed backup and recovery"
    )

    assert checkout["with"]["persist-credentials"] is False
    assert setup["with"] == {
        "version": "0.9.30",
        "python-version": "3.12",
        "enable-cache": True,
    }
    assert acceptance["shell"] == "bash"
    assert acceptance["run"] == "tests/acceptance/ubuntu_24_04_deployment_recovery.sh"
    assert "env" not in acceptance
