from __future__ import annotations

import os
import re
import stat
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "tests" / "acceptance" / "ubuntu_24_04_deployment_recovery.sh"


def _shell_function(name: str) -> str:
    script = SCRIPT.read_text(encoding="utf-8")
    match = re.search(rf"(?ms)^{re.escape(name)}\(\) \{{\n.*?^\}}\n", script)
    assert match is not None
    return match.group(0)


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
    assert script.count('mountpoint_status "$backup_root"') == 2
    assert script.count('mountpoint_status "$state_root"') == 2
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


def test_acceptance_hardens_only_opt_and_restores_its_exact_identity_bound_mode() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert "sudo test -d /opt || sudo test -L /opt" in script
    assert "sudo readlink --canonicalize-existing -- /opt" in script
    assert "sudo stat --format='%d:%i:%u:%g' -- /opt" in script
    assert '[[ "$opt_identity" =~ ^[0-9]+:[0-9]+:0:0$ ]]' in script
    assert "sudo stat --format='%a' -- /opt" in script
    assert "sudo chmod go-w -- /opt" in script
    assert 'sudo chmod "$opt_original_mode" -- /opt' in script
    assert "chmod -R go-w -- /opt" not in script
    assert "chmod --recursive go-w -- /opt" not in script

    application_absence_checks = [
        match.start()
        for match in re.finditer(
            re.escape('require_absent "$application_root"'),
            script,
        )
    ]
    assert len(application_absence_checks) == 2
    hardening = script.index("sudo chmod go-w -- /opt")
    identity_verification = script.index(
        'fail "/opt changed while its mode was hardened"',
        hardening,
    )
    privileged_creation = script.index(
        'sudo install -d -o root -g root -m 0755 "$application_root"',
        identity_verification,
    )
    assert (
        application_absence_checks[0]
        < hardening
        < identity_verification
        < application_absence_checks[1]
        < privileged_creation
    )

    cleanup_start = script.index("cleanup() {")
    cleanup_end = script.index("\n}\ntrap cleanup EXIT", cleanup_start)
    cleanup = script[cleanup_start:cleanup_end]
    managed_removal = cleanup.index('sudo rmdir -- "$application_root"')
    managed_absence_check = cleanup.index('sudo test -e "$application_root"')
    identity_check = cleanup.index('current_opt_identity="$(')
    mode_restore = cleanup.index('sudo chmod "$opt_original_mode" -- /opt')
    assert managed_removal < managed_absence_check < identity_check < mode_restore
    assert "managed_opt_cleanup_failed=1" in cleanup
    assert "Refusing to restore /opt mode after managed application cleanup failed" in cleanup
    assert "Refusing to restore /opt mode while managed application paths remain" in cleanup
    assert "Refusing to restore mode on a changed /opt directory" in cleanup


def test_mountpoint_status_normalizes_only_a_confirmed_absent_path(
    tmp_path: Path,
) -> None:
    function = _shell_function("mountpoint_status")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    sudo = fake_bin / "sudo"
    sudo.write_text(
        """#!/usr/bin/env bash
set -eu
if [[ "${1:-}" == "--non-interactive" ]]; then
  shift
fi
exec "$@"
""",
        encoding="utf-8",
    )
    sudo.chmod(0o755)
    mountpoint = fake_bin / "mountpoint"
    mountpoint.write_text(
        """#!/usr/bin/env bash
set -eu
printf 'called\\n' >>"$MOUNTPOINT_LOG"
exit "${MOUNTPOINT_STATUS:?}"
""",
        encoding="utf-8",
    )
    mountpoint.chmod(0o755)
    harness = f"""set +e
{function}
mountpoint_status "$TARGET"
status=$?
printf '%s\\n' "$status"
"""
    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}{os.pathsep}{env['PATH']}"
    log = tmp_path / "mountpoint.log"
    env["MOUNTPOINT_LOG"] = os.fspath(log)
    env["MOUNTPOINT_STATUS"] = "19"

    missing = tmp_path / "missing"
    env["TARGET"] = os.fspath(missing)
    result = subprocess.run(
        ["bash", "-c", harness],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "32\n"
    assert not log.exists()

    regular_file = tmp_path / "regular-file"
    regular_file.write_text("not a directory\n", encoding="utf-8")
    env["TARGET"] = os.fspath(regular_file / "child")
    result = subprocess.run(
        ["bash", "-c", harness],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "1\n"
    assert "mountpoint path inspection failed" in result.stderr
    assert not log.exists()

    for existing in (tmp_path / "existing", tmp_path / "dangling"):
        if existing.name == "existing":
            existing.mkdir()
        else:
            existing.symlink_to(tmp_path / "absent-target", target_is_directory=True)
        env["TARGET"] = os.fspath(existing)
        result = subprocess.run(
            ["bash", "-c", harness],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout == "19\n"

    assert log.read_text(encoding="utf-8") == "called\ncalled\n"


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
