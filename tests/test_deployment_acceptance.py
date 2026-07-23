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


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


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
    assert "Refusing to clean a path containing a mount" in script
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


def test_acceptance_normalizes_and_probes_the_release_as_the_service_identity() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    source_types = script.index("immutable release source contains an unsafe entry")
    source_links = script.index(
        "immutable release source contains a multiply linked file",
        source_types,
    )
    initial_identity = script.index(
        'release_directory_identity="$(stat --format=\'%d:%i\' -- "$release")"',
        source_links,
    )
    initial_mount = script.index(
        'nested_release_mount="$(mounted_path_at_or_below "$release")"',
        initial_identity,
    )
    sync = script.index("uv sync \\\n")
    no_editable = script.index("  --no-editable \\\n", sync)
    no_config = script.index("  --no-config \\\n", no_editable)
    no_python_downloads = script.index("  --no-python-downloads \\\n", no_config)
    post_sync_identity = script.index(
        "immutable release identity changed during dependency installation",
        no_python_downloads,
    )
    post_sync_mount = script.index(
        "immutable release acquired a mount during dependency installation",
        post_sync_identity,
    )
    ownership = script.index(
        'sudo find "$release" -xdev -exec chown -h root:root -- {} +',
        post_sync_mount,
    )
    normalization = script.index(
        'sudo find "$release" -xdev ! -type l -exec chmod u=rwX,go=rX -- {} +',
        ownership,
    )
    marker_reset = script.index(
        'sudo chmod 0600 -- "${release}/.autocontribute-acceptance"',
        normalization,
    )
    normalized_identity = script.index(
        "immutable release identity changed during permission normalization",
        marker_reset,
    )
    normalized_mount = script.index(
        "immutable release acquired a mount during permission normalization",
        normalized_identity,
    )
    postconditions = script.index(
        'fail "immutable release contains a multiply linked file: $unsafe_release_path"',
        normalized_mount,
    )
    marker_mode = script.index(
        'fail "immutable release cleanup marker mode is unsafe"',
        postconditions,
    )
    venv_identity = script.index(
        'fail "immutable release virtual environment is aliased or unsafe"',
        marker_mode,
    )
    bin_identity = script.index(
        'fail "immutable release executable directory is aliased or unsafe"',
        venv_identity,
    )
    entrypoint_identity = script.index(
        'fail "immutable release entrypoint is aliased or unsafe"',
        bin_identity,
    )
    python_identity = script.index(
        'fail "immutable release Python does not resolve to the pinned system interpreter"',
        entrypoint_identity,
    )
    service_import = script.index(
        '"${release}/.venv/bin/python" -I - "$release" "$service_uid"',
        python_identity,
    )
    uid_check = script.index("if os.getuid()", service_import)
    application_import = script.index("from autocontribute import store", uid_check)
    service_verifier = script.index(
        '"${release}/.venv/bin/autocontribute" \\\n'
        "  deployment verify-systemd-assets --source-root",
        application_import,
    )
    asset_install = script.index("assets_install_started=1", service_verifier)
    current_selection = script.index(
        'sudo ln --symbolic "releases/${release_id}" "$current_release"',
        asset_install,
    )

    assert (
        source_types
        < source_links
        < initial_identity
        < initial_mount
        < sync
        < no_editable
        < no_config
        < no_python_downloads
        < post_sync_identity
        < post_sync_mount
        < ownership
        < normalization
        < marker_reset
        < normalized_identity
        < normalized_mount
        < postconditions
        < marker_mode
        < venv_identity
        < bin_identity
        < entrypoint_identity
        < python_identity
        < service_import
        < uid_check
        < application_import
        < service_verifier
        < asset_install
        < current_selection
    )
    assert 'sudo chmod -R go-w "$release"' not in script
    assert "UV_LINK_MODE=copy" in script
    assert 'UV_PROJECT_ENVIRONMENT="${release}/.venv"' in script
    assert "PYTHONNOUSERSITE=1" in script
    assert "release import probe did not run as the service identity" in script
    assert "release import did not use the installed immutable package" in script
    assert 'sudo test -L "${release}/.venv"' in script
    assert 'sudo test -L "${release}/.venv/bin"' in script
    assert 'sudo test -L "${release}/.venv/bin/autocontribute"' in script
    assert 'find "$release" -xdev -type f -links +1' in script
    assert "--no-config" in script
    assert "--no-python-downloads" in script

    remove_marked_tree = _shell_function("remove_marked_tree")
    first_mount_check = remove_marked_tree.index('mounted_path_at_or_below "$root"')
    marker_check = remove_marked_tree.index('sudo test -f "$marker_path"')
    second_mount_check = remove_marked_tree.index(
        'mounted_path_at_or_below "$root"',
        first_mount_check + 1,
    )
    identity_recheck = remove_marked_tree.index(
        '[[ "$current_root_identity" != "$root_identity" ]]',
        second_mount_check,
    )
    recursive_removal = remove_marked_tree.index('sudo /bin/rm -rf --one-file-system -- "$root"')
    assert (
        first_mount_check < marker_check < second_mount_check < identity_recheck < recursive_removal
    )
    assert script.count("/bin/rm -rf") == 1
    assert 'remove_marked_tree "$smoke_root"' in script


def test_release_mode_normalization_preserves_executables_and_private_marker(
    tmp_path: Path,
) -> None:
    release = tmp_path / "release"
    package = release / ".venv" / "lib" / "site-packages" / "autocontribute"
    package.mkdir(parents=True)
    entrypoint = release / ".venv" / "bin" / "autocontribute"
    entrypoint.parent.mkdir()
    module = package / "store.py"
    marker = release / ".autocontribute-acceptance"
    external = tmp_path / "external"
    linked_external = release / "linked-external"
    entrypoint.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    module.write_text("class RunStore: ...\n", encoding="utf-8")
    marker.write_text("marker\n", encoding="utf-8")
    external.write_text("private\n", encoding="utf-8")
    linked_external.symlink_to(external)
    for directory in (release, release / ".venv", release / ".venv" / "lib", package):
        directory.chmod(0o700)
    entrypoint.parent.chmod(0o700)
    entrypoint.chmod(0o711)
    module.chmod(0o600)
    marker.chmod(0o600)
    external.chmod(0o600)

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    chmod_log = tmp_path / "chmod.log"
    _write_executable(
        fake_bin / "chmod",
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        'printf \'%s\\n\' "$@" >>"$CHMOD_LOG"\n'
        '[[ "$1" == u=rwX,go=rX && "$2" == -- ]]\n'
        "shift 2\n"
        '/bin/chmod u=rwX,go=rX "$@"\n',
    )
    env = os.environ.copy()
    env["CHMOD_LOG"] = os.fspath(chmod_log)
    env["PATH"] = f"{fake_bin}{os.pathsep}{env['PATH']}"

    result = subprocess.run(
        [
            "bash",
            "-c",
            'find "$1" -xdev ! -type l -exec chmod u=rwX,go=rX -- {} +',
            "bash",
            os.fspath(release),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0, result.stderr
    marker.chmod(0o600)

    assert stat.S_IMODE(release.stat().st_mode) == 0o755
    assert stat.S_IMODE(package.stat().st_mode) == 0o755
    assert stat.S_IMODE(entrypoint.stat().st_mode) == 0o755
    assert stat.S_IMODE(module.stat().st_mode) == 0o644
    assert stat.S_IMODE(marker.stat().st_mode) == 0o600
    assert stat.S_IMODE(external.stat().st_mode) == 0o600
    assert os.fspath(linked_external) not in chmod_log.read_text(encoding="utf-8")


def test_remove_marked_tree_fails_closed_on_mount_inspection_and_races(
    tmp_path: Path,
) -> None:
    mounted_function = _shell_function("mounted_path_at_or_below").replace(
        "/usr/bin/findmnt",
        '"$FAKE_FINDMNT"',
    )
    remove_function = _shell_function("remove_marked_tree")
    target = tmp_path / "managed"
    target.mkdir()
    (target / ".autocontribute-acceptance").write_text("expected\n", encoding="utf-8")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    rm_log = tmp_path / "rm.log"
    counter = tmp_path / "findmnt.count"
    fake_findmnt = fake_bin / "findmnt"
    _write_executable(
        fake_findmnt,
        """#!/usr/bin/env bash
set -euo pipefail
count=0
if [[ -f "$FINDMNT_COUNT" ]]; then count="$(<"$FINDMNT_COUNT")"; fi
count=$((count + 1))
printf '%s\n' "$count" >"$FINDMNT_COUNT"
case "$MOUNT_SCENARIO" in
  failure) exit 23 ;;
  failure_second) if [[ "$count" -eq 2 ]]; then exit 23; fi ;;
  exact) printf '%s\n' "$TARGET" ;;
  nested) printf '%s/child\n' "$TARGET" ;;
  sibling) printf '%s-sibling\n' "$TARGET" ;;
  acquired) if [[ "$count" -eq 2 ]]; then printf '%s/late\n' "$TARGET"; fi ;;
  none) ;;
  *) exit 97 ;;
esac
""",
    )
    _write_executable(
        fake_bin / "sudo",
        """#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  test) shift; exec /bin/test "$@" ;;
  readlink) printf '%s\n' "${@: -1}" ;;
  stat) printf '1:2\n' ;;
  /bin/cat) printf 'expected\n' ;;
  /bin/rm) printf '%s\n' "$*" >>"$RM_LOG" ;;
  *) exit 98 ;;
esac
""",
    )
    harness = f"""set -uo pipefail
acceptance_marker=expected
{mounted_function}
{remove_function}
set +e
remove_marked_tree "$TARGET"
status=$?
printf '%s\\n' "$status"
"""
    env = os.environ.copy()
    env.update(
        {
            "FAKE_FINDMNT": os.fspath(fake_findmnt),
            "FINDMNT_COUNT": os.fspath(counter),
            "PATH": f"{fake_bin}{os.pathsep}{env['PATH']}",
            "RM_LOG": os.fspath(rm_log),
            "TARGET": os.fspath(target),
        }
    )

    for scenario, expected_status, removal_expected in (
        ("failure", 1, False),
        ("failure_second", 1, False),
        ("exact", 1, False),
        ("nested", 1, False),
        ("acquired", 1, False),
        ("sibling", 0, True),
        ("none", 0, True),
    ):
        counter.unlink(missing_ok=True)
        rm_log.unlink(missing_ok=True)
        env["MOUNT_SCENARIO"] = scenario
        result = subprocess.run(
            ["bash", "-c", harness],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout == f"{expected_status}\n", (scenario, result.stderr)
        assert rm_log.exists() is removal_expected
        if removal_expected:
            assert "--one-file-system" in rm_log.read_text(encoding="utf-8")


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
