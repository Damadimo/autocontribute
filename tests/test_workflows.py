import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def _security_workflow() -> dict[str, object]:
    return yaml.safe_load((ROOT / ".github" / "workflows" / "security-integration.yml").read_text())


def _security_classifier_script() -> str:
    document = _security_workflow()
    job = document["jobs"]["classify-security-changes"]
    step = next(step for step in job["steps"] if step.get("id") == "classify")
    return str(step["run"])


def _git(repository: Path, *arguments: str) -> str:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "LC_ALL": "C",
        }
    )
    result = subprocess.run(
        ["git", "-c", "commit.gpgsign=false", *arguments],
        cwd=repository,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _security_classifier_repository(tmp_path: Path) -> tuple[Path, str]:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "--initial-branch=main")
    _git(repository, "config", "user.name", "Security classifier test")
    _git(repository, "config", "user.email", "security-classifier@example.invalid")
    (repository / "README.md").write_text("initial\n", encoding="utf-8")
    _git(repository, "add", "--all")
    _git(repository, "commit", "-m", "initial")
    return repository, _git(repository, "rev-parse", "HEAD")


def _commit_security_classifier_change(
    repository: Path,
    relative_path: str,
    content: str = "changed\n",
) -> str:
    target = repository / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    _git(repository, "add", "--all")
    _git(repository, "commit", "-m", f"change {relative_path}")
    return _git(repository, "rev-parse", "HEAD")


def _run_security_classifier(
    repository: Path,
    tmp_path: Path,
    *,
    event_name: str,
    pull_request_base_sha: str = "",
    pull_request_head_sha: str = "",
) -> dict[str, str]:
    github_output = tmp_path / "github-output"
    github_output.unlink(missing_ok=True)
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir(exist_ok=True)
    environment = os.environ.copy()
    environment.update(
        {
            "EVENT_NAME": event_name,
            "PULL_REQUEST_BASE_SHA": pull_request_base_sha,
            "PULL_REQUEST_HEAD_SHA": pull_request_head_sha,
            "GITHUB_OUTPUT": str(github_output),
            "RUNNER_TEMP": str(runner_temp),
        }
    )
    subprocess.run(
        ["bash", "-c", _security_classifier_script()],
        cwd=repository,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    return dict(
        line.split("=", 1) for line in github_output.read_text(encoding="utf-8").splitlines()
    )


def test_ci_audits_workflows_shell_and_complete_history_for_secrets() -> None:
    document = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    job = document["jobs"]["repository-audit"]
    steps = job["steps"]
    checkout = next(
        step for step in steps if str(step.get("uses", "")).startswith("actions/checkout@")
    )
    setup_go = next(
        step for step in steps if str(step.get("uses", "")).startswith("actions/setup-go@")
    )
    install = next(
        step for step in steps if step.get("name") == "Install pinned repository scanners"
    )
    workflow_audit = next(
        step for step in steps if step.get("name") == "Check workflows and embedded shell"
    )
    secret_scan = next(
        step for step in steps if step.get("name") == "Scan complete history for secrets"
    )

    assert checkout["with"] == {"fetch-depth": 0, "persist-credentials": False}
    assert setup_go["with"] == {"go-version": "1.23.8", "cache": False}
    assert "actionlint/cmd/actionlint@v1.7.7" in install["run"]
    assert "gitleaks/v8@v8.28.0" in install["run"]
    assert "shellcheck" in install["run"]
    assert "actionlint" in workflow_audit["run"]
    assert "-shellcheck" in workflow_audit["run"]
    assert secret_scan["run"] == '"$(go env GOPATH)/bin/gitleaks" git --redact --verbose .'


def test_ci_audits_locked_dependencies_and_runs_static_security_analysis() -> None:
    document = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    triggers = document.get("on", document[True])
    job = document["jobs"]["dependency-and-sast"]
    steps = job["steps"]
    checkout = next(
        step for step in steps if str(step.get("uses", "")).startswith("actions/checkout@")
    )
    setup_uv = next(
        step for step in steps if str(step.get("uses", "")).startswith("astral-sh/setup-uv@")
    )
    dependency_audit = next(
        step for step in steps if step.get("name") == "Audit the locked runtime dependency graph"
    )
    static_analysis = next(
        step
        for step in steps
        if step.get("name")
        == "Scan Python sources for medium and high confidence security findings"
    )

    assert triggers == {
        "push": {"branches": ["main"]},
        "pull_request": None,
        "workflow_dispatch": None,
        "schedule": [{"cron": "23 5 * * 1"}],
    }
    assert job["timeout-minutes"] == 10
    assert checkout["with"] == {"persist-credentials": False}
    assert setup_uv["with"] == {
        "version": "0.9.30",
        "python-version": "3.12",
        "enable-cache": True,
    }
    assert "set -euo pipefail" in dependency_audit["run"]
    assert "uv export" in dependency_audit["run"]
    assert "--locked" in dependency_audit["run"]
    assert "--no-dev" in dependency_audit["run"]
    assert "pip-audit==2.9.0" in dependency_audit["run"]
    assert "--disable-pip" in dependency_audit["run"]
    assert "bandit==1.8.6" in static_analysis["run"]
    assert "--severity-level medium" in static_analysis["run"]
    assert "--confidence-level medium" in static_analysis["run"]


def test_ci_verifies_complete_systemd_assets_in_source_distribution() -> None:
    document = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    steps = document["jobs"]["package"]["steps"]
    build_sdist = next(step for step in steps if step["name"] == "Build source distribution")
    verify_sdist = next(
        step for step in steps if step["name"] == "Verify source distribution systemd assets"
    )
    build_wheel = next(
        step for step in steps if step["name"] == "Build wheel from source distribution"
    )
    script = verify_sdist["run"]

    assert steps.index(build_sdist) < steps.index(verify_sdist) < steps.index(build_wheel)
    assert "len(assets) != 28" in script
    assert "source distribution contains non-regular systemd assets" in script
    assert "archived_assets != set(expected)" in script
    assert "extracted.read() != Path(source_path).read_bytes()" in script
    assert "member.mode != expected_mode" in script


def test_ci_exercises_workspace_quota_preflight_on_a_real_hardened_mount() -> None:
    document = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    job = document["jobs"]["systemd-deployment"]
    steps = job["steps"]
    install = next(
        step
        for step in steps
        if step["name"] == "Make packaged helpers available to executable validation"
    )
    smoke = next(
        step
        for step in steps
        if step["name"] == "Exercise bounded workspace preflight in a hardened service"
    )
    script = smoke["run"]

    assert job["runs-on"] == "ubuntu-24.04"
    assert steps.index(install) < steps.index(smoke)
    assert 'test "$(cat /proc/1/comm)" = systemd' in script
    assert 'truncate --size 5G "$workspace_image"' in script
    assert 'sudo losetup --find --show "$workspace_image"' in script
    assert 'sudo mkfs.ext4 -q -N 131072 "$loop_device"' in script
    assert 'sudo mount -t ext4 -o nodev,nosuid -- "$loop_device" "$workspace_mount"' in script
    assert 'test "$service_uid" -ne 0' in script
    assert "sudo systemd-run" in script
    assert "--property=PrivateDevices=yes" in script
    assert "--property=ProtectSystem=strict" in script
    assert '--property="ReadWritePaths=$smoke_root"' in script
    assert (
        "/usr/local/libexec/autocontribute-workspace-quota-check "
        '--headroom "$workspace_mount"' in script
    )
    assert "trap cleanup_workspace_quota_smoke EXIT" in script
    assert 'sudo umount -- "$workspace_mount"' in script
    assert 'sudo losetup --detach "$loop_device"' in script
    assert "rm -rf" not in script


def test_ci_exercises_docker_data_preflight_on_a_real_hardened_mount() -> None:
    document = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    job = document["jobs"]["systemd-deployment"]
    steps = job["steps"]
    install = next(
        step
        for step in steps
        if step["name"] == "Make packaged helpers available to executable validation"
    )
    smoke = next(
        step
        for step in steps
        if step["name"] == "Exercise bounded Docker data-root preflight in a hardened service"
    )
    script = smoke["run"]

    assert job["runs-on"] == "ubuntu-24.04"
    assert steps.index(install) < steps.index(smoke)
    assert 'test "$(cat /proc/1/comm)" = systemd' in script
    assert 'fallocate --length 2G "$docker_data_image"' in script
    assert 'sudo losetup --find --show "$docker_data_image"' in script
    assert 'sudo mkfs.ext4 -q -m 0 -N 32768 "$loop_device"' in script
    assert 'sudo mount -t ext4 -o nodev,nosuid -- "$loop_device" "$docker_data_mount"' in script
    assert 'chmod 0710 "$docker_data_mount"' in script
    assert "sudo systemd-run" in script
    assert script.count("sudo systemd-run") == 2
    assert "--property=PrivateDevices=yes" in script
    assert "--property=ProtectSystem=strict" in script
    assert '--property="ReadWritePaths=$smoke_root"' in script
    assert script.count('--property="ReadWritePaths=$smoke_root"') == 2
    assert '--property="ReadOnlyPaths=$docker_data_mount"' in script
    assert "/usr/local/libexec/autocontribute-docker-data-check" in script
    assert '--mount-only "$docker_data_mount"' in script
    assert '--read-only-health "$docker_data_mount"' in script
    assert script.index('--mount-only "$docker_data_mount"') < script.index(
        '--read-only-health "$docker_data_mount"'
    )
    assert "trap cleanup_docker_data_smoke EXIT" in script
    assert 'sudo umount -- "$docker_data_mount"' in script
    assert 'sudo losetup --detach "$loop_device"' in script
    assert "rm -rf" not in script


def test_security_integration_always_materializes_fail_closed_gate() -> None:
    document = _security_workflow()
    triggers = document[True]
    classifier = document["jobs"]["classify-security-changes"]
    live = document["jobs"]["live-docker-isolation"]
    gate = document["jobs"]["security-integration-gate"]

    assert triggers["push"] == {"branches": ["main"]}
    assert triggers["pull_request"] is None
    assert triggers["merge_group"] == {"types": ["checks_requested"]}
    assert triggers["workflow_dispatch"] is None
    assert triggers["schedule"] == [{"cron": "43 6 * * 1"}]
    assert all(
        "paths" not in configuration and "paths-ignore" not in configuration
        for configuration in triggers.values()
        if isinstance(configuration, dict)
    )

    checkout = next(
        step
        for step in classifier["steps"]
        if str(step.get("uses", "")).startswith("actions/checkout@")
    )
    assert checkout["with"] == {
        "ref": "${{ github.sha }}",
        "fetch-depth": 0,
        "persist-credentials": False,
    }
    assert classifier["outputs"]["run_live"] == "${{ steps.classify.outputs.run_live }}"
    classifier_script = _security_classifier_script()
    assert 'git merge-base "$base_sha" "$head_sha"' in classifier_script
    assert "reason=push_requires_live" in classifier_script
    assert "reason=merge_group_requires_live" in classifier_script
    assert "git diff --no-renames --name-only -z" in classifier_script
    assert "while IFS= read -r -d '' changed_path" in classifier_script
    assert "docs/* | README.md | CONTRIBUTING.md | SECURITY.md | LICENSE)" in classifier_script
    assert "run_live=true" in classifier_script
    assert "reason=diff_failed" in classifier_script

    assert document["concurrency"] == {
        "group": "security-integration-${{ github.event_name }}-${{ github.sha }}",
        "cancel-in-progress": False,
    }
    assert live["needs"] == "classify-security-changes"
    assert "!cancelled()" in live["if"]
    assert "always()" not in live["if"]
    assert "result != 'success'" in live["if"]
    assert "outputs.run_live != 'false'" in live["if"]
    assert gate["name"] == "Security integration gate"
    assert gate["needs"] == ["classify-security-changes", "live-docker-isolation"]
    assert gate["if"] == "${{ always() }}"


def test_security_workflow_changes_are_assigned_to_a_trusted_code_owner() -> None:
    rules = {
        line
        for raw_line in (ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8").splitlines()
        if (line := raw_line.strip()) and not line.startswith("#")
    }

    assert "/.github/workflows/ @Damadimo" in rules
    assert "/.github/CODEOWNERS @Damadimo" in rules


@pytest.mark.parametrize(
    "relative_path",
    ["docs/operator.md", "README.md", "CONTRIBUTING.md", "SECURITY.md", "LICENSE"],
)
def test_security_classifier_skips_only_documentation_changes(
    tmp_path: Path, relative_path: str
) -> None:
    repository, base_sha = _security_classifier_repository(tmp_path)
    head_sha = _commit_security_classifier_change(repository, relative_path)

    outputs = _run_security_classifier(
        repository,
        tmp_path,
        event_name="pull_request",
        pull_request_base_sha=base_sha,
        pull_request_head_sha=head_sha,
    )

    assert outputs == {"run_live": "false", "reason": "documentation_only"}


@pytest.mark.parametrize(
    "relative_path",
    [
        "src/autocontribute/new_module.py",
        "tests/test_new_behavior.py",
        ".github/workflows/new-workflow.yml",
        "pyproject.toml",
    ],
)
def test_security_classifier_runs_for_executable_or_control_changes(
    tmp_path: Path, relative_path: str
) -> None:
    repository, base_sha = _security_classifier_repository(tmp_path)
    head_sha = _commit_security_classifier_change(repository, relative_path)

    outputs = _run_security_classifier(
        repository,
        tmp_path,
        event_name="pull_request",
        pull_request_base_sha=base_sha,
        pull_request_head_sha=head_sha,
    )

    assert outputs == {"run_live": "true", "reason": "security_relevant_changes"}


def test_security_classifier_uses_pull_request_merge_base(tmp_path: Path) -> None:
    repository, _initial_sha = _security_classifier_repository(tmp_path)
    _git(repository, "checkout", "-b", "feature")
    head_sha = _commit_security_classifier_change(repository, "docs/feature.md")
    _git(repository, "checkout", "main")
    base_sha = _commit_security_classifier_change(repository, "src/base_advance.py")

    outputs = _run_security_classifier(
        repository,
        tmp_path,
        event_name="pull_request",
        pull_request_base_sha=base_sha,
        pull_request_head_sha=head_sha,
    )

    assert outputs == {"run_live": "false", "reason": "documentation_only"}


def test_security_classifier_treats_code_to_docs_rename_as_relevant(tmp_path: Path) -> None:
    repository, _initial_sha = _security_classifier_repository(tmp_path)
    base_sha = _commit_security_classifier_change(repository, "src/moved.py")
    (repository / "docs").mkdir(exist_ok=True)
    _git(repository, "mv", "src/moved.py", "docs/moved.md")
    _git(repository, "commit", "-m", "move code into docs")
    head_sha = _git(repository, "rev-parse", "HEAD")

    outputs = _run_security_classifier(
        repository,
        tmp_path,
        event_name="pull_request",
        pull_request_base_sha=base_sha,
        pull_request_head_sha=head_sha,
    )

    assert outputs == {"run_live": "true", "reason": "security_relevant_changes"}


def test_security_classifier_checks_relevant_paths_after_three_hundred_docs(
    tmp_path: Path,
) -> None:
    repository, base_sha = _security_classifier_repository(tmp_path)
    for index in range(305):
        path = repository / "docs" / f"generated-{index:03d}.md"
        path.parent.mkdir(exist_ok=True)
        path.write_text(f"document {index}\n", encoding="utf-8")
    relevant = repository / "src" / "relevant.py"
    relevant.parent.mkdir()
    relevant.write_text("relevant = True\n", encoding="utf-8")
    _git(repository, "add", "--all")
    _git(repository, "commit", "-m", "large mixed change")
    head_sha = _git(repository, "rev-parse", "HEAD")

    outputs = _run_security_classifier(
        repository,
        tmp_path,
        event_name="pull_request",
        pull_request_base_sha=base_sha,
        pull_request_head_sha=head_sha,
    )

    assert outputs == {"run_live": "true", "reason": "security_relevant_changes"}


def test_security_classifier_uncertainty_runs_live(tmp_path: Path) -> None:
    repository, head_sha = _security_classifier_repository(tmp_path)

    invalid_sha = _run_security_classifier(
        repository,
        tmp_path,
        event_name="pull_request",
        pull_request_base_sha="not-a-sha",
        pull_request_head_sha=head_sha,
    )
    missing_commit = _run_security_classifier(
        repository,
        tmp_path,
        event_name="pull_request",
        pull_request_base_sha="1" * 40,
        pull_request_head_sha=head_sha,
    )
    empty_diff = _run_security_classifier(
        repository,
        tmp_path,
        event_name="pull_request",
        pull_request_base_sha=head_sha,
        pull_request_head_sha=head_sha,
    )
    push = _run_security_classifier(
        repository,
        tmp_path,
        event_name="push",
    )
    merge_group = _run_security_classifier(
        repository,
        tmp_path,
        event_name="merge_group",
    )
    scheduled = _run_security_classifier(
        repository,
        tmp_path,
        event_name="schedule",
    )

    assert invalid_sha == {"run_live": "true", "reason": "invalid_pull_request_sha"}
    assert missing_commit == {"run_live": "true", "reason": "missing_pull_request_commit"}
    assert empty_diff == {"run_live": "true", "reason": "empty_diff"}
    assert push == {"run_live": "true", "reason": "push_requires_live"}
    assert merge_group == {"run_live": "true", "reason": "merge_group_requires_live"}
    assert scheduled == {"run_live": "true", "reason": "event_requires_live"}


@pytest.mark.parametrize(
    ("classifier_result", "run_live", "live_result", "expected_status"),
    [
        ("success", "false", "skipped", 0),
        ("success", "true", "success", 0),
        ("success", "invalid", "success", 1),
        ("failure", "true", "success", 1),
        ("success", "false", "success", 1),
        ("success", "true", "failure", 1),
    ],
)
def test_security_integration_gate_accepts_only_exact_result_contract(
    classifier_result: str,
    run_live: str,
    live_result: str,
    expected_status: int,
) -> None:
    document = _security_workflow()
    gate = document["jobs"]["security-integration-gate"]
    script = gate["steps"][0]["run"]
    environment = os.environ.copy()
    environment.update(
        {
            "CLASSIFIER_RESULT": classifier_result,
            "RUN_LIVE": run_live,
            "LIVE_RESULT": live_result,
        }
    )

    result = subprocess.run(
        ["bash", "-c", script],
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == expected_status


def test_security_integration_pins_uv_version() -> None:
    document = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "security-integration.yml").read_text()
    )
    job = document["jobs"]["live-docker-isolation"]
    setup_uv = next(
        step for step in job["steps"] if str(step.get("uses", "")).startswith("astral-sh/setup-uv@")
    )

    assert setup_uv["with"]["version"] == "0.9.30"


def test_security_integration_exercises_rootful_and_rootless_resource_boundaries() -> None:
    document = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "security-integration.yml").read_text()
    )
    job = document["jobs"]["live-docker-isolation"]
    rootless = next(
        step
        for step in job["steps"]
        if step["name"] == "Exercise live rootless Docker production topology"
    )
    rootful = next(
        step for step in job["steps"] if step["name"] == "Exercise live rootful Docker isolation"
    )
    script = rootless["run"]

    assert job["runs-on"] == "ubuntu-24.04"
    assert job["strategy"]["matrix"]["docker_mode"] == ["rootful", "rootless"]
    assert rootful["if"] == "matrix.docker_mode == 'rootful'"
    assert rootless["if"] == "matrix.docker_mode == 'rootless'"
    assert rootless["env"]["AUTOCONTRIBUTE_RUN_DOCKER_TESTS"] == "1"
    assert "set -Eeuo pipefail" in script
    assert "trap rootless_error ERR" in script
    assert "trap - ERR" in script
    assert 'install -d -m 0700 "$gpg_home"' in script
    assert '--homedir "$gpg_home"' in script
    assert "9DC858229FC7DD38854AE2D88D81803C0EBFCD88" in script
    assert '"docker-ce-rootless-extras=${docker_package_version}"' in script
    assert "Required rootless command is unavailable" in script
    assert "no shared subordinate UID/GID range is available" in script
    assert "sudo systemctl stop docker.service docker.socket" in script
    assert "Rootful Docker remained reachable after shutdown" in script
    assert 'sudo rm -f -- "$rootful_socket"' in script
    assert 'user_runtime="/run/user/${service_uid}"' in script
    assert 'sudo loginctl enable-linger "$account"' in script
    assert 'manager_drop_in_directory="/etc/systemd/system/user@${service_uid}.service.d"' in script
    assert "/etc/systemd/system/user@.service.d/50-autocontribute.conf" in script
    assert '"storage-driver": "fuse-overlayfs"' in script
    assert 'sudo systemctl restart "user@${service_uid}.service"' in script
    assert 'DBUS_SESSION_BUS_ADDRESS="unix:path=$user_bus"' in script
    assert "systemctl --user show-environment" in script
    readiness_loop = script[
        script.index("user_manager_ready=0") : script.index('test "$user_manager_ready" -eq 1')
    ]
    assert "user_manager_readiness_timeout_seconds=20" in readiness_loop
    assert "while (( SECONDS < user_manager_readiness_deadline ))" in readiness_loop
    assert readiness_loop.count('--kill-after="${user_manager_readiness_kill_grace_seconds}s"') == 2
    assert readiness_loop.count('"${user_manager_readiness_probe_timeout}s"') == 2
    readiness_assignment = readiness_loop.index("user_manager_ready=1")
    ownership_probe = readiness_loop.index("org.freedesktop.DBus GetConnectionUnixProcessID")
    ownership_target = readiness_loop.index("s org.freedesktop.systemd1", ownership_probe)
    assert ownership_probe < ownership_target < readiness_assignment
    assert (
        '[[ "$user_manager_owner" =~ ^u[[:space:]][1-9][0-9]*$ ]]'
        in readiness_loop[:readiness_assignment]
    )
    assert 'test "$manager_effective_unit_path" = "$expected_manager_unit_path"' in script
    assert 'sudo systemctl start "$system_unit"' in script
    assert '"${user_systemctl[@]}" is-active --quiet "$user_unit"' in script
    assert 'proxy_pid_before="$(sudo systemctl show "$system_unit"' in script
    assert 'daemon_pid_before="$("${user_systemctl[@]}" show "$user_unit"' in script
    assert '"/proc/${daemon_pid_before}/status"' in script
    assert 'test "$daemon_no_new_privileges" = 0' in script
    assert "Rootless Docker socket owner and group" in script
    assert 'test "$docker_socket_owner_group" = \\' in script
    assert '"${service_uid}:${service_gid}"' in script
    reload_command = 'sudo systemctl reload "$system_unit"'
    docker_probe = '"${service_env[@]}" docker info >/dev/null'
    assert script.count(reload_command) == 1
    assert '--property=MainPID --value)" = "$proxy_pid_before"' in script
    assert '--property=MainPID --value)" = "$manager_pid_before"' in script
    assert '--property=MainPID --value)" = "$daemon_pid_before"' in script
    assert script.count('"$runtime" "$docker_socket" "$rootful_socket"') == 2
    reload_index = script.index(reload_command)
    docker_probe_index = script.index(docker_probe)
    post_reload = script[reload_index : docker_probe_index + len(docker_probe)]
    assert script.index('sudo systemctl start "$system_unit"') < reload_index
    assert reload_index < docker_probe_index
    assert 'sudo systemctl is-active --quiet "$system_unit"' in post_reload
    assert '"${user_systemctl[@]}" is-active --quiet "$user_unit"' in post_reload
    assert post_reload.count('--property=SubState --value)" = running') == 2
    assert "/usr/local/libexec/autocontribute-rootless-docker-check" in post_reload
    assert '"$runtime" "$docker_socket" "$rootful_socket"' in post_reload
    assert 'test "$cgroup_driver" != none' in script
    assert "cleanup_rootless_job" in script
    assert "--signal=KILL" in script
    assert '"_SYSTEMD_USER_UNIT=$user_unit"' in script
    assert "SYSLOG_IDENTIFIER=autocontribute-rootless-dockerd" in script
    assert "fixture_preflight_complete=0" in script
    assert "manager_drop_in_preflight_complete=0" in script
    assert "service_home_created=0" in script
    cleanup = script[
        script.index("cleanup_rootless_job()") : script.index("trap rootless_error ERR")
    ]
    assert 'if [[ "$fixture_preflight_complete" -eq 1 ]]; then' in cleanup
    assert "sudo rm -rf -- /opt/autocontribute" in cleanup
    assert 'if [[ "$manager_drop_in_preflight_complete" -eq 1 ]]; then' in cleanup
    assert '"$service_home_created" -eq 1' in cleanup
    assert 'sudo rm -f -- "$docker_apt_source" "$docker_apt_key"' not in cleanup
    preflight = script[script.index("trap cleanup_rootless_job EXIT") :]
    fixture_collision = preflight.index("Production-topology fixture path already exists")
    assert fixture_collision < preflight.index("fixture_preflight_complete=1")
    manager_collision = preflight.index(
        "Production-topology fixture path already exists",
        fixture_collision + 1,
    )
    assert manager_collision < preflight.index("manager_drop_in_preflight_complete=1")
    assert preflight.index(
        'sudo install -d -o root -g "$account" -m 0750 "$service_home"'
    ) < preflight.index("service_home_created=1")
    assert "smoke_environment=/opt/autocontribute/smoke/.venv" in script
    assert "smoke_test=/opt/autocontribute/smoke/tests/test_sandbox_live.py" in script
    assert 'UV_PROJECT_ENVIRONMENT="$smoke_environment"' in script
    assert 'UV_CACHE_DIR="${RUNNER_TEMP}/autocontribute-root-uv-cache"' in script
    assert '"$(command -v uv)" sync' in script
    assert '--project "$GITHUB_WORKSPACE"' in script
    assert "--python /usr/bin/python3 --no-python-downloads" in script
    assert "--locked --extra dev --no-editable" in script
    assert "sudo chown -R root:root /opt/autocontribute/smoke" in script
    assert "sudo chmod -R go-w /opt/autocontribute/smoke" in script
    assert '"$GITHUB_WORKSPACE/tests/test_sandbox_live.py" "$smoke_test"' in script
    assert "env --chdir=/opt/autocontribute/smoke" in script
    assert '"PATH=$smoke_environment/bin:/usr/local/bin:/usr/bin:/bin"' in script
    assert '"$GITHUB_WORKSPACE/.venv/bin/' not in script
    assert '"$smoke_environment/bin/pytest"' in script
    assert '-q -p no:cacheprovider "$smoke_test"' in script
