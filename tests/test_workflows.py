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


def test_ci_package_installs_the_built_wheel_in_a_clean_environment() -> None:
    document = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    steps = document["jobs"]["package"]["steps"]
    build = next(step for step in steps if step["name"] == "Build source distribution and wheel")
    install = next(
        step for step in steps if step["name"] == "Install the wheel in a clean environment"
    )
    smoke = next(step for step in steps if step["name"] == "Run the installed command")

    assert steps.index(build) < steps.index(install) < steps.index(smoke)
    assert build["run"] == "uv build --clear"
    assert 'uv venv --python 3.12 "${RUNNER_TEMP}/autocontribute-package"' in install["run"]
    assert "dist/autocontribute-*.whl" in install["run"]
    assert "autocontribute-package/bin/autocontribute --help" in smoke["run"]


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


def test_security_integration_runs_live_rootful_docker_isolation() -> None:
    job = _security_workflow()["jobs"]["live-docker-isolation"]
    rootful = next(
        step for step in job["steps"] if step["name"] == "Exercise live rootful Docker isolation"
    )

    assert job["name"] == "Live Docker isolation (rootful)"
    assert job["runs-on"] == "ubuntu-24.04"
    assert "strategy" not in job
    assert rootful["env"]["AUTOCONTRIBUTE_RUN_DOCKER_TESTS"] == "1"
    assert rootful["run"] == (
        "uv run pytest -q tests/test_sandbox_live.py tests/test_environments_live.py"
    )
