from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    ("workflow", "run_path", "evaluation_path", "snapshot_path"),
    [
        (
            "autocontribute.yml",
            ".autocontribute/runs/",
            ".autocontribute/evaluations/",
            ".autocontribute/snapshots/state.sqlite3",
        ),
        (
            "staging.yml",
            ".autocontribute-staging/runs/",
            ".autocontribute-staging/evaluations/",
            ".autocontribute-staging/snapshots/state.sqlite3",
        ),
    ],
)
def test_scheduler_persistence_keeps_evaluations_with_every_state_copy(
    workflow: str,
    run_path: str,
    evaluation_path: str,
    snapshot_path: str,
) -> None:
    document = yaml.safe_load((ROOT / ".github" / "workflows" / workflow).read_text())
    job = next(iter(document["jobs"].values()))
    persistence_steps = [
        step
        for step in job["steps"]
        if str(step.get("uses", "")).startswith(
            ("actions/cache/restore@", "actions/cache/save@", "actions/upload-artifact@")
        )
    ]

    assert len(persistence_steps) == 4
    for step in persistence_steps:
        persisted_paths = set(str(step["with"]["path"]).splitlines())
        assert persisted_paths == {run_path, evaluation_path, snapshot_path}
        if str(step.get("uses", "")).startswith("actions/upload-artifact@"):
            assert step["with"]["if-no-files-found"] == "error"


@pytest.mark.parametrize(
    (
        "workflow",
        "lineage_variable",
        "state_token",
        "key_prefix",
        "v4_key_prefix",
        "v3_key_prefix",
    ),
    [
        (
            "autocontribute.yml",
            "AUTOCONTRIBUTE_STATE_LINEAGE",
            "${{ secrets.AUTOCONTRIBUTE_STATE_TOKEN }}",
            "autocontribute-state-v5-",
            "autocontribute-state-v4-",
            "autocontribute-state-v3-",
        ),
        (
            "staging.yml",
            "AUTOCONTRIBUTE_STAGING_STATE_LINEAGE",
            "${{ secrets.AUTOCONTRIBUTE_STAGING_STATE_TOKEN }}",
            "autocontribute-staging-state-v5-",
            "autocontribute-staging-state-v4-",
            "autocontribute-staging-state-v3-",
        ),
    ],
)
def test_scheduler_cache_uses_externally_committed_exact_lineage(
    workflow: str,
    lineage_variable: str,
    state_token: str,
    key_prefix: str,
    v4_key_prefix: str,
    v3_key_prefix: str,
) -> None:
    document = yaml.safe_load((ROOT / ".github" / "workflows" / workflow).read_text())
    assert document["permissions"] == {"contents": "read"}
    job = next(iter(document["jobs"].values()))
    steps = job["steps"]
    checkout = next(
        step for step in steps if str(step.get("uses", "")).startswith("actions/checkout@")
    )
    resolve = next(step for step in steps if str(step.get("name", "")).startswith("Resolve "))
    claim = next(step for step in steps if str(step.get("name", "")).startswith("Claim "))
    restore = next(
        step for step in steps if str(step.get("uses", "")).startswith("actions/cache/restore@")
    )
    save = next(
        step for step in steps if str(step.get("uses", "")).startswith("actions/cache/save@")
    )
    verify = next(step for step in steps if step.get("id") == "state_cache_verify")
    commit = next(step for step in steps if str(step.get("name", "")).startswith("Commit "))
    confirm = next(step for step in steps if str(step.get("name", "")).startswith("Confirm live "))

    assert checkout["with"] == {
        "ref": "${{ github.sha }}",
        "persist-credentials": False,
    }
    assert resolve["env"]["LINEAGE_VARIABLE"] == lineage_variable
    assert resolve["env"]["GH_TOKEN"] == state_token
    assert "STATE_TOKEN is required" in resolve["run"]
    assert "gh api --method POST" not in resolve["run"]
    assert "gh api --method PATCH" not in resolve["run"]
    assert "refusing stale rollback" in resolve["run"]
    assert 'echo "resolved_lineage=$current"' in resolve["run"]
    assert claim["env"]["LINEAGE_VARIABLE"] == lineage_variable
    assert claim["env"]["GH_TOKEN"] == state_token
    assert claim["env"]["RESOLVED_LINEAGE"] == (
        "${{ steps.state_lineage.outputs.resolved_lineage }}"
    )
    assert "in-progress:" in claim["run"]
    assert 'current" != "$RESOLVED_LINEAGE' in claim["run"]
    assert 'echo "claim=$claim"' in claim["run"]
    lineage_suffix = "${RUNNER_OS}-${REPOSITORY_ID}-[1-9][0-9]*-[1-9][0-9]*$"
    assert f'v5_lineage_pattern="^committed:{key_prefix}{lineage_suffix}"' in resolve["run"]
    assert f'v4_lineage_pattern="^committed:{v4_key_prefix}{lineage_suffix}"' in resolve["run"]
    assert f'v3_lineage_pattern="^committed:{v3_key_prefix}{lineage_suffix}"' in resolve["run"]
    assert '[[ "$current" =~ $v5_lineage_pattern ]]' in resolve["run"]
    assert '[[ "$current" =~ $v4_lineage_pattern ]]' in resolve["run"]
    assert '[[ "$current" =~ $v3_lineage_pattern ]]' in resolve["run"]
    assert "== committed:" not in resolve["run"]
    assert 'echo "parent_schema=$parent_schema"' in resolve["run"]
    assert f'new_key="{key_prefix}$RUNNER_OS-$REPOSITORY_ID-$RUN_ID-$RUN_ATTEMPT"' in resolve["run"]
    assert restore["with"]["key"] == "${{ steps.state_lineage.outputs.parent_key }}"
    assert "restore-keys" not in restore["with"]
    assert save["with"]["key"] == "${{ steps.state_lineage.outputs.new_key }}"
    assert verify["with"]["key"] == "${{ steps.state_lineage.outputs.new_key }}"
    assert verify["with"]["lookup-only"] is True
    assert verify["with"]["fail-on-cache-miss"] is True
    assert "steps.state_cache_verify.outcome == 'success'" in commit["if"]
    assert "steps.state_cache_verify.outputs.cache-hit == 'true'" in commit["if"]
    assert commit["env"]["CLAIMED_LINEAGE"] == "${{ steps.state_claim.outputs.claim }}"
    assert commit["env"]["GH_TOKEN"] == state_token
    assert 'current" != "$CLAIMED_LINEAGE' in commit["run"]
    assert "CURRENT_SCHEMA_VERSION" in confirm["run"]
    assert "RunStore" in confirm["run"]
    assert confirm["env"]["PARENT_SCHEMA"] == "${{ steps.state_lineage.outputs.parent_schema }}"
    assert '"bootstrap": 5, "v3": 3, "v4": 4, "v5": 5' in confirm["run"]
    assert "cache schema does not match its committed lineage" in confirm["run"]
    assert steps.index(confirm) < steps.index(claim)
    assert "${{ github.token }}" not in (ROOT / ".github" / "workflows" / workflow).read_text()


@pytest.mark.parametrize(
    ("workflow", "lifecycle_step", "doctor_step", "run_step"),
    [
        (
            "autocontribute.yml",
            "Sync open pull-request lifecycle",
            "Validate configuration and isolation",
            "Prepare one contribution attempt",
        ),
        (
            "staging.yml",
            "Sync staging pull-request lifecycle",
            "Validate live staging dependencies",
            "Prepare shadow contribution",
        ),
    ],
)
def test_scheduler_claims_before_lifecycle_doctor_and_run_then_always_snapshots(
    workflow: str,
    lifecycle_step: str,
    doctor_step: str,
    run_step: str,
) -> None:
    document = yaml.safe_load((ROOT / ".github" / "workflows" / workflow).read_text())
    job = next(iter(document["jobs"].values()))
    steps = job["steps"]
    claim_index = next(
        index for index, step in enumerate(steps) if str(step.get("name", "")).startswith("Claim ")
    )
    snapshot = next(
        step for step in steps if str(step.get("name", "")).startswith("Create verified ")
    )
    lifecycle_index = next(
        index for index, step in enumerate(steps) if step.get("name") == lifecycle_step
    )
    doctor_index = next(
        index for index, step in enumerate(steps) if step.get("name") == doctor_step
    )
    run_index = next(index for index, step in enumerate(steps) if step.get("name") == run_step)
    snapshot_index = steps.index(snapshot)

    # Reconciliation must run before breaker-gated doctor checks so an interrupted
    # publication can be recovered even when its ambiguity tripped the breaker.
    assert lifecycle_index == claim_index + 1
    assert claim_index < lifecycle_index < doctor_index < run_index < snapshot_index
    assert "always()" in snapshot["if"]
    assert "steps.state_claim.outcome == 'success'" in snapshot["if"]
    assert "doctor" not in snapshot["if"]


@pytest.mark.parametrize("workflow", ["autocontribute.yml", "staging.yml"])
def test_scheduler_commits_only_after_cache_and_evidence_upload(workflow: str) -> None:
    document = yaml.safe_load((ROOT / ".github" / "workflows" / workflow).read_text())
    job = next(iter(document["jobs"].values()))
    steps = job["steps"]
    upload = next(
        step for step in steps if str(step.get("uses", "")).startswith("actions/upload-artifact@")
    )
    commit = next(step for step in steps if str(step.get("name", "")).startswith("Commit "))

    assert steps.index(upload) < steps.index(commit)
    assert upload["id"] == "evidence_upload"
    assert "steps.state_cache_verify.outcome == 'success'" in upload["if"]
    assert "steps.state_cache_verify.outputs.cache-hit == 'true'" in upload["if"]
    assert "steps.state_cache_verify.outcome == 'success'" in commit["if"]
    assert "steps.state_cache_verify.outputs.cache-hit == 'true'" in commit["if"]
    assert "steps.evidence_upload.outcome == 'success'" in commit["if"]


@pytest.mark.parametrize(
    ("workflow", "step_name"),
    [
        ("autocontribute.yml", "Enforce production Actions configuration"),
        ("staging.yml", "Enforce staging-only configuration"),
    ],
)
def test_hosted_workflows_require_review_only_docker_isolation(
    workflow: str,
    step_name: str,
) -> None:
    document = yaml.safe_load((ROOT / ".github" / "workflows" / workflow).read_text())
    job = next(iter(document["jobs"].values()))
    step = next(step for step in job["steps"] if step["name"] == step_name)

    assert 'settings.publishing.mode != "review_required"' in step["run"]
    assert 'settings.sandbox.backend != "docker"' in step["run"]
    assert 'settings.sandbox.network != "none"' in step["run"]
    assert "settings.sandbox.allow_unsafe_local" in step["run"]
    assert "work_budget_seconds > 3 * 60 * 60" in step["run"]
    assert job["timeout-minutes"] == 240


def test_production_handoff_locks_hosted_mutation_steps() -> None:
    document = yaml.safe_load((ROOT / ".github" / "workflows" / "autocontribute.yml").read_text())
    job = document["jobs"]["prepare"]
    triggers = document.get("on", document[True])
    inputs = triggers["workflow_dispatch"]["inputs"]

    assert inputs["lock_for_handoff"]["default"] is False
    for name in (
        "Sync open pull-request lifecycle",
        "Preload the configured sandbox image",
        "Validate configuration and isolation",
        "Prepare one contribution attempt",
    ):
        step = next(step for step in job["steps"] if step["name"] == name)
        assert step["if"] == "${{ inputs.lock_for_handoff != true }}"

    commit = next(step for step in job["steps"] if step["name"] == "Commit scheduler state lineage")
    upload = next(step for step in job["steps"] if step["name"] == "Upload evidence bundle")

    assert job["steps"].index(upload) < job["steps"].index(commit)
    assert upload["id"] == "evidence_upload"
    assert "steps.state_cache_verify.outcome == 'success'" in upload["if"]
    assert "steps.state_cache_verify.outputs.cache-hit == 'true'" in upload["if"]
    assert upload["with"]["if-no-files-found"] == "error"
    assert "steps.evidence_upload.outcome == 'success'" in commit["if"]
    assert "handoff:$NEW_KEY" in commit["run"]


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


def test_security_integration_pins_uv_version() -> None:
    document = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "security-integration.yml").read_text()
    )
    job = document["jobs"]["live-docker-isolation"]
    setup_uv = next(
        step for step in job["steps"] if str(step.get("uses", "")).startswith("astral-sh/setup-uv@")
    )

    assert setup_uv["with"]["version"] == "0.9.30"
