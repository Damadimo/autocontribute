from pathlib import Path

import pytest
import yaml

from autocontribute.config import load_config

ROOT = Path(__file__).resolve().parents[1]


def test_checked_in_staging_config_is_safe_for_the_operator_fixture() -> None:
    settings = load_config(ROOT / "autocontribute.staging.yml")

    assert settings.github.repositories == ["Damadimo/autocontribute-staging-fixture"]
    assert settings.github.owners == []
    assert settings.validation.required_commands == {
        "damadimo/autocontribute-staging-fixture": [
            "python tools/lint.py",
            "python tools/typecheck.py",
            "python -m unittest discover -s tests/unit -v",
            "python -m unittest discover -s tests/integration -v",
        ]
    }
    assert settings.publishing.mode == "review_required"
    assert settings.publishing.draft is True
    assert settings.sandbox.backend == "docker"
    assert settings.sandbox.network == "none"
    assert settings.sandbox.max_commands == 11
    assert settings.storage.path == ROOT / ".autocontribute-staging"


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
        "key_stem",
        "claim_expression",
    ),
    [
        (
            "autocontribute.yml",
            "AUTOCONTRIBUTE_STATE_LINEAGE",
            "${{ secrets.AUTOCONTRIBUTE_STATE_TOKEN }}",
            "autocontribute-state-",
            "in-progress:v2:$final_prefix:$RUN_ID:$RUN_ATTEMPT:$PARENT_KEY:$NEW_KEY",
        ),
        (
            "staging.yml",
            "AUTOCONTRIBUTE_STAGING_STATE_LINEAGE",
            "${{ secrets.AUTOCONTRIBUTE_STAGING_STATE_TOKEN }}",
            "autocontribute-staging-state-",
            "in-progress:v2:committed:$RUN_ID:$RUN_ATTEMPT:$PARENT_KEY:$NEW_KEY",
        ),
    ],
)
def test_scheduler_cache_uses_externally_committed_exact_lineage(
    workflow: str,
    lineage_variable: str,
    state_token: str,
    key_stem: str,
    claim_expression: str,
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
    assert claim["env"]["NEW_KEY"] == "${{ steps.state_lineage.outputs.new_key }}"
    assert f'claim="{claim_expression}"' in claim["run"]
    assert 'current" != "$RESOLVED_LINEAGE' in claim["run"]
    assert 'echo "claim=$claim"' in claim["run"]
    lineage_suffix = "${RUNNER_OS}-${REPOSITORY_ID}-[1-9][0-9]*-[1-9][0-9]*$"
    for version in (3, 4, 5, 6):
        assert (
            f'v{version}_lineage_pattern="^committed:{key_stem}v{version}-{lineage_suffix}"'
        ) in resolve["run"]
        assert f'[[ "$current" =~ $v{version}_lineage_pattern ]]' in resolve["run"]
        assert f'parent_schema="v{version}"' in resolve["run"]
    assert "v2_lineage_pattern" not in resolve["run"]
    assert "== committed:" not in resolve["run"]
    assert 'echo "parent_schema=$parent_schema"' in resolve["run"]
    assert (
        f'new_key="{key_stem}v6-$RUNNER_OS-$REPOSITORY_ID-$RUN_ID-$RUN_ATTEMPT"' in resolve["run"]
    )
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
    assert '"bootstrap": 6, "v3": 3, "v4": 4, "v5": 5, "v6": 6' in confirm["run"]
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
    claim = next(step for step in job["steps"] if step["name"] == "Claim scheduler state lineage")
    upload = next(step for step in job["steps"] if step["name"] == "Upload evidence bundle")

    assert job["steps"].index(upload) < job["steps"].index(commit)
    assert upload["id"] == "evidence_upload"
    assert "steps.state_cache_verify.outcome == 'success'" in upload["if"]
    assert "steps.state_cache_verify.outputs.cache-hit == 'true'" in upload["if"]
    assert upload["with"]["if-no-files-found"] == "error"
    assert "steps.evidence_upload.outcome == 'success'" in commit["if"]
    assert claim["env"]["LOCK_FOR_HANDOFF"] == "${{ inputs.lock_for_handoff }}"
    assert 'final_prefix="handoff"' in claim["run"]
    assert (
        'claim="in-progress:v2:$final_prefix:$RUN_ID:$RUN_ATTEMPT:$PARENT_KEY:$NEW_KEY"'
        in claim["run"]
    )
    assert 'echo "final_prefix=$final_prefix"' in claim["run"]
    assert commit["env"]["FINAL_PREFIX"] == "${{ steps.state_claim.outputs.final_prefix }}"
    assert 'committed="$FINAL_PREFIX:$NEW_KEY"' in commit["run"]


@pytest.mark.parametrize(
    (
        "wrapper",
        "scheduler",
        "enabled_variable",
        "lineage_variable",
        "state_secret",
        "key_prefix",
        "storage_root",
        "artifact_prefix",
    ),
    [
        (
            "recover-production-lineage.yml",
            "autocontribute.yml",
            "AUTOCONTRIBUTE_ENABLED",
            "AUTOCONTRIBUTE_STATE_LINEAGE",
            "${{ secrets.AUTOCONTRIBUTE_STATE_TOKEN }}",
            "autocontribute-state-",
            ".autocontribute",
            "autocontribute",
        ),
        (
            "recover-staging-lineage.yml",
            "staging.yml",
            "AUTOCONTRIBUTE_STAGING_ENABLED",
            "AUTOCONTRIBUTE_STAGING_STATE_LINEAGE",
            "${{ secrets.AUTOCONTRIBUTE_STAGING_STATE_TOKEN }}",
            "autocontribute-staging-state-",
            ".autocontribute-staging",
            "autocontribute-staging",
        ),
    ],
)
def test_hosted_lineage_recovery_wrappers_share_scheduler_lock_and_fixed_boundaries(
    wrapper: str,
    scheduler: str,
    enabled_variable: str,
    lineage_variable: str,
    state_secret: str,
    key_prefix: str,
    storage_root: str,
    artifact_prefix: str,
) -> None:
    workflow_root = ROOT / ".github" / "workflows"
    document = yaml.safe_load((workflow_root / wrapper).read_text())
    scheduler_document = yaml.safe_load((workflow_root / scheduler).read_text())
    triggers = document.get("on", document[True])
    inputs = triggers["workflow_dispatch"]["inputs"]
    job = document["jobs"]["recover"]

    assert inputs["recovery_action"]["options"] == [
        "promote_claimed",
        "restore_parent_stopped",
    ]
    assert inputs["expected_claim"]["required"] is True
    assert inputs["restore_over_unusable_claimant"]["default"] is False
    assert inputs["legacy_claim_intent"]["default"] == "reject"
    assert "operator_actor" not in inputs
    assert document["permissions"] == {"actions": "read", "contents": "read"}
    assert document["concurrency"] == scheduler_document["concurrency"]
    assert "github.event.repository.default_branch" in job["if"]
    assert job["uses"] == "./.github/workflows/_recover-lineage.yml"
    assert job["with"]["enabled_variable"] == enabled_variable
    assert job["with"]["lineage_variable"] == lineage_variable
    assert job["with"]["key_prefix"] == key_prefix
    assert job["with"]["storage_root"] == storage_root
    assert job["with"]["source_artifact_prefix"] == artifact_prefix
    assert job["with"]["scheduler_enabled"] == f"${{{{ vars.{enabled_variable} }}}}"
    assert "operator_actor" not in job["with"]
    assert job["secrets"] == {"state_token": state_secret}


def test_hosted_lineage_recovery_requires_exact_claim_and_exact_retained_evidence() -> None:
    path = ROOT / ".github" / "workflows" / "_recover-lineage.yml"
    document = yaml.safe_load(path.read_text())
    job = document["jobs"]["recover"]
    steps = job["steps"]
    resolve = next(step for step in steps if step.get("id") == "recovery_lineage")
    claimant_probe = next(step for step in steps if step.get("id") == "claimant_probe")
    artifact_probe = next(step for step in steps if step.get("id") == "claimant_artifact")
    claimant_restore = next(step for step in steps if step.get("id") == "claimant_cache")
    artifact_restore = next(
        step for step in steps if step.get("name") == "Restore exact claimant evidence artifact"
    )
    schema_validation = next(
        step
        for step in steps
        if step.get("name") == "Validate recovery configuration and source schema"
    )

    assert document["permissions"] == {"actions": "read", "contents": "read"}
    assert job["timeout-minutes"] == 45
    assert 'current" != "$EXPECTED_CLAIM' in resolve["run"]
    assert '"${#claim_parts[@]}" -eq 7' in resolve["run"]
    assert '"${claim_parts[1]}" == "v2"' in resolve["run"]
    assert 'candidate_key="${claim_parts[6]}"' in resolve["run"]
    assert 'candidate_key="${KEY_PREFIX}v5-' in resolve["run"]
    assert 'candidate_pattern="^${KEY_PREFIX}v(5|6)-' in resolve["run"]
    assert '[[ ! "$candidate_key" =~ $candidate_pattern ]]' in resolve["run"]
    assert 'candidate_schema="v${BASH_REMATCH[1]}"' in resolve["run"]
    assert "^${KEY_PREFIX}v(3|4|5|6)-" in resolve["run"]
    assert 'recovery_key="${KEY_PREFIX}v6-' in resolve["run"]
    assert 'echo "candidate_schema=$candidate_schema"' in resolve["run"]
    assert "requires an explicit committed or handoff intent" in resolve["run"]
    assert claimant_probe["with"]["key"] == "${{ steps.recovery_lineage.outputs.candidate_key }}"
    assert claimant_probe["with"]["lookup-only"] is True
    assert "restore-keys" not in claimant_probe["with"]
    assert claimant_restore["with"]["key"] == "${{ steps.recovery_lineage.outputs.candidate_key }}"
    assert claimant_restore["with"]["fail-on-cache-miss"] is True
    assert "restore-keys" not in claimant_restore["with"]
    assert "actions/artifacts?per_page=100&name=$ARTIFACT_NAME" in artifact_probe["run"]
    assert ".workflow_run.id == $CLAIM_RUN_ID" in artifact_probe["run"]
    assert ".expired == false" in artifact_probe["run"]
    assert "ARTIFACT_NAME" in artifact_probe["run"]
    assert artifact_probe["env"]["GH_TOKEN"] == "${{ github.token }}"
    assert "steps.claimant_probe.outputs.cache-hit != 'true'" in artifact_restore["if"]
    assert "steps.claimant_artifact.outputs.artifact-hit == 'true'" in artifact_restore["if"]
    assert 'gh run download "$CLAIM_RUN_ID"' in artifact_restore["run"]
    assert ' --name "$ARTIFACT_NAME"' in artifact_restore["run"]
    assert schema_validation["env"]["CANDIDATE_SCHEMA"] == (
        "${{ steps.recovery_lineage.outputs.candidate_schema }}"
    )
    assert '"v3": 3, "v4": 4, "v5": 5, "v6": 6' in schema_validation["run"]
    assert "Recovery lineage did not declare a supported source schema" in schema_validation["run"]


def test_hosted_lineage_recovery_persists_safe_generation_before_stale_claim_cas() -> None:
    path = ROOT / ".github" / "workflows" / "_recover-lineage.yml"
    document = yaml.safe_load(path.read_text())
    steps = document["jobs"]["recover"]["steps"]
    require_disabled = next(step for step in steps if step["name"] == "Require disabled scheduling")
    resolve = next(step for step in steps if step.get("id") == "recovery_lineage")
    refuse_rollback = next(
        step for step in steps if step["name"] == "Refuse recoverable claimant rollback"
    )
    stop = next(step for step in steps if step["name"] == "Activate continuity-loss safety stop")
    complete_backup = next(
        step
        for step in steps
        if step["name"] == "Verify recovered state and create complete evidence"
    )
    save = next(step for step in steps if step.get("id") == "recovery_cache_save")
    verify = next(step for step in steps if step.get("id") == "recovery_cache_verify")
    upload = next(step for step in steps if step.get("id") == "recovery_evidence")
    compare_and_swap = next(
        step for step in steps if step["name"] == "Compare-and-swap recovered lineage"
    )

    assert '"$SCHEDULER_ENABLED" == "true"' in require_disabled["run"]
    assert '"$enabled" == "true"' in resolve["run"]
    assert "operator_actor" not in document[True]["workflow_call"]["inputs"]
    assert resolve["env"]["TRIGGERING_ACTOR"] == "${{ github.triggering_actor }}"
    assert resolve["env"]["WORKFLOW_ACTOR"] == "${{ github.actor }}"
    assert '"$TRIGGERING_ACTOR" =~ $github_login' in resolve["run"]
    assert '"$WORKFLOW_ACTOR" =~ $github_login' in resolve["run"]
    assert "RESTORE_OVER_UNUSABLE" in refuse_rollback["run"]
    assert "use promote_claimed instead of discarding it" in refuse_rollback["run"]
    assert stop["if"] == "${{ inputs.recovery_action == 'restore_parent_stopped' }}"
    assert "safety stop" in stop["run"]
    assert stop["env"]["TRIGGERING_ACTOR"] == "${{ github.triggering_actor }}"
    assert stop["env"]["WORKFLOW_ACTOR"] == "${{ github.actor }}"
    assert '--actor "$TRIGGERING_ACTOR"' in stop["run"]
    assert '"$TRIGGERING_ACTOR" != "$WORKFLOW_ACTOR"' in stop["run"]
    assert "[workflow authority: $WORKFLOW_ACTOR]" in stop["run"]
    assert "--complete" in complete_backup["run"]
    assert save["with"]["key"] == "${{ steps.recovery_lineage.outputs.recovery_key }}"
    assert verify["with"]["key"] == "${{ steps.recovery_lineage.outputs.recovery_key }}"
    assert verify["with"]["lookup-only"] is True
    assert verify["with"]["fail-on-cache-miss"] is True
    assert upload["with"]["if-no-files-found"] == "error"
    assert steps.index(complete_backup) < steps.index(save) < steps.index(verify)
    assert steps.index(verify) < steps.index(upload) < steps.index(compare_and_swap)
    assert '"$enabled" == "true"' in compare_and_swap["run"]
    assert 'current" != "$CLAIMED_LINEAGE' in compare_and_swap["run"]
    assert '-f value="$FINAL_PREFIX:$RECOVERY_KEY"' in compare_and_swap["run"]

    state_token = "${{ secrets.state_token }}"
    token_steps = [step["name"] for step in steps if state_token in step.get("env", {}).values()]
    assert token_steps == [
        "Resolve exact stuck lineage claim",
        "Compare-and-swap recovered lineage",
    ]
    workflow_text = path.read_text()
    assert "OPENAI_API_KEY" not in workflow_text
    assert "AUTOCONTRIBUTE_GITHUB_TOKEN" not in workflow_text


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
    assert "len(assets) != 23" in script
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
    assert "fixture_preflight_complete=0" in script
    assert "manager_drop_in_preflight_complete=0" in script
    assert "service_home_created=0" in script
    cleanup = script[
        script.index("cleanup_rootless_job()") : script.index("trap rootless_error ERR")
    ]
    assert 'if [[ "$fixture_preflight_complete" -eq 1 ]]; then' in cleanup
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
    assert '"$GITHUB_WORKSPACE/.venv/bin/pytest"' in script
    assert "-q -p no:cacheprovider tests/test_sandbox_live.py" in script
