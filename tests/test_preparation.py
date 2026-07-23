from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from autocontribute.config import AutocontributeConfig
from autocontribute.domain import (
    CommandResult,
    CriticReview,
    FileEdit,
    GateResult,
    IssueCandidate,
    PatchProposal,
    QualityReport,
    RepositoryInfo,
    ReviewScores,
    RunManifest,
    RunStatus,
)
from autocontribute.exceptions import PolicyError
from autocontribute.preparation import (
    compute_preparation_config_fingerprint,
    compute_preparation_fingerprint,
    render_validation_artifact,
    validate_preparation_config_fingerprint,
    validate_preparation_fingerprint,
    validate_validation_artifact,
)
from autocontribute.store import RunStore

NOW = datetime(2026, 7, 21, 12, tzinfo=UTC)
PATCH = b"diff --git a/app.py b/app.py\n-old\n+new\n"


def _ready_manifest(*, run_id: str = "a" * 32) -> RunManifest:
    review = CriticReview(
        verdict="approve",
        summary="The focused change is ready.",
        scores=ReviewScores(
            correctness=96,
            issue_alignment=97,
            tests=95,
            repository_conventions=95,
            diff_hygiene=98,
            maintainer_clarity=96,
        ),
        blocking_findings=[],
        non_blocking_findings=[],
        issue_requirements_met=["The boundary is corrected"],
        issue_requirements_missing=[],
        test_evidence_assessment="The regression command passed.",
        maintainer_perspective="Small and reviewable.",
    )
    manifest = RunManifest(
        run_id=run_id,
        status=RunStatus.READY_FOR_APPROVAL,
        created_at=NOW,
        updated_at=NOW,
        candidate=IssueCandidate(
            repository="example/project",
            number=42,
            title="Correct the boundary",
            body="The current boundary result is incorrect.",
            html_url="https://github.com/example/project/issues/42",
            state="open",
            author="maintainer",
            labels=["bug"],
            assignees=[],
            comments=1,
            created_at=NOW,
            updated_at=NOW,
        ),
        repository=RepositoryInfo(
            full_name="example/project",
            html_url="https://github.com/example/project",
            clone_url="https://github.com/example/project.git",
            default_branch="main",
            stars=10_000,
            archived=False,
            disabled=False,
            private=False,
            pushed_at=NOW,
            license_spdx="MIT",
        ),
        base_sha="b" * 40,
        proposal=PatchProposal(
            summary="Correct the boundary result.",
            edits=[
                FileEdit(
                    operation="replace",
                    path="app.py",
                    find="old",
                    replace="new",
                    content=None,
                    rationale="Match the documented behavior.",
                )
            ],
            validation_commands=["python -m pytest"],
            commit_message="Correct the boundary result",
            pull_request_title="Correct the boundary result",
            pull_request_body="Fixes #42.",
            limitations=[],
        ),
        patched_validation=[
            CommandResult(
                command="python -m pytest",
                exit_code=0,
                duration_seconds=1.25,
                stdout="1 passed",
                stderr="",
            )
        ],
        quality=QualityReport(
            ready=True,
            readiness_score=96,
            gates=[GateResult(gate="validation", passed=True, evidence="1/1 passed")],
            review=review,
            changed_files=1,
            changed_lines=2,
        ),
    )
    manifest.preparation_config_fingerprint = compute_preparation_config_fingerprint(
        _config(),
        repository="example/project",
    )
    return manifest


def _config() -> AutocontributeConfig:
    return AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "validation": {"required_commands": {"example/project": ["python -m pytest"]}},
        }
    )


def _sealed_manifest() -> RunManifest:
    manifest = _ready_manifest()
    manifest.preparation_fingerprint = compute_preparation_fingerprint(manifest, diff=PATCH)
    return manifest


def test_preparation_fingerprint_survives_store_persistence(tmp_path) -> None:  # type: ignore[no-untyped-def]
    store = RunStore(tmp_path / "state")
    created = store.create_run()
    store.transition(created, RunStatus.DISCOVERING, reason="fixture started")
    manifest = _ready_manifest(run_id=created.run_id)
    manifest.status = RunStatus.DISCOVERING
    manifest.updated_at = created.updated_at
    manifest.preparation_fingerprint = compute_preparation_fingerprint(manifest, diff=PATCH)
    lease_owner = f"preparation-fixture-{manifest.run_id}"
    lease = store.acquire_lease(
        "autocontribute.run",
        lease_owner,
        ttl=timedelta(minutes=1),
    )
    assert lease is not None
    store.claim_candidate(manifest, lease=lease)
    assert store.release_lease("autocontribute.run", lease_owner, lease.generation)
    manifest.status = RunStatus.READY_FOR_APPROVAL
    store.save(manifest, event="fixture.ready", details={})

    persisted = store.get(manifest.run_id)

    assert persisted.preparation_fingerprint == manifest.preparation_fingerprint
    validate_preparation_fingerprint(persisted, diff=PATCH)


def test_preparation_fingerprint_rejects_exact_patch_tampering() -> None:
    manifest = _sealed_manifest()

    with pytest.raises(PolicyError, match="does not match"):
        validate_preparation_fingerprint(manifest, diff=PATCH + b"\n")


def test_preparation_fingerprint_rejects_proposal_tampering() -> None:
    manifest = _sealed_manifest()
    assert manifest.proposal is not None
    manifest.proposal.pull_request_title = "A different publication title"

    with pytest.raises(PolicyError, match="does not match"):
        validate_preparation_fingerprint(manifest, diff=PATCH)


def test_preparation_fingerprint_rejects_quality_tampering() -> None:
    manifest = _sealed_manifest()
    assert manifest.quality is not None
    manifest.quality.gates[0].evidence = "different validation evidence"

    with pytest.raises(PolicyError, match="does not match"):
        validate_preparation_fingerprint(manifest, diff=PATCH)


def test_preparation_config_fingerprint_rejects_gate_and_allowlist_drift() -> None:
    manifest = _sealed_manifest()
    config = _config()

    validate_preparation_config_fingerprint(manifest, config)

    changed_quality = config.model_copy(deep=True)
    changed_quality.quality.max_files_changed += 1
    with pytest.raises(PolicyError, match="configuration changed"):
        validate_preparation_config_fingerprint(manifest, changed_quality)

    changed_commands = config.model_copy(deep=True)
    changed_commands.validation.required_commands["example/project"] = ["python -m pytest -q"]
    with pytest.raises(PolicyError, match="configuration changed"):
        validate_preparation_config_fingerprint(manifest, changed_commands)

    removed_target = config.model_copy(deep=True)
    removed_target.github.repositories = []
    with pytest.raises(PolicyError, match="no longer in the configured allowlist"):
        validate_preparation_config_fingerprint(manifest, removed_target)


@pytest.mark.parametrize(
    ("section", "field", "replacement"),
    [
        ("sandbox", "command_timeout_seconds", 901),
        ("sandbox", "max_commands", 9),
        ("publishing", "mode", "auto"),
        ("publishing", "branch_prefix", "different-prefix"),
        ("publishing", "draft", False),
    ],
)
def test_preparation_config_fingerprint_rejects_execution_and_publication_drift(
    section: str,
    field: str,
    replacement: object,
) -> None:
    manifest = _sealed_manifest()
    changed = _config()
    setattr(getattr(changed, section), field, replacement)

    with pytest.raises(PolicyError, match="configuration changed"):
        validate_preparation_config_fingerprint(manifest, changed)


def test_preparation_fingerprint_binds_preparation_config_fingerprint() -> None:
    manifest = _sealed_manifest()
    manifest.preparation_config_fingerprint = "0" * 64

    with pytest.raises(PolicyError, match="does not match"):
        validate_preparation_fingerprint(manifest, diff=PATCH)


def test_preparation_fingerprint_rejects_patched_validation_tampering() -> None:
    manifest = _sealed_manifest()
    manifest.patched_validation[0].stdout = "different command output"

    with pytest.raises(PolicyError, match="does not match"):
        validate_preparation_fingerprint(manifest, diff=PATCH)


def test_preparation_fingerprint_requires_patched_validation_evidence() -> None:
    manifest = _ready_manifest()
    manifest.patched_validation = []

    with pytest.raises(PolicyError, match="without patched validation evidence"):
        compute_preparation_fingerprint(manifest, diff=PATCH)


def test_validation_artifact_must_match_durable_command_evidence() -> None:
    manifest = _ready_manifest()
    manifest.patched_validation[0].stdout = "1 résultat réussi"
    artifact = render_validation_artifact(manifest)

    validate_validation_artifact(manifest, artifact=artifact)
    with pytest.raises(PolicyError, match="does not match durable command evidence"):
        validate_validation_artifact(
            manifest,
            artifact=artifact.replace(
                '"stdout": "1 r\\u00e9sultat r\\u00e9ussi"',
                '"stdout": "2 r\\u00e9sultats r\\u00e9ussis"',
            ),
        )


def test_validation_artifact_rejects_extra_or_duplicate_evidence() -> None:
    manifest = _ready_manifest()
    artifact = render_validation_artifact(manifest)
    with pytest.raises(PolicyError, match="does not match durable command evidence"):
        validate_validation_artifact(
            manifest,
            artifact=artifact.replace('"baseline": null,', '"baseline": null, "extra": true,'),
        )
    with pytest.raises(PolicyError, match="strict UTF-8 JSON"):
        validate_validation_artifact(
            manifest,
            artifact=artifact.replace('"baseline": null,', '"baseline": null, "baseline": null,'),
        )


def test_preparation_fingerprint_is_optional_only_for_legacy_loading() -> None:
    payload = _ready_manifest().model_dump(mode="json", exclude={"preparation_fingerprint"})
    legacy = RunManifest.model_validate(payload)

    assert legacy.preparation_fingerprint is None
    with pytest.raises(PolicyError, match="missing its preparation fingerprint"):
        validate_preparation_fingerprint(legacy, diff=PATCH)
