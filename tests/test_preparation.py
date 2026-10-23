from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from test_evidence import ENVIRONMENT, MODELS, VERSION, proposal, ready_quality

from autocontribute.config import AutocontributeConfig
from autocontribute.domain import (
    IssueCandidate,
    RepositoryInfo,
    RunManifest,
    RunStatus,
)
from autocontribute.environments import EnvironmentOverride
from autocontribute.exceptions import PolicyError
from autocontribute.preparation import (
    compute_preparation_config_fingerprint,
    compute_preparation_fingerprint,
    validate_preparation_config_fingerprint,
    validate_preparation_fingerprint,
    validate_validation_artifact,
)
from autocontribute.store import RunStore

NOW = datetime(2026, 7, 21, 12, tzinfo=UTC)
PATCH = b"diff --git a/app.py b/app.py\n-old\n+new\n"


VALIDATION = b'{"recipe": {}}\n'


def _ready_manifest(*, run_id: str = "a" * 32) -> RunManifest:
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
        models=MODELS,
        autocontribute_version=VERSION,
        environment=ENVIRONMENT,
        proposal=proposal(_config()),
        quality=ready_quality(),
        validation_sha256=hashlib.sha256(VALIDATION).hexdigest(),
    )
    manifest.preparation_config_fingerprint = compute_preparation_config_fingerprint(
        _config(), repository="example/project", models=MODELS
    )
    return manifest


def _config() -> AutocontributeConfig:
    return AutocontributeConfig.model_validate({"github": {"repositories": ["example/project"]}})


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

    changed_environment = config.model_copy(deep=True)
    changed_environment.environments = {
        "example/project": EnvironmentOverride(test="python -m pytest -q")
    }
    with pytest.raises(PolicyError, match="configuration changed"):
        validate_preparation_config_fingerprint(manifest, changed_environment)

    # An environment for another repository is no part of this one's preparation.
    other_environment = config.model_copy(deep=True)
    other_environment.environments = {"example/other": EnvironmentOverride(test="make test")}
    validate_preparation_config_fingerprint(manifest, other_environment)

    other_models = manifest.model_copy(deep=True)
    other_models.models = MODELS.model_copy(update={"critic": "claude-opus-5-5"})
    with pytest.raises(PolicyError, match="configuration changed"):
        validate_preparation_config_fingerprint(other_models, config)

    removed_target = config.model_copy(deep=True)
    removed_target.github.repositories = []
    with pytest.raises(PolicyError, match="no longer in the configured allowlist"):
        validate_preparation_config_fingerprint(manifest, removed_target)


@pytest.mark.parametrize(
    ("section", "field", "replacement"),
    [
        ("sandbox", "command_timeout_seconds", 901),
        ("sandbox", "memory", "8g"),
        ("publishing", "branch_prefix", "different-prefix"),
        ("publishing", "draft", True),
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


def test_preparation_fingerprint_binds_the_validation_evidence_and_models() -> None:
    manifest = _sealed_manifest()
    manifest.validation_sha256 = "0" * 64

    with pytest.raises(PolicyError, match="does not match"):
        validate_preparation_fingerprint(manifest, diff=PATCH)

    other_environment = _sealed_manifest()
    other_environment.environment = ENVIRONMENT.model_copy(update={"recipe_source": "agent"})
    with pytest.raises(PolicyError, match="does not match"):
        validate_preparation_fingerprint(other_environment, diff=PATCH)


@pytest.mark.parametrize("missing", ["models", "environment", "validation_sha256"])
def test_preparation_fingerprint_requires_the_runs_evidence(missing: str) -> None:
    manifest = _ready_manifest()
    setattr(manifest, missing, None)

    with pytest.raises(PolicyError, match="Cannot fingerprint a preparation without"):
        compute_preparation_fingerprint(manifest, diff=PATCH)


def test_validation_artifact_must_be_the_recorded_evidence() -> None:
    manifest = _ready_manifest()

    validate_validation_artifact(manifest, artifact=VALIDATION)
    with pytest.raises(PolicyError, match="does not match the run's validation evidence"):
        validate_validation_artifact(manifest, artifact=VALIDATION.replace(b"{}", b"[]"))
    manifest.validation_sha256 = None
    with pytest.raises(PolicyError, match="missing the digest of its validation evidence"):
        validate_validation_artifact(manifest, artifact=VALIDATION)


def test_preparation_fingerprint_is_optional_only_for_legacy_loading() -> None:
    payload = _ready_manifest().model_dump(mode="json", exclude={"preparation_fingerprint"})
    legacy = RunManifest.model_validate(payload)

    assert legacy.preparation_fingerprint is None
    with pytest.raises(PolicyError, match="missing its preparation fingerprint"):
        validate_preparation_fingerprint(legacy, diff=PATCH)
