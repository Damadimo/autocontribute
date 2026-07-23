import hashlib
import json
import os
import stat
import zipfile
from datetime import timedelta
from pathlib import Path

import pytest

from autocontribute.backup import create_state_bundle, restore_state_bundle
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
from autocontribute.exceptions import StateError
from autocontribute.preparation import (
    compute_preparation_fingerprint,
    render_validation_artifact,
)
from autocontribute.store import RunStore

_PATCH = b"diff --git a/app.py b/app.py\n-old\n+new\n"


def _prepared_run(
    store: RunStore,
    *,
    status: RunStatus = RunStatus.READY_FOR_APPROVAL,
) -> RunManifest:
    run = store.create_run()
    store.transition(run, RunStatus.DISCOVERING, reason="fixture started")
    now = run.created_at
    run.candidate = IssueCandidate(
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
        created_at=now,
        updated_at=now,
    )
    run.repository = RepositoryInfo(
        full_name="example/project",
        html_url="https://github.com/example/project",
        clone_url="https://github.com/example/project.git",
        default_branch="main",
        stars=10_000,
        archived=False,
        disabled=False,
        private=False,
        pushed_at=now,
        license_spdx="MIT",
    )
    run.base_sha = "b" * 40
    run.proposal = PatchProposal(
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
    )
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
    run.patched_validation = [
        CommandResult(
            command="python -m pytest",
            exit_code=0,
            duration_seconds=1.0,
            stdout="1 passed",
            stderr="",
        )
    ]
    run.quality = QualityReport(
        ready=True,
        readiness_score=96,
        gates=[GateResult(gate="validation", passed=True, evidence="1/1 passed")],
        review=review,
        changed_files=1,
        changed_lines=2,
    )
    run.preparation_config_fingerprint = "f" * 64
    store.write_artifact(run.run_id, "contribution.patch", _PATCH.decode())
    store.write_artifact(run.run_id, "validation.json", render_validation_artifact(run))
    run.preparation_fingerprint = compute_preparation_fingerprint(run, diff=_PATCH)
    lease_owner = f"backup-fixture-{run.run_id}"
    lease = store.acquire_lease(
        "autocontribute.run",
        lease_owner,
        ttl=timedelta(minutes=1),
    )
    assert lease is not None
    store.claim_candidate(run, lease=lease)
    assert store.release_lease("autocontribute.run", lease_owner, lease.generation)
    run.status = status
    store.save(run, event="fixture.prepared", details={"status": status.value})
    return run


def test_complete_state_bundle_round_trip_is_checksummed_and_atomic(tmp_path: Path) -> None:
    source = RunStore(tmp_path / "source")
    run = source.create_run()
    source.write_artifact(run.run_id, "review-note.txt", "evidence\n")
    evaluations = source.root / "evaluations"
    evaluations.mkdir()
    bundle = create_state_bundle(source, tmp_path / "backups" / "state.zip")

    with zipfile.ZipFile(bundle) as archive:
        names = set(archive.namelist())
        manifest = json.loads(archive.read("bundle-manifest.json"))
    assert "state.sqlite3" in names
    assert f"runs/{run.run_id}/manifest.json" in names
    assert f"runs/{run.run_id}/review-note.txt" in names
    assert set(manifest["files"]) == names - {"bundle-manifest.json"}

    restored_database = restore_state_bundle(tmp_path / "restored", bundle)
    restored = RunStore(restored_database.parent)
    assert restored.get(run.run_id) == run
    assert restored.artifact_dir(run.run_id).joinpath("review-note.txt").read_text() == "evidence\n"


def test_complete_bundle_verifies_staging_with_live_root_bindings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = RunStore(tmp_path / "source")
    run = source.create_run()
    monkeypatch.setenv("AUTOCONTRIBUTE_REQUIRED_STORAGE_ROOT", os.fspath(source.root))
    monkeypatch.setenv(
        "AUTOCONTRIBUTE_REQUIRED_WORKSPACE_ROOT",
        os.fspath(source.workspaces_dir),
    )

    bundle = create_state_bundle(source, tmp_path / "backups" / "state.zip")
    restored_database = restore_state_bundle(tmp_path / "restored", bundle)

    monkeypatch.delenv("AUTOCONTRIBUTE_REQUIRED_STORAGE_ROOT")
    monkeypatch.delenv("AUTOCONTRIBUTE_REQUIRED_WORKSPACE_ROOT")
    restored = RunStore(restored_database.parent)
    assert restored.get(run.run_id) == run


def test_complete_bundle_rejects_unanchored_evaluation_file(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = store.create_run()
    evaluations = store.root / "evaluations"
    evaluations.mkdir()
    (evaluations / f"{run.run_id}.json").write_text("{}", encoding="utf-8")

    with pytest.raises(StateError, match="Invalid evaluation record"):
        create_state_bundle(store, tmp_path / "state.zip")


def test_complete_bundle_rejects_submitting_run_with_stored_commit(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = store.create_run()
    run.status = RunStatus.SUBMITTING
    run.commit_sha = "c" * 40
    store.save(run, event="fixture.commit_stored", details={})
    destination = tmp_path / "state.zip"

    with pytest.raises(
        StateError,
        match="Reconcile or finish publication on the persistent worker",
    ):
        create_state_bundle(store, destination)

    assert not destination.exists()


def test_complete_bundle_preserves_precommit_submitting_evidence(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = _prepared_run(store, status=RunStatus.SUBMITTING)

    bundle = create_state_bundle(store, tmp_path / "state.zip")
    restored_database = restore_state_bundle(tmp_path / "restored", bundle)
    restored = RunStore(restored_database.parent)

    assert restored.get(run.run_id).commit_sha is None
    assert restored.artifact_dir(run.run_id).joinpath("contribution.patch").read_bytes() == _PATCH


@pytest.mark.parametrize("filename", ["contribution.patch", "validation.json"])
def test_complete_bundle_rejects_missing_prepared_run_artifact(
    tmp_path: Path,
    filename: str,
) -> None:
    store = RunStore(tmp_path / "state")
    run = _prepared_run(store)
    store.artifact_dir(run.run_id).joinpath(filename).unlink()

    with pytest.raises(StateError, match=f"missing required prepared-run artifact {filename}"):
        create_state_bundle(store, tmp_path / "state.zip")


@pytest.mark.parametrize(
    ("filename", "tampered"),
    [
        ("contribution.patch", b"diff --git a/app.py b/app.py\n-old\n+tampered\n"),
        ("validation.json", b'{"baseline":null,"patched":[]}\n'),
    ],
)
def test_complete_bundle_rejects_tampered_prepared_run_artifact(
    tmp_path: Path,
    filename: str,
    tampered: bytes,
) -> None:
    store = RunStore(tmp_path / "state")
    run = _prepared_run(store)
    store.artifact_dir(run.run_id).joinpath(filename).write_bytes(tampered)

    with pytest.raises(StateError, match="invalid prepared-run recovery artifacts"):
        create_state_bundle(store, tmp_path / "state.zip")


def test_complete_bundle_keeps_existing_generation_when_stored_commit_is_in_flight(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    run = store.create_run()
    destination = create_state_bundle(store, tmp_path / "state.zip")
    original = destination.read_bytes()
    run.status = RunStatus.SUBMITTING
    run.commit_sha = "c" * 40
    store.save(run, event="fixture.commit_stored", details={})

    with pytest.raises(StateError, match="cannot reproduce that commit byte-for-byte"):
        create_state_bundle(store, destination, overwrite=True)

    assert destination.read_bytes() == original


def test_complete_bundle_restore_rejects_checksum_tampering(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "source")
    store.create_run()
    original = create_state_bundle(store, tmp_path / "original.zip")
    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(original) as source, zipfile.ZipFile(tampered, "w") as target:
        for info in source.infolist():
            data = source.read(info)
            if info.filename == "state.sqlite3":
                data = data + b"tampered"
            target.writestr(info.filename, data)

    with pytest.raises(StateError, match="checksum mismatch"):
        restore_state_bundle(tmp_path / "restored", tampered)
    assert not (tmp_path / "restored").exists()


@pytest.mark.parametrize(
    ("filename", "tampered_content"),
    [
        ("contribution.patch", b"diff --git a/app.py b/app.py\n-old\n+tampered\n"),
        ("validation.json", b'{"baseline":null,"patched":[]}\n'),
    ],
)
def test_complete_bundle_restore_rejects_checksummed_prepared_artifact_tampering(
    tmp_path: Path,
    filename: str,
    tampered_content: bytes,
) -> None:
    store = RunStore(tmp_path / "source")
    run = _prepared_run(store)
    original = create_state_bundle(store, tmp_path / "original.zip")
    tampered = tmp_path / "tampered.zip"
    member_name = f"runs/{run.run_id}/{filename}"
    with zipfile.ZipFile(original) as source:
        infos = source.infolist()
        contents = {info.filename: source.read(info) for info in infos}
    manifest = json.loads(contents["bundle-manifest.json"])
    contents[member_name] = tampered_content
    manifest["files"][member_name] = {
        "sha256": hashlib.sha256(tampered_content).hexdigest(),
        "size": len(tampered_content),
    }
    contents["bundle-manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
    with zipfile.ZipFile(tampered, "w") as target:
        for info in infos:
            target.writestr(info, contents[info.filename])

    with pytest.raises(StateError, match="invalid prepared-run recovery artifacts"):
        restore_state_bundle(tmp_path / "restored", tampered)
    assert not (tmp_path / "restored").exists()


def test_complete_bundle_restore_rejects_checksummed_empty_database(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "source")
    store.create_run()
    original = create_state_bundle(store, tmp_path / "original.zip")
    empty = tmp_path / "empty.zip"
    with zipfile.ZipFile(original) as source, zipfile.ZipFile(empty, "w") as target:
        manifest = json.loads(source.read("bundle-manifest.json"))
        manifest["files"]["state.sqlite3"] = {
            "sha256": hashlib.sha256(b"").hexdigest(),
            "size": 0,
        }
        for info in source.infolist():
            if info.filename == "bundle-manifest.json":
                data = (json.dumps(manifest, indent=2) + "\n").encode()
            elif info.filename == "state.sqlite3":
                data = b""
            else:
                data = source.read(info)
            target.writestr(info, data)

    with pytest.raises(StateError, match="missing or unsupported tables"):
        restore_state_bundle(tmp_path / "restored", empty)
    assert not (tmp_path / "restored").exists()


def test_complete_bundle_restore_rejects_special_member_type(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "source")
    store.create_run()
    original = create_state_bundle(store, tmp_path / "original.zip")
    unsafe = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(original) as source, zipfile.ZipFile(unsafe, "w") as target:
        for info in source.infolist():
            data = source.read(info)
            if info.filename == "state.sqlite3":
                info.external_attr = (stat.S_IFIFO | 0o600) << 16
            target.writestr(info, data)

    with pytest.raises(StateError, match="unsafe member type"):
        restore_state_bundle(tmp_path / "restored", unsafe)
    assert not (tmp_path / "restored").exists()


def test_complete_bundle_cannot_replace_live_database(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "source")
    run = store.create_run()

    with pytest.raises(StateError, match="cannot replace live SQLite state"):
        create_state_bundle(store, store.database_path, overwrite=True)

    assert store.get(run.run_id) == run


@pytest.mark.parametrize("captured_directory", ["runs", "evaluations"])
def test_complete_bundle_destination_cannot_recurse_into_captured_state(
    tmp_path: Path,
    captured_directory: str,
) -> None:
    store = RunStore(tmp_path / "source")
    store.create_run()
    destination = store.root / captured_directory / "unexpected" / "state.zip"

    with pytest.raises(StateError, match="cannot be inside captured state"):
        create_state_bundle(store, destination)

    assert not destination.exists()
    assert not destination.parent.exists()


def test_complete_bundle_repairs_an_explicitly_pending_manifest_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = RunStore(tmp_path / "source")
    run = store.create_run()
    original_writer = store._write_manifest
    attempts = 0

    def fail_once(manifest: RunManifest) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OSError("injected manifest write failure")
        original_writer(manifest)

    monkeypatch.setattr(store, "_write_manifest", fail_once)
    run.error = "committed before artifact publication"
    with pytest.raises(StateError, match="Could not synchronize manifest artifact"):
        store.save(run, event="fixture.pending_manifest", details={"state": "committed"})

    bundle = create_state_bundle(store, tmp_path / "state.zip")

    assert bundle.is_file()
    with store._connection() as connection:
        assert connection.execute("SELECT count(*) FROM manifest_artifact_sync").fetchone()[0] == 0
    with zipfile.ZipFile(bundle) as archive:
        artifact = json.loads(archive.read(f"runs/{run.run_id}/manifest.json"))
    assert artifact["error"] == "committed before artifact publication"


def test_complete_bundle_does_not_repair_unmarked_manifest_tampering(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "source")
    run = store.create_run()
    tampered = run.model_copy(deep=True)
    tampered.error = "unmarked tampering"
    store.artifact_dir(run.run_id).joinpath("manifest.json").write_text(
        tampered.model_dump_json(),
        encoding="utf-8",
    )
    destination = tmp_path / "state.zip"

    with pytest.raises(StateError, match="manifest artifact is stale"):
        create_state_bundle(store, destination)

    assert not destination.exists()
    with store._connection() as connection:
        assert connection.execute("SELECT count(*) FROM manifest_artifact_sync").fetchone()[0] == 0
