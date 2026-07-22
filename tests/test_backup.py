import hashlib
import json
import stat
import zipfile
from pathlib import Path

import pytest

from autocontribute.backup import create_state_bundle, restore_state_bundle
from autocontribute.domain import RunManifest, RunStatus
from autocontribute.exceptions import StateError
from autocontribute.store import RunStore


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
    run = store.create_run()
    run.status = RunStatus.SUBMITTING
    run.base_sha = "b" * 40
    store.write_artifact(run.run_id, "contribution.patch", "durable patch\n")
    store.save(run, event="fixture.submitting", details={})

    bundle = create_state_bundle(store, tmp_path / "state.zip")
    restored_database = restore_state_bundle(tmp_path / "restored", bundle)
    restored = RunStore(restored_database.parent)

    assert restored.get(run.run_id).commit_sha is None
    assert (
        restored.artifact_dir(run.run_id).joinpath("contribution.patch").read_text()
        == "durable patch\n"
    )


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
