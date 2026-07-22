"""Atomic, checksummed backups of durable state and human-review evidence."""

from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import stat
import tempfile
import zipfile
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Final

from pydantic import BaseModel, ConfigDict, Field

from autocontribute.domain import RunManifest, RunStatus
from autocontribute.evaluation import EvaluationStore
from autocontribute.exceptions import PolicyError, StateError
from autocontribute.preparation import (
    validate_preparation_fingerprint,
    validate_validation_artifact,
)
from autocontribute.store import RunStore

_BUNDLE_SCHEMA_VERSION: Final = 1
_MAX_BUNDLE_FILES: Final = 100_000
_MAX_BUNDLE_FILE_BYTES: Final = 250_000_000
_MAX_BUNDLE_BYTES: Final = 5_000_000_000
_COPY_CHUNK_BYTES: Final = 1024 * 1024
_PREPARED_RUN_STATUSES: Final = frozenset(
    {
        RunStatus.READY_FOR_APPROVAL,
        RunStatus.APPROVED,
        RunStatus.SUBMITTING,
        RunStatus.PR_OPEN,
    }
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class BundleFile(_StrictModel):
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size: int = Field(ge=0, le=_MAX_BUNDLE_FILE_BYTES)


class BundleManifest(_StrictModel):
    schema_version: int = Field(ge=1, le=1)
    created_at: datetime
    files: dict[str, BundleFile]


def create_state_bundle(
    store: RunStore,
    destination: Path,
    *,
    overwrite: bool = False,
) -> Path:
    """Create one verified generation containing SQLite, runs, and evaluations."""

    requested_target = destination.expanduser()
    if requested_target.is_symlink():
        raise StateError("Backup bundle destination cannot be a symbolic link")
    target = requested_target.resolve()
    _validate_bundle_destination(store, target)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and not target.is_file():
        raise StateError("Backup bundle destination must be a regular file path")
    if target.exists() and not overwrite:
        raise StateError("Backup bundle destination already exists; pass overwrite explicitly")

    store.synchronize_manifest_artifacts()
    staging = Path(tempfile.mkdtemp(prefix=".autocontribute-bundle.", dir=target.parent))
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        first_snapshot = store.create_snapshot(staging / "state.sqlite3")
        _copy_tree(store.runs_dir, staging / "runs")
        evaluation_root = store.root / "evaluations"
        if evaluation_root.exists():
            _copy_tree(evaluation_root, staging / "evaluations")
        else:
            (staging / "evaluations").mkdir(mode=0o700)

        # Any SQLite-backed writer racing the filesystem copy changes this second snapshot.
        # A non-database artifact race is caught by the manifest/evaluation validation below.
        second_snapshot = store.create_snapshot(staging / "state.after.sqlite3")
        if _file_digest(first_snapshot) != _file_digest(second_snapshot):
            raise StateError("Durable state changed during backup; retry after active work stops")
        second_snapshot.unlink()

        staged_store = RunStore(staging)
        staged_store.verify_event_chains()
        _validate_run_manifests(staged_store)
        _validate_workspace_independent_recovery(staged_store)
        _validate_prepared_run_artifacts(staged_store)
        EvaluationStore(staged_store).list()

        files = _inventory(staging)
        manifest = BundleManifest(
            schema_version=_BUNDLE_SCHEMA_VERSION,
            created_at=datetime.now(UTC),
            files=files,
        )
        with zipfile.ZipFile(
            temporary,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=6,
        ) as archive:
            archive.writestr(
                "bundle-manifest.json",
                manifest.model_dump_json(indent=2) + "\n",
            )
            for relative in sorted(files):
                archive.write(staging / relative, arcname=relative)
        with temporary.open("rb") as bundle_file:
            os.fsync(bundle_file.fileno())
        if overwrite:
            os.replace(temporary, target)
        else:
            try:
                os.link(temporary, target, follow_symlinks=False)
            except FileExistsError as exc:
                raise StateError("Backup bundle destination appeared during creation") from exc
            temporary.unlink()
        _fsync_directory(target.parent)
        return target
    except StateError:
        raise
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        raise StateError(f"Could not create complete state bundle: {exc}") from exc
    finally:
        temporary.unlink(missing_ok=True)
        shutil.rmtree(staging, ignore_errors=True)


def restore_state_bundle(root: Path, source: Path) -> Path:
    """Verify and atomically promote a complete state generation into an absent root."""

    requested_source = source.expanduser()
    if requested_source.is_symlink():
        raise StateError("Backup bundle source cannot be a symbolic link")
    try:
        bundle = requested_source.resolve(strict=True)
    except OSError as exc:
        raise StateError(f"Backup bundle source is unavailable: {exc}") from exc
    if not bundle.is_file():
        raise StateError("Backup bundle source must be a regular file")

    requested_root = root.expanduser()
    if requested_root.is_symlink():
        raise StateError("State storage root cannot be a symbolic link during restore")
    target = requested_root.resolve()
    if target.exists():
        raise StateError("Complete bundle restore requires an absent storage root")
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{target.name}.restore.", dir=target.parent))
    try:
        with zipfile.ZipFile(bundle, mode="r") as archive:
            manifest, members = _validate_archive(archive)
            for relative, member in members.items():
                destination = staging / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                digest = hashlib.sha256()
                copied = 0
                with (
                    archive.open(member, mode="r") as source_file,
                    destination.open("xb") as destination_file,
                ):
                    while chunk := source_file.read(_COPY_CHUNK_BYTES):
                        copied += len(chunk)
                        if copied > _MAX_BUNDLE_FILE_BYTES:
                            raise StateError("Backup bundle file exceeds the safe restore limit")
                        digest.update(chunk)
                        destination_file.write(chunk)
                    destination_file.flush()
                    os.fsync(destination_file.fileno())
                expected = manifest.files[relative]
                if copied != expected.size or digest.hexdigest() != expected.sha256:
                    raise StateError(f"Backup bundle checksum mismatch: {relative}")

        _validate_restorable_database(staging / "state.sqlite3")
        restored_store = RunStore(staging)
        restored_store.verify_event_chains()
        _validate_run_manifests(restored_store)
        _validate_workspace_independent_recovery(restored_store)
        _validate_prepared_run_artifacts(restored_store)
        EvaluationStore(restored_store).list()
        os.rename(staging, target)
        _fsync_directory(target.parent)
        return target / "state.sqlite3"
    except StateError:
        raise
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        raise StateError(f"Could not restore complete state bundle: {exc}") from exc
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)


def _copy_tree(source: Path, destination: Path) -> None:
    if source.is_symlink() or not source.is_dir():
        raise StateError(f"Backup source directory is missing or unsafe: {source.name}")
    destination.mkdir(mode=0o700)
    count = 0
    total = 0
    for path in sorted(source.rglob("*"), key=lambda item: item.relative_to(source).as_posix()):
        if path.is_symlink():
            raise StateError(f"Backup source contains a symbolic link: {path.name}")
        relative = path.relative_to(source)
        target = destination / relative
        if path.is_dir():
            target.mkdir(mode=0o700, exist_ok=True)
            continue
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode):
            raise StateError(f"Backup source contains a non-regular file: {path.name}")
        count += 1
        total += metadata.st_size
        if count > _MAX_BUNDLE_FILES or metadata.st_size > _MAX_BUNDLE_FILE_BYTES:
            raise StateError("Backup source exceeds the safe file limits")
        if total > _MAX_BUNDLE_BYTES:
            raise StateError("Backup source exceeds the safe aggregate size")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target, follow_symlinks=False)


def _validate_bundle_destination(store: RunStore, target: Path) -> None:
    """Keep bundle staging and replacement away from the live state it captures."""

    database_paths = {
        store.database_path,
        Path(f"{store.database_path}-wal"),
        Path(f"{store.database_path}-shm"),
        Path(f"{store.database_path}-journal"),
    }
    if target in database_paths:
        raise StateError("Backup bundle destination cannot replace live SQLite state")

    copied_roots = (store.runs_dir, store.root / "evaluations")
    if any(target.is_relative_to(root) for root in copied_roots):
        raise StateError("Backup bundle destination cannot be inside captured state")


def _inventory(root: Path) -> dict[str, BundleFile]:
    result: dict[str, BundleFile] = {}
    total = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if path.is_symlink():
            raise StateError("Staged backup contains a symbolic link")
        if path.is_dir():
            continue
        if not path.is_file():
            raise StateError("Staged backup contains a non-regular file")
        relative = path.relative_to(root).as_posix()
        size = path.stat().st_size
        total += size
        if len(result) >= _MAX_BUNDLE_FILES or size > _MAX_BUNDLE_FILE_BYTES:
            raise StateError("Staged backup exceeds the safe file limits")
        if total > _MAX_BUNDLE_BYTES:
            raise StateError("Staged backup exceeds the safe aggregate size")
        result[relative] = BundleFile(sha256=_file_digest(path), size=size)
    if "state.sqlite3" not in result:
        raise StateError("Staged backup is missing SQLite state")
    return result


def _validate_archive(
    archive: zipfile.ZipFile,
) -> tuple[BundleManifest, dict[str, zipfile.ZipInfo]]:
    infos = archive.infolist()
    if len(infos) > _MAX_BUNDLE_FILES + 1:
        raise StateError("Backup bundle contains too many files")
    by_name: dict[str, zipfile.ZipInfo] = {}
    folded: set[str] = set()
    total = 0
    for info in infos:
        name = info.filename
        path = PurePosixPath(name)
        if (
            info.is_dir()
            or not name
            or "\\" in name
            or path.is_absolute()
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise StateError("Backup bundle contains an unsafe member path")
        unix_mode = info.external_attr >> 16
        file_type = stat.S_IFMT(unix_mode)
        if file_type not in {0, stat.S_IFREG}:
            raise StateError("Backup bundle contains an unsafe member type")
        if info.flag_bits & 0x1:
            raise StateError("Backup bundle contains an encrypted member")
        if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
            raise StateError("Backup bundle uses an unsupported compression method")
        if name in by_name or name.casefold() in folded:
            raise StateError("Backup bundle contains a duplicate member")
        if info.file_size > _MAX_BUNDLE_FILE_BYTES:
            raise StateError("Backup bundle member exceeds the safe size limit")
        total += info.file_size
        if total > _MAX_BUNDLE_BYTES:
            raise StateError("Backup bundle exceeds the safe aggregate size")
        by_name[name] = info
        folded.add(name.casefold())
    manifest_info = by_name.pop("bundle-manifest.json", None)
    if manifest_info is None or manifest_info.file_size > 1_000_000:
        raise StateError("Backup bundle manifest is missing or oversized")
    try:
        manifest = BundleManifest.model_validate_json(archive.read(manifest_info))
    except ValueError as exc:
        raise StateError("Backup bundle manifest is invalid") from exc
    if manifest.schema_version != _BUNDLE_SCHEMA_VERSION:
        raise StateError("Backup bundle schema is unsupported")
    if set(manifest.files) != set(by_name):
        raise StateError("Backup bundle inventory does not match its manifest")
    if "state.sqlite3" not in by_name:
        raise StateError("Backup bundle is missing SQLite state")
    for name in by_name:
        if not (
            name == "state.sqlite3" or name.startswith("runs/") or name.startswith("evaluations/")
        ):
            raise StateError("Backup bundle contains an unsupported state path")
    return manifest, by_name


def _validate_restorable_database(path: Path) -> None:
    """Reject invalid or empty SQLite state before RunStore can initialize or migrate it."""

    validation: sqlite3.Connection | None = None
    try:
        validation = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro&immutable=1", uri=True)
        row = validation.execute("PRAGMA integrity_check").fetchone()
        if row is None or row[0] != "ok":
            raise StateError("SQLite rejected the restored complete state snapshot")
        validation.row_factory = sqlite3.Row
        RunStore._validate_restorable_schema(validation)
    except sqlite3.Error as exc:
        raise StateError(f"SQLite rejected the restored complete state snapshot: {exc}") from exc
    finally:
        if validation is not None:
            validation.close()


def _validate_run_manifests(store: RunStore) -> None:
    manifests = store.oldest_runs(limit=10_000)
    with store._connection() as connection:
        count_row = connection.execute("SELECT count(*) FROM runs").fetchone()
    if count_row is None or count_row[0] != len(manifests):
        raise StateError("Backup run corpus exceeds the supported integrity bound")
    expected_ids = {manifest.run_id for manifest in manifests}
    actual_ids = {
        path.name for path in store.runs_dir.iterdir() if path.is_dir() and not path.is_symlink()
    }
    if actual_ids != expected_ids:
        raise StateError("Backup run-artifact directories do not match durable run state")
    for manifest in manifests:
        path = store.runs_dir / manifest.run_id / "manifest.json"
        if path.is_symlink() or not path.is_file():
            raise StateError(f"Run {manifest.run_id} is missing its durable manifest artifact")
        try:
            artifact = RunManifest.model_validate_json(path.read_bytes())
        except (OSError, ValueError) as exc:
            raise StateError(f"Run {manifest.run_id} has an invalid manifest artifact") from exc
        if artifact != manifest:
            raise StateError(f"Run {manifest.run_id} manifest artifact is stale")


def _validate_prepared_run_artifacts(store: RunStore) -> None:
    """Require every prepared outcome to remain independently reviewable after restore."""

    for manifest in store.oldest_runs(limit=10_000):
        if (
            manifest.status not in _PREPARED_RUN_STATUSES
            and manifest.preparation_fingerprint is None
        ):
            continue
        patch = _read_required_run_artifact(store, manifest, "contribution.patch")
        validation = _read_required_run_artifact(store, manifest, "validation.json")
        try:
            validate_preparation_fingerprint(manifest, diff=patch)
            validate_validation_artifact(manifest, artifact=validation)
        except PolicyError as exc:
            raise StateError(
                f"Run {manifest.run_id} has invalid prepared-run recovery artifacts: {exc}"
            ) from exc


def _read_required_run_artifact(
    store: RunStore,
    manifest: RunManifest,
    filename: str,
) -> bytes:
    path = store.runs_dir / manifest.run_id / filename
    if path.is_symlink() or not path.is_file():
        raise StateError(
            f"Run {manifest.run_id} is missing required prepared-run artifact {filename}"
        )
    try:
        return path.read_bytes()
    except OSError as exc:
        raise StateError(
            f"Run {manifest.run_id} prepared-run artifact {filename} could not be read"
        ) from exc


def _validate_workspace_independent_recovery(store: RunStore) -> None:
    """Reject in-flight commits that the workspace-free bundle cannot reproduce."""

    for manifest in store.list_submitting_runs(limit=10_000):
        if manifest.commit_sha is not None:
            raise StateError(
                f"Cannot create a complete backup while submitting run {manifest.run_id} has "
                "a stored commit: the bundle omits its workspace and cannot reproduce that "
                "commit byte-for-byte. Reconcile or finish publication on the persistent worker "
                "before retrying"
            )


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(_COPY_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def _fsync_directory(path: Path) -> None:
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)


__all__ = ["create_state_bundle", "restore_state_bundle"]
