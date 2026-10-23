"""One-file snapshots of the local state for runners that keep no disk between jobs."""

from __future__ import annotations

import gzip
import hashlib
import os
import re
import shutil
import sqlite3
import stat
import tarfile
import tempfile
import uuid
import zlib
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from autocontribute.domain import TERMINAL_STATUSES, RunManifest, RunStatus
from autocontribute.exceptions import StateError
from autocontribute.store import RunStore

_DATABASE_NAME = "state.sqlite3"
_RUN_ID = re.compile(r"^[0-9a-f]{16}$")
_ENTRY_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,255}$")
_MAX_ENTRIES = 10_000
_MAX_BYTES = 1 << 30
_FINISHED_STATUSES = frozenset(status.value for status in TERMINAL_STATUSES)
# Only an approval, given by a person outside any preparation, moves a run into these.
_APPROVED_STATUSES = frozenset({RunStatus.APPROVED, RunStatus.SUBMITTING, RunStatus.PR_OPEN})
_WAITING_STATUSES = frozenset({RunStatus.READY_FOR_APPROVAL, RunStatus.APPROVED})
# Rows that _assert_extends compares itself, or bookkeeping that no decision reads; every other
# table may only gain rows.
_REWRITABLE_TABLES = frozenset(
    {
        "runs",
        "circuit_breaker",
        "leases",
        "lease_generations",
        "manifest_artifact_sync",
        "schema_metadata",
    }
)


@dataclass(frozen=True, slots=True)
class StateExport:
    unfinished_runs: int
    sha256: str


def export_state(store: RunStore, output: Path) -> StateExport:
    """Write the database and the evidence of unfinished runs as one deterministic .tar.gz.

    Equal state gives equal bytes, so a runner commits the archive only when it changed.
    Workspaces are left out; a publisher rebuilds them from the patch.
    """

    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".autocontribute-export-", dir=output.parent) as work:
        snapshot = Path(work) / _DATABASE_NAME
        store.backup(snapshot)
        # The run list comes from the snapshot, so the archive holds evidence for exactly the
        # runs its database describes.
        with closing(sqlite3.connect(snapshot)) as connection:
            rows = connection.execute("SELECT run_id, status FROM runs").fetchall()
        unfinished = sorted(
            str(run_id) for run_id, status in rows if status not in _FINISHED_STATUSES
        )
        entries = [(_DATABASE_NAME, snapshot)]
        for run_id in unfinished:
            entries.extend(_run_evidence(store.runs_dir, run_id))
        entries.sort()
        archive = Path(work) / "state.tar.gz"
        _write_archive(archive, entries)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        archive.replace(output)
    return StateExport(unfinished_runs=len(unfinished), sha256=digest)


def import_state(
    archive: Path,
    root: Path,
    *,
    force: bool = False,
    release_leases: bool = False,
    append_only: bool = False,
) -> int:
    """Replace the state at ``root`` with an exported archive; return the leases released.

    The archive is unpacked next to ``root`` and opened as a store, which checks the schema and
    reconciles reservations, and every event chain is verified before anything is replaced.
    With ``append_only`` the archive comes from a job that ran untrusted code, and it replaces
    the state at ``root`` (empty if there is none) only if it extends that state.
    """

    root = root.expanduser().resolve()
    if root.is_symlink() or (root.exists() and not root.is_dir()):
        raise StateError(f"State path {root} is not a directory")
    if _holds_state(root) and not (force or append_only):
        raise StateError(f"{root} already holds state; pass --force to replace it")
    root.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{root.name}.import-", dir=root.parent))
    try:
        _extract(archive, staging)
        try:
            store = RunStore(staging)
            store.verify_event_chains()
            if append_only:
                _assert_extends(RunStore(root), store)
        except sqlite3.DatabaseError as exc:
            raise StateError(f"The archived database is not usable state: {exc}") from exc
        released = store.release_all_leases() if release_leases else 0
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    if root.exists():
        retired = root.with_name(f".{root.name}.replaced-{uuid.uuid4().hex}")
        root.rename(retired)
        staging.rename(root)
        shutil.rmtree(retired, ignore_errors=True)
    else:
        staging.rename(root)
    return released


def _assert_extends(trusted: RunStore, prepared: RunStore) -> None:
    """Refuse a prepared state that drops or rewrites what the trusted state holds.

    A preparation adds runs and events, may start a safety stop, and cancels runs whose
    approval can no longer publish. It never approves or publishes, and never ends a stop.
    """

    with closing(sqlite3.connect(prepared.database_path)) as connection:
        connection.execute("ATTACH DATABASE ? AS trusted", (str(trusted.database_path),))
        tables = [
            str(name)
            for (name,) in connection.execute(
                "SELECT name FROM trusted.sqlite_master "
                "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
        for table in tables:
            if table in _REWRITABLE_TABLES:
                continue
            # Table names come from the trusted schema, which the store checked.
            (dropped,) = connection.execute(
                f'SELECT count(*) FROM (SELECT * FROM trusted."{table}" '
                f'EXCEPT SELECT * FROM main."{table}")'
            ).fetchone()
            if dropped:
                raise StateError(
                    f"The prepared state drops or rewrites {dropped} saved {table} row(s)"
                )
        changed = connection.execute(
            "SELECT run_id, main.runs.status, main.runs.manifest_json "
            "FROM (SELECT * FROM trusted.runs EXCEPT SELECT * FROM main.runs) "
            "LEFT JOIN main.runs USING (run_id)"
        ).fetchall()
        added = connection.execute(
            "SELECT run_id, status, manifest_json FROM main.runs "
            "WHERE run_id NOT IN (SELECT run_id FROM trusted.runs)"
        ).fetchall()
    before = trusted.circuit_breaker_status()
    after = prepared.circuit_breaker_status()
    if after.epoch != before.epoch or (before.is_tripped and not after.is_tripped):
        raise StateError("The prepared state ends a safety stop")
    for run_id, status, manifest_json in added:
        if _prepared_run(run_id, status, manifest_json).status in _APPROVED_STATUSES:
            raise StateError(f"The prepared state adds run {run_id} as {status}")
    for run_id, status, manifest_json in changed:
        if status is None:
            raise StateError(f"The prepared state drops run {run_id}")
        saved = trusted.get(run_id)
        current = _prepared_run(run_id, status, manifest_json)
        if not _preparation_may_change(saved, current):
            raise StateError(
                f"The prepared state rewrites run {run_id} "
                f"({saved.status.value} to {current.status.value})"
            )


def _prepared_run(run_id: object, status: object, manifest_json: object) -> RunManifest:
    try:
        manifest = RunManifest.model_validate_json(str(manifest_json))
    except ValueError as exc:
        raise StateError(f"The prepared state holds an invalid run {run_id}") from exc
    if manifest.run_id != run_id or manifest.status.value != status:
        raise StateError(f"The prepared run {run_id} disagrees with its state row")
    return manifest


def _preparation_may_change(saved: RunManifest, current: RunManifest) -> bool:
    if saved.status == RunStatus.PR_OPEN:
        # Lifecycle observation may record what it saw, but the pull request stays tracked.
        return (
            current.status == RunStatus.PR_OPEN
            and current.pull_request_url == saved.pull_request_url
        )
    if saved.status == RunStatus.SUBMITTING:
        return False
    if saved.status in _WAITING_STATUSES:
        return current.status == RunStatus.CANCELLED
    if saved.status in TERMINAL_STATUSES:
        return current.status == saved.status
    return current.status not in _APPROVED_STATUSES


def _run_evidence(runs_dir: Path, run_id: str) -> list[tuple[str, Path]]:
    if not _RUN_ID.fullmatch(run_id):
        raise StateError(f"Run identifier {run_id!r} cannot name an archive entry")
    directory = runs_dir / run_id
    if directory.is_symlink():
        raise StateError(f"Run evidence {directory} is a symbolic link")
    if not directory.is_dir():
        return []
    entries: list[tuple[str, Path]] = []
    for current, directories, files in os.walk(directory):
        for name in (*directories, *files):
            path = Path(current) / name
            mode = path.lstat().st_mode
            if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)) or not _ENTRY_NAME.fullmatch(name):
                raise StateError(f"Run evidence {path} is not a plainly named file or directory")
            if stat.S_ISREG(mode):
                entries.append((f"runs/{run_id}/{path.relative_to(directory).as_posix()}", path))
    return entries


def _write_archive(target: Path, entries: list[tuple[str, Path]]) -> None:
    with (
        target.open("xb") as raw,
        gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed,
        tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as tar,
    ):
        for name, path in entries:
            with _open_regular(path) as source:
                info = tarfile.TarInfo(name)
                info.size = os.fstat(source.fileno()).st_size
                info.mode = 0o644
                tar.addfile(info, source)


def _open_regular(path: Path) -> BinaryIO:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise StateError(f"State file {path} is not a regular file")
        return os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise


def _holds_state(root: Path) -> bool:
    """Whether ``root`` has anything besides the empty directories a new store creates."""

    if not root.exists():
        return False
    for entry in root.iterdir():
        empty_directory = entry.is_dir() and not entry.is_symlink() and not any(entry.iterdir())
        if not (entry.name in {"runs", "workspaces"} and empty_directory):
            return True
    return False


def _extract(archive: Path, staging: Path) -> None:
    """Unpack only the entries an export writes, as regular files, within fixed bounds."""

    seen: set[str] = set()
    total = 0
    try:
        with tarfile.open(archive, mode="r:gz") as tar:
            for member in tar:
                if len(seen) >= _MAX_ENTRIES:
                    raise StateError("The state archive has too many entries")
                parts = _entry_parts(member)
                if member.name in seen:
                    raise StateError(f"The state archive repeats {member.name!r}")
                seen.add(member.name)
                total += member.size
                if total > _MAX_BYTES:
                    raise StateError("The state archive is larger than 1 GiB unpacked")
                source = tar.extractfile(member)
                if source is None:
                    raise StateError(f"The state archive entry {member.name!r} has no content")
                target = staging.joinpath(*parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                with source, target.open("xb") as written:
                    shutil.copyfileobj(source, written)
    except (OSError, EOFError, tarfile.TarError, zlib.error) as exc:
        raise StateError(f"The state archive could not be read: {exc}") from exc
    if _DATABASE_NAME not in seen:
        raise StateError(f"The state archive has no {_DATABASE_NAME}")


def _entry_parts(member: tarfile.TarInfo) -> tuple[str, ...]:
    parts = tuple(member.name.split("/"))
    expected = member.name == _DATABASE_NAME or (
        len(parts) >= 3
        and parts[0] == "runs"
        and _RUN_ID.fullmatch(parts[1]) is not None
        and all(_ENTRY_NAME.fullmatch(part) and part not in {".", ".."} for part in parts[2:])
    )
    if not member.isreg() or not expected:
        raise StateError(f"The state archive has an unexpected entry {member.name!r}")
    return parts


__all__ = ["StateExport", "export_state", "import_state"]
