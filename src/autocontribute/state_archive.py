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

from autocontribute.domain import TERMINAL_STATUSES
from autocontribute.exceptions import StateError
from autocontribute.store import RunStore

_DATABASE_NAME = "state.sqlite3"
_RUN_ID = re.compile(r"^[0-9a-f]{16}$")
_ENTRY_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,255}$")
_MAX_ENTRIES = 10_000
_MAX_BYTES = 1 << 30
_FINISHED_STATUSES = frozenset(status.value for status in TERMINAL_STATUSES)


@dataclass(frozen=True, slots=True)
class StateExport:
    unfinished_runs: int
    files: int
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
    return StateExport(unfinished_runs=len(unfinished), files=len(entries), sha256=digest)


def import_state(
    archive: Path,
    root: Path,
    *,
    force: bool = False,
    release_leases: bool = False,
) -> int:
    """Replace the state at ``root`` with an exported archive; return the leases released.

    The archive is unpacked next to ``root`` and opened as a store, which checks the schema and
    reconciles reservations, and every event chain is verified before anything is replaced.
    """

    root = root.expanduser().resolve()
    if root.is_symlink() or (root.exists() and not root.is_dir()):
        raise StateError(f"State path {root} is not a directory")
    if _holds_state(root) and not force:
        raise StateError(f"{root} already holds state; pass --force to replace it")
    root.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{root.name}.import-", dir=root.parent))
    try:
        _extract(archive, staging)
        try:
            store = RunStore(staging)
            store.verify_event_chains()
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
