"""Host-side file access to a workspace that sandboxed commands can also write.

The workspace is bind-mounted into the agent's container, so anything in it, including a
symlink to any host path, may have been planted by repository code. Every access walks the
path one component at a time from a directory descriptor and never follows a symlink.
"""

from __future__ import annotations

import os
import secrets
import stat
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path, PurePosixPath
from typing import Final, Literal

from autocontribute.exceptions import RepositoryError

CONTAINER_WORKSPACE: Final = "/workspace"
MAX_EDIT_BYTES: Final = 2_000_000
_DIRECTORY_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
# O_NONBLOCK keeps a planted FIFO from blocking the open; it is refused right after.
_READ_FLAGS: Final = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_TEMPORARY_FLAGS: Final = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_NEW_FILE_MODE: Final = 0o644
_NEW_DIRECTORY_MODE: Final = 0o755

EntryKind = Literal["file", "directory"]


class WorkspaceFiles:
    """Read, write and list files under one workspace root without following symlinks."""

    def __init__(self, root: Path) -> None:
        if root.is_symlink() or not root.is_dir():
            raise RepositoryError(f"Workspace root is not a real directory: {root}")
        self.root = root.resolve()

    def normalize(self, path: str) -> str:
        """Return the workspace-relative form of a model-supplied path; ``""`` is the root.

        Paths may be relative or start with ``/workspace``, as the agent sees them.
        """

        if not isinstance(path, str) or "\0" in path:
            raise RepositoryError("Path must be a string without NUL bytes")
        if not _is_unicode_text(path):
            raise RepositoryError("Path must be Unicode text without lone surrogates")
        candidate = PurePosixPath(path)
        if candidate.is_absolute():
            try:
                candidate = candidate.relative_to(CONTAINER_WORKSPACE)
            except ValueError as exc:
                raise RepositoryError(f"Path is outside {CONTAINER_WORKSPACE}: {path}") from exc
        if ".." in candidate.parts:
            raise RepositoryError(f"Path cannot contain '..': {path}")
        # Case-folded because .GIT reaches .git on a case-insensitive host filesystem.
        if any(part.casefold() == ".git" for part in candidate.parts):
            raise RepositoryError(f"Path cannot reach a .git directory: {path}")
        normalized = candidate.as_posix()
        return "" if normalized == "." else normalized

    def display(self, relative: str) -> str:
        """Return the container path of a normalized path, for messages to the agent."""

        return f"{CONTAINER_WORKSPACE}/{relative}" if relative else CONTAINER_WORKSPACE

    def kind(self, path: str) -> EntryKind | None:
        """Return whether a path is a file or a directory, or ``None`` when it is absent."""

        parts = self._parts(path)
        if not parts:
            return "directory"
        with _os_errors(path), self._directory(parts[:-1], path=path, create=False) as parent:
            metadata = _entry(parent, parts[-1], path=path)
        if metadata is None:
            return None
        if stat.S_ISDIR(metadata.st_mode):
            return "directory"
        if stat.S_ISREG(metadata.st_mode):
            return "file"
        raise RepositoryError(f"Not a regular file or directory: {path}")

    def read_bytes(self, path: str, *, max_bytes: int = MAX_EDIT_BYTES) -> bytes:
        """Read a regular file of at most ``max_bytes`` bytes."""

        parts = self._file_parts(path)
        with _os_errors(path):
            with self._directory(parts[:-1], path=path, create=False) as parent:
                metadata = _entry(parent, parts[-1], path=path)
                if metadata is None:
                    raise RepositoryError(f"File does not exist: {path}")
                _require_regular(metadata, path)
                descriptor = os.open(parts[-1], _READ_FLAGS, dir_fd=parent)
            return _read_open_file(descriptor, path=path, max_bytes=max_bytes)

    def read_text(self, path: str) -> str:
        """Read a file for editing: UTF-8 text of at most 2 MB."""

        data = self.read_bytes(path)
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RepositoryError(f"File is not UTF-8 text: {path}") from exc

    def write_text(self, path: str, text: str) -> None:
        """Create or replace a file atomically, creating missing parent directories.

        A replaced file keeps its permission bits.
        """

        if not _is_unicode_text(text):
            # JSON tool arguments can carry a lone surrogate escape such as \ud800.
            raise RepositoryError(f"New content is not UTF-8 text: it has a lone surrogate: {path}")
        data = text.encode("utf-8")
        if len(data) > MAX_EDIT_BYTES:
            raise RepositoryError(f"New content is larger than {MAX_EDIT_BYTES} bytes: {path}")
        parts = self._file_parts(path)
        with _os_errors(path), self._directory(parts[:-1], path=path, create=True) as parent:
            name = parts[-1]
            existing = _entry(parent, name, path=path)
            mode = _NEW_FILE_MODE
            if existing is not None:
                _require_regular(existing, path)
                mode = stat.S_IMODE(existing.st_mode)
            temporary = f".autocontribute-{secrets.token_hex(8)}.tmp"
            descriptor = os.open(temporary, _TEMPORARY_FLAGS, 0o600, dir_fd=parent)
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(data)
                    os.fchmod(handle.fileno(), mode)
                # rename(2) replaces a symlink that appears at the target instead of
                # following it.
                os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
            except BaseException:
                with suppress(FileNotFoundError):
                    os.unlink(temporary, dir_fd=parent)
                raise

    def delete(self, path: str) -> None:
        """Delete a regular file."""

        parts = self._file_parts(path)
        with _os_errors(path), self._directory(parts[:-1], path=path, create=False) as parent:
            metadata = _entry(parent, parts[-1], path=path)
            if metadata is None:
                raise RepositoryError(f"File does not exist: {path}")
            _require_regular(metadata, path)
            os.unlink(parts[-1], dir_fd=parent)

    def list_directory(self, path: str, *, depth: int) -> list[str]:
        """List entries up to ``depth`` levels below a directory, skipping hidden ones.

        Returns workspace-relative paths, directories with a trailing slash. Symlinks are
        listed but never entered.
        """

        parts = self._parts(path)
        with _os_errors(path), self._directory(parts, path=path, create=False) as directory:
            return sorted(_list_entries(directory, "/".join(parts), depth))

    def _parts(self, path: str) -> tuple[str, ...]:
        normalized = self.normalize(path)
        return tuple(normalized.split("/")) if normalized else ()

    def _file_parts(self, path: str) -> tuple[str, ...]:
        parts = self._parts(path)
        if not parts:
            raise RepositoryError(f"Path names the workspace directory, not a file: {path}")
        return parts

    @contextmanager
    def _directory(self, parts: tuple[str, ...], *, path: str, create: bool) -> Iterator[int]:
        """Yield a descriptor for the directory at ``parts``, opened one component at a time."""

        descriptor = os.open(self.root, _DIRECTORY_FLAGS)
        try:
            for part in parts:
                if create:
                    with suppress(FileExistsError):
                        os.mkdir(part, _NEW_DIRECTORY_MODE, dir_fd=descriptor)
                metadata = _entry(descriptor, part, path=path)
                if metadata is None:
                    raise RepositoryError(f"Directory does not exist: {path}")
                if not stat.S_ISDIR(metadata.st_mode):
                    raise RepositoryError(f"Path crosses a non-directory: {path}")
                try:
                    child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
                except OSError as exc:
                    # The entry changed after it was checked, for example into a symlink.
                    raise RepositoryError(f"Could not open a directory safely: {path}") from exc
                os.close(descriptor)
                descriptor = child
            yield descriptor
        finally:
            os.close(descriptor)


def _is_unicode_text(text: str) -> bool:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _entry(directory: int, name: str, *, path: str) -> os.stat_result | None:
    try:
        metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(metadata.st_mode):
        raise RepositoryError(f"Refusing a path through a symlink: {path}")
    return metadata


def _read_open_file(descriptor: int, *, path: str, max_bytes: int) -> bytes:
    with os.fdopen(descriptor, "rb") as handle:
        # Checked again on the open descriptor in case the entry was swapped.
        opened = os.fstat(handle.fileno())
        _require_regular(opened, path)
        if opened.st_size > max_bytes:
            raise RepositoryError(
                f"File is larger than {max_bytes} bytes ({opened.st_size} bytes): {path}"
            )
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise RepositoryError(f"File is larger than {max_bytes} bytes: {path}")
    return data


@contextmanager
def _os_errors(path: str) -> Iterator[None]:
    try:
        yield
    except OSError as exc:
        raise RepositoryError(f"{exc.strerror or 'File operation failed'}: {path}") from exc


def _require_regular(metadata: os.stat_result, path: str) -> None:
    if stat.S_ISDIR(metadata.st_mode):
        raise RepositoryError(f"Path is a directory, not a file: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise RepositoryError(f"Not a regular file: {path}")


def _list_entries(directory: int, prefix: str, depth: int) -> Iterator[str]:
    with os.scandir(directory) as entries:
        children = [entry for entry in entries if not entry.name.startswith(".")]
    for entry in children:
        relative = f"{prefix}/{entry.name}" if prefix else entry.name
        if not entry.is_dir(follow_symlinks=False):
            yield relative
            continue
        yield f"{relative}/"
        if depth <= 1:
            continue
        try:
            child = os.open(entry.name, _DIRECTORY_FLAGS, dir_fd=directory)
        except OSError:
            # Replaced or made unreadable while listing; the listing is advisory.
            continue
        try:
            yield from _list_entries(child, relative, depth - 1)
        finally:
            os.close(child)


__all__ = ["CONTAINER_WORKSPACE", "MAX_EDIT_BYTES", "EntryKind", "WorkspaceFiles"]
