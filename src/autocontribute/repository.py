"""Safe, pinned repository workspaces and exact file editing primitives."""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Iterable, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final
from urllib.parse import urlsplit

from autocontribute.domain import FileEdit
from autocontribute.exceptions import RepositoryError
from autocontribute.redaction import is_sensitive_path

_FULL_SHA: Final = re.compile(r"^[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?$")
_GIT_TIMEOUT_SECONDS: Final = 120
_MAX_ERROR_CHARACTERS: Final = 4_000
_DEFAULT_MAX_FILE_BYTES: Final = 1_000_000

# Git runs with no repository credentials and executes no repository hooks or
# filters. Inherit only the operator-controlled process settings needed to find
# Git, reach a public HTTPS remote through a proxy/custom CA, and create
# temporary files. In particular, do not copy the model, GitHub, cloud, Python,
# or dynamic-loader variables that commonly coexist in the worker process.
_GIT_HOST_ENVIRONMENT_ALLOWLIST: Final[frozenset[str]] = frozenset(
    {
        "ALL_PROXY",
        "COMSPEC",
        "GIT_SSL_CAINFO",
        "GIT_SSL_CAPATH",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "NO_PROXY",
        "PATH",
        "PATHEXT",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "WINDIR",
        "all_proxy",
        "http_proxy",
        "https_proxy",
        "no_proxy",
    }
)

_GIT_SAFETY_OPTIONS: Final[tuple[str, ...]] = (
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "http.followRedirects=false",
    "-c",
    "submodule.recurse=false",
    "-c",
    "filter.lfs.clean=",
    "-c",
    "filter.lfs.smudge=",
    "-c",
    "filter.lfs.required=false",
)


@dataclass(frozen=True, slots=True)
class ContextEntry:
    """A bounded description of one tracked, regular repository file."""

    path: str
    size: int
    lines: int | None
    binary: bool
    content_inspected: bool = True


@dataclass(frozen=True, slots=True)
class TextMatch:
    """One bounded literal reference found without executing repository tooling."""

    query: str
    path: str
    line_number: int
    line: str


@dataclass(frozen=True, slots=True)
class PatchMetrics:
    """Deterministic metrics for the complete working-tree patch."""

    changed_files: int
    insertions: int
    deletions: int
    binary_files: int = 0

    @property
    def changed_lines(self) -> int:
        return self.insertions + self.deletions


class RepositoryWorkspace:
    """A repository checked out at an immutable base commit.

    The Git ``HEAD`` remains at ``base_sha``. Changes live only in the working
    tree, which makes the resulting patch auditable and reproducible.
    """

    def __init__(self, path: Path, base_sha: str) -> None:
        if path.is_symlink():
            raise RepositoryError("Repository workspace cannot be a symlink")
        self.path = path.expanduser().resolve()
        self.base_sha = _validate_sha(base_sha)
        git_dir = self.path / ".git"
        if not self.path.is_dir() or not git_dir.is_dir() or git_dir.is_symlink():
            raise RepositoryError(f"Not a safe Git workspace: {self.path}")
        self._assert_base_commit()

    @classmethod
    def clone(
        cls,
        clone_url: str,
        base_sha: str,
        destination: Path,
        *,
        allow_local_source: bool = False,
        timeout_seconds: int = _GIT_TIMEOUT_SECONDS,
    ) -> RepositoryWorkspace:
        """Fetch exactly ``base_sha`` into a new workspace and detach ``HEAD``.

        Only HTTPS sources are accepted in normal operation. Local repositories
        exist solely for explicit fixture/development use.
        """

        sha = _validate_sha(base_sha)
        source, local_source = _validate_clone_source(clone_url, allow_local_source)
        target = _new_destination(destination)
        target.mkdir(mode=0o700)

        protocol = "always" if local_source else "never"
        environment = _git_environment()
        environment["GIT_LFS_SKIP_SMUDGE"] = "1"
        try:
            _run_git_at(
                None,
                ["init", "--quiet", str(target)],
                timeout_seconds=timeout_seconds,
                environment=environment,
            )
            local_settings = (
                ("core.hooksPath", "/dev/null"),
                ("submodule.recurse", "false"),
                ("filter.lfs.clean", ""),
                ("filter.lfs.smudge", ""),
                ("filter.lfs.required", "false"),
                ("core.autocrlf", "false"),
            )
            for key, value in local_settings:
                _run_git_at(
                    target,
                    ["config", "--local", key, value],
                    timeout_seconds=timeout_seconds,
                    environment=environment,
                    protocol=protocol,
                )
            _run_git_at(
                target,
                ["remote", "add", "origin", source],
                timeout_seconds=timeout_seconds,
                environment=environment,
                protocol=protocol,
            )
            _run_git_at(
                target,
                [
                    "fetch",
                    "--quiet",
                    "--no-tags",
                    "--no-recurse-submodules",
                    "--depth=1",
                    "origin",
                    sha,
                ],
                timeout_seconds=timeout_seconds,
                environment=environment,
                protocol=protocol,
            )
            fetched = _run_git_at(
                target,
                ["rev-parse", "--verify", "FETCH_HEAD^{commit}"],
                timeout_seconds=timeout_seconds,
                environment=environment,
                protocol=protocol,
            ).stdout.strip()
            if fetched.lower() != sha:
                raise RepositoryError(
                    "Fetched commit did not match the requested base SHA; refusing checkout"
                )
            _run_git_at(
                target,
                ["checkout", "--quiet", "--detach", "--force", sha],
                timeout_seconds=timeout_seconds,
                environment=environment,
                protocol=protocol,
            )
            return cls(target, sha)
        except Exception:
            # The directory was required not to exist and was created above, so
            # this cleanup cannot remove pre-existing user data.
            shutil.rmtree(target, ignore_errors=True)
            raise

    def read_file(self, relative_path: str, *, max_bytes: int = _DEFAULT_MAX_FILE_BYTES) -> str:
        """Read one UTF-8 regular file without following symlinks."""

        path = self._resolve_path(relative_path, must_exist=True)
        data = self._read_regular_file(path, max_bytes=max_bytes)
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RepositoryError(f"File is not UTF-8 text: {relative_path}") from exc

    def discard(self) -> None:
        """Remove this run-owned checkout after sensitive generated content is detected."""

        if not self.path.is_dir() or not (self.path / ".git").is_dir():
            raise RepositoryError("Repository workspace cannot be discarded safely")
        shutil.rmtree(self.path)

    # A shorter alias is convenient for agent context assembly.
    read_text = read_file

    def context_index(
        self,
        *,
        max_files: int = 5_000,
        max_file_bytes: int = _DEFAULT_MAX_FILE_BYTES,
        max_total_bytes: int = 64_000_000,
    ) -> list[ContextEntry]:
        """Return a stable, bounded index without reading symlinks/submodules."""

        if max_files < 1 or max_file_bytes < 1 or max_total_bytes < 1:
            raise ValueError("context index limits must be positive")
        entries: list[ContextEntry] = []
        inspected_bytes = 0
        for relative_path in self._tracked_paths():
            try:
                path = self._resolve_path(relative_path, must_exist=True)
                metadata = path.lstat()
            except (FileNotFoundError, RepositoryError):
                continue
            if not stat.S_ISREG(metadata.st_mode):
                continue
            if len(entries) >= max_files:
                raise RepositoryError(
                    "Repository context index exceeds the configured file limit; "
                    "completeness cannot be guaranteed"
                )
            size = metadata.st_size
            if size > max_file_bytes or inspected_bytes + size > max_total_bytes:
                entries.append(
                    ContextEntry(
                        relative_path,
                        size,
                        None,
                        False,
                        content_inspected=False,
                    )
                )
                continue
            data = self._read_regular_file(path, max_bytes=max_file_bytes)
            inspected_bytes += len(data)
            binary = b"\0" in data[:8_192]
            lines: int | None = None
            if not binary:
                try:
                    data.decode("utf-8")
                except UnicodeDecodeError:
                    binary = True
                else:
                    lines = data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)
            entries.append(ContextEntry(relative_path, size, lines, binary))
        return entries

    def search_text(
        self,
        queries: Sequence[str],
        *,
        max_files: int = 5_000,
        max_matches: int = 200,
        max_file_bytes: int = _DEFAULT_MAX_FILE_BYTES,
        max_total_bytes: int = 32_000_000,
        max_line_characters: int = 500,
    ) -> list[TextMatch]:
        """Search tracked UTF-8 files for bounded literal references.

        Queries are treated only as case-insensitive text, never as regular expressions or shell
        input. This gives a planner safe symbol/caller exploration without executing repository
        tooling or allowing a model-controlled query to consume unbounded resources.
        """

        if (
            max_files < 1
            or max_matches < 1
            or max_file_bytes < 1
            or max_total_bytes < 1
            or max_line_characters < 1
        ):
            raise ValueError("repository search limits must be positive")
        materialized: list[str] = []
        seen: set[str] = set()
        for query in queries:
            normalized = query.strip()
            folded_query = normalized.casefold()
            if normalized and folded_query not in seen:
                materialized.append(normalized)
                seen.add(folded_query)
        if not materialized:
            raise RepositoryError("Repository search requires at least one non-empty query")
        if len(materialized) > 20:
            raise RepositoryError("Repository search accepts at most 20 literal queries")
        if any("\0" in query or len(query) > 200 for query in materialized):
            raise RepositoryError("Repository search query is unsafe or exceeds 200 characters")

        folded = [(query, query.casefold()) for query in materialized]
        matches: list[TextMatch] = []
        entries = self.context_index(
            max_files=max_files,
            max_file_bytes=max_file_bytes,
            max_total_bytes=max_total_bytes,
        )
        incomplete = [entry.path for entry in entries if not entry.content_inspected]
        if incomplete:
            raise RepositoryError(
                "Repository search exceeded its byte limits before inspecting every tracked "
                f"file; first incomplete path: {incomplete[0]}"
            )
        for entry in entries:
            if entry.binary:
                continue
            content = self.read_file(entry.path, max_bytes=max_file_bytes)
            for line_number, line in enumerate(content.splitlines(), start=1):
                folded_line = line.casefold()
                for query, folded_query in folded:
                    if folded_query not in folded_line:
                        continue
                    rendered = line
                    if len(rendered) > max_line_characters:
                        rendered = rendered[:max_line_characters] + " [truncated]"
                    if len(matches) >= max_matches:
                        raise RepositoryError(
                            "Repository search exceeds the configured match limit; "
                            "results would be incomplete"
                        )
                    matches.append(
                        TextMatch(
                            query=query,
                            path=entry.path,
                            line_number=line_number,
                            line=rendered,
                        )
                    )
        return matches

    def guidance(
        self,
        *,
        max_files: int = 30,
        max_characters: int = 120_000,
    ) -> dict[str, str]:
        """Read contribution, PR, security, AI, and repository guidance files."""

        if max_files < 1 or max_characters < 1:
            raise ValueError("guidance limits must be positive")
        candidates = [path for path in self._tracked_paths() if _is_guidance_path(path)]
        templates = sorted(path for path in candidates if _is_pull_request_template_path(path))
        if len(templates) > max_files:
            raise RepositoryError(
                "Repository has more pull-request templates than the configured guidance file "
                "limit; refusing to evaluate an incomplete template set"
            )
        other_guidance = sorted(
            (path for path in candidates if not _is_pull_request_template_path(path)),
            key=_guidance_sort_key,
        )
        # Templates are publication requirements, so load every one in full before spending the
        # bounded remainder on generic guidance. This also makes ambiguity detection exhaustive.
        candidates = [*templates, *other_guidance]
        result: dict[str, str] = {}
        remaining = max_characters
        for relative_path in candidates[:max_files]:
            if remaining <= 0:
                if _is_pull_request_template_path(relative_path):
                    raise RepositoryError(
                        "Pull-request templates exceed the configured guidance character limit; "
                        "refusing to validate a truncated template"
                    )
                break
            try:
                content = self.read_file(relative_path, max_bytes=min(remaining * 4, 2_000_000))
            except RepositoryError as exc:
                if _is_pull_request_template_path(relative_path):
                    raise RepositoryError(
                        f"Could not load pull-request template in full: {relative_path}"
                    ) from exc
                continue
            if len(content) > remaining:
                if _is_pull_request_template_path(relative_path):
                    raise RepositoryError(
                        "Pull-request templates exceed the configured guidance character limit; "
                        "refusing to validate a truncated template"
                    )
                suffix = "\n\n[truncated by autocontribute]"
                content = content[: max(0, remaining - len(suffix))] + suffix
            result[relative_path] = content
            remaining -= len(content)
        return result

    def apply_edit(self, edit: FileEdit) -> None:
        """Apply one exact create/replace/delete operation."""

        if not isinstance(edit, FileEdit):
            raise TypeError("edit must be a FileEdit")
        if is_sensitive_path(edit.path):
            raise RepositoryError(f"Refusing to edit sensitive repository path: {edit.path}")
        path = self._resolve_path(edit.path, must_exist=False)
        if self._is_ignored(edit.path):
            raise RepositoryError(f"Edit target is ignored by Git: {edit.path}")

        if edit.operation == "create":
            if _lstat(path) is not None:
                raise RepositoryError(f"Create target already exists: {edit.path}")
            assert edit.content is not None
            self._write_file(path, edit.content.encode("utf-8"), mode=0o644, require_absent=True)
            return

        metadata = _lstat(path)
        if metadata is None:
            raise RepositoryError(f"Edit target does not exist: {edit.path}")
        if stat.S_ISLNK(metadata.st_mode):
            raise RepositoryError(f"Refusing to edit symlink: {edit.path}")
        if not stat.S_ISREG(metadata.st_mode):
            raise RepositoryError(f"Edit target is not a regular file: {edit.path}")

        if edit.operation == "delete":
            path.unlink()
            return

        assert edit.operation == "replace"
        assert edit.find is not None and edit.replace is not None
        if edit.find == "":
            raise RepositoryError("Exact replacement search text cannot be empty")
        original = self._read_regular_file(path, max_bytes=None)
        try:
            text = original.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RepositoryError(f"File is not UTF-8 text: {edit.path}") from exc
        occurrences = text.count(edit.find)
        if occurrences != 1:
            raise RepositoryError(
                f"Exact replacement in {edit.path} requires one match; found {occurrences}"
            )
        updated = text.replace(edit.find, edit.replace, 1).encode("utf-8")
        self._write_file(path, updated, mode=stat.S_IMODE(metadata.st_mode), require_absent=False)

    def apply_edits(self, edits: Iterable[FileEdit]) -> list[str]:
        """Apply edits as a small transaction, restoring originals on failure."""

        materialized = list(edits)
        if not materialized:
            raise RepositoryError("A patch must contain at least one edit")
        sensitive = [edit.path for edit in materialized if is_sensitive_path(edit.path)]
        if sensitive:
            raise RepositoryError(
                f"Refusing to edit sensitive repository path: {sorted(sensitive)[0]}"
            )

        snapshots: dict[str, tuple[bytes | None, int | None]] = {}
        order: list[str] = []
        try:
            for edit in materialized:
                normalized = self._normalize_path(edit.path)
                if normalized not in snapshots:
                    path = self._resolve_path(normalized, must_exist=False)
                    metadata = _lstat(path)
                    if metadata is None:
                        snapshots[normalized] = (None, None)
                    elif stat.S_ISREG(metadata.st_mode):
                        snapshots[normalized] = (
                            self._read_regular_file(path, max_bytes=None),
                            stat.S_IMODE(metadata.st_mode),
                        )
                    else:
                        raise RepositoryError(f"Patch target is not a regular file: {normalized}")
                    order.append(normalized)
                self.apply_edit(edit)
        except Exception as exc:
            try:
                self._restore_snapshots(snapshots, reversed(order))
            except Exception as rollback_exc:
                raise RepositoryError(
                    f"Edit failed and workspace rollback also failed: {rollback_exc}"
                ) from exc
            raise
        return self.changed_paths()

    def changed_paths(self) -> list[str]:
        """Return every path represented by the complete reconstructable patch."""

        with self._temporary_index() as environment:
            output = self._git_bytes(
                ["diff", "--cached", "--name-only", "-z", "--no-renames", "HEAD", "--"],
                environment=environment,
            )
        paths = [_decode_git_path(item) for item in output.split(b"\0") if item]
        for relative_path in paths:
            path = self._resolve_path(relative_path, must_exist=False)
            metadata = _lstat(path)
            if metadata is not None and stat.S_ISLNK(metadata.st_mode):
                raise RepositoryError(f"Patch contains a symlink: {relative_path}")
        return sorted(paths)

    def diff(self) -> str:
        """Return a full-index binary-safe patch, including untracked files."""

        return self.diff_bytes().decode("utf-8", errors="surrogateescape")

    def diff_bytes(self) -> bytes:
        """Return the lossless byte representation used by ``git apply``."""

        # Validate changed paths first so a newly-created symlink can never be
        # serialized into a contribution patch.
        self.changed_paths()
        with self._temporary_index() as environment:
            return self._git_bytes(
                [
                    "diff",
                    "--cached",
                    "--binary",
                    "--full-index",
                    "--no-color",
                    "--no-ext-diff",
                    "--no-renames",
                    "--src-prefix=a/",
                    "--dst-prefix=b/",
                    "HEAD",
                    "--",
                ],
                environment=environment,
            )

    def diff_stat(self) -> str:
        """Return Git's human-readable diffstat for the complete patch."""

        with self._temporary_index() as environment:
            output = self._git_bytes(
                [
                    "diff",
                    "--cached",
                    "--stat",
                    "--no-color",
                    "--no-ext-diff",
                    "--no-renames",
                    "HEAD",
                    "--",
                ],
                environment=environment,
            )
        return output.decode("utf-8", errors="replace")

    # Common spelling used in review UIs.
    diffstat = diff_stat

    def metrics(self) -> PatchMetrics:
        """Measure insertions/deletions without trusting model-supplied counts."""

        with self._temporary_index() as environment:
            output = self._git_bytes(
                [
                    "diff",
                    "--cached",
                    "--numstat",
                    "-z",
                    "--no-renames",
                    "HEAD",
                    "--",
                ],
                environment=environment,
            )
        insertions = 0
        deletions = 0
        binary_files = 0
        files = 0
        for record in output.split(b"\0"):
            if not record:
                continue
            fields = record.split(b"\t", 2)
            if len(fields) != 3:
                raise RepositoryError("Git returned malformed patch metrics")
            added, removed, _path = fields
            files += 1
            if added == b"-" or removed == b"-":
                binary_files += 1
                continue
            try:
                insertions += int(added)
                deletions += int(removed)
            except ValueError as exc:
                raise RepositoryError("Git returned malformed line counts") from exc
        return PatchMetrics(files, insertions, deletions, binary_files)

    def _tracked_paths(self) -> list[str]:
        output = self._git_bytes(["ls-files", "-z", "--cached"])
        return sorted(
            self._normalize_path(_decode_git_path(item)) for item in output.split(b"\0") if item
        )

    def _normalize_path(self, relative_path: str) -> str:
        if not isinstance(relative_path, str) or not relative_path:
            raise RepositoryError("Repository path must be a non-empty string")
        if "\\" in relative_path or any(not character.isprintable() for character in relative_path):
            raise RepositoryError(f"Unsafe repository path: {relative_path!r}")
        raw_parts = relative_path.split("/")
        if any(part in {"", ".", ".."} for part in raw_parts):
            raise RepositoryError(f"Unsafe repository path: {relative_path!r}")
        pure_path = PurePosixPath(relative_path)
        if pure_path.is_absolute() or any(part.casefold() == ".git" for part in pure_path.parts):
            raise RepositoryError(f"Unsafe repository path: {relative_path!r}")
        return pure_path.as_posix()

    def _resolve_path(self, relative_path: str, *, must_exist: bool) -> Path:
        normalized = self._normalize_path(relative_path)
        candidate = self.path.joinpath(*PurePosixPath(normalized).parts)
        current = self.path
        for part in PurePosixPath(normalized).parts:
            current = current / part
            metadata = _lstat(current)
            if metadata is None:
                break
            if stat.S_ISLNK(metadata.st_mode):
                raise RepositoryError(f"Repository path crosses a symlink: {relative_path}")
        if must_exist and _lstat(candidate) is None:
            raise RepositoryError(f"Repository file does not exist: {relative_path}")
        try:
            if os.path.commonpath((str(self.path), str(candidate))) != str(self.path):
                raise RepositoryError(f"Repository path escapes workspace: {relative_path}")
        except ValueError as exc:
            raise RepositoryError(f"Repository path escapes workspace: {relative_path}") from exc
        return candidate

    def _read_regular_file(self, path: Path, *, max_bytes: int | None) -> bytes:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            relative = path.relative_to(self.path)
            raise RepositoryError(f"Refusing to read non-regular file: {relative}")
        if max_bytes is not None and metadata.st_size > max_bytes:
            raise RepositoryError(
                f"File exceeds the {max_bytes}-byte context limit: {path.relative_to(self.path)}"
            )
        try:
            # O_NOFOLLOW closes the final-component race on supported Unix hosts.
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags)
            with os.fdopen(descriptor, "rb") as handle:
                return handle.read()
        except OSError as exc:
            relative = path.relative_to(self.path)
            raise RepositoryError(f"Could not safely read {relative}: {exc}") from exc

    def _write_file(
        self,
        path: Path,
        content: bytes,
        *,
        mode: int,
        require_absent: bool,
    ) -> None:
        self._ensure_parent_directories(path.parent)
        existing = _lstat(path)
        if require_absent and existing is not None:
            raise RepositoryError(f"Create target already exists: {path.relative_to(self.path)}")
        if existing is not None and not stat.S_ISREG(existing.st_mode):
            relative = path.relative_to(self.path)
            raise RepositoryError(f"Refusing to overwrite non-regular path: {relative}")

        descriptor, temporary_name = tempfile.mkstemp(prefix=".autocontribute-", dir=path.parent)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, mode)
            # Recheck after writing the temporary file so a swapped target is
            # detected before the atomic replacement.
            current = _lstat(path)
            if require_absent and current is not None:
                relative = path.relative_to(self.path)
                raise RepositoryError(f"Create target appeared during edit: {relative}")
            if current is not None and not stat.S_ISREG(current.st_mode):
                raise RepositoryError(f"Edit target changed type: {path.relative_to(self.path)}")
            os.replace(temporary, path)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise

    def _ensure_parent_directories(self, parent: Path) -> None:
        relative = parent.relative_to(self.path)
        current = self.path
        for part in relative.parts:
            current = current / part
            metadata = _lstat(current)
            if metadata is None:
                with suppress(FileExistsError):
                    current.mkdir(mode=0o755)
                metadata = _lstat(current)
            if (
                metadata is None
                or stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISDIR(metadata.st_mode)
            ):
                raise RepositoryError(f"Unsafe parent directory: {current.relative_to(self.path)}")

    def _restore_snapshots(
        self,
        snapshots: dict[str, tuple[bytes | None, int | None]],
        paths: Iterable[str],
    ) -> None:
        for relative_path in paths:
            content, mode = snapshots[relative_path]
            path = self._resolve_path(relative_path, must_exist=False)
            if content is None:
                metadata = _lstat(path)
                if metadata is not None:
                    if not stat.S_ISREG(metadata.st_mode):
                        raise RepositoryError(f"Cannot roll back unsafe path: {relative_path}")
                    path.unlink()
            else:
                assert mode is not None
                self._write_file(path, content, mode=mode, require_absent=False)

    def _is_ignored(self, relative_path: str) -> bool:
        result = self._run_git(["check-ignore", "--quiet", "--", relative_path], check=False)
        if result.returncode not in {0, 1}:
            raise RepositoryError(f"Could not determine whether Git ignores {relative_path}")
        return result.returncode == 0

    def _assert_base_commit(self) -> None:
        current = self._run_git(["rev-parse", "--verify", "HEAD^{commit}"]).stdout.strip().lower()
        if current != self.base_sha:
            raise RepositoryError(
                f"Workspace HEAD moved from pinned base {self.base_sha} to {current}"
            )

    def _temporary_index(self) -> _TemporaryIndex:
        self._assert_base_commit()
        return _TemporaryIndex(self)

    def _run_git(
        self,
        arguments: list[str],
        *,
        check: bool = True,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return _run_git_at(
            self.path,
            arguments,
            timeout_seconds=_GIT_TIMEOUT_SECONDS,
            environment=environment or _git_environment(),
            check=check,
        )

    def _git_bytes(
        self,
        arguments: list[str],
        *,
        environment: dict[str, str] | None = None,
    ) -> bytes:
        command = ["git", *_GIT_SAFETY_OPTIONS, *arguments]
        try:
            result = subprocess.run(
                command,
                cwd=self.path,
                env=environment or _git_environment(),
                capture_output=True,
                check=False,
                timeout=_GIT_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RepositoryError(f"Git operation failed safely: {exc}") from exc
        if result.returncode != 0:
            error = result.stderr.decode("utf-8", errors="replace")[-_MAX_ERROR_CHARACTERS:].strip()
            raise RepositoryError(f"Git operation failed: {error or 'unknown Git error'}")
        return result.stdout


class _TemporaryIndex:
    """Build a complete patch without changing the workspace's real index."""

    def __init__(self, workspace: RepositoryWorkspace) -> None:
        self.workspace = workspace
        self._directory: tempfile.TemporaryDirectory[str] | None = None
        self.environment: dict[str, str] | None = None

    def __enter__(self) -> dict[str, str]:
        self._directory = tempfile.TemporaryDirectory(prefix="autocontribute-index-")
        index = Path(self._directory.name) / "index"
        real_index = self.workspace.path / ".git" / "index"
        if not real_index.is_file() or real_index.is_symlink():
            self._directory.cleanup()
            raise RepositoryError("Workspace Git index is missing or unsafe")
        shutil.copyfile(real_index, index)
        environment = _git_environment()
        environment["GIT_INDEX_FILE"] = str(index)
        try:
            self.workspace._git_bytes(["add", "--all", "--", "."], environment=environment)
        except Exception:
            self._directory.cleanup()
            raise
        self.environment = environment
        return environment

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if self._directory is not None:
            self._directory.cleanup()


def _validate_sha(value: str) -> str:
    if not isinstance(value, str) or not _FULL_SHA.fullmatch(value):
        raise RepositoryError("base_sha must be a complete 40- or 64-character hexadecimal SHA")
    return value.lower()


def _validate_clone_source(value: str, allow_local_source: bool) -> tuple[str, bool]:
    if not isinstance(value, str) or not value or "\0" in value or value.startswith("-"):
        raise RepositoryError("Clone source is invalid")
    parsed = urlsplit(value)
    if parsed.scheme == "https":
        has_unsafe_component = (
            not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        )
        if has_unsafe_component:
            raise RepositoryError(
                "HTTPS clone URL must not contain credentials, query, or fragment"
            )
        return value, False
    if parsed.scheme:
        raise RepositoryError("Only credential-free HTTPS clone URLs are allowed")
    if not allow_local_source:
        raise RepositoryError("Local clone sources require allow_local_source=True")
    source = Path(value).expanduser()
    if source.is_symlink() or not source.resolve().is_dir():
        raise RepositoryError("Local clone source must be a real directory")
    return str(source.resolve()), True


def _new_destination(destination: Path) -> Path:
    expanded = destination.expanduser()
    if expanded.name in {"", ".", ".."}:
        raise RepositoryError("Clone destination must name a new directory")
    try:
        parent = expanded.parent.resolve(strict=True)
    except OSError as exc:
        raise RepositoryError(f"Clone destination parent is unavailable: {exc}") from exc
    target = parent / expanded.name
    if _lstat(target) is not None:
        raise RepositoryError(f"Clone destination already exists: {target}")
    return target


def _git_environment() -> dict[str, str]:
    """Build a credential-free environment for public HTTPS and local Git operations."""

    environment = {
        name: value
        for name in _GIT_HOST_ENVIRONMENT_ALLOWLIST
        if (value := os.environ.get(name)) is not None
    }
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "",
            "GIT_PAGER": "cat",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_EXTERNAL_DIFF": "",
            "GIT_LFS_SKIP_SMUDGE": "1",
        }
    )
    return environment


def _run_git_at(
    working_directory: Path | None,
    arguments: list[str],
    *,
    timeout_seconds: int,
    environment: dict[str, str],
    protocol: str = "never",
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    command = [
        "git",
        *_GIT_SAFETY_OPTIONS,
        "-c",
        f"protocol.file.allow={protocol}",
        *arguments,
    ]
    try:
        result = subprocess.run(
            command,
            cwd=working_directory,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RepositoryError(f"Git operation failed safely: {exc}") from exc
    if check and result.returncode != 0:
        error = result.stderr[-_MAX_ERROR_CHARACTERS:].strip()
        raise RepositoryError(f"Git operation failed: {error or 'unknown Git error'}")
    return result


def _lstat(path: Path) -> os.stat_result | None:
    try:
        return path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise RepositoryError(f"Could not inspect repository path {path}: {exc}") from exc


def _decode_git_path(value: bytes) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RepositoryError("Repository contains a non-UTF-8 path") from exc


def _is_guidance_path(relative_path: str) -> bool:
    lowered = relative_path.casefold()
    name = PurePosixPath(lowered).name
    if name in {"agents.md", "readme.md", "readme.rst", "readme.txt"}:
        return True
    if name.startswith(("contributing", "security", "code_of_conduct", "code-of-conduct")):
        return True
    if name.startswith(
        (
            "ai_policy",
            "ai-policy",
            "ai_contribution",
            "ai-contribution",
            "responsible-ai",
            "generative-ai",
        )
    ):
        return True
    return _is_pull_request_template_path(relative_path)


def _is_pull_request_template_path(relative_path: str) -> bool:
    lowered = relative_path.casefold().strip("/")
    name = PurePosixPath(lowered).name
    markdown = name.endswith((".md", ".markdown"))
    return markdown and (
        lowered == ".github/pull_request_template.md"
        or lowered.startswith(".github/pull_request_template/")
        or name.startswith("pull_request_template")
    )


def _guidance_sort_key(relative_path: str) -> tuple[int, str]:
    lowered = relative_path.casefold()
    name = PurePosixPath(lowered).name
    priorities = (
        ("agents", 0),
        ("contributing", 1),
        ("pull_request", 2),
        ("security", 3),
        ("ai", 4),
        ("responsible-ai", 4),
        ("generative-ai", 4),
        ("code", 5),
        ("readme", 6),
    )
    for prefix, priority in priorities:
        if name.startswith(prefix):
            return priority, lowered
    return 7, lowered


__all__ = ["ContextEntry", "PatchMetrics", "RepositoryWorkspace", "TextMatch"]
