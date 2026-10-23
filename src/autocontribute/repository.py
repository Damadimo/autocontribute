"""Safe, pinned repository workspaces and exact file editing primitives."""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final
from urllib.parse import urlsplit

from autocontribute.exceptions import RepositoryError
from autocontribute.host_environment import proxy_environment

_FULL_SHA: Final = re.compile(r"^[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?$")
_GIT_TIMEOUT_SECONDS: Final = 120
_GIT_FETCH_TIMEOUT_SECONDS: Final = 900
_MAX_ERROR_CHARACTERS: Final = 4_000
_FILTER_COMMAND_KEY: Final = re.compile(r"filter\..+\.(?:clean|smudge|process)", re.DOTALL)
_PATCH_DIFF_ARGUMENTS: Final = (
    "diff",
    "--cached",
    "--binary",
    "--full-index",
    "--no-color",
    "--no-ext-diff",
    "--no-textconv",
    "--no-renames",
    "--src-prefix=a/",
    "--dst-prefix=b/",
    "HEAD",
    "--",
)

# Git runs with no repository credentials and executes no repository hooks or
# filters. Inherit only the operator-controlled process settings needed to find
# Git and create temporary files, plus the proxy and CA settings that reach a
# public HTTPS remote. In particular, do not copy the model, GitHub, cloud,
# Python, or dynamic-loader variables that commonly coexist in the worker process.
_GIT_HOST_ENVIRONMENT_ALLOWLIST: Final[frozenset[str]] = frozenset(
    {
        "COMSPEC",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "WINDIR",
    }
)

# Repository containers can write the working tree, so these keep host git from running
# anything the tree or a tampered .git/config names: hooks, an fsmonitor daemon, external
# diff programs, and the LFS filters. Diff commands add --no-ext-diff and --no-textconv,
# and other filter drivers are refused (see _refuse_filter_commands).
_GIT_SAFETY_OPTIONS: Final[tuple[str, ...]] = (
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "diff.external=",
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
class TreeEntry:
    """One file or submodule in the tree of the base commit."""

    path: str
    object_id: str
    # None for a submodule, whose object is a commit of another repository.
    size: int | None


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

    def changed_paths(self) -> list[str]:
        """Return every path represented by the complete reconstructable patch."""

        with self._temporary_index() as environment:
            output = self._git_bytes(
                [
                    "diff",
                    "--cached",
                    "--name-only",
                    "-z",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--no-renames",
                    "HEAD",
                    "--",
                ],
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
        return self.patch_bytes()

    def patch_bytes(self) -> bytes:
        """Return the patch of tracked changes and new non-ignored files since the base.

        Unlike :meth:`diff_bytes`, symlinks, mode changes and binary files stay in the patch so
        the diff gates can judge them.
        """

        with self._temporary_index() as environment:
            return self._git_bytes(list(_PATCH_DIFF_ARGUMENTS), environment=environment)

    def apply_patch(self, patch: str) -> None:
        """Apply a patch to the working tree, after ``git apply --check`` accepts all of it."""

        if not patch:
            raise RepositoryError("Refusing to apply an empty patch")
        self._assert_base_commit()
        # git apply reads the files it patches through the clean filter.
        self._refuse_filter_commands()
        content = patch.encode("utf-8")
        self._git_bytes(["apply", "--check", "--whitespace=nowarn", "-"], input_bytes=content)
        self._git_bytes(["apply", "--whitespace=nowarn", "-"], input_bytes=content)

    def fetch_tags(self, *, allow_local_source: bool = False) -> None:
        """Fetch the history and tags that version tools such as setuptools-scm read (§B5).

        The clone is shallow and tagless. History comes without trees or blobs, so the
        repository grows by its commits only.
        """

        shallow = self._run_git(["rev-parse", "--is-shallow-repository"]).stdout.strip()
        unshallow = ["--filter=tree:0", "--unshallow"] if shallow == "true" else []
        self._fetch(
            ["fetch", "--quiet", *unshallow, "--tags", "origin"],
            allow_local_source=allow_local_source,
        )

    def fetch_submodules(self, *, allow_local_source: bool = False) -> None:
        """Check out every submodule at the commit the base records, over HTTPS only."""

        self._fetch(
            ["submodule", "update", "--init", "--recursive", "--depth=1"],
            allow_local_source=allow_local_source,
        )

    def restore_base(self) -> list[str]:
        """Undo every change a patch would carry: restore tracked files, delete new ones.

        Ignored files stay. Returns the paths that were restored or deleted.
        """

        with self._temporary_index() as environment:
            output = self._git_bytes(
                [
                    "diff",
                    "--cached",
                    "--name-status",
                    "-z",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--no-renames",
                    "HEAD",
                    "--",
                ],
                environment=environment,
            )
        fields = [_decode_git_path(item) for item in output.split(b"\0") if item]
        changes = list(zip(fields[::2], fields[1::2], strict=True))
        for status, relative_path in changes:
            if status == "A":
                # A new symlink goes too; only its parent directories must be real ones.
                parent = PurePosixPath(relative_path).parent
                directory = (
                    self.path
                    if parent == PurePosixPath(".")
                    else self._resolve_path(str(parent), must_exist=True)
                )
                target = directory / PurePosixPath(relative_path).name
                try:
                    if stat.S_ISDIR(os.lstat(target).st_mode):
                        # A new nested repository is one added path; rmtree never follows
                        # a symlink inside it.
                        shutil.rmtree(target)
                    else:
                        target.unlink()
                except OSError as exc:
                    raise RepositoryError(f"Could not delete {relative_path}: {exc}") from exc
        restored = [path for status, path in changes if status != "A"]
        if restored:
            # A file named like a glob must restore only itself.
            literal = {**_git_environment(), "GIT_LITERAL_PATHSPECS": "1"}
            self._git_bytes(["checkout", "HEAD", "--", *restored], environment=literal)
        return sorted(path for _, path in changes)

    def remove_ignored(self) -> None:
        """Delete everything Git ignores, so a recipe is replayed on a pristine tree."""

        # -f twice also removes ignored directories that hold a Git repository of their own.
        self._git_bytes(["clean", "-f", "-f", "-d", "-X", "-q"])

    def ignored_paths(self) -> list[str]:
        """List untracked paths Git ignores; a directory ignored as a whole ends in ``/``."""

        output = self._git_bytes(
            ["ls-files", "-z", "--others", "--ignored", "--exclude-standard", "--directory"]
        )
        return sorted(_decode_git_path(item) for item in output.split(b"\0") if item)

    def base_tree(self) -> list[TreeEntry]:
        """List every file and submodule of the base commit.

        This reads Git objects only, so neither the working tree nor the index, which a
        container may have changed, affects the result. Paths that are not UTF-8 are left out.
        """

        output = self._git_bytes(["ls-tree", "-r", "-l", "-z", "--full-tree", self.base_sha])
        entries: list[TreeEntry] = []
        for record in output.split(b"\0"):
            metadata, separator, raw_path = record.partition(b"\t")
            fields = metadata.split()
            if not separator or len(fields) != 4:
                continue
            try:
                path = raw_path.decode("utf-8")
            except UnicodeDecodeError:
                continue
            _, kind, object_id, size = (field.decode("ascii") for field in fields)
            if kind not in {"blob", "commit"}:
                continue
            entries.append(TreeEntry(path, object_id, None if kind == "commit" else int(size)))
        return entries

    def read_blob(self, object_id: str, *, max_bytes: int) -> bytes:
        """Return a blob's committed content; no clean, smudge or textconv filter runs."""

        if not _FULL_SHA.fullmatch(object_id):
            raise RepositoryError("Blob object ID must be a complete hexadecimal SHA")
        data = self._git_bytes(["cat-file", "blob", object_id])
        if len(data) > max_bytes:
            raise RepositoryError(f"Blob {object_id} exceeds the {max_bytes}-byte limit")
        return data

    def _submodule_paths(self) -> list[str]:
        """Every submodule path of the base commit, non-UTF-8 ones included."""

        output = self._git_bytes(["ls-tree", "-r", "-z", "--full-tree", self.base_sha])
        paths: list[str] = []
        for record in output.split(b"\0"):
            metadata, separator, raw_path = record.partition(b"\t")
            if separator and metadata.startswith(b"160000 "):
                # Round-trips through the file-system encoding back to the same bytes.
                paths.append(os.fsdecode(raw_path))
        return paths

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

    def _assert_base_commit(self) -> None:
        current = self._run_git(["rev-parse", "--verify", "HEAD^{commit}"]).stdout.strip().lower()
        if current != self.base_sha:
            raise RepositoryError(
                f"Workspace HEAD moved from pinned base {self.base_sha} to {current}"
            )

    def _temporary_index(self) -> _TemporaryIndex:
        self._assert_base_commit()
        # `git add --all` runs every file through its clean filter.
        self._refuse_filter_commands()
        return _TemporaryIndex(self)

    def _refuse_filter_commands(self) -> None:
        """Refuse a workspace whose Git config names a filter program.

        Clones configure none beyond the blanked LFS filter, and containers see .git
        read-only, so one here means .git was tampered with; host git would run it.
        """

        entries = self._git_bytes(["config", "--null", "--list"]).split(b"\0")
        # Later entries override earlier ones, as they do for git itself, so the blanked
        # LFS filter of _GIT_SAFETY_OPTIONS counts as empty.
        effective = {key: value for key, _, value in (entry.partition(b"\n") for entry in entries)}
        for raw_key, value in effective.items():
            key = raw_key.decode("utf-8", errors="replace")
            if value and _FILTER_COMMAND_KEY.fullmatch(key):
                raise RepositoryError(f"Workspace Git config defines a filter command: {key}")

    def _fetch(self, arguments: list[str], *, allow_local_source: bool) -> None:
        self._assert_base_commit()
        self._refuse_filter_commands()
        # Only the HTTPS remotes clones use, and a local fixture source when asked; never a
        # submodule URL with another transport.
        _run_git_at(
            self.path,
            ["-c", "protocol.allow=never", "-c", "protocol.https.allow=always", *arguments],
            timeout_seconds=_GIT_FETCH_TIMEOUT_SECONDS,
            environment=_git_environment(),
            protocol="always" if allow_local_source else "never",
        )

    def _run_git(
        self,
        arguments: list[str],
        *,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        return _run_git_at(
            self.path,
            arguments,
            timeout_seconds=_GIT_TIMEOUT_SECONDS,
            environment=_git_environment(),
            check=check,
        )

    def _git_bytes(
        self,
        arguments: list[str],
        *,
        environment: dict[str, str] | None = None,
        input_bytes: bytes | None = None,
    ) -> bytes:
        command = ["git", *_GIT_SAFETY_OPTIONS, *arguments]
        try:
            result = subprocess.run(
                command,
                cwd=self.path,
                env=environment or _git_environment(),
                input=input_bytes,
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
        # copy2 keeps the index's mtime, which Git compares with each entry's to catch files
        # changed in the same second they were checked out ("racily clean" entries). A fresh
        # mtime made Git trust stale stat data and miss such edits.
        shutil.copy2(real_index, index)
        environment = _git_environment()
        environment["GIT_INDEX_FILE"] = str(index)
        # `git add` runs `git status` inside a submodule's directory to see whether it is
        # dirty, and that child git reads the configuration and attributes of whatever
        # repository a container put there. Submodule paths are therefore left out, so their
        # changes never reach a patch.
        excluded = [f":(exclude,literal){path}" for path in self.workspace._submodule_paths()]
        try:
            self.workspace._git_bytes(
                ["add", "--all", "--", ".", *excluded], environment=environment
            )
        except Exception:
            self._directory.cleanup()
            raise
        self.environment = environment
        return environment

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
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
    environment.update(proxy_environment())
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


__all__ = ["RepositoryWorkspace", "TreeEntry"]
