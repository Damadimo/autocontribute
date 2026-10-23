"""What a repository declares about building and testing it, read at its base commit.

Detection and the setup agent work from these signals (DESIGN §5.2, research-envsetup.md §B2):
maintainer agent and dev-environment files, CI workflows, task runners, manifests, lockfiles and
version pins, plus the scripts those files call. Everything is read from Git objects of the base
commit, so no repository code runs and nothing a container wrote can change what is seen.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Final

from autocontribute.repository import RepositoryWorkspace, TreeEntry

_MAX_FILE_BYTES: Final = 256_000
_MAX_TOTAL_BYTES: Final = 4_000_000
_MAX_REFERENCED_FILES: Final = 40
_ROOT_SIGNAL_FILES: Final = frozenset(
    {
        ".cargo/config",
        ".cargo/config.toml",
        ".cursor/environment.json",
        ".devcontainer.json",
        ".devcontainer/devcontainer.json",
        ".github/copilot-instructions.md",
        ".gitattributes",
        ".gitmodules",
        ".node-version",
        ".npmrc",
        ".nvmrc",
        ".python-version",
        ".tool-versions",
        ".yarnrc.yml",
        "AGENTS.md",
        "CLAUDE.md",
        "Cargo.toml",
        "GNUmakefile",
        "Makefile",
        "environment.yml",
        "go.mod",
        "go.work",
        "justfile",
        "makefile",
        "noxfile.py",
        "package.json",
        "pixi.toml",
        "pnpm-workspace.yaml",
        "pyproject.toml",
        "rust-toolchain",
        "rust-toolchain.toml",
        "setup.cfg",
        "setup.py",
        "tox.ini",
        "tox.toml",
    }
)
# Files whose content decides what setup installs, wherever they are in the tree (§B11).
_DEPENDENCY_FILE_NAMES: Final = frozenset(
    {
        ".gitmodules",
        ".node-version",
        ".npmrc",
        ".nvmrc",
        ".python-version",
        ".tool-versions",
        ".yarnrc.yml",
        "Cargo.lock",
        "Cargo.toml",
        "Pipfile",
        "Pipfile.lock",
        "bun.lock",
        "bun.lockb",
        "environment.yml",
        "go.mod",
        "go.sum",
        "go.work",
        "go.work.sum",
        "noxfile.py",
        "npm-shrinkwrap.json",
        "package-lock.json",
        "package.json",
        "pdm.lock",
        "pixi.lock",
        "pixi.toml",
        "pnpm-lock.yaml",
        "pnpm-workspace.yaml",
        "poetry.lock",
        "pyproject.toml",
        "rust-toolchain",
        "rust-toolchain.toml",
        "setup.cfg",
        "setup.py",
        "tox.ini",
        "tox.toml",
        "uv.lock",
        "yarn.lock",
    }
)
# Guidance only the setup agent reads; detection builds nothing from them, so editing one must
# not discard a cached environment.
_GUIDANCE_FILES: Final = frozenset(
    {
        ".cursor/environment.json",
        ".devcontainer.json",
        ".devcontainer/devcontainer.json",
        ".gitattributes",
        ".github/copilot-instructions.md",
        "AGENTS.md",
        "CLAUDE.md",
    }
)
# Files whose commands name scripts that CI or a task runner runs (§B7: one level deep).
_COMMAND_FILES: Final = (
    "GNUmakefile",
    "Makefile",
    "justfile",
    "makefile",
    "noxfile.py",
    "package.json",
    "tox.ini",
)
_PATH_REFERENCE: Final = re.compile(r"(?<![\w./-])(\./)?([\w.-]+(?:/[\w.-]+)*)")


@dataclass(frozen=True, slots=True)
class RepositorySignals:
    """The build and test signals of one repository at its base commit."""

    # Every file and submodule path in the base tree.
    paths: frozenset[str]
    # The UTF-8 text of every signal file that was read, by path.
    files: Mapping[str, str]
    # (path, object ID) of every file the environment depends on, sorted: manifests and
    # lockfiles anywhere in the tree, each CI, task-runner and script file that was read, and
    # submodule commits.
    dependency_files: tuple[tuple[str, str], ...]


def read_signals(workspace: RepositoryWorkspace) -> RepositorySignals:
    """Read the signal files of the base commit without running anything from the repository.

    Files over 256 kB, files that are not UTF-8, and anything past a 4 MB total are left
    unread; their object IDs still count as dependencies.
    """

    entries = {entry.path: entry for entry in workspace.base_tree()}
    files: dict[str, str] = {}
    budget = _MAX_TOTAL_BYTES
    for path in sorted(path for path in entries if _is_signal_file(path)):
        budget = _read_text(workspace, entries[path], files, budget)
    referenced = sorted(
        path
        for path in _referenced_paths(files)
        if path in entries and path not in files and entries[path].size is not None
    )
    for path in referenced[:_MAX_REFERENCED_FILES]:
        budget = _read_text(workspace, entries[path], files, budget)
    dependencies = {
        (entry.path, entry.object_id)
        for entry in entries.values()
        if entry.size is None
        or (entry.path in files and not _is_guidance_file(entry.path))
        or PurePosixPath(entry.path).name in _DEPENDENCY_FILE_NAMES
        or _is_requirements_file(entry.path)
    }
    return RepositorySignals(frozenset(entries), files, tuple(sorted(dependencies)))


def _is_signal_file(path: str) -> bool:
    if path in _ROOT_SIGNAL_FILES or _is_contributing_guide(path):
        return True
    pure = PurePosixPath(path)
    directory, name = str(pure.parent), pure.name
    if directory == ".github/workflows":
        return name.endswith((".yml", ".yaml"))
    return pure.suffix == ".txt" and (
        directory == "requirements" or (directory == "." and "requirements" in name)
    )


def _is_contributing_guide(path: str) -> bool:
    pure = PurePosixPath(path)
    return str(pure.parent) in {".", ".github", "docs"} and pure.name.upper().startswith(
        "CONTRIBUTING"
    )


def _is_guidance_file(path: str) -> bool:
    return path in _GUIDANCE_FILES or _is_contributing_guide(path)


def _is_requirements_file(path: str) -> bool:
    pure = PurePosixPath(path)
    return pure.suffix == ".txt" and ("requirements" in pure.name or "requirements" in pure.parts)


def _read_text(
    workspace: RepositoryWorkspace, entry: TreeEntry, files: dict[str, str], budget: int
) -> int:
    if entry.size is None or entry.size > min(_MAX_FILE_BYTES, budget):
        return budget
    try:
        files[entry.path] = workspace.read_blob(entry.object_id, max_bytes=_MAX_FILE_BYTES).decode(
            "utf-8"
        )
    except UnicodeDecodeError:
        return budget
    return budget - entry.size


def _referenced_paths(files: Mapping[str, str]) -> set[str]:
    """Paths that workflow steps and task runners mention as scripts to run."""

    referenced: set[str] = set()
    for path, text in files.items():
        if not (path.startswith(".github/workflows/") or path in _COMMAND_FILES):
            continue
        for match in _PATH_REFERENCE.finditer(text):
            dot_slash, candidate = match.groups()
            if dot_slash or "/" in candidate or candidate.endswith(".sh"):
                referenced.add(candidate)
    return referenced


__all__ = ["RepositorySignals", "read_signals"]
