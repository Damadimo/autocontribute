"""Copies of a run's workspace (DESIGN §5.4).

The agent works in the clone ``W``. ``S`` is a copy of ``W`` taken right after environment
setup and never modified; validation patches a copy ``V`` of ``S`` and red/green a copy ``R``,
so stray files and build output from the agent's work never reach them.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Final

from autocontribute.exceptions import RepositoryError

_COPY_TIMEOUT_SECONDS: Final = 1_800


def copy_workspace(source: Path, destination: Path) -> None:
    """Copy a workspace tree to a new directory, keeping symlinks as symlinks.

    File data is shared copy-on-write where the filesystem supports it: ``cp -c`` (clonefile)
    on macOS and ``cp --reflink=auto`` on Linux, both of which copy the data otherwise. A
    ``cp`` without those options falls back to a plain copy in Python.
    """

    if source.is_symlink() or not source.is_dir():
        raise RepositoryError(f"Workspace to copy is not a real directory: {source}")
    if os.path.lexists(destination):
        raise RepositoryError(f"Workspace copy destination already exists: {destination}")
    clone_option = "-c" if sys.platform == "darwin" else "--reflink=auto"
    try:
        copied = subprocess.run(
            ["cp", "-a", clone_option, "--", str(source), str(destination)],
            env={"PATH": os.environ.get("PATH", os.defpath), "LC_ALL": "C"},
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=_COPY_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        copied = None
    if copied is not None and copied.returncode == 0:
        return
    remove_workspace_copy(destination)
    try:
        shutil.copytree(source, destination, symlinks=True)
    except (OSError, shutil.Error) as exc:
        remove_workspace_copy(destination)
        raise RepositoryError(f"Could not copy workspace {source}: {exc}") from exc


def remove_workspace_copy(path: Path) -> None:
    """Delete a workspace or copy, never following a symlink inside it; absent is fine."""

    if not os.path.lexists(path):
        return
    if path.is_symlink() or not path.is_dir():
        raise RepositoryError(
            f"Refusing to delete a workspace that is not a real directory: {path}"
        )
    try:
        shutil.rmtree(path)
    except OSError:
        # Repository code can leave directories without write or search permission.
        _make_directories_writable(path)
        try:
            shutil.rmtree(path)
        except OSError as exc:
            raise RepositoryError(f"Could not delete workspace {path}: {exc}") from exc


def _make_directories_writable(root: Path) -> None:
    _add_owner_permissions(str(root))
    # Top-down, so each directory is fixed before os.walk lists it.
    for directory, subdirectories, _ in os.walk(root):
        for name in subdirectories:
            _add_owner_permissions(os.path.join(directory, name))


def _add_owner_permissions(directory: str) -> None:
    metadata = os.lstat(directory)
    if stat.S_ISDIR(metadata.st_mode):
        os.chmod(directory, stat.S_IMODE(metadata.st_mode) | stat.S_IRWXU)


__all__ = ["copy_workspace", "remove_workspace_copy"]
