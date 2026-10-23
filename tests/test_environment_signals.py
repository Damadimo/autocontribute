from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from autocontribute.environment_signals import read_signals
from autocontribute.environments import dependency_digest
from autocontribute.exceptions import RepositoryError
from autocontribute.repository import RepositoryWorkspace

_SUBMODULE_COMMIT = "1" * 40


def _git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull},
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def _commit(root: Path, files: dict[str, str | bytes]) -> RepositoryWorkspace:
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
    if not (root / ".git").exists():
        _git(root, "init", "--quiet")
    _git(root, "add", "--all")
    _git(root, "-c", "user.name=F", "-c", "user.email=f@example.invalid", "commit", "-qm", "c")
    return RepositoryWorkspace(root, _git(root, "rev-parse", "HEAD"))


_BASE = {
    "pyproject.toml": "[project]\nname = 'demo'\n",
    "uv.lock": "version = 1\n",
    "README.md": "readme\n",
    "Makefile": "test:\n\t./tools/run-tests --fast\n",
    "tools/run-tests": "#!/bin/sh\npytest\n",
    "tools/unused": "#!/bin/sh\nexit 0\n",
    ".github/workflows/ci.yml": "jobs: {}\n",
    ".github/workflows/nested/ignored.yml": "jobs: {}\n",
    "web/package.json": "{}\n",
    "docs/requirements.txt": "sphinx\n",
}


def test_signals_come_from_the_base_commit_not_the_working_tree(tmp_path: Path) -> None:
    workspace = _commit(tmp_path / "repository", _BASE)
    (workspace.path / "pyproject.toml").write_text("[project]\nname = 'tampered'\n")
    (workspace.path / "noxfile.py").write_text("import os\n")

    signals = read_signals(workspace)

    assert signals.files["pyproject.toml"] == "[project]\nname = 'demo'\n"
    assert "noxfile.py" not in signals.paths
    assert ".github/workflows/ci.yml" in signals.files
    assert ".github/workflows/nested/ignored.yml" not in signals.files
    # Scripts that a task runner names are read one level deep; others are not.
    assert signals.files["tools/run-tests"] == "#!/bin/sh\npytest\n"
    assert "tools/unused" not in signals.files
    assert "README.md" not in signals.files
    assert "uv.lock" not in signals.files


def test_dependency_files_cover_manifests_anywhere_and_every_file_read(tmp_path: Path) -> None:
    workspace = _commit(tmp_path / "repository", _BASE)

    paths = {path for path, _ in read_signals(workspace).dependency_files}

    assert paths == {
        ".github/workflows/ci.yml",
        "Makefile",
        "docs/requirements.txt",
        "pyproject.toml",
        "tools/run-tests",
        "uv.lock",
        "web/package.json",
    }


def test_oversized_and_binary_files_are_not_read_but_still_count(tmp_path: Path) -> None:
    workspace = _commit(
        tmp_path / "repository",
        {
            "pyproject.toml": "[project]\n" + "# padding\n" * 30_000,
            "setup.cfg": b"\xff\xfe not utf-8",
        },
    )

    signals = read_signals(workspace)

    assert "pyproject.toml" not in signals.files
    assert "setup.cfg" not in signals.files
    assert {"pyproject.toml", "setup.cfg"} <= {path for path, _ in signals.dependency_files}


def test_submodule_commits_are_dependencies(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    _git(root, "init", "--quiet")
    (root / ".gitmodules").write_text('[submodule "lib"]\n\tpath = lib\n\turl = ../lib\n')
    _git(root, "add", ".gitmodules")
    _git(root, "update-index", "--add", "--cacheinfo", f"160000,{_SUBMODULE_COMMIT},lib")
    _git(root, "-c", "user.name=F", "-c", "user.email=f@example.invalid", "commit", "-qm", "c")
    workspace = RepositoryWorkspace(root, _git(root, "rev-parse", "HEAD"))

    signals = read_signals(workspace)

    assert ("lib", _SUBMODULE_COMMIT) in signals.dependency_files
    assert "lib" in signals.paths
    assert ".gitmodules" in signals.files


def test_dependency_digest_follows_lockfiles_and_ignores_unrelated_files(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    first = dependency_digest(read_signals(_commit(root, _BASE)).dependency_files)
    readme = dependency_digest(
        read_signals(_commit(root, {"README.md": "new readme\n"})).dependency_files
    )
    lockfile = dependency_digest(
        read_signals(_commit(root, {"uv.lock": "version = 2\n"})).dependency_files
    )

    assert readme == first
    assert lockfile != first


def test_read_blob_refuses_malformed_ids_and_oversized_objects(tmp_path: Path) -> None:
    workspace = _commit(tmp_path / "repository", {"pyproject.toml": "x" * 100})
    entry = next(entry for entry in workspace.base_tree() if entry.path == "pyproject.toml")

    assert entry.size == 100
    assert workspace.read_blob(entry.object_id, max_bytes=100) == b"x" * 100
    with pytest.raises(RepositoryError, match="exceeds"):
        workspace.read_blob(entry.object_id, max_bytes=99)
    with pytest.raises(RepositoryError, match="hexadecimal"):
        workspace.read_blob("HEAD:pyproject.toml", max_bytes=100)
