from __future__ import annotations

import os
from pathlib import Path

import pytest

import autocontribute.workspace_files as workspace_files_module
from autocontribute.exceptions import RepositoryError
from autocontribute.workspace_files import MAX_EDIT_BYTES, WorkspaceFiles


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "workspace"
    (root / "src").mkdir(parents=True)
    (root / "src" / "module.py").write_text("value = 1\n", encoding="utf-8")
    (root / ".git").mkdir()
    (root / ".git" / "config").write_text("[core]\n", encoding="utf-8")
    return root


@pytest.fixture
def outside(tmp_path: Path) -> Path:
    directory = tmp_path / "outside"
    directory.mkdir()
    (directory / "secret.txt").write_text("host secret\n", encoding="utf-8")
    return directory


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("src/module.py", "src/module.py"),
        ("/workspace/src/module.py", "src/module.py"),
        ("./src//module.py", "src/module.py"),
        ("/workspace", ""),
        ("/workspace/", ""),
        (".", ""),
        ("", ""),
        ("src/", "src"),
    ],
)
def test_model_paths_are_normalized_to_the_workspace(
    workspace: Path, path: str, expected: str
) -> None:
    assert WorkspaceFiles(workspace).normalize(path) == expected


@pytest.mark.parametrize(
    ("path", "message"),
    [
        ("src/\0module.py", "NUL"),
        ("/etc/passwd", "outside /workspace"),
        ("/workspaces/other", "outside /workspace"),
        ("../outside/secret.txt", r"'\.\.'"),
        ("src/../../outside", r"'\.\.'"),
        ("/workspace/../etc/passwd", r"'\.\.'"),
        (".git/config", r"\.git"),
        ("src/.GIT/config", r"\.git"),
    ],
)
def test_unsafe_model_paths_are_rejected(workspace: Path, path: str, message: str) -> None:
    files = WorkspaceFiles(workspace)
    with pytest.raises(RepositoryError, match=message):
        files.normalize(path)
    with pytest.raises(RepositoryError, match=message):
        files.write_text(path, "planted\n")


def test_text_round_trip_keeps_modes_and_creates_parents(workspace: Path) -> None:
    files = WorkspaceFiles(workspace)
    script = workspace / "src" / "module.py"
    script.chmod(0o755)

    files.write_text("/workspace/src/module.py", "value = 2\n")
    files.write_text("tests/unit/test_module.py", "def test():\n    pass\n")

    assert files.read_text("src/module.py") == "value = 2\n"
    assert script.stat().st_mode & 0o777 == 0o755
    created = workspace / "tests" / "unit" / "test_module.py"
    assert created.read_text(encoding="utf-8") == "def test():\n    pass\n"
    assert created.stat().st_mode & 0o777 == 0o644
    assert files.kind("tests/unit") == "directory"
    assert files.kind("tests/unit/test_module.py") == "file"
    assert files.kind("missing.py") is None
    assert not [name for name in os.listdir(workspace / "src") if name.startswith(".")]

    files.delete("tests/unit/test_module.py")
    assert not created.exists()
    with pytest.raises(RepositoryError, match="does not exist"):
        files.delete("tests/unit/test_module.py")


def test_planted_file_symlinks_are_never_followed(workspace: Path, outside: Path) -> None:
    files = WorkspaceFiles(workspace)
    (workspace / "src" / "link.py").symlink_to(outside / "secret.txt")

    with pytest.raises(RepositoryError, match="symlink"):
        files.read_bytes("src/link.py")
    with pytest.raises(RepositoryError, match="symlink"):
        files.write_text("src/link.py", "overwritten\n")
    with pytest.raises(RepositoryError, match="symlink"):
        files.delete("src/link.py")
    with pytest.raises(RepositoryError, match="symlink"):
        files.kind("src/link.py")

    assert (outside / "secret.txt").read_text(encoding="utf-8") == "host secret\n"
    assert (workspace / "src" / "link.py").is_symlink()


def test_planted_directory_symlinks_are_never_crossed(workspace: Path, outside: Path) -> None:
    files = WorkspaceFiles(workspace)
    (workspace / "escape").symlink_to(outside, target_is_directory=True)
    (workspace / "src" / "nested").symlink_to("../escape", target_is_directory=True)

    for path in ("escape/secret.txt", "src/nested/secret.txt"):
        with pytest.raises(RepositoryError, match="symlink"):
            files.read_bytes(path)
        with pytest.raises(RepositoryError, match="symlink"):
            files.write_text(path, "overwritten\n")
        with pytest.raises(RepositoryError, match="symlink"):
            files.delete(path)
    with pytest.raises(RepositoryError, match="symlink"):
        files.write_text("escape/new/file.txt", "planted\n")
    with pytest.raises(RepositoryError, match="symlink"):
        files.list_directory("escape", depth=2)

    assert sorted(os.listdir(outside)) == ["secret.txt"]
    assert (outside / "secret.txt").read_text(encoding="utf-8") == "host secret\n"


def test_a_symlink_swapped_in_during_a_write_is_replaced_not_followed(
    workspace: Path, outside: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    files = WorkspaceFiles(workspace)
    target = workspace / "src" / "module.py"
    real_fchmod = os.fchmod

    def swap_then_fchmod(descriptor: int, mode: int) -> None:
        target.unlink()
        target.symlink_to(outside / "secret.txt")
        real_fchmod(descriptor, mode)

    monkeypatch.setattr(workspace_files_module.os, "fchmod", swap_then_fchmod)
    files.write_text("src/module.py", "value = 3\n")

    assert not target.is_symlink()
    assert target.read_text(encoding="utf-8") == "value = 3\n"
    assert (outside / "secret.txt").read_text(encoding="utf-8") == "host secret\n"


def test_special_and_oversized_files_are_refused(workspace: Path) -> None:
    files = WorkspaceFiles(workspace)
    os.mkfifo(workspace / "src" / "pipe")
    (workspace / "src" / "large.txt").write_bytes(b"x" * (MAX_EDIT_BYTES + 1))
    (workspace / "src" / "latin1.txt").write_bytes("caf\xe9\n".encode("latin-1"))

    with pytest.raises(RepositoryError, match="Not a regular file"):
        files.read_bytes("src/pipe")
    with pytest.raises(RepositoryError, match="Not a regular file"):
        files.write_text("src/pipe", "data\n")
    with pytest.raises(RepositoryError, match="larger than"):
        files.read_text("src/large.txt")
    with pytest.raises(RepositoryError, match="not UTF-8"):
        files.read_text("src/latin1.txt")
    with pytest.raises(RepositoryError, match="larger than"):
        files.write_text("src/new.txt", "x" * (MAX_EDIT_BYTES + 1))
    with pytest.raises(RepositoryError, match="directory, not a file"):
        files.read_text("src")
    with pytest.raises(RepositoryError, match="not a file"):
        files.write_text("/workspace", "data\n")
    with pytest.raises(RepositoryError, match="non-directory"):
        files.write_text("src/module.py/child.py", "data\n")


def test_directory_listing_is_bounded_and_skips_hidden_entries(
    workspace: Path, outside: Path
) -> None:
    files = WorkspaceFiles(workspace)
    (workspace / "src" / "pkg" / "deep").mkdir(parents=True)
    (workspace / "src" / "pkg" / "deep" / "hidden_by_depth.py").write_text("", encoding="utf-8")
    (workspace / "src" / ".cache").mkdir()
    (workspace / ".env").write_text("", encoding="utf-8")
    (workspace / "README.md").write_text("", encoding="utf-8")
    (workspace / "linked").symlink_to(outside, target_is_directory=True)

    assert files.list_directory("/workspace", depth=2) == [
        "README.md",
        "linked",
        "src/",
        "src/module.py",
        "src/pkg/",
    ]
    assert files.list_directory("src", depth=2) == [
        "src/module.py",
        "src/pkg/",
        "src/pkg/deep/",
    ]
    with pytest.raises(RepositoryError, match="does not exist"):
        files.list_directory("missing", depth=2)


def test_workspace_root_must_be_a_real_directory(workspace: Path, tmp_path: Path) -> None:
    link = tmp_path / "link"
    link.symlink_to(workspace, target_is_directory=True)
    with pytest.raises(RepositoryError, match="real directory"):
        WorkspaceFiles(link)


def test_symlinks_swapped_in_after_the_check_are_still_not_followed(
    workspace: Path, outside: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    files = WorkspaceFiles(workspace)
    (workspace / "dir-link").symlink_to(outside, target_is_directory=True)
    (workspace / "file-link").symlink_to(outside / "secret.txt")
    regular = os.stat(workspace / "src" / "module.py")
    directory = os.stat(workspace / "src")

    # Simulates a container replacing the entry between the lstat and the open.
    def stale_entry(_parent: int, name: str, *, path: str) -> os.stat_result:
        return directory if name == "dir-link" else regular

    monkeypatch.setattr(workspace_files_module, "_entry", stale_entry)

    with pytest.raises(RepositoryError, match="Could not open a directory safely"):
        files.read_bytes("dir-link/secret.txt")
    with pytest.raises(RepositoryError, match="file-link"):
        files.read_bytes("file-link")
