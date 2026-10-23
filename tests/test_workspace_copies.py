from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

import autocontribute.workspace_copies as workspace_copies_module
from autocontribute.exceptions import RepositoryError
from autocontribute.patches import extract_patch
from autocontribute.repository import RepositoryWorkspace
from autocontribute.workspace_copies import copy_workspace, remove_workspace_copy


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    root = tmp_path / "workspace"
    (root / "pkg" / "deep").mkdir(parents=True)
    (root / "pkg" / "module.py").write_text("value = 1\n", encoding="utf-8")
    (root / "pkg" / "deep" / "data.bin").write_bytes(b"\x00\xff" * 1_000)
    script = root / "run.sh"
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    script.chmod(0o755)
    (root / "relative-link").symlink_to("pkg/module.py")
    (root / "absolute-link").symlink_to(tmp_path / "outside")
    (root / "dangling-link").symlink_to("missing")
    return root


def _assert_same_tree(source: Path, copy: Path) -> None:
    for directory, subdirectories, names in os.walk(source):
        relative = Path(directory).relative_to(source)
        for name in [*subdirectories, *names]:
            original = Path(directory) / name
            copied = copy / relative / name
            assert copied.is_symlink() == original.is_symlink(), relative / name
            if original.is_symlink():
                assert os.readlink(copied) == os.readlink(original)
            elif original.is_file():
                assert copied.read_bytes() == original.read_bytes()
                assert copied.stat().st_mode == original.stat().st_mode


def test_copy_keeps_contents_modes_and_symlinks_and_is_independent(
    tree: Path, tmp_path: Path
) -> None:
    copy = tmp_path / "snapshot"

    copy_workspace(tree, copy)

    _assert_same_tree(tree, copy)
    (copy / "pkg" / "module.py").write_text("value = 2\n", encoding="utf-8")
    assert (tree / "pkg" / "module.py").read_text(encoding="utf-8") == "value = 1\n"


def test_copy_falls_back_to_python_when_cp_fails(
    tree: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    copy = tmp_path / "snapshot"

    def failing_cp(arguments: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        Path(arguments[-1]).mkdir()
        (Path(arguments[-1]) / "partial").write_text("", encoding="utf-8")
        return subprocess.CompletedProcess(arguments, 1, b"", b"cp: unrecognized option")

    monkeypatch.setattr(workspace_copies_module.subprocess, "run", failing_cp)

    copy_workspace(tree, copy)

    _assert_same_tree(tree, copy)
    assert not (copy / "partial").exists()


def test_copy_refuses_unsafe_sources_and_existing_destinations(tree: Path, tmp_path: Path) -> None:
    link = tmp_path / "link"
    link.symlink_to(tree, target_is_directory=True)
    existing = tmp_path / "existing"
    existing.mkdir()

    with pytest.raises(RepositoryError, match="not a real directory"):
        copy_workspace(link, tmp_path / "copy")
    with pytest.raises(RepositoryError, match="already exists"):
        copy_workspace(tree, existing)
    with pytest.raises(RepositoryError, match="already exists"):
        copy_workspace(tree, link)


def test_remove_deletes_locked_directories_without_following_symlinks(
    tree: Path, tmp_path: Path
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("host\n", encoding="utf-8")
    (tree / "pkg" / "escape").symlink_to(outside, target_is_directory=True)
    (tree / "pkg" / "deep").chmod(0o000)
    (tree / "pkg").chmod(0o500)

    remove_workspace_copy(tree)

    assert not os.path.lexists(tree)
    assert (outside / "keep.txt").read_text(encoding="utf-8") == "host\n"
    remove_workspace_copy(tree)


def test_remove_refuses_a_symlink_or_a_file(tree: Path, tmp_path: Path) -> None:
    link = tmp_path / "link"
    link.symlink_to(tree, target_is_directory=True)

    with pytest.raises(RepositoryError, match="not a real directory"):
        remove_workspace_copy(link)
    with pytest.raises(RepositoryError, match="not a real directory"):
        remove_workspace_copy(tree / "run.sh")
    assert (tree / "pkg" / "module.py").exists()


def test_validation_copy_gets_the_patch_but_not_the_agents_stray_files(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    environment = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
    (source / ".gitignore").write_text("build/\n", encoding="utf-8")
    (source / "calc.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
    for arguments in (
        ["init", "--quiet"],
        ["add", "."],
        ["-c", "user.name=F", "-c", "user.email=f@example.invalid", "commit", "-qm", "base"],
    ):
        subprocess.run(["git", *arguments], cwd=source, env=environment, check=True)
    base = (
        subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=source,
            env=environment,
            check=True,
            capture_output=True,
        )
        .stdout.decode()
        .strip()
    )
    work = RepositoryWorkspace.clone(str(source), base, tmp_path / "w", allow_local_source=True)
    (work.path / "build").mkdir()
    (work.path / "build" / "setup-output.txt").write_text("from setup\n", encoding="utf-8")

    copy_workspace(work.path, tmp_path / "s")
    (work.path / "calc.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    (work.path / "build" / "agent-output.txt").write_text("stray\n", encoding="utf-8")
    patch = extract_patch(work)
    copy_workspace(tmp_path / "s", tmp_path / "v")
    validation = RepositoryWorkspace(tmp_path / "v", base)
    validation.apply_patch(patch.text)

    assert patch.paths == ("calc.py",)
    assert (validation.path / "calc.py").read_text(encoding="utf-8").endswith("a + b\n")
    assert (validation.path / "build" / "setup-output.txt").exists()
    assert not (validation.path / "build" / "agent-output.txt").exists()
    assert (tmp_path / "s" / "calc.py").read_text(encoding="utf-8").endswith("a - b\n")
