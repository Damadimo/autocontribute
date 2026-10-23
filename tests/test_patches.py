from __future__ import annotations

import os
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from autocontribute.exceptions import PatchEncodingError, RepositoryError
from autocontribute.patches import extract_patch, is_test_path, parse_patch, split_patch
from autocontribute.repository import RepositoryWorkspace
from autocontribute.workspace_files import WorkspaceFiles

_RUST_BASE = """pub fn add(a: i32, b: i32) -> i32 {
    a - b
}

pub fn label() -> &'static str {
    "}{"
}

pub fn one() -> i32 {
    1
}

pub fn two() -> i32 {
    2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels() {
        let brace = '}';
        let raw = r#"{ "}" "#;
        /* } nested /* } */ */
        assert_eq!(label(), "}{");
        assert_eq!(brace, '}');
        assert!(raw.starts_with('{'));
    }
}
"""


_RUST_MODULE = "pub fn three() -> i32 {\n    3\n}\n"


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


@pytest.fixture
def clone(tmp_path: Path) -> Callable[[str], RepositoryWorkspace]:
    source = tmp_path / "source"
    source.mkdir()
    _git(source, "init", "--quiet")
    files = {
        ".gitignore": "build/\n",
        "README.md": "readme\n",
        "src/calc.py": "def add(a, b):\n    return a - b\n",
        "src/lib.rs": _RUST_BASE,
        "src/three.rs": _RUST_MODULE,
        "tests/test_calc.py": "from calc import add\n",
        "old.txt": "old\n",
    }
    for relative, content in files.items():
        (source / relative).parent.mkdir(parents=True, exist_ok=True)
        (source / relative).write_text(content, encoding="utf-8")
    _git(source, "add", ".")
    _git(
        source,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=f@example.invalid",
        "commit",
        "-qm",
        "base",
    )
    base = _git(source, "rev-parse", "HEAD")

    def make(name: str) -> RepositoryWorkspace:
        return RepositoryWorkspace.clone(
            str(source), base, tmp_path / name, allow_local_source=True
        )

    return make


def test_extracted_patch_holds_tracked_and_new_files_but_not_ignored_ones(
    clone: Callable[[str], RepositoryWorkspace],
) -> None:
    workspace = clone("workspace")
    root = workspace.path
    (root / "src" / "calc.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    (root / "old.txt").unlink()
    (root / "docs").mkdir()
    (root / "docs" / "user guide.md").write_text("guide\n", encoding="utf-8")
    (root / "docs" / "café.md").write_text("menu\n", encoding="utf-8")
    (root / "logo.bin").write_bytes(b"\x00\x01\xff")
    (root / "build").mkdir()
    (root / "build" / "output.o").write_bytes(b"\x7fELF")
    (root / "link").symlink_to("/etc/passwd")

    patch = extract_patch(workspace)

    assert sorted(patch.paths) == [
        "docs/café.md",
        "docs/user guide.md",
        "link",
        "logo.bin",
        "old.txt",
        "src/calc.py",
    ]
    assert parse_patch(patch.text) == patch
    assert "GIT binary patch" in patch.text
    assert "new file mode 120000" in patch.text
    assert patch.changed_lines == 6


def test_extracted_patch_applies_to_a_fresh_copy(
    clone: Callable[[str], RepositoryWorkspace],
) -> None:
    workspace = clone("workspace")
    target = clone("target")
    (workspace.path / "src" / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    (workspace.path / "old.txt").unlink()
    (workspace.path / "docs").mkdir()
    (workspace.path / "docs" / "user guide.md").write_text("guide\n", encoding="utf-8")
    (workspace.path / "logo.bin").write_bytes(b"\x00\x01\xff")

    target.apply_patch(extract_patch(workspace).text)

    assert (target.path / "src" / "calc.py").read_text() == "def add(a, b):\n    return a + b\n"
    assert not (target.path / "old.txt").exists()
    assert (target.path / "docs" / "user guide.md").read_text(encoding="utf-8") == "guide\n"
    assert (target.path / "logo.bin").read_bytes() == b"\x00\x01\xff"


def test_non_utf8_content_is_a_typed_gate_error_naming_the_file(
    clone: Callable[[str], RepositoryWorkspace],
) -> None:
    workspace = clone("workspace")
    (workspace.path / "README.md").write_bytes("café\n".encode("latin-1"))
    (workspace.path / "src" / "calc.py").write_text("# fine\n", encoding="utf-8")

    with pytest.raises(PatchEncodingError) as raised:
        extract_patch(workspace)

    assert raised.value.paths == ("README.md",)
    assert "not UTF-8" in str(raised.value)


def test_non_utf8_quoted_path_is_a_typed_gate_error() -> None:
    patch = 'diff --git "a/\\377.txt" "b/\\377.txt"\nnew file mode 100644\n'

    with pytest.raises(PatchEncodingError):
        parse_patch(patch)


@pytest.mark.parametrize(
    "header",
    [
        "diff --git a/one.txt b/two.txt",
        'diff --git "a/one" b/one',
        'diff --git "a/\\q" "b/\\q"',
        "diff --git a/x",
    ],
)
def test_unreadable_patch_headers_are_rejected(header: str) -> None:
    with pytest.raises(RepositoryError, match="patch header"):
        parse_patch(f"{header}\n")


def test_quoted_header_paths_are_unescaped() -> None:
    patch = parse_patch(
        'diff --git "a/tab\\there \\"q\\" caf\\303\\251" "b/tab\\there \\"q\\" caf\\303\\251"\n'
    )

    assert patch.paths == ('tab\there "q" café',)


def test_patch_text_must_start_with_a_file_header() -> None:
    assert parse_patch("").files == ()
    with pytest.raises(RepositoryError, match="diff --git"):
        parse_patch("junk\ndiff --git a/x b/x\n")


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("tests/test_calc.py", True),
        ("pkg/tests/helpers.py", True),
        ("test/app.router.js", True),
        ("src/__tests__/button.jsx", True),
        ("test_calc.py", True),
        ("calc_test.py", True),
        ("pkg/server_test.go", True),
        ("src/button.test.tsx", True),
        ("src/button.spec.ts", True),
        ("src/calc.py", False),
        ("src/testing.py", False),
        ("src/contest.py", False),
        ("conftest.py", False),
        ("tests.md", False),
        ("src/lib.rs", False),
    ],
)
def test_test_files_are_recognised_by_directory_or_name(path: str, expected: bool) -> None:
    assert is_test_path(path) is expected


def test_split_separates_test_files_from_source_files(
    clone: Callable[[str], RepositoryWorkspace],
) -> None:
    workspace = clone("workspace")
    (workspace.path / "src" / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    (workspace.path / "tests" / "test_calc.py").write_text(
        "from calc import add\n\n\ndef test_add():\n    assert add(1, 2) == 3\n"
    )

    split = split_patch(extract_patch(workspace), WorkspaceFiles(workspace.path))

    assert split.tests.paths == ("tests/test_calc.py",)
    assert split.sources.paths == ("src/calc.py",)


def test_rust_cfg_test_hunks_count_as_tests_and_apply_on_their_own(
    clone: Callable[[str], RepositoryWorkspace],
) -> None:
    workspace = clone("workspace")
    edited = _RUST_BASE.replace(
        "    a - b\n", "    // Addition, not subtraction.\n    a + b\n"
    ).replace(
        "        assert!(raw.starts_with('{'));\n    }\n",
        "        assert!(raw.starts_with('{'));\n    }\n\n"
        "    #[test]\n    fn adds() {\n        assert_eq!(add(1, 2), 3);\n    }\n",
    )
    (workspace.path / "src" / "lib.rs").write_text(edited, encoding="utf-8")
    full = extract_patch(workspace)

    split = split_patch(full, WorkspaceFiles(workspace.path))

    assert split.tests.paths == split.sources.paths == ("src/lib.rs",)
    assert "fn adds()" in split.tests.text and "a + b" not in split.tests.text
    assert "a + b" in split.sources.text and "fn adds()" not in split.sources.text
    assert "\nindex " not in split.tests.text
    full_headers = re.findall(r"^@@ .* @@", full.text, flags=re.MULTILINE)
    assert full_headers[1] == "@@ -27,4 +28,9 @@"
    assert re.findall(r"^@@ .* @@", split.tests.text, flags=re.MULTILINE) == ["@@ -27,4 +27,9 @@"]

    red = clone("red")
    red.apply_patch(split.tests.text)
    red_text = (red.path / "src" / "lib.rs").read_text(encoding="utf-8")
    assert "fn adds()" in red_text and "a - b" in red_text
    green = clone("green")
    green.apply_patch(split.sources.text)
    assert (green.path / "src" / "lib.rs").read_text(encoding="utf-8") == _RUST_BASE.replace(
        "    a - b\n", "    // Addition, not subtraction.\n    a + b\n"
    )


def test_a_new_rust_test_module_counts_as_a_test(
    clone: Callable[[str], RepositoryWorkspace],
) -> None:
    workspace = clone("workspace")
    (workspace.path / "src" / "three.rs").write_text(
        _RUST_MODULE + "\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn three() {\n"
        "        assert_eq!(super::three(), 3);\n    }\n}\n",
        encoding="utf-8",
    )

    split = split_patch(extract_patch(workspace), WorkspaceFiles(workspace.path))

    assert split.tests.paths == ("src/three.rs",)
    assert split.sources.files == ()


def test_a_rust_hunk_touching_code_outside_test_items_is_source(
    clone: Callable[[str], RepositoryWorkspace],
) -> None:
    workspace = clone("workspace")
    # Six lines apart, so Git puts both changes in one hunk.
    edited = _RUST_BASE.replace("    2\n}", "    2 + 0\n}").replace(
        "    use super::*;\n", "    use super::*;\n    use std::fmt;\n"
    )
    (workspace.path / "src" / "lib.rs").write_text(edited, encoding="utf-8")
    patch = extract_patch(workspace)

    split = split_patch(patch, WorkspaceFiles(workspace.path))

    assert len(patch.files[0].hunks) == 1
    assert split.tests.files == ()
    assert split.sources == patch


@pytest.mark.skipif(sys.platform == "darwin", reason="APFS refuses non-UTF-8 file names")
def test_non_utf8_file_name_is_a_typed_gate_error(
    clone: Callable[[str], RepositoryWorkspace],
) -> None:
    workspace = clone("workspace")
    (workspace.path / os.fsdecode(b"caf\xe9.txt")).write_text("x\n", encoding="utf-8")

    with pytest.raises(PatchEncodingError):
        extract_patch(workspace)
