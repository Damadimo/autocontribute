from __future__ import annotations

import pytest

from autocontribute.quality import environment_failure_signature, patch_paths, workflow_paths


@pytest.mark.parametrize(
    ("output", "reason"),
    [
        ("sh: tool: command not found", "not installed"),
        ("No such file or directory", "file or executable was missing"),
        ("no tests collected", "discovered no tests"),
        ("No tests were executed!", "discovered no tests"),
        ("ModuleNotFoundError: No module named 'suite'", "module was unavailable"),
        ("Error: Cannot find module 'dependency'", "module was unavailable"),
        (
            "src/Main.hs:3:1: error: Could not load module 'Missing.Package'",
            "module was unavailable",
        ),
        ("npm ERR! Missing script: test", "script was missing"),
        ("INTERNALERROR> AssertionError: plugin state", "runner failed internally"),
        ("error[E0463]: can't find crate for `serde`", "dependency or type environment"),
        ("error TS2688: Cannot find type definition file", "dependency or type environment"),
        ("[ERROR] COMPILATION ERROR: invalid target release: 21", "toolchain was unavailable"),
        ("OSError: [Errno 28] No space left on device", "storage was unavailable"),
        ("java.lang.OutOfMemoryError: Java heap space", "memory was exhausted"),
        ("Permission denied", "lacked permission"),
        ("Cannot connect to the Docker daemon. Is the docker daemon running?", "Docker"),
    ],
)
def test_environment_failure_signatures_name_a_broken_environment(output: str, reason: str) -> None:
    found = environment_failure_signature(output)

    assert found is not None and reason in found


@pytest.mark.parametrize(
    "output",
    [
        "curl: Could not resolve host: example.test",
        "OSError: Network is unreachable",
        "FAILED test_remote.py - ProxyError: Cannot connect to proxy",
        "AssertionError: assert 1 == 2",
    ],
)
def test_network_and_assertion_failures_are_not_environment_failures(output: str) -> None:
    # Tests that need the network fail on the unmodified base too, offline by design.
    assert environment_failure_signature(output) is None


def test_patch_paths_read_quoted_renamed_and_removed_files() -> None:
    diff = (
        'diff --git "a/docs/user guide.md" "b/docs/user guide.md"\n'
        '--- "a/docs/user guide.md"\n+++ "b/docs/user guide.md"\n@@ -1 +1 @@\n-a\n+b\n'
        "diff --git a/old.py b/new.py\nsimilarity index 90%\n"
        "rename from old.py\nrename to new.py\n"
        "diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml\n"
        "deleted file mode 100644\n--- a/.github/workflows/ci.yml\n+++ /dev/null\n"
        "@@ -1 +0,0 @@\n-on: push\n"
    )

    assert patch_paths(diff) == [
        ".github/workflows/ci.yml",
        "docs/user guide.md",
        "new.py",
        "old.py",
    ]
    assert workflow_paths(diff) == [".github/workflows/ci.yml"]
    with pytest.raises(ValueError, match="cannot be parsed"):
        patch_paths('diff --git "a/unterminated b/x\n')
