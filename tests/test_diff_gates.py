from __future__ import annotations

import os
import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from autocontribute.config import PolicyConfig, QualityConfig
from autocontribute.diff_gates import (
    DiffGateOutcome,
    changed_tests,
    diff_gates,
    is_dependency_path,
    is_workflow_path,
    path_matches,
)
from autocontribute.patches import extract_patch, split_patch
from autocontribute.repository import RepositoryWorkspace
from autocontribute.workspace_files import WorkspaceFiles

_BASE = {
    ".gitignore": "build/\n",
    "src/calc.py": "def add(a, b):\n    return a - b\n",
    "tests/test_calc.py": (
        "import pytest\n\nfrom calc import add\n\n\n"
        "def test_adds():\n    assert add(1, 2) == 3\n\n\n"
        "def test_zero():\n    assert add(0, 0) == 0\n"
    ),
    "web/sum.test.js": "test('sums', () => {\n  expect(1 + 1).toBe(2);\n});\n",
    "pkg/sum_test.go": "package pkg\n\nfunc TestSum(t *testing.T) {\n\tt.Log(1)\n}\n",
    "web/parse.test.js": (
        "describe('parser', () => {\n"
        "  it('parses numbers', () => {\n    expect(parse('1')).toBe(1);\n  });\n"
        "  test.each([1, 2])('parses %i', (n) => {\n    expect(parse(String(n))).toBe(n);\n  });\n"
        "});\n"
    ),
}
# Assembled at runtime so the repository's own secret scan does not report this file.
_TOKEN = "ghp_" + "Z9" * 18
_HOST_SECRET = "host-secret-value-0123456789"

Edit = Callable[[Path], None]


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
def workspace(tmp_path: Path) -> RepositoryWorkspace:
    source = tmp_path / "source"
    source.mkdir()
    _git(source, "init", "--quiet")
    for relative, content in _BASE.items():
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    _git(source, "add", ".")
    _git(source, "-c", "user.name=T", "-c", "user.email=t@example.invalid", "commit", "-qm", "b")
    base = _git(source, "rev-parse", "HEAD")
    return RepositoryWorkspace.clone(str(source), base, tmp_path / "work", allow_local_source=True)


def _write(workspace: RepositoryWorkspace, files: Mapping[str, str]) -> None:
    for relative, content in files.items():
        path = workspace.path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def _gates(
    workspace: RepositoryWorkspace,
    *,
    quality: QualityConfig | None = None,
    policy: PolicyConfig | None = None,
    host_values: frozenset[str] = frozenset(),
) -> tuple[DiffGateOutcome, dict[str, tuple[bool, str]]]:
    patch = extract_patch(workspace)
    split = split_patch(patch, WorkspaceFiles(workspace.path))
    outcome = diff_gates(
        workspace,
        patch,
        split,
        quality=quality or QualityConfig(),
        policy=policy or PolicyConfig(),
        host_values=host_values,
    )
    return outcome, {gate.gate: (gate.passed, gate.evidence) for gate in outcome.gates}


def _failed(gates: dict[str, tuple[bool, str]]) -> set[str]:
    return {name for name, (passed, _) in gates.items() if not passed}


def test_a_small_fix_with_a_test_passes_every_gate(workspace: RepositoryWorkspace) -> None:
    _write(
        workspace,
        {
            "src/calc.py": "def add(a, b):\n    return a + b\n",
            "tests/test_calc.py": _BASE["tests/test_calc.py"]
            + "\n\ndef test_negative():\n    assert add(-1, 1) == 0\n",
        },
    )

    outcome, gates = _gates(workspace)

    assert outcome.passed and not outcome.host_secret
    assert list(gates) == [
        "diff_present",
        "file_count",
        "changed_lines",
        "source_file_count",
        "source_changed_lines",
        "no_binary_files",
        "no_symlinks",
        "no_submodules",
        "no_mode_changes",
        "safe_paths",
        "forbidden_paths",
        "sensitive_paths",
        "dependency_policy",
        "workflow_policy",
        "existing_tests",
        "secrets",
    ]


def test_an_empty_diff_fails(workspace: RepositoryWorkspace) -> None:
    _, gates = _gates(workspace)

    assert _failed(gates) == {"diff_present"}


def test_source_limits_count_only_non_test_files(workspace: RepositoryWorkspace) -> None:
    _write(workspace, {f"src/module_{index}.py": "x = 1\n" for index in range(4)})
    _write(workspace, {f"tests/test_new_{index}.py": "x = 1\n" for index in range(3)})

    _, gates = _gates(workspace)

    assert _failed(gates) == {"source_file_count"}
    assert gates["source_file_count"][1] == "4 changed non-test file(s); the limit is 3"

    _, narrow = _gates(workspace, quality=QualityConfig(max_files_changed=5))
    assert _failed(narrow) == {"file_count", "source_file_count"}


def test_source_line_limit(workspace: RepositoryWorkspace) -> None:
    _write(workspace, {"src/big.py": "".join(f"x{i} = {i}\n" for i in range(151))})

    _, gates = _gates(workspace)

    assert _failed(gates) == {"source_changed_lines"}


def test_paths_with_spaces_are_safe_and_judged_by_their_real_name(
    workspace: RepositoryWorkspace,
) -> None:
    # G1: the old header parser rejected any path with a space.
    _write(workspace, {"docs/user guide.md": "Guide\n"})

    _, gates = _gates(workspace)

    assert not _failed(gates)


def test_symlinks_fail_their_gate_and_the_safe_path_gate(workspace: RepositoryWorkspace) -> None:
    (workspace.path / "link").symlink_to("/etc/passwd")

    _, gates = _gates(workspace)

    assert _failed(gates) == {"no_symlinks", "safe_paths"}
    assert "link" in gates["no_symlinks"][1]


def test_mode_changes_and_binary_files_fail(workspace: RepositoryWorkspace) -> None:
    (workspace.path / "src" / "calc.py").chmod(0o755)
    (workspace.path / "logo.bin").write_bytes(b"\x00\x01\x02binary")

    _, gates = _gates(workspace)

    assert _failed(gates) == {"no_mode_changes", "no_binary_files"}


def test_forbidden_sensitive_dependency_and_workflow_paths(workspace: RepositoryWorkspace) -> None:
    _write(
        workspace,
        {
            ".github/ISSUE_TEMPLATE/bug.md": "x\n",
            ".env.production": "X=1\n",
            "pyproject.toml": "[project]\nname = 'x'\n",
        },
    )

    _, gates = _gates(workspace)

    assert _failed(gates) == {"forbidden_paths", "sensitive_paths", "dependency_policy"}
    assert gates["forbidden_paths"][1] == "forbidden path(s): .github/ISSUE_TEMPLATE/bug.md"
    assert gates["sensitive_paths"][1] == "credential file(s): .env.production"


def test_policy_allows_dependency_and_workflow_changes(workspace: RepositoryWorkspace) -> None:
    _write(workspace, {".gitlab-ci.yml": "test: {}\n", "requirements.txt": "x\n"})
    allowed = PolicyConfig(allow_dependency_changes=True, allow_workflow_changes=True)

    _, refused = _gates(workspace)
    _, gates = _gates(workspace, policy=allowed)

    assert _failed(refused) == {"dependency_policy", "workflow_policy"}
    assert not _failed(gates)


@pytest.mark.parametrize(
    ("files", "expected"),
    [
        (
            {"tests/test_calc.py": "import pytest\n\nfrom calc import add\n"},
            "test_adds, test_zero removed or renamed in tests/test_calc.py",
        ),
        (
            {
                "tests/test_calc.py": _BASE["tests/test_calc.py"].replace(
                    "def test_zero", "@pytest.mark.skip\ndef test_zero"
                )
            },
            "@pytest.mark.skip",
        ),
        (
            {
                "tests/test_calc.py": _BASE["tests/test_calc.py"].replace(
                    "    assert add(0, 0)", "    pytest.skip('flaky')\n    assert add(0, 0)"
                )
            },
            "pytest.skip('flaky')",
        ),
        (
            {
                "web/sum.test.js": _BASE["web/sum.test.js"].replace(
                    "test('sums'", "test.skip('sums'"
                )
            },
            "test.skip('sums'",
        ),
        (
            {
                "web/sum.test.js": _BASE["web/sum.test.js"]
                + "test.only('new', () => {\n  expect(2).toBe(2);\n});\n"
            },
            "test.only('new'",
        ),
        (
            {
                "pkg/sum_test.go": _BASE["pkg/sum_test.go"].replace(
                    "\tt.Log(1)", '\tt.Skip("later")\n\tt.Log(1)'
                )
            },
            't.Skip("later")',
        ),
    ],
)
def test_removed_and_skipped_existing_tests_fail(
    workspace: RepositoryWorkspace, files: dict[str, str], expected: str
) -> None:
    _write(workspace, files)

    _, gates = _gates(workspace)

    assert _failed(gates) == {"existing_tests"}
    assert expected in gates["existing_tests"][1]


_PARSE = _BASE["web/parse.test.js"]


@pytest.mark.parametrize(
    ("files", "expected"),
    [
        (
            {"web/parse.test.js": _PARSE.replace("describe('parser'", "describe.skip('parser'")},
            "describe.skip('parser'",
        ),
        (
            {"web/parse.test.js": _PARSE.replace("describe('parser'", "xdescribe('parser'")},
            "xdescribe('parser'",
        ),
        (
            {"web/parse.test.js": _PARSE.replace("test.each([1, 2])", "test.skip.each([1, 2])")},
            "test.skip.each([1, 2])('parses %i'",
        ),
        (
            {
                "web/sum.test.js": "describe.skip('all', () => {\n"
                + _BASE["web/sum.test.js"]
                + "});\n"
            },
            "describe.skip('all'",
        ),
        (
            {
                "tests/test_calc.py": _BASE["tests/test_calc.py"].replace(
                    "from calc import add\n",
                    "from calc import add\n\npytestmark = pytest.mark.xfail\n",
                )
            },
            "pytestmark = pytest.mark.xfail",
        ),
    ],
)
def test_skipped_describe_blocks_tables_and_modules_fail(
    workspace: RepositoryWorkspace, files: dict[str, str], expected: str
) -> None:
    _write(workspace, files)

    _, gates = _gates(workspace)

    assert _failed(gates) == {"existing_tests"}
    assert expected in gates["existing_tests"][1]


def test_new_skipped_blocks_and_new_skipped_modules_pass(workspace: RepositoryWorkspace) -> None:
    _write(
        workspace,
        {
            "web/sum.test.js": _BASE["web/sum.test.js"]
            + "describe.skip('later', () => {\n  it('works', () => {});\n});\n",
            "tests/test_new.py": (
                "import pytest\n\npytestmark = pytest.mark.skip\n\n\ndef test_x():\n    pass\n"
            ),
        },
    )

    _, gates = _gates(workspace)

    assert not _failed(gates)


def test_a_deleted_test_file_fails(workspace: RepositoryWorkspace) -> None:
    (workspace.path / "pkg" / "sum_test.go").unlink()

    _, gates = _gates(workspace)

    assert gates["existing_tests"] == (
        False,
        "existing tests are removed or skipped: pkg/sum_test.go is deleted",
    )


def test_new_tests_may_carry_skip_markers(workspace: RepositoryWorkspace) -> None:
    _write(
        workspace,
        {
            "tests/test_calc.py": _BASE["tests/test_calc.py"]
            + "\n\n@pytest.mark.skipif(True, reason='posix only')\ndef test_new():\n"
            "    pytest.skip('not here')\n",
        },
    )

    _, gates = _gates(workspace)

    assert not _failed(gates)


def test_a_token_fails_the_secrets_gate_without_its_value(workspace: RepositoryWorkspace) -> None:
    _write(workspace, {"src/calc.py": f'TOKEN = "{_TOKEN}"\n' + _BASE["src/calc.py"]})

    outcome, gates = _gates(workspace, host_values=frozenset({_HOST_SECRET}))

    assert _failed(gates) == {"secrets"}
    assert not outcome.host_secret
    assert gates["secrets"][1] == "credentials found (values withheld): GitHub token in src/calc.py"
    assert _TOKEN not in str(outcome)


def test_a_host_secret_value_is_flagged_for_the_breaker(workspace: RepositoryWorkspace) -> None:
    _write(workspace, {"src/calc.py": f"# {_HOST_SECRET}\n" + _BASE["src/calc.py"]})

    outcome, gates = _gates(workspace, host_values=frozenset({_HOST_SECRET}))

    assert outcome.host_secret
    assert _failed(gates) == {"secrets"}
    assert _HOST_SECRET not in str(outcome)


@pytest.mark.parametrize(
    ("path", "pattern", "matches"),
    [
        ("build.rs", "**/build.rs", True),
        ("crates/x/build.rs", "**/build.rs", True),
        (".husky/pre-commit", "**/.husky/**", True),
        (".github/CODEOWNERS", ".github/**", True),
        ("src/github.py", ".github/**", False),
    ],
)
def test_path_matches(path: str, pattern: str, matches: bool) -> None:
    assert path_matches(path, pattern) is matches


def test_dependency_and_workflow_paths() -> None:
    assert is_dependency_path("requirements-dev.txt")
    assert is_dependency_path("web/package-lock.json")
    assert not is_dependency_path("src/package.py")
    assert is_workflow_path(".github/workflows/ci.yml")
    assert is_workflow_path(".circleci/config.yml")
    assert not is_workflow_path("docs/workflows.md")


def test_changed_tests_name_the_tests_whose_lines_change(workspace: RepositoryWorkspace) -> None:
    _write(
        workspace,
        {
            "tests/test_calc.py": _BASE["tests/test_calc.py"].replace(
                "add(0, 0) == 0", "add(0, 1) == 1"
            )
            + "\n\ndef helper():\n    return 1\n",
            "web/parse.test.js": _PARSE.replace("parse('1')).toBe(1)", "parse('2')).toBe(2)"),
        },
    )
    (workspace.path / "pkg" / "sum_test.go").unlink()
    patch = extract_patch(workspace)

    changed = changed_tests(
        split_patch(patch, WorkspaceFiles(workspace.path)).tests, WorkspaceFiles(workspace.path)
    )

    assert changed.paths == {"tests/test_calc.py", "web/parse.test.js"}
    assert changed.names == {"test_zero", "parses numbers"}
    assert changed.includes("tests.test_calc::test_zero")
    assert changed.includes("tests.test_calc::test_zero[1]")
    assert not changed.includes("tests.test_calc::test_adds")
    assert not changed.includes("tests.test_other::test_zero")
    assert changed.includes("web/parse.test.js::parser parses numbers")
    assert not changed.includes("web/sum.test.js::parser parses numbers")
