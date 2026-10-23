"""The checks a submitted patch passes before any test runs (DESIGN §7.1, step 2).

They read the patch, its paths and the agent's workspace only, so they take milliseconds and
need no container. Each gate names what failed, and the agent gets the list back with its
submit. Test files are told from source files as :func:`autocontribute.patches.split_patch`
does, and the source-only limits count what remains.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Final

from autocontribute.config import PolicyConfig, QualityConfig
from autocontribute.domain import GateResult
from autocontribute.exceptions import RepositoryError
from autocontribute.patches import FilePatch, Patch, PatchSplit
from autocontribute.redaction import high_confidence_token_labels, is_sensitive_path
from autocontribute.repository import RepositoryWorkspace

# DESIGN §2: the new quality keys for non-test files.
DEFAULT_MAX_SOURCE_FILES: Final = 3
DEFAULT_MAX_SOURCE_LINES: Final = 150
_LISTED_PATHS: Final = 5

_DEPENDENCY_FILES: Final = frozenset(
    {
        "build.sbt",
        "cargo.toml",
        "composer.json",
        "deno.json",
        "deno.jsonc",
        "deps.edn",
        "directory.packages.props",
        "gemfile",
        "go.mod",
        "go.work",
        "mix.exs",
        "package.json",
        "packages.config",
        "pipfile",
        "podfile",
        "pom.xml",
        "pubspec.yaml",
        "pyproject.toml",
        "setup.cfg",
        "setup.py",
    }
)
_LOCK_FILES: Final = frozenset(
    {
        "bun.lock",
        "bun.lockb",
        "cargo.lock",
        "composer.lock",
        "deno.lock",
        "flake.lock",
        "gemfile.lock",
        "go.sum",
        "go.work.sum",
        "gradle.lockfile",
        "mix.lock",
        "package-lock.json",
        "package.resolved",
        "packages.lock.json",
        "paket.lock",
        "pipfile.lock",
        "pnpm-lock.yaml",
        "podfile.lock",
        "poetry.lock",
        "pubspec.lock",
        "renv.lock",
        "uv.lock",
        "yarn.lock",
    }
)
_WORKFLOW_FILES: Final = frozenset({".gitlab-ci.yml", "azure-pipelines.yml", "jenkinsfile"})
_SYMLINK_MODE: Final = "120000"
_SUBMODULE_MODE: Final = "160000"
# A JavaScript test or describe block, skipped, focused or table-driven: `it(`, `xit(`,
# `describe.skip(`, `test.skip.each([...])(`.
_JAVASCRIPT_TEST: Final = (
    r"(?:(?:it|test|describe)(?:\.(?:only|skip|todo|concurrent))*|x(?:it|test|describe)"
    r"|f(?:it|describe))(?:\.each\s*\(.*\)\s*)?"
)
# A test that a patch removes: Python functions and classes, Go functions, JavaScript tests
# and describe blocks.
_TEST_DEFINITIONS: Final = (
    re.compile(r"^\s*(?:async\s+)?def\s+(?P<name>test\w*)\s*\("),
    re.compile(r"^\s*class\s+(?P<name>Test\w*)\b"),
    re.compile(r"^func\s+(?P<name>Test\w*)\s*\("),
    re.compile(rf"^\s*{_JAVASCRIPT_TEST}\s*\(\s*(?P<quote>['\"`])(?P<name>.+?)(?P=quote)"),
)
_RUST_TEST_ATTRIBUTE: Final = re.compile(r"^\s*#\[\s*(?:tokio::)?test\b")
# Markers that keep a test from running, or that focus a file on one test so the rest do not.
_DECORATOR_SKIPS: Final = re.compile(
    r"^\s*(?:@pytest\.mark\.(?:skip|skipif|xfail)\b|@unittest\.(?:skip\w*|expectedFailure)\b"
    r"|#\[\s*ignore\b)"
)
_CALL_SKIPS: Final = re.compile(
    r"\bpytest\.(?:skip|xfail)\s*\(|\.skipTest\s*\(|\braise\s+(?:unittest\.)?SkipTest\b"
    r"|\bt\.Skip(?:f|Now)?\s*\("
)
# Unindented, it skips every test of the module; inside a class, the class's tests.
_PYTEST_MARK_SKIP: Final = re.compile(
    r"^(?P<indent>\s*)pytestmark\s*=.*\bpytest\.mark\.(?:skip|skipif|xfail)\b"
)
_JAVASCRIPT_SKIP: Final = re.compile(
    r"^\s*(?P<kind>(?:it|test|describe)(?:\.concurrent)?\.(?:skip|todo)|x(?:it|test|describe))"
    r"(?:\.each\s*\(.*\)\s*)?\s*\(\s*(?P<quote>['\"`])(?P<name>.+?)(?P=quote)"
)
_JAVASCRIPT_FOCUS: Final = re.compile(r"^\s*(?:(?:it|test|describe)\.only|f(?:it|describe))\s*\(")
# A line that starts a function, class or test, for finding which test a marker belongs to.
_DEFINITION: Final = re.compile(
    r"^\s*(?:(?:async\s+)?def\s|class\s|func\s|(?:pub\s+)?(?:async\s+)?fn\s"
    rf"|{_JAVASCRIPT_TEST}\s*\()"
)


@dataclass(frozen=True, slots=True)
class DiffGateOutcome:
    """The diff gates of one patch, in a fixed order."""

    gates: tuple[GateResult, ...]
    # An exact host secret value is in an added line: the caller stops every run (§3.6).
    host_secret: bool

    @property
    def passed(self) -> bool:
        return all(gate.passed for gate in self.gates)


def diff_gates(
    workspace: RepositoryWorkspace,
    patch: Patch,
    split: PatchSplit,
    *,
    quality: QualityConfig,
    policy: PolicyConfig,
    host_values: frozenset[str],
    max_source_files: int = DEFAULT_MAX_SOURCE_FILES,
    max_source_lines: int = DEFAULT_MAX_SOURCE_LINES,
) -> DiffGateOutcome:
    """Run every diff gate on ``patch``, extracted from ``workspace``, and its test split.

    The paths come from ``git diff -z`` through :meth:`RepositoryWorkspace.changed_paths`,
    which refuses unsafe names and symlinks; the patch's own headers give them otherwise.
    """

    gates: list[GateResult] = []

    def gate(name: str, passed: bool, evidence: str) -> None:
        gates.append(GateResult(gate=name, passed=passed, evidence=evidence))

    try:
        paths = workspace.changed_paths()
        unsafe = None
    except RepositoryError as exc:
        paths = list(patch.paths)
        unsafe = str(exc)
    files = len(patch.files)
    gate("diff_present", files > 0, f"{files} changed file(s)")
    gate(
        "file_count",
        files <= quality.max_files_changed,
        f"{files} changed file(s); the limit is {quality.max_files_changed}",
    )
    gate(
        "changed_lines",
        patch.changed_lines <= quality.max_changed_lines,
        f"{patch.changed_lines} changed line(s); the limit is {quality.max_changed_lines}",
    )
    sources = len(split.sources.files)
    gate(
        "source_file_count",
        sources <= max_source_files,
        f"{sources} changed non-test file(s); the limit is {max_source_files}",
    )
    gate(
        "source_changed_lines",
        split.sources.changed_lines <= max_source_lines,
        f"{split.sources.changed_lines} changed non-test line(s); the limit is {max_source_lines}",
    )
    for name, kind, flagged in (
        ("no_binary_files", "binary file", _binary),
        ("no_symlinks", "symlink", _symlink),
        ("no_submodules", "submodule", _submodule),
        ("no_mode_changes", "mode change", _mode_changed),
    ):
        found = [file.path for file in patch.files if flagged(file)]
        gate(name, not found, _evidence(kind, found))
    gate("safe_paths", unsafe is None, unsafe or "every path can be handled safely")
    forbidden = [
        path for path in paths if any(path_matches(path, glob) for glob in quality.forbidden_paths)
    ]
    gate("forbidden_paths", not forbidden, _evidence("forbidden path", forbidden))
    sensitive = [path for path in paths if is_sensitive_path(path)]
    gate("sensitive_paths", not sensitive, _evidence("credential file", sensitive))
    dependencies = [path for path in paths if is_dependency_path(path)]
    gate(
        "dependency_policy",
        policy.allow_dependency_changes or not dependencies,
        "dependency changes are allowed by policy"
        if policy.allow_dependency_changes
        else _evidence("dependency manifest or lock file", dependencies),
    )
    workflows = [path for path in paths if is_workflow_path(path)]
    gate(
        "workflow_policy",
        policy.allow_workflow_changes or not workflows,
        "CI configuration changes are allowed by policy"
        if policy.allow_workflow_changes
        else _evidence("CI configuration file", workflows),
    )
    removed = [*_removed_tests(split.tests)]
    gate(
        "existing_tests",
        not removed,
        "no existing test is removed or skipped"
        if not removed
        else "existing tests are removed or skipped: " + "; ".join(removed[:_LISTED_PATHS]),
    )
    findings = sorted(
        {
            f"{label} in {file.path}"
            for file in patch.files
            for line in _added_lines(file)
            for label in high_confidence_token_labels(line)
        }
    )
    host_secret = any(
        value in line
        for file in patch.files
        for line in _added_lines(file)
        for value in host_values
    )
    if host_secret:
        findings.insert(0, "a secret value of this machine")
    gate(
        "secrets",
        not findings,
        "no credential found in added lines"
        if not findings
        else "credentials found (values withheld): " + ", ".join(findings),
    )
    return DiffGateOutcome(tuple(gates), host_secret)


def path_matches(path: str, pattern: str) -> bool:
    """Match a repository path against a glob; ``**/`` also matches at the root."""

    normalized_path = path.replace("\\", "/").removeprefix("./")
    normalized_pattern = pattern.replace("\\", "/").removeprefix("./")
    if fnmatch.fnmatchcase(normalized_path, normalized_pattern):
        return True
    if normalized_pattern.startswith("**/"):
        return fnmatch.fnmatchcase(normalized_path, normalized_pattern[3:])
    return False


def is_dependency_path(path: str) -> bool:
    """Return whether a path is a dependency manifest or lock file."""

    lowered = path.casefold().replace("\\", "/")
    name = lowered.rsplit("/", 1)[-1]
    return (
        name in _DEPENDENCY_FILES
        or name in _LOCK_FILES
        or (name.startswith("requirements") and name.endswith((".txt", ".in")))
        or lowered.endswith("/gradle/libs.versions.toml")
        or name in {"build.gradle", "build.gradle.kts"}
        or name.endswith((".csproj", ".fsproj", ".gemspec", ".nuspec", ".vbproj"))
    )


def is_workflow_path(path: str) -> bool:
    """Return whether a path is CI configuration."""

    lowered = path.casefold().replace("\\", "/").removeprefix("./")
    name = lowered.rsplit("/", 1)[-1]
    return (
        lowered.startswith((".github/workflows/", ".github/actions/", ".circleci/", ".buildkite/"))
        or name in _WORKFLOW_FILES
    )


def _header_lines(file: FilePatch) -> list[str]:
    return file.header.split("\n")


def _binary(file: FilePatch) -> bool:
    return any(
        line == "GIT binary patch" or line.startswith("Binary files ")
        for line in _header_lines(file)
    )


def _has_mode(file: FilePatch, mode: str) -> bool:
    prefixes = ("new file mode ", "deleted file mode ", "old mode ", "new mode ", "index ")
    return any(
        line.startswith(prefixes) and line.endswith(f" {mode}") for line in _header_lines(file)
    )


def _symlink(file: FilePatch) -> bool:
    return _has_mode(file, _SYMLINK_MODE)


def _submodule(file: FilePatch) -> bool:
    return _has_mode(file, _SUBMODULE_MODE)


def _mode_changed(file: FilePatch) -> bool:
    return any(line.startswith(("old mode ", "new mode ")) for line in _header_lines(file))


def _hunk_lines(file: FilePatch) -> Iterator[list[str]]:
    """Yield each hunk's lines after its ``@@`` header; newlines only split lines."""

    for hunk in file.hunks:
        lines = hunk.split("\n")[1:]
        if lines and lines[-1] == "":
            lines.pop()
        yield lines


def _added_lines(file: FilePatch) -> Iterator[str]:
    for lines in _hunk_lines(file):
        yield from (line[1:] for line in lines if line.startswith("+"))


def _removed_tests(tests: Patch) -> Iterator[str]:
    """Describe each existing test the test part of a patch removes, renames or skips."""

    for file in tests.files:
        if "\ndeleted file mode " in file.header:
            yield f"{file.path} is deleted"
            continue
        removed: list[str] = []
        added: set[str] = set()
        rust_tests = 0
        for lines in _hunk_lines(file):
            for line in lines:
                name = _test_name(line[1:])
                if line.startswith("-") and name is not None:
                    removed.append(name)
                elif line.startswith("+") and name is not None:
                    added.add(name)
                if _RUST_TEST_ATTRIBUTE.match(line[1:]):
                    rust_tests += {"-": -1, "+": 1}.get(line[:1], 0)
        gone = [name for name in dict.fromkeys(removed) if name not in added]
        if gone:
            yield f"{', '.join(gone[:_LISTED_PATHS])} removed or renamed in {file.path}"
        if rust_tests < 0:
            yield f"{-rust_tests} #[test] function(s) removed in {file.path}"
        skipped = [*_skipped_existing(file, removed)]
        if skipped:
            yield f"skip or focus markers on existing tests in {file.path}: {', '.join(skipped)}"


def _test_name(code: str) -> str | None:
    for pattern in _TEST_DEFINITIONS:
        match = pattern.match(code)
        if match is not None:
            return match.group("name")
    return None


def _skipped_existing(file: FilePatch, removed: Sequence[str]) -> Iterator[str]:
    """Yield the added lines that skip or focus a test the patch did not add.

    A decorator, and a skipped describe block, belongs to the next definition, and a call such
    as ``pytest.skip()`` or a class's ``pytestmark`` to the one before it; a definition on an
    added line is new. When the hunk shows no definition, the test is taken to exist already.
    A module's ``pytestmark`` skips every test of a file the patch did not create.
    """

    new_file = "\nnew file mode " in file.header
    for lines in _hunk_lines(file):
        for index, line in enumerate(lines):
            if not line.startswith("+"):
                continue
            code = line[1:]
            following = (other for other in lines[index + 1 :] if not other.startswith("-"))
            preceding = (other for other in reversed(lines[:index]) if not other.startswith("-"))
            module_mark = _PYTEST_MARK_SKIP.match(code)
            if _JAVASCRIPT_FOCUS.match(code):
                yield code.strip()
                continue
            javascript = _JAVASCRIPT_SKIP.match(code)
            if javascript is not None:
                wraps = "describe" in javascript.group("kind")
                inner = next((other for other in following if _DEFINITION.match(other[1:])), None)
                existing = inner is None or not inner.startswith("+")
                if javascript.group("name") in removed or (wraps and existing):
                    yield code.strip()
                continue
            if module_mark is not None and not module_mark.group("indent"):
                if not new_file:
                    yield code.strip()
                continue
            if _DECORATOR_SKIPS.match(code):
                owner = next((other for other in following if _DEFINITION.match(other[1:])), None)
            elif _CALL_SKIPS.search(code) or module_mark is not None:
                owner = next((other for other in preceding if _DEFINITION.match(other[1:])), None)
            else:
                continue
            if owner is None or not owner.startswith("+"):
                yield code.strip()


def _evidence(kind: str, paths: Sequence[str]) -> str:
    if not paths:
        return f"no {kind}s"
    unique = sorted(dict.fromkeys(paths))
    listed = ", ".join(unique[:_LISTED_PATHS])
    more = f" and {len(unique) - _LISTED_PATHS} more" if len(unique) > _LISTED_PATHS else ""
    return f"{kind}(s): {listed}{more}"


__all__ = [
    "DEFAULT_MAX_SOURCE_FILES",
    "DEFAULT_MAX_SOURCE_LINES",
    "DiffGateOutcome",
    "diff_gates",
    "is_dependency_path",
    "is_workflow_path",
    "path_matches",
]
