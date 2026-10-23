"""Test commands narrowed to the tests related to some paths (DESIGN §7.1, steps 3 and 4).

The red/green step runs the tests of a patch's test files, and regression runs the tests related
to everything a patch changes before the full suite. Both narrow the recipe's own test command:
its options and its report stay, so the per-test results compare with the baseline. Only the
command shapes detection writes are narrowed; for anything else, or when nothing is related,
there is no narrowed command and the caller runs the full suite.
"""

from __future__ import annotations

import fnmatch
import shlex
from collections.abc import Collection, Sequence
from pathlib import PurePosixPath
from typing import Final

from autocontribute.environments import EnvironmentRecipe

# Options, without their dashes, that take the next word as their value. Every other word that
# does not start with "-" selects tests, and is replaced by the related ones.
_PYTEST_VALUE_OPTIONS: Final = frozenset(
    {
        "c",
        "k",
        "m",
        "n",
        "o",
        "p",
        "r",
        "W",
        "basetemp",
        "capture",
        "confcutdir",
        "config-file",
        "deselect",
        "dist",
        "doctest-glob",
        "durations",
        "durations-min",
        "ignore",
        "ignore-glob",
        "import-mode",
        "junit-prefix",
        "log-cli-level",
        "log-file",
        "log-file-level",
        "log-format",
        "log-level",
        "maxfail",
        "maxprocesses",
        "numprocesses",
        "override-ini",
        "pythonwarnings",
        "reruns",
        "reruns-delay",
        "rootdir",
        "tb",
        "timeout",
    }
)
_JEST_VALUE_OPTIONS: Final = frozenset(
    {
        "c",
        "t",
        "w",
        "config",
        "env",
        "maxConcurrency",
        "maxWorkers",
        "outputFile",
        "reporters",
        "rootDir",
        "roots",
        "seed",
        "selectProjects",
        "setupFiles",
        "setupFilesAfterEnv",
        "shard",
        "testEnvironment",
        "testNamePattern",
        "testPathIgnorePatterns",
        "testPathPattern",
        "testPathPatterns",
        "testTimeout",
    }
)
_VITEST_VALUE_OPTIONS: Final = frozenset(
    {
        "c",
        "r",
        "t",
        "config",
        "dir",
        "environment",
        "exclude",
        "hookTimeout",
        "maxWorkers",
        "minWorkers",
        "mode",
        "outputFile",
        "pool",
        "project",
        "reporter",
        "retry",
        "root",
        "shard",
        "testNamePattern",
        "testTimeout",
    }
)
_GO_VALUE_FLAGS: Final = frozenset(
    {
        "asmflags",
        "bench",
        "benchtime",
        "blockprofile",
        "count",
        "covermode",
        "coverpkg",
        "coverprofile",
        "cpu",
        "cpuprofile",
        "exec",
        "fuzz",
        "fuzzminimizetime",
        "fuzztime",
        "gcflags",
        "ldflags",
        "list",
        "memprofile",
        "mod",
        "modfile",
        "o",
        "outputdir",
        "overlay",
        "p",
        "parallel",
        "pkgdir",
        "run",
        "shuffle",
        "skip",
        "tags",
        "timeout",
        "toolexec",
        "trace",
        "vet",
    }
)
# Cargo options that widen a run to the whole workspace, or need it.
_CARGO_WORKSPACE_FLAGS: Final = frozenset({"--workspace", "--all"})
_CARGO_WORKSPACE_ONLY: Final = frozenset({"--exclude", "--features", "-F"})
_PYTEST_MODULES: Final = ("test_*.py", "*_test.py")
_JAVASCRIPT_SUFFIXES: Final = (
    ".cjs",
    ".cts",
    ".js",
    ".jsx",
    ".mjs",
    ".mts",
    ".svelte",
    ".ts",
    ".tsx",
    ".vue",
)
_GO_SKIPPED_DIRECTORIES: Final = frozenset({"testdata", "vendor"})


def related_test_command(
    recipe: EnvironmentRecipe, paths: Collection[str], tree_paths: Collection[str]
) -> str | None:
    """Return the recipe's test command narrowed to the tests related to ``paths``, if any.

    ``paths`` are repository paths: the test files a patch adds or changes, for the red/green
    step, or every path it changes, for regression. ``tree_paths`` lists every file of the tree
    the command will run on. Related tests are, for pytest, the test modules among ``paths``
    and those named after or placed beside a changed module; for Jest and Vitest, the tests
    the runner finds depending on ``paths``; for Go, the packages of ``paths``; for cargo, the
    one crate that holds them. Returns ``None`` when the command cannot be narrowed or nothing
    is related.
    """

    try:
        words = shlex.split(recipe.test_command)
    except ValueError:
        return None
    present = frozenset(tree_paths)
    # A path that starts with "-" would read as an option.
    changed = sorted(path for path in paths if not path.startswith("-"))
    if recipe.test_framework == "pytest":
        return _pytest_command(words, changed, present)
    if recipe.test_framework == "jest":
        return _jest_command(words, changed, present)
    if recipe.test_framework == "vitest":
        return _vitest_command(words, changed, present)
    if recipe.test_framework == "go":
        return _go_command(words, changed, present)
    if recipe.test_framework == "cargo":
        return _cargo_command(words, changed, present)
    return None


def _pytest_command(
    words: Sequence[str], paths: Sequence[str], present: frozenset[str]
) -> str | None:
    # A nox session passes the words after `--` behind its own test paths, so only a direct
    # pytest run can be narrowed.
    if not _starts(words, "python -m pytest"):
        return None
    options = _options(words[3:], _PYTEST_VALUE_OPTIONS)
    modules = frozenset(path for path in present if _is_pytest_module(path))
    selected: set[str] = set()
    for path in paths:
        changed = PurePosixPath(path)
        if changed.suffix != ".py":
            continue
        if path in modules:
            selected.add(path)
            continue
        stem = changed.parent.name if changed.name == "__init__.py" else changed.stem
        named = {f"test_{stem}.py", f"{stem}_test.py"}
        selected.update(
            module
            for module in modules
            if PurePosixPath(module).parent == changed.parent or PurePosixPath(module).name in named
        )
    if options is None or not selected:
        return None
    return shlex.join([*words[:3], *options, *sorted(selected)])


def _jest_command(
    words: Sequence[str], paths: Sequence[str], present: frozenset[str]
) -> str | None:
    files = _javascript_files(paths, present)
    if not _starts(words, "jest") or not files:
        return None
    options = _options(words[1:], _JEST_VALUE_OPTIONS)
    if options is None:
        return None
    return shlex.join(["jest", *options, "--findRelatedTests", *files])


def _vitest_command(
    words: Sequence[str], paths: Sequence[str], present: frozenset[str]
) -> str | None:
    files = _javascript_files(paths, present)
    if not _starts(words, "vitest run") or not files:
        return None
    options = _options(words[2:], _VITEST_VALUE_OPTIONS)
    if options is None:
        return None
    return shlex.join(["vitest", "related", *files, "--run", *options])


def _go_command(words: Sequence[str], paths: Sequence[str], present: frozenset[str]) -> str | None:
    if not _starts(words, "go test -json") or words[-2:-1] != [">"]:
        return None
    options = _options(words[3:-2], _GO_VALUE_FLAGS)
    directories = {PurePosixPath(path).parent for path in paths if path.endswith(".go")}
    packages = sorted(
        "." if str(directory) == "." else f"./{directory}"
        for directory in directories
        if _is_root_module_package(directory, present)
    )
    if options is None or not packages:
        return None
    return shlex.join(["go", "test", "-json", *options, *packages]) + _redirect(words)


def _cargo_command(
    words: Sequence[str], paths: Sequence[str], present: frozenset[str]
) -> str | None:
    if not _starts(words, "cargo test") or words[-2:-1] != [">"]:
        return None
    flags = list(words[2:-2])
    crates = {
        crate
        for path in paths
        if path.endswith(".rs") or PurePosixPath(path).name == "Cargo.toml"
        if (crate := _crate_of(PurePosixPath(path), present)) is not None
    }
    if len(crates) != 1 or any(flag.split("=", 1)[0] in _CARGO_WORKSPACE_ONLY for flag in flags):
        return None
    manifest = str(crates.pop() / "Cargo.toml")
    narrowed = [flag for flag in flags if flag not in _CARGO_WORKSPACE_FLAGS]
    return shlex.join(["cargo", "test", "--manifest-path", manifest, *narrowed]) + _redirect(words)


def _options(words: Sequence[str], value_options: frozenset[str]) -> list[str] | None:
    """Keep the options and their values, dropping the words that select tests.

    Returns ``None`` for a `--` separator, after which every word selects tests.
    """

    kept: list[str] = []
    takes_value = False
    for word in words:
        if takes_value:
            kept.append(word)
            takes_value = False
        elif word == "--":
            return None
        elif word.startswith("-"):
            kept.append(word)
            takes_value = "=" not in word and word.lstrip("-") in value_options
    return kept


def _starts(words: Sequence[str], prefix: str) -> bool:
    expected = prefix.split()
    return list(words[: len(expected)]) == expected


def _redirect(words: Sequence[str]) -> str:
    # Detection sends the go and cargo report to a file with a trailing `> path`.
    return f" > {shlex.quote(words[-1])}"


def _is_pytest_module(path: str) -> bool:
    name = PurePosixPath(path).name
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in _PYTEST_MODULES)


def _javascript_files(paths: Sequence[str], present: frozenset[str]) -> list[str]:
    return [path for path in paths if path in present and path.endswith(_JAVASCRIPT_SUFFIXES)]


def _is_root_module_package(directory: PurePosixPath, present: frozenset[str]) -> bool:
    """Whether ``directory`` holds Go files of the root module, which `go test` runs from."""

    if any(
        part in _GO_SKIPPED_DIRECTORIES or part.startswith(("_", ".")) for part in directory.parts
    ):
        return False
    if any(str(parent / "go.mod") in present for parent in (directory, *directory.parents)[:-1]):
        return False
    return any(PurePosixPath(path).parent == directory and path.endswith(".go") for path in present)


def _crate_of(path: PurePosixPath, present: frozenset[str]) -> PurePosixPath | None:
    for directory in path.parents:
        if str(directory / "Cargo.toml") in present:
            return directory
    return None


__all__ = ["related_test_command"]
