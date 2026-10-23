from __future__ import annotations

from typing import Any

import pytest

from autocontribute.environments import EnvironmentRecipe
from autocontribute.suite_selection import related_test_command

_PYTEST_REPORT = "-p no:cacheprovider --junitxml=/tmp/ac-report.xml"
_PYTHON_TREE = frozenset(
    {
        "pyproject.toml",
        "src/pkg/__init__.py",
        "src/pkg/calc.py",
        "src/pkg/cli.py",
        "src/pkg/test_inline.py",
        "tests/conftest.py",
        "tests/test_calc.py",
        "tests/test_cli.py",
        "tests/unit/calc_test.py",
        "tests/integration/test_pkg.py",
        "docs/index.md",
    }
)


def _recipe(framework: str, command: str, **changes: Any) -> EnvironmentRecipe:
    fields: dict[str, Any] = {
        "repository": "acme/demo",
        "language": "other",
        "base_image": "debian:bookworm",
        "system_packages": [],
        "setup_commands": [],
        "build_commands": [],
        "test_command": command,
        "test_framework": framework,
        "test_report": None,
        "env": {},
        "offline_env": {},
        "fetch_tags": False,
        "fetch_submodules": False,
        "source": "detected",
        "dependency_digest": "b" * 64,
    }
    return EnvironmentRecipe.model_validate({**fields, **changes})


def test_pytest_runs_changed_test_modules_and_those_named_after_or_beside_changed_code() -> None:
    recipe = _recipe(
        "pytest",
        "python -m pytest -o console_output_style=progress -k 'not slow' --tb short tests "
        + _PYTEST_REPORT,
    )

    command = related_test_command(
        recipe, ["src/pkg/calc.py", "tests/test_cli.py", "docs/index.md"], _PYTHON_TREE
    )

    # The CI's own `tests` argument goes; its options and the report stay.
    assert command == (
        "python -m pytest -o console_output_style=progress -k 'not slow' --tb short "
        f"{_PYTEST_REPORT} src/pkg/test_inline.py tests/test_calc.py tests/test_cli.py "
        "tests/unit/calc_test.py"
    )
    # A package's __init__ relates to tests named after the package; a conftest to the
    # test modules beside it.
    assert related_test_command(recipe, ["src/pkg/__init__.py"], _PYTHON_TREE) == (
        "python -m pytest -o console_output_style=progress -k 'not slow' --tb short "
        f"{_PYTEST_REPORT} src/pkg/test_inline.py tests/integration/test_pkg.py"
    )
    assert related_test_command(recipe, ["tests/conftest.py"], _PYTHON_TREE) == (
        "python -m pytest -o console_output_style=progress -k 'not slow' --tb short "
        f"{_PYTEST_REPORT} tests/test_calc.py tests/test_cli.py"
    )
    # A deleted test module is not selected, the modules beside it are.
    assert related_test_command(recipe, ["tests/test_gone.py"], _PYTHON_TREE) == (
        related_test_command(recipe, ["tests/conftest.py"], _PYTHON_TREE)
    )


@pytest.mark.parametrize(
    ("command", "paths"),
    [
        # Nothing related: the caller runs the full suite.
        (f"python -m pytest {_PYTEST_REPORT}", ["docs/index.md", "scripts/release.py"]),
        # Words after `--` all select tests, and nox adds its own.
        (f"python -m pytest {_PYTEST_REPORT} -- tests", ["tests/test_cli.py"]),
        (
            f"nox --session tests --force-python 3.12 -R -- {_PYTEST_REPORT}",
            ["tests/test_cli.py"],
        ),
    ],
)
def test_pytest_commands_that_cannot_be_narrowed_run_the_full_suite(
    command: str, paths: list[str]
) -> None:
    assert related_test_command(_recipe("pytest", command), paths, _PYTHON_TREE) is None


def test_jest_and_vitest_find_the_tests_that_depend_on_the_changed_files() -> None:
    tree = frozenset({"package.json", "src/sum.ts", "src/sum.test.ts", "README.md"})
    paths = ["README.md", "src/sum.test.ts", "src/sum.ts", "src/deleted.ts"]
    jest = _recipe("jest", "jest --runInBand -w 2 src --ci --json --outputFile=/tmp/ac-report.json")
    vitest = _recipe(
        "vitest", "vitest run --project unit --reporter=json --outputFile=/tmp/ac-report.json"
    )

    assert related_test_command(jest, paths, tree) == (
        "jest --runInBand -w 2 --ci --json --outputFile=/tmp/ac-report.json "
        "--findRelatedTests src/sum.test.ts src/sum.ts"
    )
    assert related_test_command(vitest, paths, tree) == (
        "vitest related src/sum.test.ts src/sum.ts --run --project unit --reporter=json "
        "--outputFile=/tmp/ac-report.json"
    )
    assert related_test_command(jest, ["README.md"], tree) is None


def test_go_runs_the_changed_packages_of_the_root_module() -> None:
    tree = frozenset(
        {
            "go.mod",
            "main.go",
            "cmd/root.go",
            "cmd/root_test.go",
            "internal/x/x.go",
            "internal/x/testdata/fixture.go",
            "tools/go.mod",
            "tools/gen/gen.go",
            "vendor/dep/dep.go",
        }
    )
    recipe = _recipe(
        "go", "go test -json -tags integration -count=1 ./cmd/... > /tmp/ac-report.json"
    )
    paths = [
        "cmd/root_test.go",
        "cmd/root.go",
        "internal/x/x.go",
        "internal/x/testdata/fixture.go",
        "internal/gone/gone.go",
        "tools/gen/gen.go",
        "vendor/dep/dep.go",
        "main.go",
        "README.md",
    ]

    assert related_test_command(recipe, paths, tree) == (
        "go test -json -tags integration -count=1 . ./cmd ./internal/x > /tmp/ac-report.json"
    )
    assert related_test_command(recipe, ["tools/gen/gen.go"], tree) is None


def test_cargo_runs_the_one_crate_that_holds_the_changes() -> None:
    tree = frozenset(
        {
            "Cargo.toml",
            "src/lib.rs",
            "crates/core/Cargo.toml",
            "crates/core/src/lib.rs",
            "crates/core/tests/api.rs",
            "crates/cli/Cargo.toml",
            "crates/cli/src/main.rs",
        }
    )
    workspace = _recipe(
        "cargo", "cargo test --workspace --all-features --no-fail-fast > /tmp/ac-report.txt"
    )

    assert related_test_command(
        workspace, ["crates/core/src/lib.rs", "crates/core/tests/api.rs"], tree
    ) == (
        "cargo test --manifest-path crates/core/Cargo.toml --all-features --no-fail-fast "
        "> /tmp/ac-report.txt"
    )
    assert related_test_command(workspace, ["src/lib.rs"], tree) == (
        "cargo test --manifest-path Cargo.toml --all-features --no-fail-fast > /tmp/ac-report.txt"
    )
    # Two crates, or features that may belong to another member, need the whole workspace.
    assert (
        related_test_command(workspace, ["crates/core/src/lib.rs", "crates/cli/src/main.rs"], tree)
        is None
    )
    featured = _recipe(
        "cargo",
        "cargo test --workspace --features cli,pcre2 --no-fail-fast > /tmp/ac-report.txt",
    )
    assert related_test_command(featured, ["crates/core/src/lib.rs"], tree) is None


@pytest.mark.parametrize(
    ("framework", "command"),
    [
        ("mocha", "mocha test/ --reporter json --reporter-option output=/tmp/ac-report.json"),
        ("unittest", "python -m unittest discover -s tests"),
        ("other", "make test"),
        ("pytest", "python -m pytest 'unterminated"),
    ],
)
def test_other_runners_are_not_narrowed(framework: str, command: str) -> None:
    recipe = _recipe(framework, command)

    assert related_test_command(recipe, ["test/app.js", "tests/test_cli.py"], _PYTHON_TREE) is None
