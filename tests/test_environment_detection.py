from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from autocontribute.environment_detection import detect_recipe
from autocontribute.environment_signals import RepositorySignals, read_signals
from autocontribute.environments import EnvironmentOverride
from autocontribute.exceptions import EnvironmentRecipeError
from autocontribute.repository import RepositoryWorkspace

# Signal files of real repositories, fetched read-only with `gh api` on 2026-10-22 at the
# commits research-envsetup.md studied: click 2247b35, requests 611c616, httpx b5addb6,
# pytest c9bf1ed, typer a5882de, express 0dee2c5, cobra adbc881, ripgrep 3fce3b5. Lockfiles
# keep only their first lines: detection reads their presence and object IDs, not content.
_FIXTURES = Path(__file__).parent / "fixtures" / "environments"
_PYTHON_SETUP = [
    "python3 -m venv /opt/ac/tools",
    "/opt/ac/tools/bin/python -m pip install --no-cache-dir --disable-pip-version-check "
    "uv==0.12.24",
    "uv venv /opt/ac/venv --python /usr/local/bin/python3",
]
_PYTEST_REPORT = "-p no:cacheprovider --junitxml=/tmp/ac-report.xml"


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


def _signals(root: Path, files: Mapping[str, str] | Path) -> RepositorySignals:
    if isinstance(files, Path):
        shutil.copytree(files, root)
    else:
        for relative, content in files.items():
            (root / relative).parent.mkdir(parents=True, exist_ok=True)
            (root / relative).write_text(content, encoding="utf-8")
    _git(root, "init", "--quiet")
    _git(root, "add", "--all")
    _git(root, "-c", "user.name=F", "-c", "user.email=f@example.invalid", "commit", "-qm", "base")
    return read_signals(RepositoryWorkspace(root, _git(root, "rev-parse", "HEAD")))


@dataclass(frozen=True)
class _Expected:
    language: str
    base_image: str
    install: list[str]
    test_command: str
    test_framework: str
    env: dict[str, str] = field(default_factory=dict)
    fetch_tags: bool = False
    system_packages: tuple[str, ...] = ()


# What research-envsetup.md "How CI expresses install and test" reports each CI doing, as the
# offline recipe: lint, coverage and network-only steps dropped, a structured reporter added.
_CI_RECIPES = {
    # CI: `uv run --group dev tox run` with TOX_ENV=py3.X; the tox env installs group
    # "tests" and runs `pytest -v --tb=short`. Newest stable matrix Python is 3.14.
    "pallets__click": _Expected(
        "python",
        "python:3.14-bookworm",
        [
            "uv sync --locked --no-default-groups --group tests "
            "|| uv sync --frozen --no-default-groups --group tests"
        ],
        # pyproject names pytest-randomly (group tests-random), so the order is pinned.
        "python -m pytest -v --tb=short -p no:cacheprovider -p no:randomly "
        "--junitxml=/tmp/ac-report.xml",
        "pytest",
    ),
    # CI: `make` installs requirements-dev.txt (which has `-e .[socks]`), `make ci` runs
    # `pytest tests --junitxml=report.xml`.
    "psf__requests": _Expected(
        "python",
        "python:3.14-bookworm",
        ["uv pip install -r requirements-dev.txt"],
        f"python -m pytest tests {_PYTEST_REPORT}",
        "pytest",
    ),
    # CI: scripts/install installs requirements.txt; scripts/test runs scripts/check (lint)
    # unless GITHUB_ACTIONS is set, then `coverage run -m pytest`, then a coverage gate.
    "encode__httpx": _Expected(
        "python",
        "python:3.13-bookworm",
        ["uv pip install -r requirements.txt"],
        f"python -m pytest {_PYTEST_REPORT}",
        "pytest",
    ),
    # CI: checkout with fetch-depth 0 (setuptools-scm versions), tox envs that install group
    # "dev" and run `pytest`; tox sets PYTHONWARNDEFAULTENCODING=1 for every env but pylib.
    "pytest-dev__pytest": _Expected(
        "python",
        "python:3.14-bookworm",
        [
            "uv sync --locked --no-default-groups --group dev "
            "|| uv sync --frozen --no-default-groups --group dev"
        ],
        f"python -m pytest {_PYTEST_REPORT}",
        "pytest",
        env={"PYTHONWARNDEFAULTENCODING": "1"},
        fetch_tags=True,
    ),
    # CI: `uv sync --no-dev --group tests`, then scripts/test.sh exports the terminal
    # variables and runs `pytest --cov … --numprocesses=auto`.
    "fastapi__typer": _Expected(
        "python",
        "python:3.14-bookworm",
        [
            "uv sync --locked --no-default-groups --group tests "
            "|| uv sync --frozen --no-default-groups --group tests"
        ],
        "python -m pytest -o console_output_style=progress --showlocals --numprocesses=auto "
        f"{_PYTEST_REPORT}",
        "pytest",
        env={
            "TERMINAL_WIDTH": "3000",
            "_TYPER_FORCE_DISABLE_TERMINAL": "1",
            "_TYPER_RUN_INSTALL_COMPLETION_TESTS": "1",
        },
    ),
    # CI: `npm install` (no lockfile), `npm run test-ci` → nyc → `npm test` → mocha.
    "expressjs__express": _Expected(
        "javascript",
        "node:24-bookworm",
        ["npm install"],
        "mocha --require test/support/env --check-leaks test/ test/acceptance/ "
        "--reporter json --reporter-option output=/tmp/ac-report.json",
        "mocha",
    ),
    # CI: Go 1.17-1.24 matrix, `make richtest` → `go get -v ./...` (network) and
    # `richgo test -v ./...`.
    "spf13__cobra": _Expected(
        "go",
        "golang:1.24-bookworm",
        ["go mod download", "go test -count=1 -vet=off -run '^$' ./..."],
        "go test -json ./... > /tmp/ac-report.json",
        "go",
        env={"GO111MODULE": "on"},
    ),
    # CI: ci/ubuntu-install-packages, then `cargo test --verbose --workspace` once with
    # `--features unstable-index` and once with `--features pcre2`.
    "BurntSushi__ripgrep": _Expected(
        "rust",
        "rust:1-bookworm",
        ["cargo fetch", "cargo test --no-run --workspace --features unstable-index,pcre2"],
        "cargo test --workspace --features unstable-index,pcre2 --no-fail-fast "
        "> /tmp/ac-report.txt",
        "cargo",
        env={"RUST_BACKTRACE": "1"},
        system_packages=("brotli", "g++", "liblz4-tool", "musl-tools", "xz-utils", "zsh", "zstd"),
    ),
}


@pytest.mark.parametrize("fixture", sorted(_CI_RECIPES))
def test_detected_recipes_follow_what_each_repository_ci_runs(tmp_path: Path, fixture: str) -> None:
    expected = _CI_RECIPES[fixture]
    repository = fixture.replace("__", "/")

    recipe = detect_recipe(repository, _signals(tmp_path / "repository", _FIXTURES / fixture))

    assert recipe.repository == repository
    assert recipe.source == "detected"
    assert recipe.language == expected.language
    assert recipe.base_image == expected.base_image
    install_start = len(_PYTHON_SETUP) if expected.language == "python" else 0
    if expected.language == "python":
        assert recipe.setup_commands[:install_start] == _PYTHON_SETUP
    assert recipe.setup_commands[install_start:] == expected.install
    assert recipe.test_command == expected.test_command
    assert recipe.test_framework == expected.test_framework
    assert recipe.build_commands == []
    assert expected.env.items() <= recipe.env.items()
    assert recipe.fetch_tags is expected.fetch_tags
    assert recipe.fetch_submodules is False
    assert recipe.system_packages == sorted(
        {"ca-certificates", "git", "less", "locales", *expected.system_packages}
    )


def test_recipes_carry_the_image_environment_that_env_i_drops(tmp_path: Path) -> None:
    signals = {name: _signals(tmp_path / name, _FIXTURES / name) for name in _CI_RECIPES}

    recipes = {
        name: detect_recipe(name.replace("__", "/"), value) for name, value in signals.items()
    }

    click = recipes["pallets__click"]
    assert click.env["PATH"].startswith("/opt/ac/venv/bin:/opt/ac/tools/bin:")
    assert click.env["UV_PROJECT_ENVIRONMENT"] == click.env["VIRTUAL_ENV"] == "/opt/ac/venv"
    assert click.offline_env == {"UV_OFFLINE": "1", "UV_NO_SYNC": "1"}
    assert click.test_report == "/tmp/ac-report.xml"
    express = recipes["expressjs__express"]
    assert express.env["PATH"].startswith("/workspace/node_modules/.bin:")
    assert express.env["PUPPETEER_SKIP_DOWNLOAD"] == "1"
    assert express.offline_env == {"npm_config_offline": "true"}
    cobra = recipes["spf13__cobra"]
    assert cobra.env["GOTOOLCHAIN"] == "local"
    assert cobra.env["GOFLAGS"] == "-buildvcs=false"
    assert cobra.offline_env == {"GOPROXY": "off"}
    assert "/usr/local/go/bin" in cobra.env["PATH"]
    ripgrep = recipes["BurntSushi__ripgrep"]
    assert ripgrep.env["RUSTUP_HOME"] == "/usr/local/rustup"
    assert ripgrep.offline_env == {"CARGO_NET_OFFLINE": "true"}
    # CI plumbing (variables its own steps read) and color settings stay out of the recipes.
    assert "CARGO" not in ripgrep.env and "TARGET_DIR" not in ripgrep.env
    assert "PYTEST_ADDOPTS" not in recipes["pytest-dev__pytest"].env
    assert "PREFIX" not in recipes["encode__httpx"].env
    assert "RICHGO_FORCE_COLOR" not in cobra.env
    for recipe in recipes.values():
        assert all(value.strip() for value in recipe.env.values())
        assert recipe.env["LANG"] == "C.UTF-8"


def test_uv_lock_route_uses_ci_named_groups_and_extras(tmp_path: Path) -> None:
    signals = _signals(
        tmp_path / "repository",
        {
            "pyproject.toml": '[project]\nname = "demo"\nrequires-python = ">=3.10,<3.13"\n'
            "[dependency-groups]\ntest = ['pytest']\nlint = ['ruff']\n",
            "uv.lock": "version = 1\n",
            ".github/workflows/ci.yml": """
on: [pull_request]
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: uv run --group lint ruff check .
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python: ["3.11", "3.12", "3.13", "3.14"]
    steps:
      - uses: actions/setup-python@v6
        with:
          python-version: ${{ matrix.python }}
      - run: uv sync --group test --extra speedups
      - run: uv run pytest -x --maxfail=2 tests/unit --cov=demo --cov-report term
""",
        },
    )

    recipe = detect_recipe("acme/demo", signals)

    # 3.13 and 3.14 are tested but excluded by requires-python.
    assert recipe.base_image == "python:3.12-bookworm"
    assert recipe.setup_commands[-1] == (
        "uv sync --locked --no-default-groups --group test --extra speedups "
        "|| uv sync --frozen --no-default-groups --group test --extra speedups"
    )
    assert recipe.test_command == f"python -m pytest tests/unit {_PYTEST_REPORT}"


def test_poetry_and_pdm_lockfiles_install_through_their_own_tools(tmp_path: Path) -> None:
    poetry = _signals(
        tmp_path / "poetry",
        {
            "pyproject.toml": "[tool.poetry]\nname = 'demo'\n"
            "[tool.poetry.group.test.dependencies]\npytest = '*'\n"
            "[tool.poetry.group.docs.dependencies]\nsphinx = '*'\n",
            "poetry.lock": "# lock\n",
        },
    )
    pdm = _signals(
        tmp_path / "pdm",
        {
            "pyproject.toml": "[project]\nname = 'demo'\n"
            "[dependency-groups]\ntesting = ['pytest']\n",
            "pdm.lock": "# lock\n",
        },
    )

    assert detect_recipe("acme/poetry", poetry).setup_commands[-2:] == [
        "uv pip install --python /opt/ac/tools/bin/python poetry",
        "poetry install --no-interaction --with test",
    ]
    assert detect_recipe("acme/pdm", pdm).setup_commands[-2:] == [
        "uv pip install --python /opt/ac/tools/bin/python pdm",
        "pdm sync -G testing",
    ]


def test_tox_only_repository_installs_what_tox_current_env_prints(tmp_path: Path) -> None:
    signals = _signals(
        tmp_path / "repository",
        {
            "setup.py": "from setuptools import setup\nsetup()\n",
            ".python-version": "3.11\n",
            "tox.ini": """[tox]
envlist = py{310,311}-{core,extra}, lint
requires = tox-uv>=1

[testenv]
deps = pytest
extras = test
dependency_groups = typing
setenv =
    DEMO_MODE=strict
    extra: DEMO_EXTRA=1
    !extra: DEMO_CORE=1
commands =
    pytest {posargs:tests} -x
    extra: pytest docs

[testenv:lint]
commands = ruff check .
""",
        },
    )

    recipe = detect_recipe("acme/demo", signals)

    # No CI: the .python-version pin picks the interpreter and env py311-core.
    assert recipe.base_image == "python:3.11-bookworm"
    assert recipe.setup_commands[-3:] == [
        "uv pip install --python /opt/ac/tools/bin/python tox tox-current-env 'tox-uv>=1'",
        "tox -e py311-core --print-deps-to /opt/ac/tox-deps.txt "
        "--print-extras-to /opt/ac/tox-extras.txt",
        "extras=$(paste -sd, /opt/ac/tox-extras.txt) && uv pip install -r /opt/ac/tox-deps.txt "
        '-e ".${extras:+[$extras]}" --group typing',
    ]
    assert recipe.test_command == f"python -m pytest {_PYTEST_REPORT}"


def test_tox_commands_reached_from_ci_carry_set_env_and_factor_conditions(
    tmp_path: Path,
) -> None:
    signals = _signals(
        tmp_path / "repository",
        {
            "setup.py": "from setuptools import setup\nsetup()\n",
            "tox.ini": """[tox]
envlist = py{311,312}-{core,extra}

[testenv]
passenv = KEEP_*
setenv =
    extra: DEMO_EXTRA=1
    !extra: DEMO_CORE=1
commands =
    pytest {posargs:tests} -x
""",
            ".github/workflows/test.yml": """
on: push
env:
  KEEP_ME: yes
  DROP_ME: yes
jobs:
  tox:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@v6
        with:
          python-version: "3.12"
      - run: tox -e py312-extra
""",
        },
    )

    recipe = detect_recipe("acme/demo", signals)

    assert recipe.base_image == "python:3.12-bookworm"
    assert recipe.test_command == f"python -m pytest tests {_PYTEST_REPORT}"
    # tox passes only pass_env variables to its commands, then applies set_env.
    assert recipe.env["KEEP_ME"] == "yes"
    assert recipe.env["DEMO_EXTRA"] == "1"
    assert "DROP_ME" not in recipe.env and "DEMO_CORE" not in recipe.env
    assert "tox -e py312-extra" in recipe.setup_commands[-2]


def test_nox_sessions_install_with_nox_and_rerun_without_installing(tmp_path: Path) -> None:
    signals = _signals(
        tmp_path / "repository",
        {
            "pyproject.toml": "[project]\nname = 'demo'\n",
            "noxfile.py": """import nox


@nox.session(python=["3.12", "3.13"])
def lint(session):
    session.run("ruff", "check", ".")


@nox.session(python=["3.12", "3.13"])
def tests(session):
    session.install(".[test]")
    session.run("pytest", "--cov", *session.posargs)
""",
            ".github/workflows/ci.yml": """
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@v6
        with:
          python-version: "3.13"
      - run: nox -s lint tests-3.13
""",
        },
    )

    recipe = detect_recipe("acme/demo", signals)

    assert recipe.setup_commands[-2:] == [
        "uv pip install --python /opt/ac/tools/bin/python nox",
        "nox --session tests --force-python 3.13 --install-only",
    ]
    assert recipe.test_command == (
        f"nox --session tests --force-python 3.13 -R -- {_PYTEST_REPORT}"
    )
    assert recipe.test_framework == "pytest"


def test_python_without_ci_or_lockfile_installs_itself_editable_with_test_extras(
    tmp_path: Path,
) -> None:
    signals = _signals(
        tmp_path / "repository",
        {
            "pyproject.toml": '[project]\nname = "demo"\nrequires-python = "~=3.10"\n'
            "[project.optional-dependencies]\ndocs = ['sphinx']\ntesting = ['pytest']\n"
            '[build-system]\nrequires = ["setuptools", "setuptools-scm>=8"]\n',
        },
    )

    recipe = detect_recipe("acme/demo", signals)

    assert recipe.base_image == "python:3.14-bookworm"
    assert recipe.setup_commands[-1] == "uv pip install -e '.[testing]' pytest"
    assert recipe.test_command == f"python -m pytest {_PYTEST_REPORT}"
    assert recipe.fetch_tags is True


def test_requirement_files_get_an_editable_install_only_when_they_lack_one(
    tmp_path: Path,
) -> None:
    signals = _signals(
        tmp_path / "repository",
        {
            "setup.cfg": "[metadata]\nname = demo\n",
            "requirements/test.txt": "pytest\n",
            "docs/requirements.txt": "sphinx\n",
            "Makefile": "install:\n\tpip install -r requirements/test.txt\n"
            "test: install\n\tpython -m unittest discover -s tests\n",
            ".github/workflows/ci.yml": """
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: pip install .[speedups]
      - run: make test
""",
        },
    )

    recipe = detect_recipe("acme/demo", signals)

    assert recipe.setup_commands[-1] == ("uv pip install -r requirements/test.txt -e '.[speedups]'")
    assert recipe.test_command == "python -m unittest discover -s tests"
    assert recipe.test_framework == "unittest"
    assert recipe.test_report is None


def test_pnpm_project_uses_corepack_frozen_install_build_and_jest_reporter(
    tmp_path: Path,
) -> None:
    signals = _signals(
        tmp_path / "repository",
        {
            "package.json": json.dumps(
                {
                    "packageManager": "pnpm@9.15.0",
                    "engines": {"node": "^20.11 || >=22"},
                    "scripts": {
                        "build": "tsc -b",
                        "lint": "eslint .",
                        "test": "pnpm lint && jest --coverage --runInBand",
                    },
                }
            ),
            "pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
            ".github/workflows/ci.yml": """
on: pull_request
jobs:
  windows:
    runs-on: windows-latest
    steps:
      - run: pnpm test
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        node: [20, 22, 23]
    steps:
      - uses: actions/setup-node@v5
        with:
          node-version: ${{ matrix.node }}
      - run: pnpm install --frozen-lockfile
      - run: pnpm run build
      - run: pnpm test
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
          API_TOKEN: literal-but-secret-looking
          TZ: UTC
""",
        },
    )

    recipe = detect_recipe("acme/web", signals)

    assert recipe.language == "javascript"
    assert recipe.base_image == "node:22-bookworm"
    assert recipe.setup_commands == [
        "corepack enable --install-directory /opt/ac/bin",
        "pnpm install --frozen-lockfile",
    ]
    assert recipe.build_commands == ["pnpm run build"]
    assert recipe.test_command == ("jest --runInBand --ci --json --outputFile=/tmp/ac-report.json")
    assert recipe.test_framework == "jest"
    assert recipe.env["TZ"] == "UTC"
    assert "API_TOKEN" not in recipe.env and "NPM_TOKEN" not in recipe.env


def test_yarn_berry_without_ci_runs_the_test_script_runner(tmp_path: Path) -> None:
    signals = _signals(
        tmp_path / "repository",
        {
            "package.json": json.dumps({"scripts": {"test": "vitest --coverage"}}),
            "yarn.lock": "__metadata:\n",
            ".yarnrc.yml": "nodeLinker: node-modules\n",
            ".nvmrc": "lts/iron\n",
        },
    )

    recipe = detect_recipe("acme/web", signals)

    assert recipe.base_image == "node:20-bookworm"
    assert recipe.setup_commands[-1] == "yarn install --immutable"
    assert recipe.test_command == ("vitest run --reporter=json --outputFile=/tmp/ac-report.json")
    assert recipe.offline_env["YARN_ENABLE_NETWORK"] == "0"


def test_javascript_without_any_test_command_cannot_be_detected(tmp_path: Path) -> None:
    signals = _signals(
        tmp_path / "repository",
        {
            "package.json": json.dumps(
                {"scripts": {"test": 'echo "Error: no test specified" && exit 1'}}
            )
        },
    )

    with pytest.raises(EnvironmentRecipeError, match="no test script"):
        detect_recipe("acme/web", signals)


def test_go_modules_are_each_downloaded_and_warmed(tmp_path: Path) -> None:
    signals = _signals(
        tmp_path / "repository",
        {
            "go.mod": "module example.com/demo\n\ngo 1.22.3\n\ntoolchain go1.25.1\n",
            "tools/go.mod": "module example.com/demo/tools\n\ngo 1.22\n",
            "internal/testdata/go.mod": "module fixture\n",
            ".github/workflows/go.yml": """
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-go@v6
        with:
          go-version: '1.23.x'
      - run: go test -race -tags integration -coverprofile cover.out ./...
""",
        },
    )

    recipe = detect_recipe("acme/demo", signals)

    assert recipe.base_image == "golang:1.25-bookworm"
    assert recipe.setup_commands == [
        "go mod download",
        "go -C tools mod download",
        "go test -count=1 -vet=off -run '^$' ./...",
        "go -C tools test -count=1 -vet=off -run '^$' ./...",
    ]
    assert recipe.test_command == ("go test -json -tags integration ./... > /tmp/ac-report.json")


def test_rust_toolchain_file_pins_the_image_and_is_installed(tmp_path: Path) -> None:
    signals = _signals(
        tmp_path / "repository",
        {
            "Cargo.toml": "[package]\nname = 'demo'\nversion = '0.1.0'\n",
            "rust-toolchain.toml": "[toolchain]\nchannel = '1.88.0'\ncomponents = ['clippy']\n",
            ".github/workflows/ci.yml": """
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: cargo test --all-features --locked -- --test-threads=1
""",
        },
    )

    recipe = detect_recipe("acme/demo", signals)

    assert recipe.base_image == "rust:1.88.0-bookworm"
    assert recipe.setup_commands == [
        "rustup toolchain install",
        "cargo fetch",
        "cargo test --no-run --locked --all-features",
    ]
    assert recipe.test_command == (
        "cargo test --locked --all-features --no-fail-fast > /tmp/ac-report.txt"
    )


def test_maturin_bindings_are_detected_as_their_rust_crate(tmp_path: Path) -> None:
    signals = _signals(
        tmp_path / "repository",
        {
            "pyproject.toml": "[project]\nname = 'demo'\n"
            "[build-system]\nbuild-backend = 'maturin'\nrequires = ['maturin']\n",
            "Cargo.toml": "[workspace]\nmembers = ['crates/*']\n",
        },
    )

    recipe = detect_recipe("acme/demo", signals)

    assert recipe.language == "rust"
    assert recipe.test_command == "cargo test --workspace --no-fail-fast > /tmp/ac-report.txt"


def test_ci_steps_in_subdirectories_or_on_other_systems_are_not_followed(tmp_path: Path) -> None:
    signals = _signals(
        tmp_path / "repository",
        {
            "pyproject.toml": "[project]\nname = 'demo'\n",
            ".github/workflows/nightly.yml": """
on:
  schedule: [{cron: "0 0 * * *"}]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: pytest --runslow
""",
            ".github/workflows/ci.yml": """
on: [push]
jobs:
  mac:
    runs-on: macos-latest
    steps:
      - run: pytest tests/mac
  sdist:
    runs-on: ubuntu-latest
    steps:
      - run: |
          cd dist/demo
          pytest tests/sdist
  docs:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: docs
    steps:
      - run: pytest tests/docs
  main:
    runs-on: ubuntu-latest
    steps:
      - run: pytest tests/main
        working-directory: sub
      - run: pytest tests/unit
""",
        },
    )

    recipe = detect_recipe("acme/demo", signals)

    # Push-triggered workflows rank before the schedule-only one.
    assert recipe.test_command == f"python -m pytest tests/unit {_PYTEST_REPORT}"


def test_config_override_replaces_detected_fields_and_keeps_the_rest(tmp_path: Path) -> None:
    signals = _signals(tmp_path / "repository", _FIXTURES / "psf__requests")
    override = EnvironmentOverride(
        image="python:3.12-bookworm",
        setup=["pip install -e .[socks] pytest"],
        test="python -m pytest -q tests/test_utils.py",
        allow_hosts=["httpbin.org"],
    )

    recipe = detect_recipe("psf/requests", signals, override)

    assert recipe.source == "config"
    assert recipe.base_image == "python:3.12-bookworm"
    assert recipe.setup_commands == ["pip install -e .[socks] pytest"]
    assert recipe.test_command == f"python -m pytest -q tests/test_utils.py {_PYTEST_REPORT}"
    assert recipe.test_framework == "pytest"
    assert recipe.env == detect_recipe("psf/requests", signals).env


def test_override_test_commands_keep_their_text_unless_they_are_one_runner_call(
    tmp_path: Path,
) -> None:
    signals = _signals(tmp_path / "repository", _FIXTURES / "spf13__cobra")

    chained = detect_recipe(
        "spf13/cobra", signals, EnvironmentOverride(test="make fixtures && go test ./...")
    )
    single = detect_recipe("spf13/cobra", signals, EnvironmentOverride(test="go test -v ./cmd/..."))
    hosts_only = detect_recipe(
        "spf13/cobra", signals, EnvironmentOverride(allow_hosts=["example.org"])
    )

    assert (chained.test_command, chained.test_framework, chained.test_report) == (
        "make fixtures && go test ./...",
        "other",
        None,
    )
    assert single.test_command == "go test -json ./cmd/... > /tmp/ac-report.json"
    assert hosts_only.source == "detected"


def test_unknown_languages_need_a_complete_override(tmp_path: Path) -> None:
    signals = _signals(tmp_path / "repository", {"CMakeLists.txt": "project(demo)\n"})

    with pytest.raises(EnvironmentRecipeError, match="No Python, JavaScript, Go or Rust"):
        detect_recipe("acme/demo", signals)
    with pytest.raises(EnvironmentRecipeError):
        detect_recipe("acme/demo", signals, EnvironmentOverride(image="gcc:14", setup=[]))

    recipe = detect_recipe(
        "acme/demo",
        signals,
        EnvironmentOverride(image="gcc:14-bookworm", setup=["cmake -B build"], test="ctest"),
    )

    assert recipe.language == "other"
    assert recipe.source == "config"
    assert (recipe.base_image, recipe.setup_commands, recipe.test_command) == (
        "gcc:14-bookworm",
        ["cmake -B build"],
        "ctest",
    )
    assert recipe.test_framework == "other"
