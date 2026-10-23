"""Deterministic environment recipes from a repository's signals (DESIGN §5.2, step 3).

The recipe follows what the repository's own CI does where that can be read, and the language
defaults of research-envsetup.md otherwise: base images per §B3, install commands per §B4, and a
test command per §B7 that runs the suite without lint, coverage gates or network wrappers and
writes per-test results to a file. Operator overrides from `environments.<repo>` replace the
detected fields (§5.2, step 1). Nothing here runs repository code.
"""

from __future__ import annotations

import re
import shlex
import tomllib
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Final

from autocontribute.environment_ci import (
    CiJob,
    CiSources,
    CiTestRun,
    Invocation,
    ToxEnvironment,
    action_inputs,
    checkout_input,
    ci_jobs,
    expand_command,
    job_test_run,
    nox_sessions,
    package_json,
    single_invocation,
)
from autocontribute.environment_signals import RepositorySignals
from autocontribute.environments import (
    DEBIAN_PACKAGE,
    TOOL_ROOT,
    EnvironmentOverride,
    EnvironmentRecipe,
    Language,
    TestFramework,
    dependency_digest,
)
from autocontribute.exceptions import EnvironmentRecipeError
from autocontribute.sandbox import CONTAINER_TMP, SAFE_CONTAINER_PATH
from autocontribute.workspace_files import CONTAINER_WORKSPACE

# Setup runs as the command uid with HOME under the tool root (DESIGN §5.2); later containers
# mount a tmpfs on /tmp, so nothing an offline command needs may live there.
_TOOLS: Final = f"{TOOL_ROOT}/tools"
_VENV: Final = f"{TOOL_ROOT}/venv"
_UV_VERSION: Final = "0.12.24"
_BASE_SYSTEM_PACKAGES: Final = ("ca-certificates", "git", "less", "locales")
_JUNIT_REPORT: Final = f"{CONTAINER_TMP}/ac-report.xml"
_JSON_REPORT: Final = f"{CONTAINER_TMP}/ac-report.json"
_TEXT_REPORT: Final = f"{CONTAINER_TMP}/ac-report.txt"
# Stable CPython minor versions with full Debian images, newest first.
_PYTHON_MINORS: Final = (14, 13, 12, 11, 10, 9)
_PYTHON_TEST_GROUPS: Final = ("test", "tests", "testing", "dev")
_NODE_LTS_MAJORS: Final = (24, 22, 20, 18)
_NODE_CODENAMES: Final = {
    "hydrogen": 18,
    "iron": 20,
    "jod": 22,
    "krypton": 24,
}
# The oldest Go with GOTOOLCHAIN, so GOTOOLCHAIN=local keeps Go from downloading one offline.
_GO_MINIMUM: Final = (1, 21)
_VCS_VERSION_TOOLS: Final = re.compile(
    r"setuptools[-_]scm|hatch-vcs|versioneer|dunamai|dynamic-versioning", re.IGNORECASE
)
_CI_ONLY_VARIABLE: Final = re.compile(
    r"COLOR|PROXY$|^(?:GITHUB_|RUNNER_|ACTIONS_|CODECOV|COVERALLS|COVERAGE|UV_|PIP_|LC_)|"
    r"^(?:PATH|HOME|LANG|TERM|CI|PYTEST_ADDOPTS)$",
    re.IGNORECASE,
)
_SECRET_VARIABLE: Final = re.compile(
    r"TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API_?KEY|PRIVATE|AUTH", re.IGNORECASE
)
_PYTHON_VERSION: Final = re.compile(r"^(?:cpython-?)?3(?:\.(\d+|x))?(?:\.\d+)?$")
_VERSION_CLAUSE: Final = re.compile(r"^(~=|===|==|!=|<=|>=|<|>)\s*(\d+(?:\.\d+)*)(\.\*)?$")
_GO_VERSION: Final = re.compile(r"^[~^>=v]*(\d+)\.(\d+)")
_GO_DIRECTIVE: Final = re.compile(r"^(?:go[ \t]+|toolchain[ \t]+go)(\d+)\.(\d+)", re.MULTILINE)
_NODE_COMPARATOR: Final = re.compile(r"^(>=|<=|>|<|=|\^|~)?v?(\d+|[xX*])(?:\.(\d+|[xX*]))?")
_EDITABLE_SELF: Final = re.compile(r"^\s*(?:-e\s+|--editable\s+)?\.(?:\[[^\]]*\])?\s*$", re.M)
_NPM_PLACEHOLDER_TEST: Final = "no test specified"

# Options that stop at the first failure or rerun a subset would cut the per-test baseline short;
# coverage options belong to CI's coverage gate.
_PYTEST_DROPPED_FLAGS: Final = frozenset(
    {
        "-x",
        "--exitfirst",
        "--no-cov",
        "--no-cov-on-fail",
        "--lf",
        "--last-failed",
        "--ff",
        "--failed-first",
        "--sw",
        "--stepwise",
        "--pdb",
    }
)
_PYTEST_DROPPED_VALUES: Final = frozenset(
    {
        "--junitxml",
        "--junit-xml",
        "--cov-report",
        "--cov-config",
        "--cov-fail-under",
        "--cov-context",
        "--basetemp",
        "--maxfail",
        "--html",
        "--color",
        "--code-highlight",
    }
)
_JEST_DROPPED: Final = frozenset({"--coverage", "--watch", "--watchAll", "--json", "--ci"})
_JEST_DROPPED_VALUES: Final = frozenset({"--outputFile", "--coverageReporters"})
_VITEST_DROPPED: Final = frozenset({"--coverage", "--watch", "--run"})
_VITEST_DROPPED_VALUES: Final = frozenset({"--reporter", "--outputFile"})
_MOCHA_DROPPED: Final = frozenset({"--watch", "-w"})
_MOCHA_DROPPED_VALUES: Final = frozenset(
    {"--reporter", "-R", "--reporter-option", "--reporter-options", "-O"}
)
_GO_DROPPED: Final = frozenset({"-v", "-race", "-cover", "-json", "-failfast"})
_GO_DROPPED_VALUES: Final = frozenset({"-coverprofile", "-covermode", "-coverpkg", "-o"})
_CARGO_DROPPED: Final = frozenset(
    {"-v", "-vv", "--verbose", "-q", "--quiet", "--no-fail-fast", "--offline", "--frozen"}
)
_CARGO_DROPPED_VALUES: Final = frozenset(
    {"--color", "--target", "--target-dir", "--message-format", "--features", "-F"}
)
_CARGO_NARROWING: Final = frozenset(
    {
        "--lib",
        "--bin",
        "--bins",
        "--test",
        "--doc",
        "--example",
        "--examples",
        "--bench",
        "--benches",
        "--manifest-path",
        "-p",
        "--package",
        "--exclude",
    }
)


@dataclass(frozen=True, slots=True)
class _TestCommand:
    command: str
    framework: TestFramework
    report: str | None


def detect_recipe(
    repository: str,
    signals: RepositorySignals,
    override: EnvironmentOverride | None = None,
) -> EnvironmentRecipe:
    """Build a repository's recipe from its signals, with the operator's override applied.

    Raises :class:`EnvironmentRecipeError` when detection finds no supported language and the
    override does not give the image, setup and test command itself.
    """

    sources = CiSources.parse(signals)
    try:
        recipe = _detected_recipe(repository, sources)
    except EnvironmentRecipeError:
        if (
            override is None
            or override.image is None
            or override.setup is None
            or override.test is None
        ):
            raise
        recipe = _recipe(
            repository,
            sources,
            "other",
            override.image,
            override.setup,
            _verbatim(override.test),
            env={"PATH": SAFE_CONTAINER_PATH, "LANG": "C.UTF-8"},
            offline_env={},
            job=None,
        )
    if override is None or all(
        value is None for value in (override.image, override.setup, override.test)
    ):
        return recipe
    updates: dict[str, object] = {"source": "config"}
    if override.image is not None:
        updates["base_image"] = override.image
    if override.setup is not None:
        updates["setup_commands"] = override.setup
    if override.test is not None:
        test = _operator_test_command(override.test)
        updates.update(
            test_command=test.command, test_framework=test.framework, test_report=test.report
        )
    return EnvironmentRecipe.model_validate({**recipe.model_dump(), **updates})


def _detected_recipe(repository: str, sources: CiSources) -> EnvironmentRecipe:
    signals = sources.signals
    language = _primary_language(signals)
    if language is None:
        raise EnvironmentRecipeError(
            "No Python, JavaScript, Go or Rust project at the repository root"
        )
    builders: dict[Language, Callable[[str, CiSources], EnvironmentRecipe]] = {
        "python": _python_recipe,
        "javascript": _javascript_recipe,
        "go": _go_recipe,
        "rust": _rust_recipe,
    }
    return builders[language](repository, sources)


def _primary_language(signals: RepositorySignals) -> Language | None:
    pyproject = _toml(signals.files.get("pyproject.toml"))
    python = bool({"setup.py", "setup.cfg"} & signals.paths) or bool(
        {"project", "build-system"} & pyproject.keys() or "poetry" in _table(pyproject.get("tool"))
    )
    rust = "Cargo.toml" in signals.paths
    # A maturin project is a Rust crate with Python bindings; its suite is the crate's.
    if rust and "maturin" in str(_table(pyproject.get("build-system")).get("build-backend")):
        python = False
    present: list[tuple[Language, bool]] = [
        ("python", python),
        ("go", "go.mod" in signals.paths or "go.work" in signals.paths),
        ("rust", rust),
        ("javascript", "package.json" in signals.paths),
    ]
    return next((language for language, found in present if found), None)


def _recipe(
    repository: str,
    sources: CiSources,
    language: Language,
    base_image: str,
    setup_commands: Sequence[str],
    test: _TestCommand,
    *,
    env: Mapping[str, str],
    offline_env: Mapping[str, str],
    job: CiTestRun | None,
    build_commands: Sequence[str] = (),
    vcs_version: bool = False,
) -> EnvironmentRecipe:
    signals = sources.signals
    packages = set(_BASE_SYSTEM_PACKAGES)
    if job is not None:
        packages.update(_apt_packages(job.installs))
    return EnvironmentRecipe(
        repository=repository,
        language=language,
        base_image=base_image,
        system_packages=sorted(packages),
        setup_commands=list(setup_commands),
        build_commands=list(build_commands),
        test_command=test.command,
        test_framework=test.framework,
        test_report=test.report,
        env={**_ci_environment(job), **env},
        offline_env=dict(offline_env),
        fetch_tags=vcs_version
        or (job is not None and checkout_input(job.job, "fetch-depth") == "0"),
        fetch_submodules=".gitmodules" in signals.paths,
        source="detected",
        dependency_digest=dependency_digest(signals.dependency_files),
    )


def _find_test_run(
    sources: CiSources,
    language: Language,
    python_minor: Callable[[CiJob], int | None] = lambda _job: None,
) -> tuple[CiTestRun | None, CiJob | None]:
    """The first CI job whose tests run in the given language, and that job."""

    for job in ci_jobs(sources.signals):
        run = job_test_run(sources, job, python_minor=python_minor(job))
        if run is not None and _language_of(run.tests[0]) == language:
            return run, job
    return None, None


def _language_of(invocation: Invocation) -> Language | None:
    runner = invocation.runner
    program = invocation.words[0]
    if runner in {"pytest", "unittest", "python-script"} or program in {"tox", "nox"}:
        return "python"
    if runner in {"jest", "vitest", "mocha"} or program in {"npm", "pnpm", "yarn"}:
        return "javascript"
    if runner == "go":
        return "go"
    if runner == "cargo":
        return "rust"
    return None


# Python


def _python_recipe(repository: str, sources: CiSources) -> EnvironmentRecipe:
    signals = sources.signals
    pyproject = _toml(signals.files.get("pyproject.toml"))
    project = _table(pyproject.get("project"))
    requires_python = project.get("requires-python")
    specifier = requires_python if isinstance(requires_python, str) else ""
    pinned = signals.files.get(".python-version", "").strip().splitlines()[:1]

    def minor_for(job: CiJob | None) -> int:
        candidates = [] if job is None else _python_candidates(job, signals)
        return _python_minor(candidates, specifier, pinned[0] if pinned else "")

    run, job = _find_test_run(sources, "python", minor_for)
    minor = minor_for(job)
    test = run.tests[0] if run is not None else None
    tox = (
        sources.tox.environment(test.tox_environment)
        if test is not None and test.tox_environment and sources.tox is not None
        else None
    )
    install_text = "" if run is None else run.install_text
    if tox is not None:
        install_text += "\n" + "\n".join(tox.deps)
    requirements = _referenced_requirements(signals, install_text)
    setup = [
        f"python3 -m venv {_TOOLS}",
        f"{_TOOLS}/bin/python -m pip install --no-cache-dir --disable-pip-version-check "
        f"uv=={_UV_VERSION}",
        f"uv venv {_VENV} --python /usr/local/bin/python3",
        *_python_install_commands(sources, pyproject, run, test, tox, requirements, minor),
    ]
    randomly = any(
        "pytest-randomly" in text or "pytest_randomly" in text
        for path, text in signals.files.items()
        if PurePosixPath(path).name in {"pyproject.toml", "setup.cfg", "tox.ini"}
        or path in requirements
    )
    if test is not None and test.nox_session is not None:
        test_command = _nox_test_command(signals, test.nox_session, minor, randomly)
    else:
        test_command = _python_test_command(test, randomly)
    return _recipe(
        repository,
        sources,
        "python",
        f"python:3.{minor}-bookworm",
        setup,
        test_command,
        env={
            "PATH": f"{_VENV}/bin:{_TOOLS}/bin:{SAFE_CONTAINER_PATH}",
            "VIRTUAL_ENV": _VENV,
            "UV_PROJECT_ENVIRONMENT": _VENV,
            "UV_PYTHON_DOWNLOADS": "never",
            "UV_CACHE_DIR": f"{CONTAINER_TMP}/uv-cache",
            "UV_LINK_MODE": "copy",
            "LANG": "C.UTF-8",
            **(tox.set_env if tox is not None else {}),
        },
        offline_env={"UV_OFFLINE": "1", "UV_NO_SYNC": "1"},
        job=run,
        vcs_version=_uses_vcs_version(signals),
    )


def _python_install_commands(
    sources: CiSources,
    pyproject: Mapping[str, object],
    run: CiTestRun | None,
    test: Invocation | None,
    tox: ToxEnvironment | None,
    requirements: Sequence[str],
    minor: int,
) -> list[str]:
    """The first install route of §B4 that applies, into the virtualenv under the tool root."""

    signals = sources.signals
    project = _table(pyproject.get("project"))
    groups, extras = _python_selection(
        run,
        test,
        tox,
        _declared_names(pyproject.get("dependency-groups")),
        _declared_names(project.get("optional-dependencies")),
    )
    group_flags = [flag for name in groups for flag in ("--group", name)]
    installable = bool({"pyproject.toml", "setup.py", "setup.cfg"} & signals.paths)
    tool_install = ["uv", "pip", "install", "--python", f"{_TOOLS}/bin/python"]
    if "uv.lock" in signals.paths:
        flags = shlex.join(
            ["--no-default-groups", *group_flags, *[f for e in extras for f in ("--extra", e)]]
        )
        return [f"uv sync --locked {flags} || uv sync --frozen {flags}"]
    if "poetry.lock" in signals.paths:
        poetry = _table(_table(pyproject.get("tool")).get("poetry"))
        with_groups = [g for g in _PYTHON_TEST_GROUPS if g in _declared_names(poetry.get("group"))]
        return [
            shlex.join([*tool_install, "poetry"]),
            shlex.join(
                [
                    "poetry",
                    "install",
                    "--no-interaction",
                    *[flag for name in with_groups for flag in ("--with", name)],
                    *[flag for name in extras for flag in ("--extras", name)],
                ]
            ),
        ]
    if "pdm.lock" in signals.paths:
        return [
            shlex.join([*tool_install, "pdm"]),
            shlex.join(["pdm", "sync", *[flag for name in groups for flag in ("-G", name)]]),
        ]
    if requirements:
        arguments = [flag for path in requirements for flag in ("-r", path)]
        if installable and not any(
            _EDITABLE_SELF.search(signals.files.get(path, "")) for path in requirements
        ):
            arguments += ["-e", _editable_target(extras)]
        return [shlex.join(["uv", "pip", "install", *arguments])]
    if sources.tox is not None and (tox is not None or run is None):
        environment = tox or sources.tox.environment(sources.tox.choose(None, minor))
        # tox-current-env prints what the environment would install without building it.
        return [
            shlex.join([*tool_install, "tox", "tox-current-env", *sources.tox.requires]),
            shlex.join(["tox", "-e", environment.name])
            + f" --print-deps-to {TOOL_ROOT}/tox-deps.txt"
            + f" --print-extras-to {TOOL_ROOT}/tox-extras.txt",
            f"extras=$(paste -sd, {TOOL_ROOT}/tox-extras.txt) && "
            f'uv pip install -r {TOOL_ROOT}/tox-deps.txt -e ".${{extras:+[$extras]}}"'
            + "".join(f" --group {shlex.quote(name)}" for name in environment.dependency_groups),
        ]
    if test is not None and test.nox_session is not None:
        nox = ["nox", "--session", test.nox_session, "--force-python", f"3.{minor}"]
        return [shlex.join([*tool_install, "nox"]), shlex.join([*nox, "--install-only"])]
    arguments = ["-e", _editable_target(extras)] if installable else []
    return [shlex.join(["uv", "pip", "install", *arguments, "pytest", *group_flags])]


def _python_candidates(job: CiJob, signals: RepositorySignals) -> list[str]:
    values = action_inputs(job, "actions/setup-python", "python-version")
    values += action_inputs(job, "astral-sh/setup-uv", "python-version")
    for path in action_inputs(job, "actions/setup-python", "python-version-file"):
        if not path.endswith(".toml"):
            values += signals.files.get(path.removeprefix("./"), "").split()[:1]
    if not values:
        for key in ("python", "python-version", "python_version", "py"):
            values.extend(job.matrix.get(key, ()))
    return values


def _python_minor(candidates: Sequence[str], specifier: str, pinned: str) -> int:
    """Newest stable CPython the CI tests that `requires-python` allows (§B3)."""

    allowed = [minor for minor in _PYTHON_MINORS if _python_allows(specifier, minor)]
    if not allowed:
        return _PYTHON_MINORS[0]
    tested: set[int] = set()
    for candidate in candidates:
        match = _PYTHON_VERSION.fullmatch(candidate.strip())
        if match is None:
            continue
        minor = match.group(1)
        tested.update(allowed if minor in {None, "x"} else {int(minor)} & set(allowed))
    if tested:
        return max(tested)
    pin = _PYTHON_VERSION.fullmatch(pinned)
    if pin is not None and pin.group(1) and pin.group(1).isdigit() and int(pin.group(1)) in allowed:
        return int(pin.group(1))
    return allowed[0]


def _python_allows(specifier: str, minor: int) -> bool:
    """Whether some 3.<minor>.x release satisfies a `requires-python` specifier."""

    candidate = (3, minor)
    for clause in specifier.split(","):
        match = _VERSION_CLAUSE.fullmatch(clause.strip())
        if match is None:
            continue
        operator, raw, wildcard = match.groups()
        version = tuple(int(part) for part in raw.split("."))
        prefix = version[:2]
        if operator in {"==", "==="} and wildcard:
            allowed = candidate[: len(version)] == version[:2]
        elif operator in {"==", "==="}:
            allowed = candidate == prefix
        elif operator == "!=":
            allowed = not (wildcard and candidate[: len(version)] == version[:2])
        elif operator == ">=":
            allowed = candidate >= prefix
        elif operator == ">":
            allowed = candidate >= prefix if len(version) > 2 else candidate > prefix
        elif operator == "<":
            allowed = (*candidate, 0) < (*version, 0, 0)[:3]
        elif operator == "<=":
            allowed = (*candidate, 0) <= (*version, 0, 0)[:3]
        else:
            allowed = (
                candidate == prefix
                if len(version) > 2
                else (candidate >= prefix and candidate[0] == prefix[0])
            )
        if not allowed:
            return False
    return True


def _python_selection(
    run: CiTestRun | None,
    test: Invocation | None,
    tox: ToxEnvironment | None,
    groups: Sequence[str],
    extras: Sequence[str],
) -> tuple[list[str], list[str]]:
    """Dependency groups and extras for the tests: the tox environment's, CI's, or defaults."""

    if tox is not None and (tox.dependency_groups or tox.extras):
        return list(tox.dependency_groups), list(tox.extras)
    named_groups: list[str] = []
    named_extras: list[str] = []
    invocations = [*(run.installs if run is not None else ()), *([test] if test else [])]
    for invocation in invocations:
        words = invocation.words
        if invocation is test and invocation.tox_environment is None:
            named_groups += invocation.uv_groups
            named_extras += invocation.uv_extras
        if words[:2] in {("uv", "sync"), ("pdm", "install"), ("pdm", "sync")} or words[:2] == (
            "poetry",
            "install",
        ):
            named_groups += _option_values(words, {"--group", "--with", "-G", "--only-group"})
            named_extras += _option_values(words, {"--extra", "--extras", "-E"})
        if words[:2] in {("pip", "install"), ("pip3", "install")} or words[:3] == (
            "uv",
            "pip",
            "install",
        ):
            named_groups += _option_values(words, {"--group"})
            for word in words:
                match = re.fullmatch(r"\.\[([\w,.-]+)\]", word)
                if match is not None:
                    named_extras += match.group(1).split(",")
    if named_groups or named_extras:
        return _unique(named_groups), _unique(named_extras)
    default_group = next((name for name in _PYTHON_TEST_GROUPS if name in groups), None)
    if default_group is not None:
        return [default_group], []
    return [], [name for name in _PYTHON_TEST_GROUPS if name in extras][:1]


def _referenced_requirements(signals: RepositorySignals, text: str) -> list[str]:
    """Requirement files the CI install steps or the tox environment name, in order."""

    found: list[tuple[int, str]] = []
    for path in signals.paths:
        pure = PurePosixPath(path)
        if pure.suffix != ".txt" or not (
            "requirements" in pure.name or "requirements" in pure.parts
        ):
            continue
        match = re.search(rf"(?:(?<![\w./-])|(?<=-r))(?:\./)?{re.escape(path)}(?![\w./-])", text)
        if match is not None:
            found.append((match.start(), path))
    return [path for _, path in sorted(found)]


def _editable_target(extras: Sequence[str]) -> str:
    return f".[{','.join(extras)}]" if extras else "."


def _python_test_command(test: Invocation | None, randomly: bool) -> _TestCommand:
    if test is not None and test.runner == "unittest":
        return _TestCommand(
            shlex.join(["python", "-m", "unittest", *_resolved(test.words[1:])]), "unittest", None
        )
    if test is not None and test.runner == "python-script":
        return _TestCommand(shlex.join(_resolved(test.words)), "other", None)
    arguments = _pytest_arguments(test.words[1:] if test is not None else ())
    return _TestCommand(
        shlex.join(["python", "-m", "pytest", *arguments, *_pytest_report_options(randomly)]),
        "pytest",
        _JUNIT_REPORT,
    )


def _nox_test_command(
    signals: RepositorySignals, session: str, minor: int, randomly: bool
) -> _TestCommand:
    source = nox_sessions(signals).get(session, "")
    command = ["nox", "--session", session, "--force-python", f"3.{minor}", "-R"]
    if re.search(r"""session\.run\(\s*["']pytest["'][^)]*\*session\.posargs""", source):
        return _TestCommand(
            shlex.join([*command, "--", *_pytest_report_options(randomly)]),
            "pytest",
            _JUNIT_REPORT,
        )
    return _TestCommand(shlex.join(command), "other", None)


def _pytest_report_options(randomly: bool) -> list[str]:
    plugins = ["-p", "no:cacheprovider", *(["-p", "no:randomly"] if randomly else [])]
    return [*plugins, f"--junitxml={_JUNIT_REPORT}"]


def _pytest_arguments(words: Sequence[str]) -> list[str]:
    return _filtered(words, _PYTEST_DROPPED_FLAGS, _PYTEST_DROPPED_VALUES, prefixes=("--cov",))


def _uses_vcs_version(signals: RepositorySignals) -> bool:
    """Whether the package version comes from Git tags, which a shallow clone lacks (§B5)."""

    pyproject = _toml(signals.files.get("pyproject.toml"))
    tool = _table(pyproject.get("tool"))
    if "setuptools_scm" in tool or any(
        _table(_table(tool.get(name)).get("version")).get("source") in {"vcs", "scm"}
        for name in ("hatch", "pdm")
    ):
        return True
    requires = " ".join(_strings(_table(pyproject.get("build-system")).get("requires")))
    return any(
        _VCS_VERSION_TOOLS.search(text)
        for text in (
            requires,
            signals.files.get("setup.cfg", ""),
            signals.files.get("setup.py", ""),
        )
    )


# JavaScript


def _javascript_recipe(repository: str, sources: CiSources) -> EnvironmentRecipe:
    signals = sources.signals
    package = package_json(signals)
    manager, berry = _package_manager(signals, package)
    run, job = _find_test_run(sources, "javascript")
    major = _node_major(job, signals, package)
    lockfile = {
        "npm": {"package-lock.json", "npm-shrinkwrap.json"},
        "pnpm": {"pnpm-lock.yaml"},
        "yarn": {"yarn.lock"},
    }[manager] & signals.paths
    install = {
        ("npm", True): "npm ci",
        ("npm", False): "npm install",
        ("pnpm", True): "pnpm install --frozen-lockfile",
        ("pnpm", False): "pnpm install",
        ("yarn", True): "yarn install --immutable" if berry else "yarn install --frozen-lockfile",
        ("yarn", False): "yarn install",
    }[(manager, bool(lockfile))]
    setup: list[str] = []
    if manager != "npm":
        if major >= 25:
            setup.append(f"npm install --global --prefix {TOOL_ROOT} corepack")
        setup.append(f"corepack enable --install-directory {TOOL_ROOT}/bin")
    setup.append(install)
    test = _javascript_test_command(sources, run, manager)
    build = [] if run is None else _javascript_build_commands(run.setup_steps, manager)
    offline = {"npm_config_offline": "true"}
    if berry:
        offline["YARN_ENABLE_NETWORK"] = "0"
    return _recipe(
        repository,
        sources,
        "javascript",
        f"node:{major}-bookworm",
        setup,
        test,
        env={
            "PATH": ":".join(
                (
                    f"{CONTAINER_WORKSPACE}/node_modules/.bin",
                    f"{TOOL_ROOT}/bin",
                    SAFE_CONTAINER_PATH,
                )
            ),
            "COREPACK_HOME": f"{TOOL_ROOT}/corepack",
            "COREPACK_ENABLE_DOWNLOAD_PROMPT": "0",
            "PUPPETEER_SKIP_DOWNLOAD": "1",
            "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD": "1",
            "LANG": "C.UTF-8",
        },
        offline_env=offline,
        job=run,
        build_commands=build,
    )


def _package_manager(signals: RepositorySignals, package: Mapping[str, object]) -> tuple[str, bool]:
    """The package manager and whether it is Yarn 2 or later, by packageManager or lockfile."""

    declared = package.get("packageManager")
    if isinstance(declared, str) and "@" in declared:
        name, _, version = declared.partition("@")
        if name in {"npm", "pnpm", "yarn"}:
            return name, name == "yarn" and not version.startswith("1.")
        raise EnvironmentRecipeError(f"Unsupported packageManager {name!r} in package.json")
    if "pnpm-lock.yaml" in signals.paths:
        return "pnpm", False
    if "yarn.lock" in signals.paths:
        return "yarn", ".yarnrc.yml" in signals.paths
    if {"bun.lock", "bun.lockb"} & signals.paths:
        raise EnvironmentRecipeError("Bun projects are not supported by detection")
    return "npm", False


def _node_major(
    job: CiJob | None, signals: RepositorySignals, package: Mapping[str, object]
) -> int:
    """Highest Node LTS that the version pins, `engines.node` and the CI matrix allow (§B3)."""

    pins = _node_pins(signals, package)
    if pins:
        return pins[0]
    engines = _table(package.get("engines")).get("node")
    majors = [
        major
        for major in _NODE_LTS_MAJORS
        if not isinstance(engines, str) or _node_range_allows(engines, major)
    ] or list(_NODE_LTS_MAJORS)
    tested: set[int] = set()
    for value in [] if job is None else action_inputs(job, "actions/setup-node", "node-version"):
        value = value.strip().casefold()
        if value.startswith("lts/") or value in {"node", "latest", "current"}:
            tested.update(majors)
        elif (match := re.match(r"^v?(\d+)", value)) is not None:
            tested.add(int(match.group(1)))
    return max(set(majors) & tested or set(majors))


def _node_pins(signals: RepositorySignals, package: Mapping[str, object]) -> list[int]:
    """Majors pinned by .nvmrc, .node-version, .tool-versions and volta, by number or LTS name."""

    values = [
        signals.files.get(".nvmrc", "").strip(),
        signals.files.get(".node-version", "").strip(),
        str(_table(package.get("volta")).get("node", "")),
    ]
    for line in signals.files.get(".tool-versions", "").splitlines():
        name, _, version = line.strip().partition(" ")
        if name in {"nodejs", "node"}:
            values.append(version.strip())
    pins: list[int] = []
    for value in values:
        value = value.casefold().removeprefix("v")
        codename = _NODE_CODENAMES.get(value.removeprefix("lts/"))
        if codename is not None:
            pins.append(codename)
        elif (match := re.match(r"^(\d+)", value)) is not None:
            pins.append(int(match.group(1)))
    return pins


def _node_range_allows(range_text: str, major: int) -> bool:
    """Whether some release of a Node major satisfies an npm semver range."""

    for alternative in range_text.split("||"):
        text = re.sub(r"(>=|<=|>|<|=|\^|~)\s+", r"\1", alternative.strip())
        bounds = re.fullmatch(r"(\S+)\s+-\s+(\S+)", text)
        comparators = [f">={bounds.group(1)}", f"<={bounds.group(2)}"] if bounds else text.split()
        if all(_node_comparator_allows(comparator, major) for comparator in comparators):
            return True
    return False


def _node_comparator_allows(comparator: str, major: int) -> bool:
    match = _NODE_COMPARATOR.match(comparator)
    if match is None or not match.group(2).isdigit():
        return True
    operator, first, second = match.group(1) or "=", int(match.group(2)), match.group(3)
    beyond_major = second is not None and second.isdigit() and int(second) > 0
    if operator == ">=":
        return major >= first
    if operator == ">":
        return major >= first if second is not None else major > first
    if operator == "<":
        return major <= first if beyond_major else major < first
    if operator == "<=":
        return major <= first
    return major == first


def _javascript_test_command(
    sources: CiSources, run: CiTestRun | None, manager: str
) -> _TestCommand:
    if run is not None:
        return _javascript_invocation_command(run.tests[0])
    script = sources.package_scripts.get("test", "")
    if not script or _NPM_PLACEHOLDER_TEST in script:
        raise EnvironmentRecipeError("No CI test step and no test script in package.json")
    invocations = expand_command(sources, f"{manager} test", python_minor=None)
    runner = next(
        (item for item in invocations if _language_of(item) == "javascript" and item.runner), None
    )
    if runner is not None:
        return _javascript_invocation_command(runner)
    return _TestCommand(f"{manager} test", "other", None)


def _javascript_invocation_command(invocation: Invocation) -> _TestCommand:
    words = invocation.words
    if invocation.runner == "jest":
        arguments = _filtered(words[1:], _JEST_DROPPED, _JEST_DROPPED_VALUES)
        return _TestCommand(
            shlex.join(["jest", *arguments, "--ci", "--json", f"--outputFile={_JSON_REPORT}"]),
            "jest",
            _JSON_REPORT,
        )
    if invocation.runner == "vitest":
        arguments = _filtered(words[1:], _VITEST_DROPPED, _VITEST_DROPPED_VALUES)
        if arguments[:1] in (["run"], ["watch"], ["dev"]):
            arguments = arguments[1:]
        return _TestCommand(
            shlex.join(
                ["vitest", "run", *arguments, "--reporter=json", f"--outputFile={_JSON_REPORT}"]
            ),
            "vitest",
            _JSON_REPORT,
        )
    if invocation.runner == "mocha":
        arguments = _filtered(words[1:], _MOCHA_DROPPED, _MOCHA_DROPPED_VALUES)
        return _TestCommand(
            shlex.join(
                [
                    "mocha",
                    *arguments,
                    "--reporter",
                    "json",
                    "--reporter-option",
                    f"output={_JSON_REPORT}",
                ]
            ),
            "mocha",
            _JSON_REPORT,
        )
    return _verbatim(shlex.join(_resolved(words)))


def _javascript_build_commands(installs: Iterable[Invocation], manager: str) -> list[str]:
    commands: list[str] = []
    for invocation in installs:
        words = invocation.words
        script = words[2:3] if words[1:2] == ("run",) else words[1:2]
        if (
            words[0] == manager
            and script
            and script[0].startswith("build")
            and not any("$" in word for word in words)
        ):
            commands.append(shlex.join(words))
    return _unique(commands)


# Go


def _go_recipe(repository: str, sources: CiSources) -> EnvironmentRecipe:
    signals = sources.signals
    run, job = _find_test_run(sources, "go")
    versions = [_GO_MINIMUM]
    for value in [] if job is None else action_inputs(job, "actions/setup-go", "go-version"):
        if (match := _GO_VERSION.match(value.strip())) is not None:
            versions.append((int(match.group(1)), int(match.group(2))))
    for match in _GO_DIRECTIVE.finditer(signals.files.get("go.mod", "")):
        versions.append((int(match.group(1)), int(match.group(2))))
    major, minor = max(versions)
    modules = sorted(
        (str(PurePosixPath(path).parent) for path in signals.paths if _is_go_module(path)),
        key=lambda directory: (directory != ".", directory),
    )[:20]
    setup: list[str] = []
    for directory in modules:
        prefix = ["go"] if directory == "." else ["go", "-C", directory]
        setup.append(shlex.join([*prefix, "mod", "download"]))
    for directory in modules:
        prefix = ["go"] if directory == "." else ["go", "-C", directory]
        # Builds every test binary without running one, so later offline runs start warm.
        setup.append(shlex.join([*prefix, "test", "-count=1", "-vet=off", "-run", "^$", "./..."]))
    return _recipe(
        repository,
        sources,
        "go",
        f"golang:{major}.{minor}-bookworm",
        setup,
        _go_test_command(run.tests[0] if run is not None else None),
        env={
            "PATH": f"{TOOL_ROOT}/go/bin:/usr/local/go/bin:{SAFE_CONTAINER_PATH}",
            "GOPATH": f"{TOOL_ROOT}/go",
            "GOMODCACHE": f"{TOOL_ROOT}/go/pkg/mod",
            "GOCACHE": f"{TOOL_ROOT}/go/cache",
            "GOTOOLCHAIN": "local",
            "GOFLAGS": "-buildvcs=false",
            "LANG": "C.UTF-8",
        },
        offline_env={"GOPROXY": "off"},
        job=run,
    )


def _go_test_command(test: Invocation | None) -> _TestCommand:
    words = test.words[2:] if test is not None else ()
    arguments = _filtered(words, _GO_DROPPED, _GO_DROPPED_VALUES)
    if all(word.startswith("-") for word in arguments):
        arguments.append("./...")
    command = shlex.join(["go", "test", "-json", *arguments]) + f" > {_JSON_REPORT}"
    return _TestCommand(command, "go", _JSON_REPORT)


def _is_go_module(path: str) -> bool:
    pure = PurePosixPath(path)
    return pure.name == "go.mod" and not any(
        part in {"testdata", "vendor"} or part.startswith(("_", ".")) for part in pure.parent.parts
    )


# Rust


def _rust_recipe(repository: str, sources: CiSources) -> EnvironmentRecipe:
    signals = sources.signals
    run, _ = _find_test_run(sources, "rust")
    channel = _rust_channel(signals)
    pinned = channel is not None and re.fullmatch(r"\d+\.\d+(?:\.\d+)?", channel) is not None
    manifest = _toml(signals.files.get("Cargo.toml"))
    flags = _cargo_flags(() if run is None else run.tests, workspace="workspace" in manifest)
    setup = ["rustup toolchain install"] if channel is not None else []
    setup += ["cargo fetch", shlex.join(["cargo", "test", "--no-run", *flags])]
    return _recipe(
        repository,
        sources,
        "rust",
        f"rust:{channel if pinned else '1'}-bookworm",
        setup,
        _cargo_test_command(flags),
        env={
            "PATH": f"/usr/local/cargo/bin:{SAFE_CONTAINER_PATH}",
            "RUSTUP_HOME": "/usr/local/rustup",
            "CARGO_HOME": f"{TOOL_ROOT}/cargo",
            "LANG": "C.UTF-8",
        },
        offline_env={"CARGO_NET_OFFLINE": "true"},
        job=run,
    )


def _rust_channel(signals: RepositorySignals) -> str | None:
    """The toolchain file's channel; "" when the file names none, None without a file."""

    for name in ("rust-toolchain.toml", "rust-toolchain"):
        if name not in signals.paths:
            continue
        text = signals.files.get(name, "").strip()
        if name.endswith(".toml") or text.startswith("["):
            channel = _table(_toml(text).get("toolchain")).get("channel")
            return channel if isinstance(channel, str) else ""
        return text.split()[0] if text else ""
    return None


def _cargo_test_command(flags: Sequence[str]) -> _TestCommand:
    # libtest prints results to stdout, so the report holds them and the output keeps cargo's
    # compiler messages.
    command = shlex.join(["cargo", "test", *flags, "--no-fail-fast"]) + f" > {_TEXT_REPORT}"
    return _TestCommand(command, "cargo", _TEXT_REPORT)


def _cargo_flags(tests: Sequence[Invocation], *, workspace: bool) -> list[str]:
    """Flags of the CI's full-suite `cargo test` runs, their features merged.

    Cargo features are additive, so one run with the union of the features that separate CI
    runs enable builds and runs every feature-gated test they do.
    """

    suites = [
        _cargo_arguments(test)
        for test in tests
        if test.runner == "cargo" and not _narrows_cargo_suite(_cargo_arguments(test))
    ]
    if not suites:
        return ["--workspace"] if workspace else []
    features: list[str] = []
    all_features = False
    for arguments in suites:
        for value in _option_values(arguments, {"--features", "-F"}):
            features += [item for item in re.split(r"[,\s]+", value) if item]
        all_features = all_features or "--all-features" in arguments
    flags = _filtered(suites[0], _CARGO_DROPPED, _CARGO_DROPPED_VALUES)
    flags = [flag for flag in flags if flag != "--all-features"]
    if all_features:
        flags.append("--all-features")
    elif features:
        flags += ["--features", ",".join(_unique(features))]
    return flags


def _cargo_arguments(test: Invocation) -> list[str]:
    words = list(test.words[3:] if test.words[1:3] == ("nextest", "run") else test.words[2:])
    if "--" in words:
        words = words[: words.index("--")]
    return [word for word in words if "$" not in word]


def _narrows_cargo_suite(arguments: Sequence[str]) -> bool:
    remaining = _filtered(arguments, _CARGO_DROPPED, _CARGO_DROPPED_VALUES)
    return any(
        word.split("=", 1)[0] in _CARGO_NARROWING or not word.startswith("-") for word in remaining
    )


# Shared helpers


def _operator_test_command(command: str) -> _TestCommand:
    """An operator's test command, with a structured reporter when it is one runner call."""

    invocation = single_invocation(command)
    if invocation is None:
        return _verbatim(command)
    language = _language_of(invocation)
    if invocation.runner in {"pytest", "unittest"}:
        return _python_test_command(invocation, randomly=False)
    if language == "javascript" and invocation.runner is not None:
        return _javascript_invocation_command(invocation)
    if invocation.runner == "go":
        return _go_test_command(invocation)
    if invocation.runner == "cargo":
        return _cargo_test_command(
            _filtered(_cargo_arguments(invocation), _CARGO_DROPPED, frozenset())
        )
    return _verbatim(command)


def _verbatim(command: str) -> _TestCommand:
    return _TestCommand(command, "other", None)


def _filtered(
    words: Sequence[str],
    dropped: frozenset[str],
    dropped_values: frozenset[str],
    *,
    prefixes: tuple[str, ...] = (),
) -> list[str]:
    """Drop unresolved words and the listed options, with the values of those that take one."""

    kept: list[str] = []
    skip = False
    for word in words:
        if skip:
            skip = False
            continue
        option = word.split("=", 1)[0]
        if "$" in word:
            continue
        if option in dropped_values:
            skip = "=" not in word
        elif option not in dropped and not option.startswith(prefixes):
            kept.append(word)
    return kept


def _option_values(words: Sequence[str], options: set[str]) -> list[str]:
    return [value for _, value in _option_pairs(words, options)]


def _option_pairs(words: Sequence[str], options: set[str]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for index, word in enumerate(words):
        option, separator, value = word.partition("=")
        if option not in options:
            continue
        if separator:
            pairs.append((option, value))
        elif index + 1 < len(words):
            pairs.append((option, words[index + 1]))
    return pairs


def _resolved(words: Iterable[str]) -> list[str]:
    return [word for word in words if "$" not in word]


def _ci_environment(run: CiTestRun | None) -> dict[str, str]:
    """Variables the CI test step sets that the tests themselves may read."""

    if run is None:
        return {}
    return {
        name: value
        for name, value in run.tests[0].environment.items()
        if value and not _CI_ONLY_VARIABLE.search(name) and not _SECRET_VARIABLE.search(name)
    }


def _apt_packages(invocations: Iterable[Invocation]) -> set[str]:
    packages: set[str] = set()
    for invocation in invocations:
        words = invocation.words
        if words[0] in {"apt-get", "apt"} and "install" in words:
            packages.update(
                word
                for word in words[words.index("install") + 1 :]
                if not word.startswith("-") and DEBIAN_PACKAGE.fullmatch(word) and word != "sudo"
            )
    return packages


def _declared_names(value: object) -> list[str]:
    return [name for name in value if isinstance(name, str)] if isinstance(value, dict) else []


def _toml(text: str | None) -> dict[str, object]:
    try:
        return tomllib.loads(text or "")
    except tomllib.TOMLDecodeError:
        return {}


def _table(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _strings(value: object) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))


__all__ = ["detect_recipe"]
