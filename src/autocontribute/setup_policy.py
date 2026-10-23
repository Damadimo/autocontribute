"""The deterministic filter on recipes the setup agent proposes (DESIGN §5.2, step 4).

The setup agent reads attacker-controllable files (README, CONTRIBUTING, CI), so its recipe is
checked before it runs: no sudo, no download piped into a shell, installs only of packages the
repository declares or of a fixed set of tools, no install from a URL or another index, no
variable that changes how tests run, and a test command with a per-test report, so the
acceptance gate sees real results. Edits to tracked files are caught after the replay, when
host Git finds them (``setup_dirty_paths``).

A package counts as declared when a manifest, requirements or lock file names it as a
dependency, or when an install command of CI, a task runner or a script installs it. Prose such
as CONTRIBUTING or AGENTS.md declares nothing: a name there is what an injected instruction
would use.
"""

from __future__ import annotations

import ast
import json
import re
import shlex
import tomllib
from collections.abc import Iterable, Iterator, Mapping, Sequence, Set
from configparser import ConfigParser
from configparser import Error as ConfigParserError
from pathlib import PurePosixPath
from typing import Final

from autocontribute.environment_ci import CiSources, ci_jobs, shell_commands
from autocontribute.environment_signals import RepositorySignals
from autocontribute.environments import EnvironmentRecipe

_ALLOWED_TOOLS: Final = frozenset(
    {
        "corepack",
        "hatch",
        "maturin",
        "nox",
        "pdm",
        "pip",
        "pnpm",
        "poetry",
        "pytest",
        "setuptools",
        "tox",
        "tox-current-env",
        "tox-uv",
        "uv",
        "wheel",
        "yarn",
    }
)
_SHELLS: Final = frozenset(
    {"sh", "bash", "dash", "zsh", "ksh", "python", "python3", "node", "perl"}
)
_DOWNLOADERS: Final = frozenset({"curl", "wget"})
_DOWNLOAD_SUBSTITUTION: Final = re.compile(r"[$<]\(\s*(?:curl|wget)\b")
# Words that start an install, by how many words name the installer.
_INSTALLERS: Final = (
    ("python", "-m", "pip", "install"),
    ("python3", "-m", "pip", "install"),
    ("uv", "pip", "install"),
    ("uv", "tool", "install"),
    ("pip", "install"),
    ("pip3", "install"),
    ("pipx", "install"),
    ("uv", "add"),
    ("poetry", "add"),
    ("pdm", "add"),
    ("npm", "install"),
    ("npm", "i"),
    ("npm", "add"),
    ("pnpm", "add"),
    ("pnpm", "install"),
    ("pnpm", "i"),
    ("yarn", "add"),
    ("yarn", "global", "add"),
    ("bun", "add"),
    ("cargo", "install"),
    ("go", "install"),
    ("go", "get"),
    ("gem", "install"),
)
# Options whose value is a file or directory of the repository.
_PATH_OPTIONS: Final = frozenset(
    {"-r", "--requirement", "-c", "--constraint", "-e", "--editable", "--prefix", "--python", "-p"}
)
_INDEX_OPTIONS: Final = frozenset(
    {
        "-i",
        "--index-url",
        "--extra-index-url",
        "--index",
        "--default-index",
        "-f",
        "--find-links",
        "--registry",
        "--git",
        "--index-strategy",
    }
)
_REQUIREMENT_NAME: Final = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_GO_REQUIREMENT: Final = re.compile(r"^\s*(?:require\s+)?([^\s()]+)\s+v\d", re.MULTILINE)
_GO_MODULE: Final = re.compile(r"^module\s+(\S+)", re.MULTILINE)
_SETUP_PY_REQUIREMENTS: Final = frozenset(
    {"install_requires", "setup_requires", "tests_require", "extras_require"}
)
_SETUP_CFG_REQUIREMENTS: Final = (
    ("options", "install_requires"),
    ("options", "setup_requires"),
    ("options", "tests_require"),
)
_PACKAGE_JSON_DEPENDENCIES: Final = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
)
_CARGO_DEPENDENCY_TABLES: Final = ("dependencies", "dev-dependencies", "build-dependencies")
_URL: Final = re.compile(r"^(?:[a-z][a-z0-9+.-]*://|git\+|git@|github:|file:)", re.IGNORECASE)
_VERSION_SUFFIX: Final = re.compile(r"[\[<>=!~;@ ].*$")
_GO_VERSION_SUFFIX: Final = re.compile(r"@.*$")
_WEAKENING_VARIABLES: Final = frozenset(
    {
        "BASH_ENV",
        "ENV",
        "LD_PRELOAD",
        "NODE_OPTIONS",
        "PYTEST_ADDOPTS",
        "PYTEST_PLUGINS",
        "PYTHONSTARTUP",
    }
)
_RUNNERS: Final = {
    "pytest": "pytest",
    "jest": "jest",
    "vitest": "vitest",
    "mocha": "mocha",
    "go": "go test",
    "cargo": "cargo test",
}


def agent_recipe_violations(recipe: EnvironmentRecipe, signals: RepositorySignals) -> list[str]:
    """Return why an agent's recipe may not run; empty when it may."""

    declared = _declared_names(signals)
    violations: list[str] = []
    commands = [*recipe.setup_commands, *recipe.build_commands, recipe.test_command]
    for command in commands:
        violations.extend(_command_violations(command, declared))
    for name in sorted(_WEAKENING_VARIABLES & {*recipe.env, *recipe.offline_env}):
        violations.append(f"the variable {name} changes how tests run")
    runner = _RUNNERS.get(recipe.test_framework)
    if runner is None or recipe.test_report is None or runner not in recipe.test_command:
        violations.append(
            "the test command must run pytest, Jest, Vitest, Mocha, go test or cargo test "
            "with its per-test report"
        )
    return list(dict.fromkeys(violations))


def _command_violations(command: str, declared: Set[str]) -> Iterator[str]:
    if _DOWNLOAD_SUBSTITUTION.search(command):
        yield f"runs a download as code: {command}"
    try:
        segments = _segments(command)
    except ValueError:
        yield f"cannot be parsed as shell words: {command}"
        return
    for index, (words, operator) in enumerate(segments):
        if "sudo" in words or "doas" in words:
            yield f"uses sudo: {command}"
        if (
            operator == "|"
            and words
            and words[0] in _DOWNLOADERS
            and index + 1 < len(segments)
            and segments[index + 1][0][:1]
            and segments[index + 1][0][0] in _SHELLS
        ):
            yield f"pipes a download into a shell: {command}"
        yield from _install_violations(words, declared)


def _segments(command: str) -> list[tuple[list[str], str]]:
    """Split a command into simple commands and the operator that follows each."""

    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|")
    lexer.whitespace_split = True
    segments: list[tuple[list[str], str]] = []
    words: list[str] = []
    for token in lexer:
        if token and set(token) <= set(";&|"):
            segments.append((words, token))
            words = []
        else:
            words.append(token)
    segments.append((words, ""))
    # A leading `VAR=value` assignment does not change which program runs.
    return [([w for w in words if not _is_assignment(w)] or words, op) for words, op in segments]


def _install_violations(words: Sequence[str], declared: Set[str]) -> Iterator[str]:
    install = _parse_install(words)
    if install is None:
        return
    names, problems = install
    yield from problems
    for name in names:
        parts = name.split("/")
        # A Go command lives under the module the repository requires.
        prefixes = {"/".join(parts[:end]) for end in range(1, len(parts) + 1)}
        if name not in _ALLOWED_TOOLS and not prefixes & declared:
            yield f"installs {name}, which the repository does not declare"


def _parse_install(words: Sequence[str]) -> tuple[list[str], list[str]] | None:
    """Return the packages an install command names and its URL or index problems.

    ``None`` when the command installs nothing.
    """

    installer = next(
        (prefix for prefix in _INSTALLERS if tuple(words[: len(prefix)]) == prefix), None
    )
    if installer is None:
        return None
    names: list[str] = []
    problems: list[str] = []
    skip_value = False
    for argument in words[len(installer) :]:
        if skip_value:
            skip_value = False
            if _URL.match(argument):
                problems.append(f"installs from a URL: {argument}")
            continue
        option = argument.split("=", 1)[0]
        if option in _INDEX_OPTIONS:
            problems.append(f"installs from another package index: {argument}")
            skip_value = "=" not in argument
        elif option in _PATH_OPTIONS:
            skip_value = "=" not in argument
        elif _URL.match(argument):
            problems.append(f"installs from a URL: {argument}")
        elif not argument.startswith(("-", ".", "/")) and (
            name := _package_name(argument, go=installer[0] == "go")
        ):
            names.append(name)
    return names, problems


def _package_name(argument: str, *, go: bool) -> str:
    name = (_GO_VERSION_SUFFIX if go else _VERSION_SUFFIX).sub("", argument)
    if not go and argument.startswith("@"):
        # A scoped npm package, perhaps with a version: @scope/name@1.2.
        scope, _, rest = argument[1:].partition("/")
        name = f"@{scope}/{rest.split('@', 1)[0]}"
    return _normalized(name)


def _declared_names(signals: RepositorySignals) -> frozenset[str]:
    """The packages the repository's manifests declare and its install commands install."""

    names: set[str] = set()
    for path, text in signals.files.items():
        name = PurePosixPath(path).name
        if name == "pyproject.toml":
            names.update(_pyproject_names(_toml(text)))
        elif name == "setup.cfg":
            names.update(_setup_cfg_names(text))
        elif name == "setup.py":
            names.update(_setup_py_names(text))
        elif name == "noxfile.py":
            names.update(_nox_install_names(text))
        elif name == "Pipfile":
            pipfile = _toml(text)
            names.update(_keys(pipfile.get("packages")) + _keys(pipfile.get("dev-packages")))
        elif name == "package.json":
            names.update(_package_json_names(text))
        elif name == "go.mod":
            names.update(_GO_MODULE.findall(text) + _GO_REQUIREMENT.findall(text))
        elif name == "Cargo.toml":
            names.update(_cargo_names(_toml(text)))
        elif name.endswith(".txt") and "requirements" in path:
            names.update(_requirement_names(text.splitlines()))
    names.update(_installed_names(signals))
    return frozenset(_normalized(name) for name in names if name)


def _installed_names(signals: RepositorySignals) -> Iterator[str]:
    """Packages that install commands of CI, task runners and scripts install."""

    sources = CiSources.parse(signals)
    texts = [step.run for job in ci_jobs(signals) for step in job.steps if step.run]
    texts += [line for _, lines in sources.make_rules.values() for line in lines]
    texts += list(sources.package_scripts.values())
    texts += [text for path, text in signals.files.items() if path.endswith(".sh")]
    commands = [command for text in texts for command in shell_commands(text)]
    if sources.tox is not None:
        names = sorted({*sources.tox.sections, *sources.tox.env_list})
        environments = [sources.tox.environment(name) for name in names]
        commands += [list(words) for environment in environments for words in environment.commands]
        yield from _requirement_names(sources.tox.requires)
        for environment in environments:
            yield from _requirement_names(environment.deps)
    for command in commands:
        words = [word for word in command if not _is_assignment(word)] or command
        install = _parse_install(words)
        if install is not None:
            yield from install[0]


def _pyproject_names(pyproject: Mapping[str, object]) -> Iterator[str]:
    project = _table(pyproject.get("project"))
    yield from _requirement_names(_strings(project.get("dependencies")))
    for extra in _table(project.get("optional-dependencies")).values():
        yield from _requirement_names(_strings(extra))
    for group in _table(pyproject.get("dependency-groups")).values():
        yield from _requirement_names(_strings(group))
    yield from _requirement_names(_strings(_table(pyproject.get("build-system")).get("requires")))
    tool = _table(pyproject.get("tool"))
    poetry = _table(tool.get("poetry"))
    yield from _keys(poetry.get("dependencies"))
    yield from _keys(poetry.get("dev-dependencies"))
    for group in _table(poetry.get("group")).values():
        yield from _keys(_table(group).get("dependencies"))
    for group in _table(_table(tool.get("pdm")).get("dev-dependencies")).values():
        yield from _requirement_names(_strings(group))
    yield from _requirement_names(_strings(_table(tool.get("uv")).get("dev-dependencies")))


def _setup_cfg_names(text: str) -> Iterator[str]:
    parser = ConfigParser(interpolation=None)
    try:
        parser.read_string(text)
    except ConfigParserError:
        return
    for section, option in _SETUP_CFG_REQUIREMENTS:
        yield from _requirement_names(parser.get(section, option, fallback="").splitlines())
    if parser.has_section("options.extras_require"):
        for _, value in parser.items("options.extras_require"):
            yield from _requirement_names(value.splitlines())


def _setup_py_names(text: str) -> Iterator[str]:
    """Requirement strings of setup()'s requirement arguments, read without running it."""

    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg in _SETUP_PY_REQUIREMENTS:
            yield from _requirement_names(_string_constants(node.value))


def _nox_install_names(text: str) -> Iterator[str]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "install"
        ):
            arguments = [string for argument in node.args for string in _string_constants(argument)]
            yield from _requirement_names(arguments)


def _package_json_names(text: str) -> Iterator[str]:
    try:
        package = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        return
    if isinstance(package, dict):
        for key in _PACKAGE_JSON_DEPENDENCIES:
            yield from _keys(package.get(key))


def _cargo_names(manifest: Mapping[str, object]) -> Iterator[str]:
    tables = [manifest, _table(manifest.get("workspace"))]
    tables += [_table(target) for target in _table(manifest.get("target")).values()]
    for table in tables:
        for key in _CARGO_DEPENDENCY_TABLES:
            for name, value in _table(table.get(key)).items():
                # `alias = { package = "real-name" }` installs real-name.
                renamed = _table(value).get("package")
                yield renamed if isinstance(renamed, str) else name


def _requirement_names(lines: Iterable[str]) -> Iterator[str]:
    """Names of PEP 508 requirements; options, paths and URLs are skipped."""

    for line in lines:
        requirement = line.split("#", 1)[0].strip()
        if requirement.startswith(("-", ".", "/")) or _URL.match(requirement):
            continue
        if (match := _REQUIREMENT_NAME.match(requirement)) is not None:
            yield match.group(1)


def _string_constants(node: ast.AST) -> list[str]:
    return [
        child.value
        for child in ast.walk(node)
        if isinstance(child, ast.Constant) and isinstance(child.value, str)
    ]


def _toml(text: str) -> dict[str, object]:
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return {}


def _table(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _keys(value: object) -> list[str]:
    return [key for key in value if isinstance(key, str)] if isinstance(value, dict) else []


def _strings(value: object) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _normalized(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _is_assignment(word: str) -> bool:
    name, separator, _ = word.partition("=")
    return bool(separator) and name.isidentifier()


__all__ = ["agent_recipe_violations"]
