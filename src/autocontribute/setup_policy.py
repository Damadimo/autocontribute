"""The deterministic filter on recipes the setup agent proposes (DESIGN §5.2, step 4).

The setup agent reads attacker-controllable files (README, CONTRIBUTING, CI), so its recipe is
checked before it runs: no sudo, no download piped into a shell, installs only of packages the
repository declares or of a fixed set of tools, no install from a URL or another index, no
variable that changes how tests run, and a test command with a per-test report, so the
acceptance gate sees real results. Edits to tracked files are caught after the replay, when
host Git finds them (``setup_dirty_paths``).
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Iterator, Sequence, Set
from typing import Final

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
_DECLARED_NAME: Final = re.compile(r"@?[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9._-]+)*")
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
    installer = next(
        (prefix for prefix in _INSTALLERS if tuple(words[: len(prefix)]) == prefix), None
    )
    if installer is None:
        return
    arguments = list(words[len(installer) :])
    skip_value = False
    for argument in arguments:
        if skip_value:
            skip_value = False
            if _URL.match(argument):
                yield f"installs from a URL: {argument}"
            continue
        option = argument.split("=", 1)[0]
        if option in _INDEX_OPTIONS:
            yield f"installs from another package index: {argument}"
            skip_value = "=" not in argument
            continue
        if option in _PATH_OPTIONS:
            skip_value = "=" not in argument
            continue
        if argument.startswith("-"):
            continue
        if _URL.match(argument):
            yield f"installs from a URL: {argument}"
        elif argument.startswith((".", "/")):
            continue
        else:
            name = _package_name(argument, go=installer[0] == "go")
            parts = name.split("/")
            # A Go command lives under the module the repository requires.
            prefixes = {"/".join(parts[:end]) for end in range(1, len(parts) + 1)}
            if name and name not in _ALLOWED_TOOLS and not prefixes & declared:
                yield f"installs {name}, which the repository does not declare"


def _package_name(argument: str, *, go: bool) -> str:
    name = (_GO_VERSION_SUFFIX if go else _VERSION_SUFFIX).sub("", argument)
    if not go and argument.startswith("@"):
        # A scoped npm package, perhaps with a version: @scope/name@1.2.
        scope, _, rest = argument[1:].partition("/")
        name = f"@{scope}/{rest.split('@', 1)[0]}"
    return _normalized(name)


def _declared_names(signals: RepositorySignals) -> frozenset[str]:
    """Every name in the signal files: manifests, requirements, CI and task runners."""

    return frozenset(
        _normalized(match)
        for text in signals.files.values()
        for match in _DECLARED_NAME.findall(text)
    )


def _normalized(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _is_assignment(word: str) -> bool:
    name, separator, _ = word.partition("=")
    return bool(separator) and name.isidentifier()


__all__ = ["agent_recipe_violations"]
