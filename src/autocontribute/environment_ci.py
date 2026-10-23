"""How a repository's CI installs and tests it, read as text (research-envsetup.md §B2, §B7).

Workflows, Makefiles, package.json scripts, tox and nox configuration and the scripts they call
are parsed, never run. Each CI step is expanded through its wrappers and task runner into
simple commands, so detection sees the test runner and the install steps behind `make ci`,
`scripts/test`, `tox run` or `npm run test-ci`.
"""

from __future__ import annotations

import configparser
import fnmatch
import json
import re
import shlex
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Final

import yaml

from autocontribute.environment_signals import RepositorySignals

# Make targets, scripts and package scripts may call one another; deeper chains are rare.
_MAX_DEPTH: Final = 4
# Words built from an expression that cannot be resolved statically; they contain `$` so
# command builders drop them like unresolved shell variables.
_UNRESOLVED: Final = "$__unresolved__"
_GITHUB_EXPRESSION: Final = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
_ENV_EXPRESSION: Final = re.compile(r"\s*env\.([A-Za-z_][A-Za-z0-9_]*)\s*")
_MATRIX_EXPRESSION: Final = re.compile(r"\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}")
# $(...), ${...} and `...`: make variables, shell parameters and command substitutions.
_SUBSTITUTION: Final = re.compile(r"\$\(\(?[^()]*\)?\)|\$\{[^{}]*\}|`[^`]*`")
_PYTHON_VARIABLE: Final = re.compile(r"\$[({](?:PYTHON\w*|PY)[)}]", re.IGNORECASE)
_SEPARATORS: Final = frozenset({"&&", "||", ";", ";;", "|", "|&", "&", "(", ")"})
_SHELL_KEYWORDS: Final = frozenset(
    {"if", "then", "else", "elif", "fi", "do", "done", "while", "until", "!", "{", "}"}
)
_ASSIGNMENT: Final = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.DOTALL)
_SHELL_REFERENCE: Final = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)")
_ENV_REFERENCE: Final = re.compile(r"\$\{\{\s*env\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")
_PYTHON: Final = re.compile(r"^(?:python(?:3(?:\.\d+)?)?|pypy3?)$")
_MAKE_RULE: Final = re.compile(r"^([\w./%-]+(?:[ \t]+[\w./%-]+)*)[ \t]*::?(?!=)(.*)$")
_MAKE_DEFAULT_GOAL: Final = re.compile(r"^\.DEFAULT_GOAL[ \t]*:?=[ \t]*(\S+)", re.MULTILINE)
_TOX_FACTOR_CONDITION: Final = re.compile(r"^(!?[\w.]+(?:[-,]!?[\w.]+)*):\s+(.*)$")
_TOX_POSARGS_DEFAULT: Final = re.compile(r"\{posargs:([^{}]*)\}")
_NOX_SESSION: Final = re.compile(
    r"^@nox\.session(?:\((?P<arguments>[^)]*)\))?[ \t]*\n(?:[ \t]*@[^\n]*\n)*"
    r"[ \t]*def[ \t]+(?P<function>\w+)",
    re.MULTILINE,
)
_NOX_SESSION_NAME: Final = re.compile(r"""name\s*=\s*["']([\w.-]+)["']""")
_NOX_RUN: Final = re.compile(r"session\.run\(([^)]*)\)")
_STRING_LITERAL: Final = re.compile(r"""(["'])([^"'\\]*)\1""")
_CI_TRIGGERS: Final = frozenset({"push", "pull_request", "pull_request_target", "merge_group"})
_UNSUPPORTED_SHELLS: Final = ("pwsh", "powershell", "cmd", "msys2")
_JAVASCRIPT_PROGRAMS: Final = frozenset(
    {"npm", "npx", "pnpm", "yarn", "bun", "node", "mocha", "_mocha", "jest", "vitest", "ava"}
)
_PACKAGE_MANAGERS: Final = frozenset({"npm", "pnpm", "yarn", "bun"})
_SCRIPTS: Final = frozenset({"", ".sh", ".bash"})
_UV_RUN_VALUE_OPTIONS: Final = frozenset(
    {
        "--group",
        "--extra",
        "--with",
        "--with-requirements",
        "--python",
        "-p",
        "--package",
        "--env-file",
        "--directory",
        "--project",
        "--index",
        "--resolution",
        "--only-group",
    }
)
_COVERAGE_VALUE_OPTIONS: Final = frozenset(
    {"--rcfile", "--source", "--omit", "--include", "--data-file", "--context", "--concurrency"}
)
_WRAPPERS: Final = frozenset({"sudo", "env", "time", "exec", "command", "nice", "xvfb-run"})
_WRAPPER_VALUE_OPTIONS: Final = frozenset({"-u", "-g", "-s", "-n", "--server-args"})
_KNOWN_PROGRAMS: Final = frozenset(
    {
        "pytest",
        "py.test",
        "tox",
        "nox",
        "pip",
        "pip3",
        "uv",
        "poetry",
        "pdm",
        "make",
        "go",
        "cargo",
        *_JAVASCRIPT_PROGRAMS,
    }
)


@dataclass(frozen=True, slots=True)
class Invocation:
    """One simple command a CI step runs once wrappers and task runners are expanded."""

    # The program and its arguments; `python -m X` reads as X and wrappers such as `uv run`,
    # `coverage run` and `nyc` are gone. Words that depended on unresolved variables contain
    # a `$`.
    words: tuple[str, ...]
    # Literal variables a step, an assignment or a script export set for the command.
    environment: Mapping[str, str] = field(default_factory=dict)
    # The tox environment whose commands the invocation came from.
    tox_environment: str | None = None
    # Dependency groups and extras a `uv run` wrapper asked for.
    uv_groups: tuple[str, ...] = ()
    uv_extras: tuple[str, ...] = ()
    # The nox session whose `session.run` call the invocation is.
    nox_session: str | None = None

    @property
    def runner(self) -> str | None:
        """The test runner the command starts, or None when it is not a test run."""

        program = self.words[0]
        if program in {"pytest", "py.test", "unittest", "jest", "vitest", "mocha"}:
            return "pytest" if program == "py.test" else program
        if program == "_mocha":
            return "mocha"
        if program in {"go", "cargo"} and self.words[1:2] == ("test",):
            return program
        if program == "cargo" and self.words[1:3] == ("nextest", "run"):
            return "cargo"
        if (
            _PYTHON.fullmatch(program)
            and len(self.words) > 1
            and self.words[1].endswith(".py")
            and "test" in PurePosixPath(self.words[1]).name
        ):
            return "python-script"
        return None


@dataclass(frozen=True, slots=True)
class CiStep:
    run: str | None
    # The action a step uses, without its version, e.g. "actions/setup-python".
    uses: str
    inputs: Mapping[str, str]
    env: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class CiJob:
    # Workflow and job variables with literal values that no step reads itself.
    env: Mapping[str, str]
    matrix: Mapping[str, tuple[str, ...]]
    steps: tuple[CiStep, ...]
    # Every workflow and job variable with a literal value, for `${{ env.X }}`.
    literal_env: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class CiTestRun:
    """The test steps of one CI job and the steps that prepare them."""

    job: CiJob
    # Test-runner invocations of every test step, in order. When the job's test step reaches
    # no known runner (a monorepo's `pnpm test`), its own command, with no runner.
    tests: tuple[Invocation, ...]
    # Every other command the job runs up to and including its first test step.
    installs: tuple[Invocation, ...]
    # The text those commands came from, scripts and make targets included.
    install_text: str
    # The commands of the steps before the first test step as written, not expanded.
    setup_steps: tuple[Invocation, ...]


@dataclass(frozen=True, slots=True)
class ToxEnvironment:
    name: str
    commands: tuple[tuple[str, ...], ...]
    dependency_groups: tuple[str, ...]
    extras: tuple[str, ...]
    deps: tuple[str, ...]
    set_env: Mapping[str, str]
    # Patterns of the variables tox passes through from its own environment.
    pass_env: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ToxConfig:
    env_list: tuple[str, ...]
    requires: tuple[str, ...]
    # Settings by section: "" for the base section, else the environment name.
    sections: Mapping[str, Mapping[str, object]]
    ini: bool

    def environment(self, name: str) -> ToxEnvironment:
        """Resolve one environment's settings, factor conditions applied (ini only)."""

        base = self.sections.get("", {})
        specific = self.sections.get(name, {})
        factors = set(name.split("-"))

        def setting(key: str) -> object:
            return specific[key] if key in specific else base.get(key)

        if self.ini:
            commands = tuple(
                words
                for line in _tox_ini_lines(setting("commands"), factors)
                if (words := _tox_words(line))
            )
            set_env = dict(
                pair
                for line in _tox_ini_lines(setting("setenv") or setting("set_env"), factors)
                if (pair := _assignment(line)) is not None and "{" not in line
            )
            return ToxEnvironment(
                name,
                commands,
                _tox_names(_tox_ini_lines(setting("dependency_groups"), factors)),
                _tox_names(_tox_ini_lines(setting("extras"), factors)),
                tuple(
                    line.replace("{toxinidir}/", "").replace("{tox_root}/", "")
                    for line in _tox_ini_lines(setting("deps"), factors)
                ),
                set_env,
                tuple(
                    pattern
                    for line in _tox_ini_lines(setting("passenv") or setting("pass_env"), factors)
                    for pattern in re.split(r"[,\s]+", line)
                    if pattern
                ),
            )
        raw_commands = setting("commands")
        commands = tuple(
            words
            for command in (raw_commands if isinstance(raw_commands, list) else [])
            if isinstance(command, list) and (words := _tox_toml_words(command))
        )
        raw_env = setting("set_env")
        return ToxEnvironment(
            name,
            commands,
            _string_list(setting("dependency_groups")),
            _string_list(setting("extras")),
            _string_list(setting("deps")),
            {
                key: value
                for key, value in (raw_env.items() if isinstance(raw_env, dict) else [])
                if isinstance(value, str) and "{" not in value
            },
            _string_list(setting("pass_env")),
        )

    def choose(self, requested: str | None, python_minor: int | None) -> str:
        """Pick the environment CI asked for, else the one for the chosen Python version."""

        if requested and "$" not in requested:
            return requested.split(",")[0]
        if python_minor is not None:
            wanted = {f"py3{python_minor}", f"py3.{python_minor}"}
            matching = [name for name in self.env_list if wanted & set(name.split("-"))]
            if matching:
                return min(matching, key=lambda name: name.count("-"))
            return f"py3{python_minor}"
        return next((name for name in self.env_list if name.startswith("py")), "py")


@dataclass(frozen=True, slots=True)
class CiSources:
    """The parsed task-runner files of one repository."""

    signals: RepositorySignals
    package_scripts: Mapping[str, str]
    make_rules: Mapping[str, tuple[tuple[str, ...], tuple[str, ...]]]
    make_default: str | None
    tox: ToxConfig | None
    nox_sessions: Mapping[str, str]

    @classmethod
    def parse(cls, signals: RepositorySignals) -> CiSources:
        makefile = next(
            (
                signals.files[name]
                for name in ("GNUmakefile", "makefile", "Makefile")
                if name in signals.files
            ),
            "",
        )
        rules, default = _parse_makefile(makefile)
        return cls(
            signals,
            _package_scripts(signals),
            rules,
            default,
            _parse_tox(signals),
            nox_sessions(signals),
        )


def ci_jobs(signals: RepositorySignals) -> list[CiJob]:
    """Linux jobs of the repository's workflows, those that run on pushes and pulls first."""

    ranked: list[tuple[tuple[int, int, str], list[CiJob]]] = []
    for path, text in signals.files.items():
        if not path.startswith(".github/workflows/"):
            continue
        document = load_strings_yaml(text)
        if not isinstance(document, dict):
            continue
        triggers = document.get("on")
        names = (
            set(triggers)
            if isinstance(triggers, dict | list)
            else {triggers}
            if isinstance(triggers, str)
            else set()
        )
        stem = PurePosixPath(path).stem.casefold()
        rank = (0 if names & _CI_TRIGGERS else 1, 0 if "test" in stem or "ci" in stem else 1, path)
        ranked.append((rank, _workflow_jobs(document)))
    return [job for _, jobs in sorted(ranked, key=lambda item: item[0]) for job in jobs]


def matrix_values(job: CiJob, value: str) -> list[str]:
    """Expand a `${{ matrix.X }}` template in an action input into its matrix values."""

    match = _MATRIX_EXPRESSION.search(value)
    if match is None:
        return [] if "${{" in value else [line.strip() for line in value.splitlines() if line]
    template = _MATRIX_EXPRESSION.sub("\0", value, count=1)
    if "${{" in template:
        return []
    return [template.replace("\0", item) for item in job.matrix.get(match.group(1), ())]


def action_inputs(job: CiJob, action: str, *names: str) -> list[str]:
    """Every value the job gives the named inputs of an action, matrix templates expanded."""

    values: list[str] = []
    for step in job.steps:
        if step.uses == action:
            for name in names:
                if name in step.inputs:
                    values.extend(matrix_values(job, step.inputs[name]))
    return values


def checkout_input(job: CiJob, name: str) -> str | None:
    values = action_inputs(job, "actions/checkout", name)
    return values[0] if values else None


def job_test_run(sources: CiSources, job: CiJob, *, python_minor: int | None) -> CiTestRun | None:
    """Expand a job's steps and return its test run, or None when it runs no tests."""

    expander = _Expander(sources, python_minor)
    setup_steps: list[Invocation] = []
    installs: list[Invocation] = []
    texts: list[str] = []
    tests: list[Invocation] = []
    fallback: Invocation | None = None
    for step in job.steps:
        if step.run is None:
            continue
        environment = {**job.env, **step.env}
        script = substitute_expressions(step.run, {**job.literal_env, **step.env})
        expander.texts = [script]
        invocations = expander.expand_text(script, environment, depth=0)
        commands = [
            _unwrap(Invocation(tuple(words), environment)) for words in shell_commands(script)
        ]
        if tests or fallback is not None:
            tests.extend(invocation for invocation in invocations if invocation.runner)
            continue
        # The first test step's own preparation (make prerequisites, a script's installs)
        # counts as setup too.
        installs.extend(invocation for invocation in invocations if not invocation.runner)
        texts.extend(expander.texts)
        tests.extend(invocation for invocation in invocations if invocation.runner)
        if not tests and commands and _looks_like_test(commands[0].words):
            fallback = commands[0]
        elif not tests:
            setup_steps.extend(commands)
    if not tests and fallback is not None:
        tests.append(fallback)
    if not tests:
        return None
    return CiTestRun(job, tuple(tests), tuple(installs), "\n".join(texts), tuple(setup_steps))


def expand_command(
    sources: CiSources, command: str, *, python_minor: int | None
) -> list[Invocation]:
    """Expand a command that is not part of CI, such as a package's test script."""

    return _Expander(sources, python_minor).expand_text(command, {}, depth=0)


def single_invocation(command: str) -> Invocation | None:
    """The one simple command a command line runs, wrappers stripped; None for anything else."""

    commands = shell_commands(command)
    return _unwrap(Invocation(tuple(commands[0]))) if len(commands) == 1 else None


def _package_scripts(signals: RepositorySignals) -> dict[str, str]:
    package = package_json(signals)
    scripts = package.get("scripts")
    if not isinstance(scripts, dict):
        return {}
    return {name: value for name, value in scripts.items() if isinstance(value, str)}


def package_json(signals: RepositorySignals) -> dict[str, object]:
    try:
        document = json.loads(signals.files.get("package.json", "{}"))
    except json.JSONDecodeError:
        return {}
    return document if isinstance(document, dict) else {}


def nox_sessions(signals: RepositorySignals) -> dict[str, str]:
    """Session names of the noxfile, each with the source of its function."""

    text = signals.files.get("noxfile.py", "")
    matches = list(_NOX_SESSION.finditer(text))
    sessions: dict[str, str] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        named = _NOX_SESSION_NAME.search(match.group("arguments") or "")
        sessions[named.group(1) if named else match.group("function")] = text[match.start() : end]
    return sessions


def load_strings_yaml(text: str) -> object:
    """Parse YAML keeping every scalar a string, so `3.10` stays "3.10" and `on` stays "on".

    BaseLoader resolves no tags at all, so it constructs only strings, lists and mappings.
    """

    try:
        return yaml.BaseLoader(text).get_single_data()
    except yaml.YAMLError:
        return None


def substitute_expressions(text: str, environment: Mapping[str, str]) -> str:
    """Replace `${{ env.X }}` with literal values; other expressions become unresolved."""

    def replace(match: re.Match[str]) -> str:
        name = _ENV_EXPRESSION.fullmatch(match.group(1))
        if name is not None and name.group(1) in environment:
            return environment[name.group(1)]
        return _UNRESOLVED

    return _GITHUB_EXPRESSION.sub(replace, text)


def shell_commands(text: str) -> list[list[str]]:
    """Split shell text into simple commands, each a list of words.

    Redirections, shell keywords and substitutions are dropped; a make or shell variable that
    names Python reads as `python`.
    """

    commands: list[list[str]] = []
    for line in text.replace("\\\n", " ").splitlines():
        line = _SUBSTITUTION.sub("", _PYTHON_VARIABLE.sub("python", line))
        lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        try:
            words = list(lexer)
        except ValueError:
            continue
        current: list[str] = []
        skip_next = False
        for word in words:
            if skip_next:
                skip_next = False
            elif word in _SEPARATORS:
                commands.append(current)
                current = []
            elif word.startswith(("<", ">")):
                if current and current[-1].isdigit():
                    current.pop()
                skip_next = True
            elif current or word not in _SHELL_KEYWORDS:
                current.append(word)
        commands.append(current)
    return [command for command in commands if command]


def _unwrap(invocation: Invocation) -> Invocation:
    """Strip assignments and wrapper commands until the real program comes first."""

    words = list(invocation.words)
    environment = dict(invocation.environment)
    groups = list(invocation.uv_groups)
    extras = list(invocation.uv_extras)
    while words:
        assignment = _assignment(words[0])
        program = PurePosixPath(words[0]).name
        rest = words[1:]
        if assignment is not None:
            if "$" not in assignment[1]:
                environment[assignment[0]] = assignment[1]
            words = rest
        elif program in _WRAPPERS:
            words, _ = _split_options(rest, _WRAPPER_VALUE_OPTIONS)
        elif program == "uv" and rest[:1] == ["run"]:
            words, uv_options = _split_options(rest[1:], _UV_RUN_VALUE_OPTIONS)
            groups += [value for option, value in uv_options if option == "--group"]
            extras += [value for option, value in uv_options if option == "--extra"]
        elif program in {"uvx", "npx", "pnpx", "bunx"}:
            words, _ = _split_options(rest, frozenset({"--from", "--with", "-p", "--package"}))
        elif program in {"poetry", "pdm", "pipenv", "hatch", "rye"} and rest[:1] == ["run"]:
            words = rest[1:]
            if program == "hatch" and words and ":" in words[0]:
                words[0] = words[0].split(":", 1)[1]
        elif program in {"pnpm", "yarn"} and rest[:1] in (["exec"], ["dlx"]):
            words = rest[1:]
        elif _PYTHON.fullmatch(program) and rest:
            words = _python_target(rest, frozenset({"-W", "-X"}))
            if words[0] == "python":
                break
        elif program == "coverage" and rest[:1] == ["run"]:
            words = _python_target(rest[1:], _COVERAGE_VALUE_OPTIONS)
        elif program in {"nyc", "c8"}:
            start = next(
                (
                    index
                    for index, word in enumerate(rest)
                    if PurePosixPath(word).name in _JAVASCRIPT_PROGRAMS
                ),
                len(rest),
            )
            words = rest[start:]
        elif program == "richgo":
            words = ["go", *rest]
        elif program == "gotestsum":
            words = ["go", "test", *rest[rest.index("--") + 1 :]] if "--" in rest else []
        else:
            if program in _KNOWN_PROGRAMS:
                words[0] = program
            break
    return Invocation(
        tuple(words),
        environment,
        invocation.tox_environment,
        tuple(groups),
        tuple(extras),
    )


def _looks_like_test(words: Sequence[str]) -> bool:
    if not words:
        return False
    program = PurePosixPath(words[0]).name
    if program in {"tox", "nox"}:
        named = [word for word in words[1:] if not word.startswith("-") and word != "run"]
        return not named or any(name.startswith("py") or "test" in name for name in named)
    target = next((word for word in words[1:] if not word.startswith("-")), "")
    if program in {"make", *_PACKAGE_MANAGERS} and target == "run":
        target = next((word for word in words[2:] if not word.startswith("-")), "")
    return program in {"make", *_PACKAGE_MANAGERS} and target.startswith("test")


class _Expander:
    def __init__(self, sources: CiSources, python_minor: int | None) -> None:
        self.sources = sources
        self.python_minor = python_minor
        self.texts: list[str] = []

    def expand_text(
        self, text: str, environment: Mapping[str, str], *, depth: int
    ) -> list[Invocation]:
        invocations: list[Invocation] = []
        exported = dict(environment)
        # A variable the text reads itself is the script's own plumbing, such as a venv prefix.
        referenced = set(_SHELL_REFERENCE.findall(text))
        for words in shell_commands(text):
            if words[0] == "cd" and words[1:2] not in ([], ["."], ["./"]):
                # Only commands at the repository root are followed.
                break
            if words[0] == "export":
                exported.update(
                    pair
                    for word in words[1:]
                    if (pair := _assignment(word)) is not None
                    and "$" not in pair[1]
                    and pair[0] not in referenced
                )
                continue
            invocations.extend(self.expand(Invocation(tuple(words), exported), depth=depth))
        return invocations

    def expand(self, invocation: Invocation, *, depth: int) -> list[Invocation]:
        invocation = _unwrap(invocation)
        words = invocation.words
        if not words or depth >= _MAX_DEPTH:
            return [invocation] if words else []
        program = words[0]
        script = program.removeprefix("./")
        if program in {"bash", "sh"} and len(words) > 1 and not words[1].startswith("-"):
            script = words[1].removeprefix("./")
        if script in self.sources.signals.files and PurePosixPath(script).suffix in _SCRIPTS:
            text = self.sources.signals.files[script]
            self.texts.append(text)
            return self.expand_text(text, invocation.environment, depth=depth + 1)
        if program == "make":
            return self._expand_make(invocation, depth)
        if program in _PACKAGE_MANAGERS:
            return self._expand_package_script(invocation, depth)
        if program == "tox" and self.sources.tox is not None:
            return self._expand_tox(invocation, self.sources.tox, depth)
        if program == "nox":
            return self._expand_nox(invocation, depth)
        return [invocation]

    def _expand_make(self, invocation: Invocation, depth: int) -> list[Invocation]:
        arguments = invocation.words[1:]
        if any(word in {"-C", "-f", "--directory", "--file"} for word in arguments):
            return [invocation]
        targets = [word for word in arguments if not word.startswith("-") and "=" not in word]
        lines: list[str] = []
        for target in targets or [self.sources.make_default or ""]:
            lines.extend(self._make_lines(target, depth))
        if not lines:
            return [invocation]
        text = "\n".join(line.lstrip("@-+").replace("$$", "$") for line in lines)
        self.texts.append(text)
        return self.expand_text(text, invocation.environment, depth=depth + 1)

    def _make_lines(self, target: str, depth: int) -> list[str]:
        rule = self.sources.make_rules.get(target)
        if rule is None or depth >= _MAX_DEPTH:
            return []
        prerequisites, recipe = rule
        lines = [line for item in prerequisites for line in self._make_lines(item, depth + 1)]
        return [*lines, *recipe]

    def _expand_package_script(self, invocation: Invocation, depth: int) -> list[Invocation]:
        manager, *arguments = invocation.words
        name, extra = _package_script_name(manager, arguments, self.sources.package_scripts)
        if name is None:
            return [invocation]
        script = self.sources.package_scripts[name]
        if extra:
            script = f"{script} {shlex.join(extra)}"
        self.texts.append(script)
        return self.expand_text(script, invocation.environment, depth=depth + 1)

    def _expand_nox(self, invocation: Invocation, depth: int) -> list[Invocation]:
        names = _nox_session_names(self.sources.nox_sessions, _nox_requested(invocation.words))
        if not names:
            return [invocation]
        invocations: list[Invocation] = []
        for name in names:
            for words in _nox_run_calls(self.sources.nox_sessions[name]):
                for item in self.expand(Invocation(words, invocation.environment), depth=depth + 1):
                    invocations.append(Invocation(item.words, item.environment, nox_session=name))
        return invocations

    def _expand_tox(
        self, invocation: Invocation, config: ToxConfig, depth: int
    ) -> list[Invocation]:
        arguments = list(invocation.words[1:])
        if "--" in arguments:
            arguments = arguments[: arguments.index("--")]
        requested = None
        for index, word in enumerate(arguments):
            if word in {"-e", "--env"} and index + 1 < len(arguments):
                requested = arguments[index + 1]
            elif word.startswith(("-e=", "--env=")):
                requested = word.split("=", 1)[1]
        name = config.choose(requested, self.python_minor)
        environment = config.environment(name)
        self.texts.extend(environment.deps)
        # tox gives its commands only the variables pass_env names, plus set_env.
        variables = {
            **{
                variable: value
                for variable, value in invocation.environment.items()
                if any(fnmatch.fnmatchcase(variable, pattern) for pattern in environment.pass_env)
            },
            **environment.set_env,
        }
        invocations: list[Invocation] = []
        for words in environment.commands:
            expanded = self.expand(Invocation(words, variables, name), depth=depth + 1)
            invocations.extend(
                Invocation(item.words, item.environment, name, item.uv_groups, item.uv_extras)
                for item in expanded
            )
        return invocations


def _workflow_jobs(document: dict[object, object]) -> list[CiJob]:
    jobs = document.get("jobs")
    if not isinstance(jobs, dict):
        return []
    workflow_env = _literal_env(document.get("env"))
    result: list[CiJob] = []
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        runs_on = job.get("runs-on")
        labels = " ".join(runs_on if isinstance(runs_on, list) else [str(runs_on)]).casefold()
        if "${{" not in labels and ("windows" in labels or "macos" in labels):
            continue
        defaults = job.get("defaults")
        run_defaults = defaults.get("run") if isinstance(defaults, dict) else None
        if isinstance(run_defaults, dict) and (
            run_defaults.get("working-directory") not in {None, ".", "./"}
            or str(run_defaults.get("shell", "")).startswith(_UNSUPPORTED_SHELLS)
        ):
            continue
        strategy = job.get("strategy")
        matrix = strategy.get("matrix") if isinstance(strategy, dict) else None
        raw_steps = job.get("steps")
        steps = tuple(
            step
            for raw in (raw_steps if isinstance(raw_steps, list) else [])
            if (step := _workflow_step(raw)) is not None
        )
        # Variables the steps read themselves configure CI, not the tests.
        referenced = {
            name
            for step in steps
            for pattern in (_ENV_REFERENCE, _SHELL_REFERENCE)
            for name in pattern.findall(step.run or "")
        }
        environment = {**workflow_env, **_literal_env(job.get("env"))}
        result.append(
            CiJob(
                {name: value for name, value in environment.items() if name not in referenced},
                _matrix(matrix),
                steps,
                environment,
            )
        )
    return result


def _workflow_step(raw: object) -> CiStep | None:
    if not isinstance(raw, dict):
        return None
    run = raw.get("run")
    shell = raw.get("shell")
    directory = raw.get("working-directory")
    if (isinstance(shell, str) and shell.startswith(_UNSUPPORTED_SHELLS)) or directory not in {
        None,
        ".",
        "./",
    }:
        run = None
    uses = raw.get("uses")
    inputs = raw.get("with")
    return CiStep(
        run if isinstance(run, str) else None,
        uses.split("@", 1)[0] if isinstance(uses, str) else "",
        {
            key: value
            for key, value in (inputs.items() if isinstance(inputs, dict) else [])
            if isinstance(key, str) and isinstance(value, str)
        },
        _literal_env(raw.get("env")),
    )


def _literal_env(raw: object) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    return {
        key: value
        for key, value in raw.items()
        if isinstance(key, str) and isinstance(value, str) and "${{" not in value
    }


def _matrix(raw: object) -> dict[str, tuple[str, ...]]:
    if not isinstance(raw, dict):
        return {}
    values: dict[str, list[str]] = {}
    for key, value in raw.items():
        if isinstance(key, str) and key not in {"include", "exclude"} and isinstance(value, list):
            values.setdefault(key, []).extend(item for item in value if isinstance(item, str))
    include = raw.get("include")
    for entry in include if isinstance(include, list) else []:
        if isinstance(entry, dict):
            for key, value in entry.items():
                if isinstance(key, str) and isinstance(value, str):
                    values.setdefault(key, []).append(value)
    return {key: tuple(dict.fromkeys(items)) for key, items in values.items()}


def _assignment(word: str) -> tuple[str, str] | None:
    match = _ASSIGNMENT.match(word)
    return (match.group(1), match.group(2)) if match else None


def _split_options(
    words: Sequence[str], value_options: frozenset[str]
) -> tuple[list[str], list[tuple[str, str]]]:
    """Separate leading options (and the values of those that take one) from the command."""

    options: list[tuple[str, str]] = []
    index = 0
    while index < len(words) and words[index].startswith("-"):
        option, separator, value = words[index].partition("=")
        if option == "--":
            index += 1
            break
        if not separator and option in value_options and index + 1 < len(words):
            index += 1
            value = words[index]
        options.append((option, value))
        index += 1
    return list(words[index:]), options


def _python_target(words: Sequence[str], value_options: frozenset[str]) -> list[str]:
    """What an interpreter runs: `-W x -m pytest -q` → ["pytest", "-q"], or ["python", script]."""

    index = 0
    while index < len(words) and words[index].startswith("-"):
        if words[index] == "-m" and index + 1 < len(words):
            return list(words[index + 1 :])
        if words[index].startswith("-m") and not words[index].startswith("-m="):
            return [words[index][2:], *words[index + 1 :]]
        index += 2 if words[index] in value_options else 1
    return ["python", *words[index:]]


def _package_script_name(
    manager: str, arguments: Sequence[str], scripts: Mapping[str, str]
) -> tuple[str | None, list[str]]:
    if any(
        word in {"-r", "--recursive", "--filter", "-F", "-w", "--workspace"} for word in arguments
    ):
        return None, []
    positional = [word for word in arguments if not word.startswith("-")]
    extra = list(arguments[arguments.index("--") + 1 :]) if "--" in arguments else []
    if not positional:
        return None, []
    command, *rest = positional
    if command in {"test", "t", "tst"} and manager != "bun":
        name: str | None = "test"
    elif command in {"run", "run-script"} and rest:
        name = rest[0]
    elif manager in {"yarn", "pnpm"} and command in scripts:
        name = command
    else:
        name = None
    if name is None or name not in scripts:
        return None, []
    return name, extra


def _nox_session_names(sessions: Mapping[str, str], requested: Sequence[str]) -> list[str]:
    """The sessions CI names, Python suffixes removed; else the one that looks like the tests."""

    if requested:
        names: list[str] = []
        for name in requested:
            found = next((item for item in (name, name.rsplit("-", 1)[0]) if item in sessions), "")
            if found and found not in names:
                names.append(found)
        return names
    default = next((name for name in ("tests", "test") if name in sessions), None)
    if default is None:
        default = next((name for name, source in sessions.items() if "pytest" in source), None)
    return [] if default is None else [default]


def _nox_requested(words: Sequence[str]) -> list[str]:
    arguments = list(words[1:])
    if "--" in arguments:
        arguments = arguments[: arguments.index("--")]
    requested: list[str] = []
    collecting = False
    for word in arguments:
        if word in {"-s", "--session", "--sessions", "-e"}:
            collecting = True
        elif word.startswith("-"):
            collecting = False
        elif collecting:
            requested.append(word)
    return requested


def _nox_run_calls(source: str) -> list[tuple[str, ...]]:
    """The literal positional words of each `session.run(...)` call in a session."""

    calls: list[tuple[str, ...]] = []
    for match in _NOX_RUN.finditer(source):
        words: list[str] = []
        for item in match.group(1).split(","):
            literal = _STRING_LITERAL.fullmatch(item.strip())
            if literal is not None:
                words.append(literal.group(2))
            elif "=" in item:
                break
        if words:
            calls.append(tuple(words))
    return calls


def _parse_makefile(
    text: str,
) -> tuple[dict[str, tuple[tuple[str, ...], tuple[str, ...]]], str | None]:
    rules: dict[str, tuple[tuple[str, ...], list[str]]] = {}
    default: str | None = None
    recipe: list[str] | None = None
    for line in text.replace("\\\n", " ").splitlines():
        if line.startswith("\t"):
            if recipe is not None and line.strip() and not line.lstrip().startswith("#"):
                recipe.append(line.strip())
            continue
        recipe = None
        match = _MAKE_RULE.match(line)
        if match is None:
            continue
        prerequisites, _, inline = match.group(2).partition(";")
        recipe = [inline.strip()] if inline.strip() else []
        for target in match.group(1).split():
            if target.startswith(".") or "%" in target or target in rules:
                continue
            rules[target] = (tuple(prerequisites.split("#")[0].split()), recipe)
            default = default or target
    goal = _MAKE_DEFAULT_GOAL.search(text)
    if goal is not None and goal.group(1) in rules:
        default = goal.group(1)
    return {name: (prereqs, tuple(lines)) for name, (prereqs, lines) in rules.items()}, default


def _parse_tox(signals: RepositorySignals) -> ToxConfig | None:
    if "tox.ini" in signals.files:
        return _parse_tox_ini(signals.files["tox.ini"])
    try:
        pyproject = tomllib.loads(signals.files.get("pyproject.toml", ""))
        tox_toml = tomllib.loads(signals.files.get("tox.toml", ""))
    except tomllib.TOMLDecodeError:
        return None
    tool = pyproject.get("tool")
    section = tool.get("tox") if isinstance(tool, dict) else None
    if isinstance(section, dict) and isinstance(section.get("legacy_tox_ini"), str):
        return _parse_tox_ini(section["legacy_tox_ini"])
    document = section if isinstance(section, dict) else tox_toml
    if not document:
        return None
    sections: dict[str, Mapping[str, object]] = {}
    base = document.get("env_run_base")
    if isinstance(base, dict):
        sections[""] = base
    environments = document.get("env")
    for name, settings in environments.items() if isinstance(environments, dict) else []:
        if isinstance(settings, dict):
            sections[name] = settings
    return ToxConfig(
        _string_list(document.get("env_list")),
        _string_list(document.get("requires")),
        sections,
        ini=False,
    )


def _parse_tox_ini(text: str) -> ToxConfig | None:
    parser = configparser.RawConfigParser(strict=False, interpolation=None)
    try:
        parser.read_string(text)
    except configparser.Error:
        return None
    sections: dict[str, Mapping[str, object]] = {}
    for section in parser.sections():
        if section == "testenv":
            sections[""] = dict(parser.items(section))
        elif section.startswith("testenv:"):
            sections[section.removeprefix("testenv:")] = dict(parser.items(section))
    tox = dict(parser.items("tox")) if parser.has_section("tox") else {}
    env_list = tox.get("envlist") or tox.get("env_list") or ""
    return ToxConfig(
        tuple(
            name
            for item in re.split(r",(?![^{]*\})|\n", env_list)
            for name in _expand_braces(item.strip())
            if name
        ),
        tuple(line.strip() for line in (tox.get("requires") or "").splitlines() if line.strip()),
        sections,
        ini=True,
    )


def _expand_braces(text: str) -> list[str]:
    match = re.search(r"\{([^{}]*)\}", text)
    if match is None:
        return [text]
    head, tail = text[: match.start()], text[match.end() :]
    return [
        expanded
        for option in match.group(1).split(",")
        for expanded in _expand_braces(head + option.strip() + tail)
    ]


def _tox_ini_lines(value: object, factors: set[str]) -> list[str]:
    if not isinstance(value, str):
        return []
    lines: list[str] = []
    for raw in value.replace("\\\n", " ").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        condition = _TOX_FACTOR_CONDITION.match(line)
        if condition is not None:
            if not _factors_match(condition.group(1), factors):
                continue
            line = condition.group(2).strip()
        lines.append(line)
    return lines


def _factors_match(condition: str, factors: set[str]) -> bool:
    return any(
        all(
            (factor[1:] not in factors) if factor.startswith("!") else (factor in factors)
            for factor in group.split("-")
        )
        for group in condition.split(",")
    )


def _tox_words(line: str) -> tuple[str, ...]:
    line = _TOX_POSARGS_DEFAULT.sub(r"\1", line.lstrip("- "))
    for name, value in (("{toxinidir}", "."), ("{tox_root}", "."), ("{envpython}", "python")):
        line = line.replace(name, value)
    try:
        words = shlex.split(line)
    except ValueError:
        return ()
    return tuple(word for word in words if "{" not in word and "}" not in word)


def _tox_toml_words(command: list[object]) -> tuple[str, ...]:
    words: list[str] = []
    for item in command:
        if isinstance(item, str) and "{" not in item:
            words.append(item)
        elif isinstance(item, dict) and item.get("replace") == "posargs":
            words.extend(_string_list(item.get("default")))
    return tuple(words)


def _tox_names(lines: Sequence[str]) -> tuple[str, ...]:
    return tuple(name.strip() for line in lines for name in line.split(",") if name.strip())


def _string_list(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        return tuple(item for item in value if isinstance(item, str))
    return ()


__all__ = [
    "CiJob",
    "CiSources",
    "CiStep",
    "CiTestRun",
    "Invocation",
    "ToxConfig",
    "ToxEnvironment",
    "action_inputs",
    "checkout_input",
    "ci_jobs",
    "expand_command",
    "job_test_run",
    "load_strings_yaml",
    "matrix_values",
    "nox_sessions",
    "package_json",
    "shell_commands",
    "single_invocation",
    "substitute_expressions",
]
