"""Non-mutating deployment preflight checks."""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
from collections.abc import Callable, Iterable
from contextvars import ContextVar, Token
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Literal, cast
from urllib.parse import quote

import httpx
from pydantic import BaseModel, ConfigDict
from rich.markup import escape

from autocontribute.config import (
    AutocontributeConfig,
    ModelProfile,
    auto_publish_opt_in_enabled,
    validate_model_identifier,
)
from autocontribute.github import GitHubClient
from autocontribute.providers import create_provider
from autocontribute.redaction import redact_text
from autocontribute.store import RunStore

_DETAIL_LIMIT = 500
_MODEL_PROBE_MAX_OUTPUT_TOKENS = 1_024
_MODEL_PROBE_TIMEOUT_SECONDS = 60.0
_SAFE_CONTAINER_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_SHELL_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_SHELL_SEPARATORS = frozenset({";", ";;", "&", "&&", "|", "||", "(", ")"})
_SHELL_BUILTINS = frozenset(
    {
        ".",
        ":",
        "[",
        "alias",
        "bg",
        "break",
        "cd",
        "continue",
        "eval",
        "exit",
        "export",
        "false",
        "fc",
        "fg",
        "getopts",
        "hash",
        "jobs",
        "kill",
        "pwd",
        "read",
        "readonly",
        "return",
        "set",
        "shift",
        "test",
        "times",
        "trap",
        "true",
        "type",
        "ulimit",
        "umask",
        "unalias",
        "unset",
        "wait",
    }
)
_SHELL_KEYWORDS = frozenset(
    {
        "case",
        "do",
        "done",
        "elif",
        "else",
        "esac",
        "fi",
        "for",
        "if",
        "in",
        "select",
        "then",
        "until",
        "while",
    }
)
_COMMAND_WRAPPERS = frozenset({"command", "exec", "time"})
_CLASSIC_PUBLIC_WRITE_SCOPES = frozenset({"public_repo", "repo"})
_DOCTOR_SECRET_ENV_NAMES: ContextVar[tuple[str, ...]] = ContextVar(
    "autocontribute_doctor_secret_env_names", default=()
)
_DOCTOR_SECRET_VALUES: ContextVar[tuple[str, ...]] = ContextVar(
    "autocontribute_doctor_secret_values", default=()
)


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    passed: bool
    detail: str
    warning: bool = False


@dataclass(frozen=True)
class _ToolchainRequirements:
    executables: tuple[str, ...]
    python_modules: tuple[tuple[str, str], ...]
    workspace_entrypoints: tuple[str, ...]
    command_count: int


class _ModelCapabilityResponse(BaseModel):
    """Minimal strict schema used to prove the configured provider path."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["ready"]


def run_doctor(
    config: AutocontributeConfig,
    *,
    store: RunStore | None = None,
) -> list[DoctorCheck]:
    """Run bounded preflight probes without changing a repository or GitHub state."""

    secret_env_names = tuple(
        sorted(
            {
                config.github.token_env,
                config.models.scout.api_key_env,
                config.models.builder.api_key_env,
                config.models.critic.api_key_env,
            }
        )
    )
    secret_values = tuple(
        dict.fromkeys(value for name in secret_env_names if (value := os.environ.get(name)))
    )
    names_token = _DOCTOR_SECRET_ENV_NAMES.set(secret_env_names)
    values_token = _DOCTOR_SECRET_VALUES.set(secret_values)
    try:
        return _run_doctor(config, store=store)
    finally:
        _DOCTOR_SECRET_VALUES.reset(values_token)
        _DOCTOR_SECRET_ENV_NAMES.reset(names_token)


def _run_doctor(
    config: AutocontributeConfig,
    *,
    store: RunStore | None = None,
) -> list[DoctorCheck]:
    """Execute doctor while the configured credential-redaction context is active."""

    checks: list[DoctorCheck] = []
    breaker_is_tripped = False
    if store is not None:
        breaker = store.circuit_breaker_status()
        breaker_is_tripped = breaker.is_tripped
        if breaker_is_tripped:
            checks.append(
                DoctorCheck(
                    "operational circuit breaker",
                    False,
                    _safe_detail(
                        f"active: {breaker.source}: {breaker.reason}; billed model and "
                        "GitHub probes were not sent"
                    ),
                )
            )
        else:
            checks.append(
                DoctorCheck(
                    "operational circuit breaker",
                    True,
                    "clear; external capability probes are allowed",
                )
            )

    checks.append(_command_check("git", ["git", "--version"]))
    if config.sandbox.backend == "docker":
        checks.append(
            _command_check("docker", ["docker", "info", "--format", "{{.ServerVersion}}"])
        )
        checks.append(
            _command_check(
                "sandbox image",
                [
                    "docker",
                    "image",
                    "inspect",
                    "--format",
                    "{{.Id}}",
                    config.sandbox.image,
                ],
            )
        )
    else:
        checks.append(
            DoctorCheck(
                "sandbox",
                config.sandbox.allow_unsafe_local,
                "local execution is enabled; repository code can access the host",
                warning=True,
            )
        )
    checks.append(_offline_toolchain_check(config))

    key_names = {
        config.models.scout.api_key_env,
        config.models.builder.api_key_env,
        config.models.critic.api_key_env,
    }
    for name in sorted(key_names):
        checks.append(
            DoctorCheck(
                f"model credential {name}",
                bool(os.environ.get(name)),
                "set" if os.environ.get(name) else "missing",
            )
        )
    if not breaker_is_tripped:
        checks.extend(_model_capability_checks(config))
    checks.append(
        DoctorCheck(
            "model tool boundary",
            True,
            "configured providers receive strict schemas but no tools or repository credentials",
        )
    )

    if not breaker_is_tripped:
        checks.extend(_github_checks(config, store=store))

    has_targets = bool(config.github.repositories or config.github.owners)
    checks.append(
        DoctorCheck(
            "discovery targets",
            has_targets,
            "configured" if has_targets else "add at least one repository or owner",
        )
    )
    if config.publishing.mode == "auto":
        enabled = auto_publish_opt_in_enabled(config.publishing)
        checks.append(
            DoctorCheck(
                "automatic publication kill-switch",
                enabled,
                (
                    "enabled"
                    if enabled
                    else f"set {config.publishing.auto_publish_env}=1 to allow GitHub writes"
                ),
            )
        )
    else:
        checks.append(
            DoctorCheck(
                "publication policy",
                True,
                "review_required; scheduled runs cannot publish",
            )
        )
    return checks


def _model_capability_checks(config: AutocontributeConfig) -> list[DoctorCheck]:
    grouped: dict[str, tuple[ModelProfile, list[str]]] = {}
    for role in ("scout", "builder", "critic"):
        profile = config.model_for(role)
        fingerprint = profile.model_dump_json()
        if fingerprint in grouped:
            grouped[fingerprint][1].append(role)
        else:
            grouped[fingerprint] = (profile, [role])

    checks: list[DoctorCheck] = []
    for profile, roles in grouped.values():
        label = "/".join(roles)
        credential = os.environ.get(profile.api_key_env)
        if not credential:
            checks.append(
                DoctorCheck(
                    f"model capability {label}",
                    False,
                    f"{profile.api_key_env} is missing; strict-schema probe was not sent",
                )
            )
            continue
        try:
            provider = create_provider(profile)
            result = provider.generate(
                instructions=(
                    "This is a deployment capability probe. Return the requested strict schema "
                    "with status set to ready. No tools are available."
                ),
                prompt="Confirm strict structured-output support.",
                output_type=_ModelCapabilityResponse,
                max_output_tokens=_MODEL_PROBE_MAX_OUTPUT_TOKENS,
                timeout_seconds=_MODEL_PROBE_TIMEOUT_SECONDS,
            )
            if result.output.status != "ready":  # defensive against a non-conforming adapter
                raise ValueError("provider returned the wrong capability sentinel")
            resolved_model = validate_model_identifier(result.model)
            if profile.deployment_model is not None and resolved_model != profile.deployment_model:
                raise ValueError("provider returned a model ID outside the calibrated deployment")
        except Exception as exc:
            checks.append(
                DoctorCheck(
                    f"model capability {label}",
                    False,
                    _safe_detail(
                        f"{profile.provider} model {profile.model} failed the bounded billed "
                        "strict-schema API probe (at most "
                        f"{_MODEL_PROBE_MAX_OUTPUT_TOKENS} output tokens and "
                        f"{int(_MODEL_PROBE_TIMEOUT_SECONDS)} seconds): {exc}"
                    ),
                )
            )
            continue
        checks.append(
            DoctorCheck(
                f"model capability {label}",
                True,
                _safe_detail(
                    f"{profile.provider} model {profile.model} resolved to {resolved_model} and "
                    "completed a strict-schema response with usage accounting (bounded billed "
                    "API probe: at most "
                    f"{_MODEL_PROBE_MAX_OUTPUT_TOKENS} output tokens and "
                    f"{int(_MODEL_PROBE_TIMEOUT_SECONDS)} seconds)"
                ),
            )
        )
    return checks


def _github_checks(
    config: AutocontributeConfig,
    *,
    store: RunStore | None,
) -> list[DoctorCheck]:
    github_token: Token[tuple[str, ...]] | None = None
    try:
        with GitHubClient(
            config.github,
            safety_trigger_handler=(
                store.trip_circuit_breaker_trigger if store is not None else None
            ),
        ) as github:
            github_token = _DOCTOR_SECRET_VALUES.set(
                tuple(dict.fromkeys((*_DOCTOR_SECRET_VALUES.get(), github.token)))
            )
            login, scopes = _authenticated_login_and_scopes(github)
            authentication = DoctorCheck(
                "GitHub authentication", True, _safe_detail(f"authenticated as {login}")
            )
            target_access = _github_target_access_check(config, github)
            permissions = _github_permission_check(config, github, login=login, scopes=scopes)
    except Exception as exc:
        detail = _safe_detail(str(exc))
        return [
            DoctorCheck("GitHub authentication", False, detail),
            DoctorCheck(
                "GitHub target access",
                False,
                "not checked because GitHub authentication failed",
            ),
            DoctorCheck(
                "GitHub permission boundary",
                False,
                "not checked because GitHub authentication failed",
            ),
        ]
    else:
        return [authentication, target_access, permissions]
    finally:
        if github_token is not None:
            _DOCTOR_SECRET_VALUES.reset(github_token)


def _authenticated_login_and_scopes(
    github: GitHubClient,
) -> tuple[str, frozenset[str] | None]:
    """Authenticate through the hardened client while observing its response headers."""

    captured: list[httpx.Headers] = []

    def capture_headers(response: httpx.Response) -> None:
        if response.request.method == "GET" and response.request.url.path.rstrip("/").endswith(
            "/user"
        ):
            captured.append(response.headers)

    response_hooks = cast(
        "list[Callable[[httpx.Response], None]]",
        github._client.event_hooks.setdefault("response", []),
    )
    response_hooks.append(capture_headers)
    try:
        login = github.authenticated_login()
    finally:
        response_hooks.remove(capture_headers)

    if not captured:
        return login, None
    raw_scopes = captured[-1].get("X-OAuth-Scopes")
    if not raw_scopes:
        # Fine-grained PATs and GitHub App user tokens do not expose classic OAuth scopes.
        return login, None
    return login, frozenset(scope.strip() for scope in raw_scopes.split(",") if scope.strip())


def _github_target_access_check(
    config: AutocontributeConfig,
    github: GitHubClient,
) -> DoctorCheck:
    if not (config.github.repositories or config.github.owners):
        return DoctorCheck(
            "GitHub target access", False, "no repositories or owners are configured"
        )

    repository_count = 0
    owner_count = 0
    try:
        for expected in config.github.repositories:
            repository = github.get_repository(expected)
            if repository.full_name.casefold() != expected.casefold():
                raise ValueError(f"GitHub returned a different repository for {expected}")
            if repository.private:
                raise ValueError(f"{expected} is private; only open-source targets are allowed")
            repository_count += 1
        for owner in config.github.owners:
            repositories = github.list_owner_repositories(owner, limit=1)
            if not repositories:
                raise ValueError(f"{owner} has no accessible public repositories")
            if repositories[0].private:
                raise ValueError(f"{owner} returned a private repository")
            owner_count += 1
    except Exception as exc:
        return DoctorCheck("GitHub target access", False, _safe_detail(str(exc)))

    return DoctorCheck(
        "GitHub target access",
        True,
        f"read-only access verified for {repository_count} repository target(s) and "
        f"{owner_count} owner target(s)",
    )


def _github_permission_check(
    config: AutocontributeConfig,
    github: GitHubClient,
    *,
    login: str,
    scopes: frozenset[str] | None,
) -> DoctorCheck:
    write_scopes = _CLASSIC_PUBLIC_WRITE_SCOPES.intersection(scopes or ())
    scope_text = ", ".join(sorted(scopes or ()))
    if config.publishing.mode != "auto":
        if write_scopes:
            return DoctorCheck(
                "GitHub permission boundary",
                True,
                _safe_detail(
                    "read access was verified, but the classic token exposes write scope(s) "
                    f"not needed for preparation: {', '.join(sorted(write_scopes))}"
                ),
                warning=True,
            )
        if scopes is None:
            return DoctorCheck(
                "GitHub permission boundary",
                True,
                "read access was verified; this token type does not expose classic OAuth scopes",
                warning=True,
            )
        return DoctorCheck(
            "GitHub permission boundary",
            True,
            _safe_detail(
                "read access verified with no classic public-repository write scope"
                + (f" (reported scopes: {scope_text})" if scope_text else "")
            ),
        )

    source = config.github.repositories[0]
    fork = f"{login}/{source.split('/', 1)[1]}"
    try:
        raw_fork = github._request(
            "GET",
            f"/repos/{quote(fork, safe='/')}",
            allow_not_found=True,
        )
    except Exception as exc:
        return DoctorCheck("GitHub permission boundary", False, _safe_detail(str(exc)))

    if raw_fork is None:
        if not write_scopes:
            return DoctorCheck(
                "GitHub permission boundary",
                False,
                _safe_detail(
                    f"{fork} does not exist and this token exposes no verifiable classic "
                    "public-repository write scope; create the fork manually or use a "
                    "write-capable token"
                ),
            )
        return DoctorCheck(
            "GitHub permission boundary",
            True,
            _safe_detail(
                f"classic {', '.join(sorted(write_scopes))} scope permits public repository "
                f"writes; {fork} is absent and fork creation was intentionally not attempted"
            ),
            warning=True,
        )
    if not isinstance(raw_fork, dict):
        return DoctorCheck(
            "GitHub permission boundary", False, "GitHub returned malformed fork metadata"
        )
    parent = raw_fork.get("parent")
    permissions = raw_fork.get("permissions")
    if (
        raw_fork.get("fork") is not True
        or not isinstance(parent, dict)
        or str(parent.get("full_name", "")).casefold() != source.casefold()
    ):
        return DoctorCheck(
            "GitHub permission boundary",
            False,
            _safe_detail(f"{fork} exists but is not the expected fork of {source}"),
        )
    if not isinstance(permissions, dict) or permissions.get("push") is not True:
        return DoctorCheck(
            "GitHub permission boundary",
            False,
            _safe_detail(f"the authenticated account cannot push to {fork}"),
        )
    if scopes is not None and not write_scopes:
        return DoctorCheck(
            "GitHub permission boundary",
            False,
            _safe_detail(
                "the account can push to its fork, but the classic token lacks public_repo or "
                "repo scope"
            ),
        )
    if scopes is None:
        detail = (
            f"read-only metadata reports account push access to {fork}; this token type does not "
            "expose token-level fork or pull-request write permissions, and no write was sent"
        )
    else:
        detail = (
            f"read-only metadata reports account push access to {fork}, and classic scope "
            "evidence infers public-repository write capability; no write was sent"
        )
    return DoctorCheck(
        "GitHub permission boundary",
        True,
        _safe_detail(detail),
        warning=True,
    )


def _offline_toolchain_check(config: AutocontributeConfig) -> DoctorCheck:
    commands = [
        command
        for repository_commands in config.validation.required_commands.values()
        for command in repository_commands
    ]
    if not commands:
        return DoctorCheck(
            "offline validation toolchain",
            False,
            "no validation.required_commands are configured",
        )
    try:
        requirements = _toolchain_requirements(commands)
    except ValueError as exc:
        return DoctorCheck("offline validation toolchain", False, _safe_detail(str(exc)))

    if config.sandbox.backend == "local":
        missing = [tool for tool in requirements.executables if shutil.which(tool) is None]
        if not os.path.isfile("/bin/sh"):
            missing.insert(0, "/bin/sh")
        if missing:
            return DoctorCheck(
                "offline validation toolchain",
                False,
                _safe_detail("missing local executable(s): " + ", ".join(missing)),
            )
        for interpreter, module in requirements.python_modules:
            module_check = _local_python_module_check(interpreter, module)
            if module_check is not None:
                return DoctorCheck("offline validation toolchain", False, module_check)
        return DoctorCheck(
            "offline validation toolchain",
            True,
            _toolchain_success_detail(requirements, backend="unsafe local host"),
            warning=True,
        )

    command = _docker_toolchain_probe(config, requirements)
    result = _command_check(
        "offline validation toolchain",
        command,
        timeout_seconds=30,
    )
    if not result.passed:
        return result
    return DoctorCheck(
        "offline validation toolchain",
        True,
        _toolchain_success_detail(requirements, backend="network-disabled sandbox image"),
    )


def _toolchain_requirements(commands: Iterable[str]) -> _ToolchainRequirements:
    executables: set[str] = set()
    python_modules: set[tuple[str, str]] = set()
    workspace_entrypoints: set[str] = set()
    command_count = 0
    for command in commands:
        command_count += 1
        if "\n" in command or "\r" in command:
            raise ValueError(
                "multiline validation commands cannot be probed reliably; split them into "
                "separate configured commands"
            )
        try:
            lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|()<>")
            lexer.whitespace_split = True
            lexer.commenters = ""
            tokens = list(lexer)
        except ValueError as exc:
            raise ValueError(f"validation command cannot be parsed safely: {exc}") from exc
        for segment in _shell_segments(tokens):
            requirement = _segment_requirement(segment)
            if requirement is None:
                continue
            executable, arguments = requirement
            if "$" in executable or "`" in executable or executable.startswith("-"):
                raise ValueError(
                    f"validation command has a dynamic executable that cannot be probed: "
                    f"{executable}"
                )
            if "/" in executable and not PurePosixPath(executable).is_absolute():
                workspace_entrypoints.add(executable)
                continue
            executables.add(executable)
            if PurePosixPath(executable).name.startswith("python") and "-m" in arguments:
                module_index = arguments.index("-m") + 1
                if module_index >= len(arguments) or arguments[module_index].startswith("-"):
                    raise ValueError("python -m validation command is missing its module name")
                module = arguments[module_index].split(".", 1)[0]
                if not module or not module.replace("_", "a").isalnum():
                    raise ValueError("python -m validation module cannot be probed safely")
                python_modules.add((executable, module))
    return _ToolchainRequirements(
        executables=tuple(sorted(executables)),
        python_modules=tuple(sorted(python_modules)),
        workspace_entrypoints=tuple(sorted(workspace_entrypoints)),
        command_count=command_count,
    )


def _shell_segments(tokens: list[str]) -> list[list[str]]:
    segments: list[list[str]] = []
    current: list[str] = []
    for token in tokens:
        if token in _SHELL_SEPARATORS:
            if current:
                segments.append(current)
                current = []
            continue
        current.append(token)
    if current:
        segments.append(current)
    return segments


def _segment_requirement(segment: list[str]) -> tuple[str, list[str]] | None:
    index = 0
    while index < len(segment) and (
        segment[index] == "!" or _SHELL_ASSIGNMENT.match(segment[index])
    ):
        index += 1
    if index >= len(segment):
        return None
    executable = segment[index]
    if executable in _SHELL_KEYWORDS:
        raise ValueError(
            f"complex shell keyword {executable!r} prevents a reliable toolchain probe"
        )
    if executable in _SHELL_BUILTINS:
        return None
    if executable == "env":
        index += 1
        while index < len(segment):
            token = segment[index]
            if token in {"-u", "--unset"}:
                index += 2
                continue
            if token.startswith("-") or _SHELL_ASSIGNMENT.match(token):
                index += 1
                continue
            break
        if index >= len(segment):
            return "env", []
        executable = segment[index]
    elif executable in _COMMAND_WRAPPERS:
        index += 1
        while index < len(segment) and segment[index].startswith("-"):
            index += 1
        if index >= len(segment):
            return None
        executable = segment[index]
    return executable, segment[index + 1 :]


def _docker_toolchain_probe(
    config: AutocontributeConfig,
    requirements: _ToolchainRequirements,
) -> list[str]:
    script = (
        'tool_count="$1"; shift; '
        'while [ "$tool_count" -gt 0 ]; do tool="$1"; shift; '
        'command -v "$tool" >/dev/null 2>&1 || '
        '{ printf "missing executable: %s\\n" "$tool"; exit 1; }; '
        "tool_count=$((tool_count - 1)); done; "
        'while [ "$#" -gt 0 ]; do interpreter="$1"; module="$2"; shift 2; '
        '"$interpreter" -I -c '
        "'import importlib.util,sys; sys.exit(importlib.util.find_spec(sys.argv[1]) is None)' "
        '"$module" >/dev/null 2>&1 || '
        '{ printf "missing Python module: %s (%s)\\n" "$module" "$interpreter"; '
        'exit 1; }; done; printf "toolchain probe passed\\n"'
    )
    module_arguments = [
        value
        for interpreter, module in requirements.python_modules
        for value in (interpreter, module)
    ]
    uid, gid = _non_root_identity()
    return [
        "docker",
        "run",
        "--rm",
        "--pull=never",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--ipc=none",
        f"--user={uid}:{gid}",
        f"--memory={config.sandbox.memory}",
        f"--memory-swap={config.sandbox.memory}",
        f"--cpus={config.sandbox.cpus}",
        f"--pids-limit={config.sandbox.pids_limit}",
        "--ulimit=nofile=1024:1024",
        "--ulimit=core=0:0",
        "--stop-timeout=2",
        "--init",
        "--tmpfs=/tmp:rw,nosuid,nodev,size=64m",
        "--entrypoint=/usr/bin/env",
        config.sandbox.image,
        "-i",
        f"PATH={_SAFE_CONTAINER_PATH}",
        "HOME=/tmp",
        "TMPDIR=/tmp",
        "PYTHONDONTWRITEBYTECODE=1",
        "/bin/sh",
        "-c",
        script,
        "autocontribute-doctor",
        str(len(requirements.executables)),
        *requirements.executables,
        *module_arguments,
    ]


def _non_root_identity() -> tuple[int, int]:
    getuid = getattr(os, "getuid", None)
    getgid = getattr(os, "getgid", None)
    uid = getuid() if getuid is not None else 65_532
    gid = getgid() if getgid is not None else 65_532
    return (65_532 if uid == 0 else uid, 65_532 if gid == 0 else gid)


def _local_python_module_check(interpreter: str, module: str) -> str | None:
    executable = shutil.which(interpreter)
    if executable is None:
        return _safe_detail(f"missing local executable: {interpreter}")
    try:
        result = subprocess.run(
            [
                executable,
                "-I",
                "-c",
                (
                    "import importlib.util,sys; "
                    "sys.exit(importlib.util.find_spec(sys.argv[1]) is None)"
                ),
                module,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env={
                "PATH": os.environ.get("PATH", ""),
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return _safe_detail(f"could not probe Python module {module}: {exc}")
    if result.returncode != 0:
        return _safe_detail(f"missing Python module: {module} ({interpreter})")
    return None


def _toolchain_success_detail(
    requirements: _ToolchainRequirements,
    *,
    backend: str,
) -> str:
    details = [
        f"{requirements.command_count} configured command(s) have available entrypoints in the "
        f"{backend}"
    ]
    if requirements.python_modules:
        details.append(
            "Python modules: " + ", ".join(module for _, module in requirements.python_modules)
        )
    if requirements.workspace_entrypoints:
        details.append(
            "repository-local scripts deferred to run validation: "
            + ", ".join(requirements.workspace_entrypoints)
        )
    return _safe_detail("; ".join(details))


def _command_check(
    name: str,
    command: list[str],
    *,
    timeout_seconds: float = 15,
) -> DoctorCheck:
    if shutil.which(command[0]) is None:
        return DoctorCheck(name, False, f"{command[0]} was not found on PATH")
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env={"PATH": os.environ.get("PATH", "")},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return DoctorCheck(name, False, _safe_detail(str(exc)))
    output = (result.stdout or result.stderr).strip().splitlines()
    detail = output[0] if output else "no output"
    return DoctorCheck(name, result.returncode == 0, _safe_detail(detail))


def _safe_detail(value: object) -> str:
    text = str(value)
    for secret in _DOCTOR_SECRET_VALUES.get():
        if secret:
            text = text.replace(secret, "[REDACTED:CREDENTIAL]")
    text = redact_text(text, secret_env_names=_DOCTOR_SECRET_ENV_NAMES.get())
    text = _CONTROL_CHARACTERS.sub(" ", text)
    text = re.sub(r"\s+", " ", text).strip() or "no detail"
    if len(text) > _DETAIL_LIMIT:
        text = text[: _DETAIL_LIMIT - 1] + "…"
    return escape(text)


__all__ = ["DoctorCheck", "run_doctor"]
