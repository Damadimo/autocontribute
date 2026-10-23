"""Non-mutating deployment preflight checks.

They cover the configuration, Git, Docker with cgroup v2 limits, a small billed tool-call probe
of each configured model, and read access to GitHub.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from collections.abc import Callable, Sequence
from contextvars import ContextVar, Token
from dataclasses import dataclass
from typing import cast

import httpx
from pydantic import ValidationError
from rich.markup import escape

from autocontribute.config import AutocontributeConfig
from autocontribute.discovery import DiscoveryService
from autocontribute.exceptions import (
    AutocontributeError,
    ConfigurationError,
    ModelError,
    SandboxError,
)
from autocontribute.github import GitHubClient
from autocontribute.pricing import DEFAULT_EFFORTS, ModelSpec, Role
from autocontribute.providers import SubprocessTurnProvider
from autocontribute.redaction import host_secret_values, redact_text
from autocontribute.sandbox import detect_docker_daemon_mode
from autocontribute.store import RunStore
from autocontribute.submissions import TriageSubmission
from autocontribute.transcript import SUBMIT_TOOLS, read_submission, start_transcript

_DETAIL_LIMIT = 500
# Enough for a short tool call after adaptive thinking at low effort.
_MODEL_PROBE_MAX_OUTPUT_TOKENS = 4_096
_MODEL_PROBE_TIMEOUT_SECONDS = 60.0
_MODEL_PROBE_INSTRUCTIONS = (
    "This is a deployment check of tool calling. Call submit_triage once, with suitable true, "
    'reasons ["deployment check"], already_fixed false, needs_design false and difficulty '
    "small. Do nothing else."
)
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f-\x9f]")
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


def run_doctor(
    config: AutocontributeConfig,
    *,
    store: RunStore | None = None,
) -> list[DoctorCheck]:
    """Run bounded preflight probes without changing a repository or GitHub state."""
    secret_env_names = tuple(sorted(config.secret_env_names()))
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
    checks.append(_docker_check())
    checks.extend(_model_checks(config, probe=not breaker_is_tripped))

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
    checks.append(
        DoctorCheck(
            "publication policy",
            True,
            "human approval required; scheduled runs cannot publish",
        )
    )
    return checks


def _docker_check() -> DoctorCheck:
    """Repository code runs only in Docker, under memory, CPU and process limits."""

    if shutil.which("docker") is None:
        return DoctorCheck("docker", False, "docker was not found on PATH")
    try:
        mode = detect_docker_daemon_mode()
    except SandboxError as exc:
        return DoctorCheck("docker", False, _safe_detail(str(exc)))
    return DoctorCheck(
        "docker", True, f"{mode} daemon that enforces cgroup v2 memory, CPU and process limits"
    )


def _model_checks(config: AutocontributeConfig, *, probe: bool) -> list[DoctorCheck]:
    """Resolve the configured models, then probe each distinct one unless ``probe`` is false."""

    try:
        models = config.models.resolve(os.environ)
    except ConfigurationError as exc:
        return [DoctorCheck("models", False, _safe_detail(str(exc)))]
    roles: dict[str, list[Role]] = {}
    specs: dict[str, ModelSpec] = {}
    for role in DEFAULT_EFFORTS:
        spec = models.spec(role)
        roles.setdefault(spec.id, []).append(role)
        specs[spec.id] = spec
    checks = [
        DoctorCheck(
            "models",
            True,
            ", ".join(f"{role} {models.spec(role).id}" for role in DEFAULT_EFFORTS),
        )
    ]
    if probe:
        checks.extend(_model_probe(specs[model], roles[model]) for model in specs)
    return checks


def _model_probe(spec: ModelSpec, roles: Sequence[Role]) -> DoctorCheck:
    """Ask the model for one strict tool call, the way every transcript ends."""

    name = f"model {spec.id} ({'/'.join(roles)})"
    limits = (
        f"billed probe of at most {_MODEL_PROBE_MAX_OUTPUT_TOKENS:,} output tokens and "
        f"{int(_MODEL_PROBE_TIMEOUT_SECONDS)} seconds"
    )
    host_values = host_secret_values(_DOCTOR_SECRET_ENV_NAMES.get(), os.environ)
    try:
        transcript = start_transcript(
            model=spec.id,
            effort="low",
            kind="triage",
            run_id="doctor",
            instructions=_MODEL_PROBE_INSTRUCTIONS,
            task="Run the deployment check.",
            host_values=host_values,
        )
        turn = SubprocessTurnProvider(spec, host_values).step(
            transcript=transcript,
            max_output_tokens=_MODEL_PROBE_MAX_OUTPUT_TOKENS,
            timeout_seconds=_MODEL_PROBE_TIMEOUT_SECONDS,
        )
        submit = SUBMIT_TOOLS["triage"].name
        call = next((call for call in turn.tool_calls if call.name == submit), None)
        if call is None:
            raise ModelError(f"the model answered without calling {submit}")
        read_submission(call, TriageSubmission)
    except (AutocontributeError, ValidationError) as exc:
        return DoctorCheck(name, False, _safe_detail(f"failed the {limits}: {exc}"))
    return DoctorCheck(
        name, True, _safe_detail(f"{turn.model} made a strict tool call with usage ({limits})")
    )


def _github_checks(
    config: AutocontributeConfig,
    *,
    store: RunStore | None,
) -> list[DoctorCheck]:
    github_token: Token[tuple[str, ...]] | None = None
    try:
        with GitHubClient(
            config.github,
            safety_trigger_handler=(store.record_stop if store is not None else None),
        ) as github:
            github_token = _DOCTOR_SECRET_VALUES.set(
                tuple(dict.fromkeys((*_DOCTOR_SECRET_VALUES.get(), github.token)))
            )
            login, scopes = _authenticated_login_and_scopes(github)
            authentication = DoctorCheck(
                "GitHub authentication", True, _safe_detail(f"authenticated as {login}")
            )
            target_access = _github_target_access_check(config, github)
            permissions = _github_permission_check(scopes=scopes)
            ai_policies = [_ai_policy_check(config, github, store)] if store is not None else []
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
        return [authentication, target_access, permissions, *ai_policies]
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


def _ai_policy_check(
    config: AutocontributeConfig,
    github: GitHubClient,
    store: RunStore,
) -> DoctorCheck:
    """Name each configured repository whose AI policy rules out this tool, with its quotes."""

    discovery = DiscoveryService(config, github, store)
    ruled_out: list[str] = []
    for name in config.github.repositories:
        try:
            reason = discovery.ai_policy_blocker(github.get_repository(name))
        except AutocontributeError as exc:
            reason = f"the AI policy could not be read: {exc}"
        if reason is not None:
            ruled_out.append(f"{name}: {reason}")
    if not ruled_out:
        return DoctorCheck(
            "repository AI policies",
            True,
            f"no AI policy rules out any of {len(config.github.repositories)} configured "
            "repository target(s)",
        )
    return DoctorCheck(
        "repository AI policies",
        True,
        _safe_detail("discovery skips " + "; ".join(ruled_out)),
        warning=True,
    )


def _github_permission_check(*, scopes: frozenset[str] | None) -> DoctorCheck:
    write_scopes = _CLASSIC_PUBLIC_WRITE_SCOPES.intersection(scopes or ())
    scope_text = ", ".join(sorted(scopes or ()))
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


def _command_check(name: str, command: list[str]) -> DoctorCheck:
    if shutil.which(command[0]) is None:
        return DoctorCheck(name, False, f"{command[0]} was not found on PATH")
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
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
