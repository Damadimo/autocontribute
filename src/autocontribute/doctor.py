"""Non-mutating deployment preflight checks."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass

from autocontribute.config import AutocontributeConfig
from autocontribute.github import GitHubClient


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    passed: bool
    detail: str
    warning: bool = False


def run_doctor(config: AutocontributeConfig) -> list[DoctorCheck]:
    checks: list[DoctorCheck] = []
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

    try:
        with GitHubClient(config.github) as github:
            login = github.authenticated_login()
        checks.append(DoctorCheck("GitHub authentication", True, f"authenticated as {login}"))
    except Exception as exc:
        checks.append(DoctorCheck("GitHub authentication", False, str(exc)))

    has_targets = bool(config.github.repositories or config.github.owners)
    checks.append(
        DoctorCheck(
            "discovery targets",
            has_targets,
            "configured" if has_targets else "add at least one repository or owner",
        )
    )
    if config.publishing.mode == "auto":
        enabled = os.environ.get(config.publishing.auto_publish_env, "").casefold() in {
            "1",
            "true",
            "yes",
        }
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
        return DoctorCheck(name, False, str(exc))
    output = (result.stdout or result.stderr).strip().splitlines()
    return DoctorCheck(name, result.returncode == 0, output[0] if output else "no output")


__all__ = ["DoctorCheck", "run_doctor"]
