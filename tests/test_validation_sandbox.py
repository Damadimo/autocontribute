from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any, ClassVar

import pytest

import autocontribute.validation_sandbox as validation_sandbox
from autocontribute.config import SandboxConfig
from autocontribute.domain import CommandResult
from autocontribute.environments import EnvironmentRecipe
from autocontribute.exceptions import SandboxError
from autocontribute.sandbox import SessionCommandResult
from autocontribute.suite_runs import CheckRun, SuiteRun
from autocontribute.validation_sandbox import DockerValidation

_IMAGE = "sha256:" + "e" * 64


def _recipe() -> EnvironmentRecipe:
    return EnvironmentRecipe(
        repository="acme/demo",
        language="python",
        base_image="python:3.13-bookworm",
        system_packages=[],
        setup_commands=[],
        build_commands=["make generated"],
        test_command="python -m pytest",
        test_framework="pytest",
        test_report="/tmp/ac-report.xml",
        env={"PATH": "/usr/bin:/bin"},
        offline_env={"UV_OFFLINE": "1"},
        fetch_tags=False,
        fetch_submodules=False,
        source="detected",
        dependency_digest="b" * 64,
    )


def _sandbox(tmp_path: Path) -> DockerValidation:
    return DockerValidation(SandboxConfig(), _IMAGE, _recipe(), "run1", tmp_path / "state")


class _Container:
    exit_codes: ClassVar[list[int]] = []

    def __init__(self, config: SandboxConfig, **options: Any) -> None:
        self.options = options
        self.commands: list[str] = []

    def __enter__(self) -> _Container:
        return self

    def __exit__(self, *_exception: object) -> None:
        pass

    def exec(
        self, command: str, *, timeout_seconds: int, environment: Mapping[str, str]
    ) -> SessionCommandResult:
        self.commands.append(command)
        result = CommandResult(
            command=command,
            exit_code=_Container.exit_codes.pop(0),
            duration_seconds=1.0,
            stdout="",
            stderr="",
        )
        return SessionCommandResult(result, None, restarted=False)


def test_runs_go_to_the_suite_helpers_with_the_run_and_its_image(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, Any]] = []
    suite = SuiteRun(0, False, 1.0, {}, True, None, "")
    check = CheckRun(1, False, None, "boom")
    monkeypatch.setattr(
        validation_sandbox, "run_suite", lambda config, **kwargs: calls.append(kwargs) or suite
    )
    monkeypatch.setattr(
        validation_sandbox, "run_check", lambda config, **kwargs: calls.append(kwargs) or check
    )
    sandbox = _sandbox(tmp_path)

    assert sandbox.run_suite(tmp_path / "v", timeout_seconds=60, test_command="pytest x") is suite
    assert sandbox.run_check(tmp_path / "v", "false", timeout_seconds=30) is check
    assert calls[0]["image_id"] == _IMAGE and calls[0]["test_command"] == "pytest x"
    assert calls[1]["command"] == "false" and calls[1]["timeout_seconds"] == 30
    assert sandbox.environment == {"PATH": "/usr/bin:/bin", "UV_OFFLINE": "1"}


def test_a_session_is_built_before_use_and_refused_when_the_build_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(validation_sandbox, "SessionContainer", _Container)
    sandbox = _sandbox(tmp_path)

    _Container.exit_codes = [0]
    with sandbox.session(tmp_path, timeout_seconds=60) as session:
        assert isinstance(session, _Container)
        assert session.commands == ["make generated"]
        assert session.options["volumes"] == ("/opt/ac",)

    _Container.exit_codes = [2]
    with (
        pytest.raises(SandboxError, match="could not be built"),
        sandbox.session(tmp_path, timeout_seconds=60),
    ):
        pass
