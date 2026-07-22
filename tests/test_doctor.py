from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

import autocontribute.doctor as doctor
from autocontribute.config import AutocontributeConfig
from autocontribute.exceptions import CircuitBreakerTrigger, GitHubSafetyError
from autocontribute.github import GitHubClient
from autocontribute.store import RunStore


def _config(
    *,
    backend: str = "docker",
    command: str = "python -m unittest discover -v",
) -> AutocontributeConfig:
    sandbox: dict[str, object] = (
        {"backend": "local", "allow_unsafe_local": True} if backend == "local" else {}
    )
    return AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "sandbox": sandbox,
            "validation": {"required_commands": {"example/project": [command]}},
        }
    )


def _auto_config() -> AutocontributeConfig:
    pricing = {
        "input_usd_per_million_tokens": "1",
        "output_usd_per_million_tokens": "1",
    }
    profile = {
        "expected_response_model": "gpt-5.6-2026-07-21",
        "immutable_response_model_attested": True,
        "pricing": pricing,
    }
    return AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "models": {
                "scout": profile,
                "builder": profile,
                "critic": {**profile, "reasoning_mode": "pro"},
            },
            "validation": {"required_commands": {"example/project": ["python -m unittest"]}},
            "publishing": {
                "mode": "auto",
                "draft": True,
                "max_new_pull_requests_per_day": 1,
                "max_open_pull_requests": 1,
                "repository_cooldown_days": 7,
            },
            "budget": {"max_model_cost_usd_per_run": "1"},
        }
    )


class _ReadyProvider:
    def __init__(self, calls: list[dict[str, Any]]) -> None:
        self.calls = calls

    def generate(self, **kwargs: Any) -> SimpleNamespace:
        self.calls.append(kwargs)
        output_type = kwargs["output_type"]
        return SimpleNamespace(
            output=output_type(status="ready"),
            model="gpt-5.6-2026-07-21",
        )


class _FakeGitHub:
    def __init__(self, fork: object) -> None:
        self.fork = fork
        self.requests: list[tuple[str, str, bool]] = []

    def _request(
        self,
        method: str,
        path: str,
        *,
        allow_not_found: bool = False,
    ) -> object:
        self.requests.append((method, path, allow_not_found))
        return self.fork


class _RateLimitedDoctorGitHub:
    def __init__(
        self,
        _config: object,
        *,
        safety_trigger_handler: object,
    ) -> None:
        assert callable(safety_trigger_handler)
        self._safety_trigger_handler = safety_trigger_handler
        self._client = SimpleNamespace(event_hooks={})
        self.token = "fixture-github-token"

    def __enter__(self) -> _RateLimitedDoctorGitHub:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def authenticated_login(self) -> str:
        trigger = CircuitBreakerTrigger(
            source="github_api:rate_or_abuse_limit",
            reason="GitHub returned a simulated 429 response",
            trigger_hash="a" * 64,
        )
        self._safety_trigger_handler(trigger)  # type: ignore[operator]
        raise GitHubSafetyError("GitHub activated the global safety stop", trigger=trigger)


def test_active_breaker_skips_billed_model_and_github_probes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = RunStore(tmp_path / "state")
    store.trip_circuit_breaker(
        source="operator:test",
        reason="review required",
        trigger_hash="b" * 64,
    )
    monkeypatch.setenv("OPENAI_API_KEY", "test-only-secret")
    monkeypatch.setattr(
        doctor,
        "_command_check",
        lambda name, *_args, **_kwargs: doctor.DoctorCheck(name, True, "available"),
    )
    monkeypatch.setattr(
        doctor,
        "_offline_toolchain_check",
        lambda _config: doctor.DoctorCheck("offline validation toolchain", True, "available"),
    )
    monkeypatch.setattr(
        doctor,
        "create_provider",
        lambda *_args, **_kwargs: pytest.fail("active breaker must block model probes"),
    )
    monkeypatch.setattr(
        doctor,
        "GitHubClient",
        lambda *_args, **_kwargs: pytest.fail("active breaker must block GitHub probes"),
    )

    checks = doctor.run_doctor(_config(), store=store)

    assert checks[0].name == "operational circuit breaker"
    assert not checks[0].passed
    assert "probes were not sent" in checks[0].detail
    assert not any(check.name.startswith("model capability") for check in checks)
    assert not any(check.name.startswith("GitHub ") for check in checks)


def test_doctor_github_safety_trigger_survives_snapshot_restore(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = RunStore(tmp_path / "state")
    monkeypatch.setattr(doctor, "GitHubClient", _RateLimitedDoctorGitHub)

    checks = doctor._github_checks(_config(), store=store)

    assert not checks[0].passed
    assert store.circuit_breaker_status().is_tripped
    snapshot = store.create_snapshot(tmp_path / "snapshots" / "state.sqlite3")
    RunStore.restore_snapshot(tmp_path / "restored", snapshot)
    restored = RunStore(tmp_path / "restored").circuit_breaker_status()
    assert restored.is_tripped
    assert restored.source == "github_api:rate_or_abuse_limit"
    assert restored.trigger_hash == "a" * 64


def test_model_capability_probe_deduplicates_exact_profiles_and_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config()
    monkeypatch.setenv("OPENAI_API_KEY", "test-only-secret")
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(doctor, "create_provider", lambda _profile: _ReadyProvider(calls))

    checks = doctor._model_capability_checks(config)

    assert [check.name for check in checks] == [
        "model capability scout/builder",
        "model capability critic",
    ]
    assert all(check.passed for check in checks)
    assert len(calls) == 2
    assert all(call["max_output_tokens"] == 1_024 for call in calls)
    assert all(call["timeout_seconds"] == 60.0 for call in calls)
    assert all("bounded billed API probe" in check.detail for check in checks)
    assert all("resolved to gpt-5.6-2026-07-21" in check.detail for check in checks)
    assert all("test-only-secret" not in check.detail for check in checks)


def test_model_capability_probe_fails_closed_without_sending_when_credential_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(
        doctor,
        "create_provider",
        lambda _profile: pytest.fail("provider must not be constructed without a credential"),
    )

    checks = doctor._model_capability_checks(_config())

    assert len(checks) == 2
    assert all(not check.passed for check in checks)
    assert all("probe was not sent" in check.detail for check in checks)


def test_model_capability_probe_rejects_a_model_outside_the_attested_deployment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class WrongModelProvider(_ReadyProvider):
        def generate(self, **kwargs: Any) -> SimpleNamespace:
            result = super().generate(**kwargs)
            result.model = "gpt-5.6-2026-07-22"
            return result

    monkeypatch.setenv("OPENAI_API_KEY", "test-only-secret")
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(doctor, "create_provider", lambda _profile: WrongModelProvider(calls))

    checks = doctor._model_capability_checks(_auto_config())

    assert len(checks) == 2
    assert all(not check.passed for check in checks)
    assert all("outside the calibrated deployment" in check.detail for check in checks)


def test_model_capability_probe_rejects_an_unbounded_resolved_model_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class UnboundedModelProvider(_ReadyProvider):
        def generate(self, **kwargs: Any) -> SimpleNamespace:
            result = super().generate(**kwargs)
            result.model = "m" * 201
            return result

    monkeypatch.setenv("OPENAI_API_KEY", "test-only-secret")
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(doctor, "create_provider", lambda _profile: UnboundedModelProvider(calls))

    checks = doctor._model_capability_checks(_config())

    assert len(checks) == 2
    assert all(not check.passed for check in checks)
    assert all("canonical provider IDs" in check.detail for check in checks)


def test_doctor_redacts_configured_and_recognizable_credentials_from_provider_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class EchoingProvider:
        def generate(self, **_kwargs: Any) -> SimpleNamespace:
            raise RuntimeError(f"upstream echoed {opaque_key} and {recognizable_token}\x1b[31m")

    config = _config()
    secret_env = "OPAQUE_PROVIDER_AUTH"
    opaque_key = "opaque-provider-key-[should-not-render]-012345"
    recognizable_token = "ghp_" + "a" * 36
    for role in ("scout", "builder", "critic"):
        config.model_for(role).api_key_env = secret_env
    monkeypatch.setenv(secret_env, opaque_key)
    monkeypatch.setattr(doctor, "create_provider", lambda _profile: EchoingProvider())
    monkeypatch.setattr(
        doctor,
        "_command_check",
        lambda name, *_args, **_kwargs: doctor.DoctorCheck(name, True, "available"),
    )
    monkeypatch.setattr(
        doctor,
        "_offline_toolchain_check",
        lambda _config: doctor.DoctorCheck("offline validation toolchain", True, "available"),
    )
    monkeypatch.setattr(doctor, "_github_checks", lambda *_args, **_kwargs: [])

    checks = doctor.run_doctor(config)
    capability_checks = [check for check in checks if check.name.startswith("model capability")]

    assert capability_checks
    assert all(not check.passed for check in capability_checks)
    assert all(opaque_key not in check.detail for check in capability_checks)
    assert all(recognizable_token not in check.detail for check in capability_checks)
    assert all("\x1b" not in check.detail for check in capability_checks)
    assert all("REDACTED" in check.detail for check in capability_checks)


def test_github_doctor_error_redacts_token_resolved_outside_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opaque_token = "opaque-ghes-auth-[should-not-render]-012345"
    recognizable_token = "sk-" + "a" * 36

    class EchoingGitHub:
        def __init__(self, _config: object, **_kwargs: object) -> None:
            self.token = opaque_token
            self._client = SimpleNamespace(event_hooks={})

        def __enter__(self) -> EchoingGitHub:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def authenticated_login(self) -> str:
            raise RuntimeError(f"server echoed {self.token} and {recognizable_token}")

    monkeypatch.setattr(doctor, "GitHubClient", EchoingGitHub)

    checks = doctor._github_checks(_config(), store=None)

    assert not checks[0].passed
    assert opaque_token not in checks[0].detail
    assert recognizable_token not in checks[0].detail
    assert "REDACTED" in checks[0].detail


def test_authentication_captures_classic_scopes_from_the_hardened_get() -> None:
    config = _config()
    github = GitHubClient(config.github, token="test-token")
    github._client.close()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/user"
        return httpx.Response(
            200,
            json={"login": "octocat"},
            headers={"X-OAuth-Scopes": "read:org, public_repo"},
            request=request,
        )

    github._client = httpx.Client(
        base_url="https://api.github.com",
        transport=httpx.MockTransport(handler),
    )
    try:
        login, scopes = doctor._authenticated_login_and_scopes(github)
    finally:
        github.close()

    assert login == "octocat"
    assert scopes == frozenset({"read:org", "public_repo"})


def test_auto_github_probe_uses_only_get_and_verifies_existing_fork_push_access() -> None:
    github = _FakeGitHub(
        {
            "fork": True,
            "parent": {"full_name": "example/project"},
            "permissions": {"push": True},
        }
    )

    check = doctor._github_permission_check(
        _auto_config(),
        github,  # type: ignore[arg-type]
        login="octocat",
        scopes=None,
    )

    assert check.passed
    assert check.warning
    assert "no write was sent" in check.detail
    assert github.requests == [("GET", "/repos/octocat/project", True)]


def test_auto_github_probe_fails_when_fork_creation_cannot_be_verified() -> None:
    github = _FakeGitHub(None)

    check = doctor._github_permission_check(
        _auto_config(),
        github,  # type: ignore[arg-type]
        login="octocat",
        scopes=None,
    )

    assert not check.passed
    assert "create the fork manually" in check.detail
    assert github.requests == [("GET", "/repos/octocat/project", True)]


def test_auto_github_probe_reports_inferred_classic_scope_without_creating_fork() -> None:
    github = _FakeGitHub(None)

    check = doctor._github_permission_check(
        _auto_config(),
        github,  # type: ignore[arg-type]
        login="octocat",
        scopes=frozenset({"public_repo"}),
    )

    assert check.passed
    assert check.warning
    assert "fork creation was intentionally not attempted" in check.detail
    assert github.requests == [("GET", "/repos/octocat/project", True)]


def test_review_required_warns_when_credential_has_unneeded_write_scope() -> None:
    check = doctor._github_permission_check(
        _config(),
        _FakeGitHub(None),  # type: ignore[arg-type]
        login="octocat",
        scopes=frozenset({"repo"}),
    )

    assert check.passed
    assert check.warning
    assert "not needed for preparation" in check.detail


def test_toolchain_parser_finds_pipeline_tools_modules_and_workspace_scripts() -> None:
    requirements = doctor._toolchain_requirements(
        [
            "MODE=test python -m pytest -q && ./scripts/check | ruff check .",
            "cd package && env CI=1 python -m unittest discover",
        ]
    )

    assert requirements.executables == ("python", "ruff")
    assert requirements.python_modules == (("python", "pytest"), ("python", "unittest"))
    assert requirements.workspace_entrypoints == ("./scripts/check",)
    assert requirements.command_count == 2


@pytest.mark.parametrize(
    "command, message",
    [
        ("$RUNNER test", "dynamic executable"),
        ("if pytest; then true; fi", "complex shell keyword"),
        ("python -m", "missing its module"),
        ("pytest\nruff check .", "multiline validation commands"),
    ],
)
def test_toolchain_parser_fails_closed_when_requirements_cannot_be_proved(
    command: str,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        doctor._toolchain_requirements([command])


def test_docker_toolchain_probe_matches_sandbox_isolation() -> None:
    config = _config(command="python -m pytest")
    requirements = doctor._toolchain_requirements(["python -m pytest && ruff check ."])

    command = doctor._docker_toolchain_probe(config, requirements)

    assert command[:3] == ["docker", "run", "--rm"]
    assert "--pull=never" in command
    assert "--network=none" in command
    assert "--read-only" in command
    assert "--cap-drop=ALL" in command
    assert "--security-opt=no-new-privileges" in command
    assert "--init" in command
    assert any(argument.startswith("--user=") for argument in command)
    assert config.sandbox.image in command
    assert "python -m pytest && ruff check ." not in command
    assert command[-4:] == ["python", "ruff", "python", "pytest"]


def test_local_toolchain_check_never_requires_docker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(backend="local")
    monkeypatch.setattr(doctor.shutil, "which", lambda tool: f"/bin/{tool}")
    monkeypatch.setattr(doctor.os.path, "isfile", lambda _path: True)
    monkeypatch.setattr(doctor, "_local_python_module_check", lambda *_args: None)
    monkeypatch.setattr(
        doctor,
        "_command_check",
        lambda *_args, **_kwargs: pytest.fail("local toolchain must not invoke Docker"),
    )

    check = doctor._offline_toolchain_check(config)

    assert check.passed
    assert check.warning
    assert "unsafe local host" in check.detail


def test_offline_toolchain_fails_when_no_commands_are_configured() -> None:
    check = doctor._offline_toolchain_check(AutocontributeConfig())

    assert not check.passed
    assert "no validation.required_commands" in check.detail
