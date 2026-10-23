from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar

import httpx
import pytest
from pydantic import JsonValue
from test_agent_loop import Submit, turn

import autocontribute.doctor as doctor
from autocontribute.config import AutocontributeConfig
from autocontribute.domain import RepositoryInfo
from autocontribute.exceptions import (
    CircuitBreakerTrigger,
    GitHubSafetyError,
    ModelRequestError,
    SandboxError,
)
from autocontribute.github import DirectoryEntry, GitHubClient
from autocontribute.pricing import ModelSpec
from autocontribute.store import RunStore
from autocontribute.transcript import Transcript, Turn

_TRIAGE: dict[str, JsonValue] = {
    "suitable": True,
    "reasons": ["deployment check"],
    "already_fixed": False,
    "needs_design": False,
    "difficulty": "small",
}


def _config() -> AutocontributeConfig:
    return AutocontributeConfig.model_validate({"github": {"repositories": ["example/project"]}})


class _ProbeProvider:
    """Answers each probe with ``answer`` and records what it was asked."""

    requests: ClassVar[list[tuple[str, Transcript, int, float]]] = []
    answer: ClassVar[Turn | Exception] = turn("openai", Submit(_TRIAGE, name="submit_triage"))

    def __init__(self, spec: ModelSpec, host_values: frozenset[str]) -> None:
        self.spec = spec

    def step(
        self, *, transcript: Transcript, max_output_tokens: int, timeout_seconds: float
    ) -> Turn:
        self.requests.append((self.spec.id, transcript, max_output_tokens, timeout_seconds))
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


@pytest.fixture
def probe(monkeypatch: pytest.MonkeyPatch) -> type[_ProbeProvider]:
    monkeypatch.setattr(_ProbeProvider, "requests", [])
    monkeypatch.setattr(doctor, "SubprocessTurnProvider", _ProbeProvider)
    return _ProbeProvider


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
    probe: type[_ProbeProvider],
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
    monkeypatch.setattr(doctor, "_docker_check", lambda: doctor.DoctorCheck("docker", True, "ok"))
    monkeypatch.setattr(
        doctor,
        "GitHubClient",
        lambda *_args, **_kwargs: pytest.fail("active breaker must block GitHub probes"),
    )

    checks = doctor.run_doctor(_config(), store=store)

    assert checks[0].name == "operational circuit breaker"
    assert not checks[0].passed
    assert "probes were not sent" in checks[0].detail
    assert probe.requests == []
    assert [check.name for check in checks if check.name.startswith("model")] == ["models"]
    assert not any(check.name.startswith("GitHub ") for check in checks)


def test_model_probe_sends_one_bounded_tool_call_per_distinct_model(
    monkeypatch: pytest.MonkeyPatch, probe: type[_ProbeProvider]
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-only-secret")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    checks = doctor._model_checks(_config(), probe=True)

    assert [check.name for check in checks] == [
        "models",
        "model gpt-5.6-sol (agent/critic)",
        "model gpt-5.6-terra (setup)",
        "model gpt-5.6-luna (triage)",
    ]
    assert checks[0].detail == (
        "agent gpt-5.6-sol, critic gpt-5.6-sol, setup gpt-5.6-terra, triage gpt-5.6-luna"
    )
    assert all(check.passed for check in checks)
    assert [model for model, *_ in probe.requests] == [
        "gpt-5.6-sol",
        "gpt-5.6-terra",
        "gpt-5.6-luna",
    ]
    for _model, transcript, max_output_tokens, timeout_seconds in probe.requests:
        assert (transcript.kind, transcript.effort) == ("triage", "low")
        assert (max_output_tokens, timeout_seconds) == (4_096, 60.0)
    assert "made a strict tool call" in checks[1].detail
    assert all("test-only-secret" not in check.detail for check in checks)


def test_model_checks_name_the_missing_key_without_probing(
    monkeypatch: pytest.MonkeyPatch, probe: type[_ProbeProvider]
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    checks = doctor._model_checks(_config(), probe=True)

    assert len(checks) == 1
    assert not checks[0].passed
    assert "ANTHROPIC_API_KEY or OPENAI_API_KEY" in checks[0].detail
    assert probe.requests == []


@pytest.mark.parametrize(
    ("answer", "detail"),
    [
        (turn("openai"), "answered without calling submit_triage"),
        (turn("openai", Submit({**_TRIAGE, "difficulty": "huge"}, name="submit_triage")), "huge"),
        (ModelRequestError("OpenAI Responses request failed (HTTP 401)"), "HTTP 401"),
    ],
)
def test_model_probe_fails_on_anything_but_a_valid_tool_call(
    monkeypatch: pytest.MonkeyPatch,
    probe: type[_ProbeProvider],
    answer: Turn | Exception,
    detail: str,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-only-secret")
    monkeypatch.setattr(probe, "answer", answer)

    checks = doctor._model_checks(
        AutocontributeConfig.model_validate(
            {"models": {"agent": "gpt-5.6-sol", "setup": "gpt-5.6-sol", "triage": "gpt-5.6-sol"}}
        ),
        probe=True,
    )

    assert [check.passed for check in checks] == [True, False]
    assert "failed the billed probe of at most 4,096 output tokens" in checks[1].detail
    assert detail in checks[1].detail


def test_doctor_redacts_configured_and_recognizable_credentials_from_provider_errors(
    monkeypatch: pytest.MonkeyPatch, probe: type[_ProbeProvider]
) -> None:
    opaque_key = "opaque-provider-key-[should-not-render]-012345"
    recognizable_token = "ghp_" + "a" * 36
    monkeypatch.setenv("OPENAI_API_KEY", opaque_key)
    monkeypatch.setattr(
        probe,
        "answer",
        ModelRequestError(f"upstream echoed {opaque_key} and {recognizable_token}\x1b[31m"),
    )
    monkeypatch.setattr(
        doctor,
        "_command_check",
        lambda name, *_args, **_kwargs: doctor.DoctorCheck(name, True, "available"),
    )
    monkeypatch.setattr(doctor, "_docker_check", lambda: doctor.DoctorCheck("docker", True, "ok"))
    monkeypatch.setattr(doctor, "_github_checks", lambda *_args, **_kwargs: [])

    checks = doctor.run_doctor(_config())
    probes = [check for check in checks if check.name.startswith("model ")]

    assert probes
    assert all(not check.passed for check in probes)
    assert all(opaque_key not in check.detail for check in probes)
    assert all(recognizable_token not in check.detail for check in probes)
    assert all("\x1b" not in check.detail for check in probes)
    assert all("REDACTED" in check.detail for check in probes)


def test_docker_check_needs_a_daemon_with_cgroup_v2_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(doctor, "detect_docker_daemon_mode", lambda: "rootless")
    ready = doctor._docker_check()

    def refuse() -> str:
        raise SandboxError("Docker daemon does not enforce required cgroup v2 resource controls")

    monkeypatch.setattr(doctor, "detect_docker_daemon_mode", refuse)
    refused = doctor._docker_check()
    monkeypatch.setattr(doctor.shutil, "which", lambda name: None)
    missing = doctor._docker_check()

    assert (ready.passed, ready.detail) == (
        True,
        "rootless daemon that enforces cgroup v2 memory, CPU and process limits",
    )
    assert not refused.passed and "cgroup v2" in refused.detail
    assert not missing.passed and "not found on PATH" in missing.detail


def test_doctor_github_safety_trigger_survives_reopening_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = RunStore(tmp_path / "state")
    monkeypatch.setattr(doctor, "GitHubClient", _RateLimitedDoctorGitHub)

    checks = doctor._github_checks(_config(), store=store)

    assert not checks[0].passed
    assert store.circuit_breaker_status().is_tripped
    reopened = RunStore(tmp_path / "state").circuit_breaker_status()
    assert reopened.is_tripped
    assert reopened.source == "github_api:rate_or_abuse_limit"
    assert reopened.trigger_hash == "a" * 64


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


def test_review_required_warns_when_credential_has_unneeded_write_scope() -> None:
    check = doctor._github_permission_check(scopes=frozenset({"repo"}))

    assert check.passed
    assert check.warning
    assert "not needed for preparation" in check.detail


class _PolicyDoctorGitHub:
    """Serves one CONTRIBUTING.md per repository at a fixed commit."""

    def __init__(self, guides: dict[str, str]) -> None:
        self.guides = guides

    def get_repository(self, full_name: str) -> RepositoryInfo:
        return RepositoryInfo(
            full_name=full_name,
            html_url=f"https://github.com/{full_name}",
            clone_url=f"https://github.com/{full_name}.git",
            default_branch="main",
            stars=1,
            archived=False,
            disabled=False,
            private=False,
            pushed_at=datetime.now(UTC),
            license_spdx="MIT",
        )

    def default_branch_sha(self, repository: str, branch: str) -> str:
        return "a" * 40

    def default_branch_sha_if_exists(self, repository: str) -> str | None:
        return None

    def list_directory(
        self, repository: str, path: str, *, ref: str
    ) -> list[DirectoryEntry] | None:
        if path or repository not in self.guides:
            return []
        return [DirectoryEntry(path="CONTRIBUTING.md", kind="file")]

    def get_file(
        self, repository: str, path: str, *, ref: str, max_bytes: int = 1_000_000
    ) -> str | None:
        return self.guides.get(repository)


def test_doctor_names_repositories_whose_ai_policy_rules_them_out(tmp_path: Path) -> None:
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project", "banning/project"]},
        }
    )
    github = _PolicyDoctorGitHub(
        {
            "example/project": "Run the tests before opening a pull request.",
            "banning/project": "Purely agentic contributions are not accepted.",
        }
    )

    check = doctor._ai_policy_check(config, github, RunStore(tmp_path / "state"))  # type: ignore[arg-type]
    clean = doctor._ai_policy_check(
        config.model_copy(
            update={
                "github": config.github.model_copy(update={"repositories": ["example/project"]})
            }
        ),
        github,  # type: ignore[arg-type]
        RunStore(tmp_path / "state"),
    )

    assert (check.name, check.passed, check.warning) == ("repository AI policies", True, True)
    assert check.detail.startswith(
        "discovery skips banning/project: the repository's AI policy bans agent-made "
        'contributions: "Purely agentic contributions are not accepted."'
    )
    assert "example/project" not in check.detail
    assert (clean.passed, clean.warning) == (True, False)
