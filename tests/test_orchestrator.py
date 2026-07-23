from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from autocontribute.config import AutocontributeConfig
from autocontribute.deployment import compute_deployment_fingerprint
from autocontribute.domain import (
    CommandResult,
    ContributionPlan,
    CriticReview,
    FileEdit,
    IssueCandidate,
    PatchProposal,
    RepositoryInfo,
    ReviewScores,
    RunStatus,
)
from autocontribute.exceptions import PolicyError, StateError
from autocontribute.orchestrator import Orchestrator, RunInvocationMode
from autocontribute.preparation import validate_preparation_fingerprint
from autocontribute.providers import ModelResult, ModelUsage
from autocontribute.redaction import MAX_ARTIFACT_CHARACTERS, MODEL_INPUT_REDACTION
from autocontribute.repository import RepositoryWorkspace
from autocontribute.sandbox import SandboxRunner
from autocontribute.store import CandidateRetryAuthorization, Lease, RunStore

REPRODUCTION_COMMAND = "python -c 'from app import value; assert value() == 2'"
TRUSTED_COMMAND = "python -m pytest"


def _git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-c", "commit.gpgsign=false", *arguments],
        cwd=repository,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def _source_repository(tmp_path: Path) -> tuple[Path, str]:
    source = tmp_path / "source"
    source.mkdir()
    _git(source, "init", "--quiet")
    _git(source, "config", "user.name", "Fixture")
    _git(source, "config", "user.email", "fixture@example.invalid")
    (source / "app.py").write_text("def value():\n    return 1\n", encoding="utf-8")
    (source / "CONTRIBUTING.md").write_text("Run python -m pytest.\n", encoding="utf-8")
    _git(source, "add", ".")
    _git(source, "commit", "--quiet", "-m", "fixture")
    return source, _git(source, "rev-parse", "HEAD")


def _issue(*, assigned: bool = False) -> IssueCandidate:
    now = datetime.now(UTC)
    return IssueCandidate(
        repository="example/project",
        number=42,
        title="Fix incorrect value at the documented boundary",
        body=(
            "Steps to reproduce the bug show that actual behavior returns 1. "
            "Expected behavior is to return 2. Please add a focused regression test. " * 4
        ),
        html_url="https://github.com/example/project/issues/42",
        state="open",
        author="maintainer",
        labels=["help wanted", "bug", "good first issue"],
        assignees=["other"] if assigned else [],
        comments=2,
        created_at=now - timedelta(days=10),
        updated_at=now - timedelta(days=1),
    )


def _repository(base_sha: str) -> RepositoryInfo:
    return RepositoryInfo(
        full_name="example/project",
        html_url="https://github.com/example/project",
        clone_url="https://github.com/example/project.git",
        default_branch="main",
        stars=50_000,
        archived=False,
        disabled=False,
        private=False,
        pushed_at=datetime.now(UTC),
        license_spdx="MIT",
    )


class FakeGitHub:
    def __init__(self, issue: IssueCandidate, repository: RepositoryInfo, sha: str) -> None:
        self.issue = issue
        self.repository = repository
        self.sha = sha

    def get_repository(self, full_name: str) -> RepositoryInfo:
        return self.repository

    def get_issue(self, repository: str, number: int) -> IssueCandidate:
        return self.issue

    def get_file(
        self,
        repository: str,
        path: str,
        *,
        ref: str,
        max_bytes: int = 1_000_000,
    ) -> str | None:
        del repository, ref, max_bytes
        return "Run the project tests." if path == "CONTRIBUTING.md" else None

    def search_competing_pull_requests(self, repository: str, issue_number: int) -> list[str]:
        return []

    def default_branch_sha(self, repository: str, branch: str) -> str:
        return self.sha

    def default_branch_sha_if_exists(self, repository: str) -> str | None:
        del repository
        return "b" * 40


class CountingGitHub(FakeGitHub):
    def __init__(self, issue: IssueCandidate, repository: RepositoryInfo, sha: str) -> None:
        super().__init__(issue, repository, sha)
        self.default_branch_calls = 0

    def default_branch_sha(self, repository: str, branch: str) -> str:
        self.default_branch_calls += 1
        return super().default_branch_sha(repository, branch)


class DiscoveryGitHub(CountingGitHub):
    def __init__(self, issue: IssueCandidate, repository: RepositoryInfo, sha: str) -> None:
        super().__init__(issue, repository, sha)
        self.search_calls = 0

    def search_issues(
        self,
        repository: str,
        *,
        labels: list[str],
        limit: int,
    ) -> list[IssueCandidate]:
        del repository, labels, limit
        self.search_calls += 1
        return [self.issue]


class FixedProvider:
    def __init__(self, output: Any, model: str, *, usage: ModelUsage | None = None) -> None:
        self.output = output
        self.model = model
        self.calls = 0
        self.requests: list[dict[str, object]] = []
        self.usage = usage or ModelUsage(input_tokens=10, output_tokens=5, total_tokens=15)

    def generate(self, **request: object) -> ModelResult[Any]:
        self.calls += 1
        self.requests.append(request)
        return ModelResult(
            output=self.output,
            response_id=f"response-{self.model}-{self.calls}",
            model=self.model,
            usage=self.usage,
        )


class SequenceProvider(FixedProvider):
    def __init__(self, outputs: list[Any], model: str) -> None:
        if not outputs:
            raise ValueError("SequenceProvider requires at least one output")
        self.outputs = outputs
        super().__init__(outputs[0], model)

    def generate(self, **request: object) -> ModelResult[Any]:
        if self.calls >= len(self.outputs):
            raise AssertionError("SequenceProvider received an unexpected extra call")
        self.output = self.outputs[self.calls]
        return super().generate(**request)


class PassingSandbox:
    def __init__(self, *, remaining_commands: int = 8) -> None:
        self.remaining_commands = remaining_commands
        self.baseline_commands: list[str] = []
        self.validation_batches: list[list[str]] = []

    def run_isolated(self, workspace: RepositoryWorkspace, command: str) -> CommandResult:
        self.baseline_commands.append(command)
        self.remaining_commands -= 1
        return CommandResult(
            command=command,
            exit_code=1,
            duration_seconds=0.1,
            stdout="",
            stderr="AssertionError",
        )

    def run_all_isolated(
        self,
        workspace: RepositoryWorkspace,
        commands: list[str],
        *,
        stop_on_failure: bool = True,
    ) -> list[CommandResult]:
        self.validation_batches.append(list(commands))
        self.remaining_commands -= len(commands)
        return [
            CommandResult(
                command=command,
                exit_code=0,
                duration_seconds=0.1,
                stdout="1 passed",
                stderr="",
            )
            for command in commands
        ]


class SequenceSandbox(PassingSandbox):
    """Return actionable failures for selected validation calls."""

    def __init__(
        self,
        *,
        remaining_commands: int = 10,
        failure_stderr: str = "AssertionError: expected the repaired boundary",
        failing_validation_calls: set[int] | None = None,
    ) -> None:
        super().__init__(remaining_commands=remaining_commands)
        self.validation_calls = 0
        self.failure_stderr = failure_stderr
        self.failing_validation_calls = frozenset(
            {1} if failing_validation_calls is None else failing_validation_calls
        )

    def run_all_isolated(
        self,
        workspace: RepositoryWorkspace,
        commands: list[str],
        *,
        stop_on_failure: bool = True,
    ) -> list[CommandResult]:
        del workspace
        self.validation_batches.append(list(commands))
        self.validation_calls += 1
        results: list[CommandResult] = []
        for command in commands:
            failed = self.validation_calls in self.failing_validation_calls and not results
            result = CommandResult(
                command=command,
                exit_code=1 if failed else 0,
                duration_seconds=0.1,
                stdout="" if failed else "1 passed",
                stderr=self.failure_stderr if failed else "",
            )
            results.append(result)
            self.remaining_commands -= 1
            if stop_on_failure and not result.passed:
                break
        return results


def _take_over_run_lease(orchestrator: Orchestrator, store: RunStore) -> Lease:
    guard = orchestrator._lease_guard
    assert guard is not None
    current = guard.lease
    takeover = store.acquire_lease(
        "autocontribute.run",
        "takeover-worker",
        ttl=timedelta(minutes=5),
        now=current.expires_at,
    )
    assert takeover is not None
    assert takeover.generation > current.generation
    return takeover


def _providers(
    *,
    validation_commands: list[str] | None = None,
    reproduction_command: str = REPRODUCTION_COMMAND,
) -> dict[str, FixedProvider]:
    commands = [TRUSTED_COMMAND] if validation_commands is None else validation_commands
    plan = ContributionPlan(
        decision="proceed",
        decision_reason="The requested bug fix is narrow and testable.",
        contribution_kind="bugfix",
        issue_understanding="Return the documented boundary value.",
        acceptance_criteria=["value() returns 2"],
        implementation_steps=["Correct the returned value", "Run the focused test"],
        files_to_read=["app.py"],
        reproduction_command=reproduction_command,
        validation_commands=commands,
        risks=["Behavior is intentionally changed only at the boundary"],
        maintainer_fit="Directly resolves the labeled issue.",
    )
    proposal = PatchProposal(
        summary="Return the documented value.",
        edits=[
            FileEdit(
                operation="replace",
                path="app.py",
                find="    return 1\n",
                replace="    return 2\n",
                content=None,
                rationale="Match the documented boundary behavior.",
            )
        ],
        validation_commands=commands,
        commit_message="Fix documented boundary value",
        pull_request_title="Fix documented boundary value",
        pull_request_body="Fixes #42. Corrects the boundary return value.",
        limitations=[],
    )
    review = CriticReview(
        verdict="approve",
        summary="The patch is narrow, clear, and validated.",
        scores=ReviewScores(
            correctness=96,
            issue_alignment=98,
            tests=95,
            repository_conventions=95,
            diff_hygiene=98,
            maintainer_clarity=95,
        ),
        blocking_findings=[],
        non_blocking_findings=[],
        issue_requirements_met=["value() returns 2"],
        issue_requirements_missing=[],
        test_evidence_assessment="The configured command passed.",
        maintainer_perspective="Ready for review.",
    )
    return {
        "scout": FixedProvider(plan, "gpt-5.6"),
        "builder": FixedProvider(proposal, "gpt-5.6"),
        "critic": FixedProvider(review, "gpt-5.6"),
    }


def test_full_prepare_pipeline_reaches_exact_approval_boundary(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    source, sha = _source_repository(tmp_path)
    original_clone = RepositoryWorkspace.clone

    def local_clone(
        cls: type[RepositoryWorkspace],
        clone_url: str,
        base_sha: str,
        destination: Path,
        **_: object,
    ) -> RepositoryWorkspace:
        return original_clone(str(source), base_sha, destination, allow_local_source=True)

    monkeypatch.setattr(RepositoryWorkspace, "clone", classmethod(local_clone))
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "validation": {"required_commands": {"example/project": [TRUSTED_COMMAND]}},
            "storage": {"path": tmp_path / "state"},
        }
    )
    store = RunStore(config.storage.path)
    github = FakeGitHub(_issue(), _repository(sha), sha)
    sandbox = PassingSandbox()

    with Orchestrator(
        config,
        store=store,
        github=github,  # type: ignore[arg-type]
        providers=_providers(),  # type: ignore[arg-type]
        sandbox=sandbox,  # type: ignore[arg-type]
    ) as orchestrator:
        manifest = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )

    assert manifest.status == RunStatus.READY_FOR_APPROVAL
    assert manifest.deployment_fingerprint == compute_deployment_fingerprint(config)
    assert manifest.quality and manifest.quality.ready
    assert manifest.model_calls == 3
    assert manifest.model_input_tokens == 30
    assert manifest.model_output_tokens == 15
    assert manifest.model_cost_usd == 0
    assert manifest.model_reservation is None
    assert sandbox.baseline_commands == [REPRODUCTION_COMMAND]
    assert sandbox.validation_batches == [[TRUSTED_COMMAND, REPRODUCTION_COMMAND]]
    patch = (store.artifact_dir(manifest.run_id) / "contribution.patch").read_text()
    assert "+    return 2" in patch
    assert "baseline-generated" not in patch
    persisted = store.get(manifest.run_id)
    assert persisted.preparation_fingerprint == manifest.preparation_fingerprint
    assert persisted.preparation_fingerprint is not None
    validate_preparation_fingerprint(persisted, diff=patch.encode("utf-8"))
    assert config.policy.ai_disclosure in manifest.proposal.pull_request_body  # type: ignore[union-attr]
    report = (store.artifact_dir(manifest.run_id) / "report.md").read_text(encoding="utf-8")
    assert "Recorded model cost: unknown" in report
    model_calls = json.loads(
        (store.artifact_dir(manifest.run_id) / "model-calls.json").read_text(encoding="utf-8")
    )
    assert all(call["cost_usd"] == "unknown" for call in model_calls)


def test_actionable_validation_failure_uses_the_single_repair_opportunity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, sha = _source_repository(tmp_path)
    original_clone = RepositoryWorkspace.clone

    def local_clone(
        cls: type[RepositoryWorkspace],
        clone_url: str,
        base_sha: str,
        destination: Path,
        **_: object,
    ) -> RepositoryWorkspace:
        return original_clone(str(source), base_sha, destination, allow_local_source=True)

    monkeypatch.setattr(RepositoryWorkspace, "clone", classmethod(local_clone))
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "sandbox": {"max_commands": 10},
            "validation": {"required_commands": {"example/project": [TRUSTED_COMMAND]}},
            "storage": {"path": tmp_path / "state"},
        }
    )
    providers = _providers()
    initial_proposal = providers["builder"].output
    assert isinstance(initial_proposal, PatchProposal)
    repair_only_command = "python -m unittest discover -s tests/repair -v"
    repair_proposal = initial_proposal.model_copy(
        update={
            "summary": "Repair the boundary implementation after validation.",
            "validation_commands": [repair_only_command],
            "edits": [
                FileEdit(
                    operation="replace",
                    path="app.py",
                    find="    return 2\n",
                    replace="    return 2  # repaired after validation\n",
                    content=None,
                    rationale="Resolve the actionable validation failure.",
                )
            ],
        }
    )
    providers["builder"] = SequenceProvider([initial_proposal, repair_proposal], "gpt-5.6")
    sandbox = SequenceSandbox()
    store = RunStore(config.storage.path)

    with Orchestrator(
        config,
        store=store,
        github=FakeGitHub(_issue(), _repository(sha), sha),  # type: ignore[arg-type]
        providers=providers,  # type: ignore[arg-type]
        sandbox=sandbox,  # type: ignore[arg-type]
    ) as orchestrator:
        manifest = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )

    expected_suite = [TRUSTED_COMMAND, REPRODUCTION_COMMAND]
    assert manifest.status == RunStatus.READY_FOR_APPROVAL
    assert manifest.model_calls == 4
    assert providers["builder"].calls == 2
    assert providers["critic"].calls == 1
    assert sandbox.validation_batches == [expected_suite, expected_suite]
    assert repair_only_command not in [
        command for batch in sandbox.validation_batches for command in batch
    ]
    assert manifest.proposal is not None
    assert manifest.proposal.validation_commands == [TRUSTED_COMMAND]
    repair_prompt = str(providers["builder"].requests[1]["prompt"])
    assert "AssertionError: expected the repaired boundary" in repair_prompt
    critic_prompt = str(providers["critic"].requests[0]["prompt"])
    assert "repaired after validation" in critic_prompt
    assert "1 passed" in critic_prompt
    events = store.events(manifest.run_id)
    assert [event["event_type"] for event in events].count("validation.repair.completed") == 1
    transitions = [
        json.loads(event["details"])
        for event in events
        if event["event_type"] == "run.transitioned"
    ]
    assert [(event["from"], event["to"]) for event in transitions[-5:]] == [
        ("implementing", "validating"),
        ("validating", "implementing"),
        ("implementing", "validating"),
        ("validating", "critiquing"),
        ("critiquing", "ready_for_approval"),
    ]


def test_actionable_validation_failure_skips_repair_when_suite_exceeds_remaining_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, sha = _source_repository(tmp_path)
    original_clone = RepositoryWorkspace.clone

    def local_clone(
        cls: type[RepositoryWorkspace],
        clone_url: str,
        base_sha: str,
        destination: Path,
        **_: object,
    ) -> RepositoryWorkspace:
        return original_clone(str(source), base_sha, destination, allow_local_source=True)

    monkeypatch.setattr(RepositoryWorkspace, "clone", classmethod(local_clone))
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "sandbox": {"max_commands": 3},
            "validation": {"required_commands": {"example/project": [TRUSTED_COMMAND]}},
            "storage": {"path": tmp_path / "state"},
        }
    )
    providers = _providers()
    sandbox = SequenceSandbox(remaining_commands=3)

    with Orchestrator(
        config,
        store=RunStore(config.storage.path),
        github=FakeGitHub(_issue(), _repository(sha), sha),  # type: ignore[arg-type]
        providers=providers,  # type: ignore[arg-type]
        sandbox=sandbox,  # type: ignore[arg-type]
    ) as orchestrator:
        manifest = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )

    assert manifest.status == RunStatus.REJECTED
    assert manifest.error is None
    assert manifest.model_calls == 3
    assert providers["builder"].calls == 1
    assert providers["critic"].calls == 1
    assert sandbox.validation_batches == [[TRUSTED_COMMAND, REPRODUCTION_COMMAND]]


def test_actionable_validation_failure_skips_repair_when_prompt_exceeds_model_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, sha = _source_repository(tmp_path)
    original_clone = RepositoryWorkspace.clone

    def local_clone(
        cls: type[RepositoryWorkspace],
        clone_url: str,
        base_sha: str,
        destination: Path,
        **_: object,
    ) -> RepositoryWorkspace:
        return original_clone(str(source), base_sha, destination, allow_local_source=True)

    monkeypatch.setattr(RepositoryWorkspace, "clone", classmethod(local_clone))
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "models": {"builder": {"max_input_tokens": 20_000}},
            "sandbox": {"max_commands": 10},
            "validation": {"required_commands": {"example/project": [TRUSTED_COMMAND]}},
            "storage": {"path": tmp_path / "state"},
        }
    )
    providers = _providers()
    sandbox = SequenceSandbox(
        failure_stderr="AssertionError: actionable but oversized\n" + ("x" * 30_000)
    )

    with Orchestrator(
        config,
        store=RunStore(config.storage.path),
        github=FakeGitHub(_issue(), _repository(sha), sha),  # type: ignore[arg-type]
        providers=providers,  # type: ignore[arg-type]
        sandbox=sandbox,  # type: ignore[arg-type]
    ) as orchestrator:
        manifest = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )

    assert manifest.status == RunStatus.REJECTED
    assert manifest.error is None
    assert manifest.model_calls == 3
    assert providers["builder"].calls == 1
    assert providers["critic"].calls == 1
    assert sandbox.validation_batches == [[TRUSTED_COMMAND, REPRODUCTION_COMMAND]]


def test_failed_validation_repair_is_not_retried(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, sha = _source_repository(tmp_path)
    original_clone = RepositoryWorkspace.clone

    def local_clone(
        cls: type[RepositoryWorkspace],
        clone_url: str,
        base_sha: str,
        destination: Path,
        **_: object,
    ) -> RepositoryWorkspace:
        return original_clone(str(source), base_sha, destination, allow_local_source=True)

    monkeypatch.setattr(RepositoryWorkspace, "clone", classmethod(local_clone))
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "sandbox": {"max_commands": 10},
            "validation": {"required_commands": {"example/project": [TRUSTED_COMMAND]}},
            "storage": {"path": tmp_path / "state"},
        }
    )
    providers = _providers()
    initial_proposal = providers["builder"].output
    assert isinstance(initial_proposal, PatchProposal)
    repair_proposal = initial_proposal.model_copy(
        update={
            "edits": [
                FileEdit(
                    operation="replace",
                    path="app.py",
                    find="    return 2\n",
                    replace="    return 2  # repaired after validation\n",
                    content=None,
                    rationale="Resolve the actionable validation failure.",
                )
            ]
        }
    )
    providers["builder"] = SequenceProvider([initial_proposal, repair_proposal], "gpt-5.6")
    sandbox = SequenceSandbox(failing_validation_calls={1, 2})

    with Orchestrator(
        config,
        store=RunStore(config.storage.path),
        github=FakeGitHub(_issue(), _repository(sha), sha),  # type: ignore[arg-type]
        providers=providers,  # type: ignore[arg-type]
        sandbox=sandbox,  # type: ignore[arg-type]
    ) as orchestrator:
        manifest = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )

    expected_suite = [TRUSTED_COMMAND, REPRODUCTION_COMMAND]
    assert manifest.status == RunStatus.REJECTED
    assert manifest.error is None
    assert manifest.model_calls == 4
    assert providers["builder"].calls == 2
    assert providers["critic"].calls == 1
    assert sandbox.validation_batches == [expected_suite, expected_suite]


def test_validation_repair_consumes_the_only_repair_opportunity_before_critic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, sha = _source_repository(tmp_path)
    original_clone = RepositoryWorkspace.clone

    def local_clone(
        cls: type[RepositoryWorkspace],
        clone_url: str,
        base_sha: str,
        destination: Path,
        **_: object,
    ) -> RepositoryWorkspace:
        return original_clone(str(source), base_sha, destination, allow_local_source=True)

    monkeypatch.setattr(RepositoryWorkspace, "clone", classmethod(local_clone))
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "sandbox": {"max_commands": 10},
            "validation": {"required_commands": {"example/project": [TRUSTED_COMMAND]}},
            "storage": {"path": tmp_path / "state"},
        }
    )
    providers = _providers()
    initial_proposal = providers["builder"].output
    approved_review = providers["critic"].output
    assert isinstance(initial_proposal, PatchProposal)
    assert isinstance(approved_review, CriticReview)
    repair_proposal = initial_proposal.model_copy(
        update={
            "edits": [
                FileEdit(
                    operation="replace",
                    path="app.py",
                    find="    return 2\n",
                    replace="    return 2  # repaired after validation\n",
                    content=None,
                    rationale="Resolve the actionable validation failure.",
                )
            ]
        }
    )
    rejecting_review = approved_review.model_copy(
        update={
            "verdict": "reject",
            "summary": "The repaired patch still has a blocker.",
            "blocking_findings": ["The final implementation remains unclear."],
            "issue_requirements_missing": ["Clear final implementation"],
        }
    )
    providers["builder"] = SequenceProvider([initial_proposal, repair_proposal], "gpt-5.6")
    providers["critic"] = SequenceProvider([rejecting_review], "gpt-5.6")
    sandbox = SequenceSandbox()

    with Orchestrator(
        config,
        store=RunStore(config.storage.path),
        github=FakeGitHub(_issue(), _repository(sha), sha),  # type: ignore[arg-type]
        providers=providers,  # type: ignore[arg-type]
        sandbox=sandbox,  # type: ignore[arg-type]
    ) as orchestrator:
        manifest = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )

    expected_suite = [TRUSTED_COMMAND, REPRODUCTION_COMMAND]
    assert manifest.status == RunStatus.REJECTED
    assert manifest.error is None
    assert manifest.model_calls == 4
    assert providers["builder"].calls == 2
    assert providers["critic"].calls == 1
    assert sandbox.validation_batches == [expected_suite, expected_suite]


def test_infrastructure_validation_failure_is_not_sent_to_builder_for_repair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, sha = _source_repository(tmp_path)
    original_clone = RepositoryWorkspace.clone

    def local_clone(
        cls: type[RepositoryWorkspace],
        clone_url: str,
        base_sha: str,
        destination: Path,
        **_: object,
    ) -> RepositoryWorkspace:
        return original_clone(str(source), base_sha, destination, allow_local_source=True)

    monkeypatch.setattr(RepositoryWorkspace, "clone", classmethod(local_clone))
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "sandbox": {"max_commands": 10},
            "validation": {"required_commands": {"example/project": [TRUSTED_COMMAND]}},
            "storage": {"path": tmp_path / "state"},
        }
    )
    providers = _providers()
    failure_stderr = (
        "AssertionError: visible but infrastructure-tainted failure\n"
        + ("verbose validation output\n" * 5_000)
        + ("ImportError: No module named fixture_dependency")
    )
    assert len(failure_stderr) > 100_000
    sandbox = SequenceSandbox(failure_stderr=failure_stderr)

    with Orchestrator(
        config,
        store=RunStore(config.storage.path),
        github=FakeGitHub(_issue(), _repository(sha), sha),  # type: ignore[arg-type]
        providers=providers,  # type: ignore[arg-type]
        sandbox=sandbox,  # type: ignore[arg-type]
    ) as orchestrator:
        manifest = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )

    assert manifest.status == RunStatus.REJECTED
    assert manifest.error is None
    assert manifest.model_calls == 3
    assert providers["builder"].calls == 1
    assert providers["critic"].calls == 1
    assert sandbox.validation_batches == [[TRUSTED_COMMAND, REPRODUCTION_COMMAND]]


def test_truncated_model_visible_failure_is_not_sent_to_builder_for_repair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, sha = _source_repository(tmp_path)
    original_clone = RepositoryWorkspace.clone

    def local_clone(
        cls: type[RepositoryWorkspace],
        clone_url: str,
        base_sha: str,
        destination: Path,
        **_: object,
    ) -> RepositoryWorkspace:
        return original_clone(str(source), base_sha, destination, allow_local_source=True)

    monkeypatch.setattr(RepositoryWorkspace, "clone", classmethod(local_clone))
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "sandbox": {"max_commands": 10},
            "validation": {"required_commands": {"example/project": [TRUSTED_COMMAND]}},
            "storage": {"path": tmp_path / "state"},
        }
    )
    providers = _providers()
    failure_stderr = "AssertionError: visible\n" + ("x" * (MAX_ARTIFACT_CHARACTERS + 100))
    sandbox = SequenceSandbox(failure_stderr=failure_stderr)

    with Orchestrator(
        config,
        store=RunStore(config.storage.path),
        github=FakeGitHub(_issue(), _repository(sha), sha),  # type: ignore[arg-type]
        providers=providers,  # type: ignore[arg-type]
        sandbox=sandbox,  # type: ignore[arg-type]
    ) as orchestrator:
        manifest = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )

    assert manifest.status == RunStatus.REJECTED
    assert manifest.error is None
    assert manifest.model_calls == 3
    assert providers["builder"].calls == 1
    assert providers["critic"].calls == 1
    assert sandbox.validation_batches == [[TRUSTED_COMMAND, REPRODUCTION_COMMAND]]


def test_redaction_created_failure_signature_cannot_authorize_repair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, sha = _source_repository(tmp_path)
    original_clone = RepositoryWorkspace.clone

    def local_clone(
        cls: type[RepositoryWorkspace],
        clone_url: str,
        base_sha: str,
        destination: Path,
        **_: object,
    ) -> RepositoryWorkspace:
        return original_clone(str(source), base_sha, destination, allow_local_source=True)

    monkeypatch.setattr(RepositoryWorkspace, "clone", classmethod(local_clone))
    secret = "AssertionError-secret-value-472839"
    monkeypatch.setenv("ASSERTIONERROR", secret)
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "models": {"builder": {"api_key_env": "ASSERTIONERROR"}},
            "sandbox": {"max_commands": 10},
            "validation": {"required_commands": {"example/project": [TRUSTED_COMMAND]}},
            "storage": {"path": tmp_path / "state"},
        }
    )
    providers = _providers()
    sandbox = SequenceSandbox(failure_stderr=secret)

    with Orchestrator(
        config,
        store=RunStore(config.storage.path),
        github=FakeGitHub(_issue(), _repository(sha), sha),  # type: ignore[arg-type]
        providers=providers,  # type: ignore[arg-type]
        sandbox=sandbox,  # type: ignore[arg-type]
    ) as orchestrator:
        manifest = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )

    assert manifest.status == RunStatus.REJECTED
    assert manifest.error is None
    assert manifest.model_calls == 3
    assert providers["builder"].calls == 1
    assert providers["critic"].calls == 1
    assert sandbox.validation_batches == [[TRUSTED_COMMAND, REPRODUCTION_COMMAND]]
    critic_prompt = str(providers["critic"].requests[0]["prompt"])
    assert secret not in critic_prompt
    assert MODEL_INPUT_REDACTION in critic_prompt


def test_critic_repair_is_skipped_when_exact_validation_suite_exceeds_remaining_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, sha = _source_repository(tmp_path)
    original_clone = RepositoryWorkspace.clone

    def local_clone(
        cls: type[RepositoryWorkspace],
        clone_url: str,
        base_sha: str,
        destination: Path,
        **_: object,
    ) -> RepositoryWorkspace:
        return original_clone(str(source), base_sha, destination, allow_local_source=True)

    monkeypatch.setattr(RepositoryWorkspace, "clone", classmethod(local_clone))
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "sandbox": {"max_commands": 3},
            "validation": {"required_commands": {"example/project": [TRUSTED_COMMAND]}},
            "storage": {"path": tmp_path / "state"},
        }
    )
    providers = _providers()
    approved_review = providers["critic"].output
    assert isinstance(approved_review, CriticReview)
    providers["critic"].output = approved_review.model_copy(
        update={
            "verdict": "reject",
            "summary": "The patch still has one blocking concern.",
            "blocking_findings": ["Add a clarifying implementation comment."],
            "issue_requirements_missing": ["Clarifying comment"],
        }
    )
    sandbox = PassingSandbox(remaining_commands=3)

    with Orchestrator(
        config,
        store=RunStore(config.storage.path),
        github=FakeGitHub(_issue(), _repository(sha), sha),  # type: ignore[arg-type]
        providers=providers,  # type: ignore[arg-type]
        sandbox=sandbox,  # type: ignore[arg-type]
    ) as orchestrator:
        manifest = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )

    assert manifest.status == RunStatus.REJECTED
    assert manifest.error is None
    assert manifest.model_calls == 3
    assert providers["builder"].calls == 1
    assert providers["critic"].calls == 1
    assert sandbox.remaining_commands == 0
    assert sandbox.validation_batches == [[TRUSTED_COMMAND, REPRODUCTION_COMMAND]]


def test_critic_repair_reuses_exact_validation_suite_when_it_fits_remaining_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, sha = _source_repository(tmp_path)
    original_clone = RepositoryWorkspace.clone

    def local_clone(
        cls: type[RepositoryWorkspace],
        clone_url: str,
        base_sha: str,
        destination: Path,
        **_: object,
    ) -> RepositoryWorkspace:
        return original_clone(str(source), base_sha, destination, allow_local_source=True)

    monkeypatch.setattr(RepositoryWorkspace, "clone", classmethod(local_clone))
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "sandbox": {"max_commands": 5},
            "validation": {"required_commands": {"example/project": [TRUSTED_COMMAND]}},
            "storage": {"path": tmp_path / "state"},
        }
    )
    providers = _providers()
    initial_proposal = providers["builder"].output
    approved_review = providers["critic"].output
    assert isinstance(initial_proposal, PatchProposal)
    assert isinstance(approved_review, CriticReview)
    repair_proposal = initial_proposal.model_copy(
        update={
            "summary": "Return the documented value with the requested clarification.",
            "validation_commands": [
                TRUSTED_COMMAND,
                "python -m unittest discover -s tests/repair -v",
            ],
            "edits": [
                FileEdit(
                    operation="replace",
                    path="app.py",
                    find="    return 2\n",
                    replace="    return 2  # documented boundary\n",
                    content=None,
                    rationale="Resolve the independent review blocker.",
                )
            ],
        }
    )
    rejecting_review = approved_review.model_copy(
        update={
            "verdict": "reject",
            "summary": "The patch still has one blocking concern.",
            "blocking_findings": ["Add a clarifying implementation comment."],
            "issue_requirements_missing": ["Clarifying comment"],
        }
    )
    providers["builder"] = SequenceProvider(
        [initial_proposal, repair_proposal],
        "gpt-5.6",
    )
    providers["critic"] = SequenceProvider(
        [rejecting_review, approved_review],
        "gpt-5.6",
    )
    sandbox = PassingSandbox(remaining_commands=5)

    with Orchestrator(
        config,
        store=RunStore(config.storage.path),
        github=FakeGitHub(_issue(), _repository(sha), sha),  # type: ignore[arg-type]
        providers=providers,  # type: ignore[arg-type]
        sandbox=sandbox,  # type: ignore[arg-type]
    ) as orchestrator:
        manifest = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )

    assert manifest.status == RunStatus.READY_FOR_APPROVAL
    assert manifest.model_calls == 5
    assert providers["builder"].calls == 2
    assert providers["critic"].calls == 2
    assert sandbox.remaining_commands == 0
    assert manifest.proposal is not None
    assert manifest.proposal.validation_commands == [TRUSTED_COMMAND]
    assert sandbox.validation_batches == [
        [TRUSTED_COMMAND, REPRODUCTION_COMMAND],
        [TRUSTED_COMMAND, REPRODUCTION_COMMAND],
    ]


def test_clone_uses_the_exact_sha_used_for_repository_policy_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sha = "a" * 40
    policy_reads: list[tuple[str, str]] = []
    clone_refs: list[str] = []

    class TrackingGitHub(FakeGitHub):
        def get_file(
            self,
            repository: str,
            path: str,
            *,
            ref: str,
            max_bytes: int = 1_000_000,
        ) -> str | None:
            policy_reads.append((repository, ref))
            return super().get_file(
                repository,
                path,
                ref=ref,
                max_bytes=max_bytes,
            )

    def stop_after_clone_ref_is_captured(
        cls: type[RepositoryWorkspace],
        clone_url: str,
        base_sha: str,
        destination: Path,
        **_: object,
    ) -> RepositoryWorkspace:
        del cls, clone_url, destination
        clone_refs.append(base_sha)
        raise RuntimeError("stop after immutable clone ref was captured")

    monkeypatch.setattr(
        RepositoryWorkspace,
        "clone",
        classmethod(stop_after_clone_ref_is_captured),
    )
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "validation": {"required_commands": {"example/project": [TRUSTED_COMMAND]}},
            "storage": {"path": tmp_path / "state"},
        }
    )
    with Orchestrator(
        config,
        store=RunStore(config.storage.path),
        github=TrackingGitHub(_issue(), _repository(sha), sha),  # type: ignore[arg-type]
        providers=_providers(),  # type: ignore[arg-type]
        sandbox=PassingSandbox(),  # type: ignore[arg-type]
    ) as orchestrator:
        manifest = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )

    repository_policy_refs = {
        ref for repository, ref in policy_reads if repository == "example/project"
    }
    assert manifest.status == RunStatus.FAILED
    assert clone_refs == [sha]
    assert repository_policy_refs == {sha}


def test_secret_finding_trips_global_breaker_without_retaining_value(
    tmp_path: Path,
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    source, sha = _source_repository(tmp_path)
    original_clone = RepositoryWorkspace.clone

    def local_clone(
        cls: type[RepositoryWorkspace],
        clone_url: str,
        base_sha: str,
        destination: Path,
        **_: object,
    ) -> RepositoryWorkspace:
        return original_clone(str(source), base_sha, destination, allow_local_source=True)

    monkeypatch.setattr(RepositoryWorkspace, "clone", classmethod(local_clone))
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "validation": {"required_commands": {"example/project": [TRUSTED_COMMAND]}},
            "storage": {"path": tmp_path / "state"},
        }
    )
    store = RunStore(config.storage.path)
    providers = _providers()
    secret = "ghp_" + "A" * 36
    proposal = providers["builder"].output
    assert isinstance(proposal, PatchProposal)
    providers["builder"].output = proposal.model_copy(
        update={
            "edits": [
                FileEdit(
                    operation="replace",
                    path="app.py",
                    find="    return 1\n",
                    replace=f"    return 2  # {secret}\n",
                    content=None,
                    rationale="Match the documented boundary behavior.",
                )
            ]
        }
    )

    with Orchestrator(
        config,
        store=store,
        github=FakeGitHub(_issue(), _repository(sha), sha),  # type: ignore[arg-type]
        providers=providers,  # type: ignore[arg-type]
        sandbox=PassingSandbox(),  # type: ignore[arg-type]
    ) as orchestrator:
        manifest = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )

    assert manifest.status == RunStatus.FAILED
    assert manifest.proposal is None
    assert not store.workspace_dir(manifest.run_id).joinpath("repository").exists()
    breaker = store.circuit_breaker_status()
    assert breaker.is_tripped
    assert breaker.source == f"secret_scanner:{manifest.run_id}"
    assert secret not in (breaker.reason or "")
    for path in config.storage.path.rglob("*"):
        if path.is_file():
            assert secret.encode() not in path.read_bytes()

    with pytest.raises(StateError, match="Circuit breaker is tripped"):
        Orchestrator(
            config,
            store=store,
            github=FakeGitHub(_issue(), _repository(sha), sha),  # type: ignore[arg-type]
            providers=_providers(),  # type: ignore[arg-type]
            sandbox=PassingSandbox(),  # type: ignore[arg-type]
        ).run(issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL)


def test_breaker_blocks_before_github_or_model_work(tmp_path: Path) -> None:
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "validation": {"required_commands": {"example/project": [TRUSTED_COMMAND]}},
            "storage": {"path": tmp_path / "state"},
        }
    )
    store = RunStore(config.storage.path)
    store.trip_circuit_breaker(
        source="test-signal",
        reason="maintainer requested a stop",
        trigger_hash="test-trigger",
    )
    providers = _providers()

    class NoGitHubWork:
        def __getattr__(self, name: str) -> object:
            raise AssertionError(f"unexpected GitHub access: {name}")

    with (
        Orchestrator(
            config,
            store=store,
            github=NoGitHubWork(),  # type: ignore[arg-type]
            providers=providers,  # type: ignore[arg-type]
            sandbox=PassingSandbox(),  # type: ignore[arg-type]
        ) as orchestrator,
        pytest.raises(StateError, match="Circuit breaker is tripped"),
    ):
        orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )

    assert store.list() == []
    assert all(provider.calls == 0 for provider in providers.values())


@pytest.mark.parametrize(
    "invocation_mode", [RunInvocationMode.AUTOMATIC, RunInvocationMode.SCHEDULED]
)
@pytest.mark.parametrize("with_retry_authorization", [False, True])
def test_nonmanual_invocation_cannot_pin_or_authorize_an_issue_before_external_work(
    tmp_path: Path,
    invocation_mode: RunInvocationMode,
    with_retry_authorization: bool,
) -> None:
    config = AutocontributeConfig.model_validate({"storage": {"path": tmp_path / "state"}})
    store = RunStore(config.storage.path)
    providers = _providers()

    class NoGitHubWork:
        def __getattr__(self, name: str) -> object:
            raise AssertionError(f"unexpected GitHub access: {name}")

    authorization = (
        CandidateRetryAuthorization(
            actor="release-operator",
            reason="Reviewed the prior terminal outcome.",
        )
        if with_retry_authorization
        else None
    )
    with (
        Orchestrator(
            config,
            store=store,
            github=NoGitHubWork(),  # type: ignore[arg-type]
            providers=providers,  # type: ignore[arg-type]
            sandbox=PassingSandbox(),  # type: ignore[arg-type]
        ) as orchestrator,
        pytest.raises(ValueError, match="explicit issue references require manual invocation mode"),
    ):
        orchestrator.run(
            issue_reference="example/project#42",
            invocation_mode=invocation_mode,
            retry_authorization=authorization,
        )

    assert store.list() == []
    assert all(provider.calls == 0 for provider in providers.values())


@pytest.mark.parametrize(
    "invocation_mode", [RunInvocationMode.AUTOMATIC, RunInvocationMode.SCHEDULED]
)
def test_nonmanual_invocation_cannot_supply_retry_authorization_without_an_issue(
    tmp_path: Path,
    invocation_mode: RunInvocationMode,
) -> None:
    config = AutocontributeConfig.model_validate({"storage": {"path": tmp_path / "state"}})
    store = RunStore(config.storage.path)
    providers = _providers()

    with (
        Orchestrator(
            config,
            store=store,
            github=object(),  # type: ignore[arg-type]
            providers=providers,  # type: ignore[arg-type]
            sandbox=PassingSandbox(),  # type: ignore[arg-type]
        ) as orchestrator,
        pytest.raises(ValueError, match="retry authorization requires an explicit issue reference"),
    ):
        orchestrator.run(
            invocation_mode=invocation_mode,
            retry_authorization=CandidateRetryAuthorization(
                actor="release-operator",
                reason="Reviewed the prior terminal outcome.",
            ),
        )

    assert store.list() == []
    assert all(provider.calls == 0 for provider in providers.values())


def test_run_recovers_stale_work_and_releases_singleton_lease(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    now = datetime.now(UTC)
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "validation": {"required_commands": {"example/project": [TRUSTED_COMMAND]}},
            "storage": {"path": tmp_path / "state"},
        }
    )
    store = RunStore(config.storage.path)
    monkeypatch.setattr("autocontribute.store.utc_now", lambda: now - timedelta(hours=3))
    abandoned = store.create_run()
    store.transition(abandoned, RunStatus.DISCOVERING, reason="worker started")
    monkeypatch.setattr("autocontribute.store.utc_now", lambda: now)
    providers = _providers()

    with Orchestrator(
        config,
        store=store,
        github=FakeGitHub(_issue(assigned=True), _repository("a" * 40), "a" * 40),  # type: ignore[arg-type]
        providers=providers,  # type: ignore[arg-type]
        sandbox=PassingSandbox(),  # type: ignore[arg-type]
    ) as orchestrator:
        current = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )

    recovered = store.get(abandoned.run_id)
    assert recovered.status == RunStatus.FAILED
    assert "previous worker stopped" in (recovered.error or "")
    assert current.status == RunStatus.SKIPPED
    assert all(provider.calls == 0 for provider in providers.values())
    lease = store.acquire_lease("autocontribute.run", "next-worker", ttl=timedelta(minutes=1))
    assert lease is not None
    assert store.release_lease("autocontribute.run", "next-worker", lease.generation)


@pytest.mark.parametrize("provider_fails", [False, True])
def test_run_lease_takeover_during_model_outcome_preserves_ambiguous_reservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    provider_fails: bool,
) -> None:
    source, sha = _source_repository(tmp_path)
    original_clone = RepositoryWorkspace.clone

    def local_clone(
        cls: type[RepositoryWorkspace],
        clone_url: str,
        base_sha: str,
        destination: Path,
        **_: object,
    ) -> RepositoryWorkspace:
        return original_clone(str(source), base_sha, destination, allow_local_source=True)

    class TakingProvider(FixedProvider):
        orchestrator: Orchestrator | None = None
        takeover: Lease | None = None

        def generate(self, **request: object) -> ModelResult[Any]:
            result = super().generate(**request)
            assert self.orchestrator is not None
            self.takeover = _take_over_run_lease(self.orchestrator, store)
            if provider_fails:
                raise RuntimeError("provider failed after lease takeover")
            return result

    monkeypatch.setattr(RepositoryWorkspace, "clone", classmethod(local_clone))
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "validation": {"required_commands": {"example/project": [TRUSTED_COMMAND]}},
            "storage": {"path": tmp_path / "state"},
        }
    )
    store = RunStore(config.storage.path)
    provider = TakingProvider(_providers()["scout"].output, "taking-scout")
    providers = _providers()
    providers["scout"] = provider

    with Orchestrator(
        config,
        store=store,
        github=FakeGitHub(_issue(), _repository(sha), sha),  # type: ignore[arg-type]
        providers=providers,  # type: ignore[arg-type]
        sandbox=PassingSandbox(),  # type: ignore[arg-type]
    ) as orchestrator:
        provider.orchestrator = orchestrator
        with pytest.raises(StateError, match="ownership was lost"):
            orchestrator.run(
                issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
            )

    assert provider.takeover is not None
    assert store.release_lease(
        provider.takeover.name,
        provider.takeover.owner,
        provider.takeover.generation,
    )
    [persisted] = store.list()
    assert persisted.status == RunStatus.PLANNING
    assert persisted.error is None
    assert persisted.model_calls == 1
    assert persisted.model_seconds == 0
    assert persisted.model_reservation is not None
    event_types = [event["event_type"] for event in store.events(persisted.run_id)]
    assert "model.call.started" in event_types
    assert "model.call.completed" not in event_types
    assert "model.call.failed" not in event_types
    run_artifacts = store.runs_dir / persisted.run_id
    assert not (run_artifacts / "validation.json").exists()
    assert not (run_artifacts / "model-calls.json").exists()
    assert not (run_artifacts / "report.md").exists()


def test_run_lease_takeover_during_github_read_stops_before_workspace_or_failure_write(
    tmp_path: Path,
) -> None:
    sha = "a" * 40
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "validation": {"required_commands": {"example/project": [TRUSTED_COMMAND]}},
            "storage": {"path": tmp_path / "state"},
        }
    )
    store = RunStore(config.storage.path)

    class TakingGitHub(FakeGitHub):
        orchestrator: Orchestrator | None = None
        takeover: Lease | None = None

        def default_branch_sha(self, repository: str, branch: str) -> str:
            result = super().default_branch_sha(repository, branch)
            assert self.orchestrator is not None
            self.takeover = _take_over_run_lease(self.orchestrator, store)
            return result

    github = TakingGitHub(_issue(), _repository(sha), sha)
    providers = _providers()
    with Orchestrator(
        config,
        store=store,
        github=github,  # type: ignore[arg-type]
        providers=providers,  # type: ignore[arg-type]
        sandbox=PassingSandbox(),  # type: ignore[arg-type]
    ) as orchestrator:
        github.orchestrator = orchestrator
        with pytest.raises(StateError, match="ownership was lost"):
            orchestrator.run(
                issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
            )

    assert github.takeover is not None
    assert store.release_lease(
        github.takeover.name,
        github.takeover.owner,
        github.takeover.generation,
    )
    [persisted] = store.list()
    assert persisted.status == RunStatus.DISCOVERING
    assert persisted.error is None
    assert persisted.base_sha is None
    assert all(provider.calls == 0 for provider in providers.values())
    assert not (store.workspaces_dir / persisted.run_id).exists()
    run_artifacts = store.runs_dir / persisted.run_id
    assert not (run_artifacts / "validation.json").exists()
    assert not (run_artifacts / "model-calls.json").exists()
    assert not (run_artifacts / "report.md").exists()


def test_breaker_trip_during_model_failure_still_records_safe_failure_bookkeeping(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, sha = _source_repository(tmp_path)
    original_clone = RepositoryWorkspace.clone

    def local_clone(
        cls: type[RepositoryWorkspace],
        clone_url: str,
        base_sha: str,
        destination: Path,
        **_: object,
    ) -> RepositoryWorkspace:
        return original_clone(str(source), base_sha, destination, allow_local_source=True)

    monkeypatch.setattr(RepositoryWorkspace, "clone", classmethod(local_clone))
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "validation": {"required_commands": {"example/project": [TRUSTED_COMMAND]}},
            "storage": {"path": tmp_path / "state"},
        }
    )
    store = RunStore(config.storage.path)

    class BreakerProvider:
        def generate(self, **_: object) -> ModelResult[Any]:
            store.trip_circuit_breaker(
                source="test:model-call",
                reason="stop while the provider call is in flight",
                trigger_hash="model-call-stop",
            )
            raise RuntimeError("provider failed after safety stop")

    providers = _providers()
    providers["scout"] = BreakerProvider()  # type: ignore[assignment]
    with Orchestrator(
        config,
        store=store,
        github=FakeGitHub(_issue(), _repository(sha), sha),  # type: ignore[arg-type]
        providers=providers,  # type: ignore[arg-type]
        sandbox=PassingSandbox(),  # type: ignore[arg-type]
    ) as orchestrator:
        manifest = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )

    assert manifest.status == RunStatus.FAILED
    assert manifest.model_reservation is not None
    event_types = [event["event_type"] for event in store.events(manifest.run_id)]
    assert "model.call.started" in event_types
    assert "model.call.failed" in event_types
    assert "run.transitioned" in event_types
    run_artifacts = store.runs_dir / manifest.run_id
    assert (run_artifacts / "validation.json").is_file()
    assert (run_artifacts / "model-calls.json").is_file()
    assert (run_artifacts / "report.md").is_file()


def test_planner_and_critic_receive_callers_tests_and_exact_publication_text(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    source, _ = _source_repository(tmp_path)
    (source / "caller.py").write_text(
        "from app import value\n\nRESULT = value()\n",
        encoding="utf-8",
    )
    (source / "tests").mkdir()
    (source / "tests" / "test_app.py").write_text(
        "from app import value\n\ndef test_value():\n    assert value() == 1\n",
        encoding="utf-8",
    )
    _git(source, "add", ".")
    _git(source, "commit", "--quiet", "-m", "add references")
    sha = _git(source, "rev-parse", "HEAD")
    original_clone = RepositoryWorkspace.clone

    def local_clone(
        cls: type[RepositoryWorkspace],
        clone_url: str,
        base_sha: str,
        destination: Path,
        **_: object,
    ) -> RepositoryWorkspace:
        return original_clone(str(source), base_sha, destination, allow_local_source=True)

    monkeypatch.setattr(RepositoryWorkspace, "clone", classmethod(local_clone))
    issue = _issue()
    issue.title = "Fix the documented `value()` boundary"
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "validation": {"required_commands": {"example/project": [TRUSTED_COMMAND]}},
            "storage": {"path": tmp_path / "state"},
        }
    )
    providers = _providers()

    with Orchestrator(
        config,
        store=RunStore(config.storage.path),
        github=FakeGitHub(issue, _repository(sha), sha),  # type: ignore[arg-type]
        providers=providers,  # type: ignore[arg-type]
        sandbox=PassingSandbox(),  # type: ignore[arg-type]
    ) as orchestrator:
        manifest = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )

    assert manifest.status == RunStatus.READY_FOR_APPROVAL
    planner_prompt = str(providers["scout"].requests[0]["prompt"])
    assert "literal_repository_references" in planner_prompt
    assert "caller.py" in planner_prompt
    assert "tests/test_app.py" in planner_prompt
    critic_prompt = str(providers["critic"].requests[0]["prompt"])
    assert "affected_source_context" in critic_prompt
    assert "caller.py" in critic_prompt
    assert "tests/test_app.py" in critic_prompt
    assert "proposed_publication_text" in critic_prompt
    assert "Fix documented boundary value" in critic_prompt
    assert "Fixes #42. Corrects the boundary return value." in critic_prompt
    assert config.policy.ai_disclosure in critic_prompt


def test_repository_pull_request_template_is_a_hard_pre_review_gate(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    source, _ = _source_repository(tmp_path)
    template_dir = source / ".github"
    template_dir.mkdir()
    (template_dir / "pull_request_template.md").write_text(
        "## Summary\n\n<!-- Describe the change. -->\n\n## Testing\n\n- [ ] Tests pass\n",
        encoding="utf-8",
    )
    _git(source, "add", ".")
    _git(source, "commit", "--quiet", "-m", "add pull request template")
    sha = _git(source, "rev-parse", "HEAD")
    original_clone = RepositoryWorkspace.clone

    def local_clone(
        cls: type[RepositoryWorkspace],
        clone_url: str,
        base_sha: str,
        destination: Path,
        **_: object,
    ) -> RepositoryWorkspace:
        return original_clone(str(source), base_sha, destination, allow_local_source=True)

    monkeypatch.setattr(RepositoryWorkspace, "clone", classmethod(local_clone))
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "validation": {"required_commands": {"example/project": [TRUSTED_COMMAND]}},
            "storage": {"path": tmp_path / "state"},
        }
    )
    providers = _providers()

    with Orchestrator(
        config,
        store=RunStore(config.storage.path),
        github=FakeGitHub(_issue(), _repository(sha), sha),  # type: ignore[arg-type]
        providers=providers,  # type: ignore[arg-type]
        sandbox=PassingSandbox(),  # type: ignore[arg-type]
    ) as orchestrator:
        manifest = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )

    assert manifest.status == RunStatus.FAILED
    assert "missing template heading" in (manifest.error or "")
    assert providers["builder"].calls == 1
    assert providers["critic"].calls == 0


def test_organization_default_pull_request_template_is_a_hard_gate(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    source, sha = _source_repository(tmp_path)
    original_clone = RepositoryWorkspace.clone

    def local_clone(
        cls: type[RepositoryWorkspace],
        clone_url: str,
        base_sha: str,
        destination: Path,
        **_: object,
    ) -> RepositoryWorkspace:
        return original_clone(str(source), base_sha, destination, allow_local_source=True)

    class OrganizationTemplateGitHub(FakeGitHub):
        def get_file(
            self,
            repository: str,
            path: str,
            *,
            ref: str,
            max_bytes: int = 1_000_000,
        ) -> str | None:
            if repository == "example/.github" and path == "PULL_REQUEST_TEMPLATE.md":
                return "## Organization verification\n"
            return super().get_file(repository, path, ref=ref, max_bytes=max_bytes)

    monkeypatch.setattr(RepositoryWorkspace, "clone", classmethod(local_clone))
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "validation": {"required_commands": {"example/project": [TRUSTED_COMMAND]}},
            "storage": {"path": tmp_path / "state"},
        }
    )
    providers = _providers()
    with Orchestrator(
        config,
        store=RunStore(config.storage.path),
        github=OrganizationTemplateGitHub(_issue(), _repository(sha), sha),  # type: ignore[arg-type]
        providers=providers,  # type: ignore[arg-type]
        sandbox=PassingSandbox(),  # type: ignore[arg-type]
    ) as orchestrator:
        manifest = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )

    assert manifest.status == RunStatus.FAILED
    assert "organization verification" in (manifest.error or "")
    assert providers["critic"].calls == 0


def test_planner_selected_new_scope_triggers_one_instruction_aware_replan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, _ = _source_repository(tmp_path)
    (source / "AGENTS.md").write_text("ROOT_GUIDANCE_MARKER\n", encoding="utf-8")
    component = source / "component"
    component.mkdir()
    (component / "AGENTS.md").write_text("COMPONENT_AGENT_MARKER\n", encoding="utf-8")
    (component / "README.md").write_text("COMPONENT_README_MARKER\n", encoding="utf-8")
    (component / "app.py").write_text("answer = 1\n", encoding="utf-8")
    unrelated = source / "unrelated"
    unrelated.mkdir()
    (unrelated / "AGENTS.md").write_text("UNRELATED_AGENT_MARKER\n", encoding="utf-8")
    (unrelated / "README.md").write_text("UNRELATED_README_MARKER\n", encoding="utf-8")
    referenced = source / "referenced"
    referenced.mkdir()
    (referenced / "AGENTS.md").write_text("REFERENCE_AGENT_MARKER\n", encoding="utf-8")
    (referenced / "probe.py").write_text("documented_boundary_value = 1\n", encoding="utf-8")
    _git(source, "add", ".")
    _git(source, "commit", "--quiet", "-m", "add scoped guidance")
    sha = _git(source, "rev-parse", "HEAD")
    original_clone = RepositoryWorkspace.clone

    def local_clone(
        cls: type[RepositoryWorkspace],
        clone_url: str,
        base_sha: str,
        destination: Path,
        **_: object,
    ) -> RepositoryWorkspace:
        return original_clone(str(source), base_sha, destination, allow_local_source=True)

    monkeypatch.setattr(RepositoryWorkspace, "clone", classmethod(local_clone))
    providers = _providers()
    plan = providers["scout"].output
    proposal = providers["builder"].output
    assert isinstance(plan, ContributionPlan)
    assert isinstance(proposal, PatchProposal)
    providers["scout"].output = plan.model_copy(update={"files_to_read": ["component/app.py"]})
    providers["builder"].output = proposal.model_copy(
        update={
            "edits": [
                FileEdit(
                    operation="replace",
                    path="component/app.py",
                    find="answer = 1\n",
                    replace="answer = 2\n",
                    content=None,
                    rationale="Match the documented boundary behavior.",
                )
            ]
        }
    )
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "validation": {"required_commands": {"example/project": [TRUSTED_COMMAND]}},
            "storage": {"path": tmp_path / "state"},
        }
    )

    with Orchestrator(
        config,
        store=RunStore(config.storage.path),
        github=FakeGitHub(_issue(), _repository(sha), sha),  # type: ignore[arg-type]
        providers=providers,  # type: ignore[arg-type]
        sandbox=PassingSandbox(),  # type: ignore[arg-type]
    ) as orchestrator:
        manifest = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )

    assert manifest.status == RunStatus.READY_FOR_APPROVAL
    assert providers["scout"].calls == 2
    planner_prompt = str(providers["scout"].requests[0]["prompt"])
    replanned_prompt = str(providers["scout"].requests[1]["prompt"])
    builder_prompt = str(providers["builder"].requests[0]["prompt"])
    critic_prompt = str(providers["critic"].requests[0]["prompt"])
    assert "ROOT_GUIDANCE_MARKER" in planner_prompt
    assert "REFERENCE_AGENT_MARKER" in planner_prompt
    assert "COMPONENT_AGENT_MARKER" not in planner_prompt
    assert "COMPONENT_README_MARKER" not in planner_prompt
    for prompt in (replanned_prompt, builder_prompt, critic_prompt):
        assert "ROOT_GUIDANCE_MARKER" in prompt
        assert "COMPONENT_AGENT_MARKER" in prompt
        assert "COMPONENT_README_MARKER" in prompt
        assert "UNRELATED_AGENT_MARKER" not in prompt
        assert "UNRELATED_README_MARKER" not in prompt


def test_replan_cannot_expand_into_a_second_unseen_guidance_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, _ = _source_repository(tmp_path)
    for directory in ("first", "second"):
        scoped = source / directory
        scoped.mkdir()
        (scoped / "AGENTS.md").write_text(f"{directory.upper()}_SCOPE_MARKER\n", encoding="utf-8")
        (scoped / "opaque.py").write_text(f"answer_{directory} = 1\n", encoding="utf-8")
    _git(source, "add", ".")
    _git(source, "commit", "--quiet", "-m", "add two scoped instruction sets")
    sha = _git(source, "rev-parse", "HEAD")
    original_clone = RepositoryWorkspace.clone

    def local_clone(
        cls: type[RepositoryWorkspace],
        clone_url: str,
        base_sha: str,
        destination: Path,
        **_: object,
    ) -> RepositoryWorkspace:
        return original_clone(str(source), base_sha, destination, allow_local_source=True)

    monkeypatch.setattr(RepositoryWorkspace, "clone", classmethod(local_clone))
    providers = _providers()
    initial_plan = providers["scout"].output
    assert isinstance(initial_plan, ContributionPlan)
    providers["scout"] = SequenceProvider(
        [
            initial_plan.model_copy(update={"files_to_read": ["first/opaque.py"]}),
            initial_plan.model_copy(update={"files_to_read": ["second/opaque.py"]}),
        ],
        "gpt-5.6",
    )
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "validation": {"required_commands": {"example/project": [TRUSTED_COMMAND]}},
            "storage": {"path": tmp_path / "state"},
        }
    )

    with Orchestrator(
        config,
        store=RunStore(config.storage.path),
        github=FakeGitHub(_issue(), _repository(sha), sha),  # type: ignore[arg-type]
        providers=providers,  # type: ignore[arg-type]
        sandbox=PassingSandbox(),  # type: ignore[arg-type]
    ) as orchestrator:
        manifest = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )

    assert manifest.status == RunStatus.FAILED
    assert "second/AGENTS.md" in (manifest.error or "")
    assert providers["scout"].calls == 2
    assert providers["builder"].calls == 0
    assert providers["critic"].calls == 0


def test_builder_edit_entering_unseen_agents_scope_fails_before_workspace_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, _ = _source_repository(tmp_path)
    other = source / "other"
    other.mkdir()
    (other / "AGENTS.md").write_text("OTHER_SCOPE_MARKER\n", encoding="utf-8")
    (other / "opaque.py").write_text("answer = 1\n", encoding="utf-8")
    _git(source, "add", ".")
    _git(source, "commit", "--quiet", "-m", "add other scope")
    sha = _git(source, "rev-parse", "HEAD")
    original_clone = RepositoryWorkspace.clone

    def local_clone(
        cls: type[RepositoryWorkspace],
        clone_url: str,
        base_sha: str,
        destination: Path,
        **_: object,
    ) -> RepositoryWorkspace:
        return original_clone(str(source), base_sha, destination, allow_local_source=True)

    monkeypatch.setattr(RepositoryWorkspace, "clone", classmethod(local_clone))
    providers = _providers()
    proposal = providers["builder"].output
    assert isinstance(proposal, PatchProposal)
    providers["builder"].output = proposal.model_copy(
        update={
            "edits": [
                FileEdit(
                    operation="replace",
                    path="other/opaque.py",
                    find="answer = 1\n",
                    replace="answer = 2\n",
                    content=None,
                    rationale="Attempt to edit a path outside the supplied guidance scope.",
                )
            ]
        }
    )
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "validation": {"required_commands": {"example/project": [TRUSTED_COMMAND]}},
            "storage": {"path": tmp_path / "state"},
        }
    )
    store = RunStore(config.storage.path)

    with Orchestrator(
        config,
        store=store,
        github=FakeGitHub(_issue(), _repository(sha), sha),  # type: ignore[arg-type]
        providers=providers,  # type: ignore[arg-type]
        sandbox=PassingSandbox(),  # type: ignore[arg-type]
    ) as orchestrator:
        manifest = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )

    assert manifest.status == RunStatus.FAILED
    assert "repository-guidance scope" in (manifest.error or "")
    assert "other/AGENTS.md" in (manifest.error or "")
    assert providers["builder"].calls == 1
    assert providers["critic"].calls == 0
    workspace = store.workspace_dir(manifest.run_id) / "repository"
    assert (workspace / "other" / "opaque.py").read_text(encoding="utf-8") == "answer = 1\n"


def test_excess_global_guidance_fails_before_any_model_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, _ = _source_repository(tmp_path)
    for index in range(30):
        (source / f"POLICY-{index:02d}.md").write_text(
            f"Policy {index}.\n",
            encoding="utf-8",
        )
    _git(source, "add", ".")
    _git(source, "commit", "--quiet", "-m", "add excessive guidance")
    sha = _git(source, "rev-parse", "HEAD")
    original_clone = RepositoryWorkspace.clone

    def local_clone(
        cls: type[RepositoryWorkspace],
        clone_url: str,
        base_sha: str,
        destination: Path,
        **_: object,
    ) -> RepositoryWorkspace:
        return original_clone(str(source), base_sha, destination, allow_local_source=True)

    monkeypatch.setattr(RepositoryWorkspace, "clone", classmethod(local_clone))
    providers = _providers()
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "validation": {"required_commands": {"example/project": [TRUSTED_COMMAND]}},
            "storage": {"path": tmp_path / "state"},
        }
    )

    with Orchestrator(
        config,
        store=RunStore(config.storage.path),
        github=FakeGitHub(_issue(), _repository(sha), sha),  # type: ignore[arg-type]
        providers=providers,  # type: ignore[arg-type]
        sandbox=PassingSandbox(),  # type: ignore[arg-type]
    ) as orchestrator:
        manifest = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )

    assert manifest.status == RunStatus.FAILED
    assert "above the configured limit of 30" in (manifest.error or "")
    assert all(provider.calls == 0 for provider in providers.values())


def test_excess_scoped_guidance_fails_after_planning_but_before_builder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, _ = _source_repository(tmp_path)
    component = source / "component"
    component.mkdir()
    (component / "app.py").write_text("answer = 1\n", encoding="utf-8")
    (component / "AGENTS.md").write_text("x" * 80_001, encoding="utf-8")
    _git(source, "add", ".")
    _git(source, "commit", "--quiet", "-m", "add oversized scoped guidance")
    sha = _git(source, "rev-parse", "HEAD")
    original_clone = RepositoryWorkspace.clone

    def local_clone(
        cls: type[RepositoryWorkspace],
        clone_url: str,
        base_sha: str,
        destination: Path,
        **_: object,
    ) -> RepositoryWorkspace:
        return original_clone(str(source), base_sha, destination, allow_local_source=True)

    monkeypatch.setattr(RepositoryWorkspace, "clone", classmethod(local_clone))
    providers = _providers()
    plan = providers["scout"].output
    assert isinstance(plan, ContributionPlan)
    providers["scout"].output = plan.model_copy(update={"files_to_read": ["component/app.py"]})
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "validation": {"required_commands": {"example/project": [TRUSTED_COMMAND]}},
            "storage": {"path": tmp_path / "state"},
        }
    )

    with Orchestrator(
        config,
        store=RunStore(config.storage.path),
        github=FakeGitHub(_issue(), _repository(sha), sha),  # type: ignore[arg-type]
        providers=providers,  # type: ignore[arg-type]
        sandbox=PassingSandbox(),  # type: ignore[arg-type]
    ) as orchestrator:
        manifest = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )

    assert manifest.status == RunStatus.FAILED
    assert "Applicable repository guidance exceeds" in (manifest.error or "")
    assert providers["scout"].calls == 1
    assert providers["builder"].calls == 0
    assert providers["critic"].calls == 0


def test_operator_required_commands_run_when_models_omit_them(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    source, sha = _source_repository(tmp_path)
    original_clone = RepositoryWorkspace.clone

    def local_clone(
        cls: type[RepositoryWorkspace],
        clone_url: str,
        base_sha: str,
        destination: Path,
        **_: object,
    ) -> RepositoryWorkspace:
        return original_clone(str(source), base_sha, destination, allow_local_source=True)

    monkeypatch.setattr(RepositoryWorkspace, "clone", classmethod(local_clone))
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "validation": {"required_commands": {"example/project": ["trusted-project-check"]}},
            "storage": {"path": tmp_path / "state"},
        }
    )
    sandbox = PassingSandbox()

    with Orchestrator(
        config,
        store=RunStore(config.storage.path),
        github=FakeGitHub(_issue(), _repository(sha), sha),  # type: ignore[arg-type]
        providers=_providers(validation_commands=[]),  # type: ignore[arg-type]
        sandbox=sandbox,  # type: ignore[arg-type]
    ) as orchestrator:
        manifest = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )

    assert manifest.status == RunStatus.READY_FOR_APPROVAL
    assert sandbox.validation_batches == [["trusted-project-check", REPRODUCTION_COMMAND]]
    assert manifest.quality
    assert next(
        gate for gate in manifest.quality.gates if gate.gate == "required_validation"
    ).passed


def test_missing_dynamic_repository_validation_fails_before_model_work(tmp_path: Path) -> None:
    sha = "a" * 40
    config = AutocontributeConfig.model_validate(
        {
            "github": {"owners": ["example"]},
            "storage": {"path": tmp_path / "state"},
        }
    )
    providers = _providers()

    with Orchestrator(
        config,
        github=FakeGitHub(_issue(), _repository(sha), sha),  # type: ignore[arg-type]
        providers=providers,  # type: ignore[arg-type]
        sandbox=PassingSandbox(),  # type: ignore[arg-type]
    ) as orchestrator:
        manifest = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )

    assert manifest.status == RunStatus.FAILED
    assert "no operator-owned validation.required_commands" in (manifest.error or "")
    assert all(provider.calls == 0 for provider in providers.values())


def test_insufficient_command_budget_fails_without_truncating_required_checks(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    source, sha = _source_repository(tmp_path)
    original_clone = RepositoryWorkspace.clone

    def local_clone(
        cls: type[RepositoryWorkspace],
        clone_url: str,
        base_sha: str,
        destination: Path,
        **_: object,
    ) -> RepositoryWorkspace:
        return original_clone(str(source), base_sha, destination, allow_local_source=True)

    monkeypatch.setattr(RepositoryWorkspace, "clone", classmethod(local_clone))
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "sandbox": {"max_commands": 2},
            "validation": {
                "required_commands": {"example/project": ["trusted-check-one", "trusted-check-two"]}
            },
            "storage": {"path": tmp_path / "state"},
        }
    )
    sandbox = PassingSandbox(remaining_commands=2)

    with Orchestrator(
        config,
        store=RunStore(config.storage.path),
        github=FakeGitHub(_issue(), _repository(sha), sha),  # type: ignore[arg-type]
        providers=_providers(validation_commands=[]),  # type: ignore[arg-type]
        sandbox=sandbox,  # type: ignore[arg-type]
    ) as orchestrator:
        manifest = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )

    assert manifest.status == RunStatus.FAILED
    assert "refusing to truncate validation" in (manifest.error or "")
    assert sandbox.validation_batches == []


def test_isolated_validation_files_never_enter_the_contribution_patch(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    source, sha = _source_repository(tmp_path)
    original_clone = RepositoryWorkspace.clone

    def local_clone(
        cls: type[RepositoryWorkspace],
        clone_url: str,
        base_sha: str,
        destination: Path,
        **_: object,
    ) -> RepositoryWorkspace:
        return original_clone(str(source), base_sha, destination, allow_local_source=True)

    monkeypatch.setattr(RepositoryWorkspace, "clone", classmethod(local_clone))
    mutating_reproduction = (
        "python -c 'from pathlib import Path; from app import value; "
        'Path("validation-generated.txt").write_text("discard"); assert value() == 2\''
    )
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "sandbox": {"backend": "local", "allow_unsafe_local": True},
            "validation": {"required_commands": {"example/project": [mutating_reproduction]}},
            "storage": {"path": tmp_path / "state"},
        }
    )
    store = RunStore(config.storage.path)

    with Orchestrator(
        config,
        store=store,
        github=FakeGitHub(_issue(), _repository(sha), sha),  # type: ignore[arg-type]
        providers=_providers(validation_commands=[], reproduction_command=mutating_reproduction),  # type: ignore[arg-type]
        sandbox=SandboxRunner(config.sandbox),
    ) as orchestrator:
        manifest = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )

    assert manifest.status == RunStatus.READY_FOR_APPROVAL
    patch = (store.artifact_dir(manifest.run_id) / "contribution.patch").read_text()
    assert "validation-generated.txt" not in patch
    assert not (
        store.workspace_dir(manifest.run_id) / "repository" / "validation-generated.txt"
    ).exists()


def test_ineligible_explicit_issue_skips_without_spending_model_tokens(tmp_path: Path) -> None:
    sha = "a" * 40
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "validation": {"required_commands": {"example/project": [TRUSTED_COMMAND]}},
            "storage": {"path": tmp_path / "state"},
        }
    )
    providers = _providers()
    github = FakeGitHub(_issue(assigned=True), _repository(sha), sha)

    with Orchestrator(
        config,
        github=github,  # type: ignore[arg-type]
        providers=providers,  # type: ignore[arg-type]
        sandbox=PassingSandbox(),  # type: ignore[arg-type]
    ) as orchestrator:
        manifest = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )

    assert manifest.status == RunStatus.SKIPPED
    assert "already assigned" in (manifest.skip_reason or "")
    assert all(provider.calls == 0 for provider in providers.values())


def test_unchanged_explicit_issue_is_deferred_before_eligibility_or_model_work(
    tmp_path: Path,
) -> None:
    sha = "a" * 40
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "validation": {"required_commands": {"example/project": [TRUSTED_COMMAND]}},
            "storage": {"path": tmp_path / "state"},
        }
    )
    store = RunStore(config.storage.path)
    providers = _providers()
    github = CountingGitHub(_issue(assigned=True), _repository(sha), sha)

    with Orchestrator(
        config,
        store=store,
        github=github,  # type: ignore[arg-type]
        providers=providers,  # type: ignore[arg-type]
        sandbox=PassingSandbox(),  # type: ignore[arg-type]
    ) as orchestrator:
        first = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )
        second = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )

    assert first.status == RunStatus.SKIPPED
    assert second.status == RunStatus.SKIPPED
    assert second.candidate is None
    assert "unchanged since prior skipped run" in (second.skip_reason or "")
    assert "--retry-unchanged" in (second.skip_reason or "")
    assert github.default_branch_calls == 1
    assert all(provider.calls == 0 for provider in providers.values())
    events = store.events(second.run_id)
    assert "candidate.retry_deferred" in [event["event_type"] for event in events]
    details = json.loads(
        next(
            event["details"]
            for event in events
            if event["event_type"] == "candidate.retry_deferred"
        )
    )
    first_selection = json.loads(
        next(
            event["details"]
            for event in store.events(first.run_id)
            if event["event_type"] == "candidate.selected"
        )
    )
    assert details == {
        "issue": "example/project#42",
        "issue_revision": first_selection["issue_revision"],
        "prior_run_id": first.run_id,
        "prior_status": "skipped",
    }


def test_unpinned_discovery_exhausts_suppressed_revision_without_model_work(
    tmp_path: Path,
) -> None:
    sha = "a" * 40
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "validation": {"required_commands": {"example/project": [TRUSTED_COMMAND]}},
            "storage": {"path": tmp_path / "state"},
        }
    )
    store = RunStore(config.storage.path)
    providers = _providers()
    github = DiscoveryGitHub(_issue(assigned=True), _repository(sha), sha)

    with Orchestrator(
        config,
        store=store,
        github=github,  # type: ignore[arg-type]
        providers=providers,  # type: ignore[arg-type]
        sandbox=PassingSandbox(),  # type: ignore[arg-type]
    ) as orchestrator:
        prior = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )
        discovered = orchestrator.run()

    assert prior.status == RunStatus.SKIPPED
    assert discovered.status == RunStatus.SKIPPED
    assert discovered.candidate is None
    assert discovered.skip_reason == (
        "No candidate is currently available: 1 unchanged issue revision was deferred after a "
        "prior skipped, rejected, or cancelled run."
    )
    assert github.search_calls == 1
    assert all(provider.calls == 0 for provider in providers.values())
    exhaustion = next(
        event
        for event in store.events(discovered.run_id)
        if event["event_type"] == "candidate.discovery_exhausted"
    )
    assert json.loads(exhaustion["details"]) == {
        "active_candidates": "0",
        "ineligible_candidates": "0",
        "suppressed_candidates": "1",
    }


def test_retry_unchanged_explicit_issue_records_override_and_rechecks_eligibility(
    tmp_path: Path,
) -> None:
    sha = "a" * 40
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "validation": {"required_commands": {"example/project": [TRUSTED_COMMAND]}},
            "storage": {"path": tmp_path / "state"},
        }
    )
    store = RunStore(config.storage.path)
    providers = _providers()
    github = CountingGitHub(_issue(assigned=True), _repository(sha), sha)

    with Orchestrator(
        config,
        store=store,
        github=github,  # type: ignore[arg-type]
        providers=providers,  # type: ignore[arg-type]
        sandbox=PassingSandbox(),  # type: ignore[arg-type]
    ) as orchestrator:
        first = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )
        retried = orchestrator.run(
            issue_reference="example/project#42",
            invocation_mode=RunInvocationMode.MANUAL,
            retry_authorization=CandidateRetryAuthorization(
                actor="release-operator",
                reason="Reviewed the prior skip after updating the model instructions.",
            ),
        )

    assert first.status == RunStatus.SKIPPED
    assert retried.status == RunStatus.SKIPPED
    assert retried.candidate is not None
    assert "already assigned" in (retried.skip_reason or "")
    assert github.default_branch_calls == 2
    assert all(provider.calls == 0 for provider in providers.values())
    events = store.events(retried.run_id)
    override = next(event for event in events if event["event_type"] == "candidate.retry_override")
    details = json.loads(override["details"])
    assert details["prior_run_id"] == first.run_id
    assert details["actor"] == "release-operator"
    assert details["reason"] == "Reviewed the prior skip after updating the model instructions."
    assert len(details["authorization_id"]) == 32
    assert set(details["authorization_id"]) <= set("0123456789abcdef")


def test_explicit_issue_cannot_bypass_repository_allowlist(tmp_path: Path) -> None:
    sha = "a" * 40
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["approved/project"]},
            "validation": {"required_commands": {"approved/project": [TRUSTED_COMMAND]}},
            "storage": {"path": tmp_path / "state"},
        }
    )
    providers = _providers()
    github = FakeGitHub(_issue(), _repository(sha), sha)

    with Orchestrator(
        config,
        github=github,  # type: ignore[arg-type]
        providers=providers,  # type: ignore[arg-type]
        sandbox=PassingSandbox(),  # type: ignore[arg-type]
    ) as orchestrator:
        manifest = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )

    assert manifest.status == RunStatus.FAILED
    assert "not in github.repositories" in (manifest.error or "")
    assert all(provider.calls == 0 for provider in providers.values())


def test_model_call_forwards_remaining_output_and_wall_clock_budgets(tmp_path: Path) -> None:
    config = AutocontributeConfig.model_validate(
        {
            "models": {
                role: {
                    "pricing": {
                        "input_usd_per_million_tokens": "2",
                        "output_usd_per_million_tokens": "4",
                    }
                }
                for role in ("scout", "builder", "critic")
            },
            "budget": {
                "max_output_tokens_per_run": 1_000,
                "max_model_seconds_per_run": 10,
            },
            "storage": {"path": tmp_path / "state"},
        }
    )
    store = RunStore(config.storage.path)
    provider = _providers()["scout"]
    ticks = iter((5.0, 7.0))
    orchestrator = Orchestrator(
        config,
        store=store,
        github=FakeGitHub(_issue(), _repository("a" * 40), "a" * 40),  # type: ignore[arg-type]
        providers={"scout": provider},  # type: ignore[arg-type]
        sandbox=PassingSandbox(),  # type: ignore[arg-type]
        clock=lambda: next(ticks),
    )
    manifest = store.create_run()

    orchestrator._call_model(
        manifest,
        role="scout",
        instructions="Plan safely.",
        prompt="Inspect one issue.",
        output_type=ContributionPlan,
    )

    assert provider.requests[0]["max_output_tokens"] == 1_000
    assert provider.requests[0]["timeout_seconds"] == 10
    assert manifest.model_input_tokens == 10
    assert manifest.model_output_tokens == 5
    assert str(manifest.model_cost_usd) == "0.00004"
    assert manifest.model_seconds == 2
    persisted = store.get(manifest.run_id)
    assert persisted.model_seconds == 2
    assert persisted.model_reservation is None


def test_cost_budget_rejects_request_before_provider_invocation(tmp_path: Path) -> None:
    priced_profile = {
        "pricing": {
            "input_usd_per_million_tokens": "100",
            "output_usd_per_million_tokens": "100",
        }
    }
    config = AutocontributeConfig.model_validate(
        {
            "models": {
                "scout": priced_profile,
                "builder": priced_profile,
                "critic": priced_profile,
            },
            "budget": {"max_model_cost_usd_per_run": "0.0001"},
            "storage": {"path": tmp_path / "state"},
        }
    )
    store = RunStore(config.storage.path)
    provider = _providers()["scout"]
    orchestrator = Orchestrator(
        config,
        store=store,
        github=FakeGitHub(_issue(), _repository("a" * 40), "a" * 40),  # type: ignore[arg-type]
        providers={"scout": provider},  # type: ignore[arg-type]
        sandbox=PassingSandbox(),  # type: ignore[arg-type]
    )
    manifest = store.create_run()

    with pytest.raises(PolicyError, match="cost budget exhausted"):
        orchestrator._call_model(
            manifest,
            role="scout",
            instructions="Plan safely.",
            prompt="Inspect one issue.",
            output_type=ContributionPlan,
        )

    assert provider.calls == 0
    assert manifest.model_calls == 0
    assert manifest.model_reservation is None


def test_failed_model_call_retains_durable_reservation(tmp_path: Path) -> None:
    class FailingProvider:
        def generate(self, **_: object) -> ModelResult[Any]:
            raise RuntimeError("provider unavailable")

    config = AutocontributeConfig.model_validate(
        {
            "budget": {"max_model_seconds_per_run": 10},
            "storage": {"path": tmp_path / "state"},
        }
    )
    store = RunStore(config.storage.path)
    ticks = iter((1.0, 2.5))
    orchestrator = Orchestrator(
        config,
        store=store,
        github=FakeGitHub(_issue(), _repository("a" * 40), "a" * 40),  # type: ignore[arg-type]
        providers={"scout": FailingProvider()},  # type: ignore[arg-type]
        sandbox=PassingSandbox(),  # type: ignore[arg-type]
        clock=lambda: next(ticks),
    )
    manifest = store.create_run()

    with pytest.raises(RuntimeError, match="provider unavailable"):
        orchestrator._call_model(
            manifest,
            role="scout",
            instructions="Plan safely.",
            prompt="Inspect one issue.",
            output_type=ContributionPlan,
        )

    assert manifest.model_reservation is not None
    assert manifest.model_seconds == 1.5
    persisted = store.get(manifest.run_id)
    assert persisted.model_reservation == manifest.model_reservation


def test_provider_usage_above_forwarded_limit_is_charged_then_rejected(tmp_path: Path) -> None:
    config = AutocontributeConfig.model_validate(
        {
            "budget": {"max_output_tokens_per_run": 1_000},
            "storage": {"path": tmp_path / "state"},
        }
    )
    store = RunStore(config.storage.path)
    plan = _providers()["scout"].output
    provider = FixedProvider(
        plan,
        "over-limit-model",
        usage=ModelUsage(input_tokens=10, output_tokens=1_001, total_tokens=1_011),
    )
    orchestrator = Orchestrator(
        config,
        store=store,
        github=FakeGitHub(_issue(), _repository("a" * 40), "a" * 40),  # type: ignore[arg-type]
        providers={"scout": provider},  # type: ignore[arg-type]
        sandbox=PassingSandbox(),  # type: ignore[arg-type]
    )
    manifest = store.create_run()

    with pytest.raises(PolicyError, match="output usage exceeded"):
        orchestrator._call_model(
            manifest,
            role="scout",
            instructions="Plan safely.",
            prompt="Inspect one issue.",
            output_type=ContributionPlan,
        )

    assert provider.requests[0]["max_output_tokens"] == 1_000
    assert manifest.model_output_tokens == 1_001
    assert manifest.model_reservation is None
    assert store.get(manifest.run_id).model_output_tokens == 1_001


def test_review_mode_accepts_observed_provider_model_without_an_attestation(
    tmp_path: Path,
) -> None:
    config = AutocontributeConfig.model_validate({"storage": {"path": tmp_path / "state"}})
    store = RunStore(config.storage.path)
    provider = FixedProvider(_providers()["scout"].output, "provider-snapshot-2026-07-21")
    orchestrator = Orchestrator(
        config,
        store=store,
        github=FakeGitHub(_issue(), _repository("a" * 40), "a" * 40),  # type: ignore[arg-type]
        providers={"scout": provider},  # type: ignore[arg-type]
        sandbox=PassingSandbox(),  # type: ignore[arg-type]
    )
    manifest = store.create_run()

    result = orchestrator._call_model(
        manifest,
        role="scout",
        instructions="Plan safely.",
        prompt="Inspect one issue.",
        output_type=ContributionPlan,
    )

    assert result.model == "provider-snapshot-2026-07-21"


def test_orchestrator_rejects_a_provider_model_outside_the_attested_deployment(
    tmp_path: Path,
) -> None:
    config = AutocontributeConfig.model_validate(
        {
            "models": {"scout": {"expected_response_model": "provider-snapshot-2026-07-21"}},
            "storage": {"path": tmp_path / "state"},
        }
    )
    store = RunStore(config.storage.path)
    provider = FixedProvider(_providers()["scout"].output, "provider-snapshot-2026-07-22")
    orchestrator = Orchestrator(
        config,
        store=store,
        github=FakeGitHub(_issue(), _repository("a" * 40), "a" * 40),  # type: ignore[arg-type]
        providers={"scout": provider},  # type: ignore[arg-type]
        sandbox=PassingSandbox(),  # type: ignore[arg-type]
    )
    manifest = store.create_run()

    with pytest.raises(PolicyError, match="outside the calibrated deployment"):
        orchestrator._call_model(
            manifest,
            role="scout",
            instructions="Plan safely.",
            prompt="Inspect one issue.",
            output_type=ContributionPlan,
        )


def test_reused_orchestrator_resets_per_run_model_call_artifact(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    source, sha = _source_repository(tmp_path)
    original_clone = RepositoryWorkspace.clone

    def local_clone(
        cls: type[RepositoryWorkspace],
        clone_url: str,
        base_sha: str,
        destination: Path,
        **_: object,
    ) -> RepositoryWorkspace:
        return original_clone(str(source), base_sha, destination, allow_local_source=True)

    monkeypatch.setattr(RepositoryWorkspace, "clone", classmethod(local_clone))
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "validation": {"required_commands": {"example/project": [TRUSTED_COMMAND]}},
            "storage": {"path": tmp_path / "state"},
        }
    )
    store = RunStore(config.storage.path)
    providers = _providers()
    github = FakeGitHub(_issue(), _repository(sha), sha)
    orchestrator = Orchestrator(
        config,
        store=store,
        github=github,  # type: ignore[arg-type]
        providers=providers,  # type: ignore[arg-type]
        sandbox=PassingSandbox(),  # type: ignore[arg-type]
    )

    first = orchestrator.run(
        issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
    )
    blocked = orchestrator.run(
        issue_reference="example/project#42",
        invocation_mode=RunInvocationMode.MANUAL,
        retry_authorization=CandidateRetryAuthorization(
            actor="release-operator",
            reason="Attempted explicit retry while prior work remains active.",
        ),
    )
    assert blocked.status == RunStatus.SKIPPED
    assert blocked.candidate is None
    assert "already has active run" in (blocked.skip_reason or "")
    assert all(provider.calls == 1 for provider in providers.values())
    assert "candidate.active_deferred" in [
        event["event_type"] for event in store.events(blocked.run_id)
    ]
    github.issue = _issue().model_copy(
        update={
            "number": 43,
            "html_url": "https://github.com/example/project/issues/43",
        }
    )
    second = orchestrator.run(
        issue_reference="example/project#43", invocation_mode=RunInvocationMode.MANUAL
    )

    assert first.status == RunStatus.READY_FOR_APPROVAL
    assert second.status == RunStatus.READY_FOR_APPROVAL
    first_events = json.loads(
        (store.artifact_dir(first.run_id) / "model-calls.json").read_text(encoding="utf-8")
    )
    second_events = json.loads(
        (store.artifact_dir(second.run_id) / "model-calls.json").read_text(encoding="utf-8")
    )
    assert len(first_events) == 3
    assert len(second_events) == 3
    assert second_events[0]["response_id"] == "response-gpt-5.6-2"


def test_orchestrator_closes_only_factory_owned_provider_once(tmp_path: Path) -> None:
    class CloseableProvider(FixedProvider):
        def __init__(self, output: Any, model: str) -> None:
            super().__init__(output, model)
            self.close_calls = 0

        def close(self) -> None:
            self.close_calls += 1

    config = AutocontributeConfig.model_validate({"storage": {"path": tmp_path / "state"}})
    store = RunStore(config.storage.path)
    created = CloseableProvider(_providers()["scout"].output, "gpt-5.6")
    injected = CloseableProvider(_providers()["builder"].output, "gpt-5.6")
    orchestrator = Orchestrator(
        config,
        store=store,
        github=FakeGitHub(_issue(), _repository("a" * 40), "a" * 40),  # type: ignore[arg-type]
        providers={"builder": injected},  # type: ignore[arg-type]
        provider_factory=lambda _: created,
        sandbox=PassingSandbox(),  # type: ignore[arg-type]
    )
    manifest = store.create_run()
    orchestrator._call_model(
        manifest,
        role="scout",
        instructions="Plan safely.",
        prompt="Inspect one issue.",
        output_type=ContributionPlan,
    )

    orchestrator.close()
    orchestrator.close()

    assert created.close_calls == 1
    assert injected.close_calls == 0
