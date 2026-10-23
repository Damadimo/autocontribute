from __future__ import annotations

import hashlib
import json
import subprocess
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from test_task_messages import _check, _facts

import autocontribute.orchestrator as orchestrator_module
from autocontribute import __version__
from autocontribute.agent_loop import (
    CheckReport,
    DidNotFinish,
    LoopFailure,
    SkippedIssue,
    SolverOutcome,
    SubmittedFix,
)
from autocontribute.config import AutocontributeConfig
from autocontribute.critic import CriticOutcome, CriticRound
from autocontribute.domain import (
    IssueCandidate,
    IssueComment,
    RepositoryInfo,
    RunStatus,
)
from autocontribute.environment_builder import PreparedEnvironment
from autocontribute.environment_setup import EnvironmentImage
from autocontribute.evidence import read_validation_evidence
from autocontribute.exceptions import (
    CircuitBreakerTrigger,
    ConfigurationError,
    EnvironmentUnavailable,
    SandboxError,
    StateError,
    StopScope,
)
from autocontribute.github import DirectoryEntry
from autocontribute.orchestrator import Orchestrator, RunInvocationMode
from autocontribute.preparation import (
    validate_preparation_config_fingerprint,
    validate_preparation_fingerprint,
    validate_validation_artifact,
)
from autocontribute.pricing import ModelSpec
from autocontribute.repository import RepositoryWorkspace
from autocontribute.store import (
    CandidateAttemptState,
    CandidateRetryAuthorization,
    Lease,
    RunStore,
)
from autocontribute.submissions import AgentSubmission, ReviewBlocker, ReviewSubmission
from autocontribute.transcript import Transcript, Turn

_GITHUB_TOKEN = "fake-github-token-for-tests"


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
        labels=["help wanted", "bug"],
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


def _config(tmp_path: Path, **sections: object) -> AutocontributeConfig:
    return AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "storage": {"path": tmp_path / "state"},
            **sections,
        }
    )


class FakeGitHub:
    token = _GITHUB_TOKEN

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

    def list_directory(
        self, repository: str, path: str, *, ref: str
    ) -> list[DirectoryEntry] | None:
        del repository, ref
        return None if path else [DirectoryEntry(path="CONTRIBUTING.md", kind="file")]

    def recent_commit_titles(self, repository: str, sha: str) -> list[str]:
        return ["Fix the parser boundary", "Add a changelog entry"]


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

    def list_labels(self, repository: str) -> list[str]:
        del repository
        return ["help wanted", "bug"]

    def search_issues(
        self,
        repository: str,
        *,
        include_labels: list[str],
        exclude_labels: list[str],
        unassigned: bool,
        page: int,
        per_page: int,
    ) -> list[IssueCandidate]:
        del repository, include_labels, exclude_labels, unassigned, per_page
        self.search_calls += 1
        # Like GitHub's, search results carry no discussion.
        return [self.issue.model_copy(update={"discussion": []})] if page == 1 else []


class NoTurns:
    """A provider for runs that must not reach a model."""

    def step(
        self, *, transcript: Transcript, max_output_tokens: int, timeout_seconds: float
    ) -> Turn:
        raise AssertionError(f"unexpected {transcript.kind} turn")


AgentStep = Callable[["FakeChecks"], SolverOutcome]


class Pipeline:
    """Fakes for the Docker- and model-backed steps; each test scripts what they return."""

    def __init__(self) -> None:
        facts = _facts()
        self.environment: Exception | None = None
        self.recipe = facts.recipe
        self.baseline = facts.baseline
        self.agent: list[AgentStep] = [fixes()]
        self.reviews: list[CriticOutcome] = [review("approve")]
        self.prepared: list[tuple[str, str]] = []
        self.blockers: list[list[ReviewBlocker]] = []
        self.patches: list[str] = []
        self.sessions = 0
        self.leftover_sweeps: list[frozenset[str]] = []

    def remove_leftovers(self, store_root: Path, unfinished: frozenset[str]) -> None:
        self.leftover_sweeps.append(unfinished)

    def provider(self, spec: ModelSpec, host_values: frozenset[str]) -> NoTurns:
        assert _GITHUB_TOKEN in host_values
        return NoTurns()

    def builder(self, config: object, store: RunStore, *, run_id: str) -> FakeBuilder:
        return FakeBuilder(self)

    def validation(self, *_: object) -> FakeValidation:
        return FakeValidation(self)

    def checks(self, workspace: RepositoryWorkspace, *_: object, **__: object) -> FakeChecks:
        return FakeChecks(workspace)

    def solver(self, transcript: Transcript, *, checker: FakeChecks, **_: object) -> FakeSolver:
        assert transcript.kind == "agent" and transcript.model == "gpt-5.6-sol"
        return FakeSolver(self, checker)

    def critic(self, *_: object, model: str, **__: object) -> FakeCritic:
        assert model == "gpt-5.6-sol"
        return FakeCritic(self)


class FakeBuilder:
    def __init__(self, pipeline: Pipeline) -> None:
        self.pipeline = pipeline

    def prepare(
        self,
        repository: str,
        workspace: RepositoryWorkspace,
        override: object,
        setup_agent: object,
    ) -> PreparedEnvironment:
        self.pipeline.prepared.append((repository, workspace.base_sha))
        if self.pipeline.environment is not None:
            raise self.pipeline.environment
        image = EnvironmentImage(
            image_id="sha256:" + "e" * 64,
            tag="autocontribute-env/example__project:abc",
            base_image="python:3.12-bookworm",
            base_digest="sha256:" + "f" * 64,
            cache_key="c" * 64,
            reused=False,
        )
        snapshot = workspace.path.with_name("repository.snapshot")
        return PreparedEnvironment(image, self.pipeline.recipe, self.pipeline.baseline, snapshot)


class FakeValidation:
    def __init__(self, pipeline: Pipeline) -> None:
        self.pipeline = pipeline
        self.environment = {"PATH": "/usr/bin:/bin"}

    @contextmanager
    def session(self, workspace: Path, *, timeout_seconds: int) -> Iterator[object]:
        assert timeout_seconds >= 1
        self.pipeline.sessions += 1
        yield object()


class FakeChecks:
    def __init__(self, workspace: RepositoryWorkspace) -> None:
        self.workspace = workspace
        self.results: dict[str, Any] = {}
        self.validated = workspace.path.with_name("repository.validation")


class FakeSolver:
    def __init__(self, pipeline: Pipeline, checks: FakeChecks) -> None:
        self.pipeline = pipeline
        self.checks = checks

    def run(self) -> SolverOutcome:
        return self.pipeline.agent.pop(0)(self.checks)

    def address_blockers(self, blockers: list[ReviewBlocker]) -> SolverOutcome:
        self.pipeline.blockers.append(list(blockers))
        return self.pipeline.agent.pop(0)(self.checks)


class FakeCritic:
    def __init__(self, pipeline: Pipeline) -> None:
        self.pipeline = pipeline
        self.rounds: list[CriticRound] = []

    def review(
        self, fix: SubmittedFix, check: object, *, patch: str, validated: Path
    ) -> CriticOutcome:
        self.pipeline.patches.append(patch)
        outcome = self.pipeline.reviews.pop(0)
        if isinstance(outcome, CriticRound):
            outcome = outcome.model_copy(update={"number": len(self.rounds) + 1})
            self.rounds.append(outcome)
        return outcome


def _submission(**changes: object) -> AgentSubmission:
    fields: dict[str, object] = {
        "outcome": "fixed",
        "skip_reason": None,
        "summary": "value() returned 1; it returns the documented 2 now.",
        "pr_title": "Fix documented boundary value",
        "pr_body": "value() returned 1 at the boundary. It returns 2 now.",
        "commit_message": "Fix documented boundary value",
        "test_files": ["tests/test_app.py"],
        "test_command": "python -m pytest tests/test_app.py",
    }
    return AgentSubmission.model_validate({**fields, **changes})


def fixes(source: str = "def value():\n    return 2\n", **submission: object) -> AgentStep:
    """The agent writes ``source`` to app.py and submits a fix that passed its checks."""

    def act(checks: FakeChecks) -> SolverOutcome:
        (checks.workspace.path / "app.py").write_text(source, encoding="utf-8")
        sha = hashlib.sha256(checks.workspace.patch_bytes()).hexdigest()
        checks.results[sha] = _check(diff_sha256=sha)
        return SubmittedFix(
            submission=_submission(**submission),
            check=CheckReport(passed=True, diff_sha256=sha, text="Checks passed."),
        )

    return act


def ends(outcome: SolverOutcome) -> AgentStep:
    return lambda _checks: outcome


def _blocker() -> ReviewBlocker:
    return ReviewBlocker(
        category="weak_test",
        path="tests/test_app.py",
        line=3,
        evidence="The test passes without the fix.",
        check_command="python -m pytest tests/test_app.py",
        fix_hint="Assert the documented value.",
    )


def review(
    decision: str, *, blockers: list[ReviewBlocker] | None = None, reason: str = ""
) -> CriticRound:
    verdict = {"approve": "approve", "request_changes": "request_changes", "reject": "abandon"}
    return CriticRound(
        number=1,
        decision=decision,  # type: ignore[arg-type]
        reason=reason,
        review=ReviewSubmission(
            verdict=verdict[decision],  # type: ignore[arg-type]
            blockers=blockers or [],
            notes=["The test could also cover negative numbers."],
            no_test_needed=False,
            summary=f"Review: {decision}.",
        ),
        confirmed=blockers or [],
        dropped=[],
    )


@pytest.fixture
def pipeline(monkeypatch: pytest.MonkeyPatch) -> Pipeline:
    fakes = Pipeline()
    monkeypatch.setenv("OPENAI_API_KEY", "openai-test-key-placeholder")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(orchestrator_module, "remove_leftover_containers", fakes.remove_leftovers)
    monkeypatch.setattr(orchestrator_module, "EnvironmentBuilder", fakes.builder)
    monkeypatch.setattr(orchestrator_module, "DockerValidation", fakes.validation)
    monkeypatch.setattr(orchestrator_module, "FixChecks", fakes.checks)
    monkeypatch.setattr(orchestrator_module, "Solver", fakes.solver)
    monkeypatch.setattr(orchestrator_module, "Critic", fakes.critic)
    return fakes


@pytest.fixture
def source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, str]:
    """A local repository that every clone comes from."""

    repository, sha = _source_repository(tmp_path)
    original_clone = RepositoryWorkspace.clone

    def local_clone(
        cls: type[RepositoryWorkspace],
        clone_url: str,
        base_sha: str,
        destination: Path,
        **_: object,
    ) -> RepositoryWorkspace:
        return original_clone(str(repository), base_sha, destination, allow_local_source=True)

    monkeypatch.setattr(RepositoryWorkspace, "clone", classmethod(local_clone))
    return repository, sha


def _run(
    tmp_path: Path,
    pipeline: Pipeline,
    sha: str,
    *,
    config: AutocontributeConfig | None = None,
    github: FakeGitHub | None = None,
) -> tuple[Any, RunStore]:
    settings = config or _config(tmp_path)
    store = RunStore(settings.storage.path)
    with Orchestrator(
        settings,
        store=store,
        github=github or FakeGitHub(_issue(), _repository(sha), sha),  # type: ignore[arg-type]
        provider_factory=pipeline.provider,
    ) as orchestrator:
        manifest = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )
    return manifest, store


def _statuses(store: RunStore, run_id: str) -> list[str]:
    return [
        json.loads(event["details"])["to"]
        for event in store.events(run_id)
        if event["event_type"] == "run.transitioned"
    ]


def test_a_fix_the_critic_approves_is_ready_with_sealed_evidence(
    tmp_path: Path, pipeline: Pipeline, source: tuple[Path, str]
) -> None:
    _, sha = source

    manifest, store = _run(tmp_path, pipeline, sha)

    assert manifest.status == RunStatus.READY_FOR_APPROVAL, manifest.error
    assert _statuses(store, manifest.run_id) == [
        "discovering",
        "candidate_selected",
        "eligibility_checked",
        "setting_up",
        "implementing",
        "validating",
        "critiquing",
        "ready_for_approval",
    ]
    assert manifest.models is not None
    assert manifest.models.model_dump() == {
        "agent": "gpt-5.6-sol",
        "critic": "gpt-5.6-sol",
        "setup": "gpt-5.6-terra",
        "triage": "gpt-5.6-luna",
    }
    assert manifest.environment is not None
    assert manifest.environment.recipe_source == "detected"
    assert manifest.environment.base_digest == "sha256:" + "f" * 64
    proposal = manifest.proposal
    assert proposal is not None
    assert proposal.pull_request_title == "Fix documented boundary value"
    assert proposal.pull_request_body.startswith("Fixes #42\n\nvalue() returned 1")
    assert "Testing (run by autocontribute):" in proposal.pull_request_body
    assert proposal.disclosure == (
        f"AI assistance: an AI coding agent (autocontribute {__version__}, gpt-5.6-sol) drafted "
        "this change and its test and ran the tests listed above in a sandbox. I reviewed the "
        "diff and the test results before opening this PR and will handle the review."
    )
    assert proposal.pull_request_body.endswith(f"\n\n---\n\n{proposal.disclosure}")
    assert proposal.summary == "value() returned 1; it returns the documented 2 now."
    assert proposal.test_files == ["tests/test_app.py"]
    assert manifest.quality is not None and manifest.quality.ready
    assert manifest.quality.review_summary == "Review: approve."
    artifacts = store.artifact_dir(manifest.run_id)
    patch = (artifacts / "contribution.patch").read_bytes()
    assert b"+    return 2" in patch
    assert pipeline.patches == [patch.decode("utf-8")]
    validation = (artifacts / "validation.json").read_bytes()
    validate_validation_artifact(manifest, artifact=validation)
    evidence = read_validation_evidence(validation)
    assert evidence.recipe == pipeline.recipe and evidence.baseline == pipeline.baseline
    assert evidence.check is not None
    assert evidence.check.diff_sha256 == hashlib.sha256(patch).hexdigest()
    assert [round_.decision for round_ in evidence.critic_rounds] == ["approve"]
    persisted = store.get(manifest.run_id)
    validate_preparation_fingerprint(persisted, diff=patch)
    validate_preparation_config_fingerprint(persisted, _config(tmp_path))
    assert (artifacts / "report.md").is_file()
    # Publication clones the repository again; nothing of the preparation stays.
    assert not (store.workspaces_dir / manifest.run_id).exists()
    assert pipeline.prepared == [("example/project", sha)]
    assert pipeline.sessions == 1
    assert pipeline.leftover_sweeps == [frozenset()]
    events = [event["event_type"] for event in store.events(manifest.run_id)]
    assert "environment.accepted" in events and "critic.reviewed" in events


def test_blockers_go_back_to_the_agent_and_the_next_fix_gets_a_new_round(
    tmp_path: Path, pipeline: Pipeline, source: tuple[Path, str]
) -> None:
    _, sha = source
    pipeline.agent = [fixes(), fixes("def value():\n    return 1 + 1\n")]
    pipeline.reviews = [review("request_changes", blockers=[_blocker()]), review("approve")]

    manifest, store = _run(tmp_path, pipeline, sha)

    assert manifest.status == RunStatus.READY_FOR_APPROVAL, manifest.error
    assert pipeline.blockers == [[_blocker()]]
    assert _statuses(store, manifest.run_id)[4:] == [
        "implementing",
        "validating",
        "critiquing",
        "implementing",
        "validating",
        "critiquing",
        "ready_for_approval",
    ]
    patch = (store.artifact_dir(manifest.run_id) / "contribution.patch").read_text()
    assert "+    return 1 + 1" in patch
    assert manifest.quality is not None and manifest.quality.review_rounds == 2
    evidence = read_validation_evidence(
        (store.artifact_dir(manifest.run_id) / "validation.json").read_bytes()
    )
    assert [round_.decision for round_ in evidence.critic_rounds] == [
        "request_changes",
        "approve",
    ]


def test_no_buildable_environment_skips_the_run(
    tmp_path: Path, pipeline: Pipeline, source: tuple[Path, str]
) -> None:
    _, sha = source
    pipeline.environment = EnvironmentUnavailable("No Python, JavaScript, Go or Rust project")

    manifest, store = _run(tmp_path, pipeline, sha)

    assert manifest.status == RunStatus.SKIPPED
    assert manifest.skip_reason == "environment: No Python, JavaScript, Go or Rust project"
    assert manifest.environment is None
    assert not (store.artifact_dir(manifest.run_id) / "validation.json").exists()
    assert pipeline.sessions == 0


def test_a_sandbox_failure_while_setting_up_fails_the_run(
    tmp_path: Path, pipeline: Pipeline, source: tuple[Path, str]
) -> None:
    _, sha = source
    pipeline.environment = SandboxError("Could not verify Docker daemon runtime information")

    manifest, _store = _run(tmp_path, pipeline, sha)

    assert manifest.status == RunStatus.FAILED
    assert manifest.error == "Could not verify Docker daemon runtime information"


def test_the_agent_can_decline_the_issue(
    tmp_path: Path, pipeline: Pipeline, source: tuple[Path, str]
) -> None:
    _, sha = source
    declined = _submission(
        outcome="skip",
        skip_reason="Maintainers must first choose between two behaviours.",
        pr_title=None,
        pr_body=None,
        commit_message=None,
    )
    pipeline.agent = [ends(SkippedIssue(reason=declined.skip_reason or "", submission=declined))]

    manifest, store = _run(tmp_path, pipeline, sha)

    assert manifest.status == RunStatus.SKIPPED
    assert manifest.skip_reason == (
        "the agent skipped the issue: Maintainers must first choose between two behaviours."
    )
    evidence = read_validation_evidence(
        (store.artifact_dir(manifest.run_id) / "validation.json").read_bytes()
    )
    assert evidence.check is None and evidence.critic_rounds == []
    assert manifest.validation_sha256 is None


def test_an_agent_that_does_not_finish_rejects_the_run(
    tmp_path: Path, pipeline: Pipeline, source: tuple[Path, str]
) -> None:
    _, sha = source
    pipeline.agent = [ends(DidNotFinish("turns", "The transcript reached its turn cap of 100"))]

    manifest, _store = _run(tmp_path, pipeline, sha)

    assert manifest.status == RunStatus.REJECTED
    assert manifest.reject_reason == (
        "agent did not finish: The transcript reached its turn cap of 100"
    )


@pytest.mark.parametrize(
    ("failing", "error"),
    [("provider", "Model refused the request"), ("sandbox", "the sandbox container stopped")],
)
def test_a_provider_or_sandbox_failure_in_the_loop_fails_the_run(
    tmp_path: Path,
    pipeline: Pipeline,
    source: tuple[Path, str],
    failing: str,
    error: str,
) -> None:
    _, sha = source
    pipeline.agent = [ends(LoopFailure(failing, error))]  # type: ignore[arg-type]

    manifest, _store = _run(tmp_path, pipeline, sha)

    assert manifest.status == RunStatus.FAILED
    assert manifest.error == error


def test_a_critic_rejection_rejects_the_run_with_its_reason(
    tmp_path: Path, pipeline: Pipeline, source: tuple[Path, str]
) -> None:
    _, sha = source
    pipeline.reviews = [review("reject", reason="the reviewer abandoned the change: unsafe")]

    manifest, store = _run(tmp_path, pipeline, sha)

    assert manifest.status == RunStatus.REJECTED
    assert manifest.reject_reason == "the reviewer abandoned the change: unsafe"
    assert manifest.quality is not None and not manifest.quality.ready
    assert not (store.artifact_dir(manifest.run_id) / "contribution.patch").exists()
    evidence = read_validation_evidence(
        (store.artifact_dir(manifest.run_id) / "validation.json").read_bytes()
    )
    assert [round_.decision for round_ in evidence.critic_rounds] == ["reject"]


def test_a_review_that_does_not_finish_rejects_the_run(
    tmp_path: Path, pipeline: Pipeline, source: tuple[Path, str]
) -> None:
    _, sha = source
    pipeline.reviews = [DidNotFinish("budget", "The critic budget has $0.0000 left")]

    manifest, _store = _run(tmp_path, pipeline, sha)

    assert manifest.status == RunStatus.REJECTED
    assert manifest.reject_reason == (
        "the review did not finish: The critic budget has $0.0000 left"
    )


def test_pull_request_text_that_cannot_be_published_rejects_the_run(
    tmp_path: Path, pipeline: Pipeline, source: tuple[Path, str]
) -> None:
    _, sha = source
    pipeline.agent = [fixes(pr_title="Fix the boundary @everyone should see")]

    manifest, _store = _run(tmp_path, pipeline, sha)

    assert manifest.status == RunStatus.REJECTED
    assert manifest.reject_reason == (
        "the pull request text cannot be published: The pull request title mentions @everyone "
        "or @here"
    )
    assert manifest.preparation_fingerprint is None


def test_a_policy_trailer_goes_in_the_commit_message(
    tmp_path: Path,
    pipeline: Pipeline,
    source: tuple[Path, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, sha = source
    policy = _facts().ai_policy
    assert policy is not None
    monkeypatch.setattr(orchestrator_module, "_ai_policy", lambda _eligibility: policy)

    manifest, _store = _run(tmp_path, pipeline, sha)

    assert manifest.proposal is not None
    assert manifest.proposal.commit_message == (
        f"Fix documented boundary value\n\nAssisted-by: autocontribute {__version__}, gpt-5.6-sol"
    )


def test_the_daily_budget_skips_the_run_before_discovery(
    tmp_path: Path, pipeline: Pipeline
) -> None:
    config = _config(tmp_path, budget={"max_cost_usd_per_run": 10, "max_cost_usd_per_day": 2})

    class NoGitHubWork(FakeGitHub):
        def get_repository(self, full_name: str) -> RepositoryInfo:
            raise AssertionError("a run over the daily budget must not reach GitHub")

    manifest, _store = _run(
        tmp_path,
        pipeline,
        "a" * 40,
        config=config,
        github=NoGitHubWork(_issue(), _repository("a" * 40), "a" * 40),
    )

    assert manifest.status == RunStatus.SKIPPED
    assert (manifest.skip_reason or "").startswith("daily budget: ")


def test_models_are_resolved_once_from_the_keys_set_when_the_orchestrator_starts(
    tmp_path: Path, pipeline: Pipeline, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(tmp_path)
    github = FakeGitHub(_issue(assigned=True), _repository("a" * 40), "a" * 40)
    with Orchestrator(
        config,
        store=RunStore(config.storage.path),
        github=github,  # type: ignore[arg-type]
        provider_factory=pipeline.provider,
    ) as orchestrator:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic-test-key-placeholder")
        manifest = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )

    assert manifest.models is not None and manifest.models.agent == "gpt-5.6-sol"


def test_orchestrator_needs_a_model_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    with pytest.raises(ConfigurationError, match="ANTHROPIC_API_KEY or OPENAI_API_KEY"):
        Orchestrator(
            _config(tmp_path),
            github=FakeGitHub(_issue(), _repository("a" * 40), "a" * 40),  # type: ignore[arg-type]
        )


def test_clone_uses_the_exact_sha_used_for_repository_policy_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pipeline: Pipeline,
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
            return super().get_file(repository, path, ref=ref, max_bytes=max_bytes)

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

    manifest, _store = _run(
        tmp_path, pipeline, sha, github=TrackingGitHub(_issue(), _repository(sha), sha)
    )

    repository_policy_refs = {
        ref for repository, ref in policy_reads if repository == "example/project"
    }
    assert manifest.status == RunStatus.FAILED
    assert clone_refs == [sha]
    assert repository_policy_refs == {sha}


class NoGitHubWork:
    token = _GITHUB_TOKEN

    def __getattr__(self, name: str) -> object:
        raise AssertionError(f"unexpected GitHub access: {name}")


def test_breaker_blocks_before_github_or_model_work(tmp_path: Path, pipeline: Pipeline) -> None:
    config = _config(tmp_path)
    store = RunStore(config.storage.path)
    store.trip_circuit_breaker(
        source="test-signal",
        reason="maintainer requested a stop",
        trigger_hash="test-trigger",
    )

    with (
        Orchestrator(
            config,
            store=store,
            github=NoGitHubWork(),  # type: ignore[arg-type]
            provider_factory=pipeline.provider,
        ) as orchestrator,
        pytest.raises(StateError, match="Circuit breaker is tripped"),
    ):
        orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )

    assert store.list() == []
    assert pipeline.leftover_sweeps == []


@pytest.mark.parametrize("with_retry_authorization", [False, True])
def test_nonmanual_invocation_cannot_pin_or_authorize_an_issue_before_external_work(
    tmp_path: Path,
    pipeline: Pipeline,
    with_retry_authorization: bool,
) -> None:
    config = AutocontributeConfig.model_validate({"storage": {"path": tmp_path / "state"}})
    store = RunStore(config.storage.path)
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
            provider_factory=pipeline.provider,
        ) as orchestrator,
        pytest.raises(ValueError, match="explicit issue references require manual invocation mode"),
    ):
        orchestrator.run(
            issue_reference="example/project#42",
            invocation_mode=RunInvocationMode.SCHEDULED,
            retry_authorization=authorization,
        )

    assert store.list() == []


def test_nonmanual_invocation_cannot_supply_retry_authorization_without_an_issue(
    tmp_path: Path, pipeline: Pipeline
) -> None:
    config = AutocontributeConfig.model_validate({"storage": {"path": tmp_path / "state"}})
    store = RunStore(config.storage.path)

    with (
        Orchestrator(
            config,
            store=store,
            github=NoGitHubWork(),  # type: ignore[arg-type]
            provider_factory=pipeline.provider,
        ) as orchestrator,
        pytest.raises(ValueError, match="retry authorization requires an explicit issue reference"),
    ):
        orchestrator.run(
            invocation_mode=RunInvocationMode.SCHEDULED,
            retry_authorization=CandidateRetryAuthorization(
                actor="release-operator",
                reason="Reviewed the prior terminal outcome.",
            ),
        )

    assert store.list() == []


def test_run_recovers_stale_work_and_releases_singleton_lease(
    tmp_path: Path, pipeline: Pipeline
) -> None:
    config = _config(tmp_path)
    store = RunStore(config.storage.path)
    # Moments old: only the lease holder prepares runs, so the age of a run says nothing.
    abandoned = store.create_run()
    store.transition(abandoned, RunStatus.DISCOVERING, reason="worker started")

    current, _store = _run(
        tmp_path,
        pipeline,
        "a" * 40,
        config=config,
        github=FakeGitHub(_issue(assigned=True), _repository("a" * 40), "a" * 40),
    )

    recovered = store.get(abandoned.run_id)
    assert recovered.status == RunStatus.FAILED
    assert "previous worker stopped" in (recovered.error or "")
    assert current.status == RunStatus.SKIPPED
    lease = store.acquire_lease("autocontribute.run", "next-worker", ttl=timedelta(minutes=1))
    assert lease is not None
    assert store.release_lease("autocontribute.run", "next-worker", lease.generation)


def test_an_interrupted_run_fails_and_releases_its_issue_and_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pipeline: Pipeline
) -> None:
    def interrupted_clone(cls: type[RepositoryWorkspace], *_: object, **__: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(RepositoryWorkspace, "clone", classmethod(interrupted_clone))
    store = RunStore(_config(tmp_path).storage.path)
    issue = _issue()

    with pytest.raises(KeyboardInterrupt):
        _run(
            tmp_path,
            pipeline,
            "a" * 40,
            github=FakeGitHub(issue, _repository("a" * 40), "a" * 40),
        )

    [persisted] = store.list()
    assert persisted.status == RunStatus.FAILED
    assert persisted.candidate is not None
    assert persisted.error == "The run was interrupted before it finished"
    assert store.candidate_attempt_disposition(issue).state == CandidateAttemptState.AVAILABLE
    lease = store.acquire_lease("autocontribute.run", "next-worker", ttl=timedelta(minutes=1))
    assert lease is not None


def _take_over_run_lease(orchestrator: Orchestrator, store: RunStore) -> Lease:
    guard = orchestrator._lease_guard
    assert guard is not None
    current = guard.assert_owned()
    takeover = store.acquire_lease(
        "autocontribute.run",
        "takeover-worker",
        ttl=timedelta(minutes=5),
        now=current.expires_at,
    )
    assert takeover is not None
    assert takeover.generation > current.generation
    return takeover


def test_run_lease_takeover_during_github_read_stops_before_workspace_or_failure_write(
    tmp_path: Path, pipeline: Pipeline
) -> None:
    sha = "a" * 40
    config = _config(tmp_path)
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
    with Orchestrator(
        config,
        store=store,
        github=github,  # type: ignore[arg-type]
        provider_factory=pipeline.provider,
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
    assert pipeline.prepared == []
    assert not (store.workspaces_dir / persisted.run_id).exists()
    run_artifacts = store.runs_dir / persisted.run_id
    assert not (run_artifacts / "validation.json").exists()
    assert not (run_artifacts / "report.md").exists()


def test_run_lease_takeover_while_the_agent_works_writes_nothing_more(
    tmp_path: Path, pipeline: Pipeline, source: tuple[Path, str]
) -> None:
    _, sha = source
    config = _config(tmp_path)
    store = RunStore(config.storage.path)
    takeovers: list[Lease] = []
    running = Orchestrator(
        config,
        store=store,
        github=FakeGitHub(_issue(), _repository(sha), sha),  # type: ignore[arg-type]
        provider_factory=pipeline.provider,
    )

    def taken_over(checks: FakeChecks) -> SolverOutcome:
        takeovers.append(_take_over_run_lease(running, store))
        return fixes()(checks)

    pipeline.agent = [taken_over]
    with running, pytest.raises(StateError, match="ownership was lost"):
        running.run(issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL)

    [persisted] = store.list()
    assert persisted.status == RunStatus.IMPLEMENTING
    assert persisted.error is None
    run_artifacts = store.runs_dir / persisted.run_id
    assert not (run_artifacts / "validation.json").exists()
    assert not (run_artifacts / "contribution.patch").exists()
    assert store.release_lease(takeovers[0].name, takeovers[0].owner, takeovers[0].generation)


def test_ineligible_explicit_issue_skips_without_environment_or_model_work(
    tmp_path: Path, pipeline: Pipeline
) -> None:
    sha = "a" * 40

    manifest, _store = _run(
        tmp_path, pipeline, sha, github=FakeGitHub(_issue(assigned=True), _repository(sha), sha)
    )

    assert manifest.status == RunStatus.SKIPPED
    assert "already assigned" in (manifest.skip_reason or "")
    assert pipeline.prepared == []


def test_explicit_issue_in_a_held_repository_skips(tmp_path: Path, pipeline: Pipeline) -> None:
    store = RunStore(_config(tmp_path).storage.path)
    store.record_stop(
        CircuitBreakerTrigger(
            source="github_issue_discussion:example/project#40",
            reason="a maintainer comment turns away automated or AI contributions",
            trigger_hash="d" * 64,
            scope=StopScope.REPOSITORY,
            scope_key="example/project",
        )
    )

    manifest, _store = _run(tmp_path, pipeline, "a" * 40)

    assert manifest.status == RunStatus.SKIPPED
    assert "the repository is held" in (manifest.skip_reason or "")
    assert pipeline.prepared == []


def test_run_deletes_workspaces_left_by_finished_runs(tmp_path: Path, pipeline: Pipeline) -> None:
    sha = "a" * 40
    store = RunStore(_config(tmp_path).storage.path)
    finished = store.create_run()
    store.transition(finished, RunStatus.FAILED, reason="an earlier run failed")
    (store.workspace_dir(finished.run_id) / "repository").mkdir()

    manifest, _store = _run(
        tmp_path, pipeline, sha, github=FakeGitHub(_issue(assigned=True), _repository(sha), sha)
    )

    assert manifest.status == RunStatus.SKIPPED
    assert not (store.workspaces_dir / finished.run_id).exists()
    assert (store.runs_dir / finished.run_id / "manifest.json").is_file()
    assert pipeline.leftover_sweeps == [frozenset()]


def test_candidate_claim_failure_cannot_attach_candidate_through_failure_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pipeline: Pipeline,
) -> None:
    sha = "a" * 40
    config = _config(tmp_path)
    store = RunStore(config.storage.path)

    def fail_claim(*_: object, **__: object) -> None:
        raise StateError("candidate claim failed before durable attachment")

    monkeypatch.setattr(store, "claim_candidate", fail_claim)
    with Orchestrator(
        config,
        store=store,
        github=FakeGitHub(_issue(), _repository(sha), sha),  # type: ignore[arg-type]
        provider_factory=pipeline.provider,
    ) as orchestrator:
        manifest = orchestrator.run(
            issue_reference="example/project#42",
            invocation_mode=RunInvocationMode.MANUAL,
        )

    durable = store.get(manifest.run_id)
    assert manifest.status == RunStatus.FAILED
    assert manifest.candidate is None
    assert manifest.repository is None
    assert durable.status == RunStatus.FAILED
    assert durable.candidate is None
    assert durable.repository is None
    assert pipeline.prepared == []


def test_unchanged_explicit_issue_is_deferred_before_eligibility_or_model_work(
    tmp_path: Path, pipeline: Pipeline
) -> None:
    sha = "a" * 40
    config = _config(tmp_path)
    store = RunStore(config.storage.path)
    github = CountingGitHub(_issue(assigned=True), _repository(sha), sha)

    with Orchestrator(
        config,
        store=store,
        github=github,  # type: ignore[arg-type]
        provider_factory=pipeline.provider,
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
    tmp_path: Path, pipeline: Pipeline
) -> None:
    sha = "a" * 40
    config = _config(tmp_path)
    store = RunStore(config.storage.path)
    now = datetime.now(UTC)
    claimed = _issue().model_copy(
        update={
            "comments": 1,
            "discussion": [
                IssueComment(
                    author="contributor",
                    author_association="NONE",
                    body="I'm working on this.",
                    html_url="https://github.com/example/project/issues/42#issuecomment-1",
                    created_at=now,
                    updated_at=now,
                )
            ],
        }
    )
    github = DiscoveryGitHub(claimed, _repository(sha), sha)

    with Orchestrator(
        config,
        store=store,
        github=github,  # type: ignore[arg-type]
        provider_factory=pipeline.provider,
    ) as orchestrator:
        prior = orchestrator.run(
            issue_reference="example/project#42", invocation_mode=RunInvocationMode.MANUAL
        )
        discovered = orchestrator.run(invocation_mode=RunInvocationMode.SCHEDULED)

    assert prior.status == RunStatus.SKIPPED
    assert discovered.status == RunStatus.SKIPPED
    assert discovered.candidate is None
    assert discovered.skip_reason == (
        "No candidate is currently available: 1 unchanged issue revision was deferred after a "
        "prior skipped, rejected, or cancelled run."
    )
    assert github.search_calls == 1
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
    tmp_path: Path, pipeline: Pipeline
) -> None:
    sha = "a" * 40
    config = _config(tmp_path)
    store = RunStore(config.storage.path)
    github = CountingGitHub(_issue(assigned=True), _repository(sha), sha)

    with Orchestrator(
        config,
        store=store,
        github=github,  # type: ignore[arg-type]
        provider_factory=pipeline.provider,
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
    events = store.events(retried.run_id)
    override = next(event for event in events if event["event_type"] == "candidate.retry_override")
    details = json.loads(override["details"])
    assert details["prior_run_id"] == first.run_id
    assert details["actor"] == "release-operator"
    assert details["reason"] == "Reviewed the prior skip after updating the model instructions."
    assert len(details["authorization_id"]) == 32
    assert set(details["authorization_id"]) <= set("0123456789abcdef")


def test_explicit_issue_cannot_bypass_repository_allowlist(
    tmp_path: Path, pipeline: Pipeline
) -> None:
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["approved/project"]},
            "storage": {"path": tmp_path / "state"},
        }
    )

    manifest, _store = _run(tmp_path, pipeline, "a" * 40, config=config)

    assert manifest.status == RunStatus.FAILED
    assert "not in github.repositories" in (manifest.error or "")
    assert pipeline.prepared == []
