from __future__ import annotations

import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from autocontribute.config import AutocontributeConfig
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
from autocontribute.orchestrator import Orchestrator
from autocontribute.providers import ModelResult, ModelUsage
from autocontribute.repository import RepositoryWorkspace
from autocontribute.store import RunStore


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

    def get_file(self, repository: str, path: str, *, ref: str | None = None) -> str | None:
        return "Run the project tests." if path == "CONTRIBUTING.md" else None

    def search_competing_pull_requests(self, repository: str, issue_number: int) -> list[str]:
        return []

    def default_branch_sha(self, repository: str, branch: str) -> str:
        return self.sha


class FixedProvider:
    def __init__(self, output: Any, model: str) -> None:
        self.output = output
        self.model = model
        self.calls = 0

    def generate(self, **_: object) -> ModelResult[Any]:
        self.calls += 1
        return ModelResult(
            output=self.output,
            response_id=f"response-{self.model}-{self.calls}",
            model=self.model,
            usage=ModelUsage(input_tokens=10, output_tokens=5, total_tokens=15),
        )


class PassingSandbox:
    def run(self, workspace: RepositoryWorkspace, command: str) -> CommandResult:
        # A reproduction is arbitrary repository code and may dirty its checkout. The orchestrator
        # must isolate this mutation from the workspace that becomes the contribution patch.
        (workspace.path / "baseline-generated.txt").write_text("discard me\n", encoding="utf-8")
        return CommandResult(
            command=command,
            exit_code=1,
            duration_seconds=0.1,
            stdout="",
            stderr="AssertionError",
        )

    def run_all(
        self,
        workspace: RepositoryWorkspace,
        commands: list[str],
        *,
        stop_on_failure: bool = True,
    ) -> list[CommandResult]:
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


def _providers() -> dict[str, FixedProvider]:
    plan = ContributionPlan(
        decision="proceed",
        decision_reason="The requested bug fix is narrow and testable.",
        contribution_kind="bugfix",
        issue_understanding="Return the documented boundary value.",
        acceptance_criteria=["value() returns 2"],
        implementation_steps=["Correct the returned value", "Run the focused test"],
        files_to_read=["app.py"],
        reproduction_command="python -c 'from app import value; assert value() == 2'",
        validation_commands=["python -m pytest"],
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
        validation_commands=["python -m pytest"],
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
        "scout": FixedProvider(plan, "scout-model"),
        "builder": FixedProvider(proposal, "builder-model"),
        "critic": FixedProvider(review, "critic-model"),
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
            "storage": {"path": tmp_path / "state"},
        }
    )
    store = RunStore(config.storage.path)
    github = FakeGitHub(_issue(), _repository(sha), sha)

    with Orchestrator(
        config,
        store=store,
        github=github,  # type: ignore[arg-type]
        providers=_providers(),  # type: ignore[arg-type]
        sandbox=PassingSandbox(),  # type: ignore[arg-type]
    ) as orchestrator:
        manifest = orchestrator.run(issue_reference="example/project#42")

    assert manifest.status == RunStatus.READY_FOR_APPROVAL
    assert manifest.quality and manifest.quality.ready
    assert manifest.model_calls == 3
    patch = (store.artifact_dir(manifest.run_id) / "contribution.patch").read_text()
    assert "+    return 2" in patch
    assert "baseline-generated" not in patch
    assert config.policy.ai_disclosure in manifest.proposal.pull_request_body  # type: ignore[union-attr]
    assert (store.artifact_dir(manifest.run_id) / "report.md").is_file()


def test_ineligible_explicit_issue_skips_without_spending_model_tokens(tmp_path: Path) -> None:
    sha = "a" * 40
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
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
        manifest = orchestrator.run(issue_reference="example/project#42")

    assert manifest.status == RunStatus.SKIPPED
    assert "already assigned" in (manifest.skip_reason or "")
    assert all(provider.calls == 0 for provider in providers.values())


def test_explicit_issue_cannot_bypass_repository_allowlist(tmp_path: Path) -> None:
    sha = "a" * 40
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["approved/project"]},
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
        manifest = orchestrator.run(issue_reference="example/project#42")

    assert manifest.status == RunStatus.FAILED
    assert "not in github.repositories" in (manifest.error or "")
    assert all(provider.calls == 0 for provider in providers.values())
