from __future__ import annotations

import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from autocontribute.config import AutocontributeConfig
from autocontribute.domain import (
    CriticReview,
    FileEdit,
    GateResult,
    IssueCandidate,
    PatchProposal,
    QualityReport,
    RepositoryInfo,
    ReviewScores,
    RunStatus,
)
from autocontribute.exceptions import PolicyError
from autocontribute.publication import Publisher, approve_run
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


def _ready_run(tmp_path: Path) -> tuple[AutocontributeConfig, RunStore, str, IssueCandidate]:
    config = AutocontributeConfig.model_validate({"storage": {"path": tmp_path / "state"}})
    store = RunStore(config.storage.path)
    run = store.create_run()
    source = tmp_path / "source"
    source.mkdir()
    _git(source, "init", "--quiet")
    _git(source, "config", "user.name", "Fixture")
    _git(source, "config", "user.email", "fixture@example.invalid")
    (source / "fix.py").write_text("answer = 1\n", encoding="utf-8")
    _git(source, "add", ".")
    _git(source, "commit", "--quiet", "-m", "base")
    sha = _git(source, "rev-parse", "HEAD")
    workspace = RepositoryWorkspace.clone(
        str(source),
        sha,
        store.workspace_dir(run.run_id) / "repository",
        allow_local_source=True,
    )
    edit = FileEdit(
        operation="replace",
        path="fix.py",
        find="answer = 1\n",
        replace="answer = 2\n",
        content=None,
        rationale="Resolve the issue.",
    )
    workspace.apply_edit(edit)
    patch = workspace.diff()
    store.write_artifact(run.run_id, "contribution.patch", patch)
    now = datetime.now(UTC)
    issue = IssueCandidate(
        repository="example/project",
        number=42,
        title="Correct the answer",
        body="The documented answer should be 2.",
        html_url="https://github.com/example/project/issues/42",
        state="open",
        author="maintainer",
        labels=["help wanted"],
        assignees=[],
        comments=1,
        created_at=now - timedelta(days=5),
        updated_at=now,
    )
    repository = RepositoryInfo(
        full_name="example/project",
        html_url="https://github.com/example/project",
        clone_url="https://github.com/example/project.git",
        default_branch="main",
        stars=10_000,
        archived=False,
        disabled=False,
        private=False,
        pushed_at=now,
        license_spdx="MIT",
    )
    proposal = PatchProposal(
        summary="Correct the answer.",
        edits=[edit],
        validation_commands=["python -m pytest"],
        commit_message="Correct documented answer",
        pull_request_title="Correct documented answer",
        pull_request_body=f"Fixes #42.\n\n---\n\n{config.policy.ai_disclosure}",
        limitations=[],
    )
    review = CriticReview(
        verdict="approve",
        summary="Ready.",
        scores=ReviewScores(
            correctness=95,
            issue_alignment=95,
            tests=95,
            repository_conventions=95,
            diff_hygiene=95,
            maintainer_clarity=95,
        ),
        blocking_findings=[],
        non_blocking_findings=[],
        issue_requirements_met=["answer is 2"],
        issue_requirements_missing=[],
        test_evidence_assessment="Passed.",
        maintainer_perspective="Ready.",
    )
    run.candidate = issue
    run.repository = repository
    run.base_sha = sha
    run.proposal = proposal
    run.quality = QualityReport(
        ready=True,
        readiness_score=95,
        gates=[GateResult(gate="fixture", passed=True, evidence="passed")],
        review=review,
        changed_files=1,
        changed_lines=2,
    )
    run.status = RunStatus.READY_FOR_APPROVAL
    store.save(run, event="fixture.ready", details={})
    approve_run(
        config,
        store,
        run.run_id,
        actor="octocat",
        attestation="I reviewed the exact contribution.",
    )
    return config, store, run.run_id, issue


class FakePublishingGitHub:
    token = "not-a-real-token"

    def __init__(
        self,
        issue: IssueCandidate,
        sha: str,
        *,
        login: str = "octocat",
        existing_pr: str | None = None,
        branch_sha: str | None = None,
    ) -> None:
        self.issue = issue
        self.sha = sha
        self.login = login
        self.existing_pr = existing_pr
        self.branch_sha = branch_sha
        self.mutated = False

    def authenticated_login(self) -> str:
        return self.login

    def find_pull_request(self, repository: str, *, head: str) -> str | None:
        return self.existing_pr

    def authored_pull_requests(self, *args, **kwargs) -> list[str]:  # type: ignore[no-untyped-def]
        return []

    def get_issue(self, repository: str, number: int) -> IssueCandidate:
        return self.issue

    def search_competing_pull_requests(self, repository: str, issue_number: int) -> list[str]:
        return []

    def default_branch_sha(self, repository: str, branch: str) -> str:
        return self.sha

    def ensure_fork(self, repository: str, login: str) -> str:
        self.mutated = True
        return f"{login}/project"

    def ref_sha(self, repository: str, ref: str) -> str | None:
        return self.branch_sha

    def create_pull_request(self, *args, **kwargs) -> str:  # type: ignore[no-untyped-def]
        self.mutated = True
        return "https://github.com/example/project/pull/7"


def test_publisher_commits_and_opens_exact_approved_artifact(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    publisher = Publisher(config, store, github)  # type: ignore[arg-type]
    pushes: list[tuple[str, str]] = []
    monkeypatch.setattr(publisher, "_wait_for_fork", lambda *args: None)
    monkeypatch.setattr(
        publisher,
        "_push",
        lambda workspace, fork, branch: pushes.append((fork, branch)),
    )

    published = publisher.publish(run_id)

    assert published.status == RunStatus.PR_OPEN
    assert published.pull_request_url == "https://github.com/example/project/pull/7"
    assert published.commit_sha
    assert pushes == [("octocat/project", published.branch_name)]
    assert publisher.publish(run_id).pull_request_url == published.pull_request_url


def test_base_drift_stops_before_any_github_mutation(tmp_path: Path) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    github = FakePublishingGitHub(issue, "b" * 40)
    publisher = Publisher(config, store, github)  # type: ignore[arg-type]

    with pytest.raises(PolicyError, match="base branch moved"):
        publisher.publish(run_id)

    assert not github.mutated


def test_authenticated_account_drift_invalidates_human_approval(tmp_path: Path) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    github = FakePublishingGitHub(issue, manifest.base_sha or "", login="different-user")

    with pytest.raises(PolicyError, match="authenticated GitHub account differs"):
        Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert not github.mutated


@pytest.mark.parametrize(
    ("change", "value"),
    [("base_branch", "next"), ("draft", True)],
)
def test_publication_behavior_drift_invalidates_human_approval(
    tmp_path: Path,
    change: str,
    value: object,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    if change == "base_branch":
        assert manifest.repository is not None
        manifest.repository.default_branch = str(value)
        store.save(manifest, event="fixture.base_branch_changed", details={})
    else:
        config.publishing.draft = bool(value)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")

    with pytest.raises(PolicyError, match="exact publication manifest"):
        Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert not github.mutated


def test_auto_mode_publishes_without_human_approval(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    manifest.approval = None
    manifest.status = RunStatus.READY_FOR_APPROVAL
    store.save(manifest, event="fixture.auto", details={})
    config.publishing.mode = "auto"
    monkeypatch.setenv(config.publishing.auto_publish_env, "1")
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    publisher = Publisher(config, store, github)  # type: ignore[arg-type]
    monkeypatch.setattr(publisher, "_wait_for_fork", lambda *args: None)
    monkeypatch.setattr(publisher, "_push", lambda *args: None)

    published = publisher.publish(run_id)

    assert published.status == RunStatus.PR_OPEN
    assert published.pull_request_url == "https://github.com/example/project/pull/7"


def test_retry_with_stored_commit_fails_if_committed_workspace_is_missing(
    tmp_path: Path,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    manifest.commit_sha = "c" * 40
    store.save(manifest, event="fixture.commit_stored", details={})
    workspace = store.workspace_dir(run_id) / "repository"
    shutil.rmtree(workspace)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")

    with pytest.raises(PolicyError, match="stored commit is missing"):
        Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert not workspace.exists()
    assert not github.mutated


def test_existing_pr_without_stored_commit_is_not_reconciled(tmp_path: Path) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    github = FakePublishingGitHub(
        issue,
        manifest.base_sha or "",
        existing_pr="https://github.com/example/project/pull/7",
    )

    with pytest.raises(PolicyError, match="without a stored commit SHA"):
        Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert store.get(run_id).status == RunStatus.APPROVED


def test_existing_pr_with_mismatched_remote_commit_is_not_reconciled(tmp_path: Path) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    manifest.commit_sha = "c" * 40
    store.save(manifest, event="fixture.commit_stored", details={})
    github = FakePublishingGitHub(
        issue,
        manifest.base_sha or "",
        existing_pr="https://github.com/example/project/pull/7",
        branch_sha="d" * 40,
    )

    with pytest.raises(PolicyError, match="does not match the stored contribution commit"):
        Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert store.get(run_id).status == RunStatus.APPROVED


def test_existing_pr_with_exact_remote_commit_is_reconciled(tmp_path: Path) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    manifest.commit_sha = "c" * 40
    store.save(manifest, event="fixture.commit_stored", details={})
    github = FakePublishingGitHub(
        issue,
        manifest.base_sha or "",
        existing_pr="https://github.com/example/project/pull/7",
        branch_sha=manifest.commit_sha,
    )

    published = Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert published.status == RunStatus.PR_OPEN
    assert published.pull_request_url == "https://github.com/example/project/pull/7"
    assert not github.mutated
