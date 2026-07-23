from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest

import autocontribute.publication as publication_module
from autocontribute.config import (
    CLA_ATTESTATION_STATEMENT,
    DCO_ATTESTATION_STATEMENT,
    AutocontributeConfig,
    LegalAttestation,
    ModelPricing,
)
from autocontribute.coordination import LeaseHeartbeatGuard
from autocontribute.deployment import compute_deployment_fingerprint
from autocontribute.discovery import DiscoveryService, apply_legal_commit_message
from autocontribute.domain import (
    CommandResult,
    CriticReview,
    FileEdit,
    GateResult,
    IssueCandidate,
    IssueComment,
    PatchProposal,
    QualityReport,
    RepositoryInfo,
    ReviewScores,
    RunManifest,
    RunStatus,
)
from autocontribute.evaluation import EvaluationSummary
from autocontribute.exceptions import (
    AutomaticRolloutBlocked,
    GitHubError,
    PolicyError,
    PublicationResumeRequired,
    StateError,
)
from autocontribute.github import (
    CheckRunDetails,
    CommitStatusDetails,
    ForkIdentity,
    GitHubComment,
    PullRequestCommit,
    PullRequestDetails,
    PullRequestReview,
    PullRequestTimeline,
    RepositoryIdentity,
)
from autocontribute.preparation import (
    compute_preparation_config_fingerprint,
    compute_preparation_fingerprint,
    render_validation_artifact,
)
from autocontribute.publication import (
    Publisher,
    approve_run,
    build_approval_review,
    validate_publication_text,
)
from autocontribute.repository import RepositoryWorkspace
from autocontribute.rollout import RolloutGate, RolloutSummary
from autocontribute.store import RunStore
from autocontribute.upstream_outcomes import UpstreamGateSummary, UpstreamPublicationScope


def _git(repository: Path, *arguments: str) -> str:
    # Keep commit fixtures independent of developer Git configuration and environment-driven
    # attribution hooks. Publication uses the same isolated configuration boundary in production.
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", "/nonexistent"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
    }
    result = subprocess.run(
        ["git", "-c", "commit.gpgsign=false", *arguments],
        cwd=repository,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def test_publication_git_environment_has_a_non_shared_fallback_home(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("HOME", raising=False)
    monkeypatch.setenv("AUTOCONTRIBUTE_GITHUB_TOKEN", "must-not-be-inherited")

    environment = publication_module._git_environment()

    assert environment["HOME"] == "/nonexistent"
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
    assert environment["GIT_CONFIG_GLOBAL"] == "/dev/null"
    assert environment["GIT_TERMINAL_PROMPT"] == "0"
    assert "AUTOCONTRIBUTE_GITHUB_TOKEN" not in environment


class _FixtureEligibilityGitHub:
    def __init__(self, policy_text: str = "Contribution guidelines") -> None:
        self.policy_text = policy_text

    def search_competing_pull_requests(self, repository: str, issue_number: int) -> list[str]:
        return []

    def get_file(
        self,
        repository: str,
        path: str,
        *,
        ref: str,
        max_bytes: int = 1_000_000,
    ) -> str | None:
        del repository, ref, max_bytes
        return self.policy_text if path == "CONTRIBUTING.md" else None

    def default_branch_sha_if_exists(self, repository: str) -> str | None:
        del repository
        return "b" * 40


def _ready_run(
    tmp_path: Path,
    *,
    guarded_auto: bool = False,
    ready_for_review: bool = False,
    legal_policy: str | None = None,
) -> tuple[AutocontributeConfig, RunStore, str, IssueCandidate]:
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "validation": {"required_commands": {"example/project": ["python -m pytest"]}},
            "storage": {"path": tmp_path / "state"},
        }
    )
    if guarded_auto:
        _enable_guarded_auto_mode(config)
    elif ready_for_review:
        config.publishing.ready_for_review = True
    store = RunStore(config.storage.path)
    source = tmp_path / "source"
    source.mkdir()
    _git(source, "init", "--quiet")
    _git(source, "config", "user.name", "Fixture")
    _git(source, "config", "user.email", "fixture@example.invalid")
    (source / "fix.py").write_text("answer = 1\n", encoding="utf-8")
    _git(source, "add", ".")
    _git(source, "commit", "--quiet", "-m", "base")
    sha = _git(source, "rev-parse", "HEAD")
    now = datetime.now(UTC)
    issue = IssueCandidate(
        repository="example/project",
        number=42,
        title="Correct the answer",
        body=(
            "Steps to reproduce: evaluate the documented fixture. The actual answer is 1, but "
            "the expected answer is 2. Please add or preserve regression coverage for this bug. "
            * 3
        ),
        html_url="https://github.com/example/project/issues/42",
        state="open",
        author="maintainer",
        labels=["help wanted", "bug", "good first issue"],
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
    eligibility_github = _FixtureEligibilityGitHub(legal_policy or "Contribution guidelines")
    if legal_policy is not None:
        snapshot = DiscoveryService(  # type: ignore[arg-type]
            config,
            eligibility_github,
            store,
        ).policy_snapshot(repository, repository_ref=sha)
        requirements = set(snapshot.legal_requirements)
        attestation: dict[str, object] = {
            "repository": repository.full_name,
            "reviewed_repository_ref": snapshot.repository_ref,
            "reviewed_organization_policy_ref": snapshot.organization_ref_evidence,
            "legal_policy_sha256": snapshot.legal_policy_sha256,
            "legal_requirements": list(snapshot.legal_requirements),
            "attested_by": "octocat",
            "attested_at": "2026-07-22T12:00:00Z",
        }
        if "cla" in requirements:
            attestation["cla"] = {"statement": CLA_ATTESTATION_STATEMENT}
        if "dco" in requirements:
            config.identity.name = "Example Signer"
            config.identity.email = "signer@example.invalid"
            attestation["dco"] = {
                "statement": DCO_ATTESTATION_STATEMENT,
                "signoff_name": config.identity.name,
                "signoff_email": config.identity.email,
            }
        config.policy.legal_attestations = {
            "example/project": LegalAttestation.model_validate(attestation)
        }
        config = AutocontributeConfig.model_validate(config.model_dump(mode="python"))
        store = RunStore(config.storage.path)
    run = store.create_run(deployment_fingerprint=compute_deployment_fingerprint(config))
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
    run.eligibility = DiscoveryService(
        config,
        eligibility_github,  # type: ignore[arg-type]
        store,
    ).evaluate(issue, repository, repository_ref=sha)
    assert run.eligibility.eligible
    issue.score = run.eligibility.score
    issue.score_evidence = run.eligibility.evidence
    run.base_sha = sha
    proposal.commit_message = apply_legal_commit_message(
        config,
        run.eligibility,
        repository.full_name,
        proposal.commit_message,
    )
    run.proposal = proposal
    run.quality = QualityReport(
        ready=True,
        readiness_score=95,
        gates=[GateResult(gate="fixture", passed=True, evidence="passed")],
        review=review,
        changed_files=1,
        changed_lines=2,
    )
    run.patched_validation = [
        CommandResult(
            command="python -m pytest",
            exit_code=0,
            duration_seconds=1.0,
            stdout="1 passed",
            stderr="",
        )
    ]
    store.write_artifact(run.run_id, "validation.json", render_validation_artifact(run))
    run.preparation_config_fingerprint = compute_preparation_config_fingerprint(
        config,
        repository=issue.repository,
    )
    run.preparation_fingerprint = compute_preparation_fingerprint(run, diff=patch)
    run.status = RunStatus.READY_FOR_APPROVAL
    store.save(run, event="fixture.ready", details={})
    approval_review = build_approval_review(config, store, run.run_id, actor="octocat")
    approve_run(
        config,
        store,
        run.run_id,
        actor="octocat",
        attestation="I reviewed the exact contribution.",
        reviewed_fingerprint=approval_review.fingerprint,
    )
    return config, store, run.run_id, issue


class _FixtureRolloutCursorStore:
    def __init__(self, evaluation_cursor: str, outcome_cursor: str) -> None:
        self.evaluation_cursor = evaluation_cursor
        self.outcome_cursor = outcome_cursor

    def evaluation_corpus_cursor(self) -> str:
        return self.evaluation_cursor

    def upstream_outcome_corpus_cursor(
        self,
        deployment_fingerprint: str,
        publishing_login: str,
        publishing_api_origin: str,
        *,
        exclude_run_id: str | None = None,
    ) -> str:
        del deployment_fingerprint, publishing_login, publishing_api_origin, exclude_run_id
        return self.outcome_cursor


class _FixtureEvaluationGate:
    def __init__(self, summary: EvaluationSummary) -> None:
        self.result = summary

    def summary(self, *, deployment_fingerprint: str) -> EvaluationSummary:
        assert deployment_fingerprint == self.result.deployment_fingerprint
        return self.result


class _FixtureUpstreamGate:
    def __init__(self, summary: UpstreamGateSummary) -> None:
        self.result = summary

    def summary(
        self,
        scope: UpstreamPublicationScope,
        *,
        exclude_run_id: str | None = None,
    ) -> UpstreamGateSummary:
        del exclude_run_id
        assert scope == self.result.scope
        return self.result


class _FixtureRolloutGate:
    """Produce validated combined summaries while controlling semantic gate results."""

    def __init__(
        self,
        store: RunStore,
        *,
        evaluation_passed: bool = True,
        manual_passed: bool = True,
        automatic_passed: bool = True,
        evaluation_cursor: str | None = None,
        outcome_cursor: str | None = None,
    ) -> None:
        self.store = store
        self.evaluation_passed = evaluation_passed
        self.manual_passed = manual_passed
        self.automatic_passed = automatic_passed
        self.evaluation_cursor = evaluation_cursor
        self.outcome_cursor = outcome_cursor

    def summary(
        self,
        scope: UpstreamPublicationScope,
        *,
        exclude_run_id: str | None = None,
    ) -> RolloutSummary:
        evaluation_cursor = self.evaluation_cursor or self.store.evaluation_corpus_cursor()
        outcome_cursor = self.outcome_cursor or self.store.upstream_outcome_corpus_cursor(
            scope.deployment_fingerprint,
            scope.publishing_login,
            scope.publishing_api_origin,
            exclude_run_id=exclude_run_id,
        )
        evaluation = EvaluationSummary(
            deployment_fingerprint=scope.deployment_fingerprint,
            corpus_cursor=evaluation_cursor,
            total_cases=100,
            prepared_cases=20,
            accepted_as_is=20 if self.evaluation_passed else 19,
            correct_abstentions=80,
            incorrect_abstentions=0,
            safety_failures=0,
            accept_as_is_precision=1.0 if self.evaluation_passed else 0.95,
            shadow_gate_passed=self.evaluation_passed,
            gate_evidence=["fixture evaluation gate"],
        )
        upstream_passed = self.manual_passed and self.automatic_passed
        upstream = UpstreamGateSummary(
            scope=scope,
            corpus_cursor=outcome_cursor,
            decision_digest="a" * 64,
            exact_manual_publications=20 if self.manual_passed else 0,
            manual_cohort=(),
            prior_automatic=(),
            ambiguous=(),
            manual_cohort_passed=self.manual_passed,
            prior_automatic_passed=self.automatic_passed,
            gate_passed=upstream_passed,
            gate_evidence=("fixture upstream-outcome gate",),
        )
        cursor_store = _FixtureRolloutCursorStore(evaluation_cursor, outcome_cursor)
        return RolloutGate(
            cursor_store,  # type: ignore[arg-type]
            _FixtureEvaluationGate(evaluation),
            _FixtureUpstreamGate(upstream),
        ).summary(scope, exclude_run_id=exclude_run_id)


def _install_fixture_rollout_gate(
    monkeypatch: pytest.MonkeyPatch,
    *,
    evaluation_passed: bool = True,
    manual_passed: bool = True,
    automatic_passed: bool = True,
    evaluation_cursor: str | None = None,
    outcome_cursor: str | None = None,
) -> None:
    def for_store(cls: type[RolloutGate], store: RunStore) -> _FixtureRolloutGate:
        del cls
        return _FixtureRolloutGate(
            store,
            evaluation_passed=evaluation_passed,
            manual_passed=manual_passed,
            automatic_passed=automatic_passed,
            evaluation_cursor=evaluation_cursor,
            outcome_cursor=outcome_cursor,
        )

    monkeypatch.setattr(RolloutGate, "for_store", classmethod(for_store))


def _enable_guarded_auto_mode(config: AutocontributeConfig) -> None:
    pricing = ModelPricing(
        input_usd_per_million_tokens="1",
        output_usd_per_million_tokens="1",
    )
    config.models.scout.pricing = pricing
    config.models.builder.pricing = pricing
    config.models.critic.pricing = pricing
    config.models.scout.expected_response_model = config.models.scout.model
    config.models.builder.expected_response_model = config.models.builder.model
    config.models.critic.expected_response_model = config.models.critic.model
    config.models.scout.immutable_response_model_attested = True
    config.models.builder.immutable_response_model_attested = True
    config.models.critic.immutable_response_model_attested = True
    config.budget.max_model_cost_usd_per_run = Decimal("10")
    config.publishing.max_open_pull_requests = 1
    config.publishing.ready_for_review = True
    config.publishing.mode = "auto"


def _remove_human_publication_context(manifest) -> None:  # type: ignore[no-untyped-def]
    manifest.approval = None
    manifest.publishing_login = None
    manifest.publishing_api_origin = None
    manifest.commit_author_name = None
    manifest.commit_author_email = None
    manifest.commit_committer_name = None
    manifest.commit_committer_email = None
    manifest.publication_draft = None
    manifest.publication_ready_for_review = None


def _begin_review_publication(
    config: AutocontributeConfig,
    store: RunStore,
    manifest: RunManifest,
    *,
    bind_fork_identity: bool = True,
) -> RunManifest:
    """Create a genuine review-authorized SUBMITTING fixture through the durable ledger API."""

    assert manifest.candidate is not None
    assert manifest.publishing_login is not None
    assert manifest.publishing_api_origin is not None
    assert manifest.commit_author_name is not None
    assert manifest.commit_author_email is not None
    assert manifest.commit_committer_name is not None
    assert manifest.commit_committer_email is not None
    assert manifest.publication_draft is not None
    assert manifest.publication_ready_for_review is not None
    manifest.upstream_repository_id = 1001
    manifest.upstream_repository_node_id = "R_upstream_fixture"
    if bind_fork_identity:
        manifest.fork_repository_id = 2001
        manifest.fork_repository_node_id = "R_fork_fixture"
    store.save(
        manifest,
        event=(
            "fixture.remote_identity.bound"
            if bind_fork_identity
            else "fixture.upstream_identity.bound"
        ),
        details={},
    )
    return store.begin_publication(
        manifest,
        manifest.candidate.repository,
        branch_name=manifest.branch_name or f"autocontribute/issue-42-{manifest.run_id[:8]}",
        publishing_login=manifest.publishing_login,
        publishing_api_origin=manifest.publishing_api_origin,
        commit_author_name=manifest.commit_author_name,
        commit_author_email=manifest.commit_author_email,
        commit_committer_name=manifest.commit_committer_name,
        commit_committer_email=manifest.commit_committer_email,
        publication_draft=manifest.publication_draft,
        publication_ready_for_review=manifest.publication_ready_for_review,
        max_per_utc_day=config.publishing.max_new_pull_requests_per_day,
        repository_cooldown=timedelta(days=config.publishing.repository_cooldown_days),
    )


class FakePublishingGitHub:
    token = "not-a-real-token"
    api_origin = "https://api.github.com"

    def __init__(
        self,
        issue: IssueCandidate,
        sha: str,
        *,
        login: str = "octocat",
        existing_pr: str | None = None,
        branch_sha: str | None = None,
        policy_text: str = "Contribution guidelines",
    ) -> None:
        self.issue = issue
        self.sha = sha
        self.login = login
        self.existing_pr = existing_pr
        self.branch_sha = branch_sha
        self.policy_text = policy_text
        self.mutated = False
        self.calls: list[str] = []
        self.last_head = f"{login}:autocontribute/issue-42-fixture"
        self.pull_request_title = "Correct documented answer"
        self.pull_request_body = (
            "Fixes #42.\n\n---\n\nThis contribution was prepared autonomously by an AI "
            "agent. Its validation evidence comes from Autocontribute's configured "
            "automated checks; no human review is implied."
        )
        self.pull_request_draft = True
        self.pull_request_state = "open"
        self.pull_request_merged = False
        self.pull_request_base = "main"
        self.pull_request_base_sha = sha
        self.pull_request_head_repository = f"{login}/project"
        self.pull_request_head_sha = branch_sha
        self.pull_request_node_id = "PR_fixture_7"
        self.pull_request_updated_at = datetime.now(UTC)
        self.reviews: list[PullRequestReview] = []
        self.issue_comments: list[GitHubComment] = []
        self.review_comments: list[GitHubComment] = []
        self.check_runs: list[CheckRunDetails] = []
        self.commit_statuses: list[CommitStatusDetails] = []
        self.created_expected_head_sha: str | None = None
        self.created_pull_request_draft: bool | None = None
        self.upstream_repository_id = 1001
        self.upstream_repository_node_id = "R_upstream_fixture"
        self.fork_repository_id = 2001
        self.fork_repository_node_id = "R_fork_fixture"

    def authenticated_login(self) -> str:
        self.calls.append("authenticated_login")
        return self.login

    def find_pull_request(self, repository: str, *, head: str) -> str | None:
        self.calls.append("find_pull_request")
        self.last_head = head
        return self.existing_pr

    def get_pull_request(self, repository: str, number: int) -> PullRequestDetails:
        self.calls.append("get_pull_request")
        return self._pull_request_details(repository, number)

    def _pull_request_details(self, repository: str, number: int) -> PullRequestDetails:
        closed = self.pull_request_state == "closed"
        merged = self.pull_request_merged
        return PullRequestDetails(
            repository=repository,
            number=number,
            html_url=f"https://github.com/{repository}/pull/{number}",
            state=self.pull_request_state,
            draft=self.pull_request_draft,
            merged=merged,
            updated_at=self.pull_request_updated_at,
            merged_at=self.pull_request_updated_at if merged else None,
            closed_at=self.pull_request_updated_at if closed else None,
            merge_commit_sha="e" * 40 if merged else None,
            head_sha=self.pull_request_head_sha or self.branch_sha or "d" * 40,
            issue_comment_count=0,
            review_comment_count=0,
            commit_count=1,
            title=self.pull_request_title,
            body=self.pull_request_body,
            base_ref=self.pull_request_base,
            base_sha=self.pull_request_base_sha,
            head_ref=self.last_head.split(":", 1)[1],
            head_label=self.last_head,
            head_repository=self.pull_request_head_repository,
            node_id=self.pull_request_node_id,
        )

    def list_pull_request_commits(
        self,
        repository: str,
        number: int,
        *,
        expected_count: int,
        expected_head_sha: str,
        max_commits: int = 250,
    ) -> list[PullRequestCommit]:
        del repository, number, max_commits
        self.calls.append("list_pull_request_commits")
        assert expected_count == 1
        return [
            PullRequestCommit(
                position=1,
                sha=expected_head_sha,
                node_id=f"C_{expected_head_sha}",
                parent_shas=(self.pull_request_base_sha,),
            )
        ]

    def list_pull_request_reviews(
        self,
        repository: str,
        number: int,
        *,
        max_reviews: int = 500,
    ) -> list[PullRequestReview]:
        del repository, number, max_reviews
        self.calls.append("list_pull_request_reviews")
        return self.reviews

    def list_issue_comments(
        self,
        repository: str,
        number: int,
        *,
        expected_count: int | None = None,
        max_comments: int = 500,
    ) -> list[GitHubComment]:
        del repository, number, max_comments
        self.calls.append("list_issue_comments")
        assert expected_count == len(self.issue_comments)
        return self.issue_comments

    def list_review_comments(
        self,
        repository: str,
        number: int,
        *,
        expected_count: int | None = None,
        max_comments: int = 500,
    ) -> list[GitHubComment]:
        del repository, number, max_comments
        self.calls.append("list_review_comments")
        assert expected_count == len(self.review_comments)
        return self.review_comments

    def list_check_runs(
        self,
        repository: str,
        ref: str,
        *,
        max_check_runs: int = 500,
    ) -> list[CheckRunDetails]:
        del repository, ref, max_check_runs
        self.calls.append("list_check_runs")
        return self.check_runs

    def list_commit_statuses(
        self,
        repository: str,
        ref: str,
        *,
        max_statuses: int = 500,
    ) -> list[CommitStatusDetails]:
        del repository, ref, max_statuses
        self.calls.append("list_commit_statuses")
        return self.commit_statuses

    def get_pull_request_timeline(
        self,
        repository: str,
        number: int,
        *,
        max_events: int = 1_000,
    ) -> PullRequestTimeline:
        del repository, number, max_events
        self.calls.append("get_pull_request_timeline")
        return PullRequestTimeline(item_count=0, events=(), references=())

    def authored_pull_requests(self, *args, **kwargs) -> list[str]:  # type: ignore[no-untyped-def]
        self.calls.append("authored_pull_requests")
        return []

    def get_issue(self, repository: str, number: int) -> IssueCandidate:
        self.calls.append("get_issue")
        return self.issue

    def search_competing_pull_requests(self, repository: str, issue_number: int) -> list[str]:
        self.calls.append("search_competing_pull_requests")
        return []

    def get_repository(self, full_name: str) -> RepositoryInfo:
        self.calls.append("get_repository")
        return RepositoryInfo(
            full_name="example/project",
            html_url="https://github.com/example/project",
            clone_url="https://github.com/example/project.git",
            default_branch="main",
            stars=10_000,
            archived=False,
            disabled=False,
            private=False,
            pushed_at=datetime.now(UTC),
            license_spdx="MIT",
        )

    def get_repository_identity(self, full_name: str) -> RepositoryIdentity:
        self.calls.append("get_repository_identity")
        if full_name.casefold() == "example/project":
            return RepositoryIdentity(
                full_name="example/project",
                database_id=self.upstream_repository_id,
                node_id=self.upstream_repository_node_id,
            )
        return RepositoryIdentity(
            full_name=f"{self.login}/project",
            database_id=self.fork_repository_id,
            node_id=self.fork_repository_node_id,
        )

    def get_fork_identity(self, full_name: str) -> ForkIdentity:
        self.calls.append("get_fork_identity")
        return ForkIdentity(
            repository=RepositoryIdentity(
                full_name=full_name,
                database_id=self.fork_repository_id,
                node_id=self.fork_repository_node_id,
            ),
            parent=RepositoryIdentity(
                full_name="example/project",
                database_id=self.upstream_repository_id,
                node_id=self.upstream_repository_node_id,
            ),
        )

    def assert_repository_identity(
        self,
        full_name: str,
        *,
        expected_database_id: int,
        expected_node_id: str,
    ) -> RepositoryIdentity:
        self.calls.append("assert_repository_identity")
        if full_name.casefold() == "example/project":
            actual_id = self.upstream_repository_id
            actual_node_id = self.upstream_repository_node_id
            canonical_name = "example/project"
        else:
            actual_id = self.fork_repository_id
            actual_node_id = self.fork_repository_node_id
            canonical_name = f"{self.login}/project"
        if expected_database_id != actual_id or expected_node_id != actual_node_id:
            raise GitHubError("GitHub repository differs from its durable immutable identity")
        return RepositoryIdentity(
            full_name=canonical_name,
            database_id=actual_id,
            node_id=actual_node_id,
        )

    def get_file(
        self,
        repository: str,
        path: str,
        *,
        ref: str,
        max_bytes: int = 1_000_000,
    ) -> str | None:
        del repository, ref, max_bytes
        self.calls.append("get_file")
        return self.policy_text if path == "CONTRIBUTING.md" else None

    def default_branch_sha(self, repository: str, branch: str) -> str:
        self.calls.append("default_branch_sha")
        return self.sha

    def default_branch_sha_if_exists(self, repository: str) -> str | None:
        del repository
        self.calls.append("default_branch_sha_if_exists")
        return "b" * 40

    def ensure_fork(
        self,
        repository: str,
        login: str,
        *,
        before_mutation=None,  # type: ignore[no-untyped-def]
    ) -> str:
        if before_mutation is not None:
            before_mutation()
        self.calls.append("ensure_fork")
        self.mutated = True
        return f"{login}/project"

    def ref_sha(self, repository: str, ref: str) -> str | None:
        self.calls.append("ref_sha")
        return self.branch_sha

    def create_pull_request(self, *args, **kwargs) -> PullRequestDetails:  # type: ignore[no-untyped-def]
        before_mutation = kwargs.pop("before_mutation", None)
        if before_mutation is not None:
            before_mutation()
        self.calls.append("create_pull_request")
        self.created_expected_head_sha = kwargs.get("expected_head_sha")
        self.created_pull_request_draft = kwargs["draft"]
        self.last_head = kwargs["head"]
        self.pull_request_title = kwargs["title"]
        self.pull_request_body = kwargs["body"]
        self.pull_request_draft = kwargs["draft"]
        self.pull_request_base = kwargs["base"]
        self.pull_request_head_sha = self.branch_sha
        self.mutated = True
        return self._pull_request_details("example/project", 7)

    def close_pull_request(
        self,
        repository: str,
        number: int,
        *,
        expected_node_id: str,
        expected_head_repository: str,
        expected_head_ref: str,
        expected_head_sha: str,
        before_observation=None,  # type: ignore[no-untyped-def]
        before_mutation=None,  # type: ignore[no-untyped-def]
    ) -> PullRequestDetails:
        self.calls.append("close_pull_request")
        if before_observation is not None:
            before_observation()
        current = self._pull_request_details(repository, number)
        assert current.node_id == expected_node_id
        assert current.head_repository.casefold() == expected_head_repository.casefold()
        assert current.head_ref == expected_head_ref
        assert current.head_sha.casefold() == expected_head_sha.casefold()
        assert not current.merged
        if self.pull_request_state != "closed":
            if before_mutation is not None:
                before_mutation()
            self.pull_request_state = "closed"
            self.mutated = True
        return self._pull_request_details(repository, number)

    def mark_pull_request_ready_for_review(
        self,
        repository: str,
        number: int,
        *,
        expected_url: str,
        expected_node_id: str,
        expected_head_repository: str,
        expected_head_ref: str,
        expected_head_sha: str,
        before_observation=None,  # type: ignore[no-untyped-def]
        before_mutation=None,  # type: ignore[no-untyped-def]
    ) -> PullRequestDetails:
        if before_observation is not None:
            before_observation()
        current = self._pull_request_details(repository, number)
        assert current.html_url == expected_url
        assert current.node_id == expected_node_id
        assert current.head_repository.casefold() == expected_head_repository.casefold()
        assert current.head_ref == expected_head_ref
        assert current.head_sha.casefold() == expected_head_sha.casefold()
        assert current.state == "open" and not current.merged
        if before_mutation is not None:
            before_mutation()
        self.calls.append("mark_pull_request_ready_for_review")
        self.pull_request_draft = False
        self.pull_request_updated_at = datetime.now(UTC)
        self.mutated = True
        return self._pull_request_details(repository, number)


def _strand_automatic_publication_after_gate_hold(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[AutocontributeConfig, RunStore, str, FakePublishingGitHub, Publisher]:
    """Crash after the dual-cursor hold is durable but before any GitHub mutation."""

    config, store, run_id, issue = _ready_run(tmp_path, guarded_auto=True)
    manifest = store.get(run_id)
    _remove_human_publication_context(manifest)
    manifest.status = RunStatus.READY_FOR_APPROVAL
    store.save(manifest, event="fixture.auto", details={})
    monkeypatch.setenv(config.publishing.auto_publish_env, "1")
    _install_fixture_rollout_gate(monkeypatch)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    publisher = Publisher(config, store, github)  # type: ignore[arg-type]
    original_find = github.find_pull_request

    def crash_after_hold(repository: str, *, head: str) -> str | None:
        del repository, head
        github.calls.append("find_pull_request")
        raise RuntimeError("simulated crash after rollout hold")

    monkeypatch.setattr(github, "find_pull_request", crash_after_hold)
    with pytest.raises(RuntimeError, match="crash after rollout hold"):
        publisher.publish(run_id)
    monkeypatch.setattr(github, "find_pull_request", original_find)

    assert store.get(run_id).status == RunStatus.SUBMITTING
    assert store.publication_gate_hold(run_id) is not None
    assert not github.mutated
    github.calls.clear()
    return config, store, run_id, github, publisher


def test_publisher_commits_and_opens_exact_approved_artifact(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    publisher = Publisher(config, store, github)  # type: ignore[arg-type]
    pushes: list[tuple[str, str, str]] = []

    def push(
        workspace: Path,
        fork: str,
        branch: str,
        commit_sha: str,
        *,
        before_mutation,  # type: ignore[no-untyped-def]
    ) -> None:
        before_mutation()
        del workspace
        github.branch_sha = commit_sha
        pushes.append((fork, branch, commit_sha))

    monkeypatch.setattr(publisher, "_wait_for_fork", lambda *args: None)
    monkeypatch.setattr(publisher, "_push", push)

    published = publisher.publish(run_id)

    assert published.status == RunStatus.PR_OPEN
    assert published.pull_request_url == "https://github.com/example/project/pull/7"
    assert published.commit_sha
    assert pushes == [("octocat/project", published.branch_name, published.commit_sha)]
    assert github.created_expected_head_sha == published.commit_sha
    event_types = [event["event_type"] for event in store.events(run_id)]
    assert event_types.index("publication.reserved") < event_types.index(
        "pull_request.creation.started"
    )
    assert publisher.publish(run_id).pull_request_url == published.pull_request_url


def test_publisher_commits_exact_authorized_dco_trailer(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    policy = (
        "All commits must include a Signed-off-by line under the Developer Certificate of Origin."
    )
    config, store, run_id, issue = _ready_run(tmp_path, legal_policy=policy)
    manifest = store.get(run_id)
    assert manifest.proposal is not None
    expected_message = (
        "Correct documented answer\n\nSigned-off-by: Example Signer <signer@example.invalid>"
    )
    assert manifest.proposal.commit_message == expected_message
    github = FakePublishingGitHub(
        issue,
        manifest.base_sha or "",
        policy_text=policy,
    )
    publisher = Publisher(config, store, github)  # type: ignore[arg-type]

    def push(
        workspace: Path,
        fork: str,
        branch: str,
        commit_sha: str,
        *,
        before_mutation,  # type: ignore[no-untyped-def]
    ) -> None:
        before_mutation()
        del workspace, fork, branch
        github.branch_sha = commit_sha

    monkeypatch.setattr(publisher, "_wait_for_fork", lambda *args: None)
    monkeypatch.setattr(publisher, "_push", push)

    published = publisher.publish(run_id)

    assert published.commit_sha is not None
    committed_message = _git(
        store.workspace_dir(run_id) / "repository",
        "show",
        "--no-patch",
        "--format=%B",
        published.commit_sha,
    )
    assert committed_message == expected_message


def test_workspace_reconstruction_rejects_stored_cross_origin_clone_before_git(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    assert manifest.repository is not None
    manifest.repository.clone_url = "https://attacker.invalid/example/project.git"
    workspace_path = store.workspace_dir(run_id) / "repository"
    shutil.rmtree(workspace_path)
    clone_called = False

    def unsafe_clone(*args: object, **kwargs: object) -> RepositoryWorkspace:
        nonlocal clone_called
        clone_called = True
        raise AssertionError("Git clone must not run for cross-origin durable metadata")

    monkeypatch.setattr(RepositoryWorkspace, "clone", unsafe_clone)
    publisher = Publisher(
        config,
        store,
        FakePublishingGitHub(issue, manifest.base_sha or ""),  # type: ignore[arg-type]
    )
    patch = (store.artifact_dir(run_id) / "contribution.patch").read_bytes()

    with pytest.raises(PolicyError, match="outside the configured GitHub origin"):
        publisher._prepare_workspace(manifest, workspace_path, patch)

    assert not clone_called


def test_durable_daily_reservation_blocks_remote_mutation(tmp_path: Path) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    capacity_run = store.create_run()
    store.reserve_publication(
        capacity_run.run_id,
        "other/project",
        max_per_utc_day=config.publishing.max_new_pull_requests_per_day,
        repository_cooldown=timedelta(days=config.publishing.repository_cooldown_days),
    )
    manifest = store.get(run_id)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")

    with pytest.raises(StateError, match="Daily publication reservation limit"):
        Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert store.get(run_id).status == RunStatus.APPROVED
    assert "ensure_fork" not in github.calls
    assert not github.mutated


def test_publisher_rejects_patch_that_differs_from_preparation_seal(tmp_path: Path) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    store.write_artifact(run_id, "contribution.patch", "tampered patch\n")

    with pytest.raises(PolicyError, match="Preparation fingerprint"):
        Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert github.calls == []
    assert not github.mutated


def test_publisher_rejects_run_from_another_deployment(tmp_path: Path) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    manifest.deployment_fingerprint = "0" * 64
    store.save(manifest, event="fixture.deployment_changed", details={})
    github = FakePublishingGitHub(issue, manifest.base_sha or "")

    with pytest.raises(PolicyError, match="differs from its immutable creation evidence"):
        Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert github.calls == []
    assert not github.mutated


def test_publisher_rejects_validation_artifact_that_differs_from_manifest(tmp_path: Path) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    store.write_artifact(
        run_id,
        "validation.json",
        render_validation_artifact(manifest).replace("1 passed", "untrusted replacement"),
    )

    with pytest.raises(PolicyError, match="durable command evidence"):
        Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert github.calls == []
    assert not github.mutated


def test_publisher_requires_exact_current_ai_disclosure(tmp_path: Path) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    config.policy.ai_disclosure = "Current operator-configured AI disclosure."

    with pytest.raises(PolicyError, match="configuration changed"):
        Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert github.calls == []
    assert not github.mutated


@pytest.mark.parametrize(
    "drift",
    ["commands", "quality", "policy", "allowlist", "sandbox", "publishing"],
)
def test_preparation_configuration_drift_stops_before_github_work(
    tmp_path: Path,
    drift: str,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    if drift == "commands":
        config.validation.required_commands["example/project"] = ["python -m pytest -q"]
    elif drift == "quality":
        config.quality.max_changed_lines += 1
    elif drift == "policy":
        config.policy.allow_dependency_changes = True
    elif drift == "allowlist":
        config.github.repositories = []
    elif drift == "sandbox":
        config.sandbox.command_timeout_seconds += 1
    else:
        config.publishing.branch_prefix = "different-prefix"

    with pytest.raises(PolicyError, match=r"configuration|allowlist"):
        Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert github.calls == []
    assert not github.mutated


def test_ai_disclosure_hidden_in_html_comment_is_rejected(tmp_path: Path) -> None:
    config, store, run_id, _ = _ready_run(tmp_path)
    manifest = store.get(run_id)
    assert manifest.proposal is not None
    manifest.proposal.pull_request_body = f"Fixes #42.\n\n<!-- {config.policy.ai_disclosure} -->"

    with pytest.raises(PolicyError, match="visibly contain"):
        validate_publication_text(
            manifest,
            required_disclosure=config.policy.ai_disclosure,
        )


@pytest.mark.parametrize("fence", ["```", "~~~~"])
def test_ai_disclosure_inside_fenced_code_is_rejected(tmp_path: Path, fence: str) -> None:
    config, store, run_id, _ = _ready_run(tmp_path)
    manifest = store.get(run_id)
    assert manifest.proposal is not None
    manifest.proposal.pull_request_body = (
        f"Fixes #42.\n\n{fence}text\n{config.policy.ai_disclosure}\n{fence}\n"
    )

    with pytest.raises(PolicyError, match="visibly contain"):
        validate_publication_text(
            manifest,
            required_disclosure=config.policy.ai_disclosure,
        )


@pytest.mark.parametrize("auto_mode", [False, True])
def test_tripped_circuit_breaker_blocks_publisher_entry_before_github_work(
    tmp_path: Path,
    auto_mode: bool,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    if auto_mode:
        config.publishing.mode = "auto"
    manifest = store.get(run_id)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    store.trip_circuit_breaker(
        source="lifecycle:test",
        reason="maintainer requested a stop",
        trigger_hash="a" * 64,
    )

    with pytest.raises(StateError, match="Circuit breaker is tripped"):
        Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert github.calls == []


def test_publication_lease_serializes_publishers_before_github_work(tmp_path: Path) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    held = store.acquire_lease(
        "autocontribute.publish",
        "other-publisher",
        ttl=timedelta(minutes=5),
    )
    assert held is not None

    with pytest.raises(StateError, match="held by another worker"):
        Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert github.calls == []
    assert store.release_lease(
        "autocontribute.publish",
        "other-publisher",
        held.generation,
    )


def test_publication_lease_loss_blocks_remote_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    original_assert_owned = LeaseHeartbeatGuard.assert_owned

    def fail_after_intent(guard: LeaseHeartbeatGuard):
        if store.get(run_id).status == RunStatus.SUBMITTING:
            raise StateError("Lease autocontribute.publish ownership was lost")
        return original_assert_owned(guard)

    monkeypatch.setattr(LeaseHeartbeatGuard, "assert_owned", fail_after_intent)

    with pytest.raises(StateError, match="ownership was lost"):
        Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert store.get(run_id).status == RunStatus.SUBMITTING
    assert "ensure_fork" not in github.calls
    assert not github.mutated


def test_fencing_takeover_after_local_commit_blocks_durable_commit_save(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    publisher = Publisher(config, store, github)  # type: ignore[arg-type]
    original_commit = publisher._commit
    takeover_generation: list[int] = []

    def commit_then_take_over(*args, **kwargs) -> str:  # type: ignore[no-untyped-def]
        commit_sha = original_commit(*args, **kwargs)
        active = store.get_lease("autocontribute.publish")
        assert active is not None
        assert store.release_lease(active.name, active.owner, active.generation)
        takeover = store.acquire_lease(
            active.name,
            "replacement-publisher",
            ttl=timedelta(minutes=5),
        )
        assert takeover is not None and takeover.generation > active.generation
        takeover_generation.append(takeover.generation)
        return commit_sha

    monkeypatch.setattr(publisher, "_commit", commit_then_take_over)
    monkeypatch.setattr(publisher, "_wait_for_fork", lambda *args: None)

    with pytest.raises(StateError, match=r"no longer owned|ownership was lost"):
        publisher.publish(run_id)

    durable = store.get(run_id)
    assert takeover_generation
    assert durable.status == RunStatus.SUBMITTING
    assert durable.commit_sha is None
    assert all(event["event_type"] != "commit.created" for event in store.events(run_id))
    assert "create_pull_request" not in github.calls


def test_base_drift_stops_before_any_github_mutation(tmp_path: Path) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    github = FakePublishingGitHub(issue, "b" * 40)
    publisher = Publisher(config, store, github)  # type: ignore[arg-type]

    with pytest.raises(PolicyError, match="base branch moved"):
        publisher.publish(run_id)

    assert not github.mutated
    assert all(event["event_type"] != "publication.reserved" for event in store.events(run_id))


def test_base_movement_during_policy_fetch_stops_before_remote_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    observed_shas = iter([manifest.base_sha or "", "c" * 40])

    def moving_default_branch_sha(repository: str, branch: str) -> str:
        del repository, branch
        github.calls.append("default_branch_sha")
        return next(observed_shas)

    monkeypatch.setattr(github, "default_branch_sha", moving_default_branch_sha)

    with pytest.raises(PolicyError, match="moved while policy evidence was fetched"):
        Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert github.calls.count("default_branch_sha") == 2
    assert "ensure_fork" not in github.calls
    assert not github.mutated
    assert all(event["event_type"] != "publication.reserved" for event in store.events(run_id))


def test_base_moves_after_push_deletes_exact_branch_without_post(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    approved_base = manifest.base_sha or ""
    github = FakePublishingGitHub(issue, approved_base)
    publisher = Publisher(config, store, github)  # type: ignore[arg-type]
    observed_bases = iter([approved_base, approved_base, "e" * 40])
    deleted: list[tuple[str, str, str]] = []

    def push(
        workspace: Path,
        fork: str,
        branch: str,
        commit_sha: str,
        *,
        before_mutation,  # type: ignore[no-untyped-def]
    ) -> None:
        before_mutation()
        del workspace, fork, branch
        github.branch_sha = commit_sha

    def delete(
        fork: str,
        branch: str,
        commit_sha: str,
        *,
        expected_repository_id: int,
        expected_repository_node_id: str,
        lease_guard: LeaseHeartbeatGuard,
        before_mutation,  # type: ignore[no-untyped-def]
    ) -> None:
        assert expected_repository_id == github.fork_repository_id
        assert expected_repository_node_id == github.fork_repository_node_id
        lease_guard.assert_owned()
        before_mutation()
        deleted.append((fork, branch, commit_sha))
        assert github.branch_sha == commit_sha
        github.branch_sha = None

    monkeypatch.setattr(
        github,
        "default_branch_sha",
        lambda repository, branch: next(observed_bases),
    )
    monkeypatch.setattr(publisher, "_wait_for_fork", lambda *args: None)
    monkeypatch.setattr(publisher, "_push", push)
    monkeypatch.setattr(publisher, "_delete_remote_branch", delete)

    with pytest.raises(PolicyError, match="moved after the contribution branch was pushed"):
        publisher.publish(run_id)

    durable = store.get(run_id)
    assert durable.status == RunStatus.FAILED
    assert deleted == [("octocat/project", durable.branch_name, durable.commit_sha)]
    assert "create_pull_request" not in github.calls
    assert any(event["event_type"] == "publication.reserved" for event in store.events(run_id))


def test_post_race_persists_url_then_closes_pr_and_deletes_exact_branch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    publisher = Publisher(config, store, github)  # type: ignore[arg-type]
    original_create = github.create_pull_request
    deleted: list[tuple[str, str, str]] = []

    def push(
        workspace: Path,
        fork: str,
        branch: str,
        commit_sha: str,
        *,
        before_mutation,  # type: ignore[no-untyped-def]
    ) -> None:
        before_mutation()
        del workspace, fork, branch
        github.branch_sha = commit_sha

    def create(*args, **kwargs) -> PullRequestDetails:  # type: ignore[no-untyped-def]
        github.pull_request_base_sha = "e" * 40
        return original_create(*args, **kwargs)

    def delete(
        fork: str,
        branch: str,
        commit_sha: str,
        *,
        expected_repository_id: int,
        expected_repository_node_id: str,
        lease_guard: LeaseHeartbeatGuard,
        before_mutation,  # type: ignore[no-untyped-def]
    ) -> None:
        assert expected_repository_id == github.fork_repository_id
        assert expected_repository_node_id == github.fork_repository_node_id
        lease_guard.assert_owned()
        before_mutation()
        deleted.append((fork, branch, commit_sha))
        assert github.branch_sha == commit_sha
        github.branch_sha = None

    monkeypatch.setattr(publisher, "_wait_for_fork", lambda *args: None)
    monkeypatch.setattr(publisher, "_push", push)
    monkeypatch.setattr(github, "create_pull_request", create)
    monkeypatch.setattr(publisher, "_delete_remote_branch", delete)

    with pytest.raises(PublicationResumeRequired, match="exact created PR was closed"):
        publisher.publish(run_id)

    durable = store.get(run_id)
    assert durable.status == RunStatus.FAILED
    assert durable.pull_request_url == "https://github.com/example/project/pull/7"
    assert deleted == [("octocat/project", durable.branch_name, durable.commit_sha)]
    assert "close_pull_request" in github.calls
    assert store.circuit_breaker_status().is_tripped


@pytest.mark.parametrize("changed_field", ["body", "labels", "discussion"])
def test_issue_evidence_drift_stops_before_any_github_mutation(
    tmp_path: Path,
    changed_field: str,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    if changed_field == "body":
        issue = issue.model_copy(update={"body": issue.body + "\nA new acceptance requirement."})
    elif changed_field == "labels":
        issue = issue.model_copy(update={"labels": [*issue.labels, "triaged"]})
    else:
        now = datetime.now(UTC)
        comment = IssueComment(
            author="maintainer",
            author_association="MEMBER",
            body="An additional implementation note.",
            html_url="https://github.com/example/project/issues/42#issuecomment-1",
            created_at=now,
            updated_at=now,
        )
        issue = issue.model_copy(update={"comments": issue.comments + 1, "discussion": [comment]})
    github = FakePublishingGitHub(issue, manifest.base_sha or "")

    with pytest.raises(PolicyError, match=f"Issue evidence changed.*{changed_field}"):
        Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert not github.mutated
    assert all(event["event_type"] != "publication.reserved" for event in store.events(run_id))


def test_benign_policy_source_drift_stops_before_any_github_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    original_get_file = github.get_file

    def changed_policy(
        repository: str,
        path: str,
        *,
        ref: str,
        max_bytes: int = 1_000_000,
    ) -> str | None:
        if repository == "example/.github" and path == "AI_POLICY.md":
            return "AI-assisted contributions must include a regression test."
        return original_get_file(repository, path, ref=ref, max_bytes=max_bytes)

    monkeypatch.setattr(github, "get_file", changed_policy)

    with pytest.raises(PolicyError, match="contribution policy changed"):
        Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert not github.mutated
    assert all(event["event_type"] != "publication.reserved" for event in store.events(run_id))


def test_legal_policy_drift_invalidates_attestation_before_github_mutation(
    tmp_path: Path,
) -> None:
    policy = "Contributors must complete our Contributor License Agreement before opening a PR."
    config, store, run_id, issue = _ready_run(tmp_path, legal_policy=policy)
    manifest = store.get(run_id)
    github = FakePublishingGitHub(
        issue,
        manifest.base_sha or "",
        policy_text=policy + " The enrollment process has changed.",
    )

    with pytest.raises(PolicyError, match="contribution policy changed"):
        Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert not github.mutated
    assert all(event["event_type"] != "publication.reserved" for event in store.events(run_id))


def test_legal_policy_drift_after_push_recovers_compensation_before_pull_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = "Contributors must complete our Contributor License Agreement before opening a PR."
    config, store, run_id, issue = _ready_run(tmp_path, legal_policy=policy)
    manifest = store.get(run_id)
    github = FakePublishingGitHub(
        issue,
        manifest.base_sha or "",
        policy_text=policy,
    )
    publisher = Publisher(config, store, github)  # type: ignore[arg-type]
    deleted: list[tuple[str, str, str]] = []
    original_finalize = store.finalize_publication_compensation

    def push(
        workspace: Path,
        fork: str,
        branch: str,
        commit_sha: str,
        *,
        before_mutation,  # type: ignore[no-untyped-def]
    ) -> None:
        before_mutation()
        del workspace, fork, branch
        github.branch_sha = commit_sha
        github.policy_text = policy + " The enrollment process has changed."

    def delete(
        fork: str,
        branch: str,
        commit_sha: str,
        *,
        expected_repository_id: int,
        expected_repository_node_id: str,
        lease_guard: LeaseHeartbeatGuard,
        before_mutation,  # type: ignore[no-untyped-def]
    ) -> None:
        assert expected_repository_id == github.fork_repository_id
        assert expected_repository_node_id == github.fork_repository_node_id
        lease_guard.assert_owned()
        before_mutation()
        deleted.append((fork, branch, commit_sha))
        github.branch_sha = None

    monkeypatch.setattr(publisher, "_wait_for_fork", lambda *args: None)
    monkeypatch.setattr(publisher, "_push", push)
    monkeypatch.setattr(publisher, "_delete_remote_branch", delete)
    monkeypatch.setattr(
        store,
        "finalize_publication_compensation",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            RuntimeError("crash before policy compensation finalization")
        ),
    )

    with pytest.raises(RuntimeError, match="policy compensation"):
        publisher.publish(run_id)

    durable = store.get(run_id)
    assert durable.status == RunStatus.SUBMITTING
    assert durable.publication_compensation_reason == "pre_pr_policy_stale"
    assert deleted == [("octocat/project", durable.branch_name, durable.commit_sha)]
    assert "create_pull_request" not in github.calls

    monkeypatch.setattr(store, "finalize_publication_compensation", original_finalize)
    reconciled = publisher.publish(run_id)

    assert reconciled.status == RunStatus.FAILED
    assert any(
        event["event_type"] == "publication.compensation.verified" for event in store.events(run_id)
    )


def test_repository_no_longer_eligible_stops_before_any_github_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    original_get_repository = github.get_repository

    def archived_repository(full_name: str) -> RepositoryInfo:
        repository = original_get_repository(full_name)
        return repository.model_copy(update={"archived": True})

    monkeypatch.setattr(github, "get_repository", archived_repository)

    with pytest.raises(PolicyError, match="no longer passes deterministic eligibility"):
        Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert not github.mutated
    assert all(event["event_type"] != "publication.reserved" for event in store.events(run_id))


def test_breaker_trip_during_preflight_blocks_fork_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    original_default_branch_sha = github.default_branch_sha

    def default_branch_sha_then_stop(repository: str, branch: str) -> str:
        sha = original_default_branch_sha(repository, branch)
        store.trip_circuit_breaker(
            source="lifecycle:test",
            reason="stop before fork",
            trigger_hash="b" * 64,
        )
        return sha

    monkeypatch.setattr(github, "default_branch_sha", default_branch_sha_then_stop)

    with pytest.raises(StateError, match="Circuit breaker is tripped"):
        Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert "ensure_fork" not in github.calls
    assert not github.mutated


def test_breaker_trip_during_upstream_identity_validation_blocks_fork_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    original_assert_identity = github.assert_repository_identity
    breaker_tripped = False

    def assert_identity_then_stop(
        full_name: str,
        *,
        expected_database_id: int,
        expected_node_id: str,
    ) -> RepositoryIdentity:
        nonlocal breaker_tripped
        identity = original_assert_identity(
            full_name,
            expected_database_id=expected_database_id,
            expected_node_id=expected_node_id,
        )
        if full_name.casefold() == "example/project":
            breaker_tripped = True
            store.trip_circuit_breaker(
                source="lifecycle:test",
                reason="stop during fork identity validation",
                trigger_hash="c" * 64,
            )
        return identity

    monkeypatch.setattr(github, "assert_repository_identity", assert_identity_then_stop)

    with pytest.raises(StateError, match="Circuit breaker is tripped"):
        Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert breaker_tripped
    assert "ensure_fork" not in github.calls
    assert not github.mutated


def test_breaker_trip_after_fork_blocks_branch_push(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    publisher = Publisher(config, store, github)  # type: ignore[arg-type]
    original_ensure_fork = github.ensure_fork
    pushes: list[tuple[str, str]] = []

    def ensure_fork_then_stop(
        repository: str,
        login: str,
        *,
        before_mutation=None,  # type: ignore[no-untyped-def]
    ) -> str:
        fork = original_ensure_fork(
            repository,
            login,
            before_mutation=before_mutation,
        )
        store.trip_circuit_breaker(
            source="lifecycle:test",
            reason="stop before push",
            trigger_hash="c" * 64,
        )
        return fork

    monkeypatch.setattr(github, "ensure_fork", ensure_fork_then_stop)
    monkeypatch.setattr(publisher, "_wait_for_fork", lambda *args: None)
    monkeypatch.setattr(
        publisher,
        "_push",
        lambda workspace, fork, branch, commit_sha, *, before_mutation: (
            before_mutation(),
            pushes.append((fork, branch)),
        )[-1],
    )

    with pytest.raises(StateError, match="Circuit breaker is tripped"):
        publisher.publish(run_id)

    assert github.calls.count("ensure_fork") == 1
    assert pushes == []
    assert "create_pull_request" not in github.calls


def test_breaker_trip_after_push_blocks_pull_request_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    publisher = Publisher(config, store, github)  # type: ignore[arg-type]
    pushes: list[tuple[str, str]] = []

    def push_then_stop(
        workspace: Path,
        fork: str,
        branch: str,
        commit_sha: str,
        *,
        before_mutation,  # type: ignore[no-untyped-def]
    ) -> None:
        before_mutation()
        pushes.append((fork, branch))
        github.branch_sha = commit_sha
        store.trip_circuit_breaker(
            source="lifecycle:test",
            reason="stop before pull request",
            trigger_hash="d" * 64,
        )

    monkeypatch.setattr(publisher, "_wait_for_fork", lambda *args: None)
    monkeypatch.setattr(publisher, "_push", push_then_stop)

    with pytest.raises(StateError, match="Circuit breaker is tripped"):
        publisher.publish(run_id)

    assert pushes == [("octocat/project", store.get(run_id).branch_name)]
    assert "create_pull_request" not in github.calls


def test_breaker_trip_after_pull_request_creation_leaves_reconcilable_intent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    publisher = Publisher(config, store, github)  # type: ignore[arg-type]
    original_create_pull_request = github.create_pull_request

    def create_pull_request_then_stop(*args, **kwargs) -> PullRequestDetails:  # type: ignore[no-untyped-def]
        details = original_create_pull_request(*args, **kwargs)
        store.trip_circuit_breaker(
            source="lifecycle:test",
            reason="stop after pull request mutation",
            trigger_hash="e" * 64,
        )
        return details

    monkeypatch.setattr(github, "create_pull_request", create_pull_request_then_stop)
    monkeypatch.setattr(publisher, "_wait_for_fork", lambda *args: None)
    monkeypatch.setattr(
        publisher,
        "_push",
        lambda workspace, fork, branch, commit_sha, *, before_mutation: (
            before_mutation(),
            setattr(github, "branch_sha", commit_sha),
        )[-1],
    )

    with pytest.raises(StateError, match="Circuit breaker is tripped"):
        publisher.publish(run_id)

    durable = store.get(run_id)
    assert durable.status == RunStatus.SUBMITTING
    assert durable.commit_sha
    assert durable.pull_request_url == "https://github.com/example/project/pull/7"
    assert github.calls.count("create_pull_request") == 1


@pytest.mark.parametrize("mutation", ["ensure_fork", "push", "pull_request"])
def test_lease_loss_is_fenced_immediately_after_each_remote_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    publisher = Publisher(config, store, github)  # type: ignore[arg-type]
    original_assert_owned = LeaseHeartbeatGuard.assert_owned
    original_ensure_fork = github.ensure_fork
    original_create_pull_request = github.create_pull_request
    lost = False
    actions: list[str] = []

    def ensure_fork(*args, **kwargs) -> str:  # type: ignore[no-untyped-def]
        nonlocal lost
        result = original_ensure_fork(*args, **kwargs)
        if mutation == "ensure_fork":
            lost = True
        return result

    def wait_for_fork(*args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        actions.append("wait")

    def push(*args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        nonlocal lost
        before_mutation = kwargs.pop("before_mutation")
        before_mutation()
        actions.append("push")
        github.branch_sha = args[3]
        if mutation == "push":
            lost = True

    def create_pull_request(*args, **kwargs) -> PullRequestDetails:  # type: ignore[no-untyped-def]
        nonlocal lost
        result = original_create_pull_request(*args, **kwargs)
        if mutation == "pull_request":
            lost = True
        return result

    def assert_owned(guard: LeaseHeartbeatGuard):  # type: ignore[no-untyped-def]
        if lost:
            raise StateError("Lease autocontribute.publish ownership was lost")
        return original_assert_owned(guard)

    monkeypatch.setattr(github, "ensure_fork", ensure_fork)
    monkeypatch.setattr(github, "create_pull_request", create_pull_request)
    monkeypatch.setattr(publisher, "_wait_for_fork", wait_for_fork)
    monkeypatch.setattr(publisher, "_push", push)
    monkeypatch.setattr(LeaseHeartbeatGuard, "assert_owned", assert_owned)

    with pytest.raises(StateError, match="ownership was lost"):
        publisher.publish(run_id)

    if mutation == "ensure_fork":
        assert actions == []
    elif mutation == "push":
        assert actions == ["wait", "push"]
        assert "create_pull_request" not in github.calls
    else:
        assert actions == ["wait", "push"]
        assert github.calls.count("create_pull_request") == 1
        assert store.get(run_id).pull_request_url == "https://github.com/example/project/pull/7"


def test_workspace_change_after_preflight_cannot_be_committed_or_pushed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    publisher = Publisher(config, store, github)  # type: ignore[arg-type]
    original_ensure_fork = github.ensure_fork
    pushes: list[object] = []

    def mutate_after_preflight(
        repository: str,
        login: str,
        *,
        before_mutation=None,  # type: ignore[no-untyped-def]
    ) -> str:
        fork = original_ensure_fork(
            repository,
            login,
            before_mutation=before_mutation,
        )
        workspace = store.workspace_dir(run_id) / "repository"
        (workspace / "fix.py").write_text("answer = 3\n", encoding="utf-8")
        return fork

    monkeypatch.setattr(github, "ensure_fork", mutate_after_preflight)
    monkeypatch.setattr(publisher, "_wait_for_fork", lambda *args: None)
    monkeypatch.setattr(
        publisher,
        "_push",
        lambda *args, **kwargs: (
            kwargs["before_mutation"](),
            pushes.append(args),
        )[-1],
    )

    with pytest.raises(PolicyError, match="Workspace diff changed after publication preflight"):
        publisher.publish(run_id)

    workspace = store.workspace_dir(run_id) / "repository"
    assert _git(workspace, "rev-parse", "HEAD") == manifest.base_sha
    assert pushes == []
    assert "create_pull_request" not in github.calls


@pytest.mark.parametrize("field", ["name", "email"])
def test_configured_git_identity_rejects_credential_material_without_echoing_it(
    tmp_path: Path,
    field: str,
) -> None:
    config, store, run_id, _issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    manifest.status = RunStatus.READY_FOR_APPROVAL
    manifest.approval = None
    _remove_human_publication_context(manifest)
    store.save(manifest, event="fixture.ready_again", details={})
    credential = "github_" + "pat_" + ("A" * 24)
    value = credential if field == "name" else f"{credential}@example.invalid"
    setattr(config.identity, field, value)

    with pytest.raises(PolicyError, match="appears to contain a credential") as error:
        build_approval_review(config, store, run_id, actor="octocat")

    assert credential not in str(error.value)
    stored = store.get(run_id)
    assert stored.commit_author_name is None
    assert stored.commit_author_email is None


@pytest.mark.parametrize(
    "field",
    [
        "commit_author_name",
        "commit_author_email",
        "commit_committer_name",
        "commit_committer_email",
    ],
)
def test_durable_git_identity_rejects_credential_material_before_mutation(
    tmp_path: Path,
    field: str,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    manifest.status = RunStatus.SUBMITTING
    manifest.branch_name = f"autocontribute/issue-42-{run_id[:8]}"
    credential = "github_" + "pat_" + ("A" * 24)
    value = credential if field.endswith("name") else f"{credential}@example.invalid"
    setattr(manifest, field, value)
    store.save(manifest, event="fixture.credential_identity", details={})
    github = FakePublishingGitHub(issue, manifest.base_sha or "")

    with pytest.raises(PolicyError, match="appears to contain a credential") as error:
        Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert credential not in str(error.value)
    assert github.calls == ["authenticated_login"]
    assert not github.mutated


def test_authenticated_account_drift_invalidates_human_approval(tmp_path: Path) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    github = FakePublishingGitHub(issue, manifest.base_sha or "", login="different-user")

    with pytest.raises(PolicyError, match="differs from durable publication intent"):
        Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert not github.mutated


@pytest.mark.parametrize("drift", ["login", "api_origin", "identity", "draft"])
def test_submitting_retry_enforces_durable_publication_context(
    tmp_path: Path,
    drift: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    manifest = _begin_review_publication(config, store, manifest)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    if drift == "login":
        github.login = "different-user"
    elif drift == "api_origin":
        config.github.api_url = "https://git.example.com/api/v3"  # type: ignore[assignment]
        github.api_origin = "https://git.example.com"
    elif drift == "identity":
        config.identity.name = "Different Committer"
    else:
        config.publishing.draft = False

    publisher = Publisher(config, store, github)  # type: ignore[arg-type]
    if drift in {"identity", "draft"}:
        monkeypatch.setattr(publisher, "_wait_for_fork", lambda *args: None)
        monkeypatch.setattr(
            publisher,
            "_push",
            lambda workspace, fork, branch, commit_sha, *, before_mutation: (
                before_mutation(),
                setattr(github, "branch_sha", commit_sha),
            )[-1],
        )

        published = publisher.publish(run_id)

        assert published.status == RunStatus.PR_OPEN
        assert published.commit_author_name == "octocat"
        assert published.publication_draft is True
        assert github.pull_request_draft is True
        return

    with pytest.raises(PolicyError, match="differs from durable publication intent"):
        publisher.publish(run_id)

    assert github.calls == ["authenticated_login"]
    assert not github.mutated


@pytest.mark.parametrize(
    ("change", "value", "expected_error"),
    [
        ("base_branch", "next", "Preparation fingerprint"),
        ("draft", False, "configuration changed"),
    ],
)
def test_publication_behavior_drift_invalidates_human_approval(
    tmp_path: Path,
    change: str,
    value: object,
    expected_error: str,
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

    with pytest.raises(PolicyError, match=expected_error):
        Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert not github.mutated


def test_review_required_preparation_cannot_be_replayed_in_auto_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    _remove_human_publication_context(manifest)
    manifest.status = RunStatus.READY_FOR_APPROVAL
    store.save(manifest, event="fixture.ready_without_approval", details={})
    _enable_guarded_auto_mode(config)
    monkeypatch.setenv(config.publishing.auto_publish_env, "1")
    github = FakePublishingGitHub(issue, manifest.base_sha or "")

    with pytest.raises(PolicyError, match="publishing configuration changed"):
        Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert github.calls == []
    assert not github.mutated


def test_auto_mode_requires_every_measured_rollout_gate(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    config, store, run_id, issue = _ready_run(tmp_path, guarded_auto=True)
    manifest = store.get(run_id)
    _remove_human_publication_context(manifest)
    manifest.status = RunStatus.READY_FOR_APPROVAL
    store.save(manifest, event="fixture.auto", details={})
    monkeypatch.setenv(config.publishing.auto_publish_env, "1")
    github = FakePublishingGitHub(issue, manifest.base_sha or "")

    with pytest.raises(
        AutomaticRolloutBlocked,
        match=r"every measured rollout gate.*expert-evaluation.*fixed manual",
    ):
        Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert github.calls == ["authenticated_login"]
    blocked = store.get(run_id)
    assert blocked.status == RunStatus.READY_FOR_APPROVAL
    assert blocked.publishing_login == "octocat"
    assert blocked.publishing_api_origin == "https://api.github.com"
    assert store.publication_gate_hold(run_id) is None
    assert not github.mutated


def test_auto_mode_publishes_only_after_every_measured_rollout_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path, guarded_auto=True)
    manifest = store.get(run_id)
    _remove_human_publication_context(manifest)
    manifest.status = RunStatus.READY_FOR_APPROVAL
    store.save(manifest, event="fixture.auto", details={})
    _install_fixture_rollout_gate(monkeypatch)
    monkeypatch.setenv(config.publishing.auto_publish_env, "1")
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    publisher = Publisher(config, store, github)  # type: ignore[arg-type]
    monkeypatch.setattr(publisher, "_wait_for_fork", lambda *args: None)
    monkeypatch.setattr(
        publisher,
        "_push",
        lambda workspace, fork, branch, commit_sha, *, before_mutation: (
            before_mutation(),
            setattr(github, "branch_sha", commit_sha),
        )[-1],
    )

    published = publisher.publish(run_id)

    assert published.status == RunStatus.PR_OPEN
    assert published.pull_request_url == "https://github.com/example/project/pull/7"
    assert published.publishing_login == "octocat"
    assert published.publishing_api_origin == "https://api.github.com"
    assert github.created_pull_request_draft is True
    assert not github.pull_request_draft
    assert github.calls.index("create_pull_request") < github.calls.index(
        "mark_pull_request_ready_for_review"
    )
    durable = store.get(run_id)
    assert durable.pull_request_ready_started
    assert durable.pull_request_ready_completed
    event_types = [event["event_type"] for event in store.events(run_id)]
    started = event_types.index("pull_request.ready_for_review.started")
    completed = event_types.index("pull_request.ready_for_review.completed")
    final_transition = len(event_types) - 1 - event_types[::-1].index("run.transitioned")
    assert event_types.index("pull_request.created.response") < started < completed
    assert completed < final_transition


@pytest.mark.parametrize("changed_cursor", ["evaluation", "outcome"])
def test_automatic_recovery_rejects_rollout_hold_cursor_drift_before_github_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    changed_cursor: str,
) -> None:
    _, store, run_id, github, publisher = _strand_automatic_publication_after_gate_hold(
        tmp_path,
        monkeypatch,
    )
    hold = store.publication_gate_hold(run_id)
    assert hold is not None
    selected_cursor = (
        hold.corpus_cursor if changed_cursor == "evaluation" else hold.outcome_corpus_cursor
    )
    assert selected_cursor is not None
    different_cursor = ("0" if selected_cursor[0] != "0" else "1") + selected_cursor[1:]
    _install_fixture_rollout_gate(
        monkeypatch,
        evaluation_cursor=different_cursor if changed_cursor == "evaluation" else None,
        outcome_cursor=different_cursor if changed_cursor == "outcome" else None,
    )

    with pytest.raises(
        StateError,
        match="semantic rollout authority differs from the durable publication hold",
    ):
        publisher.publish(run_id)

    assert store.get(run_id).status == RunStatus.SUBMITTING
    assert store.publication_gate_hold(run_id) == hold
    assert not github.mutated
    assert not {
        "ensure_fork",
        "create_pull_request",
        "close_pull_request",
        "mark_pull_request_ready_for_review",
    }.intersection(github.calls)


@pytest.mark.parametrize("changed_cursor", ["evaluation", "outcome"])
@pytest.mark.parametrize(
    "boundary",
    ["ensure_fork", "push", "create_pull_request", "mark_ready"],
)
def test_automatic_rollout_cursor_drift_blocks_each_constructive_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    changed_cursor: str,
    boundary: str,
) -> None:
    _, store, run_id, github, publisher = _strand_automatic_publication_after_gate_hold(
        tmp_path,
        monkeypatch,
    )
    holder = store.get(run_id)
    assert holder.deployment_fingerprint is not None
    drift_subject = store.create_run(
        deployment_fingerprint=holder.deployment_fingerprint,
    )
    drifted = False

    def drift() -> None:
        nonlocal drifted
        if drifted:
            return
        drifted = True
        if changed_cursor == "evaluation":
            with store._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                store._append_event(
                    connection,
                    drift_subject.run_id,
                    "evaluation.recorded",
                    {"evaluation_hash": "a" * 64},
                )
        else:
            store.save(
                drift_subject,
                event="publication.fixture_outcome_drift",
                details={"version": "later"},
            )

    pushes: list[str] = []

    def push(
        workspace: Path,
        fork: str,
        branch: str,
        commit_sha: str,
        *,
        before_mutation,  # type: ignore[no-untyped-def]
    ) -> None:
        before_mutation()
        del workspace, fork, branch
        pushes.append(commit_sha)
        github.branch_sha = commit_sha

    monkeypatch.setattr(publisher, "_wait_for_fork", lambda *args: None)
    monkeypatch.setattr(publisher, "_push", push)
    if boundary == "ensure_fork":
        original_ensure_fork = github.ensure_fork

        def ensure_fork(*args, **kwargs) -> str:  # type: ignore[no-untyped-def]
            drift()
            return original_ensure_fork(*args, **kwargs)

        monkeypatch.setattr(github, "ensure_fork", ensure_fork)
    elif boundary == "push":

        def check_freshness(manifest: RunManifest) -> None:
            del manifest
            drift()

        monkeypatch.setattr(publisher, "_check_freshness", check_freshness)
    elif boundary == "create_pull_request":
        original_create_pull_request = github.create_pull_request

        def create_pull_request(*args, **kwargs) -> PullRequestDetails:  # type: ignore[no-untyped-def]
            drift()
            return original_create_pull_request(*args, **kwargs)

        monkeypatch.setattr(github, "create_pull_request", create_pull_request)
    else:
        original_mark_ready = github.mark_pull_request_ready_for_review

        def mark_ready(*args, **kwargs) -> PullRequestDetails:  # type: ignore[no-untyped-def]
            drift()
            return original_mark_ready(*args, **kwargs)

        monkeypatch.setattr(github, "mark_pull_request_ready_for_review", mark_ready)

    expected_error = (
        "evaluation corpus" if changed_cursor == "evaluation" else "upstream-outcome corpus"
    )
    with pytest.raises(StateError, match=expected_error):
        publisher.publish(run_id)

    assert drifted
    durable = store.get(run_id)
    assert durable.status == RunStatus.SUBMITTING
    if boundary == "ensure_fork":
        assert not github.mutated
        assert "ensure_fork" not in github.calls
        assert pushes == []
    elif boundary == "push":
        assert pushes == []
        assert "create_pull_request" not in github.calls
    elif boundary == "create_pull_request":
        assert len(pushes) == 1
        assert "create_pull_request" not in github.calls
        assert durable.pull_request_url is None
    else:
        assert len(pushes) == 1
        assert github.calls.count("create_pull_request") == 1
        assert "mark_pull_request_ready_for_review" not in github.calls
        assert durable.pull_request_url == "https://github.com/example/project/pull/7"
        assert github.pull_request_draft


@pytest.mark.parametrize(
    "boundary",
    ["ensure_fork", "push", "create_pull_request", "mark_ready"],
)
def test_disabling_auto_publish_blocks_each_constructive_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    config, store, run_id, github, publisher = _strand_automatic_publication_after_gate_hold(
        tmp_path,
        monkeypatch,
    )
    switched_off = False

    def disable_auto_publish() -> None:
        nonlocal switched_off
        switched_off = True
        monkeypatch.setenv(config.publishing.auto_publish_env, "0")

    pushes: list[str] = []

    def push(
        workspace: Path,
        fork: str,
        branch: str,
        commit_sha: str,
        *,
        before_mutation,  # type: ignore[no-untyped-def]
    ) -> None:
        before_mutation()
        del workspace, fork, branch
        pushes.append(commit_sha)
        github.branch_sha = commit_sha

    monkeypatch.setattr(publisher, "_wait_for_fork", lambda *args: None)
    monkeypatch.setattr(publisher, "_push", push)
    if boundary == "ensure_fork":
        original_ensure_fork = github.ensure_fork

        def ensure_fork(*args, **kwargs) -> str:  # type: ignore[no-untyped-def]
            disable_auto_publish()
            return original_ensure_fork(*args, **kwargs)

        monkeypatch.setattr(github, "ensure_fork", ensure_fork)
    elif boundary == "push":

        def check_freshness(manifest: RunManifest) -> None:
            del manifest
            disable_auto_publish()

        monkeypatch.setattr(publisher, "_check_freshness", check_freshness)
    elif boundary == "create_pull_request":
        original_create_pull_request = github.create_pull_request

        def create_pull_request(*args, **kwargs) -> PullRequestDetails:  # type: ignore[no-untyped-def]
            disable_auto_publish()
            return original_create_pull_request(*args, **kwargs)

        monkeypatch.setattr(github, "create_pull_request", create_pull_request)
    else:
        original_mark_ready = github.mark_pull_request_ready_for_review

        def mark_ready(*args, **kwargs) -> PullRequestDetails:  # type: ignore[no-untyped-def]
            disable_auto_publish()
            return original_mark_ready(*args, **kwargs)

        monkeypatch.setattr(github, "mark_pull_request_ready_for_review", mark_ready)

    with pytest.raises(AutomaticRolloutBlocked, match="disabled before the next remote mutation"):
        publisher.publish(run_id)

    assert switched_off
    durable = store.get(run_id)
    assert durable.status == RunStatus.SUBMITTING
    if boundary == "ensure_fork":
        assert not github.mutated
        assert "ensure_fork" not in github.calls
        assert pushes == []
    elif boundary == "push":
        assert pushes == []
        assert "create_pull_request" not in github.calls
    elif boundary == "create_pull_request":
        assert len(pushes) == 1
        assert "create_pull_request" not in github.calls
        assert durable.pull_request_url is None
    else:
        assert len(pushes) == 1
        assert github.calls.count("create_pull_request") == 1
        assert "mark_pull_request_ready_for_review" not in github.calls
        assert durable.pull_request_url == "https://github.com/example/project/pull/7"
        assert github.pull_request_draft


def test_disabling_auto_publish_during_repository_identity_validation_blocks_push(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id, github, publisher = _strand_automatic_publication_after_gate_hold(
        tmp_path,
        monkeypatch,
    )
    original_assert_identity = github.assert_repository_identity
    switched_off = False
    pushes: list[str] = []

    def assert_identity_then_disable(
        full_name: str,
        *,
        expected_database_id: int,
        expected_node_id: str,
    ) -> RepositoryIdentity:
        nonlocal switched_off
        identity = original_assert_identity(
            full_name,
            expected_database_id=expected_database_id,
            expected_node_id=expected_node_id,
        )
        if full_name.casefold() == "octocat/project":
            monkeypatch.setenv(config.publishing.auto_publish_env, "0")
            switched_off = True
        return identity

    def push(
        workspace: Path,
        fork: str,
        branch: str,
        commit_sha: str,
        *,
        before_mutation,  # type: ignore[no-untyped-def]
    ) -> None:
        before_mutation()
        del workspace, fork, branch
        pushes.append(commit_sha)

    monkeypatch.setattr(github, "assert_repository_identity", assert_identity_then_disable)
    monkeypatch.setattr(publisher, "_wait_for_fork", lambda *args: None)
    monkeypatch.setattr(publisher, "_push", push)

    with pytest.raises(AutomaticRolloutBlocked, match="disabled before the next remote mutation"):
        publisher.publish(run_id)

    assert switched_off
    assert pushes == []
    assert github.branch_sha is None
    assert "create_pull_request" not in github.calls
    assert store.get(run_id).status == RunStatus.SUBMITTING


def test_breaker_resume_cannot_bypass_blocked_rollout_during_automatic_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, store, run_id, github, publisher = _strand_automatic_publication_after_gate_hold(
        tmp_path,
        monkeypatch,
    )
    hold = store.publication_gate_hold(run_id)
    assert hold is not None
    store.trip_circuit_breaker(
        source="publication:test",
        reason="exercise guarded automatic recovery",
        trigger_hash="b" * 64,
    )

    with pytest.raises(StateError, match="Circuit breaker is tripped"):
        publisher.publish(run_id)

    assert github.calls == []
    breaker = store.circuit_breaker_status()
    assert breaker.active_revision is not None
    assert store.resume_circuit_breaker(
        actor="operator",
        reason="verify that rollout evidence is independently enforced",
        expected_trigger_hash=breaker.active_revision,
    )
    _install_fixture_rollout_gate(monkeypatch, manual_passed=False)

    with pytest.raises(
        AutomaticRolloutBlocked,
        match="fixed manual upstream-outcome cohort",
    ):
        publisher.publish(run_id)

    assert store.get(run_id).status == RunStatus.SUBMITTING
    assert store.publication_gate_hold(run_id) == hold
    assert not github.mutated
    assert not {
        "ensure_fork",
        "create_pull_request",
        "close_pull_request",
        "mark_pull_request_ready_for_review",
    }.intersection(github.calls)


def test_submitting_without_gate_hold_or_exact_approval_fails_before_github_mutation(
    tmp_path: Path,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    manifest.status = RunStatus.SUBMITTING
    manifest.branch_name = f"autocontribute/issue-42-{run_id[:8]}"
    manifest.commit_sha = "c" * 40
    manifest.approval = None
    store.save(manifest, event="fixture.synthetic_unapproved_submitting", details={})
    github = FakePublishingGitHub(
        issue,
        manifest.base_sha or "",
        existing_pr="https://github.com/example/project/pull/7",
        branch_sha=manifest.commit_sha,
    )

    with pytest.raises(StateError, match="exact ledger-bound human approval"):
        Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert github.calls == ["authenticated_login"]
    assert not github.mutated
    assert store.get(run_id).status == RunStatus.SUBMITTING


def test_review_recovery_revalidates_exact_approved_patch_before_github_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    publisher = Publisher(config, store, github)  # type: ignore[arg-type]
    original_find = github.find_pull_request

    def crash_after_intent(repository: str, *, head: str) -> str | None:
        del repository, head
        github.calls.append("find_pull_request")
        raise RuntimeError("simulated crash after review publication intent")

    monkeypatch.setattr(github, "find_pull_request", crash_after_intent)
    with pytest.raises(RuntimeError, match="after review publication intent"):
        publisher.publish(run_id)
    stranded = store.get(run_id)
    assert stranded.status == RunStatus.SUBMITTING
    stranded.commit_sha = "c" * 40
    store.save(stranded, event="fixture.remote_commit_recorded", details={})
    github.branch_sha = stranded.commit_sha

    monkeypatch.setattr(github, "find_pull_request", original_find)
    store.write_artifact(run_id, "contribution.patch", "tampered patch\n")
    github.calls.clear()
    github.mutated = False

    with pytest.raises(PolicyError, match="Preparation fingerprint"):
        publisher.publish(run_id)

    assert not {
        "ensure_fork",
        "create_pull_request",
        "mark_pull_request_ready_for_review",
    }.intersection(github.calls)
    assert not github.mutated


def test_initial_draft_to_ready_observes_adverse_lifecycle_before_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path, ready_for_review=True)
    manifest = store.get(run_id)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    github.reviews = [
        PullRequestReview(
            identifier=1,
            author="maintainer",
            author_association="OWNER",
            state="CHANGES_REQUESTED",
            body="Please stop and revise this pull request.",
            html_url="https://github.com/example/project/pull/7#pullrequestreview-1",
            submitted_at=datetime.now(UTC),
        )
    ]
    publisher = Publisher(config, store, github)  # type: ignore[arg-type]
    monkeypatch.setattr(publisher, "_wait_for_fork", lambda *args: None)
    monkeypatch.setattr(
        publisher,
        "_push",
        lambda workspace, fork, branch, commit_sha, *, before_mutation: (
            before_mutation(),
            setattr(github, "branch_sha", commit_sha),
        )[-1],
    )

    with pytest.raises(StateError, match="Circuit breaker is tripped"):
        publisher.publish(run_id)

    assert "mark_pull_request_ready_for_review" not in github.calls
    assert len(store.lifecycle_snapshots(run_id)) == 1
    assert store.circuit_breaker_status().is_tripped


def test_automatic_ready_retry_observes_current_run_and_blocks_on_new_adverse_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path, guarded_auto=True)
    manifest = store.get(run_id)
    _remove_human_publication_context(manifest)
    manifest.status = RunStatus.READY_FOR_APPROVAL
    store.save(manifest, event="fixture.auto", details={})
    monkeypatch.setenv(config.publishing.auto_publish_env, "1")
    _install_fixture_rollout_gate(monkeypatch)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    publisher = Publisher(config, store, github)  # type: ignore[arg-type]
    monkeypatch.setattr(publisher, "_wait_for_fork", lambda *args: None)
    monkeypatch.setattr(
        publisher,
        "_push",
        lambda workspace, fork, branch, commit_sha, *, before_mutation: (
            before_mutation(),
            setattr(github, "branch_sha", commit_sha),
        )[-1],
    )

    def lose_ready_response(*args, **kwargs) -> PullRequestDetails:  # type: ignore[no-untyped-def]
        del args
        before_observation = kwargs.pop("before_observation")
        before_mutation = kwargs.pop("before_mutation")
        before_observation()
        before_mutation()
        github.calls.append("mark_pull_request_ready_for_review")
        raise TimeoutError("simulated ready-for-review timeout")

    original_mark_ready = github.mark_pull_request_ready_for_review
    monkeypatch.setattr(github, "mark_pull_request_ready_for_review", lose_ready_response)
    with pytest.raises(PublicationResumeRequired, match="did not confirm ready-for-review"):
        publisher.publish(run_id)
    assert len(store.lifecycle_snapshots(run_id)) == 1

    monkeypatch.setattr(github, "mark_pull_request_ready_for_review", original_mark_ready)
    github.reviews = [
        PullRequestReview(
            identifier=2,
            author="maintainer",
            author_association="MEMBER",
            state="CHANGES_REQUESTED",
            body="Do not continue with this automated contribution.",
            html_url="https://github.com/example/project/pull/7#pullrequestreview-2",
            submitted_at=datetime.now(UTC),
        )
    ]
    github.calls.clear()
    github.mutated = False

    with pytest.raises(StateError, match="Circuit breaker is tripped"):
        publisher.publish(run_id)

    assert len(store.lifecycle_snapshots(run_id)) == 2
    assert "mark_pull_request_ready_for_review" not in github.calls
    assert not github.mutated
    assert store.circuit_breaker_status().is_tripped


def test_ready_for_review_recovers_after_remote_success_before_durable_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path, ready_for_review=True)
    manifest = store.get(run_id)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    publisher = Publisher(config, store, github)  # type: ignore[arg-type]
    original_save = store.save
    completion_crashed = False

    def save_then_crash(
        saved_manifest,  # type: ignore[no-untyped-def]
        *,
        event: str,
        details: dict[str, str],
    ) -> None:
        nonlocal completion_crashed
        if event == "pull_request.ready_for_review.completed" and not completion_crashed:
            completion_crashed = True
            raise RuntimeError("simulated crash before ready completion persistence")
        original_save(saved_manifest, event=event, details=details)

    monkeypatch.setattr(store, "save", save_then_crash)
    monkeypatch.setattr(publisher, "_wait_for_fork", lambda *args: None)
    monkeypatch.setattr(
        publisher,
        "_push",
        lambda workspace, fork, branch, commit_sha, *, before_mutation: (
            before_mutation(),
            setattr(github, "branch_sha", commit_sha),
        )[-1],
    )

    with pytest.raises(RuntimeError, match="ready completion persistence"):
        publisher.publish(run_id)

    stranded = store.get(run_id)
    assert stranded.status == RunStatus.SUBMITTING
    assert stranded.pull_request_ready_started
    assert not stranded.pull_request_ready_completed
    assert not github.pull_request_draft
    assert github.calls.count("mark_pull_request_ready_for_review") == 1

    monkeypatch.setattr(store, "save", original_save)
    recovered = publisher.reconcile_submitting(run_id)

    assert recovered.status == RunStatus.PR_OPEN
    assert recovered.pull_request_ready_completed
    assert github.calls.count("mark_pull_request_ready_for_review") == 1
    event_types = [event["event_type"] for event in store.events(run_id)]
    assert event_types.count("pull_request.ready_for_review.started") == 1
    assert event_types.count("pull_request.ready_for_review.completed") == 1


def test_ambiguous_ready_for_review_is_reconciled_before_a_safe_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path, ready_for_review=True)
    manifest = store.get(run_id)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    publisher = Publisher(config, store, github)  # type: ignore[arg-type]
    original_mark_ready = github.mark_pull_request_ready_for_review
    attempts = 0

    def ambiguous_ready(*args, **kwargs) -> PullRequestDetails:  # type: ignore[no-untyped-def]
        nonlocal attempts
        del args
        before_observation = kwargs.pop("before_observation")
        before_mutation = kwargs.pop("before_mutation")
        before_observation()
        before_mutation()
        attempts += 1
        github.calls.append("mark_pull_request_ready_for_review")
        raise TimeoutError("ready-for-review response was lost")

    monkeypatch.setattr(publisher, "_wait_for_fork", lambda *args: None)
    monkeypatch.setattr(
        publisher,
        "_push",
        lambda workspace, fork, branch, commit_sha, *, before_mutation: (
            before_mutation(),
            setattr(github, "branch_sha", commit_sha),
        )[-1],
    )
    monkeypatch.setattr(github, "mark_pull_request_ready_for_review", ambiguous_ready)

    with pytest.raises(PublicationResumeRequired, match="did not confirm ready-for-review"):
        publisher.publish(run_id)

    stranded = store.get(run_id)
    assert stranded.status == RunStatus.SUBMITTING
    assert stranded.pull_request_ready_started
    assert not stranded.pull_request_ready_completed
    assert github.pull_request_draft
    assert attempts == 1

    monkeypatch.setattr(github, "mark_pull_request_ready_for_review", original_mark_ready)
    recovered = publisher.publish(run_id)

    assert recovered.status == RunStatus.PR_OPEN
    assert recovered.pull_request_ready_completed
    assert not github.pull_request_draft
    assert attempts == 1


def test_ready_for_review_observation_callback_failure_propagates_without_reconciliation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path, ready_for_review=True)
    manifest = store.get(run_id)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    publisher = Publisher(config, store, github)  # type: ignore[arg-type]
    original_mark_ready = github.mark_pull_request_ready_for_review
    original_assert_repository_identity = github.assert_repository_identity
    callback_failure = GitHubError("fork differs from its durable immutable identity")
    ready_attempt = False
    get_calls_before_callback = -1

    def assert_repository_identity(*args, **kwargs) -> RepositoryIdentity:  # type: ignore[no-untyped-def]
        if ready_attempt and args[0].casefold() == "octocat/project":
            raise callback_failure
        return original_assert_repository_identity(*args, **kwargs)

    def mark_ready(*args, **kwargs) -> PullRequestDetails:  # type: ignore[no-untyped-def]
        nonlocal ready_attempt, get_calls_before_callback
        get_calls_before_callback = github.calls.count("get_pull_request")
        ready_attempt = True
        try:
            return original_mark_ready(*args, **kwargs)
        finally:
            ready_attempt = False

    monkeypatch.setattr(publisher, "_wait_for_fork", lambda *args: None)
    monkeypatch.setattr(
        publisher,
        "_push",
        lambda workspace, fork, branch, commit_sha, *, before_mutation: (
            before_mutation(),
            setattr(github, "branch_sha", commit_sha),
        )[-1],
    )
    monkeypatch.setattr(github, "assert_repository_identity", assert_repository_identity)
    monkeypatch.setattr(github, "mark_pull_request_ready_for_review", mark_ready)

    with pytest.raises(GitHubError) as caught:
        publisher.publish(run_id)

    assert caught.value is callback_failure
    assert github.calls.count("get_pull_request") == get_calls_before_callback
    assert github.pull_request_draft
    assert store.get(run_id).status == RunStatus.SUBMITTING


def test_retry_recovers_exact_local_commit_after_crash_before_commit_persistence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    publisher = Publisher(config, store, github)  # type: ignore[arg-type]
    original_save = store.save
    crashed = False

    def save_then_crash(
        saved_manifest,  # type: ignore[no-untyped-def]
        *,
        event: str,
        details: dict[str, str],
    ) -> None:
        nonlocal crashed
        if event == "commit.created" and not crashed:
            crashed = True
            raise RuntimeError("simulated process crash before commit persistence")
        original_save(saved_manifest, event=event, details=details)

    monkeypatch.setattr(store, "save", save_then_crash)
    monkeypatch.setattr(publisher, "_wait_for_fork", lambda *args: None)
    monkeypatch.setattr(
        publisher,
        "_push",
        lambda workspace, fork, branch, commit_sha, *, before_mutation: (
            before_mutation(),
            setattr(github, "branch_sha", commit_sha),
        )[-1],
    )

    with pytest.raises(RuntimeError, match="simulated process crash"):
        publisher.publish(run_id)

    durable_after_crash = store.get(run_id)
    workspace = store.workspace_dir(run_id) / "repository"
    local_commit = _git(workspace, "rev-parse", "HEAD")
    assert durable_after_crash.status == RunStatus.SUBMITTING
    assert durable_after_crash.commit_sha is None
    assert local_commit != durable_after_crash.base_sha

    monkeypatch.setattr(store, "save", original_save)
    published = publisher.publish(run_id)

    assert published.status == RunStatus.PR_OPEN
    assert published.commit_sha == local_commit
    assert github.created_expected_head_sha == local_commit


def test_retry_rejects_local_commit_that_does_not_match_durable_intent(
    tmp_path: Path,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    manifest = _begin_review_publication(config, store, manifest)
    workspace = store.workspace_dir(run_id) / "repository"
    _git(workspace, "add", "--all")
    _git(
        workspace,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "Different publication intent",
    )
    github = FakePublishingGitHub(issue, manifest.base_sha or "")

    with pytest.raises(PolicyError, match="commit message differs from durable intent"):
        Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert "ensure_fork" not in github.calls
    assert "create_pull_request" not in github.calls


def test_retry_rejects_recovered_commit_with_different_author_or_committer(
    tmp_path: Path,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    assert manifest.proposal is not None
    manifest = _begin_review_publication(config, store, manifest)
    workspace = store.workspace_dir(run_id) / "repository"
    _git(workspace, "add", "--all")
    _git(
        workspace,
        "-c",
        "user.name=Different Author",
        "-c",
        "user.email=different@example.invalid",
        "commit",
        "--quiet",
        "-m",
        manifest.proposal.commit_message,
    )
    github = FakePublishingGitHub(issue, manifest.base_sha or "")

    with pytest.raises(PolicyError, match="commit identity differs from durable intent"):
        Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert "ensure_fork" not in github.calls
    assert "create_pull_request" not in github.calls


def test_retry_with_stored_commit_and_no_remote_state_finalizes_compensation(
    tmp_path: Path,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = _begin_review_publication(config, store, store.get(run_id))
    manifest.commit_sha = "c" * 40
    store.save(manifest, event="fixture.commit_stored", details={})
    workspace = store.workspace_dir(run_id) / "repository"
    shutil.rmtree(workspace)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")

    finalized = Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert finalized.status == RunStatus.FAILED
    assert not workspace.exists()
    assert not github.mutated
    event_types = [event["event_type"] for event in store.events(run_id)]
    assert "publication.absence.verified" in event_types
    assert "publication.compensation.verified" in event_types
    absence_event = next(
        event
        for event in store.events(run_id)
        if event["event_type"] == "publication.absence.verified"
    )
    assert json.loads(absence_event["details"]) == {
        "repository": "example/project",
        "publishing_api_origin": "https://api.github.com",
        "upstream_repository_id": "1001",
        "upstream_repository_node_id": "R_upstream_fixture",
        "head": f"octocat:{finalized.branch_name}",
        "fork": "octocat/project",
        "fork_identity_state": "bound",
        "fork_repository_id": "2001",
        "fork_repository_node_id": "R_fork_fixture",
        "branch": finalized.branch_name,
        "commit_sha": "c" * 40,
        "reason": (
            "verified absent remote publication state after the approved workspace became "
            "unavailable"
        ),
    }


def test_retry_recovers_exact_remote_push_without_ephemeral_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    manifest = _begin_review_publication(config, store, manifest)
    manifest.commit_sha = "c" * 40
    store.save(manifest, event="fixture.uncertain_push", details={})
    shutil.rmtree(store.workspace_dir(run_id) / "repository")
    github = FakePublishingGitHub(
        issue,
        manifest.base_sha or "",
        branch_sha=manifest.commit_sha,
    )
    publisher = Publisher(config, store, github)  # type: ignore[arg-type]

    def fail_if_rollout_gate_is_used(
        cls: type[RolloutGate],
        selected_store: RunStore,
    ) -> _FixtureRolloutGate:
        del cls, selected_store
        raise AssertionError("review-required recovery must not consult the automatic gate")

    monkeypatch.setattr(
        RolloutGate,
        "for_store",
        classmethod(fail_if_rollout_gate_is_used),
    )
    monkeypatch.setattr(publisher, "_wait_for_fork", lambda *args: None)
    pushes: list[object] = []
    monkeypatch.setattr(
        publisher,
        "_push",
        lambda *args, **kwargs: (
            kwargs["before_mutation"](),
            pushes.append(args),
        )[-1],
    )

    published = publisher.publish(run_id)

    assert published.status == RunStatus.PR_OPEN
    assert pushes == []
    assert "create_pull_request" in github.calls


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

    assert store.get(run_id).status == RunStatus.SUBMITTING
    assert any(event["event_type"] == "publication.intent.begun" for event in store.events(run_id))


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

    with pytest.raises(PublicationResumeRequired, match="does not match durable intent"):
        Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert store.get(run_id).status == RunStatus.SUBMITTING
    assert store.circuit_breaker_status().is_tripped


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
    event_types = [event["event_type"] for event in store.events(run_id)]
    assert event_types.index("publication.intent.begun") < event_types.index(
        "pull_request.discovered"
    )


def test_ambiguous_submitting_run_is_reconciled_without_remote_mutation(tmp_path: Path) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    manifest.commit_sha = "c" * 40
    store.save(manifest, event="fixture.commit_stored", details={})
    manifest = _begin_review_publication(config, store, manifest)
    github = FakePublishingGitHub(
        issue,
        manifest.base_sha or "",
        existing_pr="https://github.com/example/project/pull/7",
        branch_sha=manifest.commit_sha,
    )

    reconciled = Publisher(config, store, github).reconcile_submitting(run_id)  # type: ignore[arg-type]

    assert reconciled.status == RunStatus.PR_OPEN
    assert reconciled.pull_request_url == "https://github.com/example/project/pull/7"
    assert "get_pull_request" in github.calls
    assert not github.mutated


def test_submitting_reconciliation_fails_closed_when_remote_pr_is_missing(
    tmp_path: Path,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    manifest = _begin_review_publication(config, store, manifest)
    manifest.commit_sha = "c" * 40
    store.save(manifest, event="fixture.submitting", details={})
    github = FakePublishingGitHub(issue, manifest.base_sha or "")

    with pytest.raises(PublicationResumeRequired, match="resumed idempotently"):
        Publisher(config, store, github).reconcile_submitting(run_id)  # type: ignore[arg-type]

    assert store.get(run_id).status == RunStatus.SUBMITTING
    assert not github.mutated


def test_submitting_reconciliation_requires_durable_base_commit(tmp_path: Path) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    manifest.status = RunStatus.SUBMITTING
    manifest.branch_name = f"autocontribute/issue-42-{run_id[:8]}"
    manifest.commit_sha = "c" * 40
    manifest.base_sha = None
    store.save(manifest, event="fixture.submitting_without_base", details={})
    github = FakePublishingGitHub(
        issue,
        "a" * 40,
        existing_pr="https://github.com/example/project/pull/7",
        branch_sha=manifest.commit_sha,
    )

    with pytest.raises(StateError, match="lacks durable publication evidence"):
        Publisher(config, store, github).reconcile_submitting(run_id)  # type: ignore[arg-type]

    assert "authenticated_login" not in github.calls
    assert not github.mutated


def test_existing_pr_text_drift_is_not_reconciled(tmp_path: Path) -> None:
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
    github.pull_request_body = "Unexpected remote body"

    with pytest.raises(
        PublicationResumeRequired,
        match="differs from durable publication intent: body",
    ):
        Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    durable = store.get(run_id)
    assert durable.status == RunStatus.SUBMITTING
    assert durable.pull_request_url == "https://github.com/example/project/pull/7"
    assert store.circuit_breaker_status().is_tripped


@pytest.mark.parametrize("drift", ["base_sha", "head_repository"])
def test_existing_pr_repository_or_base_identity_drift_is_not_reconciled(
    tmp_path: Path,
    drift: str,
) -> None:
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
    if drift == "base_sha":
        github.pull_request_base_sha = "e" * 40
    else:
        github.pull_request_head_repository = "someone-else/project"

    with pytest.raises(PublicationResumeRequired):
        Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert store.get(run_id).status == RunStatus.SUBMITTING
    assert store.circuit_breaker_status().is_tripped
    assert not github.mutated


def test_durable_pull_request_url_precedes_exact_head_search(tmp_path: Path) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    manifest = _begin_review_publication(config, store, manifest)
    manifest.commit_sha = "c" * 40
    manifest.pull_request_url = "https://github.com/example/project/pull/7"
    manifest.pull_request_node_id = "PR_fixture_7"
    store.save(manifest, event="fixture.submitting_with_url", details={})
    github = FakePublishingGitHub(
        issue,
        manifest.base_sha or "",
        branch_sha=manifest.commit_sha,
    )
    github.last_head = f"octocat:{manifest.branch_name}"

    reconciled = Publisher(config, store, github).reconcile_submitting(run_id)  # type: ignore[arg-type]

    assert reconciled.status == RunStatus.PR_OPEN
    assert "find_pull_request" not in github.calls
    assert github.calls.count("get_pull_request") == 1


def test_ambiguous_pull_request_post_is_never_sent_twice(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    publisher = Publisher(config, store, github)  # type: ignore[arg-type]
    posts = 0

    def ambiguous_post(*args, **kwargs) -> PullRequestDetails:  # type: ignore[no-untyped-def]
        nonlocal posts
        del args
        before_mutation = kwargs.pop("before_mutation")
        before_mutation()
        posts += 1
        github.calls.append("create_pull_request")
        github.mutated = True
        raise TimeoutError("response was lost after the request was sent")

    monkeypatch.setattr(publisher, "_wait_for_fork", lambda *args: None)
    monkeypatch.setattr(
        publisher,
        "_push",
        lambda workspace, fork, branch, commit_sha, *, before_mutation: (
            before_mutation(),
            setattr(github, "branch_sha", commit_sha),
        )[-1],
    )
    monkeypatch.setattr(github, "create_pull_request", ambiguous_post)

    with pytest.raises(PublicationResumeRequired, match="will not send a second POST"):
        publisher.publish(run_id)

    durable = store.get(run_id)
    assert durable.status == RunStatus.SUBMITTING
    assert durable.pull_request_creation_started
    assert posts == 1
    breaker = store.circuit_breaker_status()
    assert breaker.active_revision is not None
    assert store.resume_circuit_breaker(
        actor="operator",
        reason="verify the exactly-once retry guard",
        expected_trigger_hash=breaker.active_revision,
    )

    with pytest.raises(PublicationResumeRequired, match="second POST is forbidden"):
        publisher.publish(run_id)

    assert posts == 1
    assert store.get(run_id).status == RunStatus.SUBMITTING


def test_malformed_post_response_retains_submitting_and_trips_breaker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    publisher = Publisher(config, store, github)  # type: ignore[arg-type]
    original_create = github.create_pull_request

    def malformed_response(*args, **kwargs) -> PullRequestDetails:  # type: ignore[no-untyped-def]
        created = original_create(*args, **kwargs)
        return replace(
            created,
            html_url="https://github.com/different/project/pull/7",
        )

    monkeypatch.setattr(publisher, "_wait_for_fork", lambda *args: None)
    monkeypatch.setattr(
        publisher,
        "_push",
        lambda workspace, fork, branch, commit_sha, *, before_mutation: (
            before_mutation(),
            setattr(github, "branch_sha", commit_sha),
        )[-1],
    )
    monkeypatch.setattr(github, "create_pull_request", malformed_response)

    with pytest.raises(PublicationResumeRequired, match="canonical identity"):
        publisher.publish(run_id)

    durable = store.get(run_id)
    assert durable.status == RunStatus.SUBMITTING
    assert durable.pull_request_creation_started
    assert durable.pull_request_url is None
    assert github.calls.count("create_pull_request") == 1
    assert store.circuit_breaker_status().is_tripped


@pytest.mark.parametrize("outcome", ["merged", "closed_unmerged"])
def test_terminal_exact_pr_reconciliation_releases_gate_hold_for_lifecycle(
    tmp_path: Path,
    outcome: str,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    assert manifest.deployment_fingerprint is not None
    store.reserve_publication(
        run_id,
        issue.repository,
        max_per_utc_day=100,
        repository_cooldown=timedelta(0),
        evaluation_corpus_cursor=store.evaluation_corpus_cursor(),
        evaluation_deployment_fingerprint=manifest.deployment_fingerprint,
        outcome_corpus_cursor=store.upstream_outcome_corpus_cursor(
            manifest.deployment_fingerprint,
            "octocat",
            "https://api.github.com",
            exclude_run_id=run_id,
        ),
        publishing_login="octocat",
        publishing_api_origin="https://api.github.com",
    )
    manifest.status = RunStatus.SUBMITTING
    manifest.branch_name = f"autocontribute/issue-42-{run_id[:8]}"
    manifest.commit_sha = "c" * 40
    manifest.upstream_repository_id = 1001
    manifest.upstream_repository_node_id = "R_upstream_fixture"
    manifest.fork_repository_id = 2001
    manifest.fork_repository_node_id = "R_fork_fixture"
    store.save(manifest, event="fixture.submitting_with_gate", details={})
    github = FakePublishingGitHub(
        issue,
        manifest.base_sha or "",
        existing_pr="https://github.com/example/project/pull/7",
        branch_sha=manifest.commit_sha,
    )
    github.pull_request_state = "closed"
    github.pull_request_merged = outcome == "merged"
    if github.pull_request_merged:
        github.pull_request_draft = False
    publisher = Publisher(config, store, github)  # type: ignore[arg-type]

    reconciled = publisher.reconcile_submitting(run_id)

    assert reconciled.status == RunStatus.PR_OPEN
    assert any(event["event_type"] == "publication.gate.released" for event in store.events(run_id))
    assert store.circuit_breaker_status().is_tripped is (outcome == "closed_unmerged")


@pytest.mark.parametrize("outcome", ["merged", "closed_unmerged"])
def test_terminal_exact_post_response_is_immediately_lifecycle_managed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    outcome: str,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    publisher = Publisher(config, store, github)  # type: ignore[arg-type]
    original_create = github.create_pull_request

    def terminal_response(*args, **kwargs) -> PullRequestDetails:  # type: ignore[no-untyped-def]
        created = original_create(*args, **kwargs)
        now = datetime.now(UTC)
        return replace(
            created,
            state="closed",
            draft=False,
            merged=outcome == "merged",
            merged_at=now if outcome == "merged" else None,
            closed_at=now,
            merge_commit_sha="e" * 40 if outcome == "merged" else None,
        )

    monkeypatch.setattr(publisher, "_wait_for_fork", lambda *args: None)
    monkeypatch.setattr(
        publisher,
        "_push",
        lambda workspace, fork, branch, commit_sha, *, before_mutation: (
            before_mutation(),
            setattr(github, "branch_sha", commit_sha),
        )[-1],
    )
    monkeypatch.setattr(github, "create_pull_request", terminal_response)

    published = publisher.publish(run_id)

    assert published.status == RunStatus.PR_OPEN
    assert published.pull_request_url == "https://github.com/example/project/pull/7"
    assert store.circuit_breaker_status().is_tripped is (outcome == "closed_unmerged")


def test_pre_pr_compensation_marker_recovers_after_delete_before_finalizer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    approved_base = manifest.base_sha or ""
    github = FakePublishingGitHub(issue, approved_base)
    publisher = Publisher(config, store, github)  # type: ignore[arg-type]
    observed_bases = iter([approved_base, approved_base, "e" * 40])
    original_finalize = store.finalize_publication_compensation

    def push(
        workspace: Path,
        fork: str,
        branch: str,
        commit_sha: str,
        *,
        before_mutation,  # type: ignore[no-untyped-def]
    ) -> None:
        before_mutation()
        del workspace, fork, branch
        github.branch_sha = commit_sha

    def delete(
        fork: str,
        branch: str,
        commit_sha: str,
        *,
        expected_repository_id: int,
        expected_repository_node_id: str,
        lease_guard: LeaseHeartbeatGuard,
        before_mutation,  # type: ignore[no-untyped-def]
    ) -> None:
        del fork, branch, expected_repository_id, expected_repository_node_id
        lease_guard.assert_owned()
        before_mutation()
        assert github.branch_sha == commit_sha
        github.branch_sha = None
        lease_guard.assert_owned()

    monkeypatch.setattr(
        github,
        "default_branch_sha",
        lambda repository, branch: next(observed_bases),
    )
    monkeypatch.setattr(publisher, "_wait_for_fork", lambda *args: None)
    monkeypatch.setattr(publisher, "_push", push)
    monkeypatch.setattr(publisher, "_delete_remote_branch", delete)
    monkeypatch.setattr(
        store,
        "finalize_publication_compensation",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            RuntimeError("crash before atomic compensation finalization")
        ),
    )

    with pytest.raises(RuntimeError, match="crash before atomic"):
        publisher.publish(run_id)

    durable = store.get(run_id)
    assert durable.status == RunStatus.SUBMITTING
    assert durable.publication_compensation_reason == "pre_pr_base_moved"
    assert github.branch_sha is None
    assert (store.workspace_dir(run_id) / "repository").is_dir()

    monkeypatch.setattr(store, "finalize_publication_compensation", original_finalize)
    reconciled = publisher.publish(run_id)

    assert reconciled.status == RunStatus.FAILED
    assert any(
        event["event_type"] == "publication.compensation.verified" for event in store.events(run_id)
    )


def test_absent_pre_post_state_finalizes_when_local_evidence_is_unavailable(
    tmp_path: Path,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    manifest = _begin_review_publication(config, store, manifest)
    (store.artifact_dir(run_id) / "contribution.patch").unlink()
    github = FakePublishingGitHub(issue, manifest.base_sha or "")

    finalized = Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert finalized.status == RunStatus.FAILED
    assert finalized.commit_sha is None
    assert not github.mutated
    absence_events = [
        event
        for event in store.events(run_id)
        if event["event_type"] == "publication.absence.verified"
    ]
    assert len(absence_events) == 1
    assert json.loads(absence_events[0]["details"]) == {
        "repository": "example/project",
        "publishing_api_origin": "https://api.github.com",
        "upstream_repository_id": "1001",
        "upstream_repository_node_id": "R_upstream_fixture",
        "head": f"octocat:{finalized.branch_name}",
        "fork": "octocat/project",
        "fork_identity_state": "bound",
        "fork_repository_id": "2001",
        "fork_repository_node_id": "R_fork_fixture",
        "branch": finalized.branch_name,
        "commit_sha": "not_persisted",
        "reason": (
            "verified absent remote publication state after durable local publication evidence "
            "became unavailable"
        ),
    }


def test_absent_pre_post_state_records_unbound_fork_before_any_commit(
    tmp_path: Path,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = _begin_review_publication(
        config,
        store,
        store.get(run_id),
        bind_fork_identity=False,
    )
    (store.artifact_dir(run_id) / "contribution.patch").unlink()
    github = FakePublishingGitHub(issue, manifest.base_sha or "")

    finalized = Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    absence_event = next(
        event
        for event in store.events(run_id)
        if event["event_type"] == "publication.absence.verified"
    )
    assert finalized.status == RunStatus.FAILED
    assert json.loads(absence_event["details"]) == {
        "repository": "example/project",
        "publishing_api_origin": "https://api.github.com",
        "upstream_repository_id": "1001",
        "upstream_repository_node_id": "R_upstream_fixture",
        "head": f"octocat:{finalized.branch_name}",
        "fork": "octocat/project",
        "fork_identity_state": "not_bound",
        "branch": finalized.branch_name,
        "commit_sha": "not_persisted",
        "reason": (
            "verified absent remote publication state after durable local publication evidence "
            "became unavailable"
        ),
    }


def test_absent_pre_post_state_rejects_commit_without_bound_fork(
    tmp_path: Path,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = _begin_review_publication(
        config,
        store,
        store.get(run_id),
        bind_fork_identity=False,
    )
    manifest.commit_sha = "c" * 40
    store.save(manifest, event="fixture.legacy_unbound_commit", details={})
    shutil.rmtree(store.workspace_dir(run_id) / "repository")
    github = FakePublishingGitHub(issue, manifest.base_sha or "")

    with pytest.raises(StateError, match="commit without immutable fork identity"):
        Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert all(
        event["event_type"] != "publication.absence.verified" for event in store.events(run_id)
    )


def test_absent_pre_post_state_rejects_branch_event_without_bound_fork(
    tmp_path: Path,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = _begin_review_publication(
        config,
        store,
        store.get(run_id),
        bind_fork_identity=False,
    )
    assert manifest.branch_name is not None
    store.save(
        manifest,
        event="branch.pushed",
        details={
            "fork": "octocat/project",
            "branch": manifest.branch_name,
            "commit_sha": "c" * 40,
        },
    )
    (store.artifact_dir(run_id) / "contribution.patch").unlink()
    github = FakePublishingGitHub(issue, manifest.base_sha or "")

    with pytest.raises(StateError, match="remote branch evidence without immutable fork identity"):
        Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert all(
        event["event_type"] != "publication.absence.verified" for event in store.events(run_id)
    )


def test_absent_pre_post_state_rechecks_bound_identity_after_absence_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = _begin_review_publication(config, store, store.get(run_id))
    (store.artifact_dir(run_id) / "contribution.patch").unlink()
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    original_find_pull_request = github.find_pull_request
    find_calls = 0

    def replace_fork_after_final_absence_read(
        repository: str,
        *,
        head: str,
    ) -> str | None:
        nonlocal find_calls
        result = original_find_pull_request(repository, head=head)
        find_calls += 1
        if find_calls == 2:
            github.fork_repository_id += 1
        return result

    monkeypatch.setattr(github, "find_pull_request", replace_fork_after_final_absence_read)

    with pytest.raises(GitHubError, match="durable immutable identity"):
        Publisher(config, store, github).publish(run_id)  # type: ignore[arg-type]

    assert find_calls == 2
    assert all(
        event["event_type"] != "publication.absence.verified" for event in store.events(run_id)
    )


@pytest.mark.parametrize("missing_identity", ["database_id", "node_id"])
def test_absent_pre_post_state_rejects_partial_fork_identity(
    tmp_path: Path,
    missing_identity: str,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = _begin_review_publication(config, store, store.get(run_id))
    if missing_identity == "database_id":
        manifest.fork_repository_id = None
    else:
        manifest.fork_repository_node_id = None
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    publisher = Publisher(config, store, github)  # type: ignore[arg-type]

    class UnexpectedLeaseUse:
        def assert_owned(self) -> None:
            raise AssertionError("partial identity reached remote absence observation")

    with pytest.raises(StateError, match="partial immutable fork identity"):
        publisher._finalize_absent_pre_post_publication(
            manifest,
            login="octocat",
            head=f"octocat:{manifest.branch_name}",
            reason="fixture partial fork identity",
            lease_guard=UnexpectedLeaseUse(),  # type: ignore[arg-type]
        )

    assert not github.mutated
    assert all(
        event["event_type"] != "publication.absence.verified" for event in store.events(run_id)
    )


def test_lease_loss_after_compensation_close_blocks_branch_delete_and_finalizer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    github = FakePublishingGitHub(issue, manifest.base_sha or "")
    publisher = Publisher(config, store, github)  # type: ignore[arg-type]
    original_create = github.create_pull_request
    original_close = github.close_pull_request
    original_assert_owned = LeaseHeartbeatGuard.assert_owned
    lost = False

    def push(
        workspace: Path,
        fork: str,
        branch: str,
        commit_sha: str,
        *,
        before_mutation,  # type: ignore[no-untyped-def]
    ) -> None:
        before_mutation()
        del workspace, fork, branch
        github.branch_sha = commit_sha

    def create(*args, **kwargs) -> PullRequestDetails:  # type: ignore[no-untyped-def]
        github.pull_request_base_sha = "e" * 40
        return original_create(*args, **kwargs)

    def close(*args, **kwargs) -> PullRequestDetails:  # type: ignore[no-untyped-def]
        nonlocal lost
        result = original_close(*args, **kwargs)
        lost = True
        return result

    def assert_owned(guard: LeaseHeartbeatGuard) -> None:
        if lost:
            raise StateError("Lease autocontribute.publish ownership was lost")
        original_assert_owned(guard)

    monkeypatch.setattr(publisher, "_wait_for_fork", lambda *args: None)
    monkeypatch.setattr(publisher, "_push", push)
    monkeypatch.setattr(github, "create_pull_request", create)
    monkeypatch.setattr(github, "close_pull_request", close)
    monkeypatch.setattr(LeaseHeartbeatGuard, "assert_owned", assert_owned)

    with pytest.raises(StateError, match="ownership was lost"):
        publisher.publish(run_id)

    durable = store.get(run_id)
    assert durable.status == RunStatus.SUBMITTING
    assert durable.publication_compensation_reason == "created_pr_base_moved"
    assert durable.pull_request_url == "https://github.com/example/project/pull/7"
    assert github.pull_request_state == "closed"
    assert github.branch_sha == durable.commit_sha
    assert all(
        event["event_type"] != "publication.compensation.verified" for event in store.events(run_id)
    )


def test_lease_loss_after_compensation_delete_blocks_finalizer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    approved_base = manifest.base_sha or ""
    github = FakePublishingGitHub(issue, approved_base)
    publisher = Publisher(config, store, github)  # type: ignore[arg-type]
    observed_bases = iter([approved_base, approved_base, "e" * 40])
    original_assert_owned = LeaseHeartbeatGuard.assert_owned
    lost = False

    def push(
        workspace: Path,
        fork: str,
        branch: str,
        commit_sha: str,
        *,
        before_mutation,  # type: ignore[no-untyped-def]
    ) -> None:
        before_mutation()
        del workspace, fork, branch
        github.branch_sha = commit_sha

    def delete(
        fork: str,
        branch: str,
        commit_sha: str,
        *,
        expected_repository_id: int,
        expected_repository_node_id: str,
        lease_guard: LeaseHeartbeatGuard,
        before_mutation,  # type: ignore[no-untyped-def]
    ) -> None:
        nonlocal lost
        del fork, branch, expected_repository_id, expected_repository_node_id
        lease_guard.assert_owned()
        before_mutation()
        assert github.branch_sha == commit_sha
        github.branch_sha = None
        lost = True
        lease_guard.assert_owned()

    def assert_owned(guard: LeaseHeartbeatGuard) -> None:
        if lost:
            raise StateError("Lease autocontribute.publish ownership was lost")
        original_assert_owned(guard)

    monkeypatch.setattr(
        github,
        "default_branch_sha",
        lambda repository, branch: next(observed_bases),
    )
    monkeypatch.setattr(publisher, "_wait_for_fork", lambda *args: None)
    monkeypatch.setattr(publisher, "_push", push)
    monkeypatch.setattr(publisher, "_delete_remote_branch", delete)
    monkeypatch.setattr(LeaseHeartbeatGuard, "assert_owned", assert_owned)

    with pytest.raises(StateError, match="ownership was lost"):
        publisher.publish(run_id)

    durable = store.get(run_id)
    assert durable.status == RunStatus.SUBMITTING
    assert durable.publication_compensation_reason == "pre_pr_base_moved"
    assert github.branch_sha is None
    assert all(
        event["event_type"] != "publication.compensation.verified" for event in store.events(run_id)
    )


def _strand_automatic_pre_pr_base_compensation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[AutocontributeConfig, RunStore, str, FakePublishingGitHub, Publisher]:
    """Leave an exact automatic branch behind after its durable base-race marker."""

    config, store, run_id, github, publisher = _strand_automatic_publication_after_gate_hold(
        tmp_path,
        monkeypatch,
    )
    approved_base = store.get(run_id).base_sha or ""
    original_delete = publisher._delete_remote_branch

    def push(
        workspace: Path,
        fork: str,
        branch: str,
        commit_sha: str,
        *,
        before_mutation,  # type: ignore[no-untyped-def]
    ) -> None:
        before_mutation()
        del workspace, fork, branch
        github.branch_sha = commit_sha

    def current_base(repository: str, branch: str) -> str:
        del repository, branch
        return "e" * 40 if github.branch_sha is not None else approved_base

    def fail_delete(*args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        del args, kwargs
        raise RuntimeError("simulated cleanup interruption")

    monkeypatch.setattr(github, "default_branch_sha", current_base)
    monkeypatch.setattr(publisher, "_wait_for_fork", lambda *args: None)
    monkeypatch.setattr(publisher, "_push", push)
    monkeypatch.setattr(publisher, "_delete_remote_branch", fail_delete)

    with pytest.raises(PublicationResumeRequired, match="conditionally removed"):
        publisher.publish(run_id)

    monkeypatch.setattr(publisher, "_delete_remote_branch", original_delete)
    durable = store.get(run_id)
    assert durable.status == RunStatus.SUBMITTING
    assert durable.publication_compensation_reason == "pre_pr_base_moved"
    assert durable.commit_sha == github.branch_sha
    assert store.publication_gate_hold(run_id) is not None
    github.calls.clear()
    github.mutated = False
    return config, store, run_id, github, publisher


def _strand_created_pr_compensation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    automatic: bool = True,
) -> tuple[AutocontributeConfig, RunStore, str, FakePublishingGitHub, Publisher]:
    """Crash after an exact created PR receives its durable compensation marker."""

    if automatic:
        config, store, run_id, github, publisher = _strand_automatic_publication_after_gate_hold(
            tmp_path,
            monkeypatch,
        )
    else:
        config, store, run_id, issue = _ready_run(tmp_path)
        manifest = store.get(run_id)
        github = FakePublishingGitHub(issue, manifest.base_sha or "")
        publisher = Publisher(config, store, github)  # type: ignore[arg-type]
    original_create = github.create_pull_request
    original_compensate = publisher._compensate_created_pull_request

    def push(
        workspace: Path,
        fork: str,
        branch: str,
        commit_sha: str,
        *,
        before_mutation,  # type: ignore[no-untyped-def]
    ) -> None:
        before_mutation()
        del workspace, fork, branch
        github.branch_sha = commit_sha

    def create(*args, **kwargs) -> PullRequestDetails:  # type: ignore[no-untyped-def]
        github.pull_request_base_sha = "e" * 40
        return original_create(*args, **kwargs)

    def crash_before_cleanup(*args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        del args, kwargs
        raise RuntimeError("simulated created-PR cleanup interruption")

    monkeypatch.setattr(publisher, "_wait_for_fork", lambda *args: None)
    monkeypatch.setattr(publisher, "_push", push)
    monkeypatch.setattr(github, "create_pull_request", create)
    monkeypatch.setattr(publisher, "_compensate_created_pull_request", crash_before_cleanup)

    with pytest.raises(RuntimeError, match="created-PR cleanup interruption"):
        publisher.publish(run_id)

    monkeypatch.setattr(publisher, "_compensate_created_pull_request", original_compensate)
    monkeypatch.setattr(github, "create_pull_request", original_create)
    durable = store.get(run_id)
    assert durable.status == RunStatus.SUBMITTING
    assert durable.publication_compensation_reason == "created_pr_base_moved"
    assert durable.pull_request_url == "https://github.com/example/project/pull/7"
    assert durable.commit_sha == github.branch_sha == github.pull_request_head_sha
    assert (store.publication_gate_hold(run_id) is not None) is automatic
    assert store.circuit_breaker_status().is_tripped
    github.calls.clear()
    github.mutated = False
    return config, store, run_id, github, publisher


@pytest.mark.parametrize(
    ("branch_present", "entrypoint"),
    [(True, "publish"), (False, "reconcile")],
)
def test_marked_pre_pr_compensation_recovers_after_restart_despite_all_constructive_stops(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    branch_present: bool,
    entrypoint: str,
) -> None:
    config, store, run_id, github, _ = _strand_automatic_pre_pr_base_compensation(
        tmp_path,
        monkeypatch,
    )
    durable = store.get(run_id)
    assert durable.deployment_fingerprint is not None
    assert durable.commit_sha is not None
    hold = store.publication_gate_hold(run_id)
    assert hold is not None
    assert hold.corpus_cursor is not None
    assert hold.outcome_corpus_cursor is not None
    if not branch_present:
        github.branch_sha = None

    drift_subject = store.create_run(
        deployment_fingerprint=durable.deployment_fingerprint,
    )
    with store._connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        store._append_event(
            connection,
            drift_subject.run_id,
            "evaluation.recorded",
            {"evaluation_hash": "a" * 64},
        )
    store.save(
        drift_subject,
        event="publication.fixture_outcome_drift",
        details={"version": "later"},
    )
    assert store.evaluation_corpus_cursor() != hold.corpus_cursor
    assert (
        store.upstream_outcome_corpus_cursor(
            durable.deployment_fingerprint,
            "octocat",
            "https://api.github.com",
            exclude_run_id=run_id,
        )
        != hold.outcome_corpus_cursor
    )
    store.trip_circuit_breaker(
        source="publication:test",
        reason="exercise exposure-reducing recovery",
        trigger_hash="f" * 64,
    )
    monkeypatch.setenv(config.publishing.auto_publish_env, "0")

    reopened = RunStore(config.storage.path)
    publisher = Publisher(config, reopened, github)  # type: ignore[arg-type]
    deleted: list[tuple[str, str, str]] = []

    def delete(
        fork: str,
        branch: str,
        commit_sha: str,
        *,
        expected_repository_id: int,
        expected_repository_node_id: str,
        lease_guard: LeaseHeartbeatGuard,
        before_mutation,  # type: ignore[no-untyped-def]
    ) -> None:
        assert expected_repository_id == github.fork_repository_id
        assert expected_repository_node_id == github.fork_repository_node_id
        lease_guard.assert_owned()
        before_mutation()
        assert github.branch_sha == commit_sha
        github.branch_sha = None
        deleted.append((fork, branch, commit_sha))
        lease_guard.assert_owned()

    def fail_constructive_authority(*args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        del args, kwargs
        raise AssertionError("compensation consulted constructive publication authority")

    monkeypatch.setattr(publisher, "_delete_remote_branch", delete)
    monkeypatch.setattr(
        publisher,
        "_assert_constructive_mutation_authorized",
        fail_constructive_authority,
    )

    if entrypoint == "publish":
        recovered = publisher.publish(run_id)
    else:
        recovered = publisher.reconcile_submitting(run_id)

    assert recovered.status == RunStatus.FAILED
    assert reopened.publication_gate_hold(run_id) is None
    assert reopened.circuit_breaker_status().is_tripped
    assert deleted == (
        [("octocat/project", durable.branch_name, durable.commit_sha)] if branch_present else []
    )
    assert not {
        "ensure_fork",
        "create_pull_request",
        "close_pull_request",
        "mark_pull_request_ready_for_review",
    }.intersection(github.calls)
    assert any(
        event["event_type"] == "publication.compensation.verified"
        for event in reopened.events(run_id)
    )


@pytest.mark.parametrize("anomaly", ["unexpected_pr", "branch_sha_mismatch"])
def test_marked_pre_pr_compensation_refuses_unbound_remote_state_without_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    anomaly: str,
) -> None:
    _, store, run_id, github, publisher = _strand_automatic_pre_pr_base_compensation(
        tmp_path,
        monkeypatch,
    )
    durable = store.get(run_id)
    assert durable.commit_sha is not None
    if anomaly == "unexpected_pr":
        github.existing_pr = "https://github.com/example/project/pull/99"
    else:
        github.branch_sha = "d" * 40

    def fail_delete(*args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        del args, kwargs
        raise AssertionError("unsafe remote state reached branch deletion")

    monkeypatch.setattr(publisher, "_delete_remote_branch", fail_delete)

    with pytest.raises(PublicationResumeRequired):
        publisher.publish(run_id)

    assert store.get(run_id).status == RunStatus.SUBMITTING
    assert "close_pull_request" not in github.calls
    assert "create_pull_request" not in github.calls
    assert not github.mutated
    assert all(
        event["event_type"] != "publication.compensation.verified" for event in store.events(run_id)
    )
    if anomaly == "unexpected_pr":
        assert github.branch_sha == durable.commit_sha
    else:
        assert github.branch_sha == "d" * 40


@pytest.mark.parametrize("repository", ["upstream", "fork"])
def test_started_compensation_refuses_reused_repository_name_before_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    repository: str,
) -> None:
    _, store, run_id, github, publisher = _strand_automatic_pre_pr_base_compensation(
        tmp_path,
        monkeypatch,
    )
    durable = store.get(run_id)
    if repository == "upstream":
        github.upstream_repository_id += 1
    else:
        github.fork_repository_id += 1

    with pytest.raises(GitHubError, match="durable immutable identity"):
        publisher.publish(run_id)

    assert store.get(run_id).status == RunStatus.SUBMITTING
    assert github.branch_sha == durable.commit_sha
    assert "close_pull_request" not in github.calls
    assert not github.mutated


def test_created_pr_compensation_refuses_changed_pull_request_node_before_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, store, run_id, github, publisher = _strand_created_pr_compensation(
        tmp_path,
        monkeypatch,
    )
    durable = store.get(run_id)
    github.pull_request_node_id = "PR_replaced_fixture"

    with pytest.raises(PublicationResumeRequired, match="no longer matches exact"):
        publisher.publish(run_id)

    assert store.get(run_id).status == RunStatus.SUBMITTING
    assert github.pull_request_state == "open"
    assert github.branch_sha == durable.commit_sha
    assert "close_pull_request" not in github.calls
    assert not github.mutated


def test_legacy_started_compensation_without_immutable_ids_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, store, run_id, github, publisher = _strand_automatic_pre_pr_base_compensation(
        tmp_path,
        monkeypatch,
    )
    durable = store.get(run_id)
    durable.upstream_repository_id = None
    durable.upstream_repository_node_id = None
    durable.fork_repository_id = None
    durable.fork_repository_node_id = None
    store.save(durable, event="fixture.legacy_remote_identity", details={})

    with pytest.raises(StateError, match="lacks durable evidence"):
        publisher.publish(run_id)

    assert github.branch_sha == durable.commit_sha
    assert "close_pull_request" not in github.calls
    assert not github.mutated


def test_unsupported_durable_compensation_reason_fails_as_state_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, store, run_id, github, publisher = _strand_automatic_pre_pr_base_compensation(
        tmp_path,
        monkeypatch,
    )
    durable = store.get(run_id)
    object.__setattr__(
        durable,
        "publication_compensation_reason",
        "unsupported_fixture_reason",
    )
    monkeypatch.setattr(store, "get", lambda requested_run_id: durable)

    with pytest.raises(StateError, match="Unsupported publication compensation reason"):
        publisher.publish(run_id)

    assert github.branch_sha == durable.commit_sha
    assert "close_pull_request" not in github.calls
    assert not github.mutated


@pytest.mark.parametrize(
    ("remote_state", "branch_present", "expected_status"),
    [
        ("open", True, RunStatus.FAILED),
        ("closed", True, RunStatus.FAILED),
        ("open", False, RunStatus.FAILED),
        ("merged", False, RunStatus.PR_OPEN),
    ],
)
def test_created_pr_compensation_resumes_each_exact_remote_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    remote_state: str,
    branch_present: bool,
    expected_status: RunStatus,
) -> None:
    _, store, run_id, github, publisher = _strand_created_pr_compensation(
        tmp_path,
        monkeypatch,
    )
    durable = store.get(run_id)
    assert durable.commit_sha is not None
    github.pull_request_state = "open" if remote_state == "open" else "closed"
    github.pull_request_merged = remote_state == "merged"
    github.pull_request_draft = remote_state != "merged"
    github.branch_sha = durable.commit_sha if branch_present else None
    deleted: list[tuple[str, str, str]] = []

    def delete(
        fork: str,
        branch: str,
        commit_sha: str,
        *,
        expected_repository_id: int,
        expected_repository_node_id: str,
        lease_guard: LeaseHeartbeatGuard,
        before_mutation,  # type: ignore[no-untyped-def]
    ) -> None:
        assert expected_repository_id == github.fork_repository_id
        assert expected_repository_node_id == github.fork_repository_node_id
        lease_guard.assert_owned()
        before_mutation()
        if github.branch_sha is not None:
            assert github.branch_sha == commit_sha
            github.branch_sha = None
        deleted.append((fork, branch, commit_sha))
        lease_guard.assert_owned()

    def fail_constructive_authority(*args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        del args, kwargs
        raise AssertionError("created-PR cleanup consulted constructive authority")

    monkeypatch.setattr(publisher, "_delete_remote_branch", delete)
    monkeypatch.setattr(
        publisher,
        "_assert_constructive_mutation_authorized",
        fail_constructive_authority,
    )

    recovered = publisher.publish(run_id)

    assert recovered.status == expected_status
    assert store.publication_gate_hold(run_id) is None
    if remote_state == "merged":
        assert "close_pull_request" not in github.calls
        assert deleted == []
        assert github.pull_request_merged
        assert any(
            event["event_type"] == "pull_request.compensation.reconciled"
            for event in store.events(run_id)
        )
    else:
        assert github.calls.count("close_pull_request") == 1
        assert github.pull_request_state == "closed"
        assert not github.pull_request_merged
        assert deleted == [("octocat/project", durable.branch_name, durable.commit_sha)]
        assert github.branch_sha is None
        assert any(
            event["event_type"] == "publication.compensation.verified"
            for event in store.events(run_id)
        )


@pytest.mark.parametrize("mismatch", ["head_repository", "head_sha"])
def test_created_pr_compensation_identity_mismatch_prevents_all_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mismatch: str,
) -> None:
    _, store, run_id, github, publisher = _strand_created_pr_compensation(
        tmp_path,
        monkeypatch,
    )
    durable = store.get(run_id)
    if mismatch == "head_repository":
        github.pull_request_head_repository = "someone-else/project"
    else:
        github.pull_request_head_sha = "d" * 40

    def fail_delete(*args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        del args, kwargs
        raise AssertionError("identity mismatch reached branch deletion")

    monkeypatch.setattr(publisher, "_delete_remote_branch", fail_delete)

    with pytest.raises(PublicationResumeRequired, match="no longer matches exact"):
        publisher.publish(run_id)

    assert store.get(run_id).status == RunStatus.SUBMITTING
    assert "close_pull_request" not in github.calls
    assert github.pull_request_state == "open"
    assert github.branch_sha == durable.commit_sha
    assert not github.mutated
    assert all(
        event["event_type"] != "publication.compensation.verified" for event in store.events(run_id)
    )


def test_push_callback_failure_occurs_before_git_is_invoked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    publisher = Publisher(
        config,
        store,
        FakePublishingGitHub(issue, manifest.base_sha or ""),  # type: ignore[arg-type]
    )
    git_calls: list[object] = []
    callback_calls = 0

    def fake_git(*args, **kwargs) -> str:  # type: ignore[no-untyped-def]
        git_calls.append((args, kwargs))
        return ""

    def reject_push() -> None:
        nonlocal callback_calls
        callback_calls += 1
        raise StateError("publication authority changed before push")

    monkeypatch.setattr("autocontribute.publication._git", fake_git)

    with pytest.raises(StateError, match="authority changed before push"):
        publisher._push(
            store.workspace_dir(run_id) / "repository",
            "octocat/project",
            f"autocontribute/issue-42-{run_id[:8]}",
            "c" * 40,
            before_mutation=reject_push,
        )

    assert callback_calls == 1
    assert git_calls == []


def test_push_uses_expected_absent_remote_branch_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id, issue = _ready_run(tmp_path)
    manifest = store.get(run_id)
    publisher = Publisher(
        config,
        store,
        FakePublishingGitHub(issue, manifest.base_sha or ""),  # type: ignore[arg-type]
    )
    git_calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
    callback_calls = 0
    branch = f"autocontribute/issue-42-{run_id[:8]}"
    commit_sha = "c" * 40

    def fake_git(*args, **kwargs) -> str:  # type: ignore[no-untyped-def]
        git_calls.append((args, kwargs))
        return ""

    def authorize_push() -> None:
        nonlocal callback_calls
        callback_calls += 1

    monkeypatch.setattr("autocontribute.publication._git", fake_git)

    publisher._push(
        store.workspace_dir(run_id) / "repository",
        "octocat/project",
        branch,
        commit_sha,
        before_mutation=authorize_push,
    )

    assert callback_calls == 1
    assert len(git_calls) == 1
    assert git_calls[0][0][1] == [
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "http.followRedirects=false",
        "push",
        f"--force-with-lease=refs/heads/{branch}:",
        "https://github.com/octocat/project.git",
        f"{commit_sha}:refs/heads/{branch}",
    ]


def test_cursor_drift_during_creation_marker_save_blocks_pull_request_post(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, store, run_id, github, publisher = _strand_automatic_publication_after_gate_hold(
        tmp_path,
        monkeypatch,
    )
    durable = store.get(run_id)
    assert durable.deployment_fingerprint is not None
    drift_subject = store.create_run(
        deployment_fingerprint=durable.deployment_fingerprint,
    )
    original_save = store.save
    drifted = False

    def push(
        workspace: Path,
        fork: str,
        branch: str,
        commit_sha: str,
        *,
        before_mutation,  # type: ignore[no-untyped-def]
    ) -> None:
        before_mutation()
        del workspace, fork, branch
        github.branch_sha = commit_sha

    def save_with_drift(*args, **kwargs):  # type: ignore[no-untyped-def]
        nonlocal drifted
        result = original_save(*args, **kwargs)
        if kwargs.get("event") == "pull_request.creation.started":
            with store._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                store._append_event(
                    connection,
                    drift_subject.run_id,
                    "evaluation.recorded",
                    {"evaluation_hash": "b" * 64},
                )
            drifted = True
        return result

    monkeypatch.setattr(publisher, "_wait_for_fork", lambda *args: None)
    monkeypatch.setattr(publisher, "_push", push)
    monkeypatch.setattr(store, "save", save_with_drift)

    with pytest.raises(StateError, match="evaluation corpus"):
        publisher.publish(run_id)

    stranded = store.get(run_id)
    assert drifted
    assert stranded.status == RunStatus.SUBMITTING
    assert stranded.pull_request_creation_started
    assert stranded.pull_request_url is None
    assert github.branch_sha == stranded.commit_sha
    assert "create_pull_request" not in github.calls


def test_manual_created_pr_compensation_adopts_exact_merged_pr_without_gate_hold(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, store, run_id, github, publisher = _strand_created_pr_compensation(
        tmp_path,
        monkeypatch,
        automatic=False,
    )
    assert store.publication_gate_hold(run_id) is None
    github.pull_request_state = "closed"
    github.pull_request_merged = True
    github.pull_request_draft = False
    github.branch_sha = None

    recovered = publisher.publish(run_id)

    assert recovered.status == RunStatus.PR_OPEN
    assert recovered.pull_request_url == "https://github.com/example/project/pull/7"
    assert store.publication_gate_hold(run_id) is None
    assert "close_pull_request" not in github.calls
    assert any(
        event["event_type"] == "pull_request.compensation.reconciled"
        for event in store.events(run_id)
    )


@pytest.mark.parametrize(
    "tampered_evidence",
    ["marker", "response", "rejection", "missing_rejection"],
)
def test_created_pr_compensation_rejects_incomplete_or_tampered_base_race_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tampered_evidence: str,
) -> None:
    _, store, run_id, github, publisher = _strand_automatic_publication_after_gate_hold(
        tmp_path,
        monkeypatch,
    )
    original_create = github.create_pull_request
    original_save = store.save

    def push(
        workspace: Path,
        fork: str,
        branch: str,
        commit_sha: str,
        *,
        before_mutation,  # type: ignore[no-untyped-def]
    ) -> None:
        before_mutation()
        del workspace, fork, branch
        github.branch_sha = commit_sha

    def create(*args, **kwargs) -> PullRequestDetails:  # type: ignore[no-untyped-def]
        github.pull_request_base_sha = "e" * 40
        return original_create(*args, **kwargs)

    def save_with_tampered_evidence(*args, **kwargs):  # type: ignore[no-untyped-def]
        event = kwargs.get("event")
        details = kwargs.get("details")
        assert isinstance(event, str)
        assert isinstance(details, dict)
        kwargs = dict(kwargs)
        kwargs["details"] = dict(details)
        if event == "publication.compensation.started" and tampered_evidence == "marker":
            kwargs["details"].pop("returned_base_sha")
        elif event == "pull_request.created.response" and tampered_evidence == "response":
            kwargs["details"]["base_sha"] = store.get(run_id).base_sha
        elif event == "pull_request.created.rejected" and tampered_evidence == "rejection":
            kwargs["details"]["mismatches"] = "draft state"
        elif event == "pull_request.created.rejected" and tampered_evidence == "missing_rejection":
            kwargs["event"] = "fixture.pull_request.rejection_missing"
        return original_save(*args, **kwargs)

    def fail_cleanup(*args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        del args, kwargs
        raise AssertionError("invalid durable evidence reached remote cleanup")

    monkeypatch.setattr(publisher, "_wait_for_fork", lambda *args: None)
    monkeypatch.setattr(publisher, "_push", push)
    monkeypatch.setattr(github, "create_pull_request", create)
    monkeypatch.setattr(store, "save", save_with_tampered_evidence)
    monkeypatch.setattr(publisher, "_compensate_created_pull_request", fail_cleanup)

    with pytest.raises(StateError, match="Created-PR"):
        publisher.publish(run_id)

    durable = store.get(run_id)
    assert durable.status == RunStatus.SUBMITTING
    assert durable.publication_compensation_reason == "created_pr_base_moved"
    assert durable.pull_request_url == "https://github.com/example/project/pull/7"
    assert github.branch_sha == durable.commit_sha
    assert "close_pull_request" not in github.calls
    assert all(
        event["event_type"] != "publication.compensation.verified" for event in store.events(run_id)
    )


def test_pre_pr_compensation_rechecks_pr_absence_after_branch_absence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, store, run_id, github, publisher = _strand_automatic_pre_pr_base_compensation(
        tmp_path,
        monkeypatch,
    )
    github.branch_sha = None
    find_calls = 0

    def pull_request_appears_after_ref_check(repository: str, *, head: str) -> str | None:
        nonlocal find_calls
        del repository
        github.calls.append("find_pull_request")
        github.last_head = head
        find_calls += 1
        return "https://github.com/example/project/pull/99" if find_calls >= 3 else None

    monkeypatch.setattr(github, "find_pull_request", pull_request_appears_after_ref_check)

    with pytest.raises(PublicationResumeRequired, match="pull request appeared"):
        publisher.publish(run_id)

    assert find_calls == 3
    assert store.get(run_id).status == RunStatus.SUBMITTING
    assert store.publication_gate_hold(run_id) is not None
    assert all(
        event["event_type"] != "publication.compensation.verified" for event in store.events(run_id)
    )


def test_pre_pr_compensation_retains_branch_when_pr_appears_before_delete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, store, run_id, github, publisher = _strand_automatic_pre_pr_base_compensation(
        tmp_path,
        monkeypatch,
    )
    durable = store.get(run_id)
    find_calls = 0
    git_commands: list[list[str]] = []

    def pull_request_appears_before_delete(repository: str, *, head: str) -> str | None:
        nonlocal find_calls
        del repository
        github.calls.append("find_pull_request")
        github.last_head = head
        find_calls += 1
        return "https://github.com/example/project/pull/99" if find_calls == 2 else None

    def fake_git(workspace: Path, arguments: list[str], **kwargs: object) -> str:
        del workspace, kwargs
        git_commands.append(arguments)
        return ""

    monkeypatch.setattr(github, "find_pull_request", pull_request_appears_before_delete)
    monkeypatch.setattr("autocontribute.publication._git", fake_git)

    with pytest.raises(
        PublicationResumeRequired,
        match="appeared immediately before pre-PR branch deletion",
    ):
        publisher.publish(run_id)

    assert find_calls == 2
    assert not any("push" in command for command in git_commands)
    assert github.branch_sha == durable.commit_sha
    assert store.get(run_id).status == RunStatus.SUBMITTING
    assert all(event["event_type"] != "branch.compensated" for event in store.events(run_id))


def test_created_pr_compensation_retains_branch_when_pr_reopens_before_delete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, store, run_id, github, publisher = _strand_created_pr_compensation(
        tmp_path,
        monkeypatch,
    )
    durable = store.get(run_id)
    original_get = github.get_pull_request
    get_calls = 0
    git_commands: list[list[str]] = []

    def pull_request_reopens_before_delete(
        repository: str,
        number: int,
    ) -> PullRequestDetails:
        nonlocal get_calls
        get_calls += 1
        if get_calls == 2:
            github.pull_request_state = "open"
        return original_get(repository, number)

    def fake_git(workspace: Path, arguments: list[str], **kwargs: object) -> str:
        del workspace, kwargs
        git_commands.append(arguments)
        return ""

    monkeypatch.setattr(github, "get_pull_request", pull_request_reopens_before_delete)
    monkeypatch.setattr("autocontribute.publication._git", fake_git)

    with pytest.raises(
        PublicationResumeRequired,
        match="changed immediately before branch deletion",
    ):
        publisher.publish(run_id)

    assert get_calls == 2
    assert not any("push" in command for command in git_commands)
    assert github.pull_request_state == "open"
    assert github.branch_sha == durable.commit_sha
    assert store.get(run_id).status == RunStatus.SUBMITTING
    assert all(event["event_type"] != "branch.compensated" for event in store.events(run_id))


def test_created_pr_compensation_rechecks_pr_after_branch_absence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, store, run_id, github, publisher = _strand_created_pr_compensation(
        tmp_path,
        monkeypatch,
    )
    durable = store.get(run_id)
    assert durable.commit_sha is not None
    original_get = github.get_pull_request
    get_calls = 0

    def delete(
        fork: str,
        branch: str,
        commit_sha: str,
        *,
        expected_repository_id: int,
        expected_repository_node_id: str,
        lease_guard: LeaseHeartbeatGuard,
        before_mutation,  # type: ignore[no-untyped-def]
    ) -> None:
        del fork, branch, expected_repository_id, expected_repository_node_id
        lease_guard.assert_owned()
        before_mutation()
        assert github.branch_sha == commit_sha
        github.branch_sha = None
        lease_guard.assert_owned()

    def pull_request_reopens_after_ref_check(
        repository: str,
        number: int,
    ) -> PullRequestDetails:
        nonlocal get_calls
        details = original_get(repository, number)
        get_calls += 1
        if get_calls >= 4:
            return replace(details, state="open", closed_at=None)
        return details

    monkeypatch.setattr(publisher, "_delete_remote_branch", delete)
    monkeypatch.setattr(github, "get_pull_request", pull_request_reopens_after_ref_check)

    with pytest.raises(
        PublicationResumeRequired,
        match="changed during final branch verification",
    ):
        publisher.publish(run_id)

    assert get_calls == 4
    assert store.get(run_id).status == RunStatus.SUBMITTING
    assert store.publication_gate_hold(run_id) is not None
    assert github.branch_sha is None
    assert all(
        event["event_type"] != "publication.compensation.verified" for event in store.events(run_id)
    )
