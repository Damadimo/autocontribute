import json
import os
import re
import signal
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import ClassVar

import pytest
from typer.testing import CliRunner, Result

import autocontribute.cli as cli
from autocontribute.cli import app
from autocontribute.config import AutocontributeConfig, load_config
from autocontribute.discovery import (
    LEGAL_REQUIREMENTS_EVIDENCE_KEY,
    DiscoveryOutcome,
    IssueEvaluation,
)
from autocontribute.domain import (
    CommandResult,
    CriticReview,
    EligibilityResult,
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
from autocontribute.exceptions import (
    AutocontributeError,
    CircuitBreakerTrigger,
    GitHubError,
    PolicyError,
    PublicationLimitError,
    PublicationResumeRequired,
    ReviewTooLargeError,
    StateError,
    StopScope,
)
from autocontribute.github import (
    DirectoryEntry,
    GitHubAccount,
    RepositoryAccess,
    RepositoryIdentity,
)
from autocontribute.lifecycle import LifecycleSyncResult
from autocontribute.orchestrator import RunInvocationMode
from autocontribute.preparation import (
    compute_preparation_config_fingerprint,
    compute_preparation_fingerprint,
    render_validation_artifact,
)
from autocontribute.publication import PublicationCheck
from autocontribute.store import CandidateAttemptState, CandidateRetryAuthorization, RunStore

runner = CliRunner()

_REVIEW_PATCH = (
    "diff --git a/src/widget.py b/src/widget.py\n"
    "--- a/src/widget.py\n"
    "+++ b/src/widget.py\n"
    "@@ -1 +1 @@\n"
    "-review_patch_old_marker = 1\n"
    "+review_patch_new_marker = 2\n"
)


class _ReviewGitHub:
    api_origin = "https://api.github.com"

    def __enter__(self):  # type: ignore[no-untyped-def]
        return self

    def __exit__(self, *_: object) -> None:
        pass

    def authenticated_login(self) -> str:
        return "octocat"

    def authenticated_user(self) -> GitHubAccount:
        return GitHubAccount(login="octocat", database_id=583231)

    def get_user(self, login: str) -> GitHubAccount:
        return GitHubAccount(login=login, database_id=583231)

    def get_repository_access(self, full_name: str) -> RepositoryAccess:
        return RepositoryAccess(
            identity=RepositoryIdentity(full_name=full_name, database_id=1001, node_id="R_1001"),
            owner=full_name.split("/", 1)[0],
            fork_parent=None,
            can_push=False,
            has_pull_requests=True,
            pull_requests_from_collaborators_only=False,
        )


class _PolicyGitHub(_ReviewGitHub):
    def get_repository(self, repository: str) -> RepositoryInfo:
        return RepositoryInfo(
            full_name=repository,
            html_url=f"https://github.com/{repository}",
            clone_url=f"https://github.com/{repository}.git",
            default_branch="main",
            stars=10_000,
            archived=False,
            disabled=False,
            private=False,
            pushed_at=datetime.now(UTC),
            license_spdx="MIT",
        )

    def default_branch_sha(self, repository: str, branch: str) -> str:
        del repository, branch
        return "a" * 40

    def default_branch_sha_if_exists(self, repository: str) -> str | None:
        del repository
        return None

    def list_directory(
        self, repository: str, path: str, *, ref: str
    ) -> list[DirectoryEntry] | None:
        del ref
        if repository == "example/project" and not path:
            return [DirectoryEntry(path="CONTRIBUTING.md", kind="file")]
        return None

    def get_file(
        self,
        repository: str,
        path: str,
        *,
        ref: str,
        max_bytes: int,
    ) -> str | None:
        del ref, max_bytes
        if repository == "example/project" and path == "CONTRIBUTING.md":
            return "Contributors must complete our Contributor License Agreement before a PR."
        return None


def _ready_review_run(
    tmp_path: Path, *, runner_owner: str | None = None
) -> tuple[Path, RunStore, str]:
    """A run ready for approval; with ``runner_owner``, under an Actions runner's configuration."""

    config_path = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    runner_settings = f"publishing:\n  login: {runner_owner}\n" if runner_owner is not None else ""
    config_path.write_text(
        "identity:\n"
        "  name: Review Author Exact Marker\n"
        "  email: review-author@example.invalid\n"
        "github:\n"
        f"  auth: {'gh' if runner_owner is None else 'token'}\n"
        "  repositories: [example/project]\n"
        "validation:\n"
        "  required_commands:\n"
        "    example/project: [python -m pytest]\n"
        f"storage:\n  path: {state}\n" + runner_settings,
        encoding="utf-8",
    )
    settings = load_config(config_path)
    store = RunStore(state)
    manifest = store.create_run()
    store.transition(manifest, RunStatus.DISCOVERING, reason="fixture started")
    now = datetime.now(UTC)
    manifest.candidate = IssueCandidate(
        repository="example/project",
        number=42,
        title="ISSUE_TITLE_EXACT_MARKER",
        body="ISSUE_BODY_EXACT_MARKER\nSecond exact issue-body line.\x1b[2J",
        html_url="https://github.com/example/project/issues/42",
        state="open",
        author="issue-author-marker",
        labels=["bug", "help wanted"],
        assignees=[],
        comments=1,
        discussion=[
            IssueComment(
                author="discussion-author-marker",
                author_association="MEMBER",
                body="ISSUE_DISCUSSION_EXACT_MARKER",
                html_url=("https://github.com/example/project/issues/42#issuecomment-77"),
                created_at=now - timedelta(hours=1),
                updated_at=now,
            )
        ],
        created_at=now - timedelta(days=2),
        updated_at=now,
    )
    manifest.repository = RepositoryInfo(
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
    manifest.eligibility = EligibilityResult(
        eligible=True,
        score=100,
        evidence={LEGAL_REQUIREMENTS_EVIDENCE_KEY: "none"},
        blockers=[],
    )
    manifest.base_sha = "a" * 40
    edit = FileEdit(
        operation="replace",
        path="src/widget.py",
        find="review_patch_old_marker = 1\n",
        replace="review_patch_new_marker = 2\n",
        content=None,
        rationale="Exercise exact immutable-review evidence.",
    )
    manifest.proposal = PatchProposal(
        summary="Apply the exact review fixture change.",
        edits=[edit],
        validation_commands=["python -m pytest"],
        commit_message="COMMIT_MESSAGE_EXACT_MARKER",
        pull_request_title="PR_TITLE_EXACT_MARKER",
        pull_request_body=("PR_BODY_EXACT_MARKER\n\n---\n\n" + settings.policy.ai_disclosure),
        limitations=[],
    )
    review = CriticReview(
        verdict="approve",
        summary="The focused fixture change is ready.",
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
        issue_requirements_met=["The exact marker is updated."],
        issue_requirements_missing=[],
        test_evidence_assessment="The configured command passed.",
        maintainer_perspective="Small and reviewable.",
    )
    manifest.patched_validation = [
        CommandResult(
            command="python -m pytest",
            exit_code=0,
            duration_seconds=1.25,
            stdout="VALIDATION_STDOUT_EXACT_MARKER",
            stderr="VALIDATION_STDERR_EXACT_MARKER",
        )
    ]
    manifest.quality = QualityReport(
        ready=True,
        readiness_score=95,
        gates=[GateResult(gate="fixture", passed=True, evidence="passed")],
        review=review,
        changed_files=1,
        changed_lines=2,
    )
    store.write_artifact(manifest.run_id, "contribution.patch", _REVIEW_PATCH)
    store.write_artifact(
        manifest.run_id,
        "validation.json",
        render_validation_artifact(manifest),
    )
    manifest.preparation_config_fingerprint = compute_preparation_config_fingerprint(
        settings,
        repository="example/project",
    )
    manifest.preparation_fingerprint = compute_preparation_fingerprint(
        manifest,
        diff=_REVIEW_PATCH,
    )
    lease_owner = f"review-fixture-{manifest.run_id}"
    lease = store.acquire_lease(
        "autocontribute.run",
        lease_owner,
        ttl=timedelta(minutes=1),
    )
    assert lease is not None
    store.claim_candidate(manifest, lease=lease)
    assert store.release_lease("autocontribute.run", lease_owner, lease.generation)
    manifest.status = RunStatus.READY_FOR_APPROVAL
    store.save(manifest, event="fixture.ready_for_review", details={})
    return config_path, store, manifest.run_id


def test_approval_review_ignores_tampered_report_and_approves_displayed_fingerprint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path, store, run_id = _ready_review_run(tmp_path)
    forged_marker = "FORGED_REPORT_CONTENT_MUST_NEVER_BE_REVIEWED"
    (store.artifact_dir(run_id) / "report.md").write_text(
        f"# Trusted review\n\n{forged_marker}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "_github_client", lambda *_: _ReviewGitHub())

    shown = runner.invoke(
        app,
        ["runs", "show", run_id, "--config", str(config_path)],
    )
    displayed = re.search(r"Resulting approval fingerprint\s+([0-9a-f]{64})", shown.output)
    assert displayed is not None, shown.output
    approved = runner.invoke(
        app,
        [
            "approve",
            run_id,
            "--yes",
            "--fingerprint",
            displayed.group(1)[:12],
            "--config",
            str(config_path),
        ],
    )

    assert shown.exit_code == 0, shown.output
    assert approved.exit_code == 0, approved.output
    durable = store.get(run_id)
    assert durable.status == RunStatus.APPROVED
    assert durable.approval is not None
    expected_markers = [
        "ISSUE_TITLE_EXACT_MARKER",
        "ISSUE_BODY_EXACT_MARKER",
        "Second exact issue-body line.",
        "discussion-author-marker",
        "MEMBER",
        "ISSUE_DISCUSSION_EXACT_MARKER",
        "https://github.com/example/project/issues/42#issuecomment-77",
        "diff --git a/src/widget.py b/src/widget.py",
        "-review_patch_old_marker = 1",
        "+review_patch_new_marker = 2",
        "VALIDATION_STDOUT_EXACT_MARKER",
        "VALIDATION_STDERR_EXACT_MARKER",
        "PR_TITLE_EXACT_MARKER",
        "PR_BODY_EXACT_MARKER",
        "COMMIT_MESSAGE_EXACT_MARKER",
        "Review Author Exact Marker",
        "review-author@example.invalid",
        "Head repository: octocat/project (fork)",
        durable.approval.manifest_hash,
    ]
    for result in (shown, approved):
        assert forged_marker not in result.output
        assert "\x1b" not in result.output
        assert r"\x1b[2J" in result.output
        for marker in expected_markers:
            assert marker in result.output
        assert result.output.count("Review Author Exact Marker") >= 2
        assert result.output.count("review-author@example.invalid") >= 2


def test_approval_rejects_evidence_race_after_interactive_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path, store, run_id = _ready_review_run(tmp_path)
    monkeypatch.setattr(cli, "_github_client", lambda *_: _ReviewGitHub())
    confirmations: list[str] = []

    def mutate_evidence_then_confirm(prompt: str, **_: object) -> bool:
        confirmations.append(prompt)
        mutated = store.get(run_id)
        assert mutated.proposal is not None
        mutated.proposal.pull_request_title = "PR_TITLE_RACED_AFTER_REVIEW"
        patch = (store.artifact_dir(run_id) / "contribution.patch").read_bytes()
        mutated.preparation_fingerprint = compute_preparation_fingerprint(
            mutated,
            diff=patch,
        )
        store.save(mutated, event="fixture.review_race", details={})
        return True

    monkeypatch.setattr(cli.typer, "confirm", mutate_evidence_then_confirm)

    result = runner.invoke(
        app,
        ["approve", run_id, "--config", str(config_path)],
    )

    assert result.exit_code == 3, result.output
    assert len(confirmations) == 1
    assert "PR_TITLE_EXACT_MARKER" in result.output
    assert "PR_TITLE_RACED_AFTER_REVIEW" not in result.output
    assert "review" in result.output.casefold()
    assert "changed" in result.output.casefold()
    durable = store.get(run_id)
    assert durable.status == RunStatus.READY_FOR_APPROVAL
    assert durable.approval is None
    assert "approval.created" not in {event["event_type"] for event in store.events(run_id)}


def _review_fingerprint(config_path: Path, store: RunStore, run_id: str) -> str:
    review = cli.build_approval_review(
        load_config(config_path),
        store,
        run_id,
        github=_ReviewGitHub(),  # type: ignore[arg-type]
    )
    return review.fingerprint


def _forbid_github(*_: object) -> None:
    pytest.fail("this approval must be decided without GitHub")


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (["--yes"], "--yes needs --fingerprint"),
        (["--json", "--fingerprint", "a" * 12], "--json cannot prompt"),
        (["--yes", "--fingerprint", "a" * 11], "12 to 64 lowercase hex characters"),
        (["--yes", "--fingerprint", "A" * 12], "12 to 64 lowercase hex characters"),
    ],
)
def test_approve_refuses_blind_or_malformed_fingerprints_before_github(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    arguments: list[str],
    message: str,
) -> None:
    config_path, store, run_id = _ready_review_run(tmp_path)
    events = store.events(run_id)
    monkeypatch.setattr(cli, "_github_client", _forbid_github)

    result = runner.invoke(app, ["approve", run_id, *arguments, "--config", str(config_path)])

    assert result.exit_code == 1, result.output
    assert message in result.output
    assert store.get(run_id).status is RunStatus.READY_FOR_APPROVAL
    assert store.events(run_id) == events


def test_approve_binds_a_fingerprint_prefix_and_records_its_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path, store, run_id = _ready_review_run(tmp_path)
    fingerprint = _review_fingerprint(config_path, store, run_id)
    source = "https://github.com/octocat/runner/issues/3#issuecomment-99"
    monkeypatch.setattr(cli, "_github_client", lambda *_: _ReviewGitHub())
    command = [
        "approve",
        run_id,
        "--fingerprint",
        fingerprint[:12],
        "--source",
        source,
        "--yes",
        "--json",
        "--config",
        str(config_path),
    ]

    approved = runner.invoke(app, command)
    events_after_approval = store.events(run_id)
    monkeypatch.setattr(cli, "_github_client", _forbid_github)
    repeated = runner.invoke(app, command)

    assert approved.exit_code == 0, approved.output
    first = json.loads(approved.output)
    durable = store.get(run_id)
    assert durable.status is RunStatus.APPROVED
    assert durable.approval is not None
    assert first == {
        "run_id": run_id,
        "outcome": "approved",
        "status": "approved",
        "fingerprint": fingerprint,
        "actor": "octocat",
        "approved_at": durable.approval.approved_at.isoformat(),
        "expires_at": durable.approval.expires_at.isoformat(),
    }
    assert durable.approval.attestation.endswith(f"Source: {source}")
    assert [event["event_type"] for event in events_after_approval[-3:]] == [
        "approval.created",
        "approval.source",
        "run.transitioned",
    ]
    assert json.loads(events_after_approval[-2]["details"]) == {"url": source}
    assert repeated.exit_code == 0, repeated.output
    assert json.loads(repeated.output) == {**first, "outcome": "already_approved"}
    assert store.events(run_id) == events_after_approval


def test_approve_reports_a_stale_fingerprint_with_its_own_exit_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path, store, run_id = _ready_review_run(tmp_path)
    fingerprint = _review_fingerprint(config_path, store, run_id)
    stale = ("0" if fingerprint[0] != "0" else "1") + fingerprint[1:12]
    monkeypatch.setattr(cli, "_github_client", lambda *_: _ReviewGitHub())

    result = runner.invoke(
        app,
        [
            "approve",
            run_id,
            "--fingerprint",
            stale,
            "--yes",
            "--json",
            "--config",
            str(config_path),
        ],
    )

    assert result.exit_code == 3, result.output
    assert json.loads(result.output) == {
        "run_id": run_id,
        "outcome": "fingerprint_mismatch",
        "message": "Approval evidence changed after review; inspect the run again before approving",
    }
    assert store.get(run_id).approval is None


def test_approve_refuses_a_bad_source_and_an_expired_repeat(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path, store, run_id = _ready_review_run(tmp_path)
    fingerprint = _review_fingerprint(config_path, store, run_id)
    monkeypatch.setattr(cli, "_github_client", lambda *_: _ReviewGitHub())
    command = ["approve", run_id, "--fingerprint", fingerprint, "--yes", "--json"]

    insecure = runner.invoke(
        app,
        [*command, "--source", "http://example.invalid/comment", "--config", str(config_path)],
    )
    assert insecure.exit_code == 1, insecure.output
    assert "https URL" in json.loads(insecure.output)["message"]
    assert store.get(run_id).approval is None

    approved = runner.invoke(app, [*command, "--config", str(config_path)])
    assert approved.exit_code == 0, approved.output
    expired = store.get(run_id)
    assert expired.approval is not None
    expired.approval.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    store.save(expired, event="fixture.approval_expired", details={})

    repeated = runner.invoke(app, [*command, "--config", str(config_path)])

    assert repeated.exit_code == 1, repeated.output
    assert "the approval expired" in json.loads(repeated.output)["message"]


def test_runs_review_writes_a_github_issue_body(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path, store, run_id = _ready_review_run(tmp_path)
    fingerprint = _review_fingerprint(config_path, store, run_id)
    monkeypatch.setattr(cli, "_github_client", lambda *_: _ReviewGitHub())
    output = tmp_path / "issue"

    result = runner.invoke(
        app,
        [
            "runs",
            "review",
            run_id,
            "--format",
            "github",
            "--output-dir",
            str(output),
            "--json",
            "--config",
            str(config_path),
        ],
    )

    assert result.exit_code == 0, result.output
    body = (output / "body.md").read_text(encoding="utf-8")
    assert json.loads(result.output) == {
        "run_id": run_id,
        "fingerprint": fingerprint,
        "approval_command": f"/approve {fingerprint[:12]}",
        "body": str(output.resolve() / "body.md"),
        "body_characters": len(body),
        "parts": [],
        "shortened": [],
    }
    assert body.startswith(f"<!-- autocontribute:run={run_id} -->\n")
    assert f"/approve {fingerprint[:12]}" in body
    assert "PR_BODY_EXACT_MARKER" in body
    assert "+review_patch_new_marker = 2" in body
    assert sorted(path.name for path in output.iterdir()) == ["body.md"]


def test_runs_review_refuses_a_used_directory_and_reports_a_review_too_large(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path, _, run_id = _ready_review_run(tmp_path)
    used = tmp_path / "used"
    used.mkdir()
    (used / "body.md").write_text("old", encoding="utf-8")
    command = ["runs", "review", run_id, "--format", "github", "--json"]
    monkeypatch.setattr(cli, "_github_client", _forbid_github)

    refused = runner.invoke(
        app,
        [*command, "--output-dir", str(used), "--config", str(config_path)],
    )

    def too_large(*_: object, **__: object) -> None:
        raise ReviewTooLargeError("The review needs more than an issue body and 5 comments")

    monkeypatch.setattr(cli, "_github_client", lambda *_: _ReviewGitHub())
    monkeypatch.setattr(cli, "render_github_review", too_large)
    fresh = tmp_path / "fresh"
    oversized = runner.invoke(
        app,
        [*command, "--output-dir", str(fresh), "--config", str(config_path)],
    )

    assert refused.exit_code == 1
    assert "must be a new or empty directory" in json.loads(refused.output)["message"]
    assert (used / "body.md").read_text(encoding="utf-8") == "old"
    assert oversized.exit_code == 4
    assert json.loads(oversized.output) == {
        "run_id": run_id,
        "outcome": "too_large",
        "message": "The review needs more than an issue body and 5 comments",
    }
    assert not fresh.exists()


def test_init_and_config_validation_are_offline(tmp_path: Path) -> None:
    config = tmp_path / "autocontribute.yml"

    initialized = runner.invoke(app, ["init", "--path", str(config)])
    refused = runner.invoke(
        app,
        ["config", "validate", "--config", str(config)],
    )

    assert initialized.exit_code == 0, initialized.output
    assert config.is_file()
    assert refused.exit_code == 1, refused.output
    refusal = " ".join(refused.output.split())
    assert "still contains starter placeholders" in refusal
    assert "github.repositories lists your-org/your-repo" in refusal
    assert "sandbox.image comes from the example.invalid placeholder registry" in refusal
    assert "identity" not in refusal
    assert "Configuration is valid" not in refusal

    config.write_text(
        config.read_text(encoding="utf-8")
        .replace("your-org/your-repo", "example/project")
        .replace("example.invalid/sandbox@sha256:", "ghcr.io/example/sandbox@sha256:"),
        encoding="utf-8",
    )
    validated = runner.invoke(
        app,
        ["config", "validate", "--config", str(config)],
    )

    assert validated.exit_code == 0, validated.output
    assert "Configuration is valid" in validated.output
    assert "gpt-5.6" in validated.output


@pytest.mark.parametrize("command", (["doctor"], ["discover"], ["run"], ["run", "--scheduled"]))
def test_commands_refuse_starter_placeholders_before_external_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: list[str],
) -> None:
    config = tmp_path / "autocontribute.yml"
    config.write_text(
        "identity:\n"
        '  name: "Your Name"\n'
        '  email: "your-handle@users.noreply.github.com"\n'
        "github:\n"
        "  repositories: [your-org/your-repo]\n"
        "validation:\n"
        "  required_commands:\n"
        "    your-org/your-repo: [python -m pytest]\n"
        "sandbox:\n"
        f"  image: example.invalid/sandbox@sha256:{'0' * 64}\n"
        f"storage:\n  path: {tmp_path / 'state'}\n",
        encoding="utf-8",
    )

    def unexpected(*_: object, **__: object) -> None:
        pytest.fail("a placeholder configuration must stop before any external work")

    monkeypatch.setattr(cli, "_github_client", unexpected)
    monkeypatch.setattr(cli, "run_doctor", unexpected)
    monkeypatch.setattr(cli, "RunStore", unexpected)

    result = runner.invoke(app, [*command, "--config", str(config)])

    assert result.exit_code == 1, result.output
    output = " ".join(result.output.split())
    assert "still contains starter placeholders" in output
    for placeholder in (
        "github.repositories lists your-org/your-repo",
        "sandbox.image comes from the example.invalid placeholder registry",
        'identity.name is "Your Name"',
        'identity.email is "your-handle@users.noreply.github.com"',
    ):
        assert placeholder in output
    assert not (tmp_path / "state").exists()


@pytest.mark.parametrize("approved", (False, True))
def test_runs_cancel_releases_a_prepared_run_and_records_the_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    approved: bool,
) -> None:
    config_path, store, run_id = _ready_review_run(tmp_path)
    if approved:
        monkeypatch.setattr(cli, "_github_client", lambda *_: _ReviewGitHub())
        approval = runner.invoke(
            app,
            ["approve", run_id, "--config", str(config_path)],
            input="y\n",
        )
        assert approval.exit_code == 0, approval.output
    prepared = store.get(run_id)
    assert prepared.status is (RunStatus.APPROVED if approved else RunStatus.READY_FOR_APPROVAL)
    assert prepared.candidate is not None
    active = store.candidate_attempt_disposition(prepared.candidate)
    assert active.state is CandidateAttemptState.ACTIVE

    result = runner.invoke(
        app,
        [
            "runs",
            "cancel",
            run_id,
            "--reason",
            "  The maintainer fixed the issue upstream.  ",
            "--config",
            str(config_path),
        ],
        input="y\n",
    )

    assert result.exit_code == 0, result.output
    assert f"Autocontribute run `{run_id}`" in result.output
    assert f"Cancel run {run_id} and release its issue" in result.output
    cancelled = store.get(run_id)
    assert cancelled.status is RunStatus.CANCELLED
    transition = store.events(run_id)[-1]
    assert transition["event_type"] == "run.transitioned"
    assert json.loads(transition["details"]) == {
        "from": prepared.status.value,
        "to": "cancelled",
        "reason": "The maintainer fixed the issue upstream.",
    }
    released = store.candidate_attempt_disposition(prepared.candidate)
    assert released.state is CandidateAttemptState.SUPPRESSED
    assert released.prior_run_id == run_id
    assert "`cancelled`" in (store.artifact_dir(run_id) / "report.md").read_text(encoding="utf-8")


def test_runs_cancel_requires_a_reason_and_confirmation(tmp_path: Path) -> None:
    config_path, store, run_id = _ready_review_run(tmp_path)
    events = store.events(run_id)

    missing = runner.invoke(app, ["runs", "cancel", run_id, "--config", str(config_path)])
    blank = runner.invoke(
        app,
        ["runs", "cancel", run_id, "--reason", " \t ", "--yes", "--config", str(config_path)],
    )
    declined = runner.invoke(
        app,
        ["runs", "cancel", run_id, "--reason", "Duplicate work", "--config", str(config_path)],
        input="n\n",
    )

    assert missing.exit_code == 2
    assert blank.exit_code == 1, blank.output
    assert "--reason must explain why the run is cancelled" in blank.output
    assert declined.exit_code == 1, declined.output
    assert f"Autocontribute run `{run_id}`" in declined.output
    assert store.get(run_id).status is RunStatus.READY_FOR_APPROVAL
    assert store.events(run_id) == events


# The store also allows QUEUED -> CANCELLED, but a queued run belongs to a live worker.
@pytest.mark.parametrize("status", (RunStatus.QUEUED, RunStatus.FAILED, RunStatus.CANCELLED))
def test_runs_cancel_refuses_runs_that_are_not_awaiting_approval_or_publication(
    tmp_path: Path,
    status: RunStatus,
) -> None:
    state = tmp_path / "state"
    config = tmp_path / "autocontribute.yml"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    store = RunStore(state)
    manifest = store.create_run()
    if status is not RunStatus.QUEUED:
        store.transition(manifest, status, reason="fixture")
    events = store.events(manifest.run_id)

    result = runner.invoke(
        app,
        [
            "runs",
            "cancel",
            manifest.run_id,
            "--reason",
            "No longer wanted",
            "--yes",
            "--config",
            str(config),
        ],
    )

    assert result.exit_code == 1, result.output
    output = " ".join(result.output.split())
    assert f"Run {manifest.run_id} is {status.value}" in output
    assert "only ready_for_approval or approved runs can be cancelled" in output
    assert store.get(manifest.run_id).status is status
    assert store.events(manifest.run_id) == events


def _discovery_outcome(*, selected: bool) -> DiscoveryOutcome:
    repository = _PolicyGitHub().get_repository("example/project")
    now = datetime.now(UTC)

    def evaluation(number: int, blockers: list[str], kinds: tuple[str, ...]) -> IssueEvaluation:
        issue = IssueCandidate(
            repository="example/project",
            number=number,
            title=f"Issue title {number}",
            body="Expected 2, actual 1.",
            html_url=f"https://github.com/example/project/issues/{number}",
            state="open",
            author="reporter",
            labels=["help wanted"],
            assignees=[],
            comments=0,
            created_at=now,
            updated_at=now,
        )
        return IssueEvaluation(
            issue=issue,
            repository=repository,
            eligibility=EligibilityResult(
                eligible=not blockers,
                score=70 if not blockers else 40,
                evidence={
                    "invitation": "25/25",
                    "ai_policy": "disclose AI use as [our policy](docs/ai.md) says [/b]",
                },
                blockers=blockers,
            ),
            blocker_kinds=kinds,
            notes=(
                ("stale linked PR, not blocking: https://github.com/example/project/pull/9",)
                if blockers
                else ()
            ),
        )

    eligible = evaluation(42, [], ())
    blocked = evaluation(
        43,
        ["issue is already assigned", "candidate score 40 is below the floor of 60"],
        ("assigned", "low score"),
    )
    return DiscoveryOutcome(
        selection=(
            (eligible.issue, eligible.repository, eligible.eligibility) if selected else None
        ),
        evaluations=(eligible, blocked) if selected else (blocked,),
        skipped_repositories=(("small/project", "repository is below the star floor"),),
        repository_errors=(("broken/project", "Search timed out"),),
        issue_errors=(("example/project#7", "Issue changed while it was fetched"),),
    )


@pytest.mark.parametrize("selected", [True, False])
def test_discover_explain_lists_every_issue_skip_and_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    selected: bool,
) -> None:
    config = tmp_path / "autocontribute.yml"
    config.write_text(
        "github:\n"
        "  repositories: [example/project]\n"
        "validation:\n"
        "  required_commands:\n"
        "    example/project: [python -m pytest]\n"
        f"storage:\n  path: {tmp_path / 'state'}\n",
        encoding="utf-8",
    )
    outcome = _discovery_outcome(selected=selected)

    class FakeDiscovery:
        def __init__(self, *_: object) -> None:
            pass

        def discover(self) -> DiscoveryOutcome:
            return outcome

    monkeypatch.setattr(cli, "_github_client", lambda *_: _ReviewGitHub())
    monkeypatch.setattr(cli, "DiscoveryService", FakeDiscovery)

    plain = runner.invoke(app, ["discover", "--config", str(config)])
    explained = runner.invoke(app, ["discover", "--explain", "--config", str(config)])

    assert plain.exit_code == 0, plain.output
    assert explained.exit_code == 0, explained.output
    assert "Issue title 43" not in plain.output
    assert "Search timed out" not in plain.output
    explanation = explained.output.splitlines()
    for line in (
        "Repositories skipped or failed:",
        "  small/project: skipped: repository is below the star floor",
        "  broken/project: error: Search timed out",
        "Issues:",
        "  example/project#43 (score 40, blocked): Issue title 43",
        "    - issue is already assigned",
        "    - candidate score 40 is below the floor of 60",
        "    note: stale linked PR, not blocking: https://github.com/example/project/pull/9",
        "  example/project#7: error: Issue changed while it was fetched",
    ):
        assert line in explanation
    if selected:
        assert "  example/project#42 (score 70, eligible): Issue title 42" in explanation
        summary = (
            "2 issues evaluated, 1 eligible; 1 candidate failed discovery gates "
            "(assigned 1, low score 1); 1 repository was skipped; 1 repository could not be "
            "searched; 1 issue could not be evaluated."
        )
        assert "example/project#42" in plain.output
        assert (
            "  ai_policy: disclose AI use as [our policy](docs/ai.md) says [/b]"
            in plain.output.splitlines()
        )
        for output in (plain.output, explained.output):
            assert summary in " ".join(output.split())
    else:
        reason = (
            "No candidate is currently available: 1 candidate failed discovery gates "
            "(assigned 1, low score 1); 1 repository was skipped; 1 repository could not be "
            "searched; 1 issue could not be evaluated."
        )
        for output in (plain.output, explained.output):
            assert reason in " ".join(output.split())


_RUN_SUMMARY_KEYS = {
    "run_id",
    "status",
    "repository",
    "issue_number",
    "issue_url",
    "created_at",
    "updated_at",
    "approval_expires_at",
    "pull_request_url",
    "skip_reason",
    "error",
}


def test_runs_list_selects_statuses_as_json_oldest_first(tmp_path: Path) -> None:
    config_path, store, ready_id = _ready_review_run(tmp_path)
    queued = store.create_run()
    failed = store.create_run()
    store.transition(failed, RunStatus.FAILED, reason="fixture")

    result = runner.invoke(
        app,
        [
            "runs",
            "list",
            "--status",
            "ready_for_approval, queued",
            "--json",
            "--config",
            str(config_path),
        ],
    )

    assert result.exit_code == 0, result.output
    listed = json.loads(result.output)
    assert [item["run_id"] for item in listed] == [ready_id, queued.run_id]
    assert all(set(item) == _RUN_SUMMARY_KEYS for item in listed)
    ready = listed[0]
    assert ready["status"] == "ready_for_approval"
    assert ready["repository"] == "example/project"
    assert ready["issue_number"] == 42
    assert ready["issue_url"] == "https://github.com/example/project/issues/42"
    assert ready["approval_expires_at"] is None
    assert listed[1]["repository"] is None


def test_runs_list_refuses_to_truncate_a_status_selection(tmp_path: Path) -> None:
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    store = RunStore(state)
    for _ in range(3):
        store.transition(store.create_run(), RunStatus.FAILED, reason="fixture")

    truncated = runner.invoke(
        app,
        ["runs", "list", "--status", "failed", "--limit", "2", "--json", "--config", str(config)],
    )
    unknown = runner.invoke(
        app,
        ["runs", "list", "--status", "failed,finished", "--json", "--config", str(config)],
    )
    unfiltered = runner.invoke(
        app,
        ["runs", "list", "--limit", "2", "--json", "--config", str(config)],
    )

    assert truncated.exit_code == 1
    assert json.loads(truncated.output) == {
        "outcome": "error",
        "message": "Selected run set exceeds the configured safety bound",
    }
    assert unknown.exit_code == 1
    refusal = json.loads(unknown.output)
    assert refusal["outcome"] == "error"
    assert "--status takes comma-separated statuses from: queued" in refusal["message"]
    assert unfiltered.exit_code == 0, unfiltered.output
    assert len(json.loads(unfiltered.output)) == 2


def test_init_does_not_overwrite_without_force(tmp_path: Path) -> None:
    config = tmp_path / "autocontribute.yml"
    config.write_text("sentinel", encoding="utf-8")

    result = runner.invoke(app, ["init", "--path", str(config)])

    assert result.exit_code == 1
    assert config.read_text(encoding="utf-8") == "sentinel"


def test_policy_inspection_and_explicit_cla_attestation_preview(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = tmp_path / "autocontribute.yml"
    config.write_text(
        "github:\n"
        "  repositories: [example/project]\n"
        "validation:\n"
        "  required_commands:\n"
        "    example/project: [python -m pytest]\n"
        f"storage:\n  path: {tmp_path / 'state'}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "_github_client", lambda *_: _PolicyGitHub())

    inspected = runner.invoke(
        app,
        ["policy", "inspect", "example/project", "--config", str(config)],
    )
    missing_authorization = runner.invoke(
        app,
        ["policy", "attest", "example/project", "--yes", "--config", str(config)],
    )
    attested = runner.invoke(
        app,
        [
            "policy",
            "attest",
            "example/project",
            "--cla-completed",
            "--yes",
            "--config",
            str(config),
        ],
    )

    assert inspected.exit_code == 0, inspected.output
    assert "Repository policy ref: " + "a" * 40 in inspected.output
    assert "Organization policy ref: absent" in inspected.output
    assert "Stable legal-policy SHA-256:" in inspected.output
    assert "Detected legal requirements: cla" in inspected.output
    assert (
        "https://github.com/example/project/blob/" + "a" * 40 + "/CONTRIBUTING.md"
        in inspected.output
    )
    assert missing_authorization.exit_code == 1
    assert "require you to --cla-completed" in missing_authorization.output
    assert attested.exit_code == 0, attested.output
    assert "legal_attestations:" in attested.output
    assert "repository: example/project" in attested.output
    assert "reviewed_repository_ref: " + "a" * 40 in attested.output
    assert "reviewed_organization_policy_ref: absent" in attested.output
    assert "legal_policy_sha256:" in attested.output
    assert "legal_requirements:" in attested.output
    assert "attested_by: octocat" in attested.output
    assert "statement:" in attested.output


def test_policy_attestation_refuses_policy_files_that_could_not_be_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _UnreadablePolicyGitHub(_PolicyGitHub):
        def get_file(
            self,
            repository: str,
            path: str,
            *,
            ref: str,
            max_bytes: int = 1_000_000,
        ) -> str | None:
            del repository, path, ref, max_bytes
            raise GitHubError("GitHub policy file could not be decoded safely")

    config = tmp_path / "autocontribute.yml"
    config.write_text(
        "github:\n"
        "  repositories: [example/project]\n"
        "validation:\n"
        "  required_commands:\n"
        "    example/project: [python -m pytest]\n"
        f"storage:\n  path: {tmp_path / 'state'}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "_github_client", lambda *_: _UnreadablePolicyGitHub())

    attested = runner.invoke(
        app,
        [
            "policy",
            "attest",
            "example/project",
            "--cla-completed",
            "--yes",
            "--config",
            str(config),
        ],
    )

    assert attested.exit_code == 1
    assert (
        "Problem: policy file example/project/CONTRIBUTING.md could not be read" in attested.output
    )
    assert "no attestation can cover them" in attested.output


def test_policy_attestation_requires_interactive_personal_confirmation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = tmp_path / "autocontribute.yml"
    config.write_text(
        "github:\n"
        "  repositories: [example/project]\n"
        "validation:\n"
        "  required_commands:\n"
        "    example/project: [python -m pytest]\n"
        f"storage:\n  path: {tmp_path / 'state'}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "_github_client", lambda *_: _PolicyGitHub())
    confirmations: list[str] = []

    def decline(prompt: str, **_: object) -> bool:
        confirmations.append(prompt)
        return False

    monkeypatch.setattr(cli.typer, "confirm", decline)

    result = runner.invoke(
        app,
        [
            "policy",
            "attest",
            "example/project",
            "--cla-completed",
            "--config",
            str(config),
        ],
    )

    assert result.exit_code == 1
    assert len(confirmations) == 1
    assert "personally make" in confirmations[0]
    assert "legal_attestations:" not in result.output


def test_safety_cli_persists_stop_status_and_audited_resume(tmp_path: Path) -> None:
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")

    stopped = runner.invoke(
        app,
        [
            "safety",
            "stop",
            "--actor",
            "operator",
            "--reason",
            "Review maintainer feedback",
            "--config",
            str(config),
        ],
    )
    status = runner.invoke(
        app,
        ["safety", "status", "--config", str(config), "--json"],
    )
    breaker_before_resume = RunStore(state).circuit_breaker_status()
    trigger_hash = breaker_before_resume.trigger_hash
    active_revision = breaker_before_resume.active_revision
    assert trigger_hash is not None
    assert active_revision is not None
    resumed = runner.invoke(
        app,
        [
            "safety",
            "resume",
            "--actor",
            "operator",
            "--reason",
            "Feedback reviewed and stop condition resolved",
            "--expected-trigger-hash",
            active_revision,
            "--config",
            str(config),
        ],
    )

    assert stopped.exit_code == 0, stopped.output
    assert "Safety stop activated" in stopped.output
    assert status.exit_code == 0, status.output
    assert '"is_tripped": true' in status.output
    assert '"reason": "Review maintainer feedback"' in status.output
    assert f'"trigger_hash": "{trigger_hash}"' in status.output
    assert f'"active_revision": "{active_revision}"' in status.output
    assert resumed.exit_code == 0, resumed.output
    assert "explicitly resumed" in resumed.output
    breaker = RunStore(state).circuit_breaker_status()
    assert not breaker.is_tripped
    assert breaker.epoch == 2


def _repository_hold(state: Path) -> None:
    RunStore(state).record_stop(
        CircuitBreakerTrigger(
            source="github_lifecycle:example/project#7:closed_unmerged",
            reason="Pull request was closed without being merged",
            trigger_hash="a" * 64,
            scope=StopScope.REPOSITORY,
            scope_key="example/project",
            expires_at=datetime(2030, 1, 1, tzinfo=UTC),
        )
    )


def test_safety_status_lists_holds_and_release_clears_one(tmp_path: Path) -> None:
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    _repository_hold(state)

    text = runner.invoke(app, ["safety", "status", "--config", str(config)])
    as_json = runner.invoke(app, ["safety", "status", "--config", str(config), "--json"])

    def release(hold_id: str, reason: str = "Reviewed the closed PR") -> Result:
        return runner.invoke(
            app,
            [
                "safety",
                "release",
                hold_id,
                "--actor",
                "operator",
                "--reason",
                reason,
                "--config",
                str(config),
            ],
        )

    blank = release("1", " ")
    released = release("1")
    again = release("1")
    missing = release("99")

    assert text.exit_code == 0, text.output
    assert "OPERATIONAL" in text.output
    assert (
        "  1. repository example/project (until 2030-01-01T00:00:00+00:00): "
        "github_lifecycle:example/project#7:closed_unmerged: "
        "Pull request was closed without being merged"
    ) in text.output
    assert as_json.exit_code == 0, as_json.output
    (hold,) = json.loads(as_json.output)["holds"]
    assert {key: hold[key] for key in ("id", "scope", "scope_key", "expires_at")} == {
        "id": 1,
        "scope": "repository",
        "scope_key": "example/project",
        "expires_at": "2030-01-01T00:00:00+00:00",
    }
    assert blank.exit_code == 1
    assert released.exit_code == 0, released.output
    assert "Released hold 1." in released.output
    assert "already released" in again.output
    assert missing.exit_code == 1
    assert "Unknown hold: 99" in missing.output
    assert RunStore(state).active_holds() == []
    cleared = runner.invoke(app, ["safety", "status", "--config", str(config)])
    assert "Active holds: none" in cleared.output


def test_safety_stop_while_stopped_records_new_evidence_and_validates_input(
    tmp_path: Path,
) -> None:
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")

    first = runner.invoke(
        app,
        [
            "safety",
            "stop",
            "--actor",
            "first",
            "--reason",
            "first reason",
            "--config",
            str(config),
        ],
    )
    second = runner.invoke(
        app,
        [
            "safety",
            "stop",
            "--actor",
            "second",
            "--reason",
            "second reason",
            "--config",
            str(config),
        ],
    )
    blank = runner.invoke(
        app,
        [
            "safety",
            "stop",
            "--actor",
            " ",
            "--reason",
            "ignored",
            "--config",
            str(config),
        ],
    )

    assert first.exit_code == 0, first.output
    assert second.exit_code == 0, second.output
    assert blank.exit_code == 1, blank.output
    status = RunStore(state).circuit_breaker_status()
    assert len(status.active_triggers) == 2
    assert status.source == "operator:second"
    assert status.reason == "second reason"


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (["--retry-unchanged"], "--retry-unchanged requires --issue"),
        (
            ["--issue", "example/project#42", "--retry-unchanged"],
            "--retry-unchanged requires both --retry-actor and --retry-reason",
        ),
        (
            [
                "--issue",
                "example/project#42",
                "--retry-unchanged",
                "--retry-actor",
                "release-operator",
            ],
            "--retry-unchanged requires both --retry-actor and --retry-reason",
        ),
        (
            [
                "--issue",
                "example/project#42",
                "--retry-unchanged",
                "--retry-reason",
                "Reviewed prior result",
            ],
            "--retry-unchanged requires both --retry-actor and --retry-reason",
        ),
        (
            ["--retry-actor", "release-operator"],
            "--retry-actor and --retry-reason require --retry-unchanged",
        ),
        (
            ["--retry-reason", "Reviewed prior result"],
            "--retry-actor and --retry-reason require --retry-unchanged",
        ),
        (
            ["--scheduled", "--issue", "example/project#42"],
            "--scheduled cannot be combined with --issue",
        ),
        (
            [
                "--scheduled",
                "--issue",
                "example/project#42",
                "--retry-unchanged",
                "--retry-actor",
                "release-operator",
                "--retry-reason",
                "Reviewed prior result",
            ],
            "--retry-unchanged cannot be used by a scheduled invocation",
        ),
    ],
)
def test_retry_unchanged_cli_combinations_fail_before_configuration_or_github(
    arguments: list[str],
    message: str,
) -> None:
    result = runner.invoke(app, ["run", *arguments])

    assert result.exit_code == 1, result.output
    assert message in result.output


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("--retry-actor", " ", "candidate retry actor must be 1-255 non-NUL characters"),
        (
            "--retry-actor",
            "release\noperator",
            "candidate retry actor must be a canonical single-line value",
        ),
        (
            "--retry-actor",
            "a" * 256,
            "candidate retry actor must be 1-255 non-NUL characters",
        ),
        ("--retry-reason", " ", "candidate retry reason must be 1-2000 non-NUL characters"),
        (
            "--retry-reason",
            "reviewed\nprior result",
            "candidate retry reason must be canonical single-line text",
        ),
        (
            "--retry-reason",
            "r" * 2_001,
            "candidate retry reason must be 1-2000 non-NUL characters",
        ),
    ],
)
def test_malformed_retry_provenance_fails_before_configuration_or_github(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: str,
    message: str,
) -> None:
    def unexpected_config(*_: object, **__: object) -> None:
        raise AssertionError("configuration should not be loaded")

    monkeypatch.setattr(cli, "_config", unexpected_config)
    arguments = [
        "run",
        "--issue",
        "example/project#42",
        "--retry-unchanged",
        "--retry-actor",
        "release-operator",
        "--retry-reason",
        "Reviewed the prior result.",
    ]
    index = arguments.index(field)
    arguments[index + 1] = value

    result = runner.invoke(app, arguments)

    assert result.exit_code == 1
    assert message in f"{result.output}\n{result.exception}"


def test_manual_retry_unchanged_is_forwarded_to_orchestrator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    calls: list[str] = []

    class FakeGitHub:
        secondary_limit_exhausted = False

        def __init__(self, *_: object, **__: object) -> None:
            pass

        def close(self) -> None:
            calls.append("close")

    class FakeOrchestrator:
        def __init__(self, _: object, *, store: RunStore, github: object) -> None:
            del github
            self.store = store

        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *_: object) -> None:
            pass

        def run(  # type: ignore[no-untyped-def]
            self,
            *,
            issue_reference: str | None = None,
            invocation_mode: RunInvocationMode,
            retry_authorization: CandidateRetryAuthorization | None = None,
        ):
            assert issue_reference == "example/project#42"
            assert invocation_mode == RunInvocationMode.MANUAL
            assert retry_authorization == CandidateRetryAuthorization(
                actor="release-operator",
                reason="Reviewed the prior result after a model upgrade.",
            )
            calls.append("run:retry")
            manifest = self.store.create_run()
            manifest.status = RunStatus.SKIPPED
            manifest.skip_reason = "fixture"
            self.store.save(manifest, event="test.skipped", details={})
            return manifest

    monkeypatch.setattr(cli, "GitHubClient", FakeGitHub)
    monkeypatch.setattr(cli, "Orchestrator", FakeOrchestrator)

    result = runner.invoke(
        app,
        [
            "run",
            "--issue",
            "example/project#42",
            "--retry-unchanged",
            "--retry-actor",
            "release-operator",
            "--retry-reason",
            "Reviewed the prior result after a model upgrade.",
            "--config",
            str(config),
        ],
    )

    assert result.exit_code == 0, result.output
    assert calls == ["run:retry", "close"]


def test_scheduled_run_syncs_lifecycle_before_orchestration(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    calls: list[str] = []

    class FakeGitHub:
        secondary_limit_exhausted = False

        def __init__(self, *_: object, **__: object) -> None:
            pass

        def close(self) -> None:
            calls.append("close")

    class FakeOrchestrator:
        def __init__(self, _: object, *, store: RunStore, github: object) -> None:
            self.store = store

        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *_: object) -> None:
            pass

        def run(  # type: ignore[no-untyped-def]
            self,
            *,
            issue_reference: str | None = None,
            invocation_mode: RunInvocationMode,
            retry_authorization: CandidateRetryAuthorization | None = None,
        ):
            assert issue_reference is None
            assert invocation_mode == RunInvocationMode.SCHEDULED
            assert retry_authorization is None
            calls.append("run")
            manifest = self.store.create_run()
            manifest.status = RunStatus.SKIPPED
            manifest.skip_reason = "fixture"
            self.store.save(manifest, event="test.skipped", details={})
            return manifest

    def fake_sync(settings: object, store: RunStore, github: object) -> LifecycleSyncResult:
        calls.append("sync")
        return LifecycleSyncResult(observations=())

    monkeypatch.setattr(cli, "GitHubClient", FakeGitHub)
    monkeypatch.setattr(cli, "Orchestrator", FakeOrchestrator)
    monkeypatch.setattr(cli, "_sync_lifecycle", fake_sync)

    result = runner.invoke(app, ["run", "--scheduled", "--config", str(config)])

    assert result.exit_code == 0, result.output
    assert calls == ["sync", "run", "close"]


class _SkippingOrchestrator:
    """Records that preparation started and ends the run as skipped."""

    calls: ClassVar[list[str]] = []

    def __init__(self, _: object, *, store: RunStore, github: object) -> None:
        self.store = store

    def __enter__(self):  # type: ignore[no-untyped-def]
        return self

    def __exit__(self, *_: object) -> None:
        pass

    def run(self, **_: object):  # type: ignore[no-untyped-def]
        self.calls.append("run")
        manifest = self.store.create_run()
        manifest.status = RunStatus.SKIPPED
        manifest.skip_reason = "fixture"
        self.store.save(manifest, event="test.skipped", details={})
        return manifest


def test_sigterm_during_a_run_exits_143_after_the_run_handles_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "autocontribute.yml"
    config.write_text(f"storage:\n  path: {tmp_path / 'state'}\n", encoding="utf-8")
    handled: list[str] = []

    class TerminatedOrchestrator(_SkippingOrchestrator):
        def run(self, **_: object):  # type: ignore[no-untyped-def]
            try:
                os.kill(os.getpid(), signal.SIGTERM)
                time.sleep(5)
            except SystemExit:
                handled.append("marked failed")
                raise

    before = signal.getsignal(signal.SIGTERM)
    monkeypatch.setattr(cli, "GitHubClient", _ClosableGitHub)
    monkeypatch.setattr(cli, "Orchestrator", TerminatedOrchestrator)

    result = runner.invoke(app, ["run", "--config", str(config)])

    assert result.exit_code == 143
    assert handled == ["marked failed"]
    assert signal.getsignal(signal.SIGTERM) is before


class _ClosableGitHub:
    secondary_limit_exhausted = False

    def __init__(self, *_: object, **__: object) -> None:
        pass

    def close(self) -> None:
        pass


def test_runs_that_keep_ending_on_secondary_rate_limits_trip_the_safety_stop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")

    class RateLimitedGitHub(_ClosableGitHub):
        secondary_limit_exhausted = True

    monkeypatch.setattr(cli, "GitHubClient", RateLimitedGitHub)
    monkeypatch.setattr(cli, "Orchestrator", _SkippingOrchestrator)

    results = [runner.invoke(app, ["run", "--config", str(config)]) for _ in range(3)]

    assert [result.exit_code for result in results] == [0, 0, 0]
    assert "safety stop is now active" not in results[1].output
    assert "safety stop is now active" in " ".join(results[2].output.split())
    status = RunStore(state).circuit_breaker_status()
    assert status.source == "escalation:secondary_rate_limits"


def test_scheduled_preflight_gates_only_on_the_global_stop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    _SkippingOrchestrator.calls = []

    def fake_sync(_: object, store: RunStore, __: object, **kwargs: object) -> LifecycleSyncResult:
        _repository_hold(store.root)
        return LifecycleSyncResult(observations=())

    monkeypatch.setattr(cli, "GitHubClient", _ClosableGitHub)
    monkeypatch.setattr(cli, "Orchestrator", _SkippingOrchestrator)
    monkeypatch.setattr(cli, "_sync_lifecycle", fake_sync)

    result = runner.invoke(app, ["run", "--scheduled", "--config", str(config)])

    assert result.exit_code == 0, result.output
    assert _SkippingOrchestrator.calls == ["run"]
    assert len(RunStore(state).active_holds()) == 1


@pytest.mark.parametrize(("hours_past_expiry", "expired"), [(-1, False), (1, True)])
def test_run_expires_runs_left_unapproved_past_approval_lifetime_plus_seven_days(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    hours_past_expiry: int,
    expired: bool,
) -> None:
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    store = RunStore(state)
    waiting = store.create_run()
    waiting.status = RunStatus.READY_FOR_APPROVAL
    store.save(waiting, event="test.ready", details={})
    _SkippingOrchestrator.calls = []
    offset = (
        timedelta(hours=AutocontributeConfig().publishing.approval_expires_hours)
        + timedelta(days=7)
        + timedelta(hours=hours_past_expiry)
    )

    class Later(datetime):
        @classmethod
        def now(cls, tz=None):  # type: ignore[no-untyped-def]
            return datetime.now(tz) + offset

    monkeypatch.setattr(cli, "datetime", Later)
    monkeypatch.setattr(cli, "GitHubClient", _ClosableGitHub)
    monkeypatch.setattr(cli, "Orchestrator", _SkippingOrchestrator)

    result = runner.invoke(app, ["run", "--config", str(config)])

    assert result.exit_code == 0, result.output
    assert (f"Expired unapproved run `{waiting.run_id}`" in result.output) is expired
    assert store.get(waiting.run_id).status == (
        RunStatus.CANCELLED if expired else RunStatus.READY_FOR_APPROVAL
    )
    assert _SkippingOrchestrator.calls == ["run"]


def test_scheduled_run_prints_its_outcome_as_json(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")

    class FakeOrchestrator:
        def __init__(self, _: object, *, store: RunStore, github: object) -> None:
            self.store = store

        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *_: object) -> None:
            pass

        def run(self, **_: object):  # type: ignore[no-untyped-def]
            manifest = self.store.create_run()
            manifest.status = RunStatus.FAILED
            manifest.error = "sandbox image is unavailable"
            self.store.save(manifest, event="test.failed", details={})
            return manifest

    monkeypatch.setattr(cli, "GitHubClient", _ClosableGitHub)
    monkeypatch.setattr(cli, "Orchestrator", FakeOrchestrator)
    monkeypatch.setattr(
        cli,
        "_sync_lifecycle",
        lambda *_, **__: LifecycleSyncResult(observations=()),
    )

    result = runner.invoke(app, ["run", "--scheduled", "--json", "--config", str(config)])
    refused = runner.invoke(
        app,
        ["run", "--scheduled", "--issue", "example/project#1", "--json", "--config", str(config)],
    )

    assert result.exit_code == 1
    summary = json.loads(result.output)
    assert set(summary) == _RUN_SUMMARY_KEYS
    assert summary["status"] == "failed"
    assert summary["error"] == "sandbox image is unavailable"
    assert refused.exit_code == 1
    assert json.loads(refused.output) == {
        "outcome": "error",
        "message": "--scheduled cannot be combined with --issue; pinned retries must be manual",
    }


@pytest.mark.parametrize("already_active", [False, True])
def test_scheduled_preflight_fails_after_lifecycle_when_breaker_is_active(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    already_active: bool,
) -> None:
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    store = RunStore(state)
    calls: list[str] = []

    if already_active:
        store.trip_circuit_breaker(
            source="existing safety evidence",
            reason="operator review is required",
            trigger_hash="a" * 64,
        )

    class FakeGitHub:
        secondary_limit_exhausted = False

        def __init__(self, *_: object, **__: object) -> None:
            pass

        def close(self) -> None:
            calls.append("close")

    class ForbiddenOrchestrator:
        def __init__(self, *_: object, **__: object) -> None:
            pytest.fail("an active breaker must not construct the model orchestrator")

    def fake_sync(_: object, observed_store: RunStore, __: object) -> LifecycleSyncResult:
        calls.append("observe")
        if not already_active:
            observed_store.trip_circuit_breaker(
                source="lifecycle safety evidence",
                reason="maintainer asked automation to stop",
                trigger_hash="b" * 64,
            )
        return LifecycleSyncResult(observations=())

    monkeypatch.setattr(cli, "GitHubClient", FakeGitHub)
    monkeypatch.setattr(cli, "Orchestrator", ForbiddenOrchestrator)
    monkeypatch.setattr(cli, "_sync_lifecycle", fake_sync)

    result = runner.invoke(app, ["run", "--scheduled", "--config", str(config)])

    assert result.exit_code == 1, result.output
    assert "Circuit breaker is tripped" in result.output
    assert calls == ["observe", "close"]
    assert store.list() == []


def test_manual_publish_syncs_lifecycle_and_preserves_target_retry(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    store = RunStore(state)
    run = store.create_run()
    run.status = RunStatus.SUBMITTING
    store.save(run, event="test.submitting", details={})
    calls: list[str] = []

    class FakeGitHub:
        def __init__(self, *_: object, **__: object) -> None:
            pass

        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *_: object) -> None:
            calls.append("close")

    class FakePublisher:
        def __init__(self, _: object, publisher_store: RunStore, github: object) -> None:
            self.store = publisher_store

        def publish(self, run_id: str):  # type: ignore[no-untyped-def]
            calls.append("publish")
            manifest = self.store.get(run_id)
            manifest.status = RunStatus.PR_OPEN
            manifest.pull_request_url = "https://github.com/example/project/pull/7"
            self.store.save(manifest, event="test.published", details={})
            return manifest

    def fake_sync(
        settings: object,
        sync_store: RunStore,
        github: object,
        *,
        publication_retry_run_id: str | None = None,
    ) -> LifecycleSyncResult:
        assert sync_store.root == store.root
        calls.append(f"sync:{publication_retry_run_id}")
        return LifecycleSyncResult(observations=())

    monkeypatch.setattr(cli, "GitHubClient", FakeGitHub)
    monkeypatch.setattr(cli, "Publisher", FakePublisher)
    monkeypatch.setattr(cli, "_sync_lifecycle", fake_sync)
    monkeypatch.setattr(cli, "_show_report", lambda *args: None)
    monkeypatch.setattr(cli, "_refresh_report", lambda *args: None)

    result = runner.invoke(
        app,
        ["publish", run.run_id, "--yes", "--config", str(config)],
    )

    assert result.exit_code == 0, result.output
    assert calls == [f"sync:{run.run_id}", "publish", "close"]


class _ContextGitHub:
    def __init__(self, *_: object, **__: object) -> None:
        pass

    def __enter__(self):  # type: ignore[no-untyped-def]
        return self

    def __exit__(self, *_: object) -> None:
        pass


def _approved_state(tmp_path: Path) -> tuple[Path, RunStore, str]:
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    store = RunStore(state)
    run = store.create_run()
    run.status = RunStatus.APPROVED
    store.save(run, event="test.approved", details={})
    return config, store, run.run_id


def test_publish_json_reports_the_open_pull_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _, run_id = _approved_state(tmp_path)

    class FakePublisher:
        def __init__(self, _: object, publisher_store: RunStore, github: object) -> None:
            self.store = publisher_store

        def publish(self, run_id: str):  # type: ignore[no-untyped-def]
            manifest = self.store.get(run_id)
            manifest.status = RunStatus.PR_OPEN
            manifest.pull_request_url = "https://github.com/example/project/pull/7"
            self.store.save(manifest, event="test.published", details={})
            return manifest

    monkeypatch.setattr(cli, "GitHubClient", _ContextGitHub)
    monkeypatch.setattr(cli, "Publisher", FakePublisher)
    monkeypatch.setattr(cli, "_sync_lifecycle", lambda *_, **__: None)

    refused = runner.invoke(app, ["publish", run_id, "--json", "--config", str(config)])
    published = runner.invoke(
        app,
        ["publish", run_id, "--yes", "--json", "--config", str(config)],
    )

    assert refused.exit_code == 1
    assert json.loads(refused.output) == {
        "run_id": run_id,
        "outcome": "error",
        "message": "--json cannot prompt; pass --yes",
    }
    assert published.exit_code == 0, published.output
    assert json.loads(published.output) == {
        "run_id": run_id,
        "status": "pr_open",
        "pull_request_url": "https://github.com/example/project/pull/7",
        "outcome": "pr_open",
        "message": "Pull request opened",
    }


@pytest.mark.parametrize(
    ("error", "outcome", "exit_code"),
    [
        (PublicationLimitError("Daily new pull-request limit reached"), "limit", 3),
        (PolicyError("Approval has expired"), "stale", 3),
        (PublicationResumeRequired("resume the exact intent"), "resume_required", 4),
        (StateError("Circuit breaker is tripped by operator:a: stop"), "safety_stop", 5),
        (GitHubError("GitHub is unavailable"), "error", 1),
    ],
)
def test_publish_failures_have_typed_outcomes_and_exit_codes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error: AutocontributeError,
    outcome: str,
    exit_code: int,
) -> None:
    config, store, run_id = _approved_state(tmp_path)

    class FailingPublisher:
        def __init__(self, *_: object) -> None:
            pass

        def publish(self, run_id: str) -> None:
            if outcome == "safety_stop":
                store.trip_circuit_breaker(
                    source="operator:a", reason="stop", trigger_hash="c" * 64
                )
            if outcome == "resume_required":
                stranded = store.get(run_id)
                stranded.status = RunStatus.SUBMITTING
                store.save(stranded, event="test.intent", details={})
            raise error

    monkeypatch.setattr(cli, "GitHubClient", _ContextGitHub)
    monkeypatch.setattr(cli, "Publisher", FailingPublisher)
    monkeypatch.setattr(cli, "_sync_lifecycle", lambda *_, **__: None)

    as_json = runner.invoke(app, ["publish", run_id, "--yes", "--json", "--config", str(config)])
    as_text = runner.invoke(app, ["publish", run_id, "--yes", "--config", str(config)])

    assert as_json.exit_code == exit_code, as_json.output
    assert json.loads(as_json.output) == {
        "run_id": run_id,
        "status": "submitting" if outcome == "resume_required" else "approved",
        "pull_request_url": None,
        "outcome": outcome,
        "message": str(error),
    }
    assert as_text.exit_code == exit_code
    assert str(error) in " ".join(as_text.output.split())


def test_publish_goes_ahead_while_another_run_waits_to_be_resumed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id = _approved_state(tmp_path)
    stuck = store.create_run()
    stuck.status = RunStatus.SUBMITTING
    store.save(stuck, event="test.unanswered_post", details={})
    calls: list[str] = []

    class FakePublisher:
        def __init__(self, _: object, publisher_store: RunStore, github: object) -> None:
            self.store = publisher_store

        def _reconcile_submitting(self, other: str, *, lease_guard: object) -> None:
            calls.append(f"reconcile:{other}")
            raise PublicationResumeRequired("A second POST is forbidden")

        def publish(self, target: str) -> RunManifest:
            calls.append(f"publish:{target}")
            manifest = self.store.get(target)
            manifest.status = RunStatus.PR_OPEN
            manifest.pull_request_url = "https://github.com/example/project/pull/7"
            self.store.save(manifest, event="test.published", details={})
            return manifest

    monkeypatch.setattr(cli, "GitHubClient", _ContextGitHub)
    monkeypatch.setattr(cli, "Publisher", FakePublisher)
    monkeypatch.setattr(
        cli, "sync_open_pull_requests", lambda *_, **__: LifecycleSyncResult(observations=())
    )

    result = runner.invoke(app, ["publish", run_id, "--yes", "--json", "--config", str(config)])

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["outcome"] == "pr_open"
    assert calls == [f"reconcile:{stuck.run_id}", f"publish:{run_id}"]
    assert store.get(stuck.run_id).status == RunStatus.SUBMITTING


def test_publish_json_reports_an_unknown_run(tmp_path: Path) -> None:
    config = tmp_path / "autocontribute.yml"
    config.write_text(f"storage:\n  path: {tmp_path / 'state'}\n", encoding="utf-8")

    result = runner.invoke(app, ["publish", "missing", "--yes", "--json", "--config", str(config)])

    assert result.exit_code == 1
    assert json.loads(result.output) == {
        "run_id": "missing",
        "outcome": "error",
        "message": "Unknown run: missing",
    }


@pytest.mark.parametrize(
    ("failing", "exit_code"),
    [((), 0), (("limits", "freshness"), 3), (("safety_stop", "limits"), 5)],
)
def test_runs_check_reports_each_check_as_json_with_a_typed_exit_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failing: tuple[str, ...],
    exit_code: int,
) -> None:
    config, _, run_id = _approved_state(tmp_path)
    names = ("safety_stop", "approval", "limits", "freshness")

    class CheckingPublisher:
        def __init__(self, *_: object) -> None:
            pass

        def check(self, checked: str) -> tuple[PublicationCheck, ...]:
            assert checked == run_id
            return tuple(
                PublicationCheck(name, name not in failing, f"{name} [detail]") for name in names
            )

    monkeypatch.setattr(cli, "GitHubClient", _ContextGitHub)
    monkeypatch.setattr(cli, "Publisher", CheckingPublisher)

    as_json = runner.invoke(app, ["runs", "check", run_id, "--json", "--config", str(config)])
    as_text = runner.invoke(app, ["runs", "check", run_id, "--config", str(config)])

    assert as_json.exit_code == exit_code, as_json.output
    assert json.loads(as_json.output) == {
        "run_id": run_id,
        "status": "approved",
        "publishable": not failing,
        "checks": [
            {"name": name, "passed": name not in failing, "detail": f"{name} [detail]"}
            for name in names
        ],
    }
    assert as_text.exit_code == exit_code
    assert "freshness [detail]" in as_text.output


def test_runs_check_reports_a_run_it_cannot_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _, run_id = _approved_state(tmp_path)

    class RefusingPublisher:
        def __init__(self, *_: object) -> None:
            pass

        def check(self, checked: str) -> None:
            raise StateError(f"Run {checked} is failed; only ready_for_approval or approved runs")

    monkeypatch.setattr(cli, "GitHubClient", _ContextGitHub)
    monkeypatch.setattr(cli, "Publisher", RefusingPublisher)

    result = runner.invoke(app, ["runs", "check", run_id, "--json", "--config", str(config)])

    assert result.exit_code == 1
    assert json.loads(result.output) == {
        "run_id": run_id,
        "outcome": "error",
        "message": f"Run {run_id} is failed; only ready_for_approval or approved runs",
    }


def _submitting_state(tmp_path: Path) -> tuple[Path, RunStore, str]:
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    store = RunStore(state)
    run = store.create_run()
    run.status = RunStatus.SUBMITTING
    store.save(run, event="test.submitting", details={})
    return config, store, run.run_id


def test_runs_abandon_confirms_then_fails_the_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id = _submitting_state(tmp_path)
    reasons: list[str] = []

    class AbandoningPublisher:
        def __init__(self, *_: object) -> None:
            pass

        def abandon(self, abandoned: str, *, reason: str):  # type: ignore[no-untyped-def]
            reasons.append(reason)
            manifest = store.get(abandoned)
            manifest.status = RunStatus.FAILED
            store.save(manifest, event="test.abandoned", details={})
            return manifest

    monkeypatch.setattr(cli, "GitHubClient", _ContextGitHub)
    monkeypatch.setattr(cli, "Publisher", AbandoningPublisher)
    command = ["runs", "abandon", run_id, "--reason", "  Stuck by D3  ", "--config", str(config)]

    declined = runner.invoke(app, command, input="n\n")
    abandoned = runner.invoke(app, [*command, "--yes"])

    assert declined.exit_code == 1
    assert f"Check that run {run_id} left nothing on GitHub" in declined.output
    assert abandoned.exit_code == 0, abandoned.output
    assert reasons == ["Stuck by D3"]
    assert f"Abandoned `{run_id}`" in abandoned.output
    assert store.get(run_id).status is RunStatus.FAILED


def test_runs_abandon_sends_remote_state_back_to_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, run_id = _submitting_state(tmp_path)

    class RemoteStatePublisher:
        def __init__(self, *_: object) -> None:
            pass

        def abandon(self, abandoned: str, *, reason: str) -> None:
            raise PublicationResumeRequired("The contribution branch exists")

    monkeypatch.setattr(cli, "GitHubClient", _ContextGitHub)
    monkeypatch.setattr(cli, "Publisher", RemoteStatePublisher)

    result = runner.invoke(
        app,
        ["runs", "abandon", run_id, "--reason", "Stuck", "--yes", "--config", str(config)],
    )

    assert result.exit_code == 4
    output = " ".join(result.output.split())
    assert f"The contribution branch exists; resume it with `autocontribute publish {run_id}`" in (
        output
    )
    assert store.get(run_id).status is RunStatus.SUBMITTING


def test_runs_abandon_refuses_blank_reasons_and_runs_that_are_not_submitting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _, run_id = _approved_state(tmp_path)
    monkeypatch.setattr(cli, "_github_client", _forbid_github)

    blank = runner.invoke(
        app,
        ["runs", "abandon", run_id, "--reason", " ", "--yes", "--config", str(config)],
    )
    approved = runner.invoke(
        app,
        ["runs", "abandon", run_id, "--reason", "Stuck", "--yes", "--config", str(config)],
    )

    assert blank.exit_code == 1
    assert "--reason must explain why the publication is abandoned" in blank.output
    assert approved.exit_code == 1
    assert "only submitting runs can be abandoned" in " ".join(approved.output.split())


def test_manual_publish_returns_reconciled_target_without_a_new_publish_call(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    store = RunStore(state)
    run = store.create_run()
    run.status = RunStatus.SUBMITTING
    store.save(run, event="test.submitting", details={})
    calls: list[str] = []

    class FakeGitHub:
        def __init__(self, *_: object, **__: object) -> None:
            pass

        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *_: object) -> None:
            calls.append("close")

    class FakePublisher:
        def __init__(self, *_: object, **__: object) -> None:
            pytest.fail("a reconciled PR must not enter the new-publication path")

    def fake_sync(
        settings: object,
        sync_store: RunStore,
        github: object,
        *,
        publication_retry_run_id: str | None = None,
    ) -> LifecycleSyncResult:
        assert publication_retry_run_id == run.run_id
        reconciled = sync_store.get(run.run_id)
        reconciled.status = RunStatus.PR_OPEN
        reconciled.pull_request_url = "https://github.com/example/project/pull/7"
        sync_store.save(reconciled, event="test.reconciled", details={})
        calls.append("reconcile")
        return LifecycleSyncResult(observations=())

    monkeypatch.setattr(cli, "GitHubClient", FakeGitHub)
    monkeypatch.setattr(cli, "Publisher", FakePublisher)
    monkeypatch.setattr(cli, "_sync_lifecycle", fake_sync)
    monkeypatch.setattr(cli, "_show_report", lambda *args: None)
    monkeypatch.setattr(cli, "_refresh_report", lambda *args: None)

    result = runner.invoke(
        app,
        ["publish", run.run_id, "--yes", "--config", str(config)],
    )

    assert result.exit_code == 0, result.output
    assert calls == ["reconcile", "close"]


def test_lifecycle_sync_adopts_existing_pr_without_publishing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    settings = load_config(config)
    store = RunStore(state)
    submitting = store.create_run()
    submitting.status = RunStatus.SUBMITTING
    store.save(submitting, event="test.submitting", details={})
    calls: list[str] = []

    class FakePublisher:
        def __init__(self, settings: object, store: RunStore, github: object) -> None:
            self.store = store

        def _reconcile_submitting(self, run_id: str, *, lease_guard: object) -> None:
            calls.append(f"reconcile:{run_id}")
            manifest = self.store.get(run_id)
            manifest.status = RunStatus.PR_OPEN
            manifest.pull_request_url = "https://github.com/example/project/pull/7"
            self.store.save(manifest, event="test.reconciled", details={})

        def _publish(self, run_id: str, *, lease_guard: object) -> None:
            pytest.fail(f"read-only reconciliation must not publish {run_id}")

    def fake_sync(
        github: object,
        observed_store: RunStore,
        *,
        assert_owned: Callable[[], object] | None = None,
    ) -> LifecycleSyncResult:
        assert observed_store is store
        assert assert_owned is not None
        assert_owned()
        calls.append("observe")
        return LifecycleSyncResult(observations=())

    monkeypatch.setattr(cli, "Publisher", FakePublisher)
    monkeypatch.setattr(cli, "sync_open_pull_requests", fake_sync)

    result = cli._sync_lifecycle(
        settings,
        store,
        object(),  # type: ignore[arg-type]
    )

    assert result == LifecycleSyncResult(observations=())
    assert calls == ["observe", f"reconcile:{submitting.run_id}"]
    reconciled = store.get(submitting.run_id)
    assert reconciled.status == RunStatus.PR_OPEN
    assert reconciled.pull_request_url == "https://github.com/example/project/pull/7"


def test_lifecycle_sync_never_resumes_publication_without_an_explicit_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    settings = load_config(config)
    store = RunStore(state)
    submitting = store.create_run()
    submitting.status = RunStatus.SUBMITTING
    store.save(submitting, event="test.submitting", details={})
    calls: list[str] = []

    class FakePublisher:
        def __init__(self, settings: object, store: RunStore, github: object) -> None:
            pass

        def _reconcile_submitting(self, run_id: str, *, lease_guard: object) -> None:
            calls.append(f"reconcile:{run_id}")
            raise PublicationResumeRequired("no remote pull request yet")

        def _publish(self, run_id: str, *, lease_guard: object) -> None:
            pytest.fail(f"lifecycle sync must not publish {run_id}")

    def fake_sync(
        github: object,
        observed_store: RunStore,
        *,
        assert_owned: Callable[[], object] | None = None,
    ) -> LifecycleSyncResult:
        assert observed_store is store
        assert assert_owned is not None
        assert_owned()
        calls.append("observe")
        return LifecycleSyncResult(observations=())

    monkeypatch.setattr(cli, "Publisher", FakePublisher)
    monkeypatch.setattr(cli, "sync_open_pull_requests", fake_sync)

    result = cli._sync_lifecycle(
        settings,
        store,
        object(),  # type: ignore[arg-type]
    )

    assert result == LifecycleSyncResult(observations=())
    assert calls == ["observe", f"reconcile:{submitting.run_id}"]
    assert store.get(submitting.run_id).status == RunStatus.SUBMITTING


def test_lifecycle_sync_reconciles_target_submitting_run_before_exact_publication_retry(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    settings = load_config(config)
    store = RunStore(state)
    target = store.create_run()
    target.status = RunStatus.SUBMITTING
    store.save(target, event="test.target_submitting", details={})
    other = store.create_run()
    other.status = RunStatus.SUBMITTING
    store.save(other, event="test.other_submitting", details={})
    calls: list[str] = []

    class FakePublisher:
        def __init__(self, settings: object, store: RunStore, github: object) -> None:
            pass

        def _reconcile_submitting(self, run_id: str, *, lease_guard: object) -> None:
            calls.append(f"reconcile:{run_id}")

    def fake_sync(
        github: object,
        observed_store: RunStore,
        *,
        assert_owned: Callable[[], object] | None = None,
    ) -> LifecycleSyncResult:
        assert observed_store is store
        assert assert_owned is not None
        assert_owned()
        calls.append("observe")
        return LifecycleSyncResult(observations=())

    monkeypatch.setattr(cli, "Publisher", FakePublisher)
    monkeypatch.setattr(cli, "sync_open_pull_requests", fake_sync)

    result = cli._sync_lifecycle(
        settings,
        store,
        object(),  # type: ignore[arg-type]
        publication_retry_run_id=target.run_id,
    )

    assert result == LifecycleSyncResult(observations=())
    assert calls == [
        "observe",
        f"reconcile:{target.run_id}",
        f"reconcile:{other.run_id}",
    ]


def test_lifecycle_sync_reuses_one_publication_lease_for_recovery_and_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    settings = load_config(config)
    store = RunStore(state)
    submitting = store.create_run()
    submitting.status = RunStatus.SUBMITTING
    store.save(submitting, event="test.submitting", details={})
    calls: list[str] = []

    class FakePublisher:
        def __init__(self, settings: object, owned_store: RunStore, github: object) -> None:
            assert owned_store is store

        def _reconcile_submitting(self, run_id: str, *, lease_guard: object) -> None:
            assert store.get_lease("autocontribute.publish") is not None
            assert callable(getattr(lease_guard, "assert_owned", None))
            lease_guard.assert_owned()  # type: ignore[attr-defined]
            calls.append(f"reconcile:{run_id}")
            raise PublicationResumeRequired("resume exact intent")

        def _publish(self, run_id: str, *, lease_guard: object) -> None:
            assert store.get_lease("autocontribute.publish") is not None
            lease_guard.assert_owned()  # type: ignore[attr-defined]
            calls.append(f"publish:{run_id}")

    def fake_sync(
        github: object,
        observed_store: RunStore,
        *,
        assert_owned: Callable[[], object] | None = None,
    ) -> LifecycleSyncResult:
        assert observed_store is store
        assert store.get_lease("autocontribute.publish") is not None
        assert assert_owned is not None
        assert_owned()
        calls.append("observe")
        return LifecycleSyncResult(observations=())

    monkeypatch.setattr(cli, "Publisher", FakePublisher)
    monkeypatch.setattr(cli, "sync_open_pull_requests", fake_sync)

    result = cli._sync_lifecycle(
        settings,
        store,
        object(),  # type: ignore[arg-type]
        publication_retry_run_id=submitting.run_id,
    )

    assert result == LifecycleSyncResult(observations=())
    assert calls == [
        "observe",
        f"reconcile:{submitting.run_id}",
        f"publish:{submitting.run_id}",
    ]


def test_lifecycle_sync_resumes_only_the_explicit_manual_retry_target(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    settings = load_config(config)
    store = RunStore(state)
    target = store.create_run()
    target.status = RunStatus.SUBMITTING
    store.save(target, event="test.target_submitting", details={})
    other = store.create_run()
    other.status = RunStatus.SUBMITTING
    store.save(other, event="test.other_submitting", details={})
    calls: list[str] = []

    class FakePublisher:
        def __init__(self, settings: object, store: RunStore, github: object) -> None:
            pass

        def _reconcile_submitting(self, run_id: str, *, lease_guard: object) -> None:
            calls.append(f"reconcile:{run_id}")
            raise PublicationResumeRequired("no remote pull request yet")

        def _publish(self, run_id: str, *, lease_guard: object) -> None:
            calls.append(f"publish:{run_id}")

    def fake_sync(
        github: object,
        observed_store: RunStore,
        *,
        assert_owned: Callable[[], object] | None = None,
    ) -> LifecycleSyncResult:
        assert observed_store is store
        assert assert_owned is not None
        assert_owned()
        calls.append("observe")
        return LifecycleSyncResult(observations=())

    monkeypatch.setattr(cli, "Publisher", FakePublisher)
    monkeypatch.setattr(cli, "sync_open_pull_requests", fake_sync)

    result = cli._sync_lifecycle(
        settings,
        store,
        object(),  # type: ignore[arg-type]
        publication_retry_run_id=target.run_id,
    )

    assert result == LifecycleSyncResult(observations=())
    assert calls == [
        "observe",
        f"reconcile:{target.run_id}",
        f"publish:{target.run_id}",
        f"reconcile:{other.run_id}",
    ]


def test_lifecycle_sync_observes_and_continues_reconciliation_before_failing_closed(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    settings = load_config(config)
    store = RunStore(state)
    ambiguous = store.create_run()
    ambiguous.status = RunStatus.SUBMITTING
    store.save(ambiguous, event="test.ambiguous_submitting", details={})
    reconcilable = store.create_run()
    reconcilable.status = RunStatus.SUBMITTING
    store.save(reconcilable, event="test.reconcilable_submitting", details={})
    calls: list[str] = []

    class FakePublisher:
        def __init__(self, settings: object, store: RunStore, github: object) -> None:
            pass

        def _reconcile_submitting(self, run_id: str, *, lease_guard: object) -> None:
            calls.append(f"reconcile:{run_id}")
            if run_id == ambiguous.run_id:
                raise StateError("publication remains ambiguous")

    def fake_sync(
        github: object,
        observed_store: RunStore,
        *,
        assert_owned: Callable[[], object] | None = None,
    ) -> LifecycleSyncResult:
        assert observed_store is store
        assert assert_owned is not None
        assert_owned()
        calls.append("observe")
        return LifecycleSyncResult(observations=())

    monkeypatch.setattr(cli, "Publisher", FakePublisher)
    monkeypatch.setattr(cli, "sync_open_pull_requests", fake_sync)

    with pytest.raises(StateError, match="publication remains ambiguous"):
        cli._sync_lifecycle(settings, store, object())  # type: ignore[arg-type]

    assert calls == [
        "observe",
        f"reconcile:{ambiguous.run_id}",
        f"reconcile:{reconcilable.run_id}",
    ]


def test_lifecycle_sync_stops_reconciliation_after_lease_takeover(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    settings = load_config(config)
    store = RunStore(state)
    first = store.create_run()
    first.status = RunStatus.SUBMITTING
    store.save(first, event="test.first_submitting", details={})
    second = store.create_run()
    second.status = RunStatus.SUBMITTING
    store.save(second, event="test.second_submitting", details={})
    calls: list[str] = []

    class FakePublisher:
        def __init__(self, settings: object, store: RunStore, github: object) -> None:
            pass

        def _reconcile_submitting(self, run_id: str, *, lease_guard: object) -> None:
            calls.append(f"reconcile:{run_id}")
            lease = store.get_lease("autocontribute.publish")
            assert lease is not None
            takeover = store.acquire_lease(
                "autocontribute.publish",
                "replacement-worker",
                ttl=timedelta(minutes=5),
                now=lease.expires_at,
            )
            assert takeover is not None

    def fake_sync(
        github: object,
        observed_store: RunStore,
        *,
        assert_owned: Callable[[], object] | None = None,
    ) -> LifecycleSyncResult:
        calls.append("observe")
        return LifecycleSyncResult(observations=())

    monkeypatch.setattr(cli, "Publisher", FakePublisher)
    monkeypatch.setattr(cli, "sync_open_pull_requests", fake_sync)

    with pytest.raises(StateError, match="no longer owned"):
        cli._sync_lifecycle(settings, store, object())  # type: ignore[arg-type]

    assert calls == ["observe", f"reconcile:{first.run_id}"]


def test_lifecycle_sync_command_reports_bounded_summary(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")

    class FakeGitHub:
        def __init__(self, *_: object, **__: object) -> None:
            pass

        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *_: object) -> None:
            pass

    monkeypatch.setattr(cli, "GitHubClient", FakeGitHub)
    monkeypatch.setattr(
        cli,
        "_sync_lifecycle",
        lambda settings, store, github: LifecycleSyncResult(observations=()),
    )

    result = runner.invoke(app, ["lifecycle", "sync", "--config", str(config)])

    assert result.exit_code == 0, result.output
    assert (
        "Lifecycle sync: 0 PR(s), 0 signal(s), 0 new stop(s), 0 unreadable PR(s)." in result.output
    )
    assert "still submitting" not in result.output

    store = RunStore(state)
    waiting = store.create_run()
    waiting.status = RunStatus.SUBMITTING
    store.save(waiting, event="test.unanswered_post", details={})

    reported = runner.invoke(app, ["lifecycle", "sync", "--config", str(config)])

    assert reported.exit_code == 0, reported.output
    assert f"Run {waiting.run_id} is still submitting" in reported.output
    assert f"autocontribute runs abandon {waiting.run_id}" in " ".join(reported.output.split())
