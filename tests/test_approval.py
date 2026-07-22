from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from autocontribute.approval import (
    ApprovalManifest,
    approval_is_valid,
    build_approval_manifest,
    create_approval,
    hash_diff,
    manifest_fingerprint,
    validate_approval,
)
from autocontribute.config import PublishingConfig
from autocontribute.domain import (
    FileEdit,
    IssueCandidate,
    PatchProposal,
    RepositoryInfo,
    RunManifest,
    RunStatus,
)
from autocontribute.exceptions import PolicyError

NOW = datetime(2026, 7, 21, 12, tzinfo=UTC)


def _manifest() -> ApprovalManifest:
    return ApprovalManifest(
        repository="owner/project",
        issue_number=42,
        base_sha="a" * 40,
        preparation_fingerprint="e" * 64,
        publishing_login="octocat",
        publishing_api_origin="https://api.github.com",
        commit_author_name="Octocat",
        commit_author_email="octocat@users.noreply.github.com",
        commit_committer_name="Octocat",
        commit_committer_email="octocat@users.noreply.github.com",
        base_branch="main",
        draft=False,
        diff_sha256=hash_diff("diff --git a/a b/a\n+fixed\n"),
        commit_message="Fix the parser boundary",
        pull_request_title="Fix parser boundary handling",
        pull_request_body="Fixes #42. Adds a regression test.",
        disclosure="Prepared with AI assistance and reviewed by the contributor.",
    )


def test_approval_is_valid_only_during_configured_window() -> None:
    manifest = _manifest()
    approval = create_approval(
        manifest,
        actor="octocat",
        attestation="I reviewed and authorize this exact contribution.",
        config=PublishingConfig(approval_expires_hours=2),
        now=NOW,
    )

    assert approval.approved_at == NOW
    assert approval.expires_at == NOW + timedelta(hours=2)
    validate_approval(approval, manifest, now=NOW)
    assert approval_is_valid(approval, manifest, now=NOW + timedelta(minutes=119))
    assert not approval_is_valid(approval, manifest, now=approval.expires_at)
    with pytest.raises(PolicyError, match="expired"):
        validate_approval(approval, manifest, now=approval.expires_at)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("repository", "different/project"),
        ("issue_number", 43),
        ("base_sha", "b" * 40),
        ("preparation_fingerprint", "e" * 63 + "f"),
        ("publishing_login", "different-user"),
        ("publishing_api_origin", "https://github.example.com"),
        ("commit_author_name", "Different Author"),
        ("commit_author_email", "different@example.com"),
        ("commit_committer_name", "Different Committer"),
        ("commit_committer_email", "committer@example.com"),
        ("base_branch", "next"),
        ("draft", True),
        ("diff_sha256", "c" * 64),
        ("commit_message", "A different commit"),
        ("pull_request_title", "A different title"),
        ("pull_request_body", "A different body"),
        ("disclosure", "A different disclosure"),
    ],
)
def test_every_publication_field_is_bound_by_fingerprint(field: str, replacement: object) -> None:
    manifest = _manifest()
    changed = manifest.model_copy(update={field: replacement})
    approval = create_approval(
        manifest,
        actor="octocat",
        attestation="I approve.",
        config=PublishingConfig(),
        now=NOW,
    )

    assert manifest_fingerprint(changed) != manifest_fingerprint(manifest)
    with pytest.raises(PolicyError, match="exact publication manifest"):
        validate_approval(approval, changed, now=NOW)


def test_diff_hash_is_byte_exact() -> None:
    assert hash_diff("same") == hash_diff(b"same")
    assert hash_diff("same") != hash_diff("same\n")


def test_approval_actor_must_match_bound_publishing_login() -> None:
    manifest = _manifest()
    approval = create_approval(
        manifest,
        actor="different-user",
        attestation="I approve.",
        config=PublishingConfig(),
        now=NOW,
    )

    with pytest.raises(PolicyError, match="actor does not match"):
        validate_approval(approval, manifest, now=NOW)


def test_build_manifest_extracts_current_run_publication_fields() -> None:
    issue = IssueCandidate(
        repository="owner/project",
        number=42,
        title="Parser fails at a boundary",
        body="Steps to reproduce the parser failure.",
        html_url="https://github.com/owner/project/issues/42",
        state="open",
        author="maintainer",
        labels=["help wanted"],
        assignees=[],
        comments=0,
        created_at=NOW,
        updated_at=NOW,
    )
    proposal = PatchProposal(
        summary="Handle the boundary and add a regression test.",
        edits=[
            FileEdit(
                operation="create",
                path="tests/test_boundary.py",
                content="def test_boundary(): pass\n",
                rationale="Regression coverage.",
                find=None,
                replace=None,
            )
        ],
        validation_commands=["pytest tests/test_boundary.py"],
        commit_message="Fix the parser boundary",
        pull_request_title="Fix parser boundary handling",
        pull_request_body="Fixes #42.",
        limitations=[],
    )
    run = RunManifest(
        run_id="run-1",
        status=RunStatus.READY_FOR_APPROVAL,
        created_at=NOW,
        updated_at=NOW,
        candidate=issue,
        repository=RepositoryInfo(
            full_name="owner/project",
            html_url="https://github.com/owner/project",
            clone_url="https://github.com/owner/project.git",
            default_branch="main",
            stars=10_000,
            archived=False,
            disabled=False,
            private=False,
            pushed_at=NOW,
            license_spdx="MIT",
        ),
        base_sha="a" * 40,
        preparation_fingerprint="e" * 64,
        publishing_login="octocat",
        publishing_api_origin="https://api.github.com",
        commit_author_name="Octocat",
        commit_author_email="octocat@users.noreply.github.com",
        commit_committer_name="Octocat",
        commit_committer_email="octocat@users.noreply.github.com",
        proposal=proposal,
    )

    manifest = build_approval_manifest(
        run,
        diff="diff bytes",
        disclosure="Reviewed AI-assisted contribution.",
        draft=True,
    )

    assert manifest.repository == issue.repository
    assert manifest.issue_number == issue.number
    assert manifest.base_sha == run.base_sha
    assert manifest.preparation_fingerprint == run.preparation_fingerprint
    assert manifest.publishing_login == "octocat"
    assert manifest.publishing_api_origin == "https://api.github.com"
    assert manifest.commit_author_name == "Octocat"
    assert manifest.commit_author_email == "octocat@users.noreply.github.com"
    assert manifest.commit_committer_name == "Octocat"
    assert manifest.commit_committer_email == "octocat@users.noreply.github.com"
    assert manifest.base_branch == "main"
    assert manifest.draft is True
    assert manifest.diff_sha256 == hash_diff("diff bytes")
    assert manifest.commit_message == proposal.commit_message
    assert manifest.pull_request_title == proposal.pull_request_title
    assert manifest.pull_request_body == proposal.pull_request_body


def test_build_manifest_fails_closed_when_run_is_incomplete() -> None:
    run = RunManifest(
        run_id="run-1",
        status=RunStatus.READY_FOR_APPROVAL,
        created_at=NOW,
        updated_at=NOW,
    )

    with pytest.raises(PolicyError, match="issue candidate"):
        build_approval_manifest(
            run,
            diff="diff",
            disclosure="Reviewed.",
            draft=False,
        )


def test_blank_attestation_and_naive_times_are_rejected() -> None:
    with pytest.raises(PolicyError, match="attestation"):
        create_approval(
            _manifest(),
            actor="octocat",
            attestation=" ",
            config=PublishingConfig(),
            now=NOW,
        )
    with pytest.raises(PolicyError, match="timezone-aware"):
        create_approval(
            _manifest(),
            actor="octocat",
            attestation="I approve.",
            config=PublishingConfig(),
            now=datetime(2026, 7, 21, 12),
        )
