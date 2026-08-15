from __future__ import annotations

import json
import os
from datetime import timedelta
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

import autocontribute.workspace_gc as workspace_gc
from autocontribute.backup import create_state_bundle
from autocontribute.cli import app
from autocontribute.config import AutocontributeConfig
from autocontribute.domain import (
    CommandResult,
    CriticReview,
    FileEdit,
    GateResult,
    IssueCandidate,
    PatchProposal,
    QualityReport,
    RepositoryInfo,
    ReviewScores,
    RunManifest,
    RunStatus,
)
from autocontribute.evaluation import EvaluationStore
from autocontribute.preparation import (
    compute_preparation_fingerprint,
    render_validation_artifact,
)
from autocontribute.store import RunStore
from autocontribute.workspace_gc import collect_terminal_workspaces

PATCH = b"diff --git a/app.py b/app.py\n-old\n+new\n"


def _terminal_run(store: RunStore, status: RunStatus = RunStatus.SKIPPED) -> RunManifest:
    run = store.create_run()
    run.status = status
    store.save(run, event="fixture.terminal", details={"status": status.value})
    workspace = store.workspace_dir(run.run_id)
    (workspace / "repository").mkdir()
    (workspace / "repository" / "evidence.txt").write_text("workspace\n", encoding="utf-8")
    return run


def _prepared_run(
    store: RunStore,
    *,
    deployment_fingerprint: str | None = None,
) -> RunManifest:
    run = store.create_run(deployment_fingerprint=deployment_fingerprint)
    store.transition(run, RunStatus.DISCOVERING, reason="fixture started")
    now = run.created_at
    run.candidate = IssueCandidate(
        repository="example/project",
        number=42,
        title="Correct the boundary",
        body="The current boundary result is incorrect.",
        html_url="https://github.com/example/project/issues/42",
        state="open",
        author="maintainer",
        labels=["bug"],
        assignees=[],
        comments=1,
        created_at=now,
        updated_at=now,
    )
    run.repository = RepositoryInfo(
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
    run.base_sha = "b" * 40
    run.proposal = PatchProposal(
        summary="Correct the boundary result.",
        edits=[
            FileEdit(
                operation="replace",
                path="app.py",
                find="old",
                replace="new",
                content=None,
                rationale="Match the documented behavior.",
            )
        ],
        validation_commands=["python -m pytest"],
        commit_message="Correct the boundary result",
        pull_request_title="Correct the boundary result",
        pull_request_body="Fixes #42.",
        limitations=[],
    )
    review = CriticReview(
        verdict="approve",
        summary="The focused change is ready.",
        scores=ReviewScores(
            correctness=96,
            issue_alignment=97,
            tests=95,
            repository_conventions=95,
            diff_hygiene=98,
            maintainer_clarity=96,
        ),
        blocking_findings=[],
        non_blocking_findings=[],
        issue_requirements_met=["The boundary is corrected"],
        issue_requirements_missing=[],
        test_evidence_assessment="The regression command passed.",
        maintainer_perspective="Small and reviewable.",
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
    run.quality = QualityReport(
        ready=True,
        readiness_score=96,
        gates=[GateResult(gate="validation", passed=True, evidence="1/1 passed")],
        review=review,
        changed_files=1,
        changed_lines=2,
    )
    run.preparation_config_fingerprint = "f" * 64
    store.write_artifact(run.run_id, "contribution.patch", PATCH.decode())
    store.write_artifact(run.run_id, "validation.json", render_validation_artifact(run))
    run.preparation_fingerprint = compute_preparation_fingerprint(run, diff=PATCH)
    lease_owner = f"workspace-gc-fixture-{run.run_id}"
    lease = store.acquire_lease(
        "autocontribute.run",
        lease_owner,
        ttl=timedelta(minutes=1),
    )
    assert lease is not None
    store.claim_candidate(run, lease=lease)
    assert store.release_lease("autocontribute.run", lease_owner, lease.generation)
    run.status = RunStatus.READY_FOR_APPROVAL
    store.save(run, event="fixture.prepared", details={"status": run.status.value})
    workspace = store.workspace_dir(run.run_id)
    (workspace / "repository").mkdir()
    (workspace / "repository" / "app.py").write_text("new\n", encoding="utf-8")
    return run


def _published_run(
    store: RunStore,
    *,
    canonical_event: str,
    ready_for_review: bool = False,
) -> RunManifest:
    run = _prepared_run(store)
    run = store.begin_publication(
        run,
        "example/project",
        branch_name=f"autocontribute/issue-42-{run.run_id}",
        publication_draft=True,
        publication_ready_for_review=ready_for_review,
        publishing_login="octocat",
        publishing_api_origin="https://api.github.com",
        commit_author_name="Octocat",
        commit_author_email="octocat@users.noreply.github.com",
        commit_committer_name="Octocat",
        commit_committer_email="octocat@users.noreply.github.com",
        max_per_utc_day=10,
        repository_cooldown=timedelta(0),
    )
    run.commit_sha = "c" * 40
    run.pull_request_creation_started = True
    run.pull_request_url = "https://github.com/example/project/pull/7"
    canonical_details = {
        "pull_request.created.response": {
            "url": run.pull_request_url,
            "repository": "example/project",
            "number": "7",
            "state": "open",
            "head_sha": run.commit_sha,
            "base_sha": run.base_sha,
        },
        "pull_request.discovered": {
            "url": run.pull_request_url,
            "repository": "example/project",
            "number": "7",
            "head_sha": run.commit_sha,
        },
        "pull_request.reconciled": {
            "url": run.pull_request_url,
            "state": "open",
            "base_sha": run.base_sha,
        },
    }
    store.save(run, event=canonical_event, details=canonical_details[canonical_event])
    if ready_for_review:
        ready_details = {
            "url": run.pull_request_url,
            "repository": "example/project",
            "number": "7",
            "head_sha": run.commit_sha,
        }
        run.pull_request_ready_started = True
        store.save(
            run,
            event="pull_request.ready_for_review.started",
            details=ready_details,
        )
        run.pull_request_ready_completed = True
        store.save(
            run,
            event="pull_request.ready_for_review.completed",
            details=ready_details,
        )
    store.transition(run, RunStatus.PR_OPEN, reason="fixture publication completed")
    return run


def _future(run: RunManifest, *, days: int = 8):
    return run.updated_at + timedelta(days=days)


def test_cleanup_is_a_bounded_dry_run_by_default(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    first = _terminal_run(store)
    second = _terminal_run(store, RunStatus.REJECTED)
    third = _terminal_run(store, RunStatus.CANCELLED)

    report = collect_terminal_workspaces(
        store,
        older_than=timedelta(days=7),
        limit=2,
        now=_future(third),
    )

    assert report.execute is False
    assert report.terminal_candidates == 3
    assert report.selected == 2
    assert report.truncated == 1
    assert report.would_delete == 2
    assert report.deleted == report.retained == report.errors == 0
    assert [item.run_id for item in report.items] == [first.run_id, second.run_id]
    assert all(item.entries >= 3 and item.bytes > 0 for item in report.items)
    assert all(store.workspaces_dir.joinpath(run.run_id).is_dir() for run in (first, second, third))


def test_older_runs_without_workspaces_do_not_starve_newer_candidate(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    for _index in range(40):
        run = store.create_run()
        run.status = RunStatus.SKIPPED
        store.save(run, event="fixture.terminal", details={"status": run.status.value})
    eligible = _terminal_run(store)

    report = collect_terminal_workspaces(
        store,
        older_than=timedelta(days=7),
        limit=1,
        now=_future(eligible),
    )

    assert report.terminal_candidates == report.selected == report.would_delete == 1
    assert report.items[0].run_id == eligible.run_id


def test_execute_deletes_only_workspace_and_preserves_durable_state(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = _terminal_run(store)
    events_before = store.events(run.run_id)

    report = collect_terminal_workspaces(
        store,
        older_than=timedelta(days=7),
        execute=True,
        now=_future(run),
    )

    assert report.deleted == 1
    assert not store.workspaces_dir.joinpath(run.run_id).exists()
    assert store.get(run.run_id) == run
    assert store.events(run.run_id) == events_before
    assert store.runs_dir.joinpath(run.run_id, "manifest.json").is_file()
    create_state_bundle(store, tmp_path / "complete.bundle.zip")


def test_nonterminal_and_submitting_publication_workspaces_are_never_candidates(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    ready = _prepared_run(store)
    submitting = store.begin_publication(
        ready,
        "example/project",
        branch_name=f"autocontribute/issue-42-{ready.run_id}",
        publication_draft=True,
        publishing_login="octocat",
        publishing_api_origin="https://api.github.com",
        commit_author_name="Octocat",
        commit_author_email="octocat@users.noreply.github.com",
        commit_committer_name="Octocat",
        commit_committer_email="octocat@users.noreply.github.com",
        max_per_utc_day=10,
        repository_cooldown=timedelta(0),
    )
    submitting.commit_sha = "c" * 40
    submitting.pull_request_creation_started = True
    store.save(submitting, event="commit.created", details={"commit_sha": submitting.commit_sha})

    report = collect_terminal_workspaces(
        store,
        older_than=timedelta(days=7),
        execute=True,
        now=_future(submitting),
    )

    assert report.terminal_candidates == report.selected == report.deleted == 0
    assert report.protected_nonterminal == 1
    assert store.workspaces_dir.joinpath(submitting.run_id).is_dir()


def test_nonpublished_terminal_run_with_publication_intent_is_retained(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = _prepared_run(store)
    run = store.begin_publication(
        run,
        "example/project",
        branch_name=f"autocontribute/issue-42-{run.run_id}",
        publication_draft=True,
        publishing_login="octocat",
        publishing_api_origin="https://api.github.com",
        commit_author_name="Octocat",
        commit_author_email="octocat@users.noreply.github.com",
        commit_committer_name="Octocat",
        commit_committer_email="octocat@users.noreply.github.com",
        max_per_utc_day=10,
        repository_cooldown=timedelta(0),
    )
    run.commit_sha = "c" * 40
    run.status = RunStatus.FAILED
    store.save(run, event="fixture.failed", details={"reason": "ambiguous publication"})

    report = collect_terminal_workspaces(
        store,
        older_than=timedelta(days=7),
        execute=True,
        now=_future(run),
    )

    assert report.retained == 1
    assert report.errors == 0
    assert "publication reconstruction evidence" in report.items[0].reason
    assert store.workspaces_dir.joinpath(run.run_id).is_dir()


def test_terminal_run_with_active_publication_hold_is_an_error_and_is_retained(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    deployment_fingerprint = "f" * 64
    run = _prepared_run(store, deployment_fingerprint=deployment_fingerprint)
    summary = EvaluationStore(store).summary(deployment_fingerprint=deployment_fingerprint)
    run = store.begin_publication(
        run,
        "example/project",
        branch_name=f"autocontribute/issue-42-{run.run_id}",
        publication_draft=True,
        publishing_login="octocat",
        publishing_api_origin="https://api.github.com",
        commit_author_name="Octocat",
        commit_author_email="octocat@users.noreply.github.com",
        commit_committer_name="Octocat",
        commit_committer_email="octocat@users.noreply.github.com",
        max_per_utc_day=10,
        repository_cooldown=timedelta(0),
        evaluation_corpus_cursor=summary.corpus_cursor,
        evaluation_deployment_fingerprint=summary.deployment_fingerprint,
        outcome_corpus_cursor=store.upstream_outcome_corpus_cursor(
            summary.deployment_fingerprint,
            "octocat",
            "https://api.github.com",
            exclude_run_id=run.run_id,
        ),
    )
    run.status = RunStatus.FAILED
    store.save(run, event="fixture.failed", details={"reason": "ambiguous publication"})

    report = collect_terminal_workspaces(
        store,
        older_than=timedelta(days=7),
        execute=True,
        now=_future(run),
    )

    assert report.retained == report.errors == 1
    assert "publication gate hold" in report.items[0].reason
    assert store.workspaces_dir.joinpath(run.run_id).is_dir()


@pytest.mark.parametrize(
    "canonical_event",
    [
        "pull_request.created.response",
        "pull_request.discovered",
        "pull_request.reconciled",
    ],
)
def test_complete_published_run_is_workspace_independent(
    tmp_path: Path,
    canonical_event: str,
) -> None:
    store = RunStore(tmp_path / "state")
    run = _published_run(store, canonical_event=canonical_event)

    report = collect_terminal_workspaces(
        store,
        older_than=timedelta(days=7),
        execute=True,
        now=_future(run),
    )

    assert report.deleted == 1
    assert report.errors == 0
    assert report.items[0].status == RunStatus.PR_OPEN
    assert not store.workspaces_dir.joinpath(run.run_id).exists()
    create_state_bundle(store, tmp_path / "published.bundle.zip")


def test_complete_ready_for_review_run_is_workspace_independent(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = _published_run(
        store,
        canonical_event="pull_request.created.response",
        ready_for_review=True,
    )

    report = collect_terminal_workspaces(
        store,
        older_than=timedelta(days=7),
        execute=True,
        now=_future(run),
    )

    assert report.deleted == 1
    assert report.errors == 0


def test_incomplete_ready_for_review_evidence_retains_workspace(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = _prepared_run(store)
    run = store.begin_publication(
        run,
        "example/project",
        branch_name=f"autocontribute/issue-42-{run.run_id}",
        publication_draft=True,
        publication_ready_for_review=True,
        publishing_login="octocat",
        publishing_api_origin="https://api.github.com",
        commit_author_name="Octocat",
        commit_author_email="octocat@users.noreply.github.com",
        commit_committer_name="Octocat",
        commit_committer_email="octocat@users.noreply.github.com",
        max_per_utc_day=10,
        repository_cooldown=timedelta(0),
    )
    run.commit_sha = "c" * 40
    run.pull_request_creation_started = True
    run.pull_request_url = "https://github.com/example/project/pull/7"
    canonical_details = {
        "url": run.pull_request_url,
        "repository": "example/project",
        "number": "7",
        "state": "open",
        "head_sha": run.commit_sha,
        "base_sha": run.base_sha,
    }
    store.save(run, event="pull_request.created.response", details=canonical_details)
    run.pull_request_ready_started = True
    store.save(
        run,
        event="pull_request.ready_for_review.started",
        details={
            "url": run.pull_request_url,
            "repository": "example/project",
            "number": "7",
            "head_sha": run.commit_sha,
        },
    )
    store.transition(run, RunStatus.PR_OPEN, reason="fixture omitted ready completion")

    report = collect_terminal_workspaces(
        store,
        older_than=timedelta(days=7),
        execute=True,
        now=_future(run),
    )

    assert report.retained == report.errors == 1
    assert "incomplete ready-for-review transition" in report.items[0].reason
    assert store.workspaces_dir.joinpath(run.run_id).is_dir()


def test_published_run_without_canonical_pr_event_is_retained(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = _prepared_run(store)
    run = store.begin_publication(
        run,
        "example/project",
        branch_name=f"autocontribute/issue-42-{run.run_id}",
        publication_draft=True,
        publishing_login="octocat",
        publishing_api_origin="https://api.github.com",
        commit_author_name="Octocat",
        commit_author_email="octocat@users.noreply.github.com",
        commit_committer_name="Octocat",
        commit_committer_email="octocat@users.noreply.github.com",
        max_per_utc_day=10,
        repository_cooldown=timedelta(0),
    )
    run.commit_sha = "c" * 40
    run.pull_request_creation_started = True
    run.pull_request_url = "https://github.com/example/project/pull/7"
    store.save(run, event="fixture.pr_response", details={"url": run.pull_request_url})
    store.transition(run, RunStatus.PR_OPEN, reason="fixture publication completed")

    report = collect_terminal_workspaces(
        store,
        older_than=timedelta(days=7),
        execute=True,
        now=_future(run),
    )

    assert report.retained == report.errors == 1
    assert "canonical pull-request persistence" in report.items[0].reason
    assert store.workspaces_dir.joinpath(run.run_id).is_dir()


def test_published_run_without_publication_intent_event_is_retained(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = _prepared_run(store)
    store.transition(run, RunStatus.SUBMITTING, reason="fixture bypassed publication intent")
    run.branch_name = f"autocontribute/issue-42-{run.run_id}"
    run.publication_draft = True
    run.publication_ready_for_review = False
    run.publishing_login = "octocat"
    run.publishing_api_origin = "https://api.github.com"
    run.commit_author_name = run.commit_committer_name = "Octocat"
    run.commit_author_email = run.commit_committer_email = "octocat@users.noreply.github.com"
    run.commit_sha = "c" * 40
    run.pull_request_creation_started = True
    run.pull_request_url = "https://github.com/example/project/pull/7"
    store.save(
        run,
        event="pull_request.created.response",
        details={
            "url": run.pull_request_url,
            "repository": "example/project",
            "number": "7",
            "state": "open",
            "head_sha": run.commit_sha,
            "base_sha": run.base_sha,
        },
    )
    store.transition(run, RunStatus.PR_OPEN, reason="fixture publication completed")

    report = collect_terminal_workspaces(
        store,
        older_than=timedelta(days=7),
        execute=True,
        now=_future(run),
    )

    assert report.retained == report.errors == 1
    assert "publication-intent" in report.items[0].reason
    assert store.workspaces_dir.joinpath(run.run_id).is_dir()


def test_published_run_with_pr_event_after_terminal_transition_is_retained(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = _prepared_run(store)
    run = store.begin_publication(
        run,
        "example/project",
        branch_name=f"autocontribute/issue-42-{run.run_id}",
        publication_draft=True,
        publishing_login="octocat",
        publishing_api_origin="https://api.github.com",
        commit_author_name="Octocat",
        commit_author_email="octocat@users.noreply.github.com",
        commit_committer_name="Octocat",
        commit_committer_email="octocat@users.noreply.github.com",
        max_per_utc_day=10,
        repository_cooldown=timedelta(0),
    )
    run.commit_sha = "c" * 40
    run.pull_request_creation_started = True
    run.pull_request_url = "https://github.com/example/project/pull/7"
    run.status = RunStatus.PR_OPEN
    store.save(
        run,
        event="run.transitioned",
        details={
            "from": RunStatus.SUBMITTING.value,
            "to": RunStatus.PR_OPEN.value,
            "reason": "fixture transition persisted too early",
        },
    )
    store.save(
        run,
        event="pull_request.created.response",
        details={
            "url": run.pull_request_url,
            "repository": "example/project",
            "number": "7",
            "state": "open",
            "head_sha": run.commit_sha,
            "base_sha": run.base_sha,
        },
    )

    report = collect_terminal_workspaces(
        store,
        older_than=timedelta(days=7),
        execute=True,
        now=_future(run),
    )

    assert report.retained == report.errors == 1
    assert "submitting-to-pr_open transition" in report.items[0].reason
    assert store.workspaces_dir.joinpath(run.run_id).is_dir()


def test_prepared_terminal_run_with_tampered_artifact_is_retained(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = _prepared_run(store)
    run.status = RunStatus.REJECTED
    store.save(run, event="fixture.rejected", details={"reason": "fixture"})
    store.runs_dir.joinpath(run.run_id, "contribution.patch").write_text(
        "tampered\n",
        encoding="utf-8",
    )

    report = collect_terminal_workspaces(
        store,
        older_than=timedelta(days=7),
        execute=True,
        now=_future(run),
    )

    assert report.retained == report.errors == 1
    assert "durable recovery evidence" in report.items[0].reason
    assert store.workspaces_dir.joinpath(run.run_id).is_dir()


def test_workspace_symlink_is_reported_and_never_followed(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = _terminal_run(store)
    workspace = store.workspaces_dir / run.run_id
    external = tmp_path / "external"
    external.mkdir()
    marker = external / "keep.txt"
    marker.write_text("keep\n", encoding="utf-8")
    for child in workspace.rglob("*"):
        if child.is_file():
            child.unlink()
    workspace.joinpath("repository").rmdir()
    workspace.rmdir()
    workspace.symlink_to(external, target_is_directory=True)

    report = collect_terminal_workspaces(
        store,
        older_than=timedelta(days=7),
        execute=True,
        now=_future(run),
    )

    assert report.retained == report.errors == 1
    assert workspace.is_symlink()
    assert marker.read_text(encoding="utf-8") == "keep\n"


def test_quarantine_restores_swapped_real_directory_without_deleting_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = RunStore(tmp_path / "state")
    run = _terminal_run(store)
    workspace = store.workspaces_dir / run.run_id
    displaced = store.workspaces_dir / "displaced-original"
    original_rename = os.rename
    swap_injected = False

    def rename_with_swap(
        source: str,
        destination: str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        nonlocal swap_injected
        if (
            not swap_injected
            and source == run.run_id
            and destination == "workspace"
            and src_dir_fd is not None
            and dst_dir_fd is not None
        ):
            original_rename(workspace, displaced)
            workspace.mkdir()
            (workspace / "replacement.txt").write_text("replacement\n", encoding="utf-8")
            swap_injected = True
        original_rename(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )

    monkeypatch.setattr(workspace_gc.os, "rename", rename_with_swap)

    report = collect_terminal_workspaces(
        store,
        older_than=timedelta(days=7),
        execute=True,
        now=_future(run),
    )

    assert swap_injected
    assert report.deleted == 0
    assert report.retained == report.errors == 1
    assert "restored without deletion" in report.items[0].reason
    assert displaced.joinpath("repository", "evidence.txt").read_text(encoding="utf-8") == (
        "workspace\n"
    )
    assert workspace.joinpath("replacement.txt").read_text(encoding="utf-8") == "replacement\n"
    assert not any(
        entry.name.startswith(".autocontribute-gc-") for entry in store.workspaces_dir.iterdir()
    )


def _terminal_file_entry(store: RunStore) -> RunManifest:
    """A terminal run whose workspace entry is a plain file, a permanent retained error."""

    run = store.create_run()
    run.status = RunStatus.SKIPPED
    store.save(run, event="fixture.terminal", details={"status": run.status.value})
    (store.workspaces_dir / run.run_id).write_text("not a directory\n", encoding="utf-8")
    return run


def test_failed_recursive_deletion_is_a_retained_error_and_cleanup_continues(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = RunStore(tmp_path / "state")
    first = _terminal_run(store)
    second = _terminal_run(store)
    original_rmtree = workspace_gc.shutil.rmtree
    calls: list[object] = []

    def failing_rmtree(*args: object, **kwargs: object) -> None:
        calls.append(args)
        if len(calls) == 1:
            raise OSError("simulated undeletable subuid-owned file")
        original_rmtree(*args, **kwargs)  # type: ignore[arg-type]

    failing_rmtree.avoids_symlink_attacks = True  # type: ignore[attr-defined]
    monkeypatch.setattr(workspace_gc.shutil, "rmtree", failing_rmtree)

    report = collect_terminal_workspaces(
        store,
        older_than=timedelta(days=7),
        execute=True,
        now=_future(second),
    )

    assert report.deleted == 1
    assert report.retained == report.errors == 1
    error_item = next(item for item in report.items if item.error)
    assert error_item.run_id == first.run_id
    assert "deletion failed safely" in error_item.reason
    assert not store.workspaces_dir.joinpath(second.run_id).exists()
    quarantines = [
        entry
        for entry in store.workspaces_dir.iterdir()
        if entry.name.startswith(".autocontribute-gc-")
    ]
    assert len(quarantines) == 1
    preserved = quarantines[0] / "workspace" / "repository" / "evidence.txt"
    assert preserved.read_text(encoding="utf-8") == "workspace\n"


def test_persistent_retained_backlog_does_not_starve_younger_deletable_workspace(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    for _index in range(3):
        _terminal_file_entry(store)
    eligible = _terminal_run(store)

    report = collect_terminal_workspaces(
        store,
        older_than=timedelta(days=7),
        limit=1,
        execute=True,
        now=_future(eligible),
    )

    assert report.terminal_candidates == report.selected == 4
    assert report.deleted == 1
    assert report.retained == report.errors == 3
    assert report.truncated == 0
    assert not store.workspaces_dir.joinpath(eligible.run_id).exists()
    assert all("not a real directory" in item.reason for item in report.items if item.error)


def test_scan_bound_defers_candidates_beyond_five_deletion_budgets(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    for _index in range(6):
        _terminal_file_entry(store)
    eligible = _terminal_run(store)

    report = collect_terminal_workspaces(
        store,
        older_than=timedelta(days=7),
        limit=1,
        execute=True,
        now=_future(eligible),
    )

    assert report.terminal_candidates == 7
    assert report.selected == 5
    assert report.truncated == 2
    assert report.deleted == 0
    assert report.retained == report.errors == 5
    assert store.workspaces_dir.joinpath(eligible.run_id).is_dir()


def test_stale_quarantine_sweep_reclaims_only_old_exact_quarantines(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = _terminal_run(store)
    observed_at = _future(run)
    stale = store.workspaces_dir / f".autocontribute-gc-{'a' * 32}"
    (stale / "workspace" / "repository").mkdir(parents=True)
    (stale / "workspace" / "repository" / "junk.txt").write_text("junk\n", encoding="utf-8")
    stale.chmod(0o700)
    os.utime(stale, times=((observed_at - timedelta(hours=7)).timestamp(),) * 2)
    live = store.workspaces_dir / f".autocontribute-gc-{'b' * 32}"
    (live / "workspace").mkdir(parents=True)
    live.chmod(0o700)
    os.utime(live, times=((observed_at - timedelta(hours=1)).timestamp(),) * 2)
    wrong_mode = store.workspaces_dir / f".autocontribute-gc-{'c' * 32}"
    wrong_mode.mkdir()
    wrong_mode.chmod(0o755)
    os.utime(wrong_mode, times=((observed_at - timedelta(hours=7)).timestamp(),) * 2)
    unrelated = store.workspaces_dir / ".autocontribute-gc-short"
    unrelated.mkdir()
    os.utime(unrelated, times=((observed_at - timedelta(hours=7)).timestamp(),) * 2)

    dry = collect_terminal_workspaces(
        store,
        older_than=timedelta(days=7),
        now=observed_at,
    )

    assert dry.stale_quarantines == 1
    assert dry.stale_quarantines_deleted == 0
    assert dry.errors == 1
    assert stale.is_dir()

    executed = collect_terminal_workspaces(
        store,
        older_than=timedelta(days=7),
        execute=True,
        now=observed_at,
    )

    assert executed.stale_quarantines == executed.stale_quarantines_deleted == 1
    assert executed.errors == 1
    assert not stale.exists()
    assert live.joinpath("workspace").is_dir()
    assert wrong_mode.is_dir()
    assert unrelated.is_dir()


def test_retention_age_keeps_recent_terminal_workspace(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = _terminal_run(store)

    report = collect_terminal_workspaces(
        store,
        older_than=timedelta(days=7),
        execute=True,
        now=_future(run, days=1),
    )

    assert report.terminal_candidates == 0
    assert report.younger_terminal == 1
    assert store.workspaces_dir.joinpath(run.run_id).is_dir()


def test_orphan_workspace_is_outside_automatic_cleanup_authority(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    orphan = store.workspaces_dir / "orphan"
    orphan.mkdir()
    (orphan / "keep.txt").write_text("keep\n", encoding="utf-8")

    report = collect_terminal_workspaces(
        store,
        older_than=timedelta(days=7),
        execute=True,
    )

    assert report.terminal_candidates == report.deleted == 0
    assert orphan.joinpath("keep.txt").read_text(encoding="utf-8") == "keep\n"


def test_cli_defaults_to_json_dry_run_and_requires_execute_for_deletion(tmp_path: Path) -> None:
    state = tmp_path / "state"
    store = RunStore(state)
    run = _terminal_run(store)
    config = AutocontributeConfig.model_validate({"storage": {"path": state}})
    config_path = tmp_path / "autocontribute.yml"
    config_path.write_text(
        yaml.safe_dump(config.model_dump(mode="json"), sort_keys=False),
        encoding="utf-8",
    )
    runner = CliRunner()

    dry = runner.invoke(
        app,
        [
            "state",
            "gc-workspaces",
            "--config",
            str(config_path),
            "--older-than-days",
            "1",
            "--json",
        ],
    )

    assert dry.exit_code == 0, dry.output
    payload = json.loads(dry.output)
    assert payload["execute"] is False
    # The real clock is later than the synthetic run timestamp only by milliseconds, so use a
    # direct future-dated execution to prove the destructive gate separately.
    assert store.workspaces_dir.joinpath(run.run_id).is_dir()
    executed = collect_terminal_workspaces(
        store,
        older_than=timedelta(days=1),
        execute=True,
        now=_future(run, days=2),
    )
    assert executed.deleted == 1
