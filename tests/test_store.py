import hashlib
import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from autocontribute.ai_policy import RepositoryAiPolicy
from autocontribute.coordination import LeaseHeartbeatGuard
from autocontribute.domain import IssueCandidate, RunManifest, RunStatus
from autocontribute.exceptions import CircuitBreakerTrigger, PolicyError, StateError, StopScope
from autocontribute.issue_revision import compute_issue_revision
from autocontribute.store import (
    CURRENT_SCHEMA_VERSION,
    CandidateAttemptDisposition,
    CandidateAttemptState,
    CandidateRetryAuthorization,
    RunStore,
)


def _set_status(store: RunStore, run: RunManifest, status: RunStatus) -> None:
    run.status = status
    store.save(run, event="test.status", details={"status": status.value})


def _rewrite_tail_event_details(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    event_type: str,
    details: dict[str, str],
) -> None:
    """Tamper with a tail event while preserving a structurally valid hash chain."""

    row = connection.execute(
        """
        SELECT id, occurred_at, previous_hash FROM events
        WHERE run_id = ? AND event_type = ? ORDER BY id DESC LIMIT 1
        """,
        (run_id, event_type),
    ).fetchone()
    assert row is not None
    tail = connection.execute(
        "SELECT id FROM events WHERE run_id = ? ORDER BY id DESC LIMIT 1",
        (run_id,),
    ).fetchone()
    assert tail == (row[0],)
    details_json = json.dumps(details, sort_keys=True, separators=(",", ":"))
    payload = json.dumps(
        {
            "run_id": run_id,
            "occurred_at": row[1],
            "event_type": event_type,
            "details": details_json,
            "previous_hash": row[2],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    event_hash = hashlib.sha256(payload.encode()).hexdigest()
    connection.execute(
        "UPDATE events SET details_json = ?, event_hash = ? WHERE id = ?",
        (details_json, event_hash, row[0]),
    )
    connection.execute(
        "UPDATE runs SET event_head_hash = ? WHERE run_id = ?",
        (event_hash, run_id),
    )


def _delete_tail_event(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    event_type: str,
) -> None:
    """Remove a tail event while preserving the run's structural ledger anchor."""

    row = connection.execute(
        """
        SELECT id, previous_hash FROM events
        WHERE run_id = ? AND event_type = ? ORDER BY id DESC LIMIT 1
        """,
        (run_id, event_type),
    ).fetchone()
    assert row is not None
    tail = connection.execute(
        "SELECT id FROM events WHERE run_id = ? ORDER BY id DESC LIMIT 1",
        (run_id,),
    ).fetchone()
    assert tail == (row[0],)
    connection.execute("DELETE FROM events WHERE id = ?", (row[0],))
    connection.execute(
        """
        UPDATE runs SET event_count = event_count - 1, event_head_hash = ?
        WHERE run_id = ?
        """,
        (row[1], run_id),
    )


def _issue_candidate(
    *,
    repository: str = "example/project",
    number: int = 42,
    title: str = "Fix the exact bug",
) -> IssueCandidate:
    observed_at = datetime(2026, 7, 21, 12, tzinfo=UTC)
    return IssueCandidate(
        repository=repository,
        number=number,
        title=title,
        body="Reproduction and expected behavior.",
        html_url=f"https://github.com/{repository}/issues/{number}",
        state="open",
        author="maintainer",
        labels=["bug"],
        assignees=[],
        comments=0,
        created_at=observed_at,
        updated_at=observed_at,
    )


def _candidate_run(
    store: RunStore,
    *,
    candidate: IssueCandidate | None = None,
    status: RunStatus = RunStatus.QUEUED,
) -> RunManifest:
    run = store.create_run()
    _set_status(store, run, RunStatus.DISCOVERING)
    run.candidate = candidate or _issue_candidate()
    lease = store.acquire_lease(
        "autocontribute.run",
        f"candidate-fixture-{run.run_id}",
        ttl=timedelta(minutes=5),
    )
    assert lease is not None
    try:
        store.claim_candidate(run, lease=lease)
    finally:
        assert store.release_lease(lease.name, lease.owner, lease.generation)
    if status is not RunStatus.DISCOVERING:
        _set_status(store, run, status)
    return run


def _publication_run(
    store: RunStore,
    *,
    status: RunStatus = RunStatus.APPROVED,
    repository: str = "example/project",
    number: int = 42,
) -> RunManifest:
    run = store.create_run()
    _set_status(store, run, RunStatus.DISCOVERING)
    run.candidate = _issue_candidate(repository=repository, number=number)
    lease = store.acquire_lease(
        "autocontribute.run",
        f"publication-fixture-{run.run_id}",
        ttl=timedelta(minutes=5),
    )
    assert lease is not None
    try:
        store.claim_candidate(run, lease=lease)
    finally:
        assert store.release_lease(lease.name, lease.owner, lease.generation)
    if status is not RunStatus.DISCOVERING:
        _set_status(store, run, status)
    return run


def _begin_publication(
    store: RunStore,
    run: RunManifest,
    *,
    branch_name: str = "autocontribute/fix-exact-bug",
    publication_draft: bool = True,
    max_per_utc_day: int = 100,
    repository_cooldown: timedelta = timedelta(0),
    now: datetime | None = None,
) -> RunManifest:
    return store.begin_publication(
        run,
        "example/project",
        branch_name=branch_name,
        publication_draft=publication_draft,
        publishing_login="octocat",
        publishing_api_origin="https://api.github.com",
        commit_author_name="Octo Cat",
        commit_author_email="octocat@users.noreply.github.com",
        commit_committer_name="Octo Cat",
        commit_committer_email="octocat@users.noreply.github.com",
        max_per_utc_day=max_per_utc_day,
        repository_cooldown=repository_cooldown,
        now=now,
    )


def _record_absent_compensation_evidence(
    store: RunStore,
    run: RunManifest,
    *,
    reason: str,
) -> dict[str, str]:
    assert run.candidate is not None
    assert run.branch_name is not None
    assert run.publishing_login is not None
    assert run.publishing_api_origin is not None
    if run.upstream_repository_id is None and run.upstream_repository_node_id is None:
        run.upstream_repository_id = 1001
        run.upstream_repository_node_id = "R_upstream_fixture"
    assert run.upstream_repository_id is not None
    assert run.upstream_repository_node_id is not None
    fork = f"{run.publishing_login}/{run.candidate.repository.split('/', 1)[1]}"
    if run.fork_repository_id is None and run.fork_repository_node_id is None:
        fork_identity = {"fork_identity_state": "not_bound"}
    else:
        assert run.fork_repository_id is not None
        assert run.fork_repository_node_id is not None
        fork_identity = {
            "fork_identity_state": "bound",
            "fork_repository_id": str(run.fork_repository_id),
            "fork_repository_node_id": run.fork_repository_node_id,
        }
    details = {
        "repository": run.candidate.repository,
        "publishing_api_origin": run.publishing_api_origin,
        "upstream_repository_id": str(run.upstream_repository_id),
        "upstream_repository_node_id": run.upstream_repository_node_id,
        "head": f"{run.publishing_login}:{run.branch_name}",
        "fork": fork,
        **fork_identity,
        "branch": run.branch_name,
        "commit_sha": run.commit_sha or "not_persisted",
        "reason": reason,
    }
    store.save(
        run,
        event="publication.absence.verified",
        details=details,
    )
    return {key: value for key, value in details.items() if key != "reason"} | {
        "pull_request": "absent",
        "remote_branch": "absent",
    }


def _record_created_pr_base_race_evidence(
    store: RunStore,
    run: RunManifest,
    *,
    pull_request_url: str = "https://github.com/example/project/pull/7",
) -> None:
    assert run.candidate is not None
    assert run.branch_name is not None
    run.base_sha = "b" * 40
    run.commit_sha = "c" * 40
    run.pull_request_url = pull_request_url
    run.pull_request_node_id = "PR_fixture_7"
    run.upstream_repository_id = 1001
    run.upstream_repository_node_id = "R_upstream_fixture"
    run.fork_repository_id = 2001
    run.fork_repository_node_id = "R_fork_fixture"
    run.publication_compensation_reason = "created_pr_base_moved"
    returned_base = "e" * 40
    store.save(
        run,
        event="branch.pushed",
        details={
            "fork": "octocat/project",
            "fork_repository_id": str(run.fork_repository_id),
            "fork_repository_node_id": run.fork_repository_node_id,
            "upstream_repository_id": str(run.upstream_repository_id),
            "upstream_repository_node_id": run.upstream_repository_node_id,
            "branch": run.branch_name,
            "commit_sha": run.commit_sha,
        },
    )
    store.save(
        run,
        event="pull_request.created.response",
        details={
            "url": pull_request_url,
            "repository": run.candidate.repository,
            "number": "7",
            "state": "open",
            "head_sha": run.commit_sha,
            "base_sha": returned_base,
            "pull_request_node_id": run.pull_request_node_id,
            "upstream_repository_id": str(run.upstream_repository_id),
            "upstream_repository_node_id": run.upstream_repository_node_id,
            "fork_repository_id": str(run.fork_repository_id),
            "fork_repository_node_id": run.fork_repository_node_id,
        },
    )
    store.save(
        run,
        event="pull_request.created.rejected",
        details={
            "url": pull_request_url,
            "mismatches": "base commit",
            "expected_base_sha": run.base_sha,
            "returned_base_sha": returned_base,
        },
    )
    store.save(
        run,
        event="publication.compensation.started",
        details={
            "reason": "created_pr_base_moved",
            "url": pull_request_url,
            "pull_request_node_id": run.pull_request_node_id,
            "repository": run.candidate.repository,
            "number": "7",
            "upstream_repository_id": str(run.upstream_repository_id),
            "upstream_repository_node_id": run.upstream_repository_node_id,
            "fork": "octocat/project",
            "fork_repository_id": str(run.fork_repository_id),
            "fork_repository_node_id": run.fork_repository_node_id,
            "branch": run.branch_name,
            "commit_sha": run.commit_sha,
            "approved_base_sha": run.base_sha,
            "returned_base_sha": returned_base,
        },
    )


def _record_merged_compensation_evidence(
    store: RunStore,
    run: RunManifest,
    *,
    pull_request_url: str = "https://github.com/example/project/pull/7",
) -> None:
    _record_created_pr_base_race_evidence(
        store,
        run,
        pull_request_url=pull_request_url,
    )
    assert run.pull_request_node_id is not None
    assert run.commit_sha is not None
    assert run.upstream_repository_id is not None
    assert run.upstream_repository_node_id is not None
    assert run.fork_repository_id is not None
    assert run.fork_repository_node_id is not None
    store.save(
        run,
        event="pull_request.compensation.reconciled",
        details={
            "url": pull_request_url,
            "pull_request_node_id": run.pull_request_node_id,
            "state": "merged",
            "head_sha": run.commit_sha,
            "upstream_repository_id": str(run.upstream_repository_id),
            "upstream_repository_node_id": run.upstream_repository_node_id,
            "fork_repository_id": str(run.fork_repository_id),
            "fork_repository_node_id": run.fork_repository_node_id,
        },
    )


def _record_created_pr_compensation_evidence(
    store: RunStore,
    run: RunManifest,
    *,
    reason: str,
    repetitions: int = 1,
) -> dict[str, str]:
    _record_created_pr_base_race_evidence(store, run)
    assert run.candidate is not None
    assert run.branch_name is not None
    assert run.commit_sha is not None
    assert run.pull_request_url is not None
    assert run.pull_request_node_id is not None
    assert run.publishing_login is not None
    assert run.upstream_repository_id is not None
    assert run.upstream_repository_node_id is not None
    assert run.fork_repository_id is not None
    assert run.fork_repository_node_id is not None
    fork = f"{run.publishing_login}/{run.candidate.repository.split('/', 1)[1]}"
    close_details = {
        "url": run.pull_request_url,
        "state": "closed_unmerged",
    }
    branch_details = {
        "fork": fork,
        "fork_repository_id": str(run.fork_repository_id),
        "fork_repository_node_id": run.fork_repository_node_id,
        "branch": run.branch_name,
        "commit_sha": run.commit_sha,
    }
    for _ in range(repetitions):
        store.save(
            run,
            event="pull_request.compensation.closed",
            details=close_details,
        )
        store.save(
            run,
            event="branch.compensated",
            details=branch_details,
        )
    return {
        "url": run.pull_request_url,
        "repository": run.candidate.repository,
        "number": "7",
        "pull_request_node_id": run.pull_request_node_id,
        "upstream_repository_id": str(run.upstream_repository_id),
        "upstream_repository_node_id": run.upstream_repository_node_id,
        "fork": fork,
        "fork_repository_id": str(run.fork_repository_id),
        "fork_repository_node_id": run.fork_repository_node_id,
        "branch": run.branch_name,
        "commit_sha": run.commit_sha,
        "pull_request": "closed_unmerged",
        "remote_branch": "absent",
    }


def test_store_persists_transitions_and_hash_chains_events(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = store.create_run()

    store.transition(run, RunStatus.DISCOVERING, reason="start")
    store.transition(run, RunStatus.SKIPPED, reason="no worthy candidate")

    loaded = store.get(run.run_id)
    events = store.events(run.run_id)
    assert loaded.status == RunStatus.SKIPPED
    assert len(events) == 3
    assert events[0]["previous_hash"] == "0" * 64
    assert events[1]["previous_hash"] == events[0]["event_hash"]
    assert json.loads(events[-1]["details"])["to"] == "skipped"
    assert (store.artifact_dir(run.run_id) / "manifest.json").is_file()


def test_store_rejects_illegal_transition(tmp_path: Path) -> None:
    store = RunStore(tmp_path)
    run = store.create_run()

    with pytest.raises(StateError, match="Invalid run transition"):
        store.transition(run, RunStatus.PR_OPEN, reason="skip every gate")


def test_stale_manifest_cannot_overwrite_a_newer_transition_or_pr_evidence(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    run = store.create_run()
    _set_status(store, run, RunStatus.READY_FOR_APPROVAL)
    published = store.get(run.run_id)
    stale = store.get(run.run_id)

    store.transition(published, RunStatus.APPROVED, reason="operator approval")
    store.transition(published, RunStatus.SUBMITTING, reason="publication reserved")
    published.branch_name = "autocontribute/fix"
    published.commit_sha = "a" * 40
    published.pull_request_url = "https://github.com/example/project/pull/1"
    store.transition(published, RunStatus.PR_OPEN, reason="pull request created")

    with pytest.raises(StateError, match="changed while this manifest was being saved"):
        store.transition(stale, RunStatus.CANCELLED, reason="stale operator cancellation")

    assert stale.status == RunStatus.READY_FOR_APPROVAL
    persisted = store.get(run.run_id)
    assert persisted.status == RunStatus.PR_OPEN
    assert persisted.commit_sha == "a" * 40
    assert persisted.pull_request_url == "https://github.com/example/project/pull/1"


def test_artifact_path_cannot_escape_run_directory(tmp_path: Path) -> None:
    store = RunStore(tmp_path)
    run = store.create_run()

    with pytest.raises(StateError, match="escaped"):
        store.write_artifact(run.run_id, "../secret", "no")


def test_fresh_database_has_current_version_and_all_tables(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")

    with sqlite3.connect(store.database_path) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        run_columns = {row[1] for row in connection.execute("PRAGMA table_info(runs)").fetchall()}
        revision_index = connection.execute(
            "PRAGMA index_info(runs_candidate_revision_idx)"
        ).fetchall()
        revision_index_xinfo = connection.execute(
            "PRAGMA index_xinfo(runs_candidate_revision_idx)"
        ).fetchall()
        run_indexes = {
            row[1]: row for row in connection.execute("PRAGMA index_list(runs)").fetchall()
        }
        index_sql = {
            row[0]: row[1]
            for row in connection.execute(
                """
                SELECT name, sql FROM sqlite_master
                WHERE type = 'index'
                    AND name IN ('runs_candidate_revision_idx', 'runs_active_candidate_idx')
                """
            )
        }
        authorization_columns = [
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(candidate_retry_authorizations)"
            ).fetchall()
        ]

    assert store.schema_version == CURRENT_SCHEMA_VERSION == 9
    assert "issue_revision" in run_columns
    assert [row[2] for row in revision_index] == [
        "repository",
        "issue_number",
        "issue_revision",
        "status",
    ]
    assert [row[4] for row in revision_index_xinfo if row[5]] == [
        "NOCASE",
        "BINARY",
        "BINARY",
        "BINARY",
    ]
    assert run_indexes["runs_active_candidate_idx"][2] == 1
    assert run_indexes["runs_active_candidate_idx"][4] == 1
    assert "repository COLLATE NOCASE" in index_sql["runs_candidate_revision_idx"]
    assert "repository COLLATE NOCASE" in index_sql["runs_active_candidate_idx"]
    assert "WHERE issue_number IS NOT NULL" in index_sql["runs_active_candidate_idx"]
    assert authorization_columns == [
        "authorization_id",
        "run_id",
        "repository",
        "issue_number",
        "issue_revision",
        "prior_run_id",
        "prior_status",
        "actor",
        "reason",
        "authorized_at",
    ]
    assert tables == {
        "schema_metadata",
        "runs",
        "events",
        "leases",
        "lease_generations",
        "circuit_breaker",
        "circuit_breaker_events",
        "publication_reservations",
        "manifest_artifact_sync",
        "candidate_retry_authorizations",
        "repository_policies",
        "holds",
    }


def test_candidate_history_lookup_uses_nocase_revision_index(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = _candidate_run(store, status=RunStatus.SKIPPED)
    assert run.candidate is not None

    with sqlite3.connect(store.database_path) as connection:
        plan = connection.execute(
            """
            EXPLAIN QUERY PLAN
            SELECT run_id, status, repository, issue_number, issue_revision, manifest_json
            FROM runs
            WHERE run_id <> ? AND repository = ? COLLATE NOCASE
                AND issue_number = ?
            ORDER BY run_id ASC LIMIT ?
            """,
            ("other-run", run.candidate.repository.upper(), run.candidate.number, 10_001),
        ).fetchall()

    assert any("USING INDEX runs_candidate_revision_idx" in row[3] for row in plan)
    disposition = store.candidate_attempt_disposition(
        run.candidate.model_copy(update={"repository": run.candidate.repository.upper()})
    )
    assert disposition.state is CandidateAttemptState.SUPPRESSED
    assert disposition.prior_run_id == run.run_id


def test_save_persists_issue_revision_and_rejects_candidate_evidence_replacement(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    run = _candidate_run(store)
    assert run.candidate is not None
    first_revision = compute_issue_revision(run.candidate)

    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            """
            SELECT repository, issue_number, issue_revision FROM runs
            WHERE run_id = ?
            """,
            (run.run_id,),
        ).fetchone() == (run.candidate.repository, run.candidate.number, first_revision)

    run.candidate = run.candidate.model_copy(
        update={"score": 99, "score_evidence": {"ranking": "refreshed"}}
    )
    store.save(run, event="test.candidate.reranked", details={})
    assert compute_issue_revision(run.candidate) == first_revision
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT issue_revision FROM runs WHERE run_id = ?",
            (run.run_id,),
        ).fetchone() == (first_revision,)
    reopened_after_reranking = RunStore(store.root)
    reranked = reopened_after_reranking.get(run.run_id)
    assert reranked.candidate is not None
    assert reranked.candidate.score == 99
    assert reranked.candidate.score_evidence == {"ranking": "refreshed"}

    run.candidate = run.candidate.model_copy(update={"title": "Fix the exact parser bug"})
    replacement_revision = compute_issue_revision(run.candidate)

    assert replacement_revision != first_revision
    with pytest.raises(StateError, match="candidate evidence changed after selection"):
        store.save(run, event="test.candidate.replaced", details={})
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT issue_revision FROM runs WHERE run_id = ?",
            (run.run_id,),
        ).fetchone() == (first_revision,)
    persisted = store.get(run.run_id)
    assert persisted.candidate is not None
    assert persisted.candidate.title == "Fix the exact bug"
    assert persisted.candidate.score == 99


@pytest.mark.parametrize(
    "status",
    (
        RunStatus.FAILED,
        RunStatus.SKIPPED,
        RunStatus.REJECTED,
        RunStatus.CANCELLED,
    ),
)
def test_save_cannot_attach_first_candidate_in_released_status(
    tmp_path: Path,
    status: RunStatus,
) -> None:
    store = RunStore(tmp_path / status.value)
    run = store.create_run()
    original_updated_at = run.updated_at
    original_events = store.events(run.run_id)
    run.candidate = _issue_candidate()
    run.status = status

    with pytest.raises(StateError, match="must be persisted through claim_candidate"):
        store.save(
            run,
            event="test.direct_candidate_attachment",
            details={"status": status.value},
        )

    assert run.updated_at == original_updated_at
    persisted = store.get(run.run_id)
    assert persisted.status is RunStatus.QUEUED
    assert persisted.candidate is None
    assert store.events(run.run_id) == original_events
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            """
            SELECT repository, issue_number, issue_revision, updated_at
            FROM runs WHERE run_id = ?
            """,
            (run.run_id,),
        ).fetchone() == (None, None, None, original_updated_at.isoformat())
        assert connection.execute(
            """
            SELECT count(*) FROM events
            WHERE run_id = ? AND event_type = 'test.direct_candidate_attachment'
            """,
            (run.run_id,),
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT count(*) FROM manifest_artifact_sync WHERE run_id = ?",
            (run.run_id,),
        ).fetchone() == (0,)


def test_pr_open_transition_and_save_reject_semantic_candidate_mutation(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    run = _publication_run(store)
    _begin_publication(store, run)
    original_candidate = run.candidate
    assert original_candidate is not None
    original_updated_at = run.updated_at
    run.candidate = original_candidate.model_copy(
        update={"title": "Semantically tampered issue title"}
    )

    with pytest.raises(StateError, match="candidate evidence changed after selection"):
        store.transition(run, RunStatus.PR_OPEN, reason="pull request created")

    assert run.status is RunStatus.SUBMITTING
    assert run.updated_at == original_updated_at
    assert store.get(run.run_id).candidate == original_candidate

    run.candidate = original_candidate
    store.transition(run, RunStatus.PR_OPEN, reason="pull request created")
    pr_open_updated_at = run.updated_at
    run.candidate = original_candidate.model_copy(
        update={"body": "Semantically tampered issue body"}
    )
    with pytest.raises(StateError, match="candidate evidence changed after selection"):
        store.save(run, event="test.pr_open.candidate_tampered", details={})

    assert run.status is RunStatus.PR_OPEN
    assert run.updated_at == pr_open_updated_at
    run.candidate = original_candidate
    store.save(run, event="test.pr_open.candidate_unchanged", details={})

    reopened = RunStore(root)
    persisted = reopened.get(run.run_id)
    assert persisted.status is RunStatus.PR_OPEN
    assert persisted.candidate == original_candidate
    reopened.verify_event_chains(run_id=run.run_id)


@pytest.mark.parametrize("tamper", ("revision", "manifest"))
def test_reopen_rejects_issue_revision_tampering(
    tmp_path: Path,
    tamper: str,
) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    run = _candidate_run(store)
    with closing(sqlite3.connect(store.database_path)) as connection:
        if tamper == "revision":
            connection.execute(
                "UPDATE runs SET issue_revision = ? WHERE run_id = ?",
                ("f" * 64, run.run_id),
            )
        else:
            row = connection.execute(
                "SELECT manifest_json FROM runs WHERE run_id = ?",
                (run.run_id,),
            ).fetchone()
            payload = json.loads(row[0])
            payload["candidate"]["title"] = "Tampered title"
            connection.execute(
                "UPDATE runs SET manifest_json = ? WHERE run_id = ?",
                (json.dumps(payload, separators=(",", ":")), run.run_id),
            )
        connection.commit()

    with pytest.raises(StateError, match="issue revision"):
        RunStore(root)


@pytest.mark.parametrize(
    ("tamper", "message"),
    (
        ("authorization", "override disagrees with its authorization"),
        ("malformed_authorization", "authorization has an invalid identity"),
        ("authorization_time", "mismatched authorization time"),
        ("override", "override disagrees with its authorization"),
        ("orphan_authorization", "exactly one candidate retry override event"),
        ("orphan_override", "lacks durable authorization"),
    ),
)
def test_reopen_rejects_tampered_or_orphaned_candidate_retry_evidence(
    tmp_path: Path,
    tamper: str,
    message: str,
) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    candidate = _issue_candidate()
    _candidate_run(store, candidate=candidate, status=RunStatus.REJECTED)
    retry = store.create_run()
    _set_status(store, retry, RunStatus.DISCOVERING)
    retry.candidate = candidate.model_copy(deep=True)
    lease = store.acquire_lease(
        "autocontribute.run",
        "reopen-retry-worker",
        ttl=timedelta(minutes=5),
    )
    assert lease is not None
    try:
        store.claim_candidate(
            retry,
            lease=lease,
            retry_authorization=CandidateRetryAuthorization(
                actor="octocat",
                reason="Retry authorized for integrity testing.",
            ),
        )
    finally:
        assert store.release_lease(lease.name, lease.owner, lease.generation)

    with closing(sqlite3.connect(store.database_path)) as connection:
        if tamper == "authorization":
            connection.execute(
                """
                UPDATE candidate_retry_authorizations SET actor = 'mallory'
                WHERE run_id = ?
                """,
                (retry.run_id,),
            )
        elif tamper == "malformed_authorization":
            connection.execute(
                """
                UPDATE candidate_retry_authorizations
                SET repository = 'invalid-without-slash'
                WHERE run_id = ?
                """,
                (retry.run_id,),
            )
        elif tamper == "authorization_time":
            connection.execute(
                """
                UPDATE candidate_retry_authorizations
                SET authorized_at = '2999-01-01T00:00:00+00:00'
                WHERE run_id = ?
                """,
                (retry.run_id,),
            )
        elif tamper == "override":
            event = next(
                event
                for event in store.events(retry.run_id)
                if event["event_type"] == "candidate.retry_override"
            )
            details = json.loads(event["details"])
            details["reason"] = "Tampered override reason."
            _rewrite_tail_event_details(
                connection,
                run_id=retry.run_id,
                event_type="candidate.retry_override",
                details=details,
            )
        elif tamper == "orphan_authorization":
            _delete_tail_event(
                connection,
                run_id=retry.run_id,
                event_type="candidate.retry_override",
            )
        else:
            connection.execute(
                "DELETE FROM candidate_retry_authorizations WHERE run_id = ?",
                (retry.run_id,),
            )
        connection.commit()

    with pytest.raises(StateError, match=message):
        RunStore(root)


def test_reopen_rejects_semantically_tampered_candidate_selection(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    run = _candidate_run(store, status=RunStatus.DISCOVERING)
    event = next(
        event for event in store.events(run.run_id) if event["event_type"] == "candidate.selected"
    )
    details = json.loads(event["details"])
    details["issue"] = "example/other#999"
    with closing(sqlite3.connect(store.database_path)) as connection:
        _rewrite_tail_event_details(
            connection,
            run_id=run.run_id,
            event_type="candidate.selected",
            details=details,
        )
        connection.commit()

    with pytest.raises(StateError, match="candidate selection disagrees"):
        RunStore(root)


def test_reopen_rejects_candidate_without_selection_provenance(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    run = _candidate_run(store, status=RunStatus.DISCOVERING)
    with closing(sqlite3.connect(store.database_path)) as connection:
        _delete_tail_event(
            connection,
            run_id=run.run_id,
            event_type="candidate.selected",
        )
        connection.commit()

    with pytest.raises(StateError, match="candidate evidence without selection provenance"):
        RunStore(root)


def test_future_older_or_malformed_schema_fails_closed(tmp_path: Path) -> None:
    newer_root = tmp_path / "v99"
    store = RunStore(newer_root)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute("UPDATE schema_metadata SET schema_version = 99 WHERE singleton = 1")
    with pytest.raises(StateError, match="newer than supported"):
        RunStore(newer_root)

    unversioned_root = tmp_path / "unversioned"
    store = RunStore(unversioned_root)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute("DROP TABLE schema_metadata")
    with pytest.raises(StateError, match="lacks schema metadata"):
        RunStore(unversioned_root)

    malformed_root = tmp_path / "malformed"
    store = RunStore(malformed_root)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute("DROP INDEX events_run_idx")
    with pytest.raises(StateError, match="required indexes"):
        RunStore(malformed_root)


@pytest.mark.parametrize("schema_version", (7, 8))
def test_older_development_state_asks_for_a_fresh_state_directory(
    tmp_path: Path,
    schema_version: int,
) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    run = store.create_run()
    with closing(sqlite3.connect(store.database_path)) as connection, connection:
        connection.execute(
            "UPDATE schema_metadata SET schema_version = ? WHERE singleton = 1",
            (schema_version,),
        )

    with pytest.raises(StateError) as error:
        RunStore(root)

    message = str(error.value)
    assert f"older development version of Autocontribute (schema {schema_version})" in message
    assert f"delete the state directory {root.resolve()}" in message
    with closing(sqlite3.connect(store.database_path)) as connection:
        assert connection.execute("SELECT schema_version FROM schema_metadata").fetchone() == (
            schema_version,
        )
        assert connection.execute("SELECT run_id FROM runs").fetchall() == [(run.run_id,)]


def test_reopen_rejects_event_tail_truncation(tmp_path: Path) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    run = store.create_run()
    store.transition(run, RunStatus.DISCOVERING, reason="fixture")
    with closing(sqlite3.connect(store.database_path)) as connection, connection:
        connection.execute(
            "DELETE FROM events WHERE run_id = ? AND event_type = 'run.transitioned'",
            (run.run_id,),
        )

    with pytest.raises(StateError, match="Event ledger anchor mismatch"):
        RunStore(root)


def test_reopen_rejects_trigger_that_can_clear_circuit_breaker(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    store.trip_circuit_breaker(source="security", reason="stop", trigger_hash="danger")
    with closing(sqlite3.connect(store.database_path)) as connection, connection:
        connection.executescript(
            """
            CREATE TRIGGER circuit_breaker_auto_clear
            AFTER UPDATE ON circuit_breaker
            BEGIN
                UPDATE circuit_breaker
                SET is_tripped = 0, source = NULL, reason = NULL, trigger_hash = NULL
                WHERE singleton = 1;
            END;
            UPDATE circuit_breaker SET changed_at = changed_at WHERE singleton = 1;
            """
        )
        assert connection.execute(
            "SELECT is_tripped FROM circuit_breaker WHERE singleton = 1"
        ).fetchone() == (0,)

    with pytest.raises(StateError, match="canonical manifest"):
        RunStore(root)


def test_reopen_preserves_complete_active_breaker_revision(tmp_path: Path) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    store.trip_circuit_breaker(
        source="maintainer",
        reason="stop requested",
        trigger_hash="signal-a",
    )
    store.trip_circuit_breaker(
        source="security",
        reason="secret detected",
        trigger_hash="signal-b",
    )
    expected = store.circuit_breaker_status()

    reopened = RunStore(root).circuit_breaker_status()

    assert reopened.active_revision == expected.active_revision
    assert reopened.active_triggers == expected.active_triggers
    assert reopened.trigger_hash == "signal-b"


def test_reopen_rejects_missing_active_breaker_evidence(tmp_path: Path) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    store.trip_circuit_breaker(
        source="security",
        reason="stop",
        trigger_hash="signal-a",
    )
    with closing(sqlite3.connect(store.database_path)) as connection, connection:
        connection.execute("DELETE FROM circuit_breaker_events WHERE event_type = 'trip'")

    with pytest.raises(StateError, match="disagrees with its active evidence"):
        RunStore(root)


@pytest.mark.parametrize(
    "tamper_sql",
    [
        "CREATE VIEW breaker_state AS SELECT is_tripped FROM circuit_breaker;",
        """
        DROP INDEX runs_status_idx;
        CREATE INDEX runs_status_idx ON runs(updated_at);
        """,
        """
        PRAGMA writable_schema = ON;
        UPDATE sqlite_master
        SET sql = replace(sql, 'CHECK(epoch >= 1)', 'CHECK(epoch >= 0)')
        WHERE type = 'table' AND name = 'circuit_breaker';
        PRAGMA writable_schema = OFF;
        """,
    ],
    ids=[
        "unexpected-view",
        "altered-index",
        "altered-check-constraint",
    ],
)
def test_reopen_rejects_altered_schema_objects(tmp_path: Path, tamper_sql: str) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    with closing(sqlite3.connect(store.database_path)) as connection, connection:
        connection.executescript(tamper_sql)

    with pytest.raises(StateError, match="canonical manifest"):
        RunStore(root)


def test_open_pull_request_remains_an_active_candidate(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = _candidate_run(store, status=RunStatus.PR_OPEN)
    assert run.candidate is not None

    disposition = store.candidate_attempt_disposition(run.candidate)
    assert disposition.state is CandidateAttemptState.ACTIVE
    assert disposition.prior_run_id == run.run_id
    assert disposition.prior_status is RunStatus.PR_OPEN

    _set_status(store, run, RunStatus.FAILED)
    assert (
        store.candidate_attempt_disposition(run.candidate).state is CandidateAttemptState.AVAILABLE
    )


def test_concurrent_candidate_claims_have_exactly_one_active_winner(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    candidate = _issue_candidate()
    runs = [store.create_run(), store.create_run()]
    for run in runs:
        _set_status(store, run, RunStatus.DISCOVERING)
        run.candidate = candidate.model_copy(deep=True)
    lease = store.acquire_lease(
        "autocontribute.run",
        "concurrent-claim-worker",
        ttl=timedelta(minutes=5),
    )
    assert lease is not None
    barrier = threading.Barrier(2)

    def claim(run: RunManifest) -> CandidateAttemptDisposition | StateError:
        barrier.wait()
        try:
            return store.claim_candidate(run, lease=lease)
        except StateError as exc:
            return exc

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(claim, runs))
    finally:
        assert store.release_lease(lease.name, lease.owner, lease.generation)

    winners = [result for result in results if not isinstance(result, StateError)]
    losers = [result for result in results if isinstance(result, StateError)]
    assert len(winners) == len(losers) == 1
    assert isinstance(winners[0], CandidateAttemptDisposition)
    assert winners[0].state is CandidateAttemptState.AVAILABLE
    assert "already has active run" in str(losers[0])
    with sqlite3.connect(store.database_path) as connection:
        active = connection.execute(
            """
            SELECT run_id FROM runs
            WHERE repository = ? COLLATE NOCASE AND issue_number = ?
                AND status NOT IN ('cancelled', 'failed', 'rejected', 'skipped')
            """,
            (candidate.repository, candidate.number),
        ).fetchall()
        selections = connection.execute(
            "SELECT count(*) FROM events WHERE event_type = 'candidate.selected'"
        ).fetchone()
    assert len(active) == 1
    assert selections == (1,)
    persisted = [store.get(run.run_id) for run in runs]
    assert sum(run.candidate is not None for run in persisted) == 1
    store.verify_event_chains()


def test_candidate_claim_rejects_wrong_and_stale_lease_generations(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = store.create_run()
    _set_status(store, run, RunStatus.DISCOVERING)
    run.candidate = _issue_candidate()
    lease = store.acquire_lease(
        "autocontribute.run",
        "first-claim-worker",
        ttl=timedelta(minutes=5),
    )
    assert lease is not None
    original_updated_at = run.updated_at
    with sqlite3.connect(store.database_path) as connection:
        original_row = connection.execute(
            "SELECT updated_at, manifest_json FROM runs WHERE run_id = ?",
            (run.run_id,),
        ).fetchone()

    with pytest.raises(StateError, match="lease ownership was lost"):
        store.claim_candidate(run, lease=replace(lease, generation=lease.generation + 1))
    assert run.updated_at == original_updated_at
    assert store.get(run.run_id).candidate is None

    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE leases SET expires_at = ? WHERE lease_name = ?",
            (datetime(2000, 1, 1, tzinfo=UTC).isoformat(), lease.name),
        )
    with pytest.raises(StateError, match="lease ownership was lost"):
        store.claim_candidate(run, lease=lease)
    assert run.updated_at == original_updated_at
    assert store.get(run.run_id).candidate is None
    with sqlite3.connect(store.database_path) as connection:
        assert (
            connection.execute(
                "SELECT updated_at, manifest_json FROM runs WHERE run_id = ?",
                (run.run_id,),
            ).fetchone()
            == original_row
        )

    assert store.release_lease(lease.name, lease.owner, lease.generation)
    current = store.acquire_lease(
        "autocontribute.run",
        "second-claim-worker",
        ttl=timedelta(minutes=5),
    )
    assert current is not None
    assert current.generation == lease.generation + 1
    try:
        with pytest.raises(StateError, match="lease ownership was lost"):
            store.claim_candidate(run, lease=lease)
        assert run.updated_at == original_updated_at
        assert store.get(run.run_id).candidate is None

        disposition = store.claim_candidate(run, lease=current)
    finally:
        assert store.release_lease(current.name, current.owner, current.generation)

    assert disposition.state is CandidateAttemptState.AVAILABLE
    assert store.get(run.run_id).candidate == run.candidate


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("repository", " example/project"),
        ("repository", "example /project"),
        ("repository", "Straße/project"),
        ("repository", "./project"),
        ("repository", "../project"),
        ("repository", "example/."),
        ("repository", "example/.."),
        ("number", 0),
        ("number", -1),
    ),
)
def test_candidate_claim_rejects_noncanonical_identity_without_mutation(
    tmp_path: Path,
    field: str,
    value: str | int,
) -> None:
    store = RunStore(tmp_path / "state")
    run = store.create_run()
    _set_status(store, run, RunStatus.DISCOVERING)
    original_updated_at = run.updated_at
    original_events = store.events(run.run_id)
    artifact_path = store.artifact_dir(run.run_id) / "manifest.json"
    original_artifact = artifact_path.read_bytes()
    with sqlite3.connect(store.database_path) as connection:
        original_row = connection.execute(
            """
            SELECT status, repository, issue_number, issue_revision, updated_at,
                   manifest_json, event_count, event_head_hash
            FROM runs WHERE run_id = ?
            """,
            (run.run_id,),
        ).fetchone()
    run.candidate = _issue_candidate().model_copy(update={field: value})
    lease = store.acquire_lease(
        "autocontribute.run",
        f"invalid-identity-{run.run_id}",
        ttl=timedelta(minutes=5),
    )
    assert lease is not None

    try:
        with pytest.raises(StateError, match="canonical issue identity"):
            store.claim_candidate(run, lease=lease)
    finally:
        assert store.release_lease(lease.name, lease.owner, lease.generation)

    assert run.updated_at == original_updated_at
    assert artifact_path.read_bytes() == original_artifact
    assert store.events(run.run_id) == original_events
    persisted = store.get(run.run_id)
    assert persisted.status is RunStatus.DISCOVERING
    assert persisted.candidate is None
    with sqlite3.connect(store.database_path) as connection:
        assert (
            connection.execute(
                """
            SELECT status, repository, issue_number, issue_revision, updated_at,
                   manifest_json, event_count, event_head_hash
            FROM runs WHERE run_id = ?
            """,
                (run.run_id,),
            ).fetchone()
            == original_row
        )
        assert connection.execute(
            "SELECT count(*) FROM candidate_retry_authorizations WHERE run_id = ?",
            (run.run_id,),
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT count(*) FROM manifest_artifact_sync WHERE run_id = ?",
            (run.run_id,),
        ).fetchone() == (0,)


def test_unchanged_suppressed_candidate_claim_requires_atomic_retry_authorization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = RunStore(tmp_path / "state")
    candidate = _issue_candidate()
    prior = _candidate_run(store, candidate=candidate, status=RunStatus.SKIPPED)
    retry = store.create_run()
    _set_status(store, retry, RunStatus.DISCOVERING)
    retry.candidate = candidate.model_copy(deep=True)
    lease = store.acquire_lease(
        "autocontribute.run",
        "authorized-retry-worker",
        ttl=timedelta(minutes=5),
    )
    assert lease is not None
    authorization = CandidateRetryAuthorization(
        actor="octocat",
        reason="Maintainer supplied explicit retry approval.",
    )
    original_append = store._append_event
    try:
        with pytest.raises(StateError, match="requires explicit retry authorization"):
            store.claim_candidate(retry, lease=lease)

        def fail_override_append(*_args: object, **_kwargs: object) -> None:
            raise StateError("injected retry override append failure")

        monkeypatch.setattr(store, "_append_event", fail_override_append)
        with pytest.raises(StateError, match="injected retry override append failure"):
            store.claim_candidate(
                retry,
                lease=lease,
                retry_authorization=authorization,
            )
        monkeypatch.setattr(store, "_append_event", original_append)
        with sqlite3.connect(store.database_path) as connection:
            assert connection.execute(
                "SELECT count(*) FROM candidate_retry_authorizations"
            ).fetchone() == (0,)
            assert connection.execute(
                """
                SELECT repository, issue_number, issue_revision FROM runs
                WHERE run_id = ?
                """,
                (retry.run_id,),
            ).fetchone() == (None, None, None)
            assert connection.execute(
                """
                SELECT count(*) FROM events
                WHERE run_id = ? AND event_type = 'candidate.retry_override'
                """,
                (retry.run_id,),
            ).fetchone() == (0,)

        disposition = store.claim_candidate(
            retry,
            lease=lease,
            retry_authorization=authorization,
        )
    finally:
        monkeypatch.setattr(store, "_append_event", original_append)
        assert store.release_lease(lease.name, lease.owner, lease.generation)

    assert disposition.state is CandidateAttemptState.SUPPRESSED
    assert disposition.prior_run_id == prior.run_id
    assert disposition.prior_status is RunStatus.SKIPPED
    revision = compute_issue_revision(candidate)
    with sqlite3.connect(store.database_path) as connection:
        row = connection.execute(
            """
            SELECT authorization_id, run_id, repository, issue_number, issue_revision,
                   prior_run_id, prior_status, actor, reason, authorized_at
            FROM candidate_retry_authorizations
            """
        ).fetchone()
    assert row is not None
    assert len(row[0]) == 32 and set(row[0]) <= set("0123456789abcdef")
    assert row[1:9] == (
        retry.run_id,
        candidate.repository,
        candidate.number,
        revision,
        prior.run_id,
        RunStatus.SKIPPED.value,
        authorization.actor,
        authorization.reason,
    )
    assert datetime.fromisoformat(row[9]).tzinfo is not None
    override = next(
        event
        for event in store.events(retry.run_id)
        if event["event_type"] == "candidate.retry_override"
    )
    assert json.loads(override["details"]) == {
        "actor": authorization.actor,
        "authorization_id": row[0],
        "issue": candidate.reference,
        "issue_revision": revision,
        "prior_run_id": prior.run_id,
        "prior_status": RunStatus.SKIPPED.value,
        "reason": authorization.reason,
    }
    assert store.get(retry.run_id).candidate == candidate
    store.verify_event_chains()


@pytest.mark.parametrize(
    ("status", "expected_state"),
    (
        (RunStatus.SKIPPED, CandidateAttemptState.SUPPRESSED),
        (RunStatus.REJECTED, CandidateAttemptState.SUPPRESSED),
        (RunStatus.CANCELLED, CandidateAttemptState.SUPPRESSED),
        (RunStatus.FAILED, CandidateAttemptState.AVAILABLE),
    ),
)
def test_candidate_attempt_disposition_applies_terminal_status_policy(
    tmp_path: Path,
    status: RunStatus,
    expected_state: CandidateAttemptState,
) -> None:
    store = RunStore(tmp_path / "state")
    run = _candidate_run(store, status=status)
    assert run.candidate is not None

    disposition = store.candidate_attempt_disposition(run.candidate)

    assert disposition.state is expected_state
    assert disposition.issue_revision == compute_issue_revision(run.candidate)
    if expected_state is CandidateAttemptState.SUPPRESSED:
        assert disposition.prior_run_id == run.run_id
        assert disposition.prior_status is status
    else:
        assert disposition.prior_run_id is None
        assert disposition.prior_status is None


def test_candidate_attempt_disposition_active_attempt_precedes_unchanged_suppression(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    candidate = _issue_candidate()
    _candidate_run(store, candidate=candidate, status=RunStatus.REJECTED)
    changed_candidate = candidate.model_copy(update={"title": "Changed issue evidence"})
    active = _candidate_run(
        store,
        candidate=changed_candidate,
        status=RunStatus.DISCOVERING,
    )

    disposition = store.candidate_attempt_disposition(candidate)

    assert disposition.state is CandidateAttemptState.ACTIVE
    assert disposition.issue_revision == compute_issue_revision(candidate)
    assert disposition.prior_run_id == active.run_id
    assert disposition.prior_status is RunStatus.DISCOVERING


def test_candidate_attempt_disposition_releases_suppression_after_issue_change(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    candidate = _issue_candidate()
    _candidate_run(store, candidate=candidate, status=RunStatus.SKIPPED)
    changed_candidate = candidate.model_copy(
        update={
            "body": "The maintainer added a deterministic reproduction.",
            "updated_at": candidate.updated_at + timedelta(hours=1),
        }
    )

    disposition = store.candidate_attempt_disposition(changed_candidate)

    assert disposition.state is CandidateAttemptState.AVAILABLE
    assert disposition.issue_revision == compute_issue_revision(changed_candidate)
    assert disposition.prior_run_id is None
    assert disposition.prior_status is None


def test_begin_publication_atomically_persists_intent_reservation_and_status(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    run = _publication_run(store)
    previous_updated_at = run.updated_at

    begun = _begin_publication(store, run)

    assert begun is run
    assert run.status == RunStatus.SUBMITTING
    assert run.updated_at > previous_updated_at
    assert run.branch_name == "autocontribute/fix-exact-bug"
    assert run.publication_draft is True
    assert run.publishing_login == "octocat"
    assert run.publishing_api_origin == "https://api.github.com"
    assert run.commit_author_name == run.commit_committer_name == "Octo Cat"
    assert (
        run.commit_author_email == run.commit_committer_email == "octocat@users.noreply.github.com"
    )
    assert store.get(run.run_id) == run
    with sqlite3.connect(store.database_path) as connection:
        durable = connection.execute(
            """
            SELECT runs.status, publication_reservations.repository
            FROM runs
            JOIN publication_reservations USING(run_id)
            WHERE runs.run_id = ?
            """,
            (run.run_id,),
        ).fetchone()
    assert durable == (RunStatus.SUBMITTING.value, "example/project")
    event_types = [event["event_type"] for event in store.events(run.run_id)]
    assert event_types[-3:] == [
        "publication.reserved",
        "run.transitioned",
        "publication.intent.begun",
    ]
    intent = json.loads(store.events(run.run_id)[-1]["details"])
    assert intent["branch"] == run.branch_name
    assert intent["draft"] == "true"


def test_begin_publication_rolls_back_reservation_if_intent_cannot_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = RunStore(tmp_path / "state")
    run = _publication_run(store)
    original_append = store._append_event

    def fail_after_reservation(
        connection: sqlite3.Connection,
        run_id: str,
        event_type: str,
        details: dict[str, str],
    ) -> None:
        original_append(connection, run_id, event_type, details)
        if event_type == "publication.reserved":
            raise RuntimeError("injected failure after reservation")

    monkeypatch.setattr(store, "_append_event", fail_after_reservation)

    with pytest.raises(RuntimeError, match="injected failure"):
        _begin_publication(store, run)

    assert run.status == RunStatus.APPROVED
    assert run.branch_name is None
    assert run.publication_draft is None
    assert store.get(run.run_id).status == RunStatus.APPROVED
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute("SELECT count(*) FROM publication_reservations").fetchone() == (
            0,
        )
    assert "publication.reserved" not in {event["event_type"] for event in store.events(run.run_id)}


def test_begin_publication_and_verified_compensation_are_durable(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    run = _publication_run(store)

    _begin_publication(store, run, publication_draft=False)

    assert run.status == RunStatus.SUBMITTING
    assert run.publication_draft is False
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute("SELECT count(*) FROM publication_reservations").fetchone() == (
            1,
        )

    reason = "verified cleanup"
    evidence = _record_absent_compensation_evidence(store, run, reason=reason)
    finalized = store.finalize_publication_compensation(
        run,
        reason=reason,
        evidence=evidence,
    )

    assert finalized.status == RunStatus.FAILED
    assert [event["event_type"] for event in store.events(run.run_id)][-2:] == [
        "publication.compensation.verified",
        "run.transitioned",
    ]


def test_begin_publication_requires_an_approved_run(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = _publication_run(store, status=RunStatus.READY_FOR_APPROVAL)

    with pytest.raises(StateError, match="cannot begin publication from ready_for_approval"):
        _begin_publication(store, run)

    assert store.get(run.run_id).status == RunStatus.READY_FOR_APPROVAL


def test_begin_publication_matching_submitting_retry_is_exactly_idempotent(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    run = _publication_run(store)
    _begin_publication(store, run)
    retry = store.get(run.run_id)
    original_updated_at = retry.updated_at
    original_events = store.events(run.run_id)

    result = _begin_publication(
        store,
        retry,
        max_per_utc_day=1,
        repository_cooldown=timedelta(days=365),
    )

    assert result is retry
    assert retry.updated_at == original_updated_at
    assert store.events(run.run_id) == original_events
    with pytest.raises(StateError, match="differs from durable intent"):
        _begin_publication(store, retry, branch_name="autocontribute/different")
    with pytest.raises(StateError, match="differs from durable intent"):
        _begin_publication(store, retry, publication_draft=False)
    assert store.events(run.run_id) == original_events


def test_begin_publication_recovers_complete_legacy_submitting_intent_but_rejects_missing_fields(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    incomplete = _publication_run(store, status=RunStatus.SUBMITTING)
    with pytest.raises(StateError, match="incomplete durable publication intent"):
        _begin_publication(store, incomplete)
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT count(*) FROM publication_reservations WHERE run_id = ?",
            (incomplete.run_id,),
        ).fetchone() == (0,)

    legacy = _publication_run(store, number=43)
    legacy.branch_name = "autocontribute/fix-exact-bug"
    legacy.publication_draft = True
    legacy.publication_ready_for_review = False
    legacy.publishing_login = "octocat"
    legacy.publishing_api_origin = "https://api.github.com"
    legacy.commit_author_name = "Octo Cat"
    legacy.commit_author_email = "octocat@users.noreply.github.com"
    legacy.commit_committer_name = "Octo Cat"
    legacy.commit_committer_email = "octocat@users.noreply.github.com"
    legacy.status = RunStatus.SUBMITTING
    store.save(legacy, event="test.legacy_publication_intent", details={})
    previous_updated_at = legacy.updated_at

    _begin_publication(store, legacy)

    assert legacy.updated_at == previous_updated_at
    event_types = [event["event_type"] for event in store.events(legacy.run_id)]
    assert event_types.count("publication.reserved") == 1
    assert event_types.count("publication.intent.begun") == 1
    assert event_types.count("run.transitioned") == 0


def test_begin_publication_rejects_stale_or_capacity_blocked_manifest_atomically(
    tmp_path: Path,
) -> None:
    stale_store = RunStore(tmp_path / "stale")
    stale = _publication_run(stale_store)
    current = stale_store.get(stale.run_id)
    current.error = "new durable evidence"
    stale_store.save(current, event="test.changed", details={})

    with pytest.raises(StateError, match="changed while publication was beginning"):
        _begin_publication(stale_store, stale)
    with sqlite3.connect(stale_store.database_path) as connection:
        assert connection.execute("SELECT count(*) FROM publication_reservations").fetchone() == (
            0,
        )

    capacity_store = RunStore(tmp_path / "capacity")
    occupied = capacity_store.create_run()
    blocked = _publication_run(capacity_store)
    reserved_at = datetime(2026, 7, 21, 12, tzinfo=UTC)
    capacity_store.reserve_publication(
        occupied.run_id,
        "other/project",
        max_per_utc_day=1,
        repository_cooldown=timedelta(0),
        now=reserved_at,
    )
    with pytest.raises(StateError, match="Daily publication reservation limit"):
        _begin_publication(
            capacity_store,
            blocked,
            max_per_utc_day=1,
            now=reserved_at,
        )
    assert blocked.status == RunStatus.APPROVED
    assert blocked.branch_name is None
    assert capacity_store.get(blocked.run_id).status == RunStatus.APPROVED
    with sqlite3.connect(capacity_store.database_path) as connection:
        assert connection.execute(
            "SELECT count(*) FROM publication_reservations WHERE run_id = ?",
            (blocked.run_id,),
        ).fetchone() == (0,)


def test_begin_publication_reuses_an_existing_same_run_reservation(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    run = _publication_run(store)
    store.reserve_publication(
        run.run_id,
        "example/project",
        max_per_utc_day=100,
        repository_cooldown=timedelta(0),
    )

    _begin_publication(store, run, max_per_utc_day=1)

    assert run.status == RunStatus.SUBMITTING
    event_types = [event["event_type"] for event in store.events(run.run_id)]
    assert event_types.count("publication.reserved") == 1
    assert event_types.count("publication.intent.begun") == 1


def test_publication_reservations_are_idempotent_and_enforce_local_limits(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    first = store.create_run()
    same_day = store.create_run()
    same_repository = store.create_run()
    next_day = store.create_run()
    reserved_at = datetime(2026, 7, 21, 23, 59, tzinfo=UTC)

    reservation = store.reserve_publication(
        first.run_id,
        "Example/Project",
        max_per_utc_day=1,
        repository_cooldown=timedelta(days=7),
        now=reserved_at,
    )

    assert reservation.repository == "example/project"
    assert (
        store.reserve_publication(
            first.run_id,
            "example/project",
            max_per_utc_day=1,
            repository_cooldown=timedelta(days=7),
            now=reserved_at + timedelta(days=30),
        )
        == reservation
    )
    with pytest.raises(StateError, match="different repository"):
        store.reserve_publication(
            first.run_id,
            "other/project",
            max_per_utc_day=1,
            repository_cooldown=timedelta(days=7),
            now=reserved_at,
        )
    with pytest.raises(StateError, match="Daily publication reservation limit"):
        store.reserve_publication(
            same_day.run_id,
            "other/project",
            max_per_utc_day=1,
            repository_cooldown=timedelta(days=7),
            now=reserved_at,
        )
    with pytest.raises(StateError, match="cooldown"):
        store.reserve_publication(
            same_repository.run_id,
            "EXAMPLE/PROJECT",
            max_per_utc_day=1,
            repository_cooldown=timedelta(days=7),
            now=reserved_at + timedelta(minutes=2),
        )

    next_reservation = store.reserve_publication(
        next_day.run_id,
        "other/project",
        max_per_utc_day=1,
        repository_cooldown=timedelta(days=7),
        now=reserved_at + timedelta(minutes=2),
    )
    assert next_reservation.reserved_at.date() != reservation.reserved_at.date()
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute("SELECT count(*) FROM publication_reservations").fetchone() == (
            2,
        )


def test_failed_runs_do_not_release_publication_reservations(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    first = store.create_run()
    second = store.create_run()
    reserved_at = datetime(2026, 7, 21, 12, tzinfo=UTC)
    store.reserve_publication(
        first.run_id,
        "example/project",
        max_per_utc_day=5,
        repository_cooldown=timedelta(days=7),
        now=reserved_at,
    )
    _set_status(store, first, RunStatus.FAILED)

    with pytest.raises(StateError, match="cooldown"):
        store.reserve_publication(
            second.run_id,
            "example/project",
            max_per_utc_day=5,
            repository_cooldown=timedelta(days=7),
            now=reserved_at + timedelta(days=1),
        )


def test_publication_reservation_limit_is_transactional_under_contention(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    runs = [store.create_run(), store.create_run()]
    reserved_at = datetime(2026, 7, 21, 12, tzinfo=UTC)

    def reserve(index: int) -> str:
        try:
            reservation = store.reserve_publication(
                runs[index].run_id,
                f"example/project-{index}",
                max_per_utc_day=1,
                repository_cooldown=timedelta(0),
                now=reserved_at,
            )
        except StateError:
            return "blocked"
        return reservation.run_id

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(reserve, range(2)))

    assert results.count("blocked") == 1
    assert len(set(results) & {run.run_id for run in runs}) == 1
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute("SELECT count(*) FROM publication_reservations").fetchone() == (
            1,
        )


def test_failed_transition_cannot_be_finalized_as_verified_compensation(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    holder = _publication_run(store)
    _begin_publication(store, holder)

    store.transition(holder, RunStatus.FAILED, reason="unverified local failure")

    with pytest.raises(StateError, match="requires a SUBMITTING manifest"):
        store.finalize_publication_compensation(
            holder,
            reason="cannot retroactively verify",
            evidence={"branch": "autocontribute/fix"},
        )


def test_verified_compensation_rejects_arbitrary_evidence_and_remains_submitting(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    holder = _publication_run(store)
    _begin_publication(store, holder)
    holder.upstream_repository_id = 1001
    holder.upstream_repository_node_id = "R_upstream_fixture"
    store.save(
        holder,
        event="test.upstream_identity.bound",
        details={"repository_id": "1001"},
    )

    with pytest.raises(StateError, match="lacks exact remote cleanup evidence"):
        store.finalize_publication_compensation(
            holder,
            reason="caller assertion is not durable proof",
            evidence={"remote_state": "absent"},
        )

    assert holder.status == RunStatus.SUBMITTING
    assert store.get(holder.run_id).status == RunStatus.SUBMITTING


def test_verified_compensation_requires_latest_exact_absence_event(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    holder = _publication_run(store)
    _begin_publication(store, holder)
    reason = "verified exact remote absence"
    evidence = _record_absent_compensation_evidence(store, holder, reason=reason)
    store.save(
        holder,
        event="publication.absence.verified",
        details={
            **evidence,
            "reason": reason,
            "commit_sha": "f" * 40,
        },
    )

    with pytest.raises(StateError, match="latest exact absence verification"):
        store.finalize_publication_compensation(
            holder,
            reason=reason,
            evidence=evidence,
        )

    assert holder.status == RunStatus.SUBMITTING


@pytest.mark.parametrize(
    ("field", "wrong_value"),
    [
        ("publishing_api_origin", "https://github.example.com/api/v3"),
        ("upstream_repository_id", "9999"),
        ("upstream_repository_node_id", "R_reused_upstream_name"),
        ("fork_repository_id", "9998"),
        ("fork_repository_node_id", "R_reused_fork_name"),
    ],
)
def test_absence_compensation_rejects_wrong_origin_or_repository_identity(
    tmp_path: Path,
    field: str,
    wrong_value: str,
) -> None:
    store = RunStore(tmp_path / "state")
    holder = _publication_run(store)
    _begin_publication(store, holder)
    holder.fork_repository_id = 2001
    holder.fork_repository_node_id = "R_fork_fixture"
    reason = "verified exact remote absence"
    evidence = _record_absent_compensation_evidence(store, holder, reason=reason)
    wrong_event = {
        key: value
        for key, value in evidence.items()
        if key not in {"pull_request", "remote_branch"}
    }
    wrong_event["reason"] = reason
    wrong_event[field] = wrong_value
    store.save(
        holder,
        event="publication.absence.verified",
        details=wrong_event,
    )

    with pytest.raises(StateError, match="latest exact absence verification"):
        store.finalize_publication_compensation(
            holder,
            reason=reason,
            evidence=evidence,
        )

    assert holder.status == RunStatus.SUBMITTING


def test_absence_compensation_accepts_exact_bound_fork_identity(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    holder = _publication_run(store)
    _begin_publication(store, holder)
    holder.fork_repository_id = 2001
    holder.fork_repository_node_id = "R_fork_fixture"
    reason = "verified exact remote absence with a bound fork"
    evidence = _record_absent_compensation_evidence(store, holder, reason=reason)

    finalized = store.finalize_publication_compensation(
        holder,
        reason=reason,
        evidence=evidence,
    )

    assert finalized.status == RunStatus.FAILED


def test_absence_compensation_rejects_partial_fork_identity(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    holder = _publication_run(store)
    _begin_publication(store, holder)
    holder.upstream_repository_id = 1001
    holder.upstream_repository_node_id = "R_upstream_fixture"
    holder.fork_repository_id = 2001

    with pytest.raises(StateError, match="partial immutable fork identity"):
        store.finalize_publication_compensation(
            holder,
            reason="partial identity must remain fenced",
            evidence={"remote_state": "absent"},
        )

    assert holder.status == RunStatus.SUBMITTING
    assert store.get(holder.run_id).status == RunStatus.SUBMITTING


@pytest.mark.parametrize("remote_stage", ["stored_commit", "branch_event"])
def test_absence_compensation_rejects_unbound_fork_after_remote_capable_stage(
    tmp_path: Path,
    remote_stage: str,
) -> None:
    store = RunStore(tmp_path / "state")
    holder = _publication_run(store)
    _begin_publication(store, holder)
    if remote_stage == "stored_commit":
        holder.commit_sha = "c" * 40
    else:
        store.save(
            holder,
            event="branch.pushed",
            details={"commit_sha": "c" * 40},
        )
    reason = "unbound fork must remain fenced after remote-capable work"
    evidence = _record_absent_compensation_evidence(store, holder, reason=reason)

    with pytest.raises(StateError, match="unbound fork identity after a remote-capable stage"):
        store.finalize_publication_compensation(
            holder,
            reason=reason,
            evidence=evidence,
        )

    assert holder.status == RunStatus.SUBMITTING
    assert store.get(holder.run_id).status == RunStatus.SUBMITTING


def test_absence_proof_cannot_finalize_an_ambiguous_pull_request_post(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    holder = _publication_run(store)
    _begin_publication(store, holder)
    holder.pull_request_creation_started = True
    store.save(
        holder,
        event="pull_request.creation.started",
        details={"head": f"octocat:{holder.branch_name}"},
    )
    reason = "remote lookup alone cannot resolve a started POST"
    evidence = _record_absent_compensation_evidence(store, holder, reason=reason)

    with pytest.raises(StateError, match="lacks exact remote cleanup evidence"):
        store.finalize_publication_compensation(
            holder,
            reason=reason,
            evidence=evidence,
        )

    assert holder.status == RunStatus.SUBMITTING


def test_verified_compensation_transition_is_atomic(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    holder = _publication_run(store)
    _begin_publication(store, holder)
    current = store.get(holder.run_id)
    current.upstream_repository_id = 1001
    current.upstream_repository_node_id = "R_upstream_fixture"
    current.fork_repository_id = 2001
    current.fork_repository_node_id = "R_fork_fixture"
    current.commit_sha = "1" * 40
    store.save(current, event="publication.identity.persisted", details={"number": "7"})
    stale = store.get(holder.run_id)
    reason = "verified exact remote cleanup"
    evidence = _record_absent_compensation_evidence(store, current, reason=reason)

    with pytest.raises(StateError, match="changed while compensation was finalized"):
        store.finalize_publication_compensation(
            stale,
            reason=reason,
            evidence=evidence,
        )
    assert store.get(holder.run_id).status == RunStatus.SUBMITTING

    finalized = store.finalize_publication_compensation(
        current,
        reason=reason,
        evidence=evidence,
    )

    assert finalized.status == RunStatus.FAILED
    persisted = store.get(holder.run_id)
    assert persisted.branch_name == "autocontribute/fix-exact-bug"
    assert persisted.commit_sha == "1" * 40
    assert persisted.pull_request_url is None
    assert [event["event_type"] for event in store.events(holder.run_id)][-2:] == [
        "publication.compensation.verified",
        "run.transitioned",
    ]


def test_created_pr_compensation_rejects_cleanup_evidence_before_its_marker(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    holder = _publication_run(store)
    _begin_publication(store, holder)
    assert holder.candidate is not None
    assert holder.branch_name is not None
    holder.base_sha = "b" * 40
    holder.commit_sha = "c" * 40
    holder.pull_request_url = "https://github.com/example/project/pull/7"
    holder.pull_request_node_id = "PR_fixture_7"
    holder.upstream_repository_id = 1001
    holder.upstream_repository_node_id = "R_upstream_fixture"
    holder.fork_repository_id = 2001
    holder.fork_repository_node_id = "R_fork_fixture"
    holder.publication_compensation_reason = "created_pr_base_moved"
    store.save(
        holder,
        event="branch.compensated",
        details={
            "fork": "octocat/project",
            "fork_repository_id": str(holder.fork_repository_id),
            "fork_repository_node_id": holder.fork_repository_node_id,
            "branch": holder.branch_name,
            "commit_sha": holder.commit_sha,
        },
    )
    reason = "verified recovery of created-PR base-race compensation"
    evidence = _record_created_pr_compensation_evidence(
        store,
        holder,
        reason=reason,
    )

    with pytest.raises(StateError, match="cleanup evidence precedes its marker"):
        store.finalize_publication_compensation(
            holder,
            reason=reason,
            evidence=evidence,
        )

    assert holder.status == RunStatus.SUBMITTING


def test_created_pr_compensation_rejects_missing_cleanup_evidence(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    holder = _publication_run(store)
    _begin_publication(store, holder)
    reason = "verified recovery of created-PR base-race compensation"
    evidence = _record_created_pr_compensation_evidence(
        store,
        holder,
        reason=reason,
        repetitions=0,
    )

    with pytest.raises(StateError, match="lacks exact pull-request and branch cleanup"):
        store.finalize_publication_compensation(
            holder,
            reason=reason,
            evidence=evidence,
        )

    assert holder.status == RunStatus.SUBMITTING


def test_created_pr_compensation_accepts_identical_crash_retry_evidence(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    holder = _publication_run(store)
    _begin_publication(store, holder)
    reason = "verified recovery of created-PR base-race compensation"
    evidence = _record_created_pr_compensation_evidence(
        store,
        holder,
        reason=reason,
        repetitions=2,
    )

    finalized = store.finalize_publication_compensation(
        holder,
        reason=reason,
        evidence=evidence,
    )

    assert finalized.status == RunStatus.FAILED


def test_created_pr_compensation_rejects_conflicting_retry_evidence(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    holder = _publication_run(store)
    _begin_publication(store, holder)
    reason = "verified recovery of created-PR base-race compensation"
    evidence = _record_created_pr_compensation_evidence(
        store,
        holder,
        reason=reason,
    )
    store.save(
        holder,
        event="pull_request.compensation.closed",
        details={"url": evidence["url"], "state": "open"},
    )
    store.save(
        holder,
        event="branch.compensated",
        details={
            "fork": evidence["fork"],
            "fork_repository_id": evidence["fork_repository_id"],
            "fork_repository_node_id": evidence["fork_repository_node_id"],
            "branch": evidence["branch"],
            "commit_sha": evidence["commit_sha"],
        },
    )

    with pytest.raises(StateError, match="closure differs from durable intent"):
        store.finalize_publication_compensation(
            holder,
            reason=reason,
            evidence=evidence,
        )

    assert holder.status == RunStatus.SUBMITTING


def test_merged_compensation_becomes_lifecycle_managed_after_restart(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    holder = _publication_run(store)
    _begin_publication(store, holder)
    _record_merged_compensation_evidence(store, holder)

    restarted = RunStore(store.root)
    recovered = restarted.get(holder.run_id)
    finalized = restarted.finalize_merged_publication_compensation(
        recovered,
        pull_request_url="https://github.com/example/project/pull/7",
        reason="exact compensating PR merged and is lifecycle-managed",
    )

    assert finalized.status == RunStatus.PR_OPEN
    assert finalized.publication_compensation_reason == "created_pr_base_moved"
    assert finalized.pull_request_url == "https://github.com/example/project/pull/7"
    assert restarted.events(holder.run_id)[-1]["event_type"] == "run.transitioned"
    assert RunStore(store.root).get(holder.run_id).status == RunStatus.PR_OPEN


def test_merged_compensation_requires_exact_remote_evidence_in_same_run(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    holder = _publication_run(store)
    _begin_publication(store, holder)
    holder.base_sha = "b" * 40
    holder.commit_sha = "c" * 40
    holder.pull_request_url = "https://github.com/example/project/pull/7"
    holder.pull_request_node_id = "PR_fixture_7"
    holder.upstream_repository_id = 1001
    holder.upstream_repository_node_id = "R_upstream_fixture"
    holder.fork_repository_id = 2001
    holder.fork_repository_node_id = "R_fork_fixture"
    holder.publication_compensation_reason = "created_pr_base_moved"
    store.save(holder, event="test.unrelated", details={"state": "merged"})

    with pytest.raises(StateError, match="one exact branch, response, rejection"):
        store.finalize_merged_publication_compensation(
            holder,
            pull_request_url=holder.pull_request_url,
            reason="must not adopt a PR without exact remote evidence",
        )

    assert holder.status == RunStatus.SUBMITTING
    assert store.get(holder.run_id).status == RunStatus.SUBMITTING


def test_merged_compensation_requires_latest_remote_reconciliation(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    holder = _publication_run(store)
    _begin_publication(store, holder)
    _record_merged_compensation_evidence(store, holder)
    store.save(
        holder,
        event="test.later_compensation_evidence",
        details={"state": "stale"},
    )

    with pytest.raises(StateError, match="not the latest run evidence"):
        store.finalize_merged_publication_compensation(
            holder,
            pull_request_url="https://github.com/example/project/pull/7",
            reason="stale merged observation must not release the hold",
        )

    assert holder.status == RunStatus.SUBMITTING
    assert store.get(holder.run_id).status == RunStatus.SUBMITTING


def test_merged_compensation_requires_exact_marker_and_durable_pull_request_url(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    holder = _publication_run(store)
    _begin_publication(store, holder)
    holder.pull_request_url = "https://github.com/example/project/pull/7"
    store.save(holder, event="test.pull_request_url", details={"number": "7"})

    with pytest.raises(StateError, match="created-PR base-race marker"):
        store.finalize_merged_publication_compensation(
            holder,
            pull_request_url=holder.pull_request_url,
            reason="must retain exact compensation intent",
        )

    holder.publication_compensation_reason = "created_pr_base_moved"
    store.save(
        holder,
        event="publication.compensation.started",
        details={"reason": "created_pr_base_moved", "url": holder.pull_request_url},
    )
    with pytest.raises(StateError, match="durable pull request URL"):
        store.finalize_merged_publication_compensation(
            holder,
            pull_request_url="https://github.com/example/project/pull/8",
            reason="must retain exact pull request identity",
        )

    assert holder.status == RunStatus.SUBMITTING
    assert store.get(holder.run_id).status == RunStatus.SUBMITTING


def test_recovery_only_fails_safe_in_flight_stages_and_is_idempotent(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    recoverable = store.create_run()
    _set_status(store, recoverable, RunStatus.PLANNING)
    preserved: dict[RunStatus, RunManifest] = {}
    for status in (
        RunStatus.READY_FOR_APPROVAL,
        RunStatus.APPROVED,
        RunStatus.SUBMITTING,
        RunStatus.PR_OPEN,
    ):
        run = store.create_run()
        _set_status(store, run, status)
        preserved[status] = run
    cutoff = datetime.now(UTC) + timedelta(minutes=1)

    recovered = store.recover_stale_runs(
        stale_before=cutoff,
        reason="worker lease expired",
    )

    assert [run.run_id for run in recovered] == [recoverable.run_id]
    loaded = store.get(recoverable.run_id)
    assert loaded.status == RunStatus.FAILED
    assert loaded.error == "worker lease expired"
    assert (
        json.loads(
            (store.artifact_dir(recoverable.run_id) / "manifest.json").read_text(encoding="utf-8")
        )["status"]
        == "failed"
    )
    assert store.events(recoverable.run_id)[-1]["event_type"] == "run.recovered"
    for status, run in preserved.items():
        assert store.get(run.run_id).status == status
    assert store.recover_stale_runs(stale_before=cutoff, reason="again") == []


def _workspace_with_clone(store: RunStore, run: RunManifest) -> Path:
    clone = store.workspace_dir(run.run_id) / "repository"
    clone.mkdir()
    (clone / "README.md").write_text("clone\n", encoding="utf-8")
    return clone


@pytest.mark.parametrize(
    "status",
    [
        RunStatus.SKIPPED,
        RunStatus.REJECTED,
        RunStatus.FAILED,
        RunStatus.CANCELLED,
        RunStatus.PR_OPEN,
    ],
)
def test_finished_run_deletes_its_workspace_but_keeps_its_evidence(
    tmp_path: Path,
    status: RunStatus,
) -> None:
    store = RunStore(tmp_path / "state")
    run = store.create_run()
    _workspace_with_clone(store, run)

    _set_status(store, run, status)

    assert not (store.workspaces_dir / run.run_id).exists()
    assert (store.runs_dir / run.run_id / "manifest.json").is_file()
    assert store.get(run.run_id).status == status


@pytest.mark.parametrize(
    "status",
    [
        RunStatus.IMPLEMENTING,
        RunStatus.READY_FOR_APPROVAL,
        RunStatus.APPROVED,
        RunStatus.SUBMITTING,
    ],
)
def test_unfinished_run_keeps_its_workspace(tmp_path: Path, status: RunStatus) -> None:
    store = RunStore(tmp_path / "state")
    run = store.create_run()
    clone = _workspace_with_clone(store, run)

    _set_status(store, run, status)
    store.remove_finished_workspaces()

    assert (clone / "README.md").is_file()


def test_stale_run_recovery_deletes_the_recovered_workspace(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = store.create_run()
    _set_status(store, run, RunStatus.PLANNING)
    _workspace_with_clone(store, run)

    store.recover_stale_runs(
        stale_before=datetime.now(UTC) + timedelta(minutes=1),
        reason="worker lease expired",
    )

    assert store.get(run.run_id).status == RunStatus.FAILED
    assert not (store.workspaces_dir / run.run_id).exists()


def test_compensation_finalizers_delete_the_finished_workspace(tmp_path: Path) -> None:
    failed_store = RunStore(tmp_path / "failed")
    failed = _publication_run(failed_store)
    _begin_publication(failed_store, failed)
    failed_clone = _workspace_with_clone(failed_store, failed)
    reason = "verified cleanup"
    evidence = _record_absent_compensation_evidence(failed_store, failed, reason=reason)
    assert failed_clone.is_dir()

    failed_store.finalize_publication_compensation(failed, reason=reason, evidence=evidence)

    assert not (failed_store.workspaces_dir / failed.run_id).exists()

    merged_store = RunStore(tmp_path / "merged")
    merged = _publication_run(merged_store)
    _begin_publication(merged_store, merged)
    _workspace_with_clone(merged_store, merged)
    _record_merged_compensation_evidence(merged_store, merged)

    merged_store.finalize_merged_publication_compensation(
        merged_store.get(merged.run_id),
        pull_request_url="https://github.com/example/project/pull/7",
        reason="exact compensating PR merged and is lifecycle-managed",
    )

    assert not (merged_store.workspaces_dir / merged.run_id).exists()


def test_finished_workspace_sweep_deletes_only_leftovers_of_finished_runs(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    finished = store.create_run()
    _set_status(store, finished, RunStatus.FAILED)
    _workspace_with_clone(store, finished)
    waiting = store.create_run()
    _set_status(store, waiting, RunStatus.READY_FOR_APPROVAL)
    waiting_clone = _workspace_with_clone(store, waiting)
    unknown = store.workspaces_dir / "not-a-run"
    unknown.mkdir()

    store.remove_finished_workspaces()

    assert not (store.workspaces_dir / finished.run_id).exists()
    assert (store.runs_dir / finished.run_id / "manifest.json").is_file()
    assert (waiting_clone / "README.md").is_file()
    assert unknown.is_dir()


def test_workspace_cleanup_never_follows_a_symlinked_workspace(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep\n", encoding="utf-8")
    run = store.create_run()
    (store.workspaces_dir / run.run_id).symlink_to(outside, target_is_directory=True)

    _set_status(store, run, RunStatus.FAILED)
    store.remove_finished_workspaces()

    assert (outside / "keep.txt").read_text(encoding="utf-8") == "keep\n"


def test_recovery_rolls_back_all_rows_when_one_manifest_is_invalid(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    first = store.create_run()
    _set_status(store, first, RunStatus.PLANNING)
    second = store.create_run()
    _set_status(store, second, RunStatus.VALIDATING)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE runs SET manifest_json = 'not-json' WHERE run_id = ?", (second.run_id,)
        )

    with pytest.raises(StateError, match="invalid manifest"):
        store.recover_stale_runs(
            stale_before=datetime.now(UTC) + timedelta(minutes=1),
            reason="crash",
        )

    assert store.get(first.run_id).status == RunStatus.PLANNING
    assert store.events(first.run_id)[-1]["event_type"] == "test.status"


def test_fenced_lease_takeover_rejects_stale_owner_and_backward_time(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    started = datetime(2025, 1, 1, tzinfo=UTC)
    first = store.acquire_lease("scheduler", "worker-a", ttl=timedelta(seconds=10), now=started)
    assert first is not None
    assert first.generation == 1
    assert (
        store.acquire_lease("scheduler", "worker-b", ttl=timedelta(seconds=10), now=started) is None
    )

    renewed = store.heartbeat_lease(
        "scheduler",
        "worker-a",
        first.generation,
        ttl=timedelta(seconds=1),
        now=started + timedelta(seconds=2),
    )
    assert renewed is not None
    assert renewed.expires_at == first.expires_at
    assert (
        store.heartbeat_lease(
            "scheduler",
            "worker-a",
            first.generation,
            ttl=timedelta(seconds=20),
            now=started + timedelta(seconds=1),
        )
        is None
    )

    takeover = store.acquire_lease(
        "scheduler",
        "worker-b",
        ttl=timedelta(seconds=10),
        now=first.expires_at,
    )
    assert takeover is not None
    assert takeover.generation == 2
    assert (
        store.heartbeat_lease(
            "scheduler",
            "worker-a",
            first.generation,
            ttl=timedelta(seconds=10),
            now=first.expires_at,
        )
        is None
    )
    assert store.release_lease("scheduler", "worker-a", first.generation) is False
    with pytest.raises(StateError, match="no longer owned"):
        store.assert_lease("scheduler", "worker-a", first.generation, now=first.expires_at)
    assert store.release_lease("scheduler", "worker-b", takeover.generation) is True


def test_clean_lease_reacquisition_advances_generation_and_fences_old_token(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    started = datetime(2025, 1, 1, tzinfo=UTC)
    first = store.acquire_lease("scheduler", "worker-a", ttl=timedelta(minutes=1), now=started)
    assert first is not None
    assert store.release_lease("scheduler", "worker-a", first.generation)

    second = store.acquire_lease(
        "scheduler",
        "worker-a",
        ttl=timedelta(minutes=1),
        now=started + timedelta(seconds=1),
    )

    assert second is not None
    assert second.generation == first.generation + 1
    with pytest.raises(StateError, match="no longer owned"):
        store.assert_lease(
            "scheduler",
            "worker-a",
            first.generation,
            now=started + timedelta(seconds=1),
        )


def test_concurrent_lease_acquisition_has_exactly_one_winner(tmp_path: Path) -> None:
    root = tmp_path / "state"
    RunStore(root)
    started = datetime(2025, 1, 1, tzinfo=UTC)

    def acquire(owner: str) -> bool:
        return (
            RunStore(root).acquire_lease("scheduler", owner, ttl=timedelta(minutes=1), now=started)
            is not None
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(acquire, ("worker-a", "worker-b")))

    assert sorted(results) == [False, True]


def test_heartbeat_guard_releases_its_fenced_lease(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    with LeaseHeartbeatGuard(
        store,
        "scheduler",
        owner="worker-a",
        ttl=timedelta(seconds=10),
        heartbeat_interval=timedelta(seconds=1),
    ) as guard:
        lease = store.get_lease("scheduler")
        assert lease is not None
        assert guard.assert_owned().generation == lease.generation
        assert store.get_lease("scheduler") is not None

    assert store.get_lease("scheduler") is None


def test_heartbeat_guard_surfaces_fencing_takeover(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    guard = LeaseHeartbeatGuard(
        store,
        "scheduler",
        owner="worker-a",
        ttl=timedelta(seconds=10),
        heartbeat_interval=timedelta(seconds=5),
    )

    with pytest.raises(StateError, match="no longer owned"), guard:
        first = guard.assert_owned()
        takeover = store.acquire_lease(
            "scheduler",
            "worker-b",
            ttl=timedelta(seconds=10),
            now=first.expires_at,
        )
        assert takeover is not None and takeover.generation > first.generation
        guard.assert_owned()


def test_open_pull_request_enumeration_never_silently_truncates(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    first = store.create_run()
    second = store.create_run()
    submitting = store.create_run()
    ignored = store.create_run()
    _set_status(store, first, RunStatus.PR_OPEN)
    _set_status(store, second, RunStatus.PR_OPEN)
    _set_status(store, submitting, RunStatus.SUBMITTING)
    _set_status(store, ignored, RunStatus.FAILED)

    assert [run.run_id for run in store.list_open_pull_request_runs(limit=2)] == [
        first.run_id,
        second.run_id,
    ]
    with pytest.raises(StateError, match="exceeds"):
        store.list_open_pull_request_runs(limit=1)
    assert [run.run_id for run in store.list_submitting_runs()] == [submitting.run_id]


def test_deleted_event_tail_cannot_be_replaced_with_a_new_event(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    run = store.create_run()
    store.transition(run, RunStatus.DISCOVERING, reason="fixture")
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            """
            DELETE FROM events
            WHERE run_id = ? AND event_type = 'run.transitioned'
            """,
            (run.run_id,),
        )

    with pytest.raises(StateError, match="Event ledger anchor mismatch"):
        store.save(run, event="test.replacement", details={"digest": "b" * 64})
    with pytest.raises(StateError, match="Event ledger anchor mismatch"):
        store.verify_event_chains(run_id=run.run_id)


def test_circuit_breaker_is_persistent_deduplicated_and_requires_audited_resume(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    assert store.trip_circuit_breaker(
        source="maintainer-comment", reason="stop requested", trigger_hash="signal-a"
    )
    stale_revision = store.circuit_breaker_status().active_revision
    assert stale_revision is not None
    assert not store.trip_circuit_breaker(
        source="maintainer-comment", reason="stop requested", trigger_hash="signal-a"
    )
    with pytest.raises(StateError, match="reused"):
        store.trip_circuit_breaker(
            source="maintainer-comment", reason="different", trigger_hash="signal-a"
        )
    assert store.trip_circuit_breaker(
        source="security", reason="credential signal", trigger_hash="signal-b"
    )

    status = RunStore(root).circuit_breaker_status()
    assert status.is_tripped is True
    assert status.source == "security"
    assert status.trigger_hash == "signal-b"
    assert len(status.active_triggers) == 2
    assert status.active_revision is not None
    assert status.active_revision != stale_revision
    with pytest.raises(StateError, match="Circuit breaker is tripped"):
        store.assert_circuit_breaker_clear()
    with pytest.raises(StateError, match="evidence changed"):
        store.resume_circuit_breaker(
            actor="operator",
            reason="reviewed stale evidence",
            expected_trigger_hash=stale_revision,
        )
    assert store.circuit_breaker_status().trigger_hash == "signal-b"
    assert (
        store.resume_circuit_breaker(
            actor="operator",
            reason="reviewed evidence",
            expected_trigger_hash=status.active_revision,
        )
        is True
    )
    assert (
        store.resume_circuit_breaker(
            actor="operator",
            reason="redundant",
            expected_trigger_hash=status.active_revision,
        )
        is False
    )
    store.assert_circuit_breaker_clear()
    assert store.circuit_breaker_status().epoch == 2

    assert not store.trip_circuit_breaker(
        source="maintainer-comment", reason="stop requested", trigger_hash="signal-a"
    )
    store.assert_circuit_breaker_clear()
    assert store.trip_circuit_breaker(
        source="maintainer-comment", reason="new stop request", trigger_hash="signal-c"
    )
    assert RunStore(root).circuit_breaker_status().is_tripped is True
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute("SELECT count(*) FROM circuit_breaker_events").fetchone() == (4,)
        assert connection.execute(
            "SELECT trigger_hash FROM circuit_breaker_events WHERE event_type = 'resume'"
        ).fetchone() == (status.active_revision,)


def test_concurrent_new_trip_cannot_be_lost_by_resume(tmp_path: Path) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    store.trip_circuit_breaker(source="first", reason="first stop", trigger_hash="signal-a")
    reviewed_revision = store.circuit_breaker_status().active_revision
    assert reviewed_revision is not None
    barrier = threading.Barrier(2)

    def resume() -> bool | StateError:
        barrier.wait()
        try:
            return RunStore(root).resume_circuit_breaker(
                actor="operator",
                reason="reviewed first stop",
                expected_trigger_hash=reviewed_revision,
            )
        except StateError as exc:
            return exc

    def trip() -> bool:
        barrier.wait()
        return RunStore(root).trip_circuit_breaker(
            source="second",
            reason="concurrent stop",
            trigger_hash="signal-b",
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        resume_future = executor.submit(resume)
        trip_future = executor.submit(trip)
        resume_result = resume_future.result()
        assert trip_future.result() is True

    assert resume_result is True or isinstance(resume_result, StateError)
    status = store.circuit_breaker_status()
    assert status.is_tripped
    assert status.source == "second"
    assert status.trigger_hash == "signal-b"


def _hold(
    scope: StopScope,
    key: str,
    trigger_hash: str,
    *,
    reason: str = "maintainer asked to stop",
    expires_at: datetime | None = None,
    maintainer_stop: bool = False,
) -> CircuitBreakerTrigger:
    return CircuitBreakerTrigger(
        source=f"fixture:{key}",
        reason=reason,
        trigger_hash=trigger_hash,
        scope=scope,
        scope_key=key,
        expires_at=expires_at,
        maintainer_stop=maintainer_stop,
    )


def test_scoped_stops_become_holds_and_leave_the_breaker_untouched(tmp_path: Path) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    now = datetime.now(UTC)

    assert store.record_stop(_hold(StopScope.REPOSITORY, "example/project", "hold-a"))
    assert store.record_stop(
        _hold(
            StopScope.PULL_REQUEST,
            "https://github.com/example/project/pull/7",
            "hold-b",
            expires_at=now + timedelta(days=30),
        )
    )
    assert store.record_stop(
        _hold(StopScope.ISSUE, "example/project#42", "hold-c", expires_at=now - timedelta(days=1))
    )
    assert not store.record_stop(_hold(StopScope.REPOSITORY, "example/project", "hold-a"))
    with pytest.raises(StateError, match="reused"):
        store.record_stop(
            _hold(StopScope.REPOSITORY, "example/project", "hold-a", reason="different")
        )

    reopened = RunStore(root)
    assert not reopened.circuit_breaker_status().is_tripped
    assert [hold.trigger_hash for hold in reopened.active_holds()] == ["hold-a", "hold-b"]
    assert [
        hold.trigger_hash for hold in reopened.active_holds(StopScope.REPOSITORY, "Example/Project")
    ] == ["hold-a"]
    assert reopened.active_holds(StopScope.ISSUE) == []
    assert [
        hold.trigger_hash
        for hold in reopened.active_holds(StopScope.ISSUE, now=now - timedelta(days=2))
    ] == ["hold-c"]
    assert reopened.active_holds(now=now + timedelta(days=31))[0].trigger_hash == "hold-a"
    assert len(reopened.active_holds(now=now + timedelta(days=31))) == 1


def test_global_stop_trips_the_breaker_and_rejects_hold_fields(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")

    assert store.record_stop(
        CircuitBreakerTrigger(source="github_api:suspended", reason="suspended", trigger_hash="g")
    )
    assert not store.record_stop(
        CircuitBreakerTrigger(source="github_api:suspended", reason="suspended", trigger_hash="g")
    )
    with pytest.raises(ValueError, match="global stop"):
        store.record_stop(
            CircuitBreakerTrigger(
                source="fixture", reason="fixture", trigger_hash="h", scope_key="example/project"
            )
        )

    assert store.circuit_breaker_status().source == "github_api:suspended"
    assert store.active_holds() == []


@pytest.mark.parametrize(
    ("scope", "key"),
    [
        (StopScope.REPOSITORY, "example"),
        (StopScope.REPOSITORY, " example/project"),
        (StopScope.ISSUE, "example/project"),
        (StopScope.PULL_REQUEST, "example/project#7"),
        (StopScope.PUBLICATION, "api.github.com"),
        (StopScope.RUN, ""),
    ],
)
def test_holds_require_a_canonical_key_for_their_scope(
    tmp_path: Path, scope: StopScope, key: str
) -> None:
    store = RunStore(tmp_path / "state")

    with pytest.raises(ValueError):
        store.record_stop(_hold(scope, key, "hold"))

    assert store.active_holds() == []


def test_released_hold_does_not_return_for_the_same_evidence(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    store.record_stop(_hold(StopScope.REPOSITORY, "example/project", "hold-a"))
    hold = store.active_holds()[0]

    assert store.release_hold(hold.hold_id, actor="operator", reason="reviewed the comment")
    assert not store.release_hold(hold.hold_id, actor="operator", reason="again")
    with pytest.raises(StateError, match="Unknown hold"):
        store.release_hold(hold.hold_id + 1, actor="operator", reason="missing")
    with pytest.raises(ValueError, match="release reason"):
        store.release_hold(hold.hold_id, actor="operator", reason=" ")

    assert not store.record_stop(_hold(StopScope.REPOSITORY, "example/project", "hold-a"))
    assert store.active_holds() == []
    assert store.record_stop(_hold(StopScope.REPOSITORY, "example/project", "hold-edited"))


def test_maintainer_stops_in_a_second_repository_escalate_to_a_global_stop(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    assert store.record_stop(
        _hold(StopScope.REPOSITORY, "example/released", "released", maintainer_stop=True)
    )
    assert store.release_hold(
        store.active_holds(StopScope.REPOSITORY, "example/released")[0].hold_id,
        actor="operator",
        reason="the comment was about a different bot",
    )
    store.record_stop(_hold(StopScope.REPOSITORY, "example/first", "first-a", maintainer_stop=True))
    store.record_stop(_hold(StopScope.REPOSITORY, "example/first", "first-b", maintainer_stop=True))
    store.record_stop(_hold(StopScope.REPOSITORY, "example/closed", "cooldown"))
    assert not store.circuit_breaker_status().is_tripped

    store.record_stop(_hold(StopScope.REPOSITORY, "example/second", "second", maintainer_stop=True))

    status = store.circuit_breaker_status()
    assert status.is_tripped
    assert status.source == "escalation:maintainer_stops"
    assert status.reason == (
        "Maintainers of 2 repositories turned away automated contributions within 30 days, "
        "most recently example/second"
    )
    assert len(store.active_holds(StopScope.REPOSITORY)) == 4


def test_publication_refuses_held_repositories_pull_requests_and_publication(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    pull_request_url = "https://github.com/example/project/pull/7"
    store.record_stop(_hold(StopScope.REPOSITORY, "example/held", "repository"))
    store.record_stop(_hold(StopScope.PULL_REQUEST, pull_request_url, "pull-request"))
    store.record_stop(_hold(StopScope.ISSUE, "example/project#42", "issue"))
    store.record_stop(
        _hold(
            StopScope.REPOSITORY,
            "example/cooled",
            "expired",
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
        )
    )

    store.assert_publication_not_held("example/project")
    store.assert_publication_not_held("example/cooled")
    with pytest.raises(PolicyError, match="Publication is held by fixture:example/held"):
        store.assert_publication_not_held("Example/Held")
    with pytest.raises(PolicyError, match="safety release 2"):
        store.assert_publication_not_held("example/project", pull_request_url=pull_request_url)

    store.record_stop(_hold(StopScope.PUBLICATION, "https://api.github.com", "publication"))
    with pytest.raises(PolicyError, match=r"fixture:https://api\.github\.com"):
        store.assert_publication_not_held("example/project")


def test_pr_open_manifest_write_failure_keeps_committed_state_and_repairs_on_reopen(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    run = _publication_run(store)
    _begin_publication(store, run)
    artifact_path = store.artifact_dir(run.run_id) / "manifest.json"

    def fail_manifest_write(_manifest: RunManifest) -> None:
        raise OSError("injected manifest write failure")

    monkeypatch.setattr(store, "_write_manifest", fail_manifest_write)
    with pytest.raises(StateError, match="Could not synchronize manifest artifact"):
        store.transition(run, RunStatus.PR_OPEN, reason="pull request created")

    assert run.status == RunStatus.PR_OPEN
    assert (
        RunManifest.model_validate_json(artifact_path.read_bytes()).status == RunStatus.SUBMITTING
    )
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT status FROM runs WHERE run_id = ?", (run.run_id,)
        ).fetchone() == (RunStatus.PR_OPEN.value,)
        assert connection.execute(
            "SELECT count(*) FROM manifest_artifact_sync WHERE run_id = ?", (run.run_id,)
        ).fetchone() == (1,)

    repaired = RunStore(root)

    assert RunManifest.model_validate_json(artifact_path.read_bytes()) == repaired.get(run.run_id)
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute("SELECT count(*) FROM manifest_artifact_sync").fetchone() == (0,)


def test_candidate_claim_manifest_write_failure_repairs_committed_outbox_on_reopen(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    run = store.create_run()
    _set_status(store, run, RunStatus.DISCOVERING)
    artifact_path = store.artifact_dir(run.run_id) / "manifest.json"
    stale_artifact = artifact_path.read_bytes()
    candidate = _issue_candidate()
    revision = compute_issue_revision(candidate)
    run.candidate = candidate
    lease = store.acquire_lease(
        "autocontribute.run",
        "claim-artifact-failure-worker",
        ttl=timedelta(minutes=5),
    )
    assert lease is not None

    def fail_manifest_write(_manifest: RunManifest) -> None:
        raise OSError("injected candidate manifest write failure")

    monkeypatch.setattr(store, "_write_manifest", fail_manifest_write)
    try:
        with pytest.raises(StateError, match="Could not synchronize manifest artifact"):
            store.claim_candidate(run, lease=lease)
    finally:
        assert store.release_lease(lease.name, lease.owner, lease.generation)

    assert RunManifest.model_validate_json(stale_artifact).candidate is None
    assert artifact_path.read_bytes() == stale_artifact
    committed = store.get(run.run_id)
    assert committed.candidate == candidate
    assert committed.updated_at == run.updated_at
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            """
            SELECT repository, issue_number, issue_revision FROM runs
            WHERE run_id = ?
            """,
            (run.run_id,),
        ).fetchone() == (candidate.repository, candidate.number, revision)
        assert connection.execute(
            """
            SELECT count(*) FROM events
            WHERE run_id = ? AND event_type = 'candidate.selected'
            """,
            (run.run_id,),
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT count(*) FROM manifest_artifact_sync WHERE run_id = ?",
            (run.run_id,),
        ).fetchone() == (1,)

    repaired = RunStore(root)

    repaired_manifest = repaired.get(run.run_id)
    assert repaired_manifest == committed
    assert RunManifest.model_validate_json(artifact_path.read_bytes()) == repaired_manifest
    assert [
        event["event_type"]
        for event in repaired.events(run.run_id)
        if event["event_type"] == "candidate.selected"
    ] == ["candidate.selected"]
    with sqlite3.connect(repaired.database_path) as connection:
        assert connection.execute(
            "SELECT count(*) FROM manifest_artifact_sync WHERE run_id = ?",
            (run.run_id,),
        ).fetchone() == (0,)


def test_compensation_manifest_write_failure_repairs_on_reopen(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    run = _publication_run(store)
    _begin_publication(store, run)
    reason = "verified no remote mutation remains"
    evidence = _record_absent_compensation_evidence(store, run, reason=reason)

    def fail_manifest_write(_manifest: RunManifest) -> None:
        raise OSError("injected manifest write failure")

    monkeypatch.setattr(store, "_write_manifest", fail_manifest_write)
    with pytest.raises(StateError, match="Could not synchronize manifest artifact"):
        store.finalize_publication_compensation(
            run,
            reason=reason,
            evidence=evidence,
        )

    assert run.status == RunStatus.FAILED
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT status FROM runs WHERE run_id = ?", (run.run_id,)
        ).fetchone() == (RunStatus.FAILED.value,)
        assert connection.execute(
            "SELECT count(*) FROM manifest_artifact_sync WHERE run_id = ?", (run.run_id,)
        ).fetchone() == (1,)

    repaired = RunStore(root)

    assert repaired.get(run.run_id).status == RunStatus.FAILED
    assert (
        RunManifest.model_validate_json(
            repaired.artifact_dir(run.run_id).joinpath("manifest.json").read_bytes()
        ).status
        == RunStatus.FAILED
    )
    assert [
        event["event_type"]
        for event in repaired.events(run.run_id)
        if event["event_type"] == "publication.compensation.verified"
    ] == ["publication.compensation.verified"]


def test_stale_manifest_publisher_cannot_overwrite_or_clear_a_newer_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = RunStore(tmp_path / "state")
    run = store.create_run()
    artifact_path = store.artifact_dir(run.run_id) / "manifest.json"
    original_artifact = artifact_path.read_bytes()

    def fail_manifest_write(_manifest: RunManifest) -> None:
        raise OSError("injected manifest write failure")

    original_writer = store._write_manifest
    with monkeypatch.context() as context:
        context.setattr(store, "_write_manifest", fail_manifest_write)
        run.error = "first committed version"
        with pytest.raises(StateError, match="Could not synchronize manifest artifact"):
            store.save(run, event="test.first", details={"version": "first"})
        with sqlite3.connect(store.database_path) as connection:
            first_token = connection.execute(
                """
                SELECT updated_at, manifest_sha256 FROM manifest_artifact_sync
                WHERE run_id = ?
                """,
                (run.run_id,),
            ).fetchone()
        assert first_token is not None

        run.error = "second committed version"
        with pytest.raises(StateError, match="Could not synchronize manifest artifact"):
            store.save(run, event="test.second", details={"version": "second"})

    monkeypatch.setattr(store, "_write_manifest", original_writer)
    with sqlite3.connect(store.database_path) as connection:
        second_token = connection.execute(
            """
            SELECT updated_at, manifest_sha256 FROM manifest_artifact_sync
            WHERE run_id = ?
            """,
            (run.run_id,),
        ).fetchone()
    assert second_token is not None and second_token != first_token

    assert (
        store._synchronize_manifest_artifact(
            run.run_id,
            updated_at=str(first_token[0]),
            manifest_sha256=str(first_token[1]),
        )
        is False
    )
    assert artifact_path.read_bytes() == original_artifact
    with sqlite3.connect(store.database_path) as connection:
        assert (
            connection.execute(
                """
            SELECT updated_at, manifest_sha256 FROM manifest_artifact_sync
            WHERE run_id = ?
            """,
                (run.run_id,),
            ).fetchone()
            == second_token
        )

    assert store.synchronize_manifest_artifacts() == 1
    assert RunManifest.model_validate_json(artifact_path.read_bytes()).error == (
        "second committed version"
    )


def test_missing_publication_reservation_is_reconstructed_without_a_second_event(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    run = store.create_run()
    reserved_at = datetime(2026, 7, 22, 9, tzinfo=UTC)
    store.reserve_publication(
        run.run_id,
        "Example/Project",
        max_per_utc_day=10,
        repository_cooldown=timedelta(0),
        now=reserved_at,
    )
    with sqlite3.connect(store.database_path) as connection:
        connection.execute("DELETE FROM publication_reservations WHERE run_id = ?", (run.run_id,))

    reopened = RunStore(root)
    reservation = reopened.reserve_publication(
        run.run_id,
        "example/project",
        max_per_utc_day=10,
        repository_cooldown=timedelta(0),
        now=reserved_at + timedelta(hours=1),
    )

    assert reservation.repository == "example/project"
    assert reservation.reserved_at == reserved_at
    assert [
        event["event_type"]
        for event in reopened.events(run.run_id)
        if event["event_type"] == "publication.reserved"
    ] == ["publication.reserved"]


def test_publication_reservation_row_mismatch_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    run = store.create_run()
    store.reserve_publication(
        run.run_id,
        "example/project",
        max_per_utc_day=10,
        repository_cooldown=timedelta(0),
    )
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE publication_reservations SET reserved_at = ? WHERE run_id = ?",
            (datetime(2020, 1, 1, tzinfo=UTC).isoformat(), run.run_id),
        )

    with pytest.raises(StateError, match="reservation disagrees with ledger evidence"):
        RunStore(root)


def test_duplicate_publication_evidence_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    run = _publication_run(store)
    _begin_publication(store, run)
    details = next(
        json.loads(event["details"])
        for event in store.events(run.run_id)
        if event["event_type"] == "publication.reserved"
    )
    with store._connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        store._append_event(connection, run.run_id, "publication.reserved", details)

    with pytest.raises(StateError, match="duplicate publication"):
        RunStore(root)


def test_incomplete_publication_evidence_fails_closed_without_reconstruction(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    run = store.create_run()
    with store._connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        store._append_event(
            connection,
            run.run_id,
            "publication.reserved",
            {"repository": "example/project"},
        )

    with pytest.raises(StateError, match="reservation evidence is incomplete"):
        RunStore(root)
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT count(*) FROM publication_reservations WHERE run_id = ?", (run.run_id,)
        ).fetchone() == (0,)


def test_repository_ai_policy_cache_matches_repository_and_policy_digest(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    first = RepositoryAiPolicy(stance="conditional", requires_disclosure=True)
    second = RepositoryAiPolicy(stance="none")

    store.record_repository_ai_policy("example/project", "a" * 64, first)

    assert store.repository_ai_policy("Example/Project", "a" * 64) == first
    assert store.repository_ai_policy("example/project", "b" * 64) is None
    assert store.repository_ai_policy("example/other", "a" * 64) is None

    store.record_repository_ai_policy("example/project", "b" * 64, second)

    assert store.repository_ai_policy("example/project", "a" * 64) is None
    assert store.repository_ai_policy("example/project", "b" * 64) == second


@pytest.mark.parametrize(
    ("repository", "digest"),
    [("not a repository", "a" * 64), ("example/project", "A" * 64), ("example/project", "a")],
)
def test_repository_ai_policy_cache_rejects_malformed_keys(
    tmp_path: Path, repository: str, digest: str
) -> None:
    store = RunStore(tmp_path / "state")

    with pytest.raises(StateError, match="cache keys"):
        store.record_repository_ai_policy(repository, digest, RepositoryAiPolicy(stance="none"))
