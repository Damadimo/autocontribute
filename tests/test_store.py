import hashlib
import json
import os
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from autocontribute.coordination import LeaseHeartbeatGuard
from autocontribute.domain import IssueCandidate, RunManifest, RunStatus
from autocontribute.exceptions import StateError
from autocontribute.github import PullRequestCommit, PullRequestDetails
from autocontribute.issue_revision import compute_issue_revision
from autocontribute.lifecycle import (
    LifecycleHistoryCapability,
    PullRequestLifecycleSnapshot,
    parse_lifecycle_snapshot_json,
)
from autocontribute.store import (
    CURRENT_SCHEMA_VERSION,
    CandidateAttemptDisposition,
    CandidateAttemptState,
    CandidateRetryAuthorization,
    RunStore,
)


def test_required_storage_root_binds_store_to_verified_mount(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    required = tmp_path / "state"
    required.mkdir()
    monkeypatch.setenv("AUTOCONTRIBUTE_REQUIRED_STORAGE_ROOT", os.fspath(required))

    store = RunStore(required)

    assert store.root == required


def test_required_storage_root_rejects_storage_bypass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    required = tmp_path / "bounded"
    required.mkdir()
    monkeypatch.setenv("AUTOCONTRIBUTE_REQUIRED_STORAGE_ROOT", os.fspath(required))

    with pytest.raises(StateError, match="bypasses the required storage root"):
        RunStore(tmp_path / "unbounded")


@pytest.mark.parametrize("required", ("", "relative/state"))
def test_required_storage_root_rejects_invalid_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    required: str,
) -> None:
    monkeypatch.setenv("AUTOCONTRIBUTE_REQUIRED_STORAGE_ROOT", required)

    with pytest.raises(StateError, match="Required storage root"):
        RunStore(tmp_path / "state")


def test_required_workspace_root_binds_storage_to_verified_mount(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    required = state / "workspaces"
    required.mkdir(parents=True)
    monkeypatch.setenv("AUTOCONTRIBUTE_REQUIRED_WORKSPACE_ROOT", os.fspath(required))

    store = RunStore(state)

    assert store.workspaces_dir == required


def test_required_workspace_root_rejects_storage_bypass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    required = tmp_path / "bounded" / "workspaces"
    required.mkdir(parents=True)
    monkeypatch.setenv("AUTOCONTRIBUTE_REQUIRED_WORKSPACE_ROOT", os.fspath(required))

    with pytest.raises(StateError, match="bypasses the required workspace root"):
        RunStore(tmp_path / "unbounded")


@pytest.mark.parametrize("required", ("", "relative/workspaces"))
def test_required_workspace_root_rejects_invalid_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    required: str,
) -> None:
    monkeypatch.setenv("AUTOCONTRIBUTE_REQUIRED_WORKSPACE_ROOT", required)

    with pytest.raises(StateError, match="Required workspace root"):
        RunStore(tmp_path / "state")


def _legacy_database(root: Path) -> RunManifest:
    root.mkdir(parents=True, exist_ok=True)
    now = datetime(2025, 1, 1, tzinfo=UTC)
    run = RunManifest(
        run_id="legacy-run",
        status=RunStatus.QUEUED,
        created_at=now,
        updated_at=now,
    )
    with sqlite3.connect(root / "state.sqlite3") as connection:
        connection.executescript(
            """
            CREATE TABLE runs (
                run_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                repository TEXT,
                issue_number INTEGER,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                manifest_json TEXT NOT NULL
            );
            CREATE INDEX runs_status_idx ON runs(status);
            CREATE INDEX runs_candidate_idx ON runs(repository, issue_number, status);
            CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL REFERENCES runs(run_id),
                occurred_at TEXT NOT NULL,
                event_type TEXT NOT NULL,
                details_json TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL UNIQUE
            );
            CREATE INDEX events_run_idx ON events(run_id, id);
            """
        )
        connection.execute(
            """
            INSERT INTO runs(
                run_id, status, created_at, updated_at, manifest_json
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                run.run_id,
                run.status.value,
                now.isoformat(),
                now.isoformat(),
                run.model_dump_json(),
            ),
        )
        details_json = "{}"
        previous_hash = "0" * 64
        payload = json.dumps(
            {
                "run_id": run.run_id,
                "occurred_at": now.isoformat(),
                "event_type": "run.created",
                "details": details_json,
                "previous_hash": previous_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        event_hash = hashlib.sha256(payload.encode()).hexdigest()
        connection.execute(
            """
            INSERT INTO events(
                run_id, occurred_at, event_type, details_json, previous_hash, event_hash
            ) VALUES (?, ?, 'run.created', '{}', ?, ?)
            """,
            (run.run_id, now.isoformat(), previous_hash, event_hash),
        )
    return run


def _downgrade_current_database_to_v7(database: Path) -> None:
    """Remove the v8 objects, leaving the exact canonical v7 schema behind."""

    connection = sqlite3.connect(database)
    try:
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.executescript(
            """
            DROP TABLE legacy_candidate_retry_overrides;
            DROP TABLE candidate_retry_authorizations;
            DROP INDEX runs_active_candidate_idx;
            DROP INDEX runs_candidate_revision_idx;
            CREATE INDEX runs_candidate_revision_idx
            ON runs(repository, issue_number, issue_revision, status);
            UPDATE schema_metadata SET schema_version = 7 WHERE singleton = 1;
            """
        )
        connection.commit()
    finally:
        connection.close()


def _downgrade_current_database_to_v6(database: Path) -> None:
    """Remove issue revisions from canonical v7, leaving canonical v6 behind."""

    _downgrade_current_database_to_v7(database)
    connection = sqlite3.connect(database)
    try:
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.executescript(
            """
            DROP INDEX runs_candidate_revision_idx;
            ALTER TABLE runs DROP COLUMN issue_revision;
            UPDATE schema_metadata SET schema_version = 6 WHERE singleton = 1;
            """
        )
        connection.commit()
    finally:
        connection.close()


def _downgrade_current_database_to_v5(database: Path) -> None:
    """Remove the v7/v6 fields, leaving the exact canonical v5 schema behind."""

    _downgrade_current_database_to_v6(database)
    connection = sqlite3.connect(database)
    try:
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.executescript(
            """
            ALTER TABLE publication_gate_holds DROP COLUMN outcome_corpus_cursor;
            UPDATE schema_metadata SET schema_version = 5 WHERE singleton = 1;
            """
        )
        connection.commit()
    finally:
        connection.close()


def _downgrade_current_database_to_v4(database: Path) -> None:
    """Remove the v7/v6/v5 objects, leaving the exact canonical v4 schema behind."""

    _downgrade_current_database_to_v5(database)
    connection = sqlite3.connect(database)
    try:
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.executescript(
            """
            DROP TABLE manifest_artifact_sync;
            UPDATE schema_metadata SET schema_version = 4 WHERE singleton = 1;
            """
        )
        connection.commit()
    finally:
        connection.close()


def _downgrade_current_database_to_v3(database: Path) -> None:
    """Remove only the v5/v4 objects, leaving the exact canonical v3 schema behind."""

    _downgrade_current_database_to_v4(database)
    connection = sqlite3.connect(database)
    try:
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.executescript(
            """
            DROP TABLE publication_gate_holds;
            DROP TABLE lease_generations;
            ALTER TABLE runs DROP COLUMN event_head_hash;
            ALTER TABLE runs DROP COLUMN event_count;
            UPDATE schema_metadata SET schema_version = 3 WHERE singleton = 1;
            """
        )
        connection.commit()
    finally:
        connection.close()


def _downgrade_current_database_to_v2(database: Path) -> None:
    """Remove the v4 and v3 objects, leaving the exact canonical v2 schema behind."""

    _downgrade_current_database_to_v3(database)
    connection = sqlite3.connect(database)
    try:
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.executescript(
            """
            DROP INDEX publication_reservations_repository_idx;
            DROP INDEX publication_reservations_reserved_at_idx;
            DROP TABLE publication_reservations;
            UPDATE schema_metadata SET schema_version = 2 WHERE singleton = 1;
            """
        )
        connection.commit()
    finally:
        connection.close()


def _set_status(store: RunStore, run: RunManifest, status: RunStatus) -> None:
    run.status = status
    store.save(run, event="test.status", details={"status": status.value})


def _lifecycle_snapshot(*, head_sha: str = "a" * 40) -> PullRequestLifecycleSnapshot:
    observed_at = datetime(2026, 7, 21, 12, tzinfo=UTC)
    return PullRequestLifecycleSnapshot(
        observed_at=observed_at,
        expected_head_sha="a" * 40,
        pull_request=PullRequestDetails(
            repository="example/project",
            number=7,
            html_url="https://github.com/example/project/pull/7",
            state="open",
            draft=True,
            merged=False,
            updated_at=observed_at,
            merged_at=None,
            closed_at=None,
            merge_commit_sha=None,
            head_sha=head_sha,
            base_sha="b" * 40,
            head_repository="example/project",
            issue_comment_count=0,
            review_comment_count=0,
            commit_count=1,
            title="Fix lifecycle evidence",
            body="",
            base_ref="main",
            head_ref="fix-lifecycle",
            head_label="example:fix-lifecycle",
            node_id="PR_fixture_node_7",
        ),
        commits=(
            PullRequestCommit(
                position=1,
                sha=head_sha,
                node_id=f"C_{head_sha}",
                parent_shas=("b" * 40,),
            ),
        ),
        reviews=(),
        issue_comments=(),
        review_comments=(),
        check_runs=(),
        commit_statuses=(),
        timeline_item_count=0,
        timeline_events=(),
        references=(),
    )


def _legacy_lifecycle_snapshot_json(*, include_pull_request_node_id: bool = True) -> str:
    payload = json.loads(_lifecycle_snapshot().to_json())
    del payload["commits"]
    del payload["evidence_version"]
    del payload["timeline_events"]
    del payload["timeline_item_count"]
    del payload["pull_request"]["commit_count"]
    if not include_pull_request_node_id:
        del payload["pull_request"]["node_id"]
    for reference in payload["references"]:
        del reference["node_id"]
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _append_lifecycle_snapshot_event(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    fingerprint: str,
) -> None:
    previous = connection.execute(
        """
        SELECT event_count, event_head_hash FROM runs WHERE run_id = ?
        """,
        (run_id,),
    ).fetchone()
    assert previous is not None
    occurred_at = datetime(2026, 7, 22, 12, tzinfo=UTC).isoformat()
    details_json = json.dumps(
        {"fingerprint": fingerprint},
        sort_keys=True,
        separators=(",", ":"),
    )
    payload = json.dumps(
        {
            "run_id": run_id,
            "occurred_at": occurred_at,
            "event_type": "lifecycle.snapshot.recorded",
            "details": details_json,
            "previous_hash": previous[1],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    event_hash = hashlib.sha256(payload.encode()).hexdigest()
    connection.execute(
        """
        INSERT INTO events(
            run_id, occurred_at, event_type, details_json, previous_hash, event_hash
        ) VALUES (?, ?, 'lifecycle.snapshot.recorded', ?, ?, ?)
        """,
        (run_id, occurred_at, details_json, previous[1], event_hash),
    )
    connection.execute(
        """
        UPDATE runs SET event_count = ?, event_head_hash = ? WHERE run_id = ?
        """,
        (previous[0] + 1, event_hash, run_id),
    )


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


def _historical_v7_candidate_retry_database(
    root: Path,
) -> tuple[RunManifest, RunManifest, int, str]:
    """Create canonical v7 state containing its historical four-field retry event."""

    store = RunStore(root)
    candidate = _issue_candidate()
    prior = _candidate_run(store, candidate=candidate, status=RunStatus.REJECTED)
    retry = store.create_run()
    _set_status(store, retry, RunStatus.DISCOVERING)
    retry.candidate = candidate.model_copy(deep=True)
    lease = store.acquire_lease(
        "autocontribute.run",
        f"legacy-retry-fixture-{retry.run_id}",
        ttl=timedelta(minutes=5),
    )
    assert lease is not None
    try:
        store.claim_candidate(
            retry,
            lease=lease,
            retry_authorization=CandidateRetryAuthorization(
                actor="historical-operator",
                reason="Authorization was not durably structured before schema v8.",
            ),
        )
    finally:
        assert store.release_lease(lease.name, lease.owner, lease.generation)

    revision = compute_issue_revision(candidate)
    with closing(sqlite3.connect(store.database_path)) as connection:
        connection.execute("PRAGMA journal_mode = DELETE")
        _rewrite_tail_event_details(
            connection,
            run_id=retry.run_id,
            event_type="candidate.retry_override",
            details={
                "issue": candidate.reference,
                "issue_revision": revision,
                "prior_run_id": prior.run_id,
                "prior_status": prior.status.value,
            },
        )
        event = connection.execute(
            """
            SELECT id, event_hash FROM events
            WHERE run_id = ? AND event_type = 'candidate.retry_override'
            """,
            (retry.run_id,),
        ).fetchone()
        assert event is not None
        event_id, event_hash = event
        connection.commit()

    _downgrade_current_database_to_v7(store.database_path)
    return prior, retry, event_id, event_hash


def _reserve_gate(
    store: RunStore,
    run: RunManifest,
    *,
    cursor: str | None = None,
    fingerprint: str = "d" * 64,
) -> None:
    run.publishing_login = "octocat"
    run.publishing_api_origin = "https://api.github.com"
    store.save(run, event="test.publication_context", details={})
    outcome_cursor = store.upstream_outcome_corpus_cursor(
        fingerprint,
        "octocat",
        "https://api.github.com",
        exclude_run_id=run.run_id,
    )
    store.reserve_publication(
        run.run_id,
        "example/project",
        max_per_utc_day=100,
        repository_cooldown=timedelta(0),
        evaluation_corpus_cursor=cursor or store.evaluation_corpus_cursor(),
        evaluation_deployment_fingerprint=fingerprint,
        outcome_corpus_cursor=outcome_cursor,
        publishing_login="octocat",
        publishing_api_origin="https://api.github.com",
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
    run = store.create_run(deployment_fingerprint="d" * 64)
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
    with_gate: bool = True,
    max_per_utc_day: int = 100,
    repository_cooldown: timedelta = timedelta(0),
    now: datetime | None = None,
) -> RunManifest:
    cursor = store.evaluation_corpus_cursor() if with_gate else None
    outcome_cursor = (
        store.upstream_outcome_corpus_cursor(
            "d" * 64,
            "octocat",
            "https://api.github.com",
            exclude_run_id=run.run_id,
        )
        if with_gate
        else None
    )
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
        evaluation_corpus_cursor=cursor,
        evaluation_deployment_fingerprint="d" * 64 if with_gate else None,
        outcome_corpus_cursor=outcome_cursor,
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

    store.transition(published, RunStatus.SUBMITTING, reason="publication reserved")
    published.branch_name = "autocontribute/fix"
    published.commit_sha = "a" * 40
    published.pull_request_url = "https://github.com/example/project/pull/1"
    store.transition(published, RunStatus.PR_OPEN, reason="pull request created")

    with pytest.raises(StateError, match="changed while this manifest was being saved"):
        store.transition(stale, RunStatus.APPROVED, reason="stale operator approval")

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


def test_fresh_database_has_current_version_and_all_v8_tables(tmp_path: Path) -> None:
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
        legacy_override_columns = [
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(legacy_candidate_retry_overrides)"
            ).fetchall()
        ]

    assert store.schema_version == CURRENT_SCHEMA_VERSION == 8
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
    assert legacy_override_columns == [
        "event_id",
        "run_id",
        "event_hash",
        "migrated_at",
    ]
    assert tables == {
        "schema_metadata",
        "runs",
        "events",
        "leases",
        "lease_generations",
        "lifecycle_snapshots",
        "circuit_breaker",
        "circuit_breaker_events",
        "publication_reservations",
        "publication_gate_holds",
        "manifest_artifact_sync",
        "candidate_retry_authorizations",
        "legacy_candidate_retry_overrides",
    }


def test_legacy_database_migrates_transactionally_without_losing_data(tmp_path: Path) -> None:
    root = tmp_path / "state"
    legacy = _legacy_database(root)

    store = RunStore(root)

    assert store.schema_version == CURRENT_SCHEMA_VERSION == 8
    assert store.get(legacy.run_id) == legacy
    assert len(store.events(legacy.run_id)) == 1
    assert store.circuit_breaker_status().is_tripped is False
    store.verify_event_chains()


def test_v7_migration_preserves_rows_and_installs_fenced_candidate_claim_schema(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    candidate_run = _candidate_run(store, status=RunStatus.SKIPPED)
    ordinary_run = store.create_run()
    with closing(sqlite3.connect(store.database_path)) as connection:
        expected_runs = connection.execute(
            """
            SELECT run_id, status, repository, issue_number, issue_revision,
                   created_at, updated_at, manifest_json, event_count, event_head_hash
            FROM runs ORDER BY run_id
            """
        ).fetchall()
        expected_events = connection.execute(
            """
            SELECT id, run_id, occurred_at, event_type, details_json,
                   previous_hash, event_hash
            FROM events ORDER BY id
            """
        ).fetchall()
    _downgrade_current_database_to_v7(store.database_path)

    with closing(sqlite3.connect(store.database_path)) as connection:
        assert connection.execute(
            "SELECT schema_version FROM schema_metadata WHERE singleton = 1"
        ).fetchone() == (7,)
        assert connection.execute(
            """
            SELECT count(*) FROM sqlite_master
            WHERE name IN (
                'candidate_retry_authorizations',
                'legacy_candidate_retry_overrides',
                'runs_active_candidate_idx'
            )
            """
        ).fetchone() == (0,)
        assert [
            row[4]
            for row in connection.execute(
                "PRAGMA index_xinfo(runs_candidate_revision_idx)"
            ).fetchall()
            if row[5]
        ] == ["BINARY", "BINARY", "BINARY", "BINARY"]

    migrated = RunStore(root)

    assert migrated.schema_version == CURRENT_SCHEMA_VERSION == 8
    assert migrated.get(candidate_run.run_id) == candidate_run
    assert migrated.get(ordinary_run.run_id) == ordinary_run
    with sqlite3.connect(migrated.database_path) as connection:
        assert (
            connection.execute(
                """
            SELECT run_id, status, repository, issue_number, issue_revision,
                   created_at, updated_at, manifest_json, event_count, event_head_hash
            FROM runs ORDER BY run_id
            """
            ).fetchall()
            == expected_runs
        )
        assert (
            connection.execute(
                """
            SELECT id, run_id, occurred_at, event_type, details_json,
                   previous_hash, event_hash
            FROM events ORDER BY id
            """
            ).fetchall()
            == expected_events
        )
        assert [
            row[4]
            for row in connection.execute(
                "PRAGMA index_xinfo(runs_candidate_revision_idx)"
            ).fetchall()
            if row[5]
        ] == ["NOCASE", "BINARY", "BINARY", "BINARY"]
        indexes = {row[1]: row for row in connection.execute("PRAGMA index_list(runs)").fetchall()}
        assert indexes["runs_active_candidate_idx"][2] == 1
        assert indexes["runs_active_candidate_idx"][4] == 1
        assert connection.execute(
            "SELECT count(*) FROM candidate_retry_authorizations"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT count(*) FROM legacy_candidate_retry_overrides"
        ).fetchone() == (0,)


def test_v7_migration_marks_historical_retry_override_and_restores_it(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    prior, retry, event_id, event_hash = _historical_v7_candidate_retry_database(root)

    migrated = RunStore(root)

    assert migrated.schema_version == CURRENT_SCHEMA_VERSION == 8
    assert migrated.get(prior.run_id) == prior
    assert migrated.get(retry.run_id) == retry
    with sqlite3.connect(migrated.database_path) as connection:
        marker = connection.execute(
            """
            SELECT event_id, run_id, event_hash, migrated_at
            FROM legacy_candidate_retry_overrides
            """
        ).fetchone()
        authorization_count = connection.execute(
            "SELECT count(*) FROM candidate_retry_authorizations"
        ).fetchone()
    assert marker is not None
    assert marker[:3] == (event_id, retry.run_id, event_hash)
    assert datetime.fromisoformat(marker[3]).tzinfo is not None
    assert authorization_count == (0,)
    migrated.verify_event_chains()

    snapshot = migrated.create_snapshot(tmp_path / "backup" / "state.sqlite3")
    restored_root = tmp_path / "restored"
    assert RunStore.restore_snapshot(restored_root, snapshot) == restored_root / "state.sqlite3"
    restored = RunStore(restored_root)

    assert restored.get(prior.run_id) == prior
    assert restored.get(retry.run_id) == retry
    restored.verify_event_chains()


@pytest.mark.parametrize(
    "tamper",
    ("issue", "revision", "prior_run", "prior_status"),
)
def test_v7_migration_rejects_tampered_historical_retry_override_transactionally(
    tmp_path: Path,
    tamper: str,
) -> None:
    root = tmp_path / "state"
    _, retry, _, _ = _historical_v7_candidate_retry_database(root)
    with closing(sqlite3.connect(root / "state.sqlite3")) as connection:
        event = connection.execute(
            """
            SELECT details_json FROM events
            WHERE run_id = ? AND event_type = 'candidate.retry_override'
            """,
            (retry.run_id,),
        ).fetchone()
        assert event is not None
        details = json.loads(event[0])
        if tamper == "issue":
            details["issue"] = "example/other#999"
        elif tamper == "revision":
            details["issue_revision"] = "f" * 64
        elif tamper == "prior_run":
            details["prior_run_id"] = retry.run_id
        else:
            details["prior_status"] = RunStatus.SKIPPED.value
        _rewrite_tail_event_details(
            connection,
            run_id=retry.run_id,
            event_type="candidate.retry_override",
            details=details,
        )
        connection.commit()

    with pytest.raises(StateError, match="legacy candidate retry override"):
        RunStore(root)

    with sqlite3.connect(root / "state.sqlite3") as connection:
        assert connection.execute(
            "SELECT schema_version FROM schema_metadata WHERE singleton = 1"
        ).fetchone() == (7,)
        assert connection.execute(
            """
            SELECT count(*) FROM sqlite_master
            WHERE name IN (
                'candidate_retry_authorizations',
                'legacy_candidate_retry_overrides',
                'runs_active_candidate_idx'
            )
            """
        ).fetchone() == (0,)
        assert RunStore._schema_manifest(connection) == RunStore._expected_schema_manifest(7)


def test_v6_migration_backfills_issue_revision_and_accepts_publication_only_identity(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    candidate_run = _candidate_run(store, status=RunStatus.SKIPPED)
    assert candidate_run.candidate is not None
    expected_revision = compute_issue_revision(candidate_run.candidate)
    publication_only = store.create_run()
    with closing(sqlite3.connect(store.database_path)) as connection:
        connection.execute(
            "UPDATE runs SET repository = ? WHERE run_id = ?",
            ("example/publication", publication_only.run_id),
        )
        connection.commit()
    _downgrade_current_database_to_v6(store.database_path)

    migrated = RunStore(root)

    assert migrated.schema_version == CURRENT_SCHEMA_VERSION == 8
    with sqlite3.connect(migrated.database_path) as connection:
        candidate_row = connection.execute(
            "SELECT issue_revision FROM runs WHERE run_id = ?",
            (candidate_run.run_id,),
        ).fetchone()
        publication_row = connection.execute(
            """
            SELECT repository, issue_number, issue_revision FROM runs
            WHERE run_id = ?
            """,
            (publication_only.run_id,),
        ).fetchone()
    assert candidate_row == (expected_revision,)
    assert publication_row == ("example/publication", None, None)


def test_v6_migration_rejects_malformed_manifest_transactionally(tmp_path: Path) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    run = _candidate_run(store)
    _downgrade_current_database_to_v6(store.database_path)
    with closing(sqlite3.connect(store.database_path)) as connection:
        connection.execute(
            "UPDATE runs SET manifest_json = '{' WHERE run_id = ?",
            (run.run_id,),
        )
        connection.commit()

    with pytest.raises(StateError, match="invalid manifest"):
        RunStore(root)

    with sqlite3.connect(store.database_path) as connection:
        version = connection.execute(
            "SELECT schema_version FROM schema_metadata WHERE singleton = 1"
        ).fetchone()
        columns = {row[1] for row in connection.execute("PRAGMA table_info(runs)")}
        revision_index = connection.execute(
            """
            SELECT 1 FROM sqlite_master
            WHERE type = 'index' AND name = 'runs_candidate_revision_idx'
            """
        ).fetchone()
    assert version == (6,)
    assert "issue_revision" not in columns
    assert revision_index is None


@pytest.mark.parametrize(
    ("column", "value"),
    (("repository", "example/other"), ("issue_number", 999)),
)
def test_v6_migration_rejects_candidate_row_identity_tampering(
    tmp_path: Path,
    column: str,
    value: str | int,
) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    run = _candidate_run(store)
    _downgrade_current_database_to_v6(store.database_path)
    with closing(sqlite3.connect(store.database_path)) as connection:
        connection.execute(
            f"UPDATE runs SET {column} = ? WHERE run_id = ?",
            (value, run.run_id),
        )
        connection.commit()

    with pytest.raises(StateError, match="candidate disagrees with its state row"):
        RunStore(root)

    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT schema_version FROM schema_metadata WHERE singleton = 1"
        ).fetchone() == (6,)
        assert "issue_revision" not in {
            row[1] for row in connection.execute("PRAGMA table_info(runs)")
        }


def test_v7_migration_rejects_duplicate_active_candidate_attempts_transactionally(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    first = _candidate_run(
        store,
        candidate=_issue_candidate(number=41),
        status=RunStatus.QUEUED,
    )
    second = _candidate_run(
        store,
        candidate=_issue_candidate(number=42),
        status=RunStatus.QUEUED,
    )
    assert first.candidate is not None
    first_revision = compute_issue_revision(first.candidate)
    _downgrade_current_database_to_v7(store.database_path)
    second.candidate = first.candidate.model_copy(deep=True)
    with closing(sqlite3.connect(store.database_path)) as connection:
        connection.execute(
            """
            UPDATE runs
            SET repository = ?, issue_number = ?, issue_revision = ?, manifest_json = ?
            WHERE run_id = ?
            """,
            (
                second.candidate.repository,
                second.candidate.number,
                first_revision,
                second.model_dump_json(),
                second.run_id,
            ),
        )
        connection.commit()

    with pytest.raises(StateError, match="duplicate active attempts"):
        RunStore(root)

    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT schema_version FROM schema_metadata WHERE singleton = 1"
        ).fetchone() == (7,)
        assert "issue_revision" in {row[1] for row in connection.execute("PRAGMA table_info(runs)")}
        assert connection.execute(
            """
            SELECT count(*) FROM sqlite_master
            WHERE name IN (
                'candidate_retry_authorizations',
                'legacy_candidate_retry_overrides',
                'runs_active_candidate_idx'
            )
            """
        ).fetchone() == (0,)
        assert [
            row[4]
            for row in connection.execute(
                "PRAGMA index_xinfo(runs_candidate_revision_idx)"
            ).fetchall()
            if row[5]
        ] == ["BINARY", "BINARY", "BINARY", "BINARY"]
        assert RunStore._schema_manifest(connection) == RunStore._expected_schema_manifest(7)


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
    assert store.publication_gate_hold(run.run_id) is not None

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
def test_restore_snapshot_rejects_issue_revision_tampering(
    tmp_path: Path,
    tamper: str,
) -> None:
    source = RunStore(tmp_path / "source")
    run = _candidate_run(source)
    snapshot = source.create_snapshot(tmp_path / "backup" / "state.sqlite3")
    with closing(sqlite3.connect(snapshot)) as connection:
        connection.execute("PRAGMA journal_mode = DELETE")
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
    target = tmp_path / "target"

    with pytest.raises(StateError, match="issue revision"):
        RunStore.restore_snapshot(target, snapshot)

    assert not (target / "state.sqlite3").exists()


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
def test_restore_snapshot_rejects_tampered_or_orphaned_candidate_retry_evidence(
    tmp_path: Path,
    tamper: str,
    message: str,
) -> None:
    source = RunStore(tmp_path / "source")
    candidate = _issue_candidate()
    _candidate_run(source, candidate=candidate, status=RunStatus.REJECTED)
    retry = source.create_run()
    _set_status(source, retry, RunStatus.DISCOVERING)
    retry.candidate = candidate.model_copy(deep=True)
    lease = source.acquire_lease(
        "autocontribute.run",
        "snapshot-retry-worker",
        ttl=timedelta(minutes=5),
    )
    assert lease is not None
    try:
        source.claim_candidate(
            retry,
            lease=lease,
            retry_authorization=CandidateRetryAuthorization(
                actor="octocat",
                reason="Retry authorized for integrity testing.",
            ),
        )
    finally:
        assert source.release_lease(lease.name, lease.owner, lease.generation)
    snapshot = source.create_snapshot(tmp_path / "backup" / f"{tamper}.sqlite3")

    with closing(sqlite3.connect(snapshot)) as connection:
        connection.execute("PRAGMA journal_mode = DELETE")
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
                for event in source.events(retry.run_id)
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

    target = tmp_path / f"target-{tamper}"
    with pytest.raises(StateError, match=message):
        RunStore.restore_snapshot(target, snapshot)

    assert not (target / "state.sqlite3").exists()


@pytest.mark.parametrize(
    "tamper",
    (
        "unmarked_event",
        "orphan_marker",
        "mismatched_run",
        "mismatched_event",
        "mismatched_hash",
        "migration_time",
        "pre_event_cutoff",
        "event_details",
    ),
)
def test_restore_snapshot_rejects_tampered_legacy_candidate_retry_marker(
    tmp_path: Path,
    tamper: str,
) -> None:
    source_root = tmp_path / "source"
    prior, retry, _, _ = _historical_v7_candidate_retry_database(source_root)
    source = RunStore(source_root)
    ordinary = source.create_run()
    snapshot = source.create_snapshot(tmp_path / "backup" / f"{tamper}.sqlite3")

    with closing(sqlite3.connect(snapshot)) as connection:
        connection.execute("PRAGMA journal_mode = DELETE")
        marker = connection.execute(
            """
            SELECT event_id, run_id, event_hash, migrated_at
            FROM legacy_candidate_retry_overrides WHERE run_id = ?
            """,
            (retry.run_id,),
        ).fetchone()
        assert marker is not None
        if tamper == "unmarked_event":
            connection.execute(
                "DELETE FROM legacy_candidate_retry_overrides WHERE run_id = ?",
                (retry.run_id,),
            )
        elif tamper == "orphan_marker":
            ordinary_event = connection.execute(
                """
                SELECT id, event_hash FROM events
                WHERE run_id = ? AND event_type = 'run.created'
                """,
                (ordinary.run_id,),
            ).fetchone()
            assert ordinary_event is not None
            connection.execute(
                """
                INSERT INTO legacy_candidate_retry_overrides(
                    event_id, run_id, event_hash, migrated_at
                ) VALUES (?, ?, ?, ?)
                """,
                (ordinary_event[0], ordinary.run_id, ordinary_event[1], marker[3]),
            )
        elif tamper == "mismatched_run":
            connection.execute(
                """
                UPDATE legacy_candidate_retry_overrides SET run_id = ?
                WHERE run_id = ?
                """,
                (prior.run_id, retry.run_id),
            )
        elif tamper == "mismatched_event":
            creation = connection.execute(
                """
                SELECT id, event_hash FROM events
                WHERE run_id = ? AND event_type = 'run.created'
                """,
                (retry.run_id,),
            ).fetchone()
            assert creation is not None
            connection.execute(
                """
                UPDATE legacy_candidate_retry_overrides
                SET event_id = ?, event_hash = ? WHERE run_id = ?
                """,
                (creation[0], creation[1], retry.run_id),
            )
        elif tamper == "mismatched_hash":
            connection.execute(
                """
                UPDATE legacy_candidate_retry_overrides SET event_hash = ?
                WHERE run_id = ?
                """,
                ("f" * 64, retry.run_id),
            )
        elif tamper == "migration_time":
            connection.execute(
                """
                UPDATE legacy_candidate_retry_overrides
                SET migrated_at = '2999-01-01T00:00:00+00:00'
                WHERE run_id = ?
                """,
                (retry.run_id,),
            )
        elif tamper == "pre_event_cutoff":
            cutoff = "2000-01-01T00:00:00+00:00"
            connection.execute(
                """
                UPDATE legacy_candidate_retry_overrides SET migrated_at = ?
                WHERE run_id = ?
                """,
                (cutoff, retry.run_id),
            )
            connection.execute(
                """
                UPDATE schema_metadata SET migrated_at = ? WHERE singleton = 1
                """,
                (cutoff,),
            )
        else:
            event = connection.execute(
                """
                SELECT details_json FROM events
                WHERE run_id = ? AND event_type = 'candidate.retry_override'
                """,
                (retry.run_id,),
            ).fetchone()
            assert event is not None
            details = json.loads(event[0])
            details["prior_status"] = RunStatus.SKIPPED.value
            _rewrite_tail_event_details(
                connection,
                run_id=retry.run_id,
                event_type="candidate.retry_override",
                details=details,
            )
            changed_hash = connection.execute(
                """
                SELECT event_hash FROM events
                WHERE run_id = ? AND event_type = 'candidate.retry_override'
                """,
                (retry.run_id,),
            ).fetchone()
            assert changed_hash is not None
            connection.execute(
                """
                UPDATE legacy_candidate_retry_overrides SET event_hash = ?
                WHERE run_id = ?
                """,
                (changed_hash[0], retry.run_id),
            )
        connection.commit()

    target = tmp_path / f"target-{tamper}"
    with pytest.raises(StateError):
        RunStore.restore_snapshot(target, snapshot)

    assert not (target / "state.sqlite3").exists()


def test_restore_snapshot_rejects_semantically_tampered_candidate_selection(
    tmp_path: Path,
) -> None:
    source = RunStore(tmp_path / "source")
    run = _candidate_run(source, status=RunStatus.DISCOVERING)
    snapshot = source.create_snapshot(tmp_path / "backup" / "selection.sqlite3")
    event = next(
        event for event in source.events(run.run_id) if event["event_type"] == "candidate.selected"
    )
    details = json.loads(event["details"])
    details["issue"] = "example/other#999"
    with closing(sqlite3.connect(snapshot)) as connection:
        connection.execute("PRAGMA journal_mode = DELETE")
        _rewrite_tail_event_details(
            connection,
            run_id=run.run_id,
            event_type="candidate.selected",
            details=details,
        )
        connection.commit()
    target = tmp_path / "target"

    with pytest.raises(StateError, match="candidate selection disagrees"):
        RunStore.restore_snapshot(target, snapshot)

    assert not (target / "state.sqlite3").exists()


def test_restore_snapshot_rejects_candidate_without_selection_provenance(
    tmp_path: Path,
) -> None:
    source = RunStore(tmp_path / "source")
    run = _candidate_run(source, status=RunStatus.DISCOVERING)
    snapshot = source.create_snapshot(tmp_path / "backup" / "missing-selection.sqlite3")
    with closing(sqlite3.connect(snapshot)) as connection:
        connection.execute("PRAGMA journal_mode = DELETE")
        _delete_tail_event(
            connection,
            run_id=run.run_id,
            event_type="candidate.selected",
        )
        connection.commit()
    target = tmp_path / "target"

    with pytest.raises(StateError, match="candidate evidence without selection provenance"):
        RunStore.restore_snapshot(target, snapshot)

    assert not (target / "state.sqlite3").exists()


def test_v3_migration_backfills_event_heads_and_active_lease_generation(tmp_path: Path) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    run = store.create_run()
    store.transition(run, RunStatus.DISCOVERING, reason="migration fixture")
    started = datetime(2025, 1, 1, tzinfo=UTC)
    first = store.acquire_lease("scheduler", "worker-a", ttl=timedelta(seconds=10), now=started)
    assert first is not None
    takeover = store.acquire_lease(
        "scheduler", "worker-b", ttl=timedelta(seconds=10), now=first.expires_at
    )
    assert takeover is not None and takeover.generation == 2
    expected_events = store.events(run.run_id)
    _downgrade_current_database_to_v3(store.database_path)

    migrated = RunStore(root)

    assert migrated.schema_version == CURRENT_SCHEMA_VERSION == 8
    migrated.verify_event_chains()
    with sqlite3.connect(migrated.database_path) as connection:
        anchor = connection.execute(
            "SELECT event_count, event_head_hash FROM runs WHERE run_id = ?",
            (run.run_id,),
        ).fetchone()
        generation = connection.execute(
            "SELECT generation FROM lease_generations WHERE lease_name = 'scheduler'"
        ).fetchone()
    assert anchor == (len(expected_events), expected_events[-1]["event_hash"])
    assert generation == (takeover.generation,)


def test_v3_migration_holds_every_reserved_submitting_run_at_the_exact_corpus(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    evaluated = store.create_run()
    store.record_evaluation_anchor(evaluated.run_id, {"evaluation_hash": "a" * 64})
    submitting = store.create_run()
    second_submitting = store.create_run()
    published = store.create_run()
    store.reserve_publication(
        submitting.run_id,
        "example/submitting",
        max_per_utc_day=10,
        repository_cooldown=timedelta(0),
    )
    store.reserve_publication(
        second_submitting.run_id,
        "example/second-submitting",
        max_per_utc_day=10,
        repository_cooldown=timedelta(0),
    )
    store.reserve_publication(
        published.run_id,
        "example/published",
        max_per_utc_day=10,
        repository_cooldown=timedelta(0),
    )
    _set_status(store, submitting, RunStatus.SUBMITTING)
    _set_status(store, second_submitting, RunStatus.SUBMITTING)
    _set_status(store, published, RunStatus.PR_OPEN)
    expected_cursor = store.evaluation_corpus_cursor()
    _downgrade_current_database_to_v3(store.database_path)
    migrated_at = datetime(2026, 7, 21, 13, tzinfo=UTC)
    monkeypatch.setattr("autocontribute.store.utc_now", lambda: migrated_at)

    migrated = RunStore(root)

    with sqlite3.connect(migrated.database_path) as connection:
        holds = connection.execute(
            """
            SELECT run_id, deployment_fingerprint, corpus_cursor, held_at
            FROM publication_gate_holds ORDER BY run_id
            """
        ).fetchall()
    assert holds == sorted(
        [
            (submitting.run_id, None, expected_cursor, migrated_at.isoformat()),
            (
                second_submitting.run_id,
                None,
                expected_cursor,
                migrated_at.isoformat(),
            ),
        ]
    )
    for run in (submitting, second_submitting):
        assert [
            event["event_type"]
            for event in migrated.events(run.run_id)
            if event["event_type"] == "publication.gate.legacy"
        ] == ["publication.gate.legacy"]


def test_v4_migration_attests_a_legacy_gate_hold_and_keeps_it_active(tmp_path: Path) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    run = store.create_run()
    store.reserve_publication(
        run.run_id,
        "example/project",
        max_per_utc_day=10,
        repository_cooldown=timedelta(0),
    )
    _set_status(store, run, RunStatus.SUBMITTING)
    cursor = store.evaluation_corpus_cursor()
    held_at = datetime(2026, 7, 21, 14, tzinfo=UTC).isoformat()
    _downgrade_current_database_to_v4(store.database_path)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            """
            INSERT INTO publication_gate_holds(
                run_id, deployment_fingerprint, corpus_cursor, held_at
            ) VALUES (?, NULL, ?, ?)
            """,
            (run.run_id, cursor, held_at),
        )

    migrated = RunStore(root)

    with sqlite3.connect(migrated.database_path) as connection:
        assert connection.execute(
            """
            SELECT deployment_fingerprint, corpus_cursor, held_at
            FROM publication_gate_holds WHERE run_id = ?
            """,
            (run.run_id,),
        ).fetchone() == (None, cursor, held_at)
    legacy = [
        event
        for event in migrated.events(run.run_id)
        if event["event_type"] == "publication.gate.legacy"
    ]
    assert len(legacy) == 1
    assert json.loads(legacy[0]["details"]) == {"corpus_cursor": cursor, "held_at": held_at}


def test_v5_migration_fences_a_pre_outcome_hold_from_automatic_recovery(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    run = _publication_run(store, status=RunStatus.READY_FOR_APPROVAL)
    _begin_publication(store, run, with_gate=False)
    cursor = store.evaluation_corpus_cursor()
    held_at = datetime(2026, 7, 21, 14, 30, tzinfo=UTC).isoformat()
    with store._connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            INSERT INTO publication_gate_holds(
                run_id, deployment_fingerprint, corpus_cursor,
                outcome_corpus_cursor, held_at
            ) VALUES (?, ?, ?, NULL, ?)
            """,
            (run.run_id, "d" * 64, cursor, held_at),
        )
        store._append_event(
            connection,
            run.run_id,
            "publication.gate.held",
            {
                "deployment_fingerprint": "d" * 64,
                "corpus_cursor": cursor,
                "held_at": held_at,
            },
        )
    _downgrade_current_database_to_v5(store.database_path)

    migrated = RunStore(root)

    assert migrated.schema_version == CURRENT_SCHEMA_VERSION == 8
    with sqlite3.connect(migrated.database_path) as connection:
        assert connection.execute(
            """
            SELECT outcome_corpus_cursor FROM publication_gate_holds
            WHERE run_id = ?
            """,
            (run.run_id,),
        ).fetchone() == (None,)
    recovered = migrated.get(run.run_id)
    with pytest.raises(StateError, match="predates schema-v6"):
        _begin_publication(migrated, recovered, with_gate=False)


def test_v4_migration_derives_released_legacy_hold_evidence_from_exact_release(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    run = store.create_run()
    store.reserve_publication(
        run.run_id,
        "example/project",
        max_per_utc_day=10,
        repository_cooldown=timedelta(0),
    )
    cursor = store.evaluation_corpus_cursor()
    held_at = datetime(2026, 7, 21, 15, tzinfo=UTC).isoformat()
    with store._connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        store._append_event(
            connection,
            run.run_id,
            "publication.gate.released",
            {"outcome": "pr_open", "corpus_cursor": cursor, "held_at": held_at},
        )
    _downgrade_current_database_to_v4(store.database_path)

    migrated = RunStore(root)

    with sqlite3.connect(migrated.database_path) as connection:
        assert connection.execute(
            "SELECT count(*) FROM publication_gate_holds WHERE run_id = ?", (run.run_id,)
        ).fetchone() == (0,)
    legacy = [
        event
        for event in migrated.events(run.run_id)
        if event["event_type"] == "publication.gate.legacy"
    ]
    assert len(legacy) == 1
    assert json.loads(legacy[0]["details"]) == {"corpus_cursor": cursor, "held_at": held_at}


def test_v3_migration_rejects_a_corrupt_legacy_event_chain_transactionally(
    tmp_path: Path,
) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    run = store.create_run()
    store.transition(run, RunStatus.DISCOVERING, reason="migration fixture")
    _downgrade_current_database_to_v3(store.database_path)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            """
            UPDATE events SET details_json = '{"tampered":true}'
            WHERE run_id = ? AND event_type = 'run.transitioned'
            """,
            (run.run_id,),
        )

    with pytest.raises(StateError, match="Event hash mismatch"):
        RunStore(root)

    with sqlite3.connect(store.database_path) as connection:
        version = connection.execute(
            "SELECT schema_version FROM schema_metadata WHERE singleton = 1"
        ).fetchone()
        run_columns = {row[1] for row in connection.execute("PRAGMA table_info(runs)").fetchall()}
        generation_table = connection.execute(
            """
            SELECT 1 FROM sqlite_master
            WHERE type = 'table' AND name = 'lease_generations'
            """
        ).fetchone()
    assert version == (3,)
    assert "event_count" not in run_columns
    assert "event_head_hash" not in run_columns
    assert generation_table is None


def test_v2_migration_conservatively_backfills_active_publications(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    submitting = store.create_run()
    published = store.create_run()
    _set_status(store, submitting, RunStatus.SUBMITTING)
    _set_status(store, published, RunStatus.PR_OPEN)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE runs SET repository = 'Example/Project' WHERE run_id = ?",
            (submitting.run_id,),
        )
        connection.execute(
            "UPDATE runs SET repository = 'Other/Project' WHERE run_id = ?",
            (published.run_id,),
        )
    connection.close()
    _downgrade_current_database_to_v2(store.database_path)
    migrated_at = datetime(2026, 7, 21, 12, tzinfo=UTC)
    monkeypatch.setattr("autocontribute.store.utc_now", lambda: migrated_at)

    migrated = RunStore(root)

    assert migrated.schema_version == CURRENT_SCHEMA_VERSION
    with sqlite3.connect(migrated.database_path) as connection:
        reservations = connection.execute(
            """
            SELECT run_id, repository, reserved_at FROM publication_reservations
            ORDER BY run_id
            """
        ).fetchall()
        holds = connection.execute(
            """
            SELECT run_id, deployment_fingerprint, corpus_cursor, held_at
            FROM publication_gate_holds ORDER BY run_id
            """
        ).fetchall()
    assert reservations == sorted(
        [
            (submitting.run_id, "example/project", migrated_at.isoformat()),
            (published.run_id, "other/project", migrated_at.isoformat()),
        ]
    )
    assert holds == [
        (
            submitting.run_id,
            None,
            hashlib.sha256(b"[]").hexdigest(),
            migrated_at.isoformat(),
        )
    ]
    assert "publication.reservation.legacy" in {
        event["event_type"] for event in migrated.events(submitting.run_id)
    }
    assert "publication.reservation.legacy" in {
        event["event_type"] for event in migrated.events(published.run_id)
    }
    assert "publication.gate.legacy" in {
        event["event_type"] for event in migrated.events(submitting.run_id)
    }
    migrated.transition(submitting, RunStatus.PR_OPEN, reason="migration fixture reconciled")
    with pytest.raises(StateError, match="Daily publication reservation limit"):
        migrated.reserve_publication(
            migrated.create_run().run_id,
            "third/project",
            max_per_utc_day=1,
            repository_cooldown=timedelta(days=7),
            now=migrated_at,
        )


def test_v2_schema_is_validated_before_migration_sql_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    _downgrade_current_database_to_v2(store.database_path)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute("CREATE VIEW unexpected_state AS SELECT run_id FROM runs")
    migration_called = False

    def unexpected_migration(connection: sqlite3.Connection) -> None:
        nonlocal migration_called
        migration_called = True

    monkeypatch.setattr(
        RunStore,
        "_migrate_2_to_3",
        staticmethod(unexpected_migration),
    )

    with pytest.raises(StateError, match="canonical manifest"):
        RunStore(root)

    assert migration_called is False


def test_failed_migration_rolls_back_every_schema_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "state"
    _legacy_database(root)

    def fail_migration(connection: sqlite3.Connection) -> None:
        connection.execute("CREATE TABLE partial_migration(value TEXT)")
        raise RuntimeError("injected migration failure")

    monkeypatch.setattr(RunStore, "_migrate_1_to_2", staticmethod(fail_migration))
    with pytest.raises(RuntimeError, match="injected"):
        RunStore(root)

    with sqlite3.connect(root / "state.sqlite3") as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            )
        }
    assert tables == {"runs", "events"}


def test_future_or_malformed_schema_fails_closed(tmp_path: Path) -> None:
    future_root = tmp_path / "future"
    _legacy_database(future_root)
    with sqlite3.connect(future_root / "state.sqlite3") as connection:
        connection.execute(
            """
            CREATE TABLE schema_metadata (
                singleton INTEGER PRIMARY KEY,
                schema_version INTEGER NOT NULL,
                migrated_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "INSERT INTO schema_metadata VALUES (1, 99, ?)",
            (datetime.now(UTC).isoformat(),),
        )
    with pytest.raises(StateError, match="newer than supported"):
        RunStore(future_root)

    malformed_root = tmp_path / "malformed"
    _legacy_database(malformed_root)
    with sqlite3.connect(malformed_root / "state.sqlite3") as connection:
        connection.execute("DROP INDEX events_run_idx")
    with pytest.raises(StateError, match="required indexes"):
        RunStore(malformed_root)


def test_snapshot_is_consistent_includes_wal_and_requires_explicit_overwrite(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    run = store.create_run()
    writer = sqlite3.connect(store.database_path)
    try:
        writer.execute("PRAGMA journal_mode = WAL")
        writer.execute("PRAGMA wal_autocheckpoint = 0")
        lifecycle_snapshot = _lifecycle_snapshot()
        fingerprint = lifecycle_snapshot.fingerprint()
        assert store.record_lifecycle_snapshot(
            run.run_id,
            fingerprint,
            lifecycle_snapshot.to_json(),
        )

        destination = tmp_path / "backups" / "state.sqlite3"
        assert store.create_snapshot(destination) == destination.resolve()
        with sqlite3.connect(destination) as backup:
            assert backup.execute("PRAGMA integrity_check").fetchone() == ("ok",)
            assert backup.execute(
                "SELECT count(*) FROM lifecycle_snapshots WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone() == (1,)

        with pytest.raises(StateError, match="already exists"):
            store.create_snapshot(destination)
        assert store.create_snapshot(destination, overwrite=True) == destination.resolve()
    finally:
        writer.close()


def test_snapshot_backup_rejects_event_tail_truncation(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = store.create_run()
    store.transition(run, RunStatus.DISCOVERING, reason="fixture")
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "DELETE FROM events WHERE run_id = ? AND event_type = 'run.transitioned'",
            (run.run_id,),
        )
    destination = tmp_path / "backups" / "state.sqlite3"

    with pytest.raises(StateError, match="Event ledger anchor mismatch"):
        store.create_snapshot(destination)

    assert not destination.exists()


def test_snapshot_rejects_symlinks_and_live_database_paths(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    sentinel = tmp_path / "sentinel"
    sentinel.write_text("unchanged", encoding="utf-8")
    symlink = tmp_path / "backup-link"
    symlink.symlink_to(sentinel)

    with pytest.raises(StateError, match="symbolic link"):
        store.create_snapshot(symlink)
    assert sentinel.read_text(encoding="utf-8") == "unchanged"

    for target in (
        store.database_path,
        Path(f"{store.database_path}-wal"),
        Path(f"{store.database_path}-shm"),
        Path(f"{store.database_path}-journal"),
    ):
        with pytest.raises(StateError, match="live SQLite"):
            store.create_snapshot(target, overwrite=True)


def test_restore_snapshot_validates_before_atomic_promotion(tmp_path: Path) -> None:
    source_store = RunStore(tmp_path / "source")
    run = source_store.create_run()
    snapshot = source_store.create_snapshot(tmp_path / "backup" / "state.sqlite3")
    restored_root = tmp_path / "restored"

    restored = RunStore.restore_snapshot(restored_root, snapshot)

    assert restored == (restored_root / "state.sqlite3").resolve()
    assert RunStore(restored_root).get(run.run_id).run_id == run.run_id
    with pytest.raises(StateError, match="existing live SQLite"):
        RunStore.restore_snapshot(restored_root, snapshot)


def test_restore_snapshot_rejects_event_tail_truncation_before_promotion(
    tmp_path: Path,
) -> None:
    source_store = RunStore(tmp_path / "source")
    run = source_store.create_run()
    source_store.transition(run, RunStatus.DISCOVERING, reason="fixture")
    snapshot = source_store.create_snapshot(tmp_path / "backup" / "state.sqlite3")
    with sqlite3.connect(snapshot) as connection:
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute(
            "DELETE FROM events WHERE run_id = ? AND event_type = 'run.transitioned'",
            (run.run_id,),
        )
    target = tmp_path / "target"

    with pytest.raises(StateError, match="Event ledger anchor mismatch"):
        RunStore.restore_snapshot(target, snapshot)

    assert not (target / "state.sqlite3").exists()


def test_restore_snapshot_accepts_exact_v2_then_initialization_migrates_it(
    tmp_path: Path,
) -> None:
    source_store = RunStore(tmp_path / "source")
    run = source_store.create_run()
    snapshot = source_store.create_snapshot(tmp_path / "backup" / "state.sqlite3")
    _downgrade_current_database_to_v2(snapshot)
    restored_root = tmp_path / "restored"

    restored = RunStore.restore_snapshot(restored_root, snapshot)

    with sqlite3.connect(restored) as connection:
        assert connection.execute("SELECT schema_version FROM schema_metadata").fetchone() == (2,)
    migrated = RunStore(restored_root)
    assert migrated.schema_version == CURRENT_SCHEMA_VERSION == 8
    assert migrated.get(run.run_id).run_id == run.run_id


def test_restore_snapshot_rejects_trigger_that_can_clear_circuit_breaker(
    tmp_path: Path,
) -> None:
    source_store = RunStore(tmp_path / "source")
    source_store.trip_circuit_breaker(source="security", reason="stop", trigger_hash="danger")
    snapshot = source_store.create_snapshot(tmp_path / "backup" / "state.sqlite3")
    with sqlite3.connect(snapshot) as connection:
        connection.execute("PRAGMA journal_mode = DELETE")
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
    target = tmp_path / "target"

    with pytest.raises(StateError, match="canonical manifest"):
        RunStore.restore_snapshot(target, snapshot)
    assert not (target / "state.sqlite3").exists()


def test_snapshot_restore_preserves_complete_active_breaker_revision(tmp_path: Path) -> None:
    source_store = RunStore(tmp_path / "source")
    source_store.trip_circuit_breaker(
        source="maintainer",
        reason="stop requested",
        trigger_hash="signal-a",
    )
    source_store.trip_circuit_breaker(
        source="security",
        reason="secret detected",
        trigger_hash="signal-b",
    )
    expected = source_store.circuit_breaker_status()
    snapshot = source_store.create_snapshot(tmp_path / "backup" / "state.sqlite3")

    RunStore.restore_snapshot(tmp_path / "restored", snapshot)
    restored = RunStore(tmp_path / "restored").circuit_breaker_status()

    assert restored.active_revision == expected.active_revision
    assert restored.active_triggers == expected.active_triggers
    assert restored.trigger_hash == "signal-b"


def test_snapshot_restore_rejects_missing_active_breaker_evidence(tmp_path: Path) -> None:
    source_store = RunStore(tmp_path / "source")
    source_store.trip_circuit_breaker(
        source="security",
        reason="stop",
        trigger_hash="signal-a",
    )
    snapshot = source_store.create_snapshot(tmp_path / "backup" / "state.sqlite3")
    with sqlite3.connect(snapshot) as connection:
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute("DELETE FROM circuit_breaker_events WHERE event_type = 'trip'")

    with pytest.raises(StateError, match="disagrees with its active evidence"):
        RunStore.restore_snapshot(tmp_path / "restored", snapshot)
    assert not (tmp_path / "restored" / "state.sqlite3").exists()


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
        """
        PRAGMA writable_schema = ON;
        UPDATE sqlite_master
        SET sql = replace(
            sql,
            'length(corpus_cursor) = 64',
            'length(corpus_cursor) = 63'
        )
        WHERE type = 'table' AND name = 'publication_gate_holds';
        PRAGMA writable_schema = OFF;
        """,
    ],
    ids=[
        "unexpected-view",
        "altered-index",
        "altered-check-constraint",
        "altered-publication-hold-constraint",
    ],
)
def test_restore_snapshot_rejects_altered_schema_objects(tmp_path: Path, tamper_sql: str) -> None:
    source_store = RunStore(tmp_path / "source")
    snapshot = source_store.create_snapshot(tmp_path / "backup" / "state.sqlite3")
    with sqlite3.connect(snapshot) as connection:
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.executescript(tamper_sql)

    with pytest.raises(StateError, match="canonical manifest"):
        RunStore.restore_snapshot(tmp_path / "target", snapshot)
    assert not (tmp_path / "target" / "state.sqlite3").exists()


def test_restore_snapshot_rejects_invalid_or_unsafe_input_without_live_state(
    tmp_path: Path,
) -> None:
    invalid = tmp_path / "invalid.sqlite3"
    invalid.write_bytes(b"")
    target = tmp_path / "target"

    with pytest.raises(StateError, match="missing or unsupported tables"):
        RunStore.restore_snapshot(target, invalid)
    assert not (target / "state.sqlite3").exists()

    symlink = tmp_path / "snapshot-link"
    symlink.symlink_to(invalid)
    with pytest.raises(StateError, match="symbolic link"):
        RunStore.restore_snapshot(target, symlink)


def test_restore_snapshot_closes_source_descriptor_when_fdopen_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_store = RunStore(tmp_path / "source")
    snapshot = source_store.create_snapshot(tmp_path / "backup" / "state.sqlite3")
    failed_descriptors: list[int] = []

    def fail_fdopen(descriptor: int, mode: str):  # type: ignore[no-untyped-def]
        failed_descriptors.append(descriptor)
        raise OSError("injected fdopen failure")

    monkeypatch.setattr("autocontribute.store.os.fdopen", fail_fdopen)

    with pytest.raises(StateError, match="injected fdopen failure"):
        RunStore.restore_snapshot(tmp_path / "target", snapshot)

    assert len(failed_descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(failed_descriptors[0])
    assert not (tmp_path / "target" / "state.sqlite3").exists()


def test_open_pull_request_remains_an_active_candidate(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = store.create_run()
    _set_status(store, run, RunStatus.PR_OPEN)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE runs SET repository = 'example/project', issue_number = 7 WHERE run_id = ?",
            (run.run_id,),
        )

    assert store.has_active_candidate("example/project", 7) is True

    _set_status(store, run, RunStatus.FAILED)
    assert store.has_active_candidate("example/project", 7) is False


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


def test_begin_publication_atomically_persists_intent_reservation_hold_and_status(
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
            SELECT runs.status, publication_reservations.repository,
                   publication_gate_holds.deployment_fingerprint
            FROM runs
            JOIN publication_reservations USING(run_id)
            JOIN publication_gate_holds USING(run_id)
            WHERE runs.run_id = ?
            """,
            (run.run_id,),
        ).fetchone()
    assert durable == (RunStatus.SUBMITTING.value, "example/project", "d" * 64)
    event_types = [event["event_type"] for event in store.events(run.run_id)]
    assert event_types[-4:] == [
        "publication.reserved",
        "publication.gate.held",
        "run.transitioned",
        "publication.intent.begun",
    ]
    intent = json.loads(store.events(run.run_id)[-1]["details"])
    assert intent["branch"] == run.branch_name
    assert intent["draft"] == "true"


def test_begin_publication_rolls_back_hold_and_reservation_if_intent_cannot_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = RunStore(tmp_path / "state")
    run = _publication_run(store)
    original_append = store._append_event

    def fail_after_hold(
        connection: sqlite3.Connection,
        run_id: str,
        event_type: str,
        details: dict[str, str],
    ) -> None:
        original_append(connection, run_id, event_type, details)
        if event_type == "publication.gate.held":
            raise RuntimeError("injected failure after hold")

    monkeypatch.setattr(store, "_append_event", fail_after_hold)

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
        assert connection.execute("SELECT count(*) FROM publication_gate_holds").fetchone() == (0,)
    assert "publication.gate.held" not in {
        event["event_type"] for event in store.events(run.run_id)
    }


def test_begin_publication_review_mode_and_no_hold_compensation_are_durable(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    run = _publication_run(store, status=RunStatus.READY_FOR_APPROVAL)

    _begin_publication(store, run, with_gate=False, publication_draft=False)

    assert run.status == RunStatus.SUBMITTING
    assert run.publication_draft is False
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute("SELECT count(*) FROM publication_reservations").fetchone() == (
            1,
        )
        assert connection.execute("SELECT count(*) FROM publication_gate_holds").fetchone() == (0,)

    reason = "verified review-mode cleanup"
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
        _begin_publication(store, incomplete, with_gate=False)
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

    _begin_publication(store, legacy, with_gate=False)

    assert legacy.updated_at == previous_updated_at
    event_types = [event["event_type"] for event in store.events(legacy.run_id)]
    assert event_types.count("publication.reserved") == 1
    assert event_types.count("publication.intent.begun") == 1
    assert event_types.count("run.transitioned") == 0


def test_begin_publication_rejects_another_runs_hold_without_mutating_intent(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    other = store.create_run(deployment_fingerprint="d" * 64)
    _reserve_gate(store, other)
    run = _publication_run(store)

    with pytest.raises(StateError, match="held by another run"):
        _begin_publication(store, run, with_gate=False)

    assert run.status == RunStatus.APPROVED
    assert run.branch_name is None
    assert run.publication_draft is None
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT count(*) FROM publication_reservations WHERE run_id = ?",
            (run.run_id,),
        ).fetchone() == (0,)


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
        assert connection.execute("SELECT count(*) FROM publication_gate_holds").fetchone() == (0,)

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
            with_gate=False,
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


def test_begin_publication_recovers_an_approved_same_run_hold_without_duplication(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    run = _publication_run(store)
    _reserve_gate(store, run)

    _begin_publication(store, run)

    assert run.status == RunStatus.SUBMITTING
    event_types = [event["event_type"] for event in store.events(run.run_id)]
    assert event_types.count("publication.reserved") == 1
    assert event_types.count("publication.gate.held") == 1
    assert event_types.count("publication.intent.begun") == 1


def test_compensation_without_a_same_run_hold_rejects_any_other_active_hold(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    review_run = _publication_run(store)
    _begin_publication(store, review_run, with_gate=False)
    reason = "verified cleanup cannot release another run"
    evidence = _record_absent_compensation_evidence(store, review_run, reason=reason)
    other = store.create_run(deployment_fingerprint="d" * 64)
    _reserve_gate(store, other)

    with pytest.raises(StateError, match="held by another run"):
        store.finalize_publication_compensation(
            review_run,
            reason=reason,
            evidence=evidence,
        )

    assert review_run.status == RunStatus.SUBMITTING
    assert store.get(review_run.run_id).status == RunStatus.SUBMITTING
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute("SELECT run_id FROM publication_gate_holds").fetchone() == (
            other.run_id,
        )


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


def test_publication_gate_reservation_is_paired_exact_and_does_not_bypass_existing_rows(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    holder = store.create_run(deployment_fingerprint="d" * 64)
    blocked = store.create_run(deployment_fingerprint="d" * 64)
    cursor = store.evaluation_corpus_cursor()
    fingerprint = "d" * 64
    holder.publishing_login = "octocat"
    holder.publishing_api_origin = "https://api.github.com"
    store.save(holder, event="test.publication_context", details={})
    outcome_cursor = store.upstream_outcome_corpus_cursor(
        fingerprint,
        "octocat",
        "https://api.github.com",
        exclude_run_id=holder.run_id,
    )
    scope = {
        "outcome_corpus_cursor": outcome_cursor,
        "publishing_login": "octocat",
        "publishing_api_origin": "https://api.github.com",
    }

    with pytest.raises(ValueError, match="provided together"):
        store.reserve_publication(
            holder.run_id,
            "example/project",
            max_per_utc_day=100,
            repository_cooldown=timedelta(0),
            evaluation_corpus_cursor=cursor,
        )
    with pytest.raises(StateError, match="corpus changed"):
        store.reserve_publication(
            holder.run_id,
            "example/project",
            max_per_utc_day=100,
            repository_cooldown=timedelta(0),
            evaluation_corpus_cursor="0" * 64,
            evaluation_deployment_fingerprint=fingerprint,
            **scope,
        )
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute("SELECT count(*) FROM publication_reservations").fetchone() == (
            0,
        )

    reservation = store.reserve_publication(
        holder.run_id,
        "example/project",
        max_per_utc_day=100,
        repository_cooldown=timedelta(0),
        evaluation_corpus_cursor=cursor,
        evaluation_deployment_fingerprint=fingerprint,
        **scope,
    )
    assert (
        store.reserve_publication(
            holder.run_id,
            "EXAMPLE/PROJECT",
            max_per_utc_day=1,
            repository_cooldown=timedelta(days=365),
            evaluation_corpus_cursor=cursor,
            evaluation_deployment_fingerprint=fingerprint,
            **scope,
        )
        == reservation
    )
    with pytest.raises(StateError, match="different deployment"):
        store.reserve_publication(
            holder.run_id,
            "example/project",
            max_per_utc_day=100,
            repository_cooldown=timedelta(0),
            evaluation_corpus_cursor=cursor,
            evaluation_deployment_fingerprint="b" * 64,
            outcome_corpus_cursor=outcome_cursor,
            publishing_login="octocat",
            publishing_api_origin="https://api.github.com",
        )
    blocked.publishing_login = "octocat"
    blocked.publishing_api_origin = "https://api.github.com"
    store.save(blocked, event="test.publication_context", details={})
    blocked_outcome_cursor = store.upstream_outcome_corpus_cursor(
        fingerprint,
        "octocat",
        "https://api.github.com",
        exclude_run_id=blocked.run_id,
    )
    with pytest.raises(StateError, match="held by another run"):
        store.reserve_publication(
            blocked.run_id,
            "other/project",
            max_per_utc_day=100,
            repository_cooldown=timedelta(0),
            evaluation_corpus_cursor=cursor,
            evaluation_deployment_fingerprint=fingerprint,
            outcome_corpus_cursor=blocked_outcome_cursor,
            publishing_login="octocat",
            publishing_api_origin="https://api.github.com",
        )

    with sqlite3.connect(store.database_path) as connection:
        hold = connection.execute(
            """
            SELECT run_id, deployment_fingerprint, corpus_cursor
            FROM publication_gate_holds
            """
        ).fetchone()
    assert hold == (holder.run_id, fingerprint, cursor)
    assert [event["event_type"] for event in store.events(holder.run_id)].count(
        "publication.gate.held"
    ) == 1


def test_existing_reservation_can_only_gain_a_gate_hold_after_cursor_validation(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    run = store.create_run(deployment_fingerprint="c" * 64)
    reservation = store.reserve_publication(
        run.run_id,
        "example/project",
        max_per_utc_day=1,
        repository_cooldown=timedelta(0),
    )
    cursor = store.evaluation_corpus_cursor()
    run.publishing_login = "octocat"
    run.publishing_api_origin = "https://api.github.com"
    store.save(run, event="test.publication_context", details={})
    outcome_cursor = store.upstream_outcome_corpus_cursor(
        "c" * 64,
        "octocat",
        "https://api.github.com",
        exclude_run_id=run.run_id,
    )

    upgraded = store.reserve_publication(
        run.run_id,
        "example/project",
        max_per_utc_day=1,
        repository_cooldown=timedelta(0),
        evaluation_corpus_cursor=cursor,
        evaluation_deployment_fingerprint="c" * 64,
        outcome_corpus_cursor=outcome_cursor,
        publishing_login="octocat",
        publishing_api_origin="https://api.github.com",
    )

    assert upgraded == reservation
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT corpus_cursor FROM publication_gate_holds WHERE run_id = ?",
            (run.run_id,),
        ).fetchone() == (cursor,)


def test_gate_hold_and_evaluation_write_are_serialized_without_a_race_window(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    holder = store.create_run(deployment_fingerprint="d" * 64)
    evaluated = store.create_run()
    cursor = store.evaluation_corpus_cursor()
    barrier = threading.Barrier(2)

    def reserve() -> str:
        barrier.wait()
        try:
            _reserve_gate(store, holder, cursor=cursor)
        except StateError:
            return "cursor-blocked"
        return "held"

    def record() -> str:
        barrier.wait()
        try:
            store.record_evaluation_anchor(evaluated.run_id, {"evaluation_hash": "a" * 64})
        except StateError:
            return "evaluation-blocked"
        return "recorded"

    with ThreadPoolExecutor(max_workers=2) as executor:
        reserve_future = executor.submit(reserve)
        record_future = executor.submit(record)
        results = {reserve_future.result(), record_future.result()}

    assert results in (
        {"held", "evaluation-blocked"},
        {"cursor-blocked", "recorded"},
    )
    with sqlite3.connect(store.database_path) as connection:
        reservations = connection.execute(
            "SELECT count(*) FROM publication_reservations"
        ).fetchone()
        holds = connection.execute("SELECT count(*) FROM publication_gate_holds").fetchone()
        evaluations = connection.execute(
            "SELECT count(*) FROM events WHERE event_type = 'evaluation.recorded'"
        ).fetchone()
    if "held" in results:
        assert (reservations, holds, evaluations) == ((1,), (1,), (0,))
    else:
        assert (reservations, holds, evaluations) == ((0,), (0,), (1,))


def test_gate_hold_blocks_all_evaluation_writes_until_pr_open_is_durable(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    evaluated = store.create_run()
    initial_hash = "a" * 64
    store.record_evaluation_anchor(evaluated.run_id, {"evaluation_hash": initial_hash})
    holder = store.create_run(deployment_fingerprint="d" * 64)
    pending = store.create_run()
    _reserve_gate(store, holder)

    with pytest.raises(StateError, match="held by active publication"):
        store.record_evaluation_anchor(pending.run_id, {"evaluation_hash": "b" * 64})
    with pytest.raises(StateError, match="held by active publication"):
        store.record_evaluation_amendment_anchor(
            evaluated.run_id,
            {
                "evaluation_hash": "c" * 64,
                "supersedes_evaluation_hash": initial_hash,
            },
            expected_previous_hash=initial_hash,
        )

    _set_status(store, holder, RunStatus.SUBMITTING)
    store.transition(holder, RunStatus.PR_OPEN, reason="exact pull request persisted")

    store.record_evaluation_anchor(pending.run_id, {"evaluation_hash": "b" * 64})
    store.record_evaluation_amendment_anchor(
        evaluated.run_id,
        {
            "evaluation_hash": "c" * 64,
            "supersedes_evaluation_hash": initial_hash,
        },
        expected_previous_hash=initial_hash,
    )
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute("SELECT count(*) FROM publication_gate_holds").fetchone() == (0,)
    event_types = [event["event_type"] for event in store.events(holder.run_id)]
    assert event_types.index("run.transitioned") < event_types.index("publication.gate.released")
    assert json.loads(store.events(holder.run_id)[-1]["details"])["outcome"] == "pr_open"


def test_publication_gate_hold_current_accepts_its_exact_scope(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    holder = store.create_run(deployment_fingerprint="d" * 64)
    _reserve_gate(store, holder)

    assert (
        store.assert_publication_gate_hold_current(
            holder.run_id,
            deployment_fingerprint="d" * 64,
            publishing_login="octocat",
            publishing_api_origin="https://api.github.com",
        )
        is True
    )


def test_publication_gate_hold_current_rejects_evaluation_cursor_drift(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    evaluated = store.create_run()
    holder = store.create_run(deployment_fingerprint="d" * 64)
    _reserve_gate(store, holder)
    with store._connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        store._append_event(
            connection,
            evaluated.run_id,
            "evaluation.recorded",
            {"evaluation_hash": "a" * 64},
        )

    with pytest.raises(StateError, match="evaluation corpus"):
        store.assert_publication_gate_hold_current(
            holder.run_id,
            deployment_fingerprint="d" * 64,
            publishing_login="octocat",
            publishing_api_origin="https://api.github.com",
        )


def test_publication_gate_hold_current_rejects_upstream_outcome_cursor_drift(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    prior = store.create_run(deployment_fingerprint="d" * 64)
    _set_status(store, prior, RunStatus.PR_OPEN)
    holder = store.create_run(deployment_fingerprint="d" * 64)
    _reserve_gate(store, holder)
    store.save(prior, event="test.outcome_drift", details={"version": "later"})

    with pytest.raises(StateError, match="upstream-outcome corpus"):
        store.assert_publication_gate_hold_current(
            holder.run_id,
            deployment_fingerprint="d" * 64,
            publishing_login="octocat",
            publishing_api_origin="https://api.github.com",
        )


def test_publication_gate_hold_current_rejects_identity_mismatch(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    holder = store.create_run(deployment_fingerprint="d" * 64)
    _reserve_gate(store, holder)

    with pytest.raises(StateError, match="different publishing identity or scope"):
        store.assert_publication_gate_hold_current(
            holder.run_id,
            deployment_fingerprint="d" * 64,
            publishing_login="hubot",
            publishing_api_origin="https://api.github.com",
        )


def test_publication_gate_hold_current_returns_cleanly_without_a_hold(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    manual = store.create_run(deployment_fingerprint="d" * 64)

    assert (
        store.assert_publication_gate_hold_current(
            manual.run_id,
            deployment_fingerprint="d" * 64,
            publishing_login="octocat",
            publishing_api_origin="https://api.github.com",
        )
        is False
    )


def test_publication_gate_hold_current_rejects_a_missing_durable_hold_row(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    holder = store.create_run(deployment_fingerprint="d" * 64)
    _reserve_gate(store, holder)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "DELETE FROM publication_gate_holds WHERE run_id = ?",
            (holder.run_id,),
        )

    with pytest.raises(StateError, match="publication gate hold row is missing"):
        store.assert_publication_gate_hold_current(
            holder.run_id,
            deployment_fingerprint="d" * 64,
            publishing_login="octocat",
            publishing_api_origin="https://api.github.com",
        )


def test_pr_open_refuses_to_release_a_hold_for_a_different_corpus(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    holder = store.create_run(deployment_fingerprint="d" * 64)
    _reserve_gate(store, holder)
    _set_status(store, holder, RunStatus.SUBMITTING)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE publication_gate_holds SET corpus_cursor = ? WHERE run_id = ?",
            ("f" * 64, holder.run_id),
        )

    with pytest.raises(StateError, match="differs from the active publication gate hold"):
        store.transition(holder, RunStatus.PR_OPEN, reason="must not release a different hold")

    assert holder.status == RunStatus.SUBMITTING
    assert store.get(holder.run_id).status == RunStatus.SUBMITTING
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT corpus_cursor FROM publication_gate_holds WHERE run_id = ?",
            (holder.run_id,),
        ).fetchone() == ("f" * 64,)
    with pytest.raises(StateError, match="disagrees with the evaluation corpus"):
        RunStore(store.root)


def test_arbitrary_failed_transition_never_releases_a_publication_gate_hold(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    holder = store.create_run(deployment_fingerprint="d" * 64)
    pending = store.create_run()
    _reserve_gate(store, holder)
    _set_status(store, holder, RunStatus.SUBMITTING)

    store.transition(holder, RunStatus.FAILED, reason="unverified local failure")

    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute("SELECT run_id FROM publication_gate_holds").fetchone() == (
            holder.run_id,
        )
    with pytest.raises(StateError, match="held by active publication"):
        store.record_evaluation_anchor(pending.run_id, {"evaluation_hash": "a" * 64})
    with pytest.raises(StateError, match="requires a SUBMITTING manifest"):
        store.finalize_publication_compensation(
            holder,
            reason="cannot retroactively verify",
            evidence={"branch": "autocontribute/fix"},
        )


def test_verified_compensation_rejects_arbitrary_evidence_and_retains_hold(
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
    assert store.publication_gate_hold(holder.run_id) is not None


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
    assert store.publication_gate_hold(holder.run_id) is not None


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
    assert store.publication_gate_hold(holder.run_id) is not None


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
    assert store.publication_gate_hold(holder.run_id) is None


def test_absence_compensation_rejects_partial_fork_identity(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    holder = _publication_run(store, status=RunStatus.READY_FOR_APPROVAL)
    _begin_publication(store, holder, with_gate=False)
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
    assert store.publication_gate_hold(holder.run_id) is not None


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
    assert store.publication_gate_hold(holder.run_id) is not None


def test_verified_compensation_transition_and_exact_hold_release_are_atomic(
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
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute("SELECT run_id FROM publication_gate_holds").fetchone() == (
            holder.run_id,
        )

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
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute("SELECT count(*) FROM publication_gate_holds").fetchone() == (0,)
    assert [event["event_type"] for event in store.events(holder.run_id)][-3:] == [
        "publication.compensation.verified",
        "run.transitioned",
        "publication.gate.released",
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
    assert store.publication_gate_hold(holder.run_id) is not None


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
    assert store.publication_gate_hold(holder.run_id) is not None


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
    assert store.publication_gate_hold(holder.run_id) is None


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
    assert store.publication_gate_hold(holder.run_id) is not None


def test_restart_allows_exact_compensation_but_not_constructive_authority_after_cursor_drift(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    prior = store.create_run(deployment_fingerprint="d" * 64)
    _set_status(store, prior, RunStatus.PR_OPEN)
    evaluated = store.create_run()
    holder = _publication_run(store)
    _begin_publication(store, holder)
    reason = "verified exact remote cleanup after rollout drift"
    evidence = _record_absent_compensation_evidence(store, holder, reason=reason)
    hold = store.publication_gate_hold(holder.run_id)
    assert hold is not None and hold.outcome_corpus_cursor is not None

    store.save(prior, event="test.outcome_drift", details={"version": "later"})
    with store._connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        store._append_event(
            connection,
            evaluated.run_id,
            "evaluation.recorded",
            {"evaluation_hash": "a" * 64},
        )

    assert store.evaluation_corpus_cursor() != hold.corpus_cursor
    assert (
        store.upstream_outcome_corpus_cursor(
            "d" * 64,
            "octocat",
            "https://api.github.com",
            exclude_run_id=holder.run_id,
        )
        != hold.outcome_corpus_cursor
    )

    restarted = RunStore(store.root)
    with pytest.raises(StateError, match="disagrees with the evaluation corpus"):
        restarted.assert_publication_gate_hold_current(
            holder.run_id,
            deployment_fingerprint="d" * 64,
            publishing_login="octocat",
            publishing_api_origin="https://api.github.com",
        )

    recovered = restarted.get(holder.run_id)
    finalized = restarted.finalize_publication_compensation(
        recovered,
        reason=reason,
        evidence=evidence,
    )

    assert finalized.status == RunStatus.FAILED
    assert restarted.publication_gate_hold(holder.run_id) is None
    release = json.loads(restarted.events(holder.run_id)[-1]["details"])
    assert release["outcome"] == "verified_compensation"
    assert release["corpus_cursor"] == hold.corpus_cursor
    assert release["outcome_corpus_cursor"] == hold.outcome_corpus_cursor
    assert RunStore(store.root).get(holder.run_id).status == RunStatus.FAILED


def test_merged_compensation_becomes_lifecycle_managed_despite_rollout_cursor_drift(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    prior = store.create_run(deployment_fingerprint="d" * 64)
    _set_status(store, prior, RunStatus.PR_OPEN)
    evaluated = store.create_run()
    holder = _publication_run(store)
    _begin_publication(store, holder)
    _record_merged_compensation_evidence(store, holder)
    hold = store.publication_gate_hold(holder.run_id)
    assert hold is not None and hold.outcome_corpus_cursor is not None

    store.save(prior, event="test.outcome_drift", details={"version": "later"})
    with store._connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        store._append_event(
            connection,
            evaluated.run_id,
            "evaluation.recorded",
            {"evaluation_hash": "a" * 64},
        )

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
    assert restarted.publication_gate_hold(holder.run_id) is None
    event_types = [event["event_type"] for event in restarted.events(holder.run_id)]
    assert event_types[-2:] == ["run.transitioned", "publication.gate.released"]
    release = json.loads(restarted.events(holder.run_id)[-1]["details"])
    assert release["outcome"] == "pr_open"
    assert release["corpus_cursor"] == hold.corpus_cursor
    assert release["outcome_corpus_cursor"] == hold.outcome_corpus_cursor


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
    assert store.publication_gate_hold(holder.run_id) is not None


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
    assert store.publication_gate_hold(holder.run_id) is not None


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
    assert store.publication_gate_hold(holder.run_id) is not None


def test_merged_compensation_rejects_tampered_same_run_hold(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    holder = _publication_run(store)
    _begin_publication(store, holder)
    holder.publication_compensation_reason = "created_pr_base_moved"
    holder.pull_request_url = "https://github.com/example/project/pull/7"
    store.save(
        holder,
        event="publication.compensation.started",
        details={"reason": "created_pr_base_moved", "url": holder.pull_request_url},
    )
    hold = store.publication_gate_hold(holder.run_id)
    assert hold is not None and hold.outcome_corpus_cursor is not None
    tampered_cursor = "0" * 64 if hold.outcome_corpus_cursor != "0" * 64 else "1" * 64
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            """
            UPDATE publication_gate_holds SET outcome_corpus_cursor = ?
            WHERE run_id = ?
            """,
            (tampered_cursor, holder.run_id),
        )

    with pytest.raises(StateError, match="hold disagrees with ledger evidence"):
        store.finalize_merged_publication_compensation(
            holder,
            pull_request_url=holder.pull_request_url,
            reason="must not adopt a PR through tampered gate evidence",
        )

    assert holder.status == RunStatus.SUBMITTING
    assert store.get(holder.run_id).status == RunStatus.SUBMITTING


def test_pr_open_release_remains_strict_after_evaluation_cursor_drift(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    evaluated = store.create_run()
    holder = _publication_run(store)
    _begin_publication(store, holder)
    with store._connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        store._append_event(
            connection,
            evaluated.run_id,
            "evaluation.recorded",
            {"evaluation_hash": "a" * 64},
        )

    with pytest.raises(StateError, match="disagrees with the evaluation corpus"):
        store.transition(holder, RunStatus.PR_OPEN, reason="pull request created")

    assert holder.status == RunStatus.SUBMITTING
    assert store.get(holder.run_id).status == RunStatus.SUBMITTING
    assert store.publication_gate_hold(holder.run_id) is not None


def test_verified_compensation_rejects_hold_row_tampering(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    holder = _publication_run(store)
    _begin_publication(store, holder)
    reason = "must not release tampered hold evidence"
    evidence = _record_absent_compensation_evidence(store, holder, reason=reason)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE publication_gate_holds SET held_at = ? WHERE run_id = ?",
            (datetime(2020, 1, 1, tzinfo=UTC).isoformat(), holder.run_id),
        )

    with pytest.raises(StateError, match="hold disagrees with ledger evidence"):
        store.finalize_publication_compensation(
            holder,
            reason=reason,
            evidence=evidence,
        )

    assert holder.status == RunStatus.SUBMITTING
    assert store.get(holder.run_id).status == RunStatus.SUBMITTING


def test_verified_compensation_releases_a_legacy_pre_outcome_hold(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    holder = _publication_run(store, status=RunStatus.READY_FOR_APPROVAL)
    _begin_publication(store, holder, with_gate=False)
    reason = "verified cleanup of a fenced pre-v6 publication"
    cursor = store.evaluation_corpus_cursor()
    held_at = datetime(2026, 7, 21, 15, tzinfo=UTC).isoformat()
    with store._connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            INSERT INTO publication_gate_holds(
                run_id, deployment_fingerprint, corpus_cursor,
                outcome_corpus_cursor, held_at
            ) VALUES (?, ?, ?, NULL, ?)
            """,
            (holder.run_id, "d" * 64, cursor, held_at),
        )
        store._append_event(
            connection,
            holder.run_id,
            "publication.gate.held",
            {
                "deployment_fingerprint": "d" * 64,
                "corpus_cursor": cursor,
                "held_at": held_at,
            },
        )
    evidence = _record_absent_compensation_evidence(store, holder, reason=reason)

    finalized = store.finalize_publication_compensation(
        holder,
        reason=reason,
        evidence=evidence,
    )

    assert finalized.status == RunStatus.FAILED
    assert store.publication_gate_hold(holder.run_id) is None
    assert json.loads(store.events(holder.run_id)[-1]["details"]) == {
        "corpus_cursor": cursor,
        "deployment_fingerprint": "d" * 64,
        "held_at": held_at,
        "outcome": "verified_compensation",
    }


def test_evaluation_corpus_cursor_is_exact_ordered_and_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = RunStore(tmp_path / "state")
    empty_cursor = hashlib.sha256(b"[]").hexdigest()
    run = store.create_run()
    assert store.evaluation_corpus_cursor() == empty_cursor
    store.transition(run, RunStatus.DISCOVERING, reason="non-evaluation event")
    assert store.evaluation_corpus_cursor() == empty_cursor
    store.record_evaluation_anchor(run.run_id, {"evaluation_hash": "a" * 64})
    store.record_evaluation_amendment_anchor(
        run.run_id,
        {
            "evaluation_hash": "b" * 64,
            "supersedes_evaluation_hash": "a" * 64,
        },
        expected_previous_hash="a" * 64,
    )
    with sqlite3.connect(store.database_path) as connection:
        rows = connection.execute(
            """
            SELECT id, run_id, event_type, event_hash FROM events
            WHERE event_type IN ('evaluation.recorded', 'evaluation.amended')
            ORDER BY id
            """
        ).fetchall()
    canonical = [
        {
            "id": row[0],
            "run_id": row[1],
            "event_type": row[2],
            "event_hash": row[3],
        }
        for row in rows
    ]
    expected = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert store.evaluation_corpus_cursor() == expected

    monkeypatch.setattr("autocontribute.store._MAX_EVALUATION_EVENT_CORPUS", 1)
    with pytest.raises(StateError, match="corpus exceeds"):
        store.evaluation_corpus_cursor()


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

    assert store.stale_run_ids(stale_before=cutoff) == [recoverable.run_id]
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
        assert guard.assert_owned().generation == guard.generation
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
        first = guard.lease
        takeover = store.acquire_lease(
            "scheduler",
            "worker-b",
            ttl=timedelta(seconds=10),
            now=first.expires_at,
        )
        assert takeover is not None and takeover.generation > first.generation
        guard.assert_owned()


def test_lifecycle_snapshots_are_immutable_and_deduplicated(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = store.create_run()
    lifecycle_snapshot = _lifecycle_snapshot()
    snapshot = lifecycle_snapshot.to_json()
    fingerprint = lifecycle_snapshot.fingerprint()

    assert store.record_lifecycle_snapshot(run.run_id, fingerprint, snapshot) is True
    assert store.record_lifecycle_snapshot(run.run_id, fingerprint, snapshot) is False
    changed = _lifecycle_snapshot(head_sha="c" * 40)
    with pytest.raises(ValueError, match="fingerprint does not match"):
        store.record_lifecycle_snapshot(run.run_id, fingerprint, changed.to_json())
    with pytest.raises(StateError, match="Unknown run"):
        store.record_lifecycle_snapshot("missing", fingerprint, snapshot)
    with pytest.raises(ValueError, match="valid JSON"):
        store.record_lifecycle_snapshot(run.run_id, "b" * 64, "not-json")

    snapshots = store.lifecycle_snapshots(run.run_id)
    assert len(snapshots) == 1
    assert snapshots[0].snapshot_json == snapshot
    assert store.events(run.run_id)[-1]["event_type"] == "lifecycle.snapshot.recorded"


@pytest.mark.parametrize("schema_version", (2, 3, 4, 5, 6, 7, 8))
@pytest.mark.parametrize("include_pull_request_node_id", (False, True))
def test_pre_history_lifecycle_snapshot_restores_from_every_supported_schema(
    tmp_path: Path,
    schema_version: int,
    include_pull_request_node_id: bool,
) -> None:
    store = RunStore(tmp_path / "source")
    run = store.create_run()
    snapshot_json = _legacy_lifecycle_snapshot_json(
        include_pull_request_node_id=include_pull_request_node_id
    )
    fingerprint = hashlib.sha256(snapshot_json.encode()).hexdigest()
    store.record_lifecycle_snapshot(run.run_id, fingerprint, snapshot_json)
    snapshot = store.create_snapshot(tmp_path / "snapshots" / f"v{schema_version}.sqlite3")
    if schema_version == 2:
        _downgrade_current_database_to_v2(snapshot)
    elif schema_version == 3:
        _downgrade_current_database_to_v3(snapshot)
    elif schema_version == 4:
        _downgrade_current_database_to_v4(snapshot)
    elif schema_version == 5:
        _downgrade_current_database_to_v5(snapshot)
    elif schema_version == 6:
        _downgrade_current_database_to_v6(snapshot)
    elif schema_version == 7:
        _downgrade_current_database_to_v7(snapshot)

    restored_root = tmp_path / f"restored-v{schema_version}"
    restored = RunStore.restore_snapshot(restored_root, snapshot)
    with sqlite3.connect(restored) as connection:
        assert connection.execute(
            "SELECT schema_version FROM schema_metadata WHERE singleton = 1"
        ).fetchone() == (schema_version,)

    migrated = RunStore(restored_root)
    rows = migrated.lifecycle_snapshots(run.run_id)
    assert len(rows) == 1
    parsed = parse_lifecycle_snapshot_json(
        rows[0].snapshot_json,
        observed_at=rows[0].observed_at,
    )
    assert parsed.to_json() == snapshot_json
    assert parsed.fingerprint() == fingerprint
    assert parsed.history_capability is LifecycleHistoryCapability.LEGACY_PARTIAL
    assert not parsed.has_complete_upstream_history
    assert bool(parsed.pull_request.node_id) is include_pull_request_node_id


def test_lifecycle_snapshot_rejects_noncanonical_and_structurally_invalid_json(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    run = store.create_run()
    snapshot = _lifecycle_snapshot()
    payload = json.loads(snapshot.to_json())
    payload["unsupported"] = True

    with pytest.raises(ValueError, match="canonical JSON"):
        store.record_lifecycle_snapshot(
            run.run_id,
            snapshot.fingerprint(),
            f" {snapshot.to_json()}",
        )
    with pytest.raises(ValueError, match="exact supported fields"):
        store.record_lifecycle_snapshot(
            run.run_id,
            snapshot.fingerprint(),
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
        )
    duplicate_key = snapshot.to_json().replace(
        '"check_runs":[]',
        '"check_runs":[],"check_runs":[]',
        1,
    )
    with pytest.raises(ValueError, match="duplicate JSON key"):
        store.record_lifecycle_snapshot(run.run_id, snapshot.fingerprint(), duplicate_key)


@pytest.mark.parametrize(
    ("path", "value", "message"),
    (
        (("expected_head_sha",), "A" * 40, "full Git SHA"),
        (("pull_request", "head_sha"), "short", "full Git SHA"),
        (("pull_request", "merge_commit_sha"), "short", "full Git SHA"),
        (("pull_request", "title"), "", "nonempty canonical string"),
        (("pull_request", "base_ref"), "", "nonempty canonical string"),
        (("pull_request", "node_id"), "bad\nnode", "bounded printable string"),
        (("pull_request", "repository"), "example/project/extra", "owner/name"),
        (
            ("pull_request", "html_url"),
            "https://github.com/example/other/pull/7",
            "canonical repository and number",
        ),
    ),
)
def test_lifecycle_snapshot_rejects_impossible_github_evidence(
    tmp_path: Path,
    path: tuple[str, ...],
    value: object,
    message: str,
) -> None:
    store = RunStore(tmp_path / "state")
    run = store.create_run()
    payload = json.loads(_lifecycle_snapshot().to_json())
    target = payload
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = value
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))

    with pytest.raises(ValueError, match=message):
        store.record_lifecycle_snapshot(
            run.run_id,
            hashlib.sha256(encoded.encode()).hexdigest(),
            encoded,
        )


def test_lifecycle_snapshot_read_recomputes_fingerprint_after_content_tamper(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    run = store.create_run()
    snapshot = _lifecycle_snapshot()
    store.record_lifecycle_snapshot(run.run_id, snapshot.fingerprint(), snapshot.to_json())
    changed = replace(
        snapshot,
        pull_request=replace(snapshot.pull_request, title="Tampered lifecycle evidence"),
    )
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE lifecycle_snapshots SET snapshot_json = ? WHERE run_id = ?",
            (changed.to_json(), run.run_id),
        )

    with pytest.raises(StateError, match="fingerprint mismatch"):
        store.lifecycle_snapshots(run.run_id)


def test_legacy_lifecycle_snapshot_read_rejects_content_tamper(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = store.create_run()
    snapshot_json = _legacy_lifecycle_snapshot_json()
    fingerprint = hashlib.sha256(snapshot_json.encode()).hexdigest()
    store.record_lifecycle_snapshot(run.run_id, fingerprint, snapshot_json)
    payload = json.loads(snapshot_json)
    payload["pull_request"]["title"] = "Tampered legacy lifecycle evidence"
    tampered = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE lifecycle_snapshots SET snapshot_json = ? WHERE run_id = ?",
            (tampered, run.run_id),
        )

    with pytest.raises(StateError, match="fingerprint mismatch"):
        store.lifecycle_snapshots(run.run_id)


def test_lifecycle_snapshot_read_rejects_missing_event_with_valid_ledger_anchor(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    run = store.create_run()
    snapshot = _lifecycle_snapshot()
    store.record_lifecycle_snapshot(run.run_id, snapshot.fingerprint(), snapshot.to_json())
    with sqlite3.connect(store.database_path) as connection:
        event = connection.execute(
            """
            SELECT id, previous_hash FROM events
            WHERE run_id = ? AND event_type = 'lifecycle.snapshot.recorded'
            """,
            (run.run_id,),
        ).fetchone()
        assert event is not None
        connection.execute("DELETE FROM events WHERE id = ?", (event[0],))
        connection.execute(
            """
            UPDATE runs SET event_count = event_count - 1, event_head_hash = ?
            WHERE run_id = ?
            """,
            (event[1], run.run_id),
        )

    with pytest.raises(StateError, match="missing its ledger event"):
        store.lifecycle_snapshots(run.run_id)


def test_lifecycle_snapshot_read_rejects_duplicate_event_with_valid_hash_chain(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    run = store.create_run()
    snapshot = _lifecycle_snapshot()
    fingerprint = snapshot.fingerprint()
    store.record_lifecycle_snapshot(run.run_id, fingerprint, snapshot.to_json())
    with sqlite3.connect(store.database_path) as connection:
        _append_lifecycle_snapshot_event(
            connection,
            run_id=run.run_id,
            fingerprint=fingerprint,
        )

    with pytest.raises(StateError, match="duplicate lifecycle snapshot ledger events"):
        store.lifecycle_snapshots(run.run_id)


def test_lifecycle_snapshot_read_rejects_orphan_event(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = store.create_run()
    snapshot = _lifecycle_snapshot()
    store.record_lifecycle_snapshot(run.run_id, snapshot.fingerprint(), snapshot.to_json())
    with sqlite3.connect(store.database_path) as connection:
        connection.execute("DELETE FROM lifecycle_snapshots WHERE run_id = ?", (run.run_id,))

    with pytest.raises(StateError, match="orphan lifecycle snapshot ledger event"):
        store.lifecycle_snapshots(run.run_id)


def test_backup_and_restore_validate_lifecycle_snapshot_integrity(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = store.create_run()
    snapshot = _lifecycle_snapshot()
    store.record_lifecycle_snapshot(run.run_id, snapshot.fingerprint(), snapshot.to_json())
    backup = store.create_snapshot(tmp_path / "backup.sqlite3")
    with sqlite3.connect(backup) as connection:
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute(
            "UPDATE lifecycle_snapshots SET observed_at = ? WHERE run_id = ?",
            ("2026-07-21T08:00:00-04:00", run.run_id),
        )

    with pytest.raises(StateError, match="canonical UTC timestamp"):
        RunStore.restore_snapshot(tmp_path / "restored", backup)

    with sqlite3.connect(store.database_path) as connection:
        connection.execute("DELETE FROM lifecycle_snapshots WHERE run_id = ?", (run.run_id,))
    destination = tmp_path / "rejected.sqlite3"
    with pytest.raises(StateError, match="orphan lifecycle snapshot ledger event"):
        store.create_snapshot(destination)
    assert not destination.exists()


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


def test_evaluation_anchors_are_atomic_bounded_and_do_not_rewrite_manifests(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    first = store.create_run()
    second = store.create_run()
    original_manifest = store.get(first.run_id)
    first_details = {"digest": "a" * 64}
    second_details = {"digest": "b" * 64}

    store.record_evaluation_anchor(first.run_id, first_details)
    store.record_evaluation_anchor(second.run_id, second_details)

    assert store.get(first.run_id) == original_manifest
    assert store.evaluation_record_anchors() == [
        {"run_id": first.run_id, "details": json.dumps(first_details, separators=(",", ":"))},
        {
            "run_id": second.run_id,
            "details": json.dumps(second_details, separators=(",", ":")),
        },
    ]
    with pytest.raises(StateError, match="already has"):
        store.record_evaluation_anchor(first.run_id, first_details)
    with pytest.raises(StateError, match="exceeds"):
        store.evaluation_record_anchors(limit=1)
    with pytest.raises(StateError, match="Unknown run"):
        store.record_evaluation_anchor("missing", first_details)


def test_evaluation_anchor_is_exactly_once_under_contention(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = store.create_run()

    def record(digest: str) -> str:
        try:
            store.record_evaluation_anchor(run.run_id, {"digest": digest})
        except StateError:
            return "blocked"
        return "recorded"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(record, ["a" * 64, "b" * 64]))

    assert sorted(results) == ["blocked", "recorded"]
    assert len(store.evaluation_record_anchors()) == 1


def test_evaluation_amendment_anchor_requires_the_current_predecessor(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = store.create_run()
    initial_hash = "a" * 64
    amended_hash = "b" * 64
    store.record_evaluation_anchor(run.run_id, {"evaluation_hash": initial_hash})

    store.record_evaluation_amendment_anchor(
        run.run_id,
        {
            "evaluation_hash": amended_hash,
            "revision": "2",
            "supersedes_evaluation_hash": initial_hash,
        },
        expected_previous_hash=initial_hash,
    )

    with pytest.raises(StateError, match="evaluation changed"):
        store.record_evaluation_amendment_anchor(
            run.run_id,
            {
                "evaluation_hash": "c" * 64,
                "revision": "2",
                "supersedes_evaluation_hash": initial_hash,
            },
            expected_previous_hash=initial_hash,
        )
    assert store.evaluation_revision_anchors() == [
        {
            "run_id": run.run_id,
            "event_type": "evaluation.recorded",
            "details": json.dumps({"evaluation_hash": initial_hash}, separators=(",", ":")),
        },
        {
            "run_id": run.run_id,
            "event_type": "evaluation.amended",
            "details": json.dumps(
                {
                    "evaluation_hash": amended_hash,
                    "revision": "2",
                    "supersedes_evaluation_hash": initial_hash,
                },
                separators=(",", ":"),
            ),
        },
    ]


def test_deleted_event_tail_cannot_be_replaced_with_a_new_evaluation_anchor(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    run = store.create_run()
    store.record_evaluation_anchor(run.run_id, {"digest": "a" * 64})
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            """
            DELETE FROM events
            WHERE run_id = ? AND event_type = 'evaluation.recorded'
            """,
            (run.run_id,),
        )

    with pytest.raises(StateError, match="Event ledger anchor mismatch"):
        store.record_evaluation_anchor(run.run_id, {"digest": "b" * 64})
    with pytest.raises(StateError, match="Event ledger anchor mismatch"):
        store.verify_event_chains(run_id=run.run_id)


def test_evaluation_anchor_enumeration_rejects_malformed_or_duplicate_rows(
    tmp_path: Path,
) -> None:
    malformed_store = RunStore(tmp_path / "malformed")
    malformed_run = malformed_store.create_run()
    malformed_store.record_evaluation_anchor(malformed_run.run_id, {"digest": "a" * 64})
    with sqlite3.connect(malformed_store.database_path) as connection:
        connection.execute(
            """
            UPDATE events SET details_json = '[]'
            WHERE run_id = ? AND event_type = 'evaluation.recorded'
            """,
            (malformed_run.run_id,),
        )
    with pytest.raises(StateError, match="malformed details"):
        malformed_store.evaluation_record_anchors()

    duplicate_store = RunStore(tmp_path / "duplicate")
    duplicate_run = duplicate_store.create_run()
    duplicate_store.record_evaluation_anchor(duplicate_run.run_id, {"digest": "a" * 64})
    with sqlite3.connect(duplicate_store.database_path) as connection:
        connection.execute(
            """
            INSERT INTO events(
                run_id, occurred_at, event_type, details_json, previous_hash, event_hash
            ) VALUES (?, ?, 'evaluation.recorded', ?, ?, ?)
            """,
            (
                duplicate_run.run_id,
                datetime.now(UTC).isoformat(),
                '{"digest":"b"}',
                "a" * 64,
                "b" * 64,
            ),
        )
    with pytest.raises(StateError, match="Duplicate evaluation record anchor"):
        duplicate_store.evaluation_record_anchors()


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
            "SELECT count(*) FROM publication_gate_holds WHERE run_id = ?", (run.run_id,)
        ).fetchone() == (0,)
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


def test_compensation_manifest_write_failure_repairs_without_reacquiring_the_hold(
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
            "SELECT count(*) FROM publication_gate_holds WHERE run_id = ?", (run.run_id,)
        ).fetchone() == (0,)
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
        if event["event_type"] == "publication.gate.released"
    ] == ["publication.gate.released"]


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


def test_missing_automatic_hold_is_reconstructed_for_retry_and_still_blocks_evaluations(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    publisher = _publication_run(store)
    _begin_publication(store, publisher)
    other = store.create_run()
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "DELETE FROM publication_gate_holds WHERE run_id = ?", (publisher.run_id,)
        )

    with pytest.raises(StateError, match="held by active publication run"):
        store.record_evaluation_anchor(other.run_id, {"evaluation_hash": "a" * 64})

    retry = store.get(publisher.run_id)
    _begin_publication(store, retry, with_gate=False)

    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "SELECT run_id FROM publication_gate_holds WHERE run_id = ?", (publisher.run_id,)
        ).fetchone() == (publisher.run_id,)
    assert [
        event["event_type"]
        for event in store.events(publisher.run_id)
        if event["event_type"] == "publication.gate.held"
    ] == ["publication.gate.held"]


def test_released_publication_hold_is_not_reconstructed(tmp_path: Path) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    run = _publication_run(store)
    _begin_publication(store, run)
    store.transition(run, RunStatus.PR_OPEN, reason="pull request created")

    reopened = RunStore(root)

    with sqlite3.connect(reopened.database_path) as connection:
        assert connection.execute(
            "SELECT count(*) FROM publication_gate_holds WHERE run_id = ?", (run.run_id,)
        ).fetchone() == (0,)


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


@pytest.mark.parametrize(
    "duplicate_event",
    ["publication.reserved", "publication.gate.held", "publication.gate.released"],
)
def test_duplicate_publication_evidence_fails_closed(
    tmp_path: Path,
    duplicate_event: str,
) -> None:
    root = tmp_path / duplicate_event.rsplit(".", 1)[-1]
    store = RunStore(root)
    run = _publication_run(store)
    _begin_publication(store, run)
    if duplicate_event == "publication.gate.released":
        store.transition(run, RunStatus.PR_OPEN, reason="pull request created")
    details = next(
        json.loads(event["details"])
        for event in store.events(run.run_id)
        if event["event_type"] == duplicate_event
    )
    with store._connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        store._append_event(connection, run.run_id, duplicate_event, details)

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
