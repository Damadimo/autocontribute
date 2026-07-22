import hashlib
import json
import os
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from autocontribute.coordination import LeaseHeartbeatGuard
from autocontribute.domain import IssueCandidate, RunManifest, RunStatus
from autocontribute.exceptions import StateError
from autocontribute.store import CURRENT_SCHEMA_VERSION, RunStore


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


def _downgrade_current_database_to_v4(database: Path) -> None:
    """Remove only the v5 object, leaving the exact canonical v4 schema behind."""

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


def _reserve_gate(
    store: RunStore,
    run: RunManifest,
    *,
    cursor: str | None = None,
    fingerprint: str = "d" * 64,
) -> None:
    store.reserve_publication(
        run.run_id,
        "example/project",
        max_per_utc_day=100,
        repository_cooldown=timedelta(0),
        evaluation_corpus_cursor=cursor or store.evaluation_corpus_cursor(),
        evaluation_deployment_fingerprint=fingerprint,
    )


def _publication_run(
    store: RunStore,
    *,
    status: RunStatus = RunStatus.APPROVED,
    repository: str = "example/project",
) -> RunManifest:
    run = store.create_run()
    observed_at = datetime(2026, 7, 21, 12, tzinfo=UTC)
    run.candidate = IssueCandidate(
        repository=repository,
        number=42,
        title="Fix the exact bug",
        body="Reproduction and expected behavior.",
        html_url=f"https://github.com/{repository}/issues/42",
        state="open",
        author="maintainer",
        labels=["bug"],
        assignees=[],
        comments=0,
        created_at=observed_at,
        updated_at=observed_at,
    )
    run.status = status
    store.save(run, event="test.publication_ready", details={"status": status.value})
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
    )


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


def test_fresh_database_has_current_version_and_all_v5_tables(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")

    with sqlite3.connect(store.database_path) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            )
        }

    assert store.schema_version == CURRENT_SCHEMA_VERSION == 5
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
    }


def test_legacy_database_migrates_transactionally_without_losing_data(tmp_path: Path) -> None:
    root = tmp_path / "state"
    legacy = _legacy_database(root)

    store = RunStore(root)

    assert store.schema_version == CURRENT_SCHEMA_VERSION == 5
    assert store.get(legacy.run_id) == legacy
    assert len(store.events(legacy.run_id)) == 1
    assert store.circuit_breaker_status().is_tripped is False
    store.verify_event_chains()


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

    assert migrated.schema_version == CURRENT_SCHEMA_VERSION == 5
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
        writer.execute(
            """
            INSERT INTO lifecycle_snapshots(
                run_id, fingerprint, observed_at, snapshot_json
            ) VALUES (?, 'wal-only', ?, '{"state":"open"}')
            """,
            (run.run_id, datetime.now(UTC).isoformat()),
        )
        writer.commit()

        destination = tmp_path / "backups" / "state.sqlite3"
        assert store.create_snapshot(destination) == destination.resolve()
        with sqlite3.connect(destination) as backup:
            assert backup.execute("PRAGMA integrity_check").fetchone() == ("ok",)
            assert backup.execute(
                "SELECT count(*) FROM lifecycle_snapshots WHERE fingerprint = 'wal-only'"
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
    assert migrated.schema_version == CURRENT_SCHEMA_VERSION == 5
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

    finalized = store.finalize_publication_compensation(
        run,
        reason="verified review-mode cleanup",
        evidence={"branch": run.branch_name or "missing"},
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

    legacy = _publication_run(store)
    legacy.branch_name = "autocontribute/fix-exact-bug"
    legacy.publication_draft = True
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
    other = store.create_run()
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
    cursor = store.evaluation_corpus_cursor()
    store.reserve_publication(
        run.run_id,
        "example/project",
        max_per_utc_day=100,
        repository_cooldown=timedelta(0),
        evaluation_corpus_cursor=cursor,
        evaluation_deployment_fingerprint="d" * 64,
    )

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
    other = store.create_run()
    _reserve_gate(store, other)

    with pytest.raises(StateError, match="held by another run"):
        store.finalize_publication_compensation(
            review_run,
            reason="verified cleanup cannot release another run",
            evidence={"branch": review_run.branch_name or "missing"},
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
    holder = store.create_run()
    blocked = store.create_run()
    cursor = store.evaluation_corpus_cursor()
    fingerprint = "a" * 64

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
    )
    assert (
        store.reserve_publication(
            holder.run_id,
            "EXAMPLE/PROJECT",
            max_per_utc_day=1,
            repository_cooldown=timedelta(days=365),
            evaluation_corpus_cursor=cursor,
            evaluation_deployment_fingerprint=fingerprint,
        )
        == reservation
    )
    with pytest.raises(StateError, match="different evaluation gate"):
        store.reserve_publication(
            holder.run_id,
            "example/project",
            max_per_utc_day=100,
            repository_cooldown=timedelta(0),
            evaluation_corpus_cursor=cursor,
            evaluation_deployment_fingerprint="b" * 64,
        )
    with pytest.raises(StateError, match="held by another run"):
        store.reserve_publication(
            blocked.run_id,
            "other/project",
            max_per_utc_day=100,
            repository_cooldown=timedelta(0),
            evaluation_corpus_cursor=cursor,
            evaluation_deployment_fingerprint=fingerprint,
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
    run = store.create_run()
    reservation = store.reserve_publication(
        run.run_id,
        "example/project",
        max_per_utc_day=1,
        repository_cooldown=timedelta(0),
    )
    cursor = store.evaluation_corpus_cursor()

    upgraded = store.reserve_publication(
        run.run_id,
        "example/project",
        max_per_utc_day=1,
        repository_cooldown=timedelta(0),
        evaluation_corpus_cursor=cursor,
        evaluation_deployment_fingerprint="c" * 64,
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
    holder = store.create_run()
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
    holder = store.create_run()
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


def test_pr_open_refuses_to_release_a_hold_for_a_different_corpus(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    holder = store.create_run()
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
    holder = store.create_run()
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


def test_verified_compensation_transition_and_exact_hold_release_are_atomic(
    tmp_path: Path,
) -> None:
    store = RunStore(tmp_path / "state")
    holder = store.create_run()
    _reserve_gate(store, holder)
    _set_status(store, holder, RunStatus.SUBMITTING)
    stale = store.get(holder.run_id)
    current = store.get(holder.run_id)
    current.branch_name = "autocontribute/fix"
    current.commit_sha = "1" * 40
    current.pull_request_url = "https://github.com/example/project/pull/7"
    store.save(current, event="publication.identity.persisted", details={"number": "7"})

    with pytest.raises(StateError, match="changed while compensation was finalized"):
        store.finalize_publication_compensation(
            stale,
            reason="verified exact remote cleanup",
            evidence={"branch": "autocontribute/fix", "commit_sha": "1" * 40},
        )
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute("SELECT run_id FROM publication_gate_holds").fetchone() == (
            holder.run_id,
        )

    finalized = store.finalize_publication_compensation(
        current,
        reason="verified exact remote cleanup",
        evidence={"branch": "autocontribute/fix", "commit_sha": "1" * 40},
    )

    assert finalized.status == RunStatus.FAILED
    persisted = store.get(holder.run_id)
    assert persisted.branch_name == "autocontribute/fix"
    assert persisted.commit_sha == "1" * 40
    assert persisted.pull_request_url == "https://github.com/example/project/pull/7"
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute("SELECT count(*) FROM publication_gate_holds").fetchone() == (0,)
    assert [event["event_type"] for event in store.events(holder.run_id)][-3:] == [
        "publication.compensation.verified",
        "run.transitioned",
        "publication.gate.released",
    ]


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
    snapshot = '{"state":"open","reviews":[]}'

    assert store.record_lifecycle_snapshot(run.run_id, "fingerprint", snapshot) is True
    assert store.record_lifecycle_snapshot(run.run_id, "fingerprint", snapshot) is False
    with pytest.raises(StateError, match="reused"):
        store.record_lifecycle_snapshot(run.run_id, "fingerprint", '{"state":"closed"}')
    with pytest.raises(StateError, match="Unknown run"):
        store.record_lifecycle_snapshot("missing", "fingerprint", snapshot)
    with pytest.raises(ValueError, match="valid JSON"):
        store.record_lifecycle_snapshot(run.run_id, "other", "not-json")

    snapshots = store.lifecycle_snapshots(run.run_id)
    assert len(snapshots) == 1
    assert snapshots[0].snapshot_json == snapshot
    assert store.events(run.run_id)[-1]["event_type"] == "lifecycle.snapshot.recorded"


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


def test_compensation_manifest_write_failure_repairs_without_reacquiring_the_hold(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "state"
    store = RunStore(root)
    run = _publication_run(store)
    _begin_publication(store, run)

    def fail_manifest_write(_manifest: RunManifest) -> None:
        raise OSError("injected manifest write failure")

    monkeypatch.setattr(store, "_write_manifest", fail_manifest_write)
    with pytest.raises(StateError, match="Could not synchronize manifest artifact"):
        store.finalize_publication_compensation(
            run,
            reason="verified no remote mutation remains",
            evidence={"remote_state": "absent"},
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
