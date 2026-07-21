"""Durable run manifests and an append-only, hash-chained event ledger."""

from __future__ import annotations

import builtins
import hashlib
import json
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from autocontribute.domain import ALLOWED_TRANSITIONS, RunManifest, RunStatus, utc_now
from autocontribute.exceptions import StateError


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


class RunStore:
    """Owns local state; model and repository code receive no database handle."""

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()
        self.runs_dir = self.root / "runs"
        self.workspaces_dir = self.root / "workspaces"
        self.database_path = self.root / "state.sqlite3"
        self.root.mkdir(parents=True, exist_ok=True)
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        self.workspaces_dir.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.database_path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    repository TEXT,
                    issue_number INTEGER,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    manifest_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS runs_status_idx ON runs(status);
                CREATE INDEX IF NOT EXISTS runs_candidate_idx
                    ON runs(repository, issue_number, status);

                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL REFERENCES runs(run_id),
                    occurred_at TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE
                );
                CREATE INDEX IF NOT EXISTS events_run_idx ON events(run_id, id);
                """
            )

    def create_run(self) -> RunManifest:
        now = utc_now()
        manifest = RunManifest(
            run_id=uuid.uuid4().hex[:16],
            status=RunStatus.QUEUED,
            created_at=now,
            updated_at=now,
        )
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO runs(run_id, status, created_at, updated_at, manifest_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    manifest.run_id,
                    manifest.status.value,
                    manifest.created_at.isoformat(),
                    manifest.updated_at.isoformat(),
                    manifest.model_dump_json(),
                ),
            )
            self._append_event(connection, manifest.run_id, "run.created", {"status": "queued"})
        self._write_manifest(manifest)
        return manifest

    def get(self, run_id: str) -> RunManifest:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT manifest_json FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
        if row is None:
            raise StateError(f"Unknown run: {run_id}")
        return RunManifest.model_validate_json(row["manifest_json"])

    def list(self, *, limit: int = 20) -> list[RunManifest]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT manifest_json FROM runs ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [RunManifest.model_validate_json(row["manifest_json"]) for row in rows]

    def save(self, manifest: RunManifest, *, event: str, details: dict[str, str]) -> None:
        manifest.updated_at = utc_now()
        candidate = manifest.candidate
        with self._connection() as connection:
            result = connection.execute(
                """
                UPDATE runs
                SET status = ?, repository = ?, issue_number = ?, updated_at = ?, manifest_json = ?
                WHERE run_id = ?
                """,
                (
                    manifest.status.value,
                    candidate.repository if candidate else None,
                    candidate.number if candidate else None,
                    manifest.updated_at.isoformat(),
                    manifest.model_dump_json(),
                    manifest.run_id,
                ),
            )
            if result.rowcount != 1:
                raise StateError(f"Unknown run: {manifest.run_id}")
            self._append_event(connection, manifest.run_id, event, details)
        self._write_manifest(manifest)

    def transition(
        self,
        manifest: RunManifest,
        target: RunStatus,
        *,
        reason: str,
    ) -> RunManifest:
        if target == manifest.status:
            return manifest
        allowed = ALLOWED_TRANSITIONS.get(manifest.status, set())
        if target not in allowed:
            raise StateError(f"Invalid run transition: {manifest.status.value} -> {target.value}")
        previous = manifest.status
        manifest.status = target
        self.save(
            manifest,
            event="run.transitioned",
            details={"from": previous.value, "to": target.value, "reason": reason},
        )
        return manifest

    def has_active_candidate(self, repository: str, issue_number: int) -> bool:
        terminal = (
            RunStatus.SKIPPED.value,
            RunStatus.REJECTED.value,
            RunStatus.FAILED.value,
            RunStatus.CANCELLED.value,
        )
        placeholders = ",".join("?" for _ in terminal)
        query = (
            "SELECT 1 FROM runs WHERE repository = ? AND issue_number = ? "
            f"AND status NOT IN ({placeholders}) LIMIT 1"
        )
        with self._connection() as connection:
            row = connection.execute(query, (repository, issue_number, *terminal)).fetchone()
        return row is not None

    def artifact_dir(self, run_id: str) -> Path:
        path = self.runs_dir / run_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def workspace_dir(self, run_id: str) -> Path:
        path = self.workspaces_dir / run_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def write_artifact(self, run_id: str, relative_path: str, content: str) -> Path:
        root = self.artifact_dir(run_id).resolve()
        target = (root / relative_path).resolve()
        if root not in target.parents:
            raise StateError("Artifact path escaped the run directory")
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(target.suffix + ".tmp")
        temporary.write_text(content, encoding="utf-8")
        temporary.replace(target)
        return target

    def events(self, run_id: str) -> builtins.list[dict[str, str]]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT occurred_at, event_type, details_json, previous_hash, event_hash
                FROM events WHERE run_id = ? ORDER BY id
                """,
                (run_id,),
            ).fetchall()
        return [
            {
                "occurred_at": row["occurred_at"],
                "event_type": row["event_type"],
                "details": row["details_json"],
                "previous_hash": row["previous_hash"],
                "event_hash": row["event_hash"],
            }
            for row in rows
        ]

    def _append_event(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        event_type: str,
        details: dict[str, str],
    ) -> None:
        row = connection.execute(
            "SELECT event_hash FROM events WHERE run_id = ? ORDER BY id DESC LIMIT 1",
            (run_id,),
        ).fetchone()
        previous_hash = row["event_hash"] if row else "0" * 64
        occurred_at = utc_now().isoformat()
        details_json = _canonical_json(details)
        payload = _canonical_json(
            {
                "run_id": run_id,
                "occurred_at": occurred_at,
                "event_type": event_type,
                "details": details_json,
                "previous_hash": previous_hash,
            }
        )
        event_hash = hashlib.sha256(payload.encode()).hexdigest()
        connection.execute(
            """
            INSERT INTO events(
                run_id, occurred_at, event_type, details_json, previous_hash, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (run_id, occurred_at, event_type, details_json, previous_hash, event_hash),
        )

    def _write_manifest(self, manifest: RunManifest) -> None:
        path = self.artifact_dir(manifest.run_id) / "manifest.json"
        temporary = path.with_suffix(".json.tmp")
        temporary.write_text(
            json.dumps(manifest.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)


__all__ = ["RunStore"]
