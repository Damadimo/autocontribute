"""Durable run manifests and an append-only, hash-chained event ledger."""

from __future__ import annotations

import builtins
import hashlib
import json
import os
import re
import sqlite3
import stat
import tempfile
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Final, cast

from autocontribute.domain import (
    ALLOWED_TRANSITIONS,
    IssueCandidate,
    RunManifest,
    RunStatus,
    utc_now,
)
from autocontribute.exceptions import CircuitBreakerTrigger, StateError
from autocontribute.github_origin import canonical_api_origin
from autocontribute.issue_revision import compute_issue_revision
from autocontribute.lifecycle import (
    PullRequestLifecycleSnapshot,
    parse_lifecycle_snapshot_json,
    parse_pull_request_url,
)

CURRENT_SCHEMA_VERSION: Final = 8
_MAX_GENERATION: Final = 2**63 - 1
_MAX_ACTIVE_CIRCUIT_BREAKER_TRIGGERS: Final = 10_000
_MAX_LIFECYCLE_SNAPSHOT_BYTES: Final = 2_000_000
_MAX_LIFECYCLE_SNAPSHOT_CORPUS: Final = 100_000
_MAX_RUN_CORPUS: Final = 10_000
_MAX_EVALUATION_EVENT_CORPUS: Final = 10_000
_UPSTREAM_OUTCOME_CURSOR_DOMAIN: Final = b"autocontribute.upstream-outcome-corpus.v1\x00"
_GITHUB_LOGIN: Final = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_CANDIDATE_REPOSITORY: Final = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_GIT_SHA: Final = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_REQUIRED_STORAGE_ROOT_ENV: Final = "AUTOCONTRIBUTE_REQUIRED_STORAGE_ROOT"
_REQUIRED_WORKSPACE_ROOT_ENV: Final = "AUTOCONTRIBUTE_REQUIRED_WORKSPACE_ROOT"
_OFFLINE_VERIFICATION: Final = object()
_INITIAL_EVENT_HASH: Final = "0" * 64
_METADATA_COLUMNS: Final = {"singleton", "schema_version", "migrated_at"}
_V3_RUN_COLUMNS: Final = {
    "run_id",
    "status",
    "repository",
    "issue_number",
    "created_at",
    "updated_at",
    "manifest_json",
}
_V4_RUN_COLUMNS: Final = {
    *_V3_RUN_COLUMNS,
    "event_count",
    "event_head_hash",
}
_RUN_COLUMNS: Final = {
    *_V4_RUN_COLUMNS,
    "issue_revision",
}
_EVENT_COLUMNS: Final = {
    "id",
    "run_id",
    "occurred_at",
    "event_type",
    "details_json",
    "previous_hash",
    "event_hash",
}
_LEASE_COLUMNS: Final = {
    "lease_name",
    "owner",
    "generation",
    "acquired_at",
    "heartbeat_at",
    "expires_at",
}
_LEASE_GENERATION_COLUMNS: Final = {
    "lease_name",
    "generation",
}
_LIFECYCLE_SNAPSHOT_COLUMNS: Final = {
    "id",
    "run_id",
    "fingerprint",
    "observed_at",
    "snapshot_json",
}
_CIRCUIT_BREAKER_COLUMNS: Final = {
    "singleton",
    "is_tripped",
    "epoch",
    "changed_at",
    "source",
    "reason",
    "trigger_hash",
}
_CIRCUIT_BREAKER_EVENT_COLUMNS: Final = {
    "id",
    "epoch",
    "occurred_at",
    "event_type",
    "source",
    "reason",
    "trigger_hash",
}
_PUBLICATION_RESERVATION_COLUMNS: Final = {
    "run_id",
    "repository",
    "reserved_at",
}
_V4_PUBLICATION_GATE_HOLD_COLUMNS: Final = {
    "run_id",
    "deployment_fingerprint",
    "corpus_cursor",
    "held_at",
}
_PUBLICATION_GATE_HOLD_COLUMNS: Final = {
    *_V4_PUBLICATION_GATE_HOLD_COLUMNS,
    "outcome_corpus_cursor",
}
_MANIFEST_ARTIFACT_SYNC_COLUMNS: Final = {
    "run_id",
    "updated_at",
    "manifest_sha256",
}
_CANDIDATE_RETRY_AUTHORIZATION_COLUMNS: Final = {
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
}
_LEGACY_CANDIDATE_RETRY_OVERRIDE_COLUMNS: Final = {
    "event_id",
    "run_id",
    "event_hash",
    "migrated_at",
}
_PUBLICATION_EVIDENCE_EVENT_TYPES: Final = (
    "publication.reserved",
    "publication.reservation.legacy",
    "publication.gate.held",
    "publication.gate.legacy",
    "publication.gate.rebound",
    "publication.gate.released",
)
_MAX_PUBLICATION_EVIDENCE_EVENTS: Final = _MAX_RUN_CORPUS * 4
_LEGACY_INDEXES: Final = {
    "runs_status_idx",
    "runs_candidate_idx",
    "events_run_idx",
}
_V2_REQUIRED_INDEXES: Final = {
    *_LEGACY_INDEXES,
    "leases_expiry_idx",
    "lifecycle_snapshots_run_idx",
    "circuit_breaker_events_epoch_idx",
}
_V6_REQUIRED_INDEXES: Final = {
    *_V2_REQUIRED_INDEXES,
    "publication_reservations_reserved_at_idx",
    "publication_reservations_repository_idx",
}
_V7_REQUIRED_INDEXES: Final = {
    *_V6_REQUIRED_INDEXES,
    "runs_candidate_revision_idx",
}
_REQUIRED_INDEXES: Final = {
    *_V7_REQUIRED_INDEXES,
    "runs_active_candidate_idx",
}

_CANDIDATE_CLAIM_LEASE_NAME: Final = "autocontribute.run"

# A completed local run can still represent an active upstream contribution. In particular, an
# open pull request must continue blocking duplicate work for the same issue.
_CANDIDATE_RELEASED_STATUSES: Final = frozenset(
    {
        RunStatus.SKIPPED,
        RunStatus.REJECTED,
        RunStatus.FAILED,
        RunStatus.CANCELLED,
    }
)
_CANDIDATE_SUPPRESSED_STATUSES: Final = frozenset(
    {
        RunStatus.SKIPPED,
        RunStatus.REJECTED,
        RunStatus.CANCELLED,
    }
)

# Only stages that are safe to abandon and recreate are crash-recoverable. Approval waits are
# durable operator state, and SUBMITTING requires remote reconciliation before it can be changed.
RECOVERABLE_IN_FLIGHT_STATUSES: Final = frozenset(
    {
        RunStatus.QUEUED,
        RunStatus.DISCOVERING,
        RunStatus.CANDIDATE_SELECTED,
        RunStatus.ELIGIBILITY_CHECKED,
        RunStatus.PLANNING,
        RunStatus.IMPLEMENTING,
        RunStatus.VALIDATING,
        RunStatus.CRITIQUING,
    }
)


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _validate_evaluation_anchor_details(details: dict[str, str]) -> None:
    _validate_event_details(details, field="evaluation anchor details")


def _validate_event_details(details: dict[str, str], *, field: str) -> None:
    if not isinstance(details, dict):
        raise TypeError(f"{field} must be a dictionary")
    if not details or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in details.items()
    ):
        raise ValueError(f"{field} must contain string keys and values")
    if len(_canonical_json(details).encode("utf-8")) > 20_000:
        raise ValueError(f"{field} exceeds the storage limit")


def _stored_event_details(value: object, *, field: str) -> dict[str, str]:
    if not isinstance(value, str):
        raise StateError(f"{field} contains invalid stored values")
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise StateError(f"{field} contains malformed details") from exc
    if not isinstance(parsed, dict) or not all(
        isinstance(key, str) and isinstance(item, str) for key, item in parsed.items()
    ):
        raise StateError(f"{field} contains malformed details")
    return parsed


def _assert_merged_publication_compensation_events(
    connection: sqlite3.Connection,
    manifest: RunManifest,
    *,
    pull_request_url: str,
) -> None:
    """Bind merged adoption to the exact base race and later remote observation."""

    if (
        manifest.candidate is None
        or manifest.base_sha is None
        or manifest.branch_name is None
        or manifest.commit_sha is None
        or manifest.publishing_login is None
        or manifest.publishing_api_origin is None
        or manifest.upstream_repository_id is None
        or manifest.upstream_repository_node_id is None
        or manifest.fork_repository_id is None
        or manifest.fork_repository_node_id is None
        or manifest.pull_request_node_id is None
    ):
        raise StateError("Merged publication compensation lacks durable identity")
    repository, number = parse_pull_request_url(
        pull_request_url,
        api_origin=manifest.publishing_api_origin,
    )
    if repository.casefold() != manifest.candidate.repository.casefold():
        raise StateError("Merged publication compensation belongs to another repository")
    expected_fork = f"{manifest.publishing_login}/{manifest.candidate.repository.split('/', 1)[1]}"
    rows = connection.execute(
        """
        SELECT id, event_type, details_json FROM events
        WHERE run_id = ? AND event_type IN (
            'branch.pushed',
            'pull_request.created.response',
            'pull_request.created.rejected',
            'publication.compensation.started',
            'pull_request.compensation.reconciled'
        )
        ORDER BY id
        """,
        (manifest.run_id,),
    ).fetchall()
    grouped: dict[str, builtins.list[sqlite3.Row]] = {}
    for row in rows:
        event_type = row["event_type"]
        if not isinstance(event_type, str):
            raise StateError("Merged publication compensation has invalid event identity")
        grouped.setdefault(event_type, []).append(row)
    singular = (
        "branch.pushed",
        "pull_request.created.response",
        "pull_request.created.rejected",
        "publication.compensation.started",
    )
    if any(len(grouped.get(event_type, ())) != 1 for event_type in singular):
        raise StateError(
            "Merged publication compensation lacks one exact branch, response, rejection, and "
            "marker"
        )
    reconciliations = grouped.get("pull_request.compensation.reconciled", [])
    if not reconciliations:
        raise StateError("Merged publication compensation lacks a remote merged observation")

    branch_row = grouped["branch.pushed"][0]
    response_row = grouped["pull_request.created.response"][0]
    rejection_row = grouped["pull_request.created.rejected"][0]
    marker_row = grouped["publication.compensation.started"][0]
    event_ids = (
        branch_row["id"],
        response_row["id"],
        rejection_row["id"],
        marker_row["id"],
        *(row["id"] for row in reconciliations),
    )
    if not all(
        isinstance(event_id, int) and not isinstance(event_id, bool) and event_id > 0
        for event_id in event_ids
    ) or tuple(event_ids) != tuple(sorted(event_ids)):
        raise StateError("Merged publication compensation evidence is out of order")
    latest = connection.execute(
        "SELECT id FROM events WHERE run_id = ? ORDER BY id DESC LIMIT 1",
        (manifest.run_id,),
    ).fetchone()
    if latest is None or latest["id"] != reconciliations[-1]["id"]:
        raise StateError(
            "Merged publication compensation observation is not the latest run evidence"
        )

    branch = _stored_event_details(
        branch_row["details_json"],
        field="published contribution branch",
    )
    response = _stored_event_details(
        response_row["details_json"],
        field="created pull-request response",
    )
    rejection = _stored_event_details(
        rejection_row["details_json"],
        field="created pull-request rejection",
    )
    marker = _stored_event_details(
        marker_row["details_json"],
        field="publication compensation marker",
    )
    returned_base = marker.get("returned_base_sha", "").casefold()
    if not _GIT_SHA.fullmatch(returned_base) or returned_base == manifest.base_sha.casefold():
        raise StateError("Merged publication compensation marker lacks an exact base race")
    expected_marker = {
        "reason": "created_pr_base_moved",
        "url": pull_request_url,
        "pull_request_node_id": manifest.pull_request_node_id,
        "repository": repository,
        "number": str(number),
        "upstream_repository_id": str(manifest.upstream_repository_id),
        "upstream_repository_node_id": manifest.upstream_repository_node_id,
        "fork": expected_fork,
        "fork_repository_id": str(manifest.fork_repository_id),
        "fork_repository_node_id": manifest.fork_repository_node_id,
        "branch": manifest.branch_name,
        "commit_sha": manifest.commit_sha,
        "approved_base_sha": manifest.base_sha,
        "returned_base_sha": marker.get("returned_base_sha", ""),
    }
    if marker != expected_marker:
        raise StateError("Merged publication compensation marker differs from durable intent")
    if branch != {
        "fork": expected_fork,
        "fork_repository_id": str(manifest.fork_repository_id),
        "fork_repository_node_id": manifest.fork_repository_node_id,
        "upstream_repository_id": str(manifest.upstream_repository_id),
        "upstream_repository_node_id": manifest.upstream_repository_node_id,
        "branch": manifest.branch_name,
        "commit_sha": manifest.commit_sha,
    }:
        raise StateError("Merged publication compensation branch differs from durable intent")
    if response != {
        "url": pull_request_url,
        "repository": repository,
        "number": str(number),
        "state": "open",
        "head_sha": manifest.commit_sha,
        "base_sha": marker["returned_base_sha"],
        "pull_request_node_id": manifest.pull_request_node_id,
        "upstream_repository_id": str(manifest.upstream_repository_id),
        "upstream_repository_node_id": manifest.upstream_repository_node_id,
        "fork_repository_id": str(manifest.fork_repository_id),
        "fork_repository_node_id": manifest.fork_repository_node_id,
    }:
        raise StateError("Merged publication compensation response differs from durable intent")
    if set(rejection) != {
        "url",
        "mismatches",
        "expected_base_sha",
        "returned_base_sha",
    }:
        raise StateError("Merged publication compensation rejection is malformed")
    mismatches = tuple(item.strip() for item in rejection["mismatches"].split(","))
    if (
        rejection["url"] != pull_request_url
        or rejection["expected_base_sha"].casefold() != manifest.base_sha.casefold()
        or rejection["returned_base_sha"].casefold() != returned_base
        or "base commit" not in mismatches
    ):
        raise StateError("Merged publication compensation rejection lacks the exact base race")
    expected_reconciliation = {
        "url": pull_request_url,
        "pull_request_node_id": manifest.pull_request_node_id,
        "state": "merged",
        "head_sha": manifest.commit_sha,
        "upstream_repository_id": str(manifest.upstream_repository_id),
        "upstream_repository_node_id": manifest.upstream_repository_node_id,
        "fork_repository_id": str(manifest.fork_repository_id),
        "fork_repository_node_id": manifest.fork_repository_node_id,
    }
    if any(
        _stored_event_details(
            row["details_json"],
            field="merged pull-request reconciliation",
        )
        != expected_reconciliation
        for row in reconciliations
    ):
        raise StateError("Merged publication compensation observation differs from durable intent")


def _assert_failed_publication_compensation_events(
    connection: sqlite3.Connection,
    manifest: RunManifest,
    *,
    reason: str,
    evidence: dict[str, str],
) -> None:
    """Bind failed finalization to exact, ordered, hash-verified remote cleanup evidence."""

    if (
        manifest.candidate is None
        or manifest.branch_name is None
        or manifest.publishing_login is None
        or manifest.publishing_api_origin is None
        or manifest.upstream_repository_id is None
        or manifest.upstream_repository_node_id is None
    ):
        raise StateError("Publication compensation lacks durable identity")
    if (manifest.fork_repository_id is None) != (manifest.fork_repository_node_id is None):
        raise StateError("Publication compensation has partial immutable fork identity")
    expected_fork = f"{manifest.publishing_login}/{manifest.candidate.repository.split('/', 1)[1]}"
    fork_identity: dict[str, str]
    if manifest.fork_repository_id is None:
        branch_was_pushed = connection.execute(
            """
            SELECT 1 FROM events
            WHERE run_id = ? AND event_type = 'branch.pushed'
            LIMIT 1
            """,
            (manifest.run_id,),
        ).fetchone()
        if manifest.commit_sha is not None or branch_was_pushed is not None:
            raise StateError(
                "Publication compensation has unbound fork identity after a remote-capable stage"
            )
        fork_identity = {"fork_identity_state": "not_bound"}
    else:
        assert manifest.fork_repository_node_id is not None
        fork_identity = {
            "fork_identity_state": "bound",
            "fork_repository_id": str(manifest.fork_repository_id),
            "fork_repository_node_id": manifest.fork_repository_node_id,
        }
    expected_absence = {
        "repository": manifest.candidate.repository,
        "publishing_api_origin": manifest.publishing_api_origin,
        "upstream_repository_id": str(manifest.upstream_repository_id),
        "upstream_repository_node_id": manifest.upstream_repository_node_id,
        "head": f"{manifest.publishing_login}:{manifest.branch_name}",
        "fork": expected_fork,
        **fork_identity,
        "branch": manifest.branch_name,
        "commit_sha": manifest.commit_sha or "not_persisted",
        "reason": reason,
    }
    if (
        manifest.pull_request_url is None
        and not manifest.pull_request_creation_started
        and evidence
        == {
            **expected_absence,
            "pull_request": "absent",
            "remote_branch": "absent",
        }
    ):
        row = connection.execute(
            """
            SELECT id, details_json FROM events
            WHERE run_id = ? AND event_type = 'publication.absence.verified'
            ORDER BY id DESC LIMIT 1
            """,
            (manifest.run_id,),
        ).fetchone()
        latest = connection.execute(
            "SELECT id FROM events WHERE run_id = ? ORDER BY id DESC LIMIT 1",
            (manifest.run_id,),
        ).fetchone()
        if (
            row is None
            or latest is None
            or row["id"] != latest["id"]
            or _stored_event_details(
                row["details_json"],
                field="publication absence verification",
            )
            != expected_absence
        ):
            raise StateError("Publication compensation lacks the latest exact absence verification")
        return

    if (
        manifest.publication_compensation_reason != "created_pr_base_moved"
        or manifest.base_sha is None
        or manifest.commit_sha is None
        or manifest.publishing_api_origin is None
        or manifest.upstream_repository_id is None
        or manifest.upstream_repository_node_id is None
        or manifest.fork_repository_id is None
        or manifest.fork_repository_node_id is None
        or manifest.pull_request_url is None
        or manifest.pull_request_node_id is None
    ):
        raise StateError("Publication compensation lacks exact remote cleanup evidence")
    repository, number = parse_pull_request_url(
        manifest.pull_request_url,
        api_origin=manifest.publishing_api_origin,
    )
    if repository.casefold() != manifest.candidate.repository.casefold():
        raise StateError("Publication compensation belongs to another repository")
    expected_final = {
        "url": manifest.pull_request_url,
        "repository": repository,
        "number": str(number),
        "pull_request_node_id": manifest.pull_request_node_id,
        "upstream_repository_id": str(manifest.upstream_repository_id),
        "upstream_repository_node_id": manifest.upstream_repository_node_id,
        "fork": expected_fork,
        "fork_repository_id": str(manifest.fork_repository_id),
        "fork_repository_node_id": manifest.fork_repository_node_id,
        "branch": manifest.branch_name,
        "commit_sha": manifest.commit_sha,
        "pull_request": "closed_unmerged",
        "remote_branch": "absent",
        "reason": reason,
    }
    if evidence != expected_final:
        raise StateError("Publication compensation evidence differs from durable intent")

    rows = connection.execute(
        """
        SELECT id, event_type, details_json FROM events
        WHERE run_id = ? AND event_type IN (
            'branch.pushed',
            'pull_request.created.response',
            'pull_request.created.rejected',
            'publication.compensation.started',
            'pull_request.compensation.closed',
            'branch.compensated'
        )
        ORDER BY id
        """,
        (manifest.run_id,),
    ).fetchall()
    grouped: dict[str, builtins.list[sqlite3.Row]] = {}
    for row in rows:
        event_type = row["event_type"]
        if not isinstance(event_type, str):
            raise StateError("Publication compensation has invalid event identity")
        grouped.setdefault(event_type, []).append(row)
    singular = (
        "branch.pushed",
        "pull_request.created.response",
        "pull_request.created.rejected",
        "publication.compensation.started",
    )
    if any(len(grouped.get(event_type, ())) != 1 for event_type in singular):
        raise StateError(
            "Publication compensation lacks one exact branch, response, rejection, and marker"
        )
    closures = grouped.get("pull_request.compensation.closed", [])
    branches = grouped.get("branch.compensated", [])
    if not closures or not branches:
        raise StateError("Publication compensation lacks exact pull-request and branch cleanup")

    branch_row = grouped["branch.pushed"][0]
    response_row = grouped["pull_request.created.response"][0]
    rejection_row = grouped["pull_request.created.rejected"][0]
    marker_row = grouped["publication.compensation.started"][0]
    ordered_ids = (
        branch_row["id"],
        response_row["id"],
        rejection_row["id"],
        marker_row["id"],
        closures[-1]["id"],
        branches[-1]["id"],
    )
    if not all(
        isinstance(event_id, int) and not isinstance(event_id, bool) and event_id > 0
        for event_id in ordered_ids
    ) or tuple(ordered_ids) != tuple(sorted(ordered_ids)):
        raise StateError("Publication compensation evidence is out of order")
    marker_id = marker_row["id"]
    if any(row["id"] <= marker_id for row in (*closures, *branches)):
        raise StateError("Publication compensation cleanup evidence precedes its marker")
    latest = connection.execute(
        "SELECT id FROM events WHERE run_id = ? ORDER BY id DESC LIMIT 1",
        (manifest.run_id,),
    ).fetchone()
    if latest is None or latest["id"] != branches[-1]["id"]:
        raise StateError("Publication compensation branch cleanup is not the latest run evidence")

    marker = _stored_event_details(
        marker_row["details_json"],
        field="publication compensation marker",
    )
    returned_base = marker.get("returned_base_sha", "").casefold()
    if not _GIT_SHA.fullmatch(returned_base) or returned_base == manifest.base_sha.casefold():
        raise StateError("Publication compensation marker lacks an exact base race")
    expected_marker = {
        "reason": "created_pr_base_moved",
        "url": manifest.pull_request_url,
        "pull_request_node_id": manifest.pull_request_node_id,
        "repository": repository,
        "number": str(number),
        "upstream_repository_id": str(manifest.upstream_repository_id),
        "upstream_repository_node_id": manifest.upstream_repository_node_id,
        "fork": expected_fork,
        "fork_repository_id": str(manifest.fork_repository_id),
        "fork_repository_node_id": manifest.fork_repository_node_id,
        "branch": manifest.branch_name,
        "commit_sha": manifest.commit_sha,
        "approved_base_sha": manifest.base_sha,
        "returned_base_sha": marker.get("returned_base_sha", ""),
    }
    if marker != expected_marker:
        raise StateError("Publication compensation marker differs from durable intent")
    expected_branch = {
        "fork": expected_fork,
        "fork_repository_id": str(manifest.fork_repository_id),
        "fork_repository_node_id": manifest.fork_repository_node_id,
        "upstream_repository_id": str(manifest.upstream_repository_id),
        "upstream_repository_node_id": manifest.upstream_repository_node_id,
        "branch": manifest.branch_name,
        "commit_sha": manifest.commit_sha,
    }
    if (
        _stored_event_details(
            branch_row["details_json"],
            field="published contribution branch",
        )
        != expected_branch
    ):
        raise StateError("Publication compensation branch differs from durable intent")
    expected_response = {
        "url": manifest.pull_request_url,
        "repository": repository,
        "number": str(number),
        "state": "open",
        "head_sha": manifest.commit_sha,
        "base_sha": marker["returned_base_sha"],
        "pull_request_node_id": manifest.pull_request_node_id,
        "upstream_repository_id": str(manifest.upstream_repository_id),
        "upstream_repository_node_id": manifest.upstream_repository_node_id,
        "fork_repository_id": str(manifest.fork_repository_id),
        "fork_repository_node_id": manifest.fork_repository_node_id,
    }
    if (
        _stored_event_details(
            response_row["details_json"],
            field="created pull-request response",
        )
        != expected_response
    ):
        raise StateError("Publication compensation response differs from durable intent")
    rejection = _stored_event_details(
        rejection_row["details_json"],
        field="created pull-request rejection",
    )
    if set(rejection) != {
        "url",
        "mismatches",
        "expected_base_sha",
        "returned_base_sha",
    }:
        raise StateError("Publication compensation rejection is malformed")
    mismatches = tuple(item.strip() for item in rejection["mismatches"].split(","))
    if (
        rejection["url"] != manifest.pull_request_url
        or rejection["expected_base_sha"].casefold() != manifest.base_sha.casefold()
        or rejection["returned_base_sha"].casefold() != returned_base
        or "base commit" not in mismatches
    ):
        raise StateError("Publication compensation rejection lacks the exact base race")
    expected_close = {
        "url": manifest.pull_request_url,
        "state": "closed_unmerged",
    }
    if any(
        _stored_event_details(
            row["details_json"],
            field="pull-request compensation closure",
        )
        != expected_close
        for row in closures
    ):
        raise StateError("Publication compensation closure differs from durable intent")
    expected_compensated_branch = {
        "fork": expected_fork,
        "fork_repository_id": str(manifest.fork_repository_id),
        "fork_repository_node_id": manifest.fork_repository_node_id,
        "branch": manifest.branch_name,
        "commit_sha": manifest.commit_sha,
    }
    if any(
        _stored_event_details(
            row["details_json"],
            field="compensated publication branch",
        )
        != expected_compensated_branch
        for row in branches
    ):
        raise StateError("Publication compensation branch cleanup differs from durable intent")


def _normalized_schema_sql(value: str | None) -> str | None:
    """Normalize harmless formatting while preserving literals in sqlite_schema SQL."""

    if value is None:
        return None
    normalized: list[str] = []
    quote: str | None = None
    index = 0
    while index < len(value):
        character = value[index]
        if quote is not None:
            normalized.append(character)
            if character == quote:
                if quote != "]" and index + 1 < len(value) and value[index + 1] == quote:
                    index += 1
                    normalized.append(value[index])
                else:
                    quote = None
        elif character.isspace():
            pass
        elif character in {"'", '"', "`"}:
            quote = character
            normalized.append(character)
        elif character == "[":
            quote = "]"
            normalized.append(character)
        else:
            normalized.append(character.casefold())
        index += 1
    return "".join(normalized)


class CandidateAttemptState(StrEnum):
    AVAILABLE = "available"
    ACTIVE = "active"
    SUPPRESSED = "suppressed"


@dataclass(frozen=True, slots=True)
class CandidateAttemptDisposition:
    state: CandidateAttemptState
    issue_revision: str
    prior_run_id: str | None = None
    prior_status: RunStatus | None = None


@dataclass(frozen=True, slots=True)
class CandidateRetryAuthorization:
    actor: str
    reason: str

    def __post_init__(self) -> None:
        """Reject non-canonical provenance before any run or remote work begins."""

        _candidate_retry_authorization(self)


@dataclass(frozen=True, slots=True)
class Lease:
    name: str
    owner: str
    generation: int
    acquired_at: datetime
    heartbeat_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class LifecycleSnapshot:
    """One verified row; ``observed_at`` is non-authoritative storage metadata.

    Upstream outcome decisions must use timestamps inside ``snapshot_json`` and immutable ledger
    order. The local polling time neither contributes to the fingerprint nor proves an outcome.
    """

    run_id: str
    fingerprint: str
    observed_at: datetime
    snapshot_json: str


@dataclass(frozen=True, slots=True)
class CircuitBreakerStatus:
    is_tripped: bool
    epoch: int
    changed_at: datetime
    source: str | None
    reason: str | None
    trigger_hash: str | None
    active_revision: str | None
    active_triggers: tuple[CircuitBreakerTrigger, ...]


@dataclass(frozen=True, slots=True)
class PublicationReservation:
    run_id: str
    repository: str
    reserved_at: datetime


@dataclass(frozen=True, slots=True)
class PublicationGateHold:
    run_id: str
    deployment_fingerprint: str | None
    corpus_cursor: str
    outcome_corpus_cursor: str | None
    held_at: datetime


@dataclass(frozen=True, slots=True)
class _PublicationReservationRequest:
    run_id: str
    repository: str
    max_per_utc_day: int
    reserved_at: datetime
    day_start: datetime
    day_end: datetime
    cooldown_start: datetime
    enforce_cooldown: bool
    evaluation_corpus_cursor: str | None
    evaluation_deployment_fingerprint: str | None
    outcome_corpus_cursor: str | None
    publishing_login: str | None
    publishing_api_origin: str | None


@dataclass(frozen=True, slots=True)
class _PublicationReservationResult:
    reservation: PublicationReservation
    reservation_created: bool
    hold_created: bool


@dataclass(frozen=True, slots=True)
class _PublicationReservationEvidence:
    run_id: str
    repository: str
    reserved_at: str


@dataclass(frozen=True, slots=True)
class _PublicationGateEvidence:
    run_id: str
    deployment_fingerprint: str | None
    corpus_cursor: str
    outcome_corpus_cursor: str | None
    held_at: str


class _ManifestArtifactSyncError(StateError):
    """A post-commit manifest publication failed while its durable marker remains pending."""


@dataclass(frozen=True, slots=True)
class _PublicationIntent:
    branch_name: str
    publication_draft: bool
    publication_ready_for_review: bool
    publishing_login: str
    publishing_api_origin: str
    commit_author_name: str
    commit_author_email: str
    commit_committer_name: str
    commit_committer_email: str

    def manifest_fields(self) -> dict[str, str | bool]:
        return {
            "branch_name": self.branch_name,
            "publication_draft": self.publication_draft,
            "publication_ready_for_review": self.publication_ready_for_review,
            "publishing_login": self.publishing_login,
            "publishing_api_origin": self.publishing_api_origin,
            "commit_author_name": self.commit_author_name,
            "commit_author_email": self.commit_author_email,
            "commit_committer_name": self.commit_committer_name,
            "commit_committer_email": self.commit_committer_email,
        }

    def event_details(self, *, repository: str) -> dict[str, str]:
        return {
            "repository": repository,
            "branch": self.branch_name,
            "draft": "true" if self.publication_draft else "false",
            "ready_for_review": "true" if self.publication_ready_for_review else "false",
            "publishing_login": self.publishing_login,
            "publishing_api_origin": self.publishing_api_origin,
            "commit_author_name": self.commit_author_name,
            "commit_author_email": self.commit_author_email,
            "commit_committer_name": self.commit_committer_name,
            "commit_committer_email": self.commit_committer_email,
        }


class RunStore:
    """Owns local state; model and repository code receive no database handle."""

    def __init__(self, root: Path, *, _mode: object | None = None) -> None:
        self.root = root.expanduser().resolve()
        self.runs_dir = self.root / "runs"
        self.workspaces_dir = self.root / "workspaces"
        self.database_path = self.root / "state.sqlite3"
        if _mode is None:
            self._validate_required_storage_root()
            self._validate_required_workspace_root()
        elif _mode is not _OFFLINE_VERIFICATION:
            raise TypeError("Unsupported run store construction mode")
        self.root.mkdir(parents=True, exist_ok=True)
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        self.workspaces_dir.mkdir(parents=True, exist_ok=True)
        self._initialize()
        self.synchronize_manifest_artifacts()

    @classmethod
    def _for_offline_verification(cls, root: Path) -> RunStore:
        """Open private staging state without applying live-deployment path bindings."""

        return cls(root, _mode=_OFFLINE_VERIFICATION)

    def _validate_required_storage_root(self) -> None:
        """Bind a hardened deployment to its preflight-verified durable-state mount."""

        required_value = os.environ.get(_REQUIRED_STORAGE_ROOT_ENV)
        if required_value is None:
            return
        if not required_value or "\0" in required_value:
            raise StateError("Required storage root is invalid")
        required = Path(required_value)
        if not required.is_absolute():
            raise StateError("Required storage root must be absolute")
        try:
            resolved = required.resolve(strict=True)
        except OSError as exc:
            raise StateError("Required storage root is unavailable") from exc
        if required != resolved:
            raise StateError("Required storage root must be an exact real path")
        if self.root != required:
            raise StateError("Configured storage path bypasses the required storage root")

    def _validate_required_workspace_root(self) -> None:
        """Bind a hardened deployment to its preflight-verified workspace mount."""

        required_value = os.environ.get(_REQUIRED_WORKSPACE_ROOT_ENV)
        if required_value is None:
            return
        if not required_value or "\0" in required_value:
            raise StateError("Required workspace root is invalid")
        required = Path(required_value)
        if not required.is_absolute():
            raise StateError("Required workspace root must be absolute")
        try:
            resolved = required.resolve(strict=True)
        except OSError as exc:
            raise StateError("Required workspace root is unavailable") from exc
        if required != resolved:
            raise StateError("Required workspace root must be an exact real path")
        if self.workspaces_dir != required:
            raise StateError("Configured storage path bypasses the required workspace root")

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
        connection = sqlite3.connect(self.database_path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            detected = self._detect_schema_version(connection)
            if detected > CURRENT_SCHEMA_VERSION:
                raise StateError(
                    f"State schema {detected} is newer than supported schema "
                    f"{CURRENT_SCHEMA_VERSION}"
                )
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("BEGIN IMMEDIATE")
            version = self._detect_schema_version(connection)
            if version > CURRENT_SCHEMA_VERSION:
                raise StateError(
                    f"State schema {version} is newer than supported schema "
                    f"{CURRENT_SCHEMA_VERSION}"
                )
            if version == 1 and "schema_metadata" not in self._table_names(connection):
                self._adopt_legacy_schema(connection)
            if version in {2, 3, 4, 5, 6, 7}:
                # Validate the complete source schema before executing migration SQL. This
                # prevents unexpected views or triggers from participating in the migration,
                # even though a later validation would ultimately roll the transaction back.
                self._validate_schema_version(connection, expected_version=version)
            while version < CURRENT_SCHEMA_VERSION:
                if version == 0:
                    self._migrate_0_to_1(connection)
                elif version == 1:
                    self._migrate_1_to_2(connection)
                elif version == 2:
                    self._migrate_2_to_3(connection)
                elif version == 3:
                    self._migrate_3_to_4(connection)
                elif version == 4:
                    self._migrate_4_to_5(connection)
                elif version == 5:
                    self._migrate_5_to_6(connection)
                elif version == 6:
                    self._migrate_6_to_7(connection)
                elif version == 7:
                    self._migrate_7_to_8(connection)
                else:  # pragma: no cover - guarded by the supported-version checks
                    raise StateError(f"No state migration is available from schema {version}")
                version += 1
            _reconcile_publication_state(
                connection,
                repair_missing=True,
                require_current_rollout_cursors=False,
            )
            self._validate_current_schema(connection)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _table_names(connection: sqlite3.Connection) -> set[str]:
        rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
        return {str(row["name"]) for row in rows}

    @staticmethod
    def _table_columns(connection: sqlite3.Connection, table: str) -> set[str]:
        if table not in {
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
        }:
            raise StateError(f"Refusing to inspect unexpected state table: {table}")
        rows = connection.execute(f"PRAGMA table_info({table})").fetchall()
        return {str(row["name"]) for row in rows}

    @staticmethod
    def _index_names(connection: sqlite3.Connection) -> set[str]:
        rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
        return {str(row["name"]) for row in rows}

    @classmethod
    def _detect_schema_version(cls, connection: sqlite3.Connection) -> int:
        tables = cls._table_names(connection)
        if not tables:
            return 0
        if "schema_metadata" in tables:
            if cls._table_columns(connection, "schema_metadata") != _METADATA_COLUMNS:
                raise StateError("State schema metadata has an unsupported shape")
            rows = connection.execute(
                "SELECT singleton, schema_version FROM schema_metadata"
            ).fetchall()
            if len(rows) != 1 or rows[0]["singleton"] != 1:
                raise StateError("State schema metadata must contain exactly one canonical row")
            version = rows[0]["schema_version"]
            if isinstance(version, bool) or not isinstance(version, int) or version < 1:
                raise StateError("State schema metadata contains an invalid version")
            return int(version)
        if tables != {"runs", "events"}:
            raise StateError("Unversioned state does not match the supported legacy schema")
        if cls._table_columns(connection, "runs") != _V3_RUN_COLUMNS:
            raise StateError("Legacy runs table has an unsupported shape")
        if cls._table_columns(connection, "events") != _EVENT_COLUMNS:
            raise StateError("Legacy events table has an unsupported shape")
        if not _LEGACY_INDEXES.issubset(cls._index_names(connection)):
            raise StateError("Legacy state database is missing one or more required indexes")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise StateError("Legacy state database contains invalid foreign-key references")
        return 1

    def _adopt_legacy_schema(self, connection: sqlite3.Connection) -> None:
        self._create_metadata_table(connection)
        connection.execute(
            """
            INSERT INTO schema_metadata(singleton, schema_version, migrated_at)
            VALUES (1, 1, ?)
            """,
            (utc_now().isoformat(),),
        )

    @classmethod
    def _migrate_0_to_1(cls, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE runs (
                run_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                repository TEXT,
                issue_number INTEGER,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                manifest_json TEXT NOT NULL
            )
            """
        )
        connection.execute("CREATE INDEX runs_status_idx ON runs(status)")
        connection.execute(
            "CREATE INDEX runs_candidate_idx ON runs(repository, issue_number, status)"
        )
        connection.execute(
            """
            CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL REFERENCES runs(run_id),
                occurred_at TEXT NOT NULL,
                event_type TEXT NOT NULL,
                details_json TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL UNIQUE
            )
            """
        )
        connection.execute("CREATE INDEX events_run_idx ON events(run_id, id)")
        cls._create_metadata_table(connection)
        connection.execute(
            """
            INSERT INTO schema_metadata(singleton, schema_version, migrated_at)
            VALUES (1, 1, ?)
            """,
            (utc_now().isoformat(),),
        )

    @staticmethod
    def _create_metadata_table(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE schema_metadata (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                schema_version INTEGER NOT NULL CHECK(schema_version >= 1),
                migrated_at TEXT NOT NULL
            )
            """
        )

    @staticmethod
    def _migrate_1_to_2(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE leases (
                lease_name TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                generation INTEGER NOT NULL CHECK(generation >= 1),
                acquired_at TEXT NOT NULL,
                heartbeat_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
            """
        )
        connection.execute("CREATE INDEX leases_expiry_idx ON leases(expires_at)")
        connection.execute(
            """
            CREATE TABLE lifecycle_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL REFERENCES runs(run_id),
                fingerprint TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                snapshot_json TEXT NOT NULL,
                UNIQUE(run_id, fingerprint)
            )
            """
        )
        connection.execute(
            "CREATE INDEX lifecycle_snapshots_run_idx ON lifecycle_snapshots(run_id, id)"
        )
        connection.execute(
            """
            CREATE TABLE circuit_breaker (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                is_tripped INTEGER NOT NULL CHECK(is_tripped IN (0, 1)),
                epoch INTEGER NOT NULL CHECK(epoch >= 1),
                changed_at TEXT NOT NULL,
                source TEXT,
                reason TEXT,
                trigger_hash TEXT,
                CHECK(
                    (is_tripped = 0 AND source IS NULL AND reason IS NULL
                        AND trigger_hash IS NULL)
                    OR
                    (is_tripped = 1 AND source IS NOT NULL AND reason IS NOT NULL
                        AND trigger_hash IS NOT NULL)
                )
            )
            """
        )
        connection.execute(
            """
            INSERT INTO circuit_breaker(
                singleton, is_tripped, epoch, changed_at, source, reason, trigger_hash
            ) VALUES (1, 0, 1, ?, NULL, NULL, NULL)
            """,
            (utc_now().isoformat(),),
        )
        connection.execute(
            """
            CREATE TABLE circuit_breaker_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                epoch INTEGER NOT NULL CHECK(epoch >= 1),
                occurred_at TEXT NOT NULL,
                event_type TEXT NOT NULL CHECK(event_type IN ('trip', 'resume')),
                source TEXT NOT NULL,
                reason TEXT NOT NULL,
                trigger_hash TEXT NOT NULL,
                UNIQUE(event_type, trigger_hash)
            )
            """
        )
        connection.execute(
            "CREATE INDEX circuit_breaker_events_epoch_idx ON circuit_breaker_events(epoch, id)"
        )
        connection.execute(
            """
            UPDATE schema_metadata
            SET schema_version = 2, migrated_at = ?
            WHERE singleton = 1 AND schema_version = 1
            """,
            (utc_now().isoformat(),),
        )
        if connection.execute("SELECT changes()").fetchone()[0] != 1:
            raise StateError("State schema changed while migration was in progress")

    @staticmethod
    def _migrate_2_to_3(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE publication_reservations (
                run_id TEXT PRIMARY KEY REFERENCES runs(run_id),
                repository TEXT NOT NULL,
                reserved_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX publication_reservations_reserved_at_idx
            ON publication_reservations(reserved_at)
            """
        )
        connection.execute(
            """
            CREATE INDEX publication_reservations_repository_idx
            ON publication_reservations(repository, reserved_at)
            """
        )
        migrated_at = utc_now()
        rows = connection.execute(
            """
            SELECT run_id, repository FROM runs
            WHERE status IN (?, ?)
            ORDER BY run_id
            """,
            (RunStatus.SUBMITTING.value, RunStatus.PR_OPEN.value),
        ).fetchall()
        for row in rows:
            run_id = _lease_identity(str(row["run_id"]), field="backfilled publication run id")
            repository_value = row["repository"]
            if not isinstance(repository_value, str):
                raise StateError(
                    f"Published run {run_id} lacks a repository for reservation backfill"
                )
            repository = _repository_identity(repository_value)
            connection.execute(
                """
                INSERT INTO publication_reservations(run_id, repository, reserved_at)
                VALUES (?, ?, ?)
                """,
                (run_id, repository, migrated_at.isoformat()),
            )
        connection.execute(
            """
            UPDATE schema_metadata
            SET schema_version = 3, migrated_at = ?
            WHERE singleton = 1 AND schema_version = 2
            """,
            (migrated_at.isoformat(),),
        )
        if connection.execute("SELECT changes()").fetchone()[0] != 1:
            raise StateError("State schema changed while migration was in progress")

    @staticmethod
    def _migrate_3_to_4(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            ALTER TABLE runs ADD COLUMN event_count INTEGER NOT NULL DEFAULT 0
            CHECK(event_count >= 0)
            """
        )
        connection.execute(
            f"""
            ALTER TABLE runs ADD COLUMN event_head_hash TEXT NOT NULL
            DEFAULT '{_INITIAL_EVENT_HASH}'
            CHECK(
                length(event_head_hash) = 64
                AND event_head_hash NOT GLOB '*[^0-9a-f]*'
            )
            """
        )
        run_rows = connection.execute("SELECT run_id FROM runs ORDER BY run_id").fetchall()
        event_rows = connection.execute(
            """
            SELECT id, run_id, occurred_at, event_type, details_json,
                   previous_hash, event_hash
            FROM events ORDER BY run_id ASC, id ASC
            """
        ).fetchall()
        heads = _verified_event_heads(run_rows, event_rows)
        for run_id, (event_count, event_head_hash) in heads.items():
            update = connection.execute(
                """
                UPDATE runs SET event_count = ?, event_head_hash = ?
                WHERE run_id = ? AND event_count = 0 AND event_head_hash = ?
                """,
                (event_count, event_head_hash, run_id, _INITIAL_EVENT_HASH),
            )
            if update.rowcount != 1:
                raise StateError(f"Run {run_id} changed while event heads were migrated")

        connection.execute(
            """
            CREATE TABLE lease_generations (
                lease_name TEXT PRIMARY KEY,
                generation INTEGER NOT NULL CHECK(generation >= 1)
            )
            """
        )
        lease_rows = connection.execute(
            "SELECT lease_name, generation FROM leases ORDER BY lease_name"
        ).fetchall()
        for row in lease_rows:
            lease_name = _lease_identity(row["lease_name"], field="stored lease name")
            generation = _stored_generation(
                row["generation"], field=f"lease {lease_name} generation"
            )
            connection.execute(
                "INSERT INTO lease_generations(lease_name, generation) VALUES (?, ?)",
                (lease_name, generation),
            )

        connection.execute(
            """
            CREATE TABLE publication_gate_holds (
                run_id TEXT PRIMARY KEY REFERENCES publication_reservations(run_id),
                deployment_fingerprint TEXT CHECK(
                    deployment_fingerprint IS NULL OR (
                        length(deployment_fingerprint) = 64
                        AND deployment_fingerprint NOT GLOB '*[^0-9a-f]*'
                    )
                ),
                corpus_cursor TEXT NOT NULL CHECK(
                    length(corpus_cursor) = 64
                    AND corpus_cursor NOT GLOB '*[^0-9a-f]*'
                ),
                held_at TEXT NOT NULL
            )
            """
        )
        migrated_at = utc_now().isoformat()
        submitting_reservations = connection.execute(
            """
            SELECT publication_reservations.run_id
            FROM publication_reservations
            JOIN runs USING(run_id)
            WHERE runs.status = ?
            ORDER BY publication_reservations.run_id
            """,
            (RunStatus.SUBMITTING.value,),
        ).fetchall()
        if submitting_reservations:
            corpus_cursor = _evaluation_corpus_cursor_from_connection(connection)
            for row in submitting_reservations:
                run_id = _lease_identity(row["run_id"], field="backfilled publication gate run id")
                connection.execute(
                    """
                    INSERT INTO publication_gate_holds(
                        run_id, deployment_fingerprint, corpus_cursor, held_at
                    ) VALUES (?, NULL, ?, ?)
                    """,
                    (run_id, corpus_cursor, migrated_at),
                )

        connection.execute(
            """
            UPDATE schema_metadata
            SET schema_version = 4, migrated_at = ?
            WHERE singleton = 1 AND schema_version = 3
            """,
            (migrated_at,),
        )
        if connection.execute("SELECT changes()").fetchone()[0] != 1:
            raise StateError("State schema changed while migration was in progress")

    @staticmethod
    def _migrate_4_to_5(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE manifest_artifact_sync (
                run_id TEXT PRIMARY KEY REFERENCES runs(run_id),
                updated_at TEXT NOT NULL,
                manifest_sha256 TEXT NOT NULL CHECK(
                    length(manifest_sha256) = 64
                    AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'
                )
            )
            """
        )
        _migrate_legacy_publication_evidence(connection)
        migrated_at = utc_now().isoformat()
        connection.execute(
            """
            UPDATE schema_metadata
            SET schema_version = 5, migrated_at = ?
            WHERE singleton = 1 AND schema_version = 4
            """,
            (migrated_at,),
        )
        if connection.execute("SELECT changes()").fetchone()[0] != 1:
            raise StateError("State schema changed while migration was in progress")

    @staticmethod
    def _migrate_5_to_6(connection: sqlite3.Connection) -> None:
        """Fence new automatic authority from pre-outcome-gate publication holds.

        Existing holds remain present but deliberately have a NULL outcome cursor. They can be
        inspected or compensated, but cannot be mistaken for schema-v6 automatic authority.
        """

        connection.execute(
            """
            ALTER TABLE publication_gate_holds
            ADD COLUMN outcome_corpus_cursor TEXT CHECK(
                outcome_corpus_cursor IS NULL OR (
                    length(outcome_corpus_cursor) = 64
                    AND outcome_corpus_cursor NOT GLOB '*[^0-9a-f]*'
                )
            )
            """
        )
        migrated_at = utc_now().isoformat()
        connection.execute(
            """
            UPDATE schema_metadata
            SET schema_version = 6, migrated_at = ?
            WHERE singleton = 1 AND schema_version = 5
            """,
            (migrated_at,),
        )
        if connection.execute("SELECT changes()").fetchone()[0] != 1:
            raise StateError("State schema changed while migration was in progress")

    @staticmethod
    def _migrate_6_to_7(connection: sqlite3.Connection) -> None:
        """Bind candidate rows to a stable digest of their complete issue evidence."""

        connection.execute(
            """
            ALTER TABLE runs ADD COLUMN issue_revision TEXT CHECK(
                issue_revision IS NULL OR (
                    length(issue_revision) = 64
                    AND issue_revision NOT GLOB '*[^0-9a-f]*'
                )
            )
            """
        )
        rows = connection.execute(
            """
            SELECT run_id, status, repository, issue_number, manifest_json
            FROM runs ORDER BY run_id
            """
        ).fetchall()
        if len(rows) > _MAX_RUN_CORPUS:
            raise StateError("Run corpus exceeds the supported issue-revision migration bound")
        for row in rows:
            try:
                run_id = _lease_identity(row["run_id"], field="stored run id")
            except (TypeError, ValueError) as exc:
                raise StateError("Issue-revision migration found an invalid run ID") from exc
            try:
                manifest = RunManifest.model_validate_json(row["manifest_json"])
            except (TypeError, ValueError) as exc:
                raise StateError(f"Run {run_id} contains an invalid manifest") from exc
            status = _stored_run_status(row["status"], run_id=run_id)
            if manifest.run_id != run_id or manifest.status != status:
                raise StateError(f"Run {run_id} manifest disagrees with its state row")
            candidate = manifest.candidate
            if candidate is None:
                if row["issue_number"] is not None:
                    raise StateError(f"Run {run_id} has issue identity without a candidate")
                continue
            if row["repository"] != candidate.repository or row["issue_number"] != candidate.number:
                raise StateError(f"Run {run_id} candidate disagrees with its state row")
            try:
                revision = compute_issue_revision(candidate)
            except (TypeError, ValueError) as exc:
                raise StateError(f"Run {run_id} has invalid issue revision evidence") from exc
            updated = connection.execute(
                """
                UPDATE runs SET issue_revision = ?
                WHERE run_id = ? AND issue_revision IS NULL
                """,
                (revision, run_id),
            )
            if updated.rowcount != 1:
                raise StateError(f"Run {run_id} changed during issue-revision migration")

        connection.execute(
            """
            CREATE INDEX runs_candidate_revision_idx
            ON runs(repository, issue_number, issue_revision, status)
            """
        )
        migrated_at = utc_now().isoformat()
        connection.execute(
            """
            UPDATE schema_metadata
            SET schema_version = 7, migrated_at = ?
            WHERE singleton = 1 AND schema_version = 6
            """,
            (migrated_at,),
        )
        if connection.execute("SELECT changes()").fetchone()[0] != 1:
            raise StateError("State schema changed while migration was in progress")

    @staticmethod
    def _migrate_7_to_8(connection: sqlite3.Connection) -> None:
        """Fence active claims and persist exact operator retry authorization."""

        duplicate = connection.execute(
            """
            SELECT lower(repository) AS repository_key, issue_number
            FROM runs
            WHERE issue_number IS NOT NULL
                AND status NOT IN (?, ?, ?, ?)
            GROUP BY lower(repository), issue_number
            HAVING count(*) > 1
            LIMIT 1
            """,
            tuple(sorted(status.value for status in _CANDIDATE_RELEASED_STATUSES)),
        ).fetchone()
        if duplicate is not None:
            raise StateError(
                "State migration found duplicate active attempts for one candidate issue"
            )
        connection.execute("DROP INDEX runs_candidate_revision_idx")
        connection.execute(
            """
            CREATE INDEX runs_candidate_revision_idx
            ON runs(repository COLLATE NOCASE, issue_number, issue_revision, status)
            """
        )
        connection.execute(
            """
            CREATE UNIQUE INDEX runs_active_candidate_idx
            ON runs(repository COLLATE NOCASE, issue_number)
            WHERE issue_number IS NOT NULL
                AND status NOT IN ('cancelled', 'failed', 'rejected', 'skipped')
            """
        )
        connection.execute(
            """
            CREATE TABLE candidate_retry_authorizations (
                authorization_id TEXT PRIMARY KEY CHECK(
                    length(authorization_id) = 32
                    AND authorization_id NOT GLOB '*[^0-9a-f]*'
                ),
                run_id TEXT NOT NULL UNIQUE REFERENCES runs(run_id),
                repository TEXT NOT NULL,
                issue_number INTEGER NOT NULL CHECK(issue_number >= 1),
                issue_revision TEXT NOT NULL CHECK(
                    length(issue_revision) = 64
                    AND issue_revision NOT GLOB '*[^0-9a-f]*'
                ),
                prior_run_id TEXT NOT NULL REFERENCES runs(run_id),
                prior_status TEXT NOT NULL CHECK(
                    prior_status IN ('cancelled', 'rejected', 'skipped')
                ),
                actor TEXT NOT NULL,
                reason TEXT NOT NULL,
                authorized_at TEXT NOT NULL,
                CHECK(run_id <> prior_run_id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE legacy_candidate_retry_overrides (
                event_id INTEGER PRIMARY KEY REFERENCES events(id),
                run_id TEXT NOT NULL UNIQUE REFERENCES runs(run_id),
                event_hash TEXT NOT NULL UNIQUE CHECK(
                    length(event_hash) = 64
                    AND event_hash NOT GLOB '*[^0-9a-f]*'
                ),
                migrated_at TEXT NOT NULL
            )
            """
        )
        legacy_events = connection.execute(
            """
            SELECT id, run_id, occurred_at, event_hash, details_json
            FROM events
            WHERE event_type = 'candidate.retry_override'
            ORDER BY id LIMIT ?
            """,
            (_MAX_RUN_CORPUS + 1,),
        ).fetchall()
        if len(legacy_events) > _MAX_RUN_CORPUS:
            raise StateError("Legacy candidate retry overrides exceed the migration bound")
        source_metadata = connection.execute(
            "SELECT migrated_at FROM schema_metadata WHERE singleton = 1"
        ).fetchone()
        if source_metadata is None:
            raise StateError("State schema metadata disappeared during migration")
        migration_time = max(
            _aware_utc(utc_now(), field="schema v8 migration time"),
            _stored_canonical_utc_datetime(
                source_metadata["migrated_at"],
                field="schema v7 migration time",
            ),
        )
        validated_legacy_events: list[tuple[int, str, str]] = []
        for event in legacy_events:
            event_id, run_id, event_hash = _validated_legacy_candidate_retry_override(
                connection,
                event_id=event["id"],
                run_id=event["run_id"],
                event_hash=event["event_hash"],
                details_json=event["details_json"],
            )
            migration_time = max(
                migration_time,
                _stored_datetime(
                    event["occurred_at"],
                    field="legacy candidate retry event time",
                ),
            )
            validated_legacy_events.append((event_id, run_id, event_hash))
        migrated_at = migration_time.isoformat()
        for event_id, run_id, event_hash in validated_legacy_events:
            connection.execute(
                """
                INSERT INTO legacy_candidate_retry_overrides(
                    event_id, run_id, event_hash, migrated_at
                ) VALUES (?, ?, ?, ?)
                """,
                (event_id, run_id, event_hash, migrated_at),
            )
        connection.execute(
            """
            UPDATE schema_metadata
            SET schema_version = 8, migrated_at = ?
            WHERE singleton = 1 AND schema_version = 7
            """,
            (migrated_at,),
        )
        if connection.execute("SELECT changes()").fetchone()[0] != 1:
            raise StateError("State schema changed while migration was in progress")

    @staticmethod
    def _schema_manifest(
        connection: sqlite3.Connection,
    ) -> tuple[tuple[str, str, str, str | None], ...]:
        rows = connection.execute(
            """
            SELECT type, name, tbl_name, sql FROM sqlite_schema
            WHERE type IN ('table', 'index', 'view', 'trigger')
            ORDER BY type, name, tbl_name
            """
        ).fetchall()
        manifest: list[tuple[str, str, str, str | None]] = []
        for row in rows:
            object_type, name, table_name, sql = row
            if not all(isinstance(value, str) for value in (object_type, name, table_name)):
                raise StateError("State database contains malformed schema metadata")
            if sql is not None and not isinstance(sql, str):
                raise StateError("State database contains malformed schema SQL")
            manifest.append(
                (
                    str(object_type),
                    str(name),
                    str(table_name),
                    _normalized_schema_sql(sql),
                )
            )
        return tuple(manifest)

    @classmethod
    def _expected_schema_manifest(
        cls, version: int
    ) -> tuple[tuple[str, str, str, str | None], ...]:
        if version not in {2, 3, 4, 5, 6, 7, CURRENT_SCHEMA_VERSION}:
            raise StateError(f"No canonical schema manifest exists for state version {version}")
        expected = sqlite3.connect(":memory:")
        expected.row_factory = sqlite3.Row
        expected.execute("PRAGMA foreign_keys = ON")
        try:
            cls._migrate_0_to_1(expected)
            cls._migrate_1_to_2(expected)
            if version >= 3:
                cls._migrate_2_to_3(expected)
            if version >= 4:
                cls._migrate_3_to_4(expected)
            if version >= 5:
                cls._migrate_4_to_5(expected)
            if version >= 6:
                cls._migrate_5_to_6(expected)
            if version >= 7:
                cls._migrate_6_to_7(expected)
            if version >= 8:
                cls._migrate_7_to_8(expected)
            return cls._schema_manifest(expected)
        finally:
            expected.close()

    @classmethod
    def _validate_schema_version(
        cls, connection: sqlite3.Connection, *, expected_version: int
    ) -> None:
        expected = {
            "schema_metadata": _METADATA_COLUMNS,
            "runs": (
                _RUN_COLUMNS
                if expected_version >= 7
                else _V4_RUN_COLUMNS
                if expected_version >= 4
                else _V3_RUN_COLUMNS
            ),
            "events": _EVENT_COLUMNS,
            "leases": _LEASE_COLUMNS,
            "lifecycle_snapshots": _LIFECYCLE_SNAPSHOT_COLUMNS,
            "circuit_breaker": _CIRCUIT_BREAKER_COLUMNS,
            "circuit_breaker_events": _CIRCUIT_BREAKER_EVENT_COLUMNS,
        }
        required_indexes = _V2_REQUIRED_INDEXES
        if expected_version >= 3:
            expected["publication_reservations"] = _PUBLICATION_RESERVATION_COLUMNS
            required_indexes = _V6_REQUIRED_INDEXES
        if expected_version >= 7:
            required_indexes = _V7_REQUIRED_INDEXES
        if expected_version >= 8:
            required_indexes = _REQUIRED_INDEXES
            expected["candidate_retry_authorizations"] = _CANDIDATE_RETRY_AUTHORIZATION_COLUMNS
            expected["legacy_candidate_retry_overrides"] = _LEGACY_CANDIDATE_RETRY_OVERRIDE_COLUMNS
        if expected_version >= 4:
            expected["lease_generations"] = _LEASE_GENERATION_COLUMNS
            expected["publication_gate_holds"] = (
                _PUBLICATION_GATE_HOLD_COLUMNS
                if expected_version >= 6
                else _V4_PUBLICATION_GATE_HOLD_COLUMNS
            )
        if expected_version >= 5:
            expected["manifest_artifact_sync"] = _MANIFEST_ARTIFACT_SYNC_COLUMNS
        tables = cls._table_names(connection)
        if tables != set(expected):
            raise StateError("State database contains missing or unsupported tables")
        for table, columns in expected.items():
            if cls._table_columns(connection, table) != columns:
                raise StateError(f"State table {table} has an unsupported shape")
        if not required_indexes.issubset(cls._index_names(connection)):
            raise StateError("State database is missing one or more required indexes")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise StateError("State database contains invalid foreign-key references")
        version = cls._detect_schema_version(connection)
        if version != expected_version:
            raise StateError(
                f"State schema migration ended at {version}, expected {expected_version}"
            )
        if cls._schema_manifest(connection) != cls._expected_schema_manifest(expected_version):
            raise StateError("State database schema objects do not match the canonical manifest")
        _verify_circuit_breaker_evidence(connection)
        if expected_version >= 4:
            _verify_event_anchors(connection)
        else:
            _verify_unanchored_event_chains(connection)
        _verify_lifecycle_snapshot_evidence(connection, collect=False)
        if expected_version == 4:
            _verify_publication_gate_holds(connection)
        if expected_version >= 5:
            _verify_manifest_artifact_sync(connection)
            _verify_publication_state(
                connection,
                require_current_rollout_cursors=False,
            )
        if expected_version >= 7:
            _verify_issue_revision_evidence(
                connection,
                require_current_provenance=expected_version >= 8,
            )

    @classmethod
    def _validate_current_schema(cls, connection: sqlite3.Connection) -> None:
        cls._validate_schema_version(connection, expected_version=CURRENT_SCHEMA_VERSION)

    @classmethod
    def _validate_restorable_schema(cls, connection: sqlite3.Connection) -> None:
        version = cls._detect_schema_version(connection)
        if version == 0:
            raise StateError("State database contains missing or unsupported tables")
        if version not in {2, 3, 4, 5, 6, 7, CURRENT_SCHEMA_VERSION}:
            raise StateError(
                f"State snapshot schema {version} cannot be restored; expected version 2, 3, 4, "
                f"5, 6, 7, or {CURRENT_SCHEMA_VERSION}"
            )
        cls._validate_schema_version(connection, expected_version=version)

    @property
    def schema_version(self) -> int:
        with self._connection() as connection:
            return self._detect_schema_version(connection)

    def create_run(self, *, deployment_fingerprint: str | None = None) -> RunManifest:
        now = utc_now()
        manifest = RunManifest(
            run_id=uuid.uuid4().hex[:16],
            status=RunStatus.QUEUED,
            created_at=now,
            updated_at=now,
            deployment_fingerprint=deployment_fingerprint,
        )
        manifest_json = manifest.model_dump_json()
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
                    manifest_json,
                ),
            )
            creation_details = {"status": "queued"}
            if deployment_fingerprint is not None:
                creation_details["deployment_fingerprint"] = deployment_fingerprint
            self._append_event(connection, manifest.run_id, "run.created", creation_details)
            _mark_manifest_artifact_sync(
                connection,
                run_id=manifest.run_id,
                updated_at=manifest.updated_at.isoformat(),
                manifest_json=manifest_json,
            )
        self._synchronize_manifest_artifact(
            manifest.run_id,
            updated_at=manifest.updated_at.isoformat(),
            manifest_sha256=_manifest_json_digest(manifest_json),
        )
        return manifest

    def get(self, run_id: str) -> RunManifest:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT manifest_json FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
        if row is None:
            raise StateError(f"Unknown run: {run_id}")
        return RunManifest.model_validate_json(row["manifest_json"])

    def list(self, *, limit: int = 20) -> builtins.list[RunManifest]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT manifest_json FROM runs ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [RunManifest.model_validate_json(row["manifest_json"]) for row in rows]

    def oldest_runs(
        self,
        *,
        limit: int = 100,
        deployment_fingerprint: str | None = None,
    ) -> builtins.list[RunManifest]:
        """Return a cohort ordered by validated, hash-chained creation evidence."""

        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("oldest run limit must be an integer")
        if not 1 <= limit <= _MAX_RUN_CORPUS:
            raise ValueError("oldest run limit must be between 1 and 10000")
        if deployment_fingerprint is not None and (
            len(deployment_fingerprint) != 64
            or any(character not in "0123456789abcdef" for character in deployment_fingerprint)
        ):
            raise ValueError("deployment fingerprint must be a lowercase SHA-256 value")
        with self._connection() as connection:
            connection.execute("BEGIN")
            _verify_event_anchors(connection)
            rows = connection.execute(
                """
                SELECT runs.run_id, runs.status, runs.created_at, runs.manifest_json,
                       creation.occurred_at AS creation_occurred_at,
                       creation.event_type AS creation_event_type,
                       creation.details_json AS creation_details
                FROM runs
                JOIN events AS creation ON creation.id = (
                    SELECT MIN(first_event.id) FROM events AS first_event
                    WHERE first_event.run_id = runs.run_id
                )
                ORDER BY runs.run_id ASC LIMIT ?
                """,
                (_MAX_RUN_CORPUS + 1,),
            ).fetchall()
        if len(rows) > _MAX_RUN_CORPUS:
            raise StateError("Run cohort exceeds the supported integrity bound")

        validated: builtins.list[tuple[datetime, RunManifest]] = []
        for row in rows:
            run_id = str(row["run_id"])
            try:
                manifest = RunManifest.model_validate_json(row["manifest_json"])
            except (TypeError, ValueError) as exc:
                raise StateError(f"Run {run_id} contains an invalid manifest") from exc
            stored_status = _stored_run_status(row["status"], run_id=run_id)
            stored_created_at = _stored_datetime(row["created_at"], field="run creation time")
            creation_occurred_at = _stored_datetime(
                row["creation_occurred_at"], field="run creation event time"
            )
            try:
                creation_details = json.loads(row["creation_details"])
            except (TypeError, ValueError) as exc:
                raise StateError(f"Run {run_id} has invalid creation evidence") from exc
            if creation_details == {"status": "queued"}:
                creation_fingerprint = None
            elif (
                isinstance(creation_details, dict)
                and set(creation_details) == {"deployment_fingerprint", "status"}
                and creation_details.get("status") == "queued"
                and isinstance(creation_details.get("deployment_fingerprint"), str)
                and len(creation_details["deployment_fingerprint"]) == 64
                and not any(
                    character not in "0123456789abcdef"
                    for character in creation_details["deployment_fingerprint"]
                )
            ):
                creation_fingerprint = creation_details["deployment_fingerprint"]
            else:
                raise StateError(f"Run {run_id} has invalid creation evidence")
            if (
                row["creation_event_type"] != "run.created"
                or manifest.run_id != run_id
                or manifest.status != stored_status
                or manifest.created_at.astimezone(UTC) != stored_created_at
                or manifest.deployment_fingerprint != creation_fingerprint
                or creation_occurred_at < stored_created_at
            ):
                raise StateError(f"Run {run_id} manifest disagrees with its state row")
            validated.append((creation_occurred_at, manifest))
        matching = [
            (created_at, manifest)
            for created_at, manifest in validated
            if deployment_fingerprint is None
            or manifest.deployment_fingerprint == deployment_fingerprint
        ]
        matching.sort(key=lambda item: (item[0], item[1].run_id))
        return [manifest for _, manifest in matching[:limit]]

    def run_deployment_fingerprint(self, run_id: str) -> str | None:
        """Read the deployment identity sealed into a run's first ledger event."""

        normalized_run_id = _lease_identity(run_id, field="run id")
        with self._connection() as connection:
            connection.execute("BEGIN")
            _verify_event_anchors(connection, selected_run_id=normalized_run_id)
            row = connection.execute(
                """
                SELECT event_type, details_json FROM events
                WHERE run_id = ? ORDER BY id ASC LIMIT 1
                """,
                (normalized_run_id,),
            ).fetchone()
        if row is None or row["event_type"] != "run.created":
            raise StateError(f"Run {normalized_run_id} is missing valid creation evidence")
        try:
            details = json.loads(row["details_json"])
        except (TypeError, ValueError) as exc:
            raise StateError(f"Run {normalized_run_id} has invalid creation evidence") from exc
        if details == {"status": "queued"}:
            return None
        if not isinstance(details, dict) or set(details) != {
            "deployment_fingerprint",
            "status",
        }:
            raise StateError(f"Run {normalized_run_id} has invalid creation evidence")
        fingerprint = details.get("deployment_fingerprint")
        if (
            details.get("status") != "queued"
            or not isinstance(fingerprint, str)
            or len(fingerprint) != 64
            or any(character not in "0123456789abcdef" for character in fingerprint)
        ):
            raise StateError(f"Run {normalized_run_id} has invalid creation evidence")
        return fingerprint

    def publication_ledger_sequence(self, run_id: str) -> int:
        """Return the global ledger position of one exact SUBMITTING-to-PR_OPEN transition."""

        normalized_run_id = _lease_identity(run_id, field="publication run id")
        with self._connection() as connection:
            connection.execute("BEGIN")
            _verify_event_anchors(connection, selected_run_id=normalized_run_id)
            rows = connection.execute(
                """
                SELECT id, details_json FROM events
                WHERE run_id = ? AND event_type = 'run.transitioned'
                ORDER BY id
                """,
                (normalized_run_id,),
            ).fetchall()
        matches: builtins.list[int] = []
        for row in rows:
            try:
                details = json.loads(row["details_json"])
            except (TypeError, ValueError) as exc:
                raise StateError(
                    f"Run {normalized_run_id} contains invalid transition evidence"
                ) from exc
            if (
                isinstance(details, dict)
                and details.get("from") == RunStatus.SUBMITTING.value
                and details.get("to") == RunStatus.PR_OPEN.value
                and isinstance(details.get("reason"), str)
                and bool(details["reason"])
            ):
                event_id = row["id"]
                if isinstance(event_id, bool) or not isinstance(event_id, int) or event_id < 1:
                    raise StateError("Publication transition has an invalid ledger position")
                matches.append(event_id)
        if len(matches) != 1:
            raise StateError(
                f"Run {normalized_run_id} does not have exactly one canonical PR_OPEN transition"
            )
        return matches[0]

    def list_open_pull_request_runs(self, *, limit: int = 1_000) -> builtins.list[RunManifest]:
        """Return every lifecycle-managed PR, failing instead of truncating the set."""

        return self._list_runs_with_status(
            RunStatus.PR_OPEN,
            limit=limit,
            resource="open pull-request",
        )

    def list_submitting_runs(self, *, limit: int = 100) -> builtins.list[RunManifest]:
        """Return every ambiguous publication intent for remote reconciliation."""

        return self._list_runs_with_status(
            RunStatus.SUBMITTING,
            limit=limit,
            resource="submitting",
        )

    def has_active_publication_gate_hold(self, run_id: str) -> bool:
        """Return whether one run still owns crash-persistent publication capacity."""

        return self.publication_gate_hold(run_id) is not None

    def publication_gate_hold(self, run_id: str) -> PublicationGateHold | None:
        """Return one validated active automatic-publication hold, if present."""

        normalized_run_id = _lease_identity(run_id, field="publication run id")
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT run_id, deployment_fingerprint, corpus_cursor,
                       outcome_corpus_cursor, held_at
                FROM publication_gate_holds WHERE run_id = ?
                """,
                (normalized_run_id,),
            ).fetchone()
        return _publication_gate_hold_from_row(row) if row is not None else None

    def assert_publication_gate_hold_current(
        self,
        run_id: str,
        *,
        deployment_fingerprint: str | None,
        publishing_login: str,
        publishing_api_origin: str,
    ) -> bool:
        """Fail closed if an automatic publication hold has lost its exact authority.

        A missing hold identifies a manual publication and requires no rollout assertion.  When
        a hold exists, every check shares one read snapshot: ledger and publication evidence,
        immutable deployment identity, durable publishing identity, and both rollout cursors.
        The return value distinguishes a true manual publication from a validated automatic hold.
        """

        normalized_run_id = _lease_identity(run_id, field="publication run id")
        with self._connection() as connection:
            connection.execute("BEGIN")
            # Read-only reconciliation verifies every event anchor, binds publication rows to
            # their ledger evidence, and compares this run's active-hold cursors.  In
            # particular, a deleted automatic hold row cannot masquerade as a manual
            # publication, while another crashed run's drifted hold cannot block this run's
            # own validated authority.
            _verify_publication_state(
                connection,
                require_current_rollout_cursors=True,
                currency_run_id=normalized_run_id,
            )
            row = connection.execute(
                """
                SELECT run_id, deployment_fingerprint, corpus_cursor,
                       outcome_corpus_cursor, held_at
                FROM publication_gate_holds WHERE run_id = ?
                """,
                (normalized_run_id,),
            ).fetchone()
            if row is None:
                return False

            hold = _publication_gate_hold_from_row(row)
            if hold.deployment_fingerprint is None or hold.outcome_corpus_cursor is None:
                raise StateError(
                    "Publication gate hold predates schema-v6 upstream-outcome authority; "
                    "automatic publication is forbidden"
                )
            if deployment_fingerprint is None:
                raise StateError("Automatic publication lacks its deployment fingerprint")
            deployment, login, origin, _ = _upstream_outcome_cursor_scope(
                deployment_fingerprint,
                publishing_login,
                publishing_api_origin,
                exclude_run_id=normalized_run_id,
            )
            if hold.deployment_fingerprint != deployment:
                raise StateError("Publication gate hold belongs to a different deployment")

            manifest_row = connection.execute(
                "SELECT manifest_json FROM runs WHERE run_id = ?",
                (normalized_run_id,),
            ).fetchone()
            if manifest_row is None or not isinstance(manifest_row["manifest_json"], str):
                raise StateError(
                    f"Publication gate hold for run {normalized_run_id} lacks its run manifest"
                )
            try:
                manifest = RunManifest.model_validate_json(manifest_row["manifest_json"])
            except (TypeError, ValueError) as exc:
                raise StateError(
                    f"Publication gate hold for run {normalized_run_id} has an invalid run manifest"
                ) from exc
            if (
                manifest.run_id != normalized_run_id
                or manifest.deployment_fingerprint != deployment
                or manifest.publishing_login != login
                or manifest.publishing_api_origin != origin
            ):
                raise StateError(
                    "Publication gate hold belongs to a different publishing identity or scope"
                )
            return True

    def has_publication_reconstruction_evidence(self, run_id: str) -> bool:
        """Return whether the ledger contains state relevant to publication recovery."""

        normalized_run_id = _lease_identity(run_id, field="publication run id")
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT 1 FROM events
                WHERE run_id = ? AND (
                    event_type GLOB 'publication.*'
                    OR event_type GLOB 'commit.*'
                    OR event_type GLOB 'branch.*'
                    OR event_type GLOB 'pull_request.*'
                )
                LIMIT 1
                """,
                (normalized_run_id,),
            ).fetchone()
        return row is not None

    def _list_runs_with_status(
        self,
        status: RunStatus,
        *,
        limit: int,
        resource: str,
    ) -> builtins.list[RunManifest]:
        """Enumerate a complete bounded status set and validate row/manifest agreement."""

        if not 1 <= limit <= 10_000:
            raise ValueError(f"{resource} run limit must be between 1 and 10000")
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT run_id, manifest_json FROM runs
                WHERE status = ? ORDER BY created_at ASC, run_id ASC LIMIT ?
                """,
                (status.value, limit + 1),
            ).fetchall()
        if len(rows) > limit:
            raise StateError(f"{resource.capitalize()} run set exceeds the configured safety bound")
        manifests: builtins.list[RunManifest] = []
        for row in rows:
            run_id = str(row["run_id"])
            try:
                manifest = RunManifest.model_validate_json(row["manifest_json"])
            except (TypeError, ValueError) as exc:
                raise StateError(f"Run {run_id} contains an invalid manifest") from exc
            if manifest.run_id != run_id or manifest.status != status:
                raise StateError(f"Run {run_id} manifest disagrees with its state row")
            manifests.append(manifest)
        return manifests

    def claim_candidate(
        self,
        manifest: RunManifest,
        *,
        lease: Lease,
        retry_authorization: CandidateRetryAuthorization | None = None,
    ) -> CandidateAttemptDisposition:
        """Atomically fence, classify, and bind one active candidate attempt."""

        if manifest.status != RunStatus.DISCOVERING:
            raise StateError("Candidate claims require a discovering run")
        candidate = manifest.candidate
        if candidate is None:
            raise StateError("Candidate claims require complete issue evidence")
        try:
            repository_key, issue_number = _candidate_identity(
                candidate.repository,
                candidate.number,
            )
            if (
                manifest.repository is not None
                and _candidate_identity(
                    manifest.repository.full_name,
                    issue_number,
                )[0]
                != repository_key
            ):
                raise ValueError("candidate repository metadata identifies a different repository")
        except (TypeError, ValueError) as exc:
            raise StateError("Candidate claims require a canonical issue identity") from exc
        if not 0 <= candidate.score <= 100:
            raise StateError("Candidate claims require a score between 0 and 100")
        if not isinstance(lease, Lease) or lease.name != _CANDIDATE_CLAIM_LEASE_NAME:
            raise StateError("Candidate claims require the fenced autocontribute run lease")

        revision = compute_issue_revision(candidate)
        expected_updated_at = manifest.updated_at
        manifest.updated_at = _next_run_update_time(expected_updated_at)
        disposition: CandidateAttemptDisposition
        try:
            manifest_json = manifest.model_dump_json()
            event_occurred_at: str | None = None
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                _assert_candidate_claim_lease(connection, lease, checked_at=utc_now())
                current = connection.execute(
                    """
                    SELECT status, repository, issue_number, issue_revision, manifest_json,
                           updated_at
                    FROM runs WHERE run_id = ?
                    """,
                    (manifest.run_id,),
                ).fetchone()
                if current is None:
                    raise StateError(f"Unknown run: {manifest.run_id}")
                try:
                    stored_manifest = RunManifest.model_validate_json(current["manifest_json"])
                except (TypeError, ValueError) as exc:
                    raise StateError(f"Run {manifest.run_id} contains an invalid manifest") from exc
                if (
                    current["status"] != RunStatus.DISCOVERING.value
                    or current["updated_at"] != expected_updated_at.isoformat()
                    or current["repository"] is not None
                    or current["issue_number"] is not None
                    or current["issue_revision"] is not None
                    or stored_manifest.run_id != manifest.run_id
                    or stored_manifest.status != RunStatus.DISCOVERING
                    or stored_manifest.candidate is not None
                ):
                    raise StateError(f"Run {manifest.run_id} changed before its candidate claim")

                rows = connection.execute(
                    """
                    SELECT run_id, status, repository, issue_number, issue_revision, manifest_json
                    FROM runs
                    WHERE run_id <> ? AND repository = ? COLLATE NOCASE
                        AND issue_number = ?
                    ORDER BY run_id ASC LIMIT ?
                    """,
                    (
                        manifest.run_id,
                        repository_key,
                        issue_number,
                        _MAX_RUN_CORPUS + 1,
                    ),
                ).fetchall()
                if len(rows) > _MAX_RUN_CORPUS:
                    raise StateError(
                        "Candidate attempt history exceeds the supported integrity bound"
                    )
                attempts = [_verified_issue_revision_row(row) for row in rows]
                active = next(
                    (
                        (run_id, status)
                        for run_id, status, _ in attempts
                        if status not in _CANDIDATE_RELEASED_STATUSES
                    ),
                    None,
                )
                if active is not None:
                    raise StateError(
                        f"Candidate already has active run {active[0]} in status {active[1].value}"
                    )
                suppressed = next(
                    (
                        (run_id, status)
                        for run_id, status, stored_revision in attempts
                        if status in _CANDIDATE_SUPPRESSED_STATUSES and stored_revision == revision
                    ),
                    None,
                )
                if suppressed is None and retry_authorization is not None:
                    raise StateError(
                        "Retry authorization no longer matches an unchanged suppressed candidate"
                    )
                if suppressed is not None and retry_authorization is None:
                    raise StateError(
                        "Unchanged suppressed candidate requires explicit retry authorization"
                    )

                if suppressed is None:
                    disposition = CandidateAttemptDisposition(
                        state=CandidateAttemptState.AVAILABLE,
                        issue_revision=revision,
                    )
                    event_type = "candidate.selected"
                    event_details = {
                        "issue": candidate.reference,
                        "issue_revision": revision,
                        "score": str(candidate.score),
                    }
                else:
                    assert retry_authorization is not None
                    actor, reason = _candidate_retry_authorization(retry_authorization)
                    authorization_id = uuid.uuid4().hex
                    authorized_at = utc_now().isoformat()
                    event_occurred_at = authorized_at
                    prior_run_id, prior_status = suppressed
                    disposition = CandidateAttemptDisposition(
                        state=CandidateAttemptState.SUPPRESSED,
                        issue_revision=revision,
                        prior_run_id=prior_run_id,
                        prior_status=prior_status,
                    )
                    connection.execute(
                        """
                        INSERT INTO candidate_retry_authorizations(
                            authorization_id, run_id, repository, issue_number,
                            issue_revision, prior_run_id, prior_status, actor, reason,
                            authorized_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            authorization_id,
                            manifest.run_id,
                            candidate.repository,
                            issue_number,
                            revision,
                            prior_run_id,
                            prior_status.value,
                            actor,
                            reason,
                            authorized_at,
                        ),
                    )
                    event_type = "candidate.retry_override"
                    event_details = {
                        "actor": actor,
                        "authorization_id": authorization_id,
                        "issue": candidate.reference,
                        "issue_revision": revision,
                        "prior_run_id": prior_run_id,
                        "prior_status": prior_status.value,
                        "reason": reason,
                    }

                result = connection.execute(
                    """
                    UPDATE runs
                    SET repository = ?, issue_number = ?, issue_revision = ?, updated_at = ?,
                        manifest_json = ?
                    WHERE run_id = ? AND status = ? AND updated_at = ?
                        AND repository IS NULL AND issue_number IS NULL
                        AND issue_revision IS NULL AND manifest_json = ?
                    """,
                    (
                        candidate.repository,
                        issue_number,
                        revision,
                        manifest.updated_at.isoformat(),
                        manifest_json,
                        manifest.run_id,
                        RunStatus.DISCOVERING.value,
                        expected_updated_at.isoformat(),
                        current["manifest_json"],
                    ),
                )
                if result.rowcount != 1:
                    raise StateError(
                        f"Run {manifest.run_id} changed while its candidate was claimed"
                    )
                self._append_event(
                    connection,
                    manifest.run_id,
                    event_type,
                    event_details,
                    occurred_at=event_occurred_at,
                )
                _mark_manifest_artifact_sync(
                    connection,
                    run_id=manifest.run_id,
                    updated_at=manifest.updated_at.isoformat(),
                    manifest_json=manifest_json,
                )
        except sqlite3.IntegrityError as exc:
            manifest.updated_at = expected_updated_at
            raise StateError("Candidate claim violated a durable state constraint") from exc
        except Exception:
            manifest.updated_at = expected_updated_at
            raise
        self._synchronize_manifest_artifact(
            manifest.run_id,
            updated_at=manifest.updated_at.isoformat(),
            manifest_sha256=_manifest_json_digest(manifest_json),
        )
        return disposition

    def save(self, manifest: RunManifest, *, event: str, details: dict[str, str]) -> None:
        candidate = manifest.candidate
        issue_revision = compute_issue_revision(candidate) if candidate is not None else None
        event_details = dict(details)
        if event == "candidate.selected":
            if candidate is None or issue_revision is None:
                raise StateError("Candidate selection cannot be saved without issue evidence")
            if not 0 <= candidate.score <= 100:
                raise StateError("Candidate selection requires a score between 0 and 100")
            supplied_revision = event_details.get("issue_revision")
            if supplied_revision is not None and supplied_revision != issue_revision:
                raise StateError("Candidate selection event has a mismatched issue revision")
            event_details["issue_revision"] = issue_revision
            if event_details != {
                "issue": candidate.reference,
                "issue_revision": issue_revision,
                "score": str(candidate.score),
            }:
                raise StateError("Candidate selection event disagrees with its candidate evidence")
        expected_updated_at = manifest.updated_at
        expected_utc = _aware_utc(expected_updated_at, field="manifest updated_at")
        saved_at = _aware_utc(utc_now(), field="run save time")
        if saved_at <= expected_utc:
            try:
                saved_at = expected_utc + timedelta(microseconds=1)
            except OverflowError as exc:
                raise StateError("Run update timestamp exhausted its supported range") from exc
        manifest.updated_at = saved_at
        manifest_json = manifest.model_dump_json()
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                current = connection.execute(
                    """
                    SELECT issue_revision FROM runs WHERE run_id = ?
                    """,
                    (manifest.run_id,),
                ).fetchone()
                if current is None:
                    raise StateError(f"Unknown run: {manifest.run_id}")
                if candidate is not None and current["issue_revision"] is None:
                    raise StateError("Candidate evidence must be persisted through claim_candidate")
                result = connection.execute(
                    """
                    UPDATE runs
                    SET status = ?, repository = ?, issue_number = ?, updated_at = ?,
                        issue_revision = ?, manifest_json = ?
                    WHERE run_id = ? AND updated_at = ?
                        AND (issue_revision IS NULL OR issue_revision = ?)
                    """,
                    (
                        manifest.status.value,
                        candidate.repository if candidate else None,
                        candidate.number if candidate else None,
                        manifest.updated_at.isoformat(),
                        issue_revision,
                        manifest_json,
                        manifest.run_id,
                        expected_updated_at.isoformat(),
                        issue_revision,
                    ),
                )
                if result.rowcount != 1:
                    changed = connection.execute(
                        "SELECT issue_revision FROM runs WHERE run_id = ?", (manifest.run_id,)
                    ).fetchone()
                    if changed is None:
                        raise StateError(f"Unknown run: {manifest.run_id}")
                    if changed["issue_revision"] not in {None, issue_revision}:
                        raise StateError(
                            f"Run {manifest.run_id} candidate evidence changed after selection"
                        )
                    raise StateError(
                        f"Run {manifest.run_id} changed while this manifest was being saved"
                    )
                self._append_event(connection, manifest.run_id, event, event_details)
                _mark_manifest_artifact_sync(
                    connection,
                    run_id=manifest.run_id,
                    updated_at=manifest.updated_at.isoformat(),
                    manifest_json=manifest_json,
                )
        except Exception:
            manifest.updated_at = expected_updated_at
            raise
        self._synchronize_manifest_artifact(
            manifest.run_id,
            updated_at=manifest.updated_at.isoformat(),
            manifest_sha256=_manifest_json_digest(manifest_json),
        )

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
        try:
            if target == RunStatus.PR_OPEN:
                self._save_pr_open_transition(manifest, previous=previous, reason=reason)
            else:
                self.save(
                    manifest,
                    event="run.transitioned",
                    details={"from": previous.value, "to": target.value, "reason": reason},
                )
        except _ManifestArtifactSyncError:
            raise
        except Exception:
            manifest.status = previous
            raise
        return manifest

    def _save_pr_open_transition(
        self,
        manifest: RunManifest,
        *,
        previous: RunStatus,
        reason: str,
    ) -> None:
        """Persist PR_OPEN and release its exact evaluation hold in one transaction."""

        expected_updated_at = manifest.updated_at
        saved_at = _next_run_update_time(expected_updated_at)
        candidate = manifest.candidate
        issue_revision = compute_issue_revision(candidate) if candidate is not None else None
        manifest.updated_at = saved_at
        manifest_json = manifest.model_dump_json()
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                current = connection.execute(
                    """
                    SELECT run_id, status, repository, issue_number, issue_revision,
                           manifest_json
                    FROM runs WHERE run_id = ?
                    """,
                    (manifest.run_id,),
                ).fetchone()
                if current is None:
                    raise StateError(f"Unknown run: {manifest.run_id}")
                _, stored_status, stored_revision = _verified_issue_revision_row(current)
                if stored_status != previous or stored_revision != issue_revision:
                    raise StateError(
                        f"Run {manifest.run_id} candidate evidence changed after selection"
                    )
                result = connection.execute(
                    """
                    UPDATE runs
                    SET status = ?, repository = ?, issue_number = ?, updated_at = ?,
                        manifest_json = ?
                    WHERE run_id = ? AND updated_at = ? AND status = ?
                        AND issue_revision IS ? AND manifest_json = ?
                    """,
                    (
                        manifest.status.value,
                        candidate.repository if candidate else None,
                        candidate.number if candidate else None,
                        manifest.updated_at.isoformat(),
                        manifest_json,
                        manifest.run_id,
                        expected_updated_at.isoformat(),
                        previous.value,
                        issue_revision,
                        current["manifest_json"],
                    ),
                )
                if result.rowcount != 1:
                    raise StateError(
                        f"Run {manifest.run_id} changed while this manifest was being saved"
                    )
                self._append_event(
                    connection,
                    manifest.run_id,
                    "run.transitioned",
                    {
                        "from": previous.value,
                        "to": RunStatus.PR_OPEN.value,
                        "reason": reason,
                    },
                )
                _release_publication_gate_hold(
                    self,
                    connection,
                    manifest.run_id,
                    outcome="pr_open",
                    required=False,
                )
                _mark_manifest_artifact_sync(
                    connection,
                    run_id=manifest.run_id,
                    updated_at=manifest.updated_at.isoformat(),
                    manifest_json=manifest_json,
                )
        except Exception:
            manifest.updated_at = expected_updated_at
            raise
        self._synchronize_manifest_artifact(
            manifest.run_id,
            updated_at=manifest.updated_at.isoformat(),
            manifest_sha256=_manifest_json_digest(manifest_json),
        )

    def finalize_merged_publication_compensation(
        self,
        manifest: RunManifest,
        *,
        pull_request_url: str,
        reason: str,
    ) -> RunManifest:
        """Adopt one exact already-merged compensating PR into lifecycle management.

        This exposure-reducing recovery is intentionally tolerant of rollout-cursor drift. It is
        not a general PR_OPEN transition: the durable created-PR compensation marker and exact
        URL must remain intact in the committing transaction. Automatic runs must retain their
        same-run hold; a genuine manual run may have no hold.
        """

        if manifest.status != RunStatus.SUBMITTING:
            raise StateError("Merged publication compensation requires a SUBMITTING manifest")
        if manifest.publication_compensation_reason != "created_pr_base_moved":
            raise StateError(
                "Merged publication compensation requires the created-PR base-race marker"
            )
        expected_pull_request_url = _canonical_publication_intent_text(
            pull_request_url,
            field="merged compensating pull request URL",
            maximum=2_000,
        )
        if manifest.pull_request_url != expected_pull_request_url:
            raise StateError(
                "Merged publication compensation does not match the durable pull request URL"
            )
        normalized_reason = _bounded_text(
            reason,
            field="merged publication compensation reason",
            maximum=2_000,
        )

        previous = manifest.status
        expected_updated_at = manifest.updated_at
        expected_manifest_json = manifest.model_dump_json()
        manifest.status = RunStatus.PR_OPEN
        manifest.updated_at = _next_run_update_time(expected_updated_at)
        updated_manifest_json = manifest.model_dump_json()
        candidate = manifest.candidate
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                _reconcile_publication_state(
                    connection,
                    repair_missing=True,
                    require_current_rollout_cursors=False,
                )
                _assert_merged_publication_compensation_events(
                    connection,
                    manifest,
                    pull_request_url=expected_pull_request_url,
                )
                other_hold = connection.execute(
                    """
                    SELECT run_id FROM publication_gate_holds
                    WHERE run_id <> ? ORDER BY run_id LIMIT 1
                    """,
                    (manifest.run_id,),
                ).fetchone()
                if other_hold is not None:
                    other_run_id = other_hold["run_id"]
                    if not isinstance(other_run_id, str) or not other_run_id:
                        raise StateError("Publication gate hold contains invalid stored values")
                    raise StateError(f"Publication gate is held by another run: {other_run_id}")
                hold_row = connection.execute(
                    "SELECT run_id FROM publication_gate_holds WHERE run_id = ?",
                    (manifest.run_id,),
                ).fetchone()
                result = connection.execute(
                    """
                    UPDATE runs
                    SET status = ?, repository = ?, issue_number = ?, updated_at = ?,
                        manifest_json = ?
                    WHERE run_id = ? AND updated_at = ? AND status = ? AND manifest_json = ?
                    """,
                    (
                        RunStatus.PR_OPEN.value,
                        candidate.repository if candidate else None,
                        candidate.number if candidate else None,
                        manifest.updated_at.isoformat(),
                        updated_manifest_json,
                        manifest.run_id,
                        expected_updated_at.isoformat(),
                        RunStatus.SUBMITTING.value,
                        expected_manifest_json,
                    ),
                )
                if result.rowcount != 1:
                    if (
                        connection.execute(
                            "SELECT 1 FROM runs WHERE run_id = ?", (manifest.run_id,)
                        ).fetchone()
                        is None
                    ):
                        raise StateError(f"Unknown run: {manifest.run_id}")
                    raise StateError(
                        f"Run {manifest.run_id} changed while merged compensation was finalized"
                    )
                self._append_event(
                    connection,
                    manifest.run_id,
                    "run.transitioned",
                    {
                        "from": previous.value,
                        "to": RunStatus.PR_OPEN.value,
                        "reason": normalized_reason,
                    },
                )
                if hold_row is not None:
                    _release_publication_gate_hold_for_compensation(
                        self,
                        connection,
                        manifest.run_id,
                        outcome="pr_open",
                        required=True,
                    )
                _mark_manifest_artifact_sync(
                    connection,
                    run_id=manifest.run_id,
                    updated_at=manifest.updated_at.isoformat(),
                    manifest_json=updated_manifest_json,
                )
        except Exception:
            manifest.status = previous
            manifest.updated_at = expected_updated_at
            raise
        self._synchronize_manifest_artifact(
            manifest.run_id,
            updated_at=manifest.updated_at.isoformat(),
            manifest_sha256=_manifest_json_digest(updated_manifest_json),
        )
        return manifest

    def finalize_publication_compensation(
        self,
        manifest: RunManifest,
        *,
        reason: str,
        evidence: dict[str, str],
    ) -> RunManifest:
        """Finalize verified compensation with an exact same-run hold or no active hold."""

        if manifest.status != RunStatus.SUBMITTING:
            raise StateError("Verified publication compensation requires a SUBMITTING manifest")
        normalized_reason = _bounded_text(
            reason,
            field="publication compensation reason",
            maximum=2_000,
        )
        if not isinstance(evidence, dict):
            raise TypeError("publication compensation evidence must be a dictionary")
        verified_details = dict(evidence)
        verified_details["reason"] = normalized_reason
        _validate_event_details(
            verified_details,
            field="publication compensation evidence",
        )

        previous = manifest.status
        expected_updated_at = manifest.updated_at
        expected_manifest_json = manifest.model_dump_json()
        manifest.status = RunStatus.FAILED
        manifest.updated_at = _next_run_update_time(expected_updated_at)
        updated_manifest_json = manifest.model_dump_json()
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                _reconcile_publication_state(
                    connection,
                    repair_missing=True,
                    require_current_rollout_cursors=False,
                )
                _assert_failed_publication_compensation_events(
                    connection,
                    manifest,
                    reason=normalized_reason,
                    evidence=verified_details,
                )
                other_hold = connection.execute(
                    """
                    SELECT run_id FROM publication_gate_holds
                    WHERE run_id <> ? ORDER BY run_id LIMIT 1
                    """,
                    (manifest.run_id,),
                ).fetchone()
                if other_hold is not None:
                    other_run_id = other_hold["run_id"]
                    if not isinstance(other_run_id, str) or not other_run_id:
                        raise StateError("Publication gate hold contains invalid stored values")
                    raise StateError(f"Publication gate is held by another run: {other_run_id}")
                hold_row = connection.execute(
                    "SELECT run_id FROM publication_gate_holds WHERE run_id = ?",
                    (manifest.run_id,),
                ).fetchone()
                result = connection.execute(
                    """
                    UPDATE runs
                    SET status = ?, updated_at = ?, manifest_json = ?
                    WHERE run_id = ? AND updated_at = ? AND status = ? AND manifest_json = ?
                    """,
                    (
                        RunStatus.FAILED.value,
                        manifest.updated_at.isoformat(),
                        updated_manifest_json,
                        manifest.run_id,
                        expected_updated_at.isoformat(),
                        RunStatus.SUBMITTING.value,
                        expected_manifest_json,
                    ),
                )
                if result.rowcount != 1:
                    if (
                        connection.execute(
                            "SELECT 1 FROM runs WHERE run_id = ?", (manifest.run_id,)
                        ).fetchone()
                        is None
                    ):
                        raise StateError(f"Unknown run: {manifest.run_id}")
                    raise StateError(
                        f"Run {manifest.run_id} changed while compensation was finalized"
                    )
                self._append_event(
                    connection,
                    manifest.run_id,
                    "publication.compensation.verified",
                    verified_details,
                )
                self._append_event(
                    connection,
                    manifest.run_id,
                    "run.transitioned",
                    {
                        "from": previous.value,
                        "to": RunStatus.FAILED.value,
                        "reason": normalized_reason,
                    },
                )
                if hold_row is not None:
                    _release_publication_gate_hold_for_compensation(
                        self,
                        connection,
                        manifest.run_id,
                        outcome="verified_compensation",
                        required=True,
                    )
                _mark_manifest_artifact_sync(
                    connection,
                    run_id=manifest.run_id,
                    updated_at=manifest.updated_at.isoformat(),
                    manifest_json=updated_manifest_json,
                )
        except Exception:
            manifest.status = previous
            manifest.updated_at = expected_updated_at
            raise
        self._synchronize_manifest_artifact(
            manifest.run_id,
            updated_at=manifest.updated_at.isoformat(),
            manifest_sha256=_manifest_json_digest(updated_manifest_json),
        )
        return manifest

    def has_active_candidate(self, repository: str, issue_number: int) -> bool:
        repository_key, normalized_issue_number = _candidate_identity(repository, issue_number)
        released = tuple(sorted(status.value for status in _CANDIDATE_RELEASED_STATUSES))
        placeholders = ",".join("?" for _ in released)
        query = (
            "SELECT 1 FROM runs WHERE repository = ? COLLATE NOCASE AND issue_number = ? "
            f"AND status NOT IN ({placeholders}) LIMIT 1"
        )
        with self._connection() as connection:
            row = connection.execute(
                query,
                (repository_key, normalized_issue_number, *released),
            ).fetchone()
        return row is not None

    def candidate_attempt_disposition(
        self,
        issue: IssueCandidate,
    ) -> CandidateAttemptDisposition:
        """Classify whether current issue evidence may start a new contribution attempt.

        Active work wins regardless of revision.  Otherwise, an unchanged conservative terminal
        outcome is suppressed, while failed attempts and semantically changed issues are available.
        Every row used for the decision is rebound to its manifest and stored revision first.
        """

        if not isinstance(issue, IssueCandidate):
            raise TypeError("candidate disposition requires an IssueCandidate")
        repository, issue_number = _candidate_identity(issue.repository, issue.number)
        revision = compute_issue_revision(issue)
        with self._connection() as connection:
            connection.execute("BEGIN")
            rows = connection.execute(
                """
                SELECT run_id, status, repository, issue_number, issue_revision, manifest_json
                FROM runs
                WHERE repository = ? COLLATE NOCASE AND issue_number = ?
                ORDER BY run_id ASC LIMIT ?
                """,
                (repository, issue_number, _MAX_RUN_CORPUS + 1),
            ).fetchall()
            if len(rows) > _MAX_RUN_CORPUS:
                raise StateError("Candidate attempt history exceeds the supported integrity bound")
            attempts = [_verified_issue_revision_row(row) for row in rows]

        active = next(
            (
                (run_id, status)
                for run_id, status, _ in attempts
                if status not in _CANDIDATE_RELEASED_STATUSES
            ),
            None,
        )
        if active is not None:
            return CandidateAttemptDisposition(
                state=CandidateAttemptState.ACTIVE,
                issue_revision=revision,
                prior_run_id=active[0],
                prior_status=active[1],
            )

        suppressed = next(
            (
                (run_id, status)
                for run_id, status, stored_revision in attempts
                if status in _CANDIDATE_SUPPRESSED_STATUSES and stored_revision == revision
            ),
            None,
        )
        if suppressed is not None:
            return CandidateAttemptDisposition(
                state=CandidateAttemptState.SUPPRESSED,
                issue_revision=revision,
                prior_run_id=suppressed[0],
                prior_status=suppressed[1],
            )
        return CandidateAttemptDisposition(
            state=CandidateAttemptState.AVAILABLE,
            issue_revision=revision,
        )

    def begin_publication(
        self,
        manifest: RunManifest,
        repository: str,
        *,
        branch_name: str,
        publication_draft: bool,
        publication_ready_for_review: bool = False,
        publishing_login: str,
        publishing_api_origin: str,
        commit_author_name: str,
        commit_author_email: str,
        commit_committer_name: str,
        commit_committer_email: str,
        max_per_utc_day: int,
        repository_cooldown: timedelta,
        now: datetime | None = None,
        evaluation_corpus_cursor: str | None = None,
        evaluation_deployment_fingerprint: str | None = None,
        outcome_corpus_cursor: str | None = None,
    ) -> RunManifest:
        """Atomically persist publication intent, capacity, gate hold, and SUBMITTING."""

        if manifest.status not in {
            RunStatus.READY_FOR_APPROVAL,
            RunStatus.APPROVED,
            RunStatus.SUBMITTING,
        }:
            raise StateError(
                f"Run {manifest.run_id} cannot begin publication from {manifest.status.value}"
            )
        request = _publication_reservation_request(
            manifest.run_id,
            repository,
            max_per_utc_day=max_per_utc_day,
            repository_cooldown=repository_cooldown,
            now=now,
            evaluation_corpus_cursor=evaluation_corpus_cursor,
            evaluation_deployment_fingerprint=evaluation_deployment_fingerprint,
            outcome_corpus_cursor=outcome_corpus_cursor,
            publishing_login=publishing_login,
            publishing_api_origin=publishing_api_origin,
        )
        intent = _publication_intent(
            branch_name=branch_name,
            publication_draft=publication_draft,
            publication_ready_for_review=publication_ready_for_review,
            publishing_login=publishing_login,
            publishing_api_origin=publishing_api_origin,
            commit_author_name=commit_author_name,
            commit_author_email=commit_author_email,
            commit_committer_name=commit_committer_name,
            commit_committer_email=commit_committer_email,
        )
        if manifest.candidate is None:
            raise StateError(f"Run {manifest.run_id} lacks a publication candidate")
        if _repository_identity(manifest.candidate.repository) != request.repository:
            raise StateError(f"Run {manifest.run_id} does not belong to {request.repository}")

        previous = manifest.status
        expected_updated_at = manifest.updated_at
        expected_manifest_json = manifest.model_dump_json()
        intent_fields = intent.manifest_fields()
        pending = manifest.model_copy(deep=True)
        mismatches: builtins.list[str] = []
        missing: builtins.list[str] = []
        for field, expected in intent_fields.items():
            actual = getattr(manifest, field)
            if previous == RunStatus.SUBMITTING:
                if actual is None:
                    missing.append(field)
                elif actual != expected:
                    mismatches.append(field)
            elif actual is not None and actual != expected:
                mismatches.append(field)
            setattr(pending, field, expected)
        if missing:
            raise StateError(
                "Submitting run has incomplete durable publication intent: "
                + ", ".join(sorted(missing))
            )
        if mismatches:
            raise StateError(
                "Publication request differs from durable intent: " + ", ".join(sorted(mismatches))
            )

        manifest_changed = previous != RunStatus.SUBMITTING
        if manifest_changed:
            pending.status = RunStatus.SUBMITTING
            pending.updated_at = _next_run_update_time(expected_updated_at)
        pending_manifest_json = pending.model_dump_json()
        intent_details = intent.event_details(repository=request.repository)

        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT status, updated_at, manifest_json FROM runs WHERE run_id = ?
                """,
                (request.run_id,),
            ).fetchone()
            if row is None:
                raise StateError(f"Unknown run: {request.run_id}")
            stored_status = _stored_run_status(row["status"], run_id=request.run_id)
            if (
                stored_status != previous
                or row["updated_at"] != expected_updated_at.isoformat()
                or row["manifest_json"] != expected_manifest_json
            ):
                raise StateError(f"Run {request.run_id} changed while publication was beginning")

            intent_rows = connection.execute(
                """
                SELECT details_json FROM events
                WHERE run_id = ? AND event_type = 'publication.intent.begun'
                ORDER BY id LIMIT 2
                """,
                (request.run_id,),
            ).fetchall()
            if len(intent_rows) > 1:
                raise StateError(f"Run {request.run_id} has duplicate publication intent events")
            if intent_rows:
                details_value = intent_rows[0]["details_json"]
                if not isinstance(details_value, str):
                    raise StateError("Publication intent event contains invalid stored values")
                try:
                    stored_details = json.loads(details_value)
                except json.JSONDecodeError as exc:
                    raise StateError("Publication intent event contains malformed details") from exc
                if stored_details != intent_details:
                    raise StateError(
                        f"Run {request.run_id} already began with different publication intent"
                    )
                if previous != RunStatus.SUBMITTING:
                    raise StateError(
                        f"Run {request.run_id} publication intent disagrees with its status"
                    )

            self._reserve_publication_in_transaction(connection, request)

            if manifest_changed:
                candidate = pending.candidate
                assert candidate is not None
                update = connection.execute(
                    """
                    UPDATE runs
                    SET status = ?, repository = ?, issue_number = ?, updated_at = ?,
                        manifest_json = ?
                    WHERE run_id = ? AND status = ? AND updated_at = ? AND manifest_json = ?
                    """,
                    (
                        RunStatus.SUBMITTING.value,
                        candidate.repository,
                        candidate.number,
                        pending.updated_at.isoformat(),
                        pending_manifest_json,
                        request.run_id,
                        previous.value,
                        expected_updated_at.isoformat(),
                        expected_manifest_json,
                    ),
                )
                if update.rowcount != 1:
                    raise StateError(
                        f"Run {request.run_id} changed while publication was beginning"
                    )
                self._append_event(
                    connection,
                    request.run_id,
                    "run.transitioned",
                    {
                        "from": previous.value,
                        "to": RunStatus.SUBMITTING.value,
                        "reason": "authorized publication intent persisted",
                    },
                )
            if not intent_rows:
                self._append_event(
                    connection,
                    request.run_id,
                    "publication.intent.begun",
                    intent_details,
                )
            if manifest_changed:
                _mark_manifest_artifact_sync(
                    connection,
                    run_id=request.run_id,
                    updated_at=pending.updated_at.isoformat(),
                    manifest_json=pending_manifest_json,
                )

        if manifest_changed:
            for field, value in intent_fields.items():
                setattr(manifest, field, value)
            manifest.status = pending.status
            manifest.updated_at = pending.updated_at
            self._synchronize_manifest_artifact(
                manifest.run_id,
                updated_at=manifest.updated_at.isoformat(),
                manifest_sha256=_manifest_json_digest(pending_manifest_json),
            )
        return manifest

    def reserve_publication(
        self,
        run_id: str,
        repository: str,
        *,
        max_per_utc_day: int,
        repository_cooldown: timedelta,
        now: datetime | None = None,
        evaluation_corpus_cursor: str | None = None,
        evaluation_deployment_fingerprint: str | None = None,
        outcome_corpus_cursor: str | None = None,
        publishing_login: str | None = None,
        publishing_api_origin: str | None = None,
    ) -> PublicationReservation:
        """Durably consume local publication capacity before the first remote mutation."""

        request = _publication_reservation_request(
            run_id,
            repository,
            max_per_utc_day=max_per_utc_day,
            repository_cooldown=repository_cooldown,
            now=now,
            evaluation_corpus_cursor=evaluation_corpus_cursor,
            evaluation_deployment_fingerprint=evaluation_deployment_fingerprint,
            outcome_corpus_cursor=outcome_corpus_cursor,
            publishing_login=publishing_login,
            publishing_api_origin=publishing_api_origin,
        )
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            result = self._reserve_publication_in_transaction(connection, request)
        return result.reservation

    def _reserve_publication_in_transaction(
        self,
        connection: sqlite3.Connection,
        request: _PublicationReservationRequest,
    ) -> _PublicationReservationResult:
        # Rows and ledger evidence must agree exactly, but a durable hold whose anchored
        # cursors drifted while its run awaited crash recovery must stay recoverable here:
        # the request-cursor branch below re-verifies currency and re-anchors the hold.
        _reconcile_publication_state(
            connection,
            repair_missing=True,
            require_current_rollout_cursors=False,
        )
        other_hold = connection.execute(
            """
            SELECT run_id FROM publication_gate_holds
            WHERE run_id <> ? ORDER BY run_id LIMIT 1
            """,
            (request.run_id,),
        ).fetchone()
        if other_hold is not None:
            other_run_id = other_hold["run_id"]
            if not isinstance(other_run_id, str) or not other_run_id:
                raise StateError("Publication gate hold contains invalid stored values")
            raise StateError(f"Publication gate is held by another run: {other_run_id}")

        existing = connection.execute(
            """
            SELECT repository, reserved_at FROM publication_reservations
            WHERE run_id = ?
            """,
            (request.run_id,),
        ).fetchone()
        run = connection.execute(
            "SELECT repository, manifest_json FROM runs WHERE run_id = ?", (request.run_id,)
        ).fetchone()
        if run is None:
            raise StateError(f"Unknown run: {request.run_id}")
        run_repository = run["repository"]
        if run_repository is not None:
            if not isinstance(run_repository, str):
                raise StateError(f"Run {request.run_id} has an invalid repository")
            if _repository_identity(run_repository) != request.repository:
                raise StateError(f"Run {request.run_id} does not belong to {request.repository}")
        if request.evaluation_deployment_fingerprint is not None:
            manifest_json_value = run["manifest_json"]
            if not isinstance(manifest_json_value, str):
                raise StateError(f"Run {request.run_id} has an invalid manifest")
            try:
                stored_manifest = RunManifest.model_validate_json(manifest_json_value)
            except (TypeError, ValueError) as exc:
                raise StateError(f"Run {request.run_id} has an invalid manifest") from exc
            creation_fingerprint = _run_creation_deployment_fingerprint(
                connection,
                request.run_id,
            )
            if (
                stored_manifest.run_id != request.run_id
                or stored_manifest.deployment_fingerprint != creation_fingerprint
                or creation_fingerprint != request.evaluation_deployment_fingerprint
            ):
                raise StateError("Automatic publication run belongs to a different deployment")

        reservation_created = existing is None
        if existing is not None:
            existing_repository = existing["repository"]
            if not isinstance(existing_repository, str):
                raise StateError("Stored publication reservation repository is invalid")
            if _repository_identity(existing_repository) != request.repository:
                raise StateError(
                    "Publication run already reserved capacity for a different repository"
                )
            effective_reserved_at = _stored_datetime(
                existing["reserved_at"], field="publication reservation time"
            )
        else:
            daily_count = connection.execute(
                """
                SELECT count(*) FROM publication_reservations
                WHERE reserved_at >= ? AND reserved_at < ?
                """,
                (request.day_start.isoformat(), request.day_end.isoformat()),
            ).fetchone()[0]
            if not isinstance(daily_count, int):  # pragma: no cover - SQLite invariant
                raise StateError("Stored publication reservation count is invalid")
            if daily_count >= request.max_per_utc_day:
                raise StateError("Daily publication reservation limit reached")

            if request.enforce_cooldown:
                cooldown_match = connection.execute(
                    """
                    SELECT run_id, reserved_at FROM publication_reservations
                    WHERE repository = ? AND reserved_at > ?
                    ORDER BY reserved_at DESC LIMIT 1
                    """,
                    (request.repository, request.cooldown_start.isoformat()),
                ).fetchone()
                if cooldown_match is not None:
                    _stored_datetime(
                        cooldown_match["reserved_at"],
                        field="publication reservation time",
                    )
                    raise StateError("Repository publication cooldown is active")

            connection.execute(
                """
                INSERT INTO publication_reservations(run_id, repository, reserved_at)
                VALUES (?, ?, ?)
                """,
                (request.run_id, request.repository, request.reserved_at.isoformat()),
            )
            self._append_event(
                connection,
                request.run_id,
                "publication.reserved",
                {
                    "repository": request.repository,
                    "reserved_at": request.reserved_at.isoformat(),
                },
            )
            effective_reserved_at = request.reserved_at

        hold_row = connection.execute(
            """
            SELECT run_id, deployment_fingerprint, corpus_cursor,
                   outcome_corpus_cursor, held_at
            FROM publication_gate_holds WHERE run_id = ?
            """,
            (request.run_id,),
        ).fetchone()
        hold_created = False
        if request.evaluation_corpus_cursor is not None:
            assert request.evaluation_deployment_fingerprint is not None
            assert request.outcome_corpus_cursor is not None
            assert request.publishing_login is not None
            assert request.publishing_api_origin is not None
            actual_corpus_cursor = _evaluation_corpus_cursor_from_connection(connection)
            if actual_corpus_cursor != request.evaluation_corpus_cursor:
                raise StateError("Evaluation corpus changed before publication could be reserved")
            actual_outcome_cursor = _upstream_outcome_corpus_cursor_from_connection(
                connection,
                request.evaluation_deployment_fingerprint,
                request.publishing_login,
                request.publishing_api_origin,
                request.run_id,
            )
            if actual_outcome_cursor != request.outcome_corpus_cursor:
                raise StateError(
                    "Upstream-outcome corpus changed before publication could be reserved"
                )
            if hold_row is None:
                connection.execute(
                    """
                    INSERT INTO publication_gate_holds(
                        run_id, deployment_fingerprint, corpus_cursor,
                        outcome_corpus_cursor, held_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        request.run_id,
                        request.evaluation_deployment_fingerprint,
                        request.evaluation_corpus_cursor,
                        request.outcome_corpus_cursor,
                        request.reserved_at.isoformat(),
                    ),
                )
                self._append_event(
                    connection,
                    request.run_id,
                    "publication.gate.held",
                    {
                        "deployment_fingerprint": request.evaluation_deployment_fingerprint,
                        "corpus_cursor": request.evaluation_corpus_cursor,
                        "outcome_corpus_cursor": request.outcome_corpus_cursor,
                        "held_at": request.reserved_at.isoformat(),
                    },
                )
                hold_created = True
            else:
                hold = _publication_gate_hold_from_row(hold_row)
                if hold.deployment_fingerprint != request.evaluation_deployment_fingerprint:
                    raise StateError("Publication run already holds different rollout evidence")
                if hold.outcome_corpus_cursor is None:
                    raise StateError(
                        "Publication gate hold predates schema-v6 upstream-outcome authority; "
                        "automatic recovery is forbidden"
                    )
                if (
                    hold.corpus_cursor != request.evaluation_corpus_cursor
                    or hold.outcome_corpus_cursor != request.outcome_corpus_cursor
                ):
                    # The corpus drifted while this run's crashed publication awaited recovery
                    # (for example lifecycle outcomes observed for other runs). The request
                    # cursors were verified against the live corpus above in this same
                    # transaction, so re-anchor the hold to the current rollout authority
                    # instead of wedging recovery behind bit-identical history.
                    rebound = connection.execute(
                        """
                        UPDATE publication_gate_holds
                        SET corpus_cursor = ?, outcome_corpus_cursor = ?, held_at = ?
                        WHERE run_id = ? AND deployment_fingerprint IS ?
                          AND corpus_cursor = ? AND outcome_corpus_cursor IS ? AND held_at = ?
                        """,
                        (
                            request.evaluation_corpus_cursor,
                            request.outcome_corpus_cursor,
                            request.reserved_at.isoformat(),
                            request.run_id,
                            hold_row["deployment_fingerprint"],
                            hold_row["corpus_cursor"],
                            hold_row["outcome_corpus_cursor"],
                            hold_row["held_at"],
                        ),
                    )
                    if rebound.rowcount != 1:
                        raise StateError(
                            "Publication gate hold changed while it was being re-anchored"
                        )
                    self._append_event(
                        connection,
                        request.run_id,
                        "publication.gate.rebound",
                        {
                            "deployment_fingerprint": request.evaluation_deployment_fingerprint,
                            "corpus_cursor": request.evaluation_corpus_cursor,
                            "outcome_corpus_cursor": request.outcome_corpus_cursor,
                            "held_at": request.reserved_at.isoformat(),
                        },
                    )
        elif hold_row is not None:
            hold = _publication_gate_hold_from_row(hold_row)
            if hold.deployment_fingerprint is None or hold.outcome_corpus_cursor is None:
                raise StateError(
                    "Publication gate hold predates schema-v6 upstream-outcome authority; "
                    "automatic recovery is forbidden"
                )
            # Re-entry without proffered rollout cursors reconciles already-durable state
            # (for example adopting a pull request that provably exists). Corpus drift since
            # the hold was anchored must not wedge that bookkeeping; every constructive
            # remote mutation still revalidates its own hold currency immediately before
            # acting.

        return _PublicationReservationResult(
            reservation=PublicationReservation(
                run_id=request.run_id,
                repository=request.repository,
                reserved_at=effective_reserved_at,
            ),
            reservation_created=reservation_created,
            hold_created=hold_created,
        )

    def stale_run_ids(self, *, stale_before: datetime, limit: int = 100) -> builtins.list[str]:
        """Return old, safely recoverable in-flight runs in deterministic order."""

        cutoff = _aware_utc(stale_before, field="stale_before")
        if not 1 <= limit <= 1_000:
            raise ValueError("stale run limit must be between 1 and 1000")
        recoverable = tuple(sorted(status.value for status in RECOVERABLE_IN_FLIGHT_STATUSES))
        placeholders = ",".join("?" for _ in recoverable)
        query = (
            # The interpolated text contains only one placeholder per member of the internal,
            # fixed RunStatus set; every value remains a bound SQLite parameter.
            "SELECT run_id, status FROM runs "
            f"WHERE status IN ({placeholders}) AND updated_at < ? "
            "ORDER BY updated_at ASC, run_id ASC LIMIT ?"
        )
        with self._connection() as connection:
            rows = connection.execute(query, (*recoverable, cutoff.isoformat(), limit)).fetchall()
        run_ids: builtins.list[str] = []
        for row in rows:
            try:
                status = RunStatus(str(row["status"]))
            except ValueError as exc:
                raise StateError(f"Run {row['run_id']} contains an unknown status") from exc
            if status not in RECOVERABLE_IN_FLIGHT_STATUSES:
                continue
            run_ids.append(str(row["run_id"]))
        return run_ids

    def is_stale_in_flight(self, run_id: str, *, stale_before: datetime) -> bool:
        """Return whether one run can safely be crash-recovered at the given cutoff."""

        cutoff = _aware_utc(stale_before, field="stale_before")
        with self._connection() as connection:
            row = connection.execute(
                "SELECT status, updated_at FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
        if row is None:
            raise StateError(f"Unknown run: {run_id}")
        try:
            status = RunStatus(str(row["status"]))
        except ValueError as exc:
            raise StateError(f"Run {run_id} contains an unknown status") from exc
        updated_at = _stored_datetime(row["updated_at"], field=f"run {run_id} updated_at")
        return status in RECOVERABLE_IN_FLIGHT_STATUSES and updated_at < cutoff

    def is_stale_nonterminal(self, run_id: str, *, stale_before: datetime) -> bool:
        """Compatibility alias for the deliberately narrower in-flight definition."""

        return self.is_stale_in_flight(run_id, stale_before=stale_before)

    def recover_stale_runs(
        self,
        *,
        stale_before: datetime,
        reason: str,
        limit: int = 100,
    ) -> builtins.list[RunManifest]:
        """Atomically fail abandoned local preparation stages and append ledger evidence."""

        cutoff = _aware_utc(stale_before, field="stale_before")
        recovery_reason = _bounded_text(reason, field="recovery reason", maximum=2_000)
        if not 1 <= limit <= 1_000:
            raise ValueError("stale run limit must be between 1 and 1000")
        recoverable = tuple(sorted(status.value for status in RECOVERABLE_IN_FLIGHT_STATUSES))
        placeholders = ",".join("?" for _ in recoverable)
        recovered_at = utc_now()
        recovered: builtins.list[RunManifest] = []
        # Only placeholder tokens are interpolated; all status values remain bound parameters.
        recovery_query = (
            "SELECT run_id, status, updated_at, manifest_json FROM runs "
            f"WHERE status IN ({placeholders}) AND updated_at < ? "
            "ORDER BY updated_at ASC, run_id ASC LIMIT ?"
        )
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                recovery_query,
                (*recoverable, cutoff.isoformat(), limit),
            ).fetchall()
            for row in rows:
                run_id = str(row["run_id"])
                previous_status = _stored_run_status(row["status"], run_id=run_id)
                if previous_status not in RECOVERABLE_IN_FLIGHT_STATUSES:
                    continue
                try:
                    manifest = RunManifest.model_validate_json(row["manifest_json"])
                except (TypeError, ValueError) as exc:
                    raise StateError(f"Run {run_id} contains an invalid manifest") from exc
                if manifest.run_id != run_id or manifest.status != previous_status:
                    raise StateError(f"Run {run_id} manifest disagrees with its state row")
                manifest.status = RunStatus.FAILED
                manifest.error = recovery_reason
                manifest.updated_at = recovered_at
                manifest_json = manifest.model_dump_json()
                result = connection.execute(
                    """
                    UPDATE runs SET status = ?, updated_at = ?, manifest_json = ?
                    WHERE run_id = ? AND status = ? AND updated_at = ?
                    """,
                    (
                        RunStatus.FAILED.value,
                        recovered_at.isoformat(),
                        manifest_json,
                        run_id,
                        previous_status.value,
                        str(row["updated_at"]),
                    ),
                )
                if result.rowcount != 1:
                    raise StateError(f"Run {run_id} changed while recovery was in progress")
                self._append_event(
                    connection,
                    run_id,
                    "run.recovered",
                    {
                        "from": previous_status.value,
                        "to": RunStatus.FAILED.value,
                        "reason": recovery_reason,
                    },
                )
                _mark_manifest_artifact_sync(
                    connection,
                    run_id=run_id,
                    updated_at=recovered_at.isoformat(),
                    manifest_json=manifest_json,
                )
                recovered.append(manifest)
        self.synchronize_manifest_artifacts()
        return recovered

    def acquire_lease(
        self,
        name: str,
        owner: str,
        *,
        ttl: timedelta,
        now: datetime | None = None,
    ) -> Lease | None:
        """Acquire/renew a lease and return its fencing generation, or refuse contention."""

        lease_name = _lease_identity(name, field="lease name")
        lease_owner = _lease_identity(owner, field="lease owner")
        acquired_at = _aware_utc(now or utc_now(), field="lease acquisition time")
        requested_expiry = _lease_expiry(acquired_at, ttl)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT owner, generation, acquired_at, heartbeat_at, expires_at
                FROM leases WHERE lease_name = ?
                """,
                (lease_name,),
            ).fetchone()
            if row is None:
                generation_row = connection.execute(
                    "SELECT generation FROM lease_generations WHERE lease_name = ?",
                    (lease_name,),
                ).fetchone()
                if generation_row is None:
                    generation = 1
                    connection.execute(
                        "INSERT INTO lease_generations(lease_name, generation) VALUES (?, ?)",
                        (lease_name, generation),
                    )
                else:
                    prior_generation = _stored_generation(
                        generation_row["generation"],
                        field=f"lease {lease_name} generation counter",
                    )
                    if prior_generation >= _MAX_GENERATION:
                        raise StateError(f"Lease {lease_name} exhausted its fencing generations")
                    generation = prior_generation + 1
                    update = connection.execute(
                        """
                        UPDATE lease_generations SET generation = ?
                        WHERE lease_name = ? AND generation = ?
                        """,
                        (generation, lease_name, prior_generation),
                    )
                    if update.rowcount != 1:
                        raise StateError(f"Lease {lease_name} generation changed while acquiring")
                connection.execute(
                    """
                    INSERT INTO leases(
                        lease_name, owner, generation, acquired_at, heartbeat_at, expires_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        lease_name,
                        lease_owner,
                        generation,
                        acquired_at.isoformat(),
                        acquired_at.isoformat(),
                        requested_expiry.isoformat(),
                    ),
                )
                return Lease(
                    name=lease_name,
                    owner=lease_owner,
                    generation=generation,
                    acquired_at=acquired_at,
                    heartbeat_at=acquired_at,
                    expires_at=requested_expiry,
                )

            current_expiry = _stored_datetime(row["expires_at"], field=f"lease {lease_name} expiry")
            current_owner = str(row["owner"])
            current_generation = _stored_generation(
                row["generation"], field=f"lease {lease_name} generation"
            )
            generation_row = connection.execute(
                "SELECT generation FROM lease_generations WHERE lease_name = ?",
                (lease_name,),
            ).fetchone()
            if (
                generation_row is None
                or _stored_generation(
                    generation_row["generation"],
                    field=f"lease {lease_name} generation counter",
                )
                != current_generation
            ):
                raise StateError(f"Lease {lease_name} fencing counter is inconsistent")
            if current_owner != lease_owner and current_expiry > acquired_at:
                return None
            original_acquired_at = _stored_datetime(
                row["acquired_at"], field=f"lease {lease_name} acquisition"
            )
            current_heartbeat = _stored_datetime(
                row["heartbeat_at"], field=f"lease {lease_name} heartbeat"
            )
            takeover = current_expiry <= acquired_at
            if takeover:
                if current_generation >= _MAX_GENERATION:
                    raise StateError(f"Lease {lease_name} exhausted its fencing generations")
                generation = current_generation + 1
                effective_acquired_at = acquired_at
                effective_expiry = requested_expiry
                counter_update = connection.execute(
                    """
                    UPDATE lease_generations SET generation = ?
                    WHERE lease_name = ? AND generation = ?
                    """,
                    (generation, lease_name, current_generation),
                )
                if counter_update.rowcount != 1:
                    raise StateError(f"Lease {lease_name} generation changed during takeover")
            else:
                if current_owner != lease_owner or acquired_at < current_heartbeat:
                    return None
                generation = current_generation
                effective_acquired_at = original_acquired_at
                effective_expiry = max(current_expiry, requested_expiry)
            update = connection.execute(
                """
                UPDATE leases SET owner = ?, generation = ?, acquired_at = ?,
                    heartbeat_at = ?, expires_at = ?
                WHERE lease_name = ? AND generation = ?
                """,
                (
                    lease_owner,
                    generation,
                    effective_acquired_at.isoformat(),
                    acquired_at.isoformat(),
                    effective_expiry.isoformat(),
                    lease_name,
                    current_generation,
                ),
            )
            if update.rowcount != 1:
                raise StateError(f"Lease {lease_name} changed while acquiring")
            return Lease(
                name=lease_name,
                owner=lease_owner,
                generation=generation,
                acquired_at=effective_acquired_at,
                heartbeat_at=acquired_at,
                expires_at=effective_expiry,
            )

    def heartbeat_lease(
        self,
        name: str,
        owner: str,
        generation: int,
        *,
        ttl: timedelta,
        now: datetime | None = None,
    ) -> Lease | None:
        """Monotonically extend a live lease only for its current fencing generation."""

        lease_name = _lease_identity(name, field="lease name")
        lease_owner = _lease_identity(owner, field="lease owner")
        lease_generation = _generation(generation)
        heartbeat_at = _aware_utc(now or utc_now(), field="lease heartbeat time")
        requested_expiry = _lease_expiry(heartbeat_at, ttl)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT owner, generation, acquired_at, heartbeat_at, expires_at
                FROM leases WHERE lease_name = ?
                """,
                (lease_name,),
            ).fetchone()
            if row is None:
                return None
            stored_generation = _stored_generation(
                row["generation"], field=f"lease {lease_name} generation"
            )
            generation_row = connection.execute(
                "SELECT generation FROM lease_generations WHERE lease_name = ?",
                (lease_name,),
            ).fetchone()
            if (
                generation_row is None
                or _stored_generation(
                    generation_row["generation"],
                    field=f"lease {lease_name} generation counter",
                )
                != stored_generation
            ):
                raise StateError(f"Lease {lease_name} fencing counter is inconsistent")
            if str(row["owner"]) != lease_owner or stored_generation != lease_generation:
                return None
            current_expiry = _stored_datetime(row["expires_at"], field=f"lease {lease_name} expiry")
            if current_expiry <= heartbeat_at:
                return None
            current_heartbeat = _stored_datetime(
                row["heartbeat_at"], field=f"lease {lease_name} heartbeat"
            )
            if heartbeat_at < current_heartbeat:
                return None
            effective_expiry = max(current_expiry, requested_expiry)
            update = connection.execute(
                """
                UPDATE leases SET heartbeat_at = ?, expires_at = ?
                WHERE lease_name = ? AND owner = ? AND generation = ?
                """,
                (
                    heartbeat_at.isoformat(),
                    effective_expiry.isoformat(),
                    lease_name,
                    lease_owner,
                    lease_generation,
                ),
            )
            if update.rowcount != 1:
                raise StateError(f"Lease {lease_name} changed while heartbeating")
            return Lease(
                name=lease_name,
                owner=lease_owner,
                generation=lease_generation,
                acquired_at=_stored_datetime(
                    row["acquired_at"], field=f"lease {lease_name} acquisition"
                ),
                heartbeat_at=heartbeat_at,
                expires_at=effective_expiry,
            )

    def release_lease(self, name: str, owner: str, generation: int) -> bool:
        """Release a lease only for its current owner and fencing generation."""

        lease_name = _lease_identity(name, field="lease name")
        lease_owner = _lease_identity(owner, field="lease owner")
        lease_generation = _generation(generation)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT owner, generation FROM leases WHERE lease_name = ?
                """,
                (lease_name,),
            ).fetchone()
            if row is None:
                return False
            stored_generation = _stored_generation(
                row["generation"], field=f"lease {lease_name} generation"
            )
            generation_row = connection.execute(
                "SELECT generation FROM lease_generations WHERE lease_name = ?",
                (lease_name,),
            ).fetchone()
            if (
                generation_row is None
                or _stored_generation(
                    generation_row["generation"],
                    field=f"lease {lease_name} generation counter",
                )
                != stored_generation
            ):
                raise StateError(f"Lease {lease_name} fencing counter is inconsistent")
            if str(row["owner"]) != lease_owner or stored_generation != lease_generation:
                return False
            result = connection.execute(
                """
                DELETE FROM leases
                WHERE lease_name = ? AND owner = ? AND generation = ?
                """,
                (lease_name, lease_owner, lease_generation),
            )
            if result.rowcount != 1:
                raise StateError(f"Lease {lease_name} changed while releasing")
            return True

    def get_lease(self, name: str) -> Lease | None:
        lease_name = _lease_identity(name, field="lease name")
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT leases.owner,
                       leases.generation AS lease_generation,
                       lease_generations.generation AS counter_generation,
                       leases.acquired_at, leases.heartbeat_at, leases.expires_at
                FROM leases
                LEFT JOIN lease_generations USING (lease_name)
                WHERE leases.lease_name = ?
                """,
                (lease_name,),
            ).fetchone()
        if row is None:
            return None
        lease_generation = _stored_generation(
            row["lease_generation"], field=f"lease {lease_name} generation"
        )
        if (
            row["counter_generation"] is None
            or _stored_generation(
                row["counter_generation"], field=f"lease {lease_name} generation counter"
            )
            != lease_generation
        ):
            raise StateError(f"Lease {lease_name} fencing counter is inconsistent")
        return Lease(
            name=lease_name,
            owner=str(row["owner"]),
            generation=lease_generation,
            acquired_at=_stored_datetime(
                row["acquired_at"], field=f"lease {lease_name} acquisition"
            ),
            heartbeat_at=_stored_datetime(
                row["heartbeat_at"], field=f"lease {lease_name} heartbeat"
            ),
            expires_at=_stored_datetime(row["expires_at"], field=f"lease {lease_name} expiry"),
        )

    def assert_lease(
        self,
        name: str,
        owner: str,
        generation: int,
        *,
        now: datetime | None = None,
    ) -> Lease:
        """Return the current lease or fail closed when ownership/fencing has been lost."""

        lease_name = _lease_identity(name, field="lease name")
        lease_owner = _lease_identity(owner, field="lease owner")
        lease_generation = _generation(generation)
        checked_at = _aware_utc(now or utc_now(), field="lease check time")
        lease = self.get_lease(lease_name)
        if (
            lease is None
            or lease.owner != lease_owner
            or lease.generation != lease_generation
            or lease.expires_at <= checked_at
        ):
            raise StateError(f"Lease {lease_name} is no longer owned by this worker")
        return lease

    def record_lifecycle_snapshot(self, run_id: str, fingerprint: str, snapshot_json: str) -> bool:
        """Persist one immutable lifecycle observation, deduplicated by its fingerprint."""

        normalized_run_id = _lease_identity(run_id, field="run id")
        observed_at = utc_now()
        normalized_fingerprint = _sha256_identity(fingerprint, field="lifecycle fingerprint")
        parsed_snapshot = _validated_snapshot_json(snapshot_json, observed_at=observed_at)
        if parsed_snapshot.fingerprint() != normalized_fingerprint:
            raise ValueError("lifecycle fingerprint does not match the canonical snapshot")
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if (
                connection.execute(
                    "SELECT 1 FROM runs WHERE run_id = ?", (normalized_run_id,)
                ).fetchone()
                is None
            ):
                raise StateError(f"Unknown run: {normalized_run_id}")
            _verify_event_anchors(connection, selected_run_id=normalized_run_id)
            _verify_lifecycle_snapshot_evidence(
                connection,
                selected_run_id=normalized_run_id,
                collect=False,
            )
            existing = connection.execute(
                """
                SELECT snapshot_json FROM lifecycle_snapshots
                WHERE run_id = ? AND fingerprint = ?
                """,
                (normalized_run_id, normalized_fingerprint),
            ).fetchone()
            if existing is not None:
                if str(existing["snapshot_json"]) != snapshot_json:
                    raise StateError(
                        "Lifecycle fingerprint was reused for different snapshot content"
                    )
                return False
            connection.execute(
                """
                INSERT INTO lifecycle_snapshots(
                    run_id, fingerprint, observed_at, snapshot_json
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    normalized_run_id,
                    normalized_fingerprint,
                    observed_at.isoformat(),
                    snapshot_json,
                ),
            )
            self._append_event(
                connection,
                normalized_run_id,
                "lifecycle.snapshot.recorded",
                {"fingerprint": normalized_fingerprint},
            )
        return True

    def lifecycle_snapshots(self, run_id: str) -> builtins.list[LifecycleSnapshot]:
        """Return strictly parsed snapshots in their verified per-run ledger order."""

        normalized_run_id = _lease_identity(run_id, field="run id")
        with self._connection() as connection:
            connection.execute("BEGIN")
            _verify_event_anchors(connection, selected_run_id=normalized_run_id)
            return _verify_lifecycle_snapshot_evidence(
                connection,
                selected_run_id=normalized_run_id,
            )

    def trip_circuit_breaker(self, *, source: str, reason: str, trigger_hash: str) -> bool:
        """Trip persistently and make each new immutable trigger the active revision."""

        normalized_source = _bounded_text(source, field="circuit-breaker source", maximum=255)
        normalized_reason = _bounded_text(reason, field="circuit-breaker reason", maximum=2_000)
        normalized_hash = _lease_identity(trigger_hash, field="circuit-breaker trigger hash")
        occurred_at = utc_now()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._circuit_breaker_row(connection)
            epoch = _stored_generation(row["epoch"], field="circuit-breaker epoch")
            result = connection.execute(
                """
                INSERT INTO circuit_breaker_events(
                    epoch, occurred_at, event_type, source, reason, trigger_hash
                ) VALUES (?, ?, 'trip', ?, ?, ?)
                ON CONFLICT(event_type, trigger_hash) DO NOTHING
                """,
                (
                    epoch,
                    occurred_at.isoformat(),
                    normalized_source,
                    normalized_reason,
                    normalized_hash,
                ),
            )
            if result.rowcount != 1:
                existing = connection.execute(
                    """
                    SELECT source, reason FROM circuit_breaker_events
                    WHERE event_type = 'trip' AND trigger_hash = ?
                    """,
                    (normalized_hash,),
                ).fetchone()
                if existing is None:
                    raise StateError("Circuit-breaker trigger could not be recorded")
                if (
                    str(existing["source"]) != normalized_source
                    or str(existing["reason"]) != normalized_reason
                ):
                    raise StateError(
                        "Circuit-breaker trigger hash was reused for different evidence"
                    )
                return False
            update = connection.execute(
                """
                UPDATE circuit_breaker
                SET is_tripped = 1, changed_at = ?, source = ?, reason = ?, trigger_hash = ?
                WHERE singleton = 1 AND epoch = ?
                """,
                (
                    occurred_at.isoformat(),
                    normalized_source,
                    normalized_reason,
                    normalized_hash,
                    epoch,
                ),
            )
            if update.rowcount != 1:
                raise StateError("Circuit-breaker state changed while tripping")
        return True

    def trip_circuit_breaker_trigger(self, trigger: CircuitBreakerTrigger) -> bool:
        """Persist a typed trigger emitted by an external safety boundary."""

        return self.trip_circuit_breaker(
            source=trigger.source,
            reason=trigger.reason,
            trigger_hash=trigger.trigger_hash,
        )

    def circuit_breaker_status(self) -> CircuitBreakerStatus:
        with self._connection() as connection:
            row = self._circuit_breaker_row(connection)
            epoch = _stored_generation(row["epoch"], field="circuit-breaker epoch")
            active_triggers = self._active_circuit_breaker_triggers(connection, epoch=epoch)
        is_tripped = _stored_boolean(row["is_tripped"], field="circuit-breaker status")
        source = _optional_stored_text(row["source"])
        reason = _optional_stored_text(row["reason"])
        trigger_hash = _optional_stored_text(row["trigger_hash"])
        evidence = (source, reason, trigger_hash)
        if (is_tripped and not all(value is not None for value in evidence)) or (
            not is_tripped and any(value is not None for value in evidence)
        ):
            raise StateError("Circuit-breaker state is internally inconsistent")
        if is_tripped != bool(active_triggers):
            raise StateError("Circuit-breaker active evidence is internally inconsistent")
        return CircuitBreakerStatus(
            is_tripped=is_tripped,
            epoch=epoch,
            changed_at=_stored_datetime(row["changed_at"], field="circuit-breaker change time"),
            source=source,
            reason=reason,
            trigger_hash=trigger_hash,
            active_revision=(
                self._circuit_breaker_revision(active_triggers) if active_triggers else None
            ),
            active_triggers=active_triggers,
        )

    def assert_circuit_breaker_clear(self) -> None:
        status = self.circuit_breaker_status()
        if status.is_tripped:
            raise StateError(f"Circuit breaker is tripped by {status.source}: {status.reason}")

    def resume_circuit_breaker(
        self,
        *,
        actor: str,
        reason: str,
        expected_trigger_hash: str,
    ) -> bool:
        """Resume only the exact active trigger revision reviewed by an operator."""

        normalized_actor = _bounded_text(actor, field="resume actor", maximum=255)
        normalized_reason = _bounded_text(reason, field="resume reason", maximum=2_000)
        normalized_expected_hash = _lease_identity(
            expected_trigger_hash,
            field="expected circuit-breaker trigger hash",
        )
        occurred_at = utc_now()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._circuit_breaker_row(connection)
            if not _stored_boolean(row["is_tripped"], field="circuit-breaker status"):
                return False
            epoch = _stored_generation(row["epoch"], field="circuit-breaker epoch")
            active_triggers = self._active_circuit_breaker_triggers(connection, epoch=epoch)
            active_revision = self._circuit_breaker_revision(active_triggers)
            if active_revision != normalized_expected_hash:
                raise StateError(
                    "Circuit-breaker evidence changed after review; inspect the active "
                    "trigger-set revision before resuming"
                )
            if epoch >= _MAX_GENERATION:
                raise StateError("Circuit breaker exhausted its audit epochs")
            connection.execute(
                """
                INSERT INTO circuit_breaker_events(
                    epoch, occurred_at, event_type, source, reason, trigger_hash
                ) VALUES (?, ?, 'resume', ?, ?, ?)
                """,
                (
                    epoch,
                    occurred_at.isoformat(),
                    normalized_actor,
                    normalized_reason,
                    normalized_expected_hash,
                ),
            )
            update = connection.execute(
                """
                UPDATE circuit_breaker SET is_tripped = 0, epoch = ?, changed_at = ?,
                    source = NULL, reason = NULL, trigger_hash = NULL
                WHERE singleton = 1 AND is_tripped = 1 AND epoch = ? AND trigger_hash = ?
                """,
                (
                    epoch + 1,
                    occurred_at.isoformat(),
                    epoch,
                    _optional_stored_text(row["trigger_hash"]),
                ),
            )
            if update.rowcount != 1:
                raise StateError("Circuit-breaker state changed while resuming")
        return True

    @staticmethod
    def _circuit_breaker_row(connection: sqlite3.Connection) -> sqlite3.Row:
        rows = connection.execute(
            """
            SELECT is_tripped, epoch, changed_at, source, reason, trigger_hash
            FROM circuit_breaker WHERE singleton = 1
            """
        ).fetchall()
        if len(rows) != 1:
            raise StateError("Circuit-breaker state must contain one canonical row")
        return cast("sqlite3.Row", rows[0])

    @staticmethod
    def _active_circuit_breaker_triggers(
        connection: sqlite3.Connection,
        *,
        epoch: int,
    ) -> tuple[CircuitBreakerTrigger, ...]:
        rows = connection.execute(
            """
            SELECT source, reason, trigger_hash
            FROM circuit_breaker_events
            WHERE epoch = ? AND event_type = 'trip'
            ORDER BY id
            """,
            (epoch,),
        ).fetchall()
        if len(rows) > _MAX_ACTIVE_CIRCUIT_BREAKER_TRIGGERS:
            raise StateError("Circuit-breaker active evidence exceeds the safe bound")
        return tuple(
            CircuitBreakerTrigger(
                source=str(row["source"]),
                reason=str(row["reason"]),
                trigger_hash=str(row["trigger_hash"]),
            )
            for row in rows
        )

    @staticmethod
    def _circuit_breaker_revision(triggers: tuple[CircuitBreakerTrigger, ...]) -> str:
        if not triggers:
            raise StateError("Circuit-breaker active evidence is missing")
        return hashlib.sha256(
            _canonical_json(
                [
                    {
                        "reason": trigger.reason,
                        "source": trigger.source,
                        "trigger_hash": trigger.trigger_hash,
                    }
                    for trigger in triggers
                ]
            ).encode()
        ).hexdigest()

    def create_snapshot(self, destination: Path, *, overwrite: bool = False) -> Path:
        """Atomically write a consistent SQLite backup, including committed WAL pages."""

        self.synchronize_manifest_artifacts()
        requested_target = destination.expanduser()
        if requested_target.is_symlink():
            raise StateError("Snapshot destination cannot be a symbolic link")
        target = requested_target.resolve()
        live_paths = {
            self.database_path,
            Path(f"{self.database_path}-wal"),
            Path(f"{self.database_path}-shm"),
            Path(f"{self.database_path}-journal"),
        }
        if target in live_paths:
            raise StateError("Snapshot destination cannot replace live SQLite state")
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and not target.is_file():
            raise StateError("Snapshot destination must be a regular file path")
        if target.exists() and not overwrite:
            raise StateError("Snapshot destination already exists; pass overwrite explicitly")
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
        )
        os.close(descriptor)
        temporary = Path(temporary_name)
        source: sqlite3.Connection | None = None
        backup: sqlite3.Connection | None = None
        try:
            source = sqlite3.connect(self.database_path, timeout=30)
            backup = sqlite3.connect(temporary, timeout=30)
            source.backup(backup)
            row = backup.execute("PRAGMA integrity_check").fetchone()
            if row is None or row[0] != "ok":
                raise StateError("SQLite rejected the completed state snapshot")
            backup.row_factory = sqlite3.Row
            self._validate_current_schema(backup)
            backup.close()
            backup = None
            source.close()
            source = None
            with temporary.open("rb") as snapshot_file:
                os.fsync(snapshot_file.fileno())
            if overwrite:
                os.replace(temporary, target)
            else:
                try:
                    os.link(temporary, target, follow_symlinks=False)
                except FileExistsError as exc:
                    raise StateError("Snapshot destination appeared during backup") from exc
                temporary.unlink()
            _fsync_directory(target.parent)
            return target
        except (OSError, sqlite3.Error) as exc:
            raise StateError(f"Could not create state snapshot: {exc}") from exc
        finally:
            if backup is not None:
                backup.close()
            if source is not None:
                source.close()
            temporary.unlink(missing_ok=True)

    @classmethod
    def restore_snapshot(cls, root: Path, source: Path) -> Path:
        """Validate and atomically promote a standalone snapshot before opening live state."""

        requested_source = source.expanduser()
        if requested_source.is_symlink():
            raise StateError("State snapshot source cannot be a symbolic link")
        try:
            snapshot = requested_source.resolve(strict=True)
        except OSError as exc:
            raise StateError(f"State snapshot source is unavailable: {exc}") from exc
        if not snapshot.is_file():
            raise StateError("State snapshot source must be a regular file")

        requested_root = root.expanduser()
        if requested_root.is_symlink():
            raise StateError("State storage root cannot be a symbolic link during restore")
        target_root = requested_root.resolve()
        target_root.mkdir(parents=True, exist_ok=True)
        target = target_root / "state.sqlite3"
        live_paths = (
            target,
            Path(f"{target}-wal"),
            Path(f"{target}-shm"),
            Path(f"{target}-journal"),
        )
        if any(path.exists() or path.is_symlink() for path in live_paths):
            raise StateError("Refusing to restore over existing live SQLite state")
        if snapshot == target:
            raise StateError("State snapshot source cannot be the live database path")

        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".state.sqlite3.", suffix=".restore", dir=target_root
        )
        temporary = Path(temporary_name)
        validation: sqlite3.Connection | None = None
        source_descriptor = -1
        try:
            source_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            source_descriptor = os.open(snapshot, source_flags)
            try:
                source_file = os.fdopen(source_descriptor, "rb")
            except BaseException:
                with suppress(OSError):
                    os.close(source_descriptor)
                source_descriptor = -1
                raise
            source_descriptor = -1
            with source_file:
                destination_file = os.fdopen(descriptor, "wb")
                descriptor = -1
                with destination_file:
                    if not stat.S_ISREG(os.fstat(source_file.fileno()).st_mode):
                        raise StateError("State snapshot source must be a regular file")
                    while chunk := source_file.read(1024 * 1024):
                        destination_file.write(chunk)
                    destination_file.flush()
                    os.fsync(destination_file.fileno())

            validation = sqlite3.connect(
                f"{temporary.resolve().as_uri()}?mode=ro&immutable=1", uri=True
            )
            row = validation.execute("PRAGMA integrity_check").fetchone()
            if row is None or row[0] != "ok":
                raise StateError("SQLite rejected the restored state snapshot")
            validation.row_factory = sqlite3.Row
            cls._validate_restorable_schema(validation)
            validation.close()
            validation = None
            try:
                os.link(temporary, target, follow_symlinks=False)
            except FileExistsError as exc:
                raise StateError("Live state appeared while the snapshot was restored") from exc
            temporary.unlink()
            _fsync_directory(target_root)
            return target
        except StateError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise StateError(f"Could not restore state snapshot: {exc}") from exc
        finally:
            if validation is not None:
                validation.close()
            if descriptor >= 0:
                with suppress(OSError):
                    os.close(descriptor)
            if source_descriptor >= 0:
                with suppress(OSError):
                    os.close(source_descriptor)
            temporary.unlink(missing_ok=True)

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

    def verify_event_chains(self, *, run_id: str | None = None) -> None:
        """Verify every selected event chain and its durable run-row anchor."""

        selected_run_id: str | None = None
        if run_id is not None:
            selected_run_id = _lease_identity(run_id, field="event run id")
        with self._connection() as connection:
            connection.execute("BEGIN")
            _verify_event_anchors(connection, selected_run_id=selected_run_id)

    def evaluation_corpus_cursor(self) -> str:
        """Hash the complete bounded evaluation-event corpus in ledger order."""

        with self._connection() as connection:
            connection.execute("BEGIN")
            return _evaluation_corpus_cursor_from_connection(connection)

    def upstream_outcome_corpus_cursor(
        self,
        deployment_fingerprint: str,
        publishing_login: str,
        publishing_api_origin: str,
        *,
        exclude_run_id: str | None = None,
    ) -> str:
        """Hash all deployment evidence that can affect an upstream-outcome decision."""

        scope = _upstream_outcome_cursor_scope(
            deployment_fingerprint,
            publishing_login,
            publishing_api_origin,
            exclude_run_id=exclude_run_id,
        )
        with self._connection() as connection:
            connection.execute("BEGIN")
            return _upstream_outcome_corpus_cursor_from_connection(connection, *scope)

    def record_evaluation_anchor(self, run_id: str, details: dict[str, str]) -> None:
        """Atomically append one evaluation anchor without rewriting the run manifest."""

        normalized_run_id = _lease_identity(run_id, field="evaluation run id")
        _validate_evaluation_anchor_details(details)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            _assert_no_publication_gate_hold(connection)
            if (
                connection.execute(
                    "SELECT 1 FROM runs WHERE run_id = ?", (normalized_run_id,)
                ).fetchone()
                is None
            ):
                raise StateError(f"Unknown run: {normalized_run_id}")
            if (
                connection.execute(
                    """
                    SELECT 1 FROM events
                    WHERE run_id = ?
                      AND event_type IN ('evaluation.recorded', 'evaluation.amended')
                    LIMIT 1
                    """,
                    (normalized_run_id,),
                ).fetchone()
                is not None
            ):
                raise StateError(f"Run {normalized_run_id} already has an evaluation anchor")
            self._append_event(
                connection,
                normalized_run_id,
                "evaluation.recorded",
                details,
            )

    def record_evaluation_amendment_anchor(
        self,
        run_id: str,
        details: dict[str, str],
        *,
        expected_previous_hash: str,
    ) -> None:
        """Append an amendment only when it extends the current evaluation revision."""

        normalized_run_id = _lease_identity(run_id, field="evaluation run id")
        _validate_evaluation_anchor_details(details)
        previous_hash = _stored_event_hash(
            expected_previous_hash,
            field="expected previous evaluation hash",
        )
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            _assert_no_publication_gate_hold(connection)
            if (
                connection.execute(
                    "SELECT 1 FROM runs WHERE run_id = ?", (normalized_run_id,)
                ).fetchone()
                is None
            ):
                raise StateError(f"Unknown run: {normalized_run_id}")
            rows = connection.execute(
                """
                SELECT event_type, details_json FROM events
                WHERE run_id = ?
                  AND event_type IN ('evaluation.recorded', 'evaluation.amended')
                ORDER BY id
                """,
                (normalized_run_id,),
            ).fetchall()
            if not rows or rows[0]["event_type"] != "evaluation.recorded":
                raise StateError(
                    f"Run {normalized_run_id} does not have an initial evaluation anchor"
                )
            if any(row["event_type"] != "evaluation.amended" for row in rows[1:]):
                raise StateError(f"Run {normalized_run_id} has an invalid evaluation history")
            latest_details_value = rows[-1]["details_json"]
            if not isinstance(latest_details_value, str):
                raise StateError("Evaluation revision anchor contains invalid stored values")
            try:
                latest_details = json.loads(latest_details_value)
            except json.JSONDecodeError as exc:
                raise StateError("Evaluation revision anchor contains malformed details") from exc
            if not isinstance(latest_details, dict):
                raise StateError("Evaluation revision anchor contains malformed details")
            latest_hash = latest_details.get("evaluation_hash")
            if latest_hash != previous_hash:
                raise StateError(
                    f"Run {normalized_run_id} evaluation changed before the amendment was recorded"
                )
            self._append_event(
                connection,
                normalized_run_id,
                "evaluation.amended",
                details,
            )

    def evaluation_record_anchors(self, *, limit: int = 10_000) -> builtins.list[dict[str, str]]:
        """Return the complete bounded set of durable evaluation-record events."""

        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("evaluation anchor limit must be an integer")
        if not 1 <= limit <= 10_000:
            raise ValueError("evaluation anchor limit must be between 1 and 10000")
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT run_id, details_json FROM events
                WHERE event_type = 'evaluation.recorded'
                ORDER BY id LIMIT ?
                """,
                (limit + 1,),
            ).fetchall()
        if len(rows) > limit:
            raise StateError("Evaluation record anchor set exceeds the configured safety bound")

        anchors: builtins.list[dict[str, str]] = []
        seen_run_ids: set[str] = set()
        for row in rows:
            run_id_value = row["run_id"]
            details_value = row["details_json"]
            if not isinstance(run_id_value, str) or not isinstance(details_value, str):
                raise StateError("Evaluation record anchor contains invalid stored values")
            try:
                parsed_details = json.loads(details_value)
            except json.JSONDecodeError as exc:
                raise StateError("Evaluation record anchor contains malformed details") from exc
            if not isinstance(parsed_details, dict) or not all(
                isinstance(key, str) and isinstance(value, str)
                for key, value in parsed_details.items()
            ):
                raise StateError("Evaluation record anchor contains malformed details")
            if run_id_value in seen_run_ids:
                raise StateError(f"Duplicate evaluation record anchor for run {run_id_value}")
            seen_run_ids.add(run_id_value)
            anchors.append({"run_id": run_id_value, "details": details_value})
        return anchors

    def evaluation_revision_anchors(
        self,
        *,
        limit: int = 10_000,
    ) -> builtins.list[dict[str, str]]:
        """Return all initial and amendment anchors in immutable ledger order."""

        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("evaluation revision anchor limit must be an integer")
        if not 1 <= limit <= 10_000:
            raise ValueError("evaluation revision anchor limit must be between 1 and 10000")
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT run_id, event_type, details_json FROM events
                WHERE event_type IN ('evaluation.recorded', 'evaluation.amended')
                ORDER BY id LIMIT ?
                """,
                (limit + 1,),
            ).fetchall()
        if len(rows) > limit:
            raise StateError("Evaluation revision anchor set exceeds the configured safety bound")

        anchors: builtins.list[dict[str, str]] = []
        for row in rows:
            run_id_value = row["run_id"]
            event_type_value = row["event_type"]
            details_value = row["details_json"]
            if (
                not isinstance(run_id_value, str)
                or event_type_value not in {"evaluation.recorded", "evaluation.amended"}
                or not isinstance(details_value, str)
            ):
                raise StateError("Evaluation revision anchor contains invalid stored values")
            try:
                parsed_details = json.loads(details_value)
            except json.JSONDecodeError as exc:
                raise StateError("Evaluation revision anchor contains malformed details") from exc
            if not isinstance(parsed_details, dict) or not all(
                isinstance(key, str) and isinstance(value, str)
                for key, value in parsed_details.items()
            ):
                raise StateError("Evaluation revision anchor contains malformed details")
            anchors.append(
                {
                    "run_id": run_id_value,
                    "event_type": event_type_value,
                    "details": details_value,
                }
            )
        return anchors

    def _append_event(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        event_type: str,
        details: dict[str, str],
        *,
        occurred_at: str | None = None,
    ) -> None:
        _append_event_to_ledger(
            connection,
            run_id,
            event_type,
            details,
            occurred_at=occurred_at,
        )

    def synchronize_manifest_artifacts(self, *, limit: int = _MAX_RUN_CORPUS) -> int:
        """Publish only explicitly pending manifest artifacts and clear their exact markers."""

        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("manifest artifact synchronization limit must be an integer")
        if not 1 <= limit <= _MAX_RUN_CORPUS:
            raise ValueError("manifest artifact synchronization limit must be between 1 and 10000")
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT run_id, updated_at, manifest_sha256
                FROM manifest_artifact_sync ORDER BY updated_at, run_id LIMIT ?
                """,
                (limit + 1,),
            ).fetchall()
        if len(rows) > limit:
            raise _ManifestArtifactSyncError(
                "Pending manifest artifact set exceeds the configured safety bound"
            )

        synchronized = 0
        for row in rows:
            run_id = row["run_id"]
            updated_at = row["updated_at"]
            manifest_sha256 = row["manifest_sha256"]
            if not all(isinstance(value, str) and value for value in (run_id, updated_at)):
                raise _ManifestArtifactSyncError(
                    "Manifest artifact synchronization marker contains invalid stored values"
                )
            try:
                digest = _stored_event_hash(
                    manifest_sha256,
                    field=f"run {run_id} pending manifest digest",
                )
                _stored_datetime(
                    updated_at,
                    field=f"run {run_id} pending manifest update time",
                )
            except StateError as exc:
                raise _ManifestArtifactSyncError(str(exc)) from exc
            if self._synchronize_manifest_artifact(
                run_id,
                updated_at=updated_at,
                manifest_sha256=digest,
            ):
                synchronized += 1
        return synchronized

    def _synchronize_manifest_artifact(
        self,
        run_id: str,
        *,
        updated_at: str,
        manifest_sha256: str,
    ) -> bool:
        """Publish one exact pending version while a SQLite write lock excludes stale writers."""

        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                pending = connection.execute(
                    """
                    SELECT updated_at, manifest_sha256 FROM manifest_artifact_sync
                    WHERE run_id = ?
                    """,
                    (run_id,),
                ).fetchone()
                if pending is None:
                    return False
                if (
                    pending["updated_at"] != updated_at
                    or pending["manifest_sha256"] != manifest_sha256
                ):
                    return False
                row = connection.execute(
                    "SELECT updated_at, manifest_json FROM runs WHERE run_id = ?",
                    (run_id,),
                ).fetchone()
                if row is None:
                    raise StateError(f"Pending manifest artifact references unknown run {run_id}")
                manifest_json = row["manifest_json"]
                if not isinstance(manifest_json, str):
                    raise StateError(f"Run {run_id} contains an invalid manifest")
                if (
                    row["updated_at"] != updated_at
                    or _manifest_json_digest(manifest_json) != manifest_sha256
                ):
                    raise StateError(
                        f"Pending manifest artifact for run {run_id} disagrees with durable state"
                    )
                try:
                    manifest = RunManifest.model_validate_json(manifest_json)
                except (TypeError, ValueError) as exc:
                    raise StateError(f"Run {run_id} contains an invalid manifest") from exc
                if manifest.run_id != run_id or manifest.updated_at.isoformat() != updated_at:
                    raise StateError(
                        f"Pending manifest artifact for run {run_id} disagrees with its state row"
                    )

                # The write lock spans file publication and marker deletion. A stale publisher
                # therefore cannot overwrite the file or clear a newer pending version.
                self._write_manifest(manifest)
                deletion = connection.execute(
                    """
                    DELETE FROM manifest_artifact_sync
                    WHERE run_id = ? AND updated_at = ? AND manifest_sha256 = ?
                    """,
                    (run_id, updated_at, manifest_sha256),
                )
                if deletion.rowcount != 1:
                    raise StateError(
                        f"Pending manifest artifact for run {run_id} changed during publication"
                    )
                return True
        except _ManifestArtifactSyncError:
            raise
        except Exception as exc:
            raise _ManifestArtifactSyncError(
                f"Could not synchronize manifest artifact for run {run_id}: {exc}"
            ) from exc

    def _write_manifest(self, manifest: RunManifest) -> None:
        path = self.artifact_dir(manifest.run_id) / "manifest.json"
        temporary = path.with_suffix(".json.tmp")
        with temporary.open("w", encoding="utf-8") as output:
            output.write(json.dumps(manifest.model_dump(mode="json"), indent=2, sort_keys=True))
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)


def _append_event_to_ledger(
    connection: sqlite3.Connection,
    run_id: str,
    event_type: str,
    details: dict[str, str],
    *,
    occurred_at: str | None = None,
) -> None:
    run_row = connection.execute(
        "SELECT event_count, event_head_hash FROM runs WHERE run_id = ?",
        (run_id,),
    ).fetchone()
    if run_row is None:
        raise StateError(f"Unknown run: {run_id}")
    stored_count = _stored_event_count(run_row["event_count"], field=f"run {run_id} event count")
    stored_head = _stored_event_hash(run_row["event_head_hash"], field=f"run {run_id} event head")
    ledger_row = connection.execute(
        """
        SELECT count(*) AS event_count,
               (SELECT event_hash FROM events
                WHERE run_id = ? ORDER BY id DESC LIMIT 1) AS event_head_hash
        FROM events WHERE run_id = ?
        """,
        (run_id, run_id),
    ).fetchone()
    if ledger_row is None:  # pragma: no cover - aggregate queries always return one row
        raise StateError(f"Unable to inspect event ledger for run {run_id}")
    actual_count = _stored_event_count(
        ledger_row["event_count"], field=f"run {run_id} ledger event count"
    )
    actual_head_value = ledger_row["event_head_hash"]
    actual_head = (
        _INITIAL_EVENT_HASH
        if actual_head_value is None
        else _stored_event_hash(actual_head_value, field=f"run {run_id} ledger event head")
    )
    if stored_count != actual_count or stored_head != actual_head:
        raise StateError(f"Event ledger anchor mismatch for run {run_id}")
    previous_hash = stored_head
    if occurred_at is None:
        occurred_at = utc_now().isoformat()
    else:
        _stored_canonical_utc_datetime(occurred_at, field="event occurrence time")
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
    insert = connection.execute(
        """
        INSERT INTO events(
            run_id, occurred_at, event_type, details_json, previous_hash, event_hash
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (run_id, occurred_at, event_type, details_json, previous_hash, event_hash),
    )
    if insert.rowcount != 1:
        raise StateError(f"Event append failed for run {run_id}")
    update = connection.execute(
        """
        UPDATE runs
        SET event_count = ?, event_head_hash = ?
        WHERE run_id = ? AND event_count = ? AND event_head_hash = ?
        """,
        (stored_count + 1, event_hash, run_id, stored_count, stored_head),
    )
    if update.rowcount != 1:
        raise StateError(f"Event ledger anchor changed while appending to run {run_id}")


def _manifest_json_digest(manifest_json: str) -> str:
    if not isinstance(manifest_json, str):
        raise TypeError("manifest JSON must be a string")
    return hashlib.sha256(manifest_json.encode("utf-8")).hexdigest()


def _mark_manifest_artifact_sync(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    updated_at: str,
    manifest_json: str,
) -> None:
    """Record the exact file version in the same transaction as its run-row write."""

    row = connection.execute(
        "SELECT updated_at, manifest_json FROM runs WHERE run_id = ?",
        (run_id,),
    ).fetchone()
    if row is None or row["updated_at"] != updated_at or row["manifest_json"] != manifest_json:
        raise StateError(f"Run {run_id} changed before its manifest artifact was marked")
    manifest_sha256 = _manifest_json_digest(manifest_json)
    connection.execute(
        """
        INSERT INTO manifest_artifact_sync(run_id, updated_at, manifest_sha256)
        VALUES (?, ?, ?)
        ON CONFLICT(run_id) DO UPDATE SET
            updated_at = excluded.updated_at,
            manifest_sha256 = excluded.manifest_sha256
        """,
        (run_id, updated_at, manifest_sha256),
    )


def _verify_manifest_artifact_sync(connection: sqlite3.Connection) -> None:
    rows = connection.execute(
        """
        SELECT manifest_artifact_sync.run_id,
               manifest_artifact_sync.updated_at AS pending_updated_at,
               manifest_artifact_sync.manifest_sha256,
               runs.updated_at AS run_updated_at,
               runs.manifest_json
        FROM manifest_artifact_sync
        JOIN runs USING(run_id)
        ORDER BY manifest_artifact_sync.run_id LIMIT ?
        """,
        (_MAX_RUN_CORPUS + 1,),
    ).fetchall()
    if len(rows) > _MAX_RUN_CORPUS:
        raise StateError("Pending manifest artifact set exceeds the configured safety bound")
    for row in rows:
        run_id = row["run_id"]
        pending_updated_at = row["pending_updated_at"]
        manifest_json = row["manifest_json"]
        if (
            not isinstance(run_id, str)
            or not run_id
            or not isinstance(pending_updated_at, str)
            or not isinstance(manifest_json, str)
        ):
            raise StateError("Manifest artifact synchronization marker contains invalid values")
        digest = _stored_event_hash(
            row["manifest_sha256"],
            field=f"run {run_id} pending manifest digest",
        )
        _stored_datetime(
            pending_updated_at,
            field=f"run {run_id} pending manifest update time",
        )
        if (
            row["run_updated_at"] != pending_updated_at
            or _manifest_json_digest(manifest_json) != digest
        ):
            raise StateError(
                f"Pending manifest artifact for run {run_id} disagrees with durable state"
            )


def _verified_issue_revision_row(
    row: sqlite3.Row,
) -> tuple[str, RunStatus, str | None]:
    """Validate one run row and return its revision-bound candidate attempt identity."""

    try:
        run_id = _lease_identity(row["run_id"], field="stored run id")
    except (TypeError, ValueError) as exc:
        raise StateError("Issue-revision evidence contains an invalid run ID") from exc
    status = _stored_run_status(row["status"], run_id=run_id)
    manifest_json = row["manifest_json"]
    if not isinstance(manifest_json, str):
        raise StateError(f"Run {run_id} contains an invalid manifest")
    try:
        manifest = RunManifest.model_validate_json(manifest_json)
    except (TypeError, ValueError) as exc:
        raise StateError(f"Run {run_id} contains an invalid manifest") from exc
    if manifest.run_id != run_id or manifest.status != status:
        raise StateError(f"Run {run_id} manifest disagrees with its state row")

    candidate = manifest.candidate
    stored_revision = row["issue_revision"]
    if candidate is None:
        if row["issue_number"] is not None or stored_revision is not None:
            raise StateError(f"Run {run_id} has issue identity without a candidate")
        # Historical publication-only rows can carry a repository reservation without ever
        # having selected an issue, so repository alone deliberately remains valid here.
        return run_id, status, None

    try:
        _candidate_identity(candidate.repository, candidate.number)
    except (TypeError, ValueError) as exc:
        raise StateError(f"Run {run_id} has an invalid candidate identity") from exc
    if row["repository"] != candidate.repository or row["issue_number"] != candidate.number:
        raise StateError(f"Run {run_id} candidate disagrees with its state row")
    try:
        expected_revision = compute_issue_revision(candidate)
    except (TypeError, ValueError) as exc:
        raise StateError(f"Run {run_id} has invalid issue revision evidence") from exc
    try:
        revision = _stored_event_hash(
            stored_revision,
            field=f"run {run_id} issue revision",
        )
    except StateError as exc:
        raise StateError(f"Run {run_id} has invalid issue revision evidence") from exc
    if revision != expected_revision:
        raise StateError(f"Run {run_id} issue revision disagrees with its manifest")
    return run_id, status, revision


def _verify_issue_revision_evidence(
    connection: sqlite3.Connection,
    *,
    require_current_provenance: bool,
) -> None:
    rows = connection.execute(
        """
        SELECT run_id, status, repository, issue_number, issue_revision, manifest_json
        FROM runs ORDER BY run_id LIMIT ?
        """,
        (_MAX_RUN_CORPUS + 1,),
    ).fetchall()
    if len(rows) > _MAX_RUN_CORPUS:
        raise StateError("Run corpus exceeds the supported issue-revision integrity bound")
    candidate_runs: set[str] = set()
    for row in rows:
        run_id, _, revision = _verified_issue_revision_row(row)
        if revision is not None:
            candidate_runs.add(run_id)
    if not require_current_provenance:
        return
    selected_runs = _verify_candidate_selection_events(connection)
    authorized_retry_runs = _verify_candidate_retry_authorizations(connection)
    missing_provenance = candidate_runs - selected_runs - authorized_retry_runs
    if missing_provenance:
        raise StateError(
            f"Run {min(missing_provenance)} has candidate evidence without selection provenance"
        )


def _verify_candidate_selection_events(connection: sqlite3.Connection) -> set[str]:
    rows = connection.execute(
        """
        SELECT events.run_id, events.details_json,
               runs.status, runs.repository, runs.issue_number,
               runs.issue_revision, runs.manifest_json
        FROM events
        JOIN runs USING(run_id)
        WHERE events.event_type = 'candidate.selected'
        ORDER BY events.id LIMIT ?
        """,
        (_MAX_RUN_CORPUS + 1,),
    ).fetchall()
    if len(rows) > _MAX_RUN_CORPUS:
        raise StateError("Candidate selection evidence exceeds the supported integrity bound")
    seen: set[str] = set()
    for row in rows:
        run_id, _, revision = _verified_issue_revision_row(row)
        if run_id in seen:
            raise StateError(f"Run {run_id} has duplicate candidate selection evidence")
        seen.add(run_id)
        if revision is None:
            raise StateError(f"Run {run_id} selected a candidate without durable issue evidence")
        manifest = RunManifest.model_validate_json(row["manifest_json"])
        candidate = manifest.candidate
        assert candidate is not None
        details = _stored_event_details(
            row["details_json"],
            field=f"run {run_id} candidate selection event",
        )
        event_revision = details.get("issue_revision")
        if event_revision is not None and event_revision != revision:
            raise StateError(f"Run {run_id} candidate selection has a mismatched issue revision")
        expected_keys = {"issue", "score"}
        if event_revision is not None:
            expected_keys.add("issue_revision")
        score = details.get("score")
        try:
            parsed_score = int(score) if isinstance(score, str) else -1
        except ValueError:
            parsed_score = -1
        if (
            set(details) != expected_keys
            or details.get("issue") != candidate.reference
            or not 0 <= parsed_score <= 100
            or score != str(parsed_score)
        ):
            raise StateError(
                f"Run {run_id} candidate selection disagrees with its candidate evidence"
            )
    return seen


def _verify_candidate_retry_authorizations(connection: sqlite3.Connection) -> set[str]:
    metadata = connection.execute(
        "SELECT migrated_at FROM schema_metadata WHERE singleton = 1"
    ).fetchone()
    if metadata is None:
        raise StateError("Candidate retry evidence lacks schema migration metadata")
    schema_migrated_at = _stored_canonical_utc_datetime(
        metadata["migrated_at"],
        field="schema migration time",
    )
    markers = connection.execute(
        """
        SELECT legacy_candidate_retry_overrides.event_id AS marker_event_id,
               legacy_candidate_retry_overrides.run_id AS marker_run_id,
               legacy_candidate_retry_overrides.event_hash AS marker_event_hash,
               legacy_candidate_retry_overrides.migrated_at,
               events.id AS event_id, events.run_id AS event_run_id,
               events.event_type, events.occurred_at, events.event_hash,
               events.details_json
        FROM legacy_candidate_retry_overrides
        LEFT JOIN events ON events.id = legacy_candidate_retry_overrides.event_id
        ORDER BY legacy_candidate_retry_overrides.event_id LIMIT ?
        """,
        (_MAX_RUN_CORPUS + 1,),
    ).fetchall()
    if len(markers) > _MAX_RUN_CORPUS:
        raise StateError("Legacy candidate retry markers exceed the supported integrity bound")
    covered_event_ids: set[int] = set()
    legacy_runs: set[str] = set()
    for marker in markers:
        marker_event_id = marker["marker_event_id"]
        event_id = marker["event_id"]
        if (
            isinstance(marker_event_id, bool)
            or not isinstance(marker_event_id, int)
            or marker_event_id < 1
            or event_id != marker_event_id
            or marker["event_type"] != "candidate.retry_override"
            or marker["event_run_id"] != marker["marker_run_id"]
            or marker["event_hash"] != marker["marker_event_hash"]
        ):
            raise StateError("Legacy candidate retry marker disagrees with its exact event")
        marker_migrated_at = _stored_canonical_utc_datetime(
            marker["migrated_at"],
            field="legacy candidate retry migration time",
        )
        event_occurred_at = _stored_datetime(
            marker["occurred_at"],
            field="legacy candidate retry event time",
        )
        if (
            marker["migrated_at"] != metadata["migrated_at"]
            or marker_migrated_at != schema_migrated_at
            or event_occurred_at > marker_migrated_at
        ):
            raise StateError("Legacy candidate retry marker has an invalid migration cutoff")
        validated_event_id, run_id, event_hash = _validated_legacy_candidate_retry_override(
            connection,
            event_id=event_id,
            run_id=marker["event_run_id"],
            event_hash=marker["event_hash"],
            details_json=marker["details_json"],
        )
        if (
            validated_event_id in covered_event_ids
            or run_id in legacy_runs
            or event_hash != marker["marker_event_hash"]
        ):
            raise StateError("Legacy candidate retry marker is duplicated or mismatched")
        covered_event_ids.add(validated_event_id)
        legacy_runs.add(run_id)

    authorizations = connection.execute(
        """
        SELECT authorization_id, run_id, repository, issue_number, issue_revision,
               prior_run_id, prior_status, actor, reason, authorized_at
        FROM candidate_retry_authorizations
        ORDER BY authorization_id LIMIT ?
        """,
        (_MAX_RUN_CORPUS + 1,),
    ).fetchall()
    if len(authorizations) > _MAX_RUN_CORPUS:
        raise StateError("Candidate retry authorizations exceed the supported integrity bound")
    authorized_runs: set[str] = set()
    for authorization in authorizations:
        authorization_id = _stored_authorization_id(authorization["authorization_id"])
        try:
            run_id = _lease_identity(authorization["run_id"], field="candidate retry run id")
            prior_run_id = _lease_identity(
                authorization["prior_run_id"],
                field="candidate retry prior run id",
            )
            repository, issue_number = _candidate_identity(
                authorization["repository"],
                authorization["issue_number"],
            )
        except (TypeError, ValueError) as exc:
            raise StateError("Candidate retry authorization has an invalid identity") from exc
        try:
            prior_status = RunStatus(authorization["prior_status"])
        except (TypeError, ValueError) as exc:
            raise StateError("Candidate retry authorization has an invalid prior status") from exc
        if prior_status not in _CANDIDATE_SUPPRESSED_STATUSES:
            raise StateError("Candidate retry authorization references a non-suppressed status")
        try:
            actor, reason = _candidate_retry_authorization(
                CandidateRetryAuthorization(
                    actor=authorization["actor"],
                    reason=authorization["reason"],
                )
            )
        except (TypeError, ValueError) as exc:
            raise StateError("Candidate retry authorization has invalid operator evidence") from exc
        _stored_canonical_utc_datetime(
            authorization["authorized_at"],
            field="candidate retry authorization time",
        )
        revision = _stored_event_hash(
            authorization["issue_revision"],
            field="candidate retry issue revision",
        )

        run_row = connection.execute(
            """
            SELECT run_id, status, repository, issue_number, issue_revision, manifest_json
            FROM runs WHERE run_id = ?
            """,
            (run_id,),
        ).fetchone()
        prior_row = connection.execute(
            """
            SELECT run_id, status, repository, issue_number, issue_revision, manifest_json
            FROM runs WHERE run_id = ?
            """,
            (prior_run_id,),
        ).fetchone()
        if run_row is None or prior_row is None:
            raise StateError("Candidate retry authorization references a missing run")
        _, _, run_revision = _verified_issue_revision_row(run_row)
        _, stored_prior_status, prior_revision = _verified_issue_revision_row(prior_row)
        try:
            run_manifest = RunManifest.model_validate_json(run_row["manifest_json"])
        except (TypeError, ValueError) as exc:
            raise StateError("Candidate retry authorization references an invalid run") from exc
        candidate = run_manifest.candidate
        candidate_repository = (
            _candidate_identity(candidate.repository, candidate.number)[0]
            if candidate is not None
            else None
        )
        if (
            candidate is None
            or run_revision != revision
            or prior_revision != revision
            or stored_prior_status != prior_status
            or authorization["repository"] != candidate.repository
            or repository != candidate_repository
            or issue_number != candidate.number
        ):
            raise StateError("Candidate retry authorization disagrees with its run evidence")

        events = connection.execute(
            """
            SELECT id, occurred_at, details_json FROM events
            WHERE run_id = ? AND event_type = 'candidate.retry_override'
            ORDER BY id LIMIT 2
            """,
            (run_id,),
        ).fetchall()
        if len(events) != 1:
            raise StateError(f"Run {run_id} must have exactly one candidate retry override event")
        if events[0]["occurred_at"] != authorization["authorized_at"]:
            raise StateError(
                f"Run {run_id} candidate retry override has a mismatched authorization time"
            )
        details = _stored_event_details(
            events[0]["details_json"],
            field=f"run {run_id} candidate retry override event",
        )
        expected_details = {
            "actor": actor,
            "authorization_id": authorization_id,
            "issue": candidate.reference,
            "issue_revision": revision,
            "prior_run_id": prior_run_id,
            "prior_status": prior_status.value,
            "reason": reason,
        }
        if details != expected_details:
            raise StateError(
                f"Run {run_id} candidate retry override disagrees with its authorization"
            )
        event_id = events[0]["id"]
        if (
            isinstance(event_id, bool)
            or not isinstance(event_id, int)
            or event_id < 1
            or event_id in covered_event_ids
        ):
            raise StateError(f"Run {run_id} candidate retry override event is invalid")
        covered_event_ids.add(event_id)
        authorized_runs.add(run_id)

    if legacy_runs & authorized_runs:
        raise StateError("Candidate retry evidence mixes legacy and authorized provenance")

    retry_events = connection.execute(
        """
        SELECT id FROM events
        WHERE event_type = 'candidate.retry_override'
        ORDER BY id LIMIT ?
        """,
        (_MAX_RUN_CORPUS + 1,),
    ).fetchall()
    if len(retry_events) > _MAX_RUN_CORPUS:
        raise StateError("Candidate retry overrides exceed the supported integrity bound")
    retry_event_ids = {row["id"] for row in retry_events}
    if retry_event_ids != covered_event_ids:
        raise StateError(
            "Candidate retry override event lacks durable authorization or migration provenance"
        )
    return authorized_runs | legacy_runs


def _validated_legacy_candidate_retry_override(
    connection: sqlite3.Connection,
    *,
    event_id: object,
    run_id: object,
    event_hash: object,
    details_json: object,
) -> tuple[int, str, str]:
    """Bind one schema-v7 retry event to its exact current and prior run evidence."""

    if isinstance(event_id, bool) or not isinstance(event_id, int) or event_id < 1:
        raise StateError("Legacy candidate retry override has an invalid event ID")
    try:
        if not isinstance(run_id, str):
            raise TypeError("legacy candidate retry run ID must be a string")
        normalized_run_id = _lease_identity(run_id, field="legacy candidate retry run id")
    except (TypeError, ValueError) as exc:
        raise StateError("Legacy candidate retry override has an invalid run ID") from exc
    normalized_event_hash = _stored_event_hash(
        event_hash,
        field="legacy candidate retry event hash",
    )
    details = _stored_event_details(
        details_json,
        field=f"run {normalized_run_id} legacy candidate retry override",
    )
    expected_keys = {"issue", "issue_revision", "prior_run_id", "prior_status"}
    if set(details) != expected_keys:
        raise StateError(
            f"Run {normalized_run_id} legacy candidate retry override has unsupported details"
        )
    try:
        prior_run_id = _lease_identity(
            details["prior_run_id"],
            field="legacy candidate retry prior run id",
        )
        prior_status = RunStatus(details["prior_status"])
    except (TypeError, ValueError) as exc:
        raise StateError(
            f"Run {normalized_run_id} legacy candidate retry override has invalid prior evidence"
        ) from exc
    if prior_run_id == normalized_run_id or prior_status not in _CANDIDATE_SUPPRESSED_STATUSES:
        raise StateError(
            f"Run {normalized_run_id} legacy candidate retry override has invalid prior evidence"
        )
    revision = _stored_event_hash(
        details["issue_revision"],
        field="legacy candidate retry issue revision",
    )
    run_row = connection.execute(
        """
        SELECT run_id, status, repository, issue_number, issue_revision, manifest_json
        FROM runs WHERE run_id = ?
        """,
        (normalized_run_id,),
    ).fetchone()
    prior_row = connection.execute(
        """
        SELECT run_id, status, repository, issue_number, issue_revision, manifest_json
        FROM runs WHERE run_id = ?
        """,
        (prior_run_id,),
    ).fetchone()
    if run_row is None or prior_row is None:
        raise StateError(
            f"Run {normalized_run_id} legacy candidate retry override references a missing run"
        )
    _, _, run_revision = _verified_issue_revision_row(run_row)
    _, stored_prior_status, prior_revision = _verified_issue_revision_row(prior_row)
    manifest = RunManifest.model_validate_json(run_row["manifest_json"])
    candidate = manifest.candidate
    expected_details = {
        "issue": candidate.reference if candidate is not None else "",
        "issue_revision": revision,
        "prior_run_id": prior_run_id,
        "prior_status": prior_status.value,
    }
    if (
        candidate is None
        or run_revision != revision
        or prior_revision != revision
        or stored_prior_status != prior_status
        or details != expected_details
    ):
        raise StateError(
            f"Run {normalized_run_id} legacy candidate retry override disagrees with run evidence"
        )
    return event_id, normalized_run_id, normalized_event_hash


def _verified_event_heads(
    run_rows: builtins.list[sqlite3.Row],
    event_rows: builtins.list[sqlite3.Row],
) -> dict[str, tuple[int, str]]:
    """Verify complete per-run chains and return their event counts and head hashes."""

    heads: dict[str, tuple[int, str]] = {}
    for row in run_rows:
        run_id_value = row["run_id"]
        if not isinstance(run_id_value, str) or not run_id_value:
            raise StateError("Run ledger contains an invalid run ID")
        if run_id_value in heads:
            raise StateError(f"Run ledger contains duplicate run ID {run_id_value}")
        heads[run_id_value] = (0, _INITIAL_EVENT_HASH)

    for row in event_rows:
        values = {
            "run_id": row["run_id"],
            "occurred_at": row["occurred_at"],
            "event_type": row["event_type"],
            "details": row["details_json"],
            "previous_hash": row["previous_hash"],
            "event_hash": row["event_hash"],
        }
        if any(not isinstance(value, str) for value in values.values()):
            raise StateError("Event ledger contains invalid stored values")
        event_run_id = cast(str, values["run_id"])
        if event_run_id not in heads:
            raise StateError(f"Event ledger references unknown run {event_run_id}")
        event_hash = _stored_event_hash(
            values["event_hash"], field=f"run {event_run_id} event hash"
        )
        previous_hash = _stored_event_hash(
            values["previous_hash"], field=f"run {event_run_id} event predecessor"
        )
        event_count, expected_previous = heads[event_run_id]
        if previous_hash != expected_previous:
            raise StateError(f"Event predecessor mismatch for run {event_run_id}")
        payload = _canonical_json(
            {
                "run_id": event_run_id,
                "occurred_at": values["occurred_at"],
                "event_type": values["event_type"],
                "details": values["details"],
                "previous_hash": previous_hash,
            }
        )
        expected_hash = hashlib.sha256(payload.encode()).hexdigest()
        if event_hash != expected_hash:
            raise StateError(f"Event hash mismatch for run {event_run_id}")
        heads[event_run_id] = (event_count + 1, event_hash)

    for run_id, (event_count, _) in heads.items():
        if event_count == 0:
            raise StateError(f"Run {run_id} is missing its event chain")
    return heads


def _verify_circuit_breaker_evidence(connection: sqlite3.Connection) -> None:
    rows = connection.execute(
        """
        SELECT is_tripped, epoch, source, reason, trigger_hash
        FROM circuit_breaker WHERE singleton = 1
        """
    ).fetchall()
    if len(rows) != 1:
        raise StateError("Circuit-breaker state must contain one canonical row")
    row = rows[0]
    is_tripped = _stored_boolean(row["is_tripped"], field="circuit-breaker status")
    epoch = _stored_generation(row["epoch"], field="circuit-breaker epoch")
    active = connection.execute(
        """
        SELECT source, reason, trigger_hash
        FROM circuit_breaker_events
        WHERE epoch = ? AND event_type = 'trip'
        ORDER BY id
        LIMIT ?
        """,
        (epoch, _MAX_ACTIVE_CIRCUIT_BREAKER_TRIGGERS + 1),
    ).fetchall()
    if len(active) > _MAX_ACTIVE_CIRCUIT_BREAKER_TRIGGERS:
        raise StateError("Circuit-breaker active evidence exceeds the safe bound")
    if is_tripped != bool(active):
        raise StateError("Circuit-breaker state disagrees with its active evidence")
    if active:
        latest = active[-1]
        if (
            latest["source"] != row["source"]
            or latest["reason"] != row["reason"]
            or latest["trigger_hash"] != row["trigger_hash"]
        ):
            raise StateError("Circuit-breaker state does not identify its latest trigger")


def _verify_unanchored_event_chains(connection: sqlite3.Connection) -> None:
    """Verify legacy v2/v3 hashes even though those schemas predate run-row anchors."""

    run_rows = connection.execute("SELECT run_id FROM runs ORDER BY run_id").fetchall()
    event_rows = connection.execute(
        """
        SELECT id, run_id, occurred_at, event_type, details_json,
               previous_hash, event_hash
        FROM events ORDER BY run_id ASC, id ASC
        """
    ).fetchall()
    _verified_event_heads(run_rows, event_rows)


def _verify_lifecycle_snapshot_evidence(
    connection: sqlite3.Connection,
    *,
    selected_run_id: str | None = None,
    collect: bool = True,
) -> builtins.list[LifecycleSnapshot]:
    """Strictly parse snapshot rows and reconcile them 1:1 with ledger events."""

    if selected_run_id is None:
        snapshot_count = connection.execute("SELECT count(*) FROM lifecycle_snapshots").fetchone()
        event_count = connection.execute(
            """
            SELECT count(*) FROM events
            WHERE event_type = 'lifecycle.snapshot.recorded'
            """
        ).fetchone()
        snapshot_rows = connection.execute(
            """
            SELECT id, run_id, fingerprint, observed_at, snapshot_json
            FROM lifecycle_snapshots ORDER BY id
            """
        )
        event_rows = connection.execute(
            """
            SELECT id, run_id, details_json FROM events
            WHERE event_type = 'lifecycle.snapshot.recorded'
            ORDER BY id
            """
        )
    else:
        snapshot_count = connection.execute(
            "SELECT count(*) FROM lifecycle_snapshots WHERE run_id = ?",
            (selected_run_id,),
        ).fetchone()
        event_count = connection.execute(
            """
            SELECT count(*) FROM events
            WHERE run_id = ? AND event_type = 'lifecycle.snapshot.recorded'
            """,
            (selected_run_id,),
        ).fetchone()
        snapshot_rows = connection.execute(
            """
            SELECT id, run_id, fingerprint, observed_at, snapshot_json
            FROM lifecycle_snapshots WHERE run_id = ? ORDER BY id
            """,
            (selected_run_id,),
        )
        event_rows = connection.execute(
            """
            SELECT id, run_id, details_json FROM events
            WHERE run_id = ? AND event_type = 'lifecycle.snapshot.recorded'
            ORDER BY id
            """,
            (selected_run_id,),
        )
    if snapshot_count is None or snapshot_count[0] > _MAX_LIFECYCLE_SNAPSHOT_CORPUS:
        raise StateError("Lifecycle snapshot corpus exceeds the configured safety bound")
    if event_count is None or event_count[0] > _MAX_LIFECYCLE_SNAPSHOT_CORPUS:
        raise StateError("Lifecycle snapshot event corpus exceeds the configured safety bound")

    snapshot_values: dict[tuple[str, str], LifecycleSnapshot] = {}
    snapshot_keys: set[tuple[str, str]] = set()
    for row in snapshot_rows:
        run_id_value = row["run_id"]
        snapshot_json_value = row["snapshot_json"]
        if not isinstance(run_id_value, str) or not run_id_value:
            raise StateError("Lifecycle snapshot row contains an invalid run ID")
        run_id = run_id_value
        fingerprint = _stored_event_hash(
            row["fingerprint"],
            field=f"run {run_id} lifecycle fingerprint",
        )
        observed_at = _stored_canonical_utc_datetime(
            row["observed_at"],
            field=f"run {run_id} lifecycle observation time",
        )
        if not isinstance(snapshot_json_value, str):
            raise StateError(f"Run {run_id} lifecycle snapshot is not stored as text")
        try:
            parsed = _validated_snapshot_json(
                snapshot_json_value,
                observed_at=observed_at,
            )
        except (TypeError, ValueError) as exc:
            raise StateError(f"Run {run_id} lifecycle snapshot is invalid: {exc}") from exc
        if parsed.fingerprint() != fingerprint:
            raise StateError(f"Run {run_id} lifecycle snapshot fingerprint mismatch")
        key = (run_id, fingerprint)
        if key in snapshot_keys:
            raise StateError(f"Run {run_id} has duplicate lifecycle snapshot rows")
        snapshot_keys.add(key)
        if collect:
            snapshot_values[key] = LifecycleSnapshot(
                run_id=run_id,
                fingerprint=fingerprint,
                observed_at=observed_at,
                snapshot_json=snapshot_json_value,
            )

    event_keys: set[tuple[str, str]] = set()
    event_order: builtins.list[tuple[str, str]] = []
    for row in event_rows:
        run_id_value = row["run_id"]
        details_value = row["details_json"]
        if not isinstance(run_id_value, str) or not run_id_value:
            raise StateError("Lifecycle snapshot event contains an invalid run ID")
        run_id = run_id_value
        fingerprint = _lifecycle_event_fingerprint(details_value, run_id=run_id)
        key = (run_id, fingerprint)
        if key in event_keys:
            raise StateError(f"Run {run_id} has duplicate lifecycle snapshot ledger events")
        event_keys.add(key)
        if collect:
            event_order.append(key)

    missing_events = snapshot_keys - event_keys
    if missing_events:
        run_id, _ = min(missing_events)
        raise StateError(f"Run {run_id} lifecycle snapshot is missing its ledger event")
    orphan_events = event_keys - snapshot_keys
    if orphan_events:
        run_id, _ = min(orphan_events)
        raise StateError(f"Run {run_id} has an orphan lifecycle snapshot ledger event")
    return [snapshot_values[key] for key in event_order] if collect else []


def _lifecycle_event_fingerprint(value: object, *, run_id: str) -> str:
    if not isinstance(value, str):
        raise StateError(f"Run {run_id} lifecycle snapshot event details are invalid")
    try:
        parsed = json.loads(value, object_pairs_hook=_unique_lifecycle_event_object)
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise StateError(f"Run {run_id} lifecycle snapshot event details are invalid") from exc
    if not isinstance(parsed, dict) or set(parsed) != {"fingerprint"}:
        raise StateError(f"Run {run_id} lifecycle snapshot event details are invalid")
    fingerprint = _stored_event_hash(
        parsed["fingerprint"],
        field=f"run {run_id} lifecycle event fingerprint",
    )
    if value != _canonical_json({"fingerprint": fingerprint}):
        raise StateError(f"Run {run_id} lifecycle snapshot event details are not canonical")
    return fingerprint


def _unique_lifecycle_event_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate lifecycle event detail: {key}")
        result[key] = value
    return result


def _verify_event_anchors(
    connection: sqlite3.Connection,
    *,
    selected_run_id: str | None = None,
) -> None:
    """Recompute selected chains and require their durable count/head anchors to match."""

    if selected_run_id is None:
        run_rows = connection.execute(
            """
            SELECT run_id, event_count, event_head_hash
            FROM runs ORDER BY run_id
            """
        ).fetchall()
        event_rows = connection.execute(
            """
            SELECT id, run_id, occurred_at, event_type, details_json,
                   previous_hash, event_hash
            FROM events ORDER BY run_id ASC, id ASC
            """
        ).fetchall()
    else:
        run_rows = connection.execute(
            """
            SELECT run_id, event_count, event_head_hash
            FROM runs WHERE run_id = ?
            """,
            (selected_run_id,),
        ).fetchall()
        event_rows = connection.execute(
            """
            SELECT id, run_id, occurred_at, event_type, details_json,
                   previous_hash, event_hash
            FROM events WHERE run_id = ? ORDER BY id ASC
            """,
            (selected_run_id,),
        ).fetchall()

    if selected_run_id is not None and not run_rows:
        raise StateError(f"Unknown run: {selected_run_id}")
    computed_heads = _verified_event_heads(run_rows, event_rows)
    for row in run_rows:
        run_id_value = row["run_id"]
        if not isinstance(run_id_value, str):
            raise StateError("Run ledger contains an invalid run ID")
        stored_count = _stored_event_count(
            row["event_count"], field=f"run {run_id_value} event count"
        )
        stored_head = _stored_event_hash(
            row["event_head_hash"], field=f"run {run_id_value} event head"
        )
        computed_count, computed_head = computed_heads[run_id_value]
        if stored_count != computed_count or stored_head != computed_head:
            raise StateError(f"Event ledger anchor mismatch for run {run_id_value}")


def _evaluation_corpus_cursor_from_connection(connection: sqlite3.Connection) -> str:
    """Return an exact bounded cursor after validating the underlying event ledger."""

    _verify_event_anchors(connection)
    rows = connection.execute(
        """
        SELECT id, run_id, event_type, event_hash FROM events
        WHERE event_type IN ('evaluation.recorded', 'evaluation.amended')
        ORDER BY id ASC LIMIT ?
        """,
        (_MAX_EVALUATION_EVENT_CORPUS + 1,),
    ).fetchall()
    if len(rows) > _MAX_EVALUATION_EVENT_CORPUS:
        raise StateError("Evaluation event corpus exceeds the configured safety bound")
    canonical: builtins.list[dict[str, int | str]] = []
    for row in rows:
        event_id = row["id"]
        run_id = row["run_id"]
        event_type = row["event_type"]
        if (
            isinstance(event_id, bool)
            or not isinstance(event_id, int)
            or event_id < 1
            or not isinstance(run_id, str)
            or not run_id
            or event_type not in {"evaluation.recorded", "evaluation.amended"}
        ):
            raise StateError("Evaluation event cursor contains invalid stored values")
        event_hash = _stored_event_hash(
            row["event_hash"], field=f"evaluation event {event_id} hash"
        )
        canonical.append(
            {
                "id": event_id,
                "run_id": run_id,
                "event_type": str(event_type),
                "event_hash": event_hash,
            }
        )
    return hashlib.sha256(_canonical_json(canonical).encode("utf-8")).hexdigest()


def _run_creation_deployment_fingerprint(
    connection: sqlite3.Connection,
    run_id: str,
) -> str | None:
    row = connection.execute(
        """
        SELECT event_type, details_json FROM events
        WHERE run_id = ? ORDER BY id ASC LIMIT 1
        """,
        (run_id,),
    ).fetchone()
    if row is None or row["event_type"] != "run.created":
        raise StateError(f"Run {run_id} is missing valid creation evidence")
    try:
        details = json.loads(row["details_json"])
    except (TypeError, ValueError) as exc:
        raise StateError(f"Run {run_id} has invalid creation evidence") from exc
    if details == {"status": "queued"}:
        return None
    if (
        not isinstance(details, dict)
        or set(details) != {"deployment_fingerprint", "status"}
        or details.get("status") != "queued"
    ):
        raise StateError(f"Run {run_id} has invalid creation evidence")
    return _stored_event_hash(
        details.get("deployment_fingerprint"),
        field=f"run {run_id} creation deployment fingerprint",
    )


def _upstream_outcome_cursor_scope(
    deployment_fingerprint: str,
    publishing_login: str,
    publishing_api_origin: str,
    *,
    exclude_run_id: str | None,
) -> tuple[str, str, str, str | None]:
    deployment = _sha256_identity(
        deployment_fingerprint,
        field="upstream-outcome deployment fingerprint",
    )
    if not isinstance(publishing_login, str):
        raise TypeError("upstream-outcome publishing login must be a string")
    login = publishing_login.strip().casefold()
    if publishing_login != login or not _GITHUB_LOGIN.fullmatch(login):
        raise ValueError("upstream-outcome publishing login must be canonical")
    if not isinstance(publishing_api_origin, str):
        raise TypeError("upstream-outcome API origin must be a string")
    origin = canonical_api_origin(publishing_api_origin)
    if publishing_api_origin != origin:
        raise ValueError("upstream-outcome API origin must be canonical")
    excluded = (
        _lease_identity(exclude_run_id, field="excluded upstream-outcome run id")
        if exclude_run_id is not None
        else None
    )
    return deployment, login, origin, excluded


def _upstream_outcome_corpus_cursor_from_connection(
    connection: sqlite3.Connection,
    deployment_fingerprint: str,
    publishing_login: str,
    publishing_api_origin: str,
    exclude_run_id: str | None,
) -> str:
    """Return a bounded cursor over every durable input to outcome classification.

    The polling timestamp on lifecycle rows is intentionally absent: only GitHub timestamps and
    hash-chained ledger order are authoritative. The exact candidate run is excluded so that the
    cursor remains the pre-publication corpus after its atomic hold and intent are appended.
    """

    _verify_event_anchors(connection)
    rows = connection.execute(
        """
        SELECT runs.run_id, runs.status, runs.created_at, runs.manifest_json,
               runs.event_count, runs.event_head_hash,
               creation.occurred_at AS creation_occurred_at,
               creation.event_type AS creation_event_type,
               creation.details_json AS creation_details
        FROM runs
        JOIN events AS creation ON creation.id = (
            SELECT MIN(first_event.id) FROM events AS first_event
            WHERE first_event.run_id = runs.run_id
        )
        ORDER BY creation.occurred_at ASC, runs.run_id ASC
        LIMIT ?
        """,
        (_MAX_RUN_CORPUS + 1,),
    ).fetchall()
    if len(rows) > _MAX_RUN_CORPUS:
        raise StateError("Upstream-outcome run corpus exceeds the configured safety bound")

    canonical_runs: builtins.list[dict[str, object]] = []
    lifecycle_count = 0
    for row in rows:
        run_id_value = row["run_id"]
        if not isinstance(run_id_value, str) or not run_id_value:
            raise StateError("Upstream-outcome corpus contains an invalid run ID")
        run_id = run_id_value
        try:
            manifest_json = row["manifest_json"]
            if not isinstance(manifest_json, str):
                raise TypeError("manifest is not text")
            manifest = RunManifest.model_validate_json(manifest_json)
            creation_details = json.loads(row["creation_details"])
        except (TypeError, ValueError) as exc:
            raise StateError(f"Run {run_id} has invalid upstream-outcome evidence") from exc
        if creation_details == {"status": "queued"}:
            creation_fingerprint = None
        elif (
            isinstance(creation_details, dict)
            and set(creation_details) == {"deployment_fingerprint", "status"}
            and creation_details.get("status") == "queued"
        ):
            creation_fingerprint = _stored_event_hash(
                creation_details.get("deployment_fingerprint"),
                field=f"run {run_id} creation deployment fingerprint",
            )
        else:
            raise StateError(f"Run {run_id} has invalid creation evidence")
        stored_created_at = _stored_datetime(row["created_at"], field="run creation time")
        creation_occurred_at = _stored_datetime(
            row["creation_occurred_at"],
            field="run creation event time",
        )
        if (
            row["creation_event_type"] != "run.created"
            or manifest.run_id != run_id
            or manifest.status != _stored_run_status(row["status"], run_id=run_id)
            or manifest.created_at.astimezone(UTC) != stored_created_at
            or manifest.deployment_fingerprint != creation_fingerprint
            or creation_occurred_at < stored_created_at
        ):
            raise StateError(f"Run {run_id} manifest disagrees with its state row")
        if creation_fingerprint != deployment_fingerprint or run_id == exclude_run_id:
            continue
        if manifest.status not in {RunStatus.SUBMITTING, RunStatus.PR_OPEN}:
            publication_event = connection.execute(
                """
                SELECT 1 FROM events WHERE run_id = ? AND (
                    event_type GLOB 'approval.*'
                    OR event_type GLOB 'branch.*'
                    OR event_type GLOB 'commit.*'
                    OR event_type GLOB 'publication.*'
                    OR event_type GLOB 'pull_request.*'
                )
                LIMIT 1
                """,
                (run_id,),
            ).fetchone()
            if publication_event is None:
                continue

        lifecycle_rows = _verify_lifecycle_snapshot_evidence(
            connection,
            selected_run_id=run_id,
        )
        lifecycle_count += len(lifecycle_rows)
        if lifecycle_count > _MAX_LIFECYCLE_SNAPSHOT_CORPUS:
            raise StateError("Upstream-outcome lifecycle corpus exceeds the safety bound")
        canonical_runs.append(
            {
                "run_id": run_id,
                "manifest_json": manifest_json,
                "event_count": _stored_event_count(
                    row["event_count"],
                    field=f"run {run_id} event count",
                ),
                "event_head_hash": _stored_event_hash(
                    row["event_head_hash"],
                    field=f"run {run_id} event head",
                ),
                "lifecycle": [
                    {
                        "fingerprint": snapshot.fingerprint,
                        "snapshot_json": snapshot.snapshot_json,
                    }
                    for snapshot in lifecycle_rows
                ],
            }
        )

    payload = {
        "schema_version": 1,
        "scope": {
            "deployment_fingerprint": deployment_fingerprint,
            "publishing_login": publishing_login,
            "publishing_api_origin": publishing_api_origin,
            "excluded_run_id": exclude_run_id,
        },
        "runs": canonical_runs,
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(_UPSTREAM_OUTCOME_CURSOR_DOMAIN + encoded).hexdigest()


def _publication_evidence_from_connection(
    connection: sqlite3.Connection,
) -> tuple[
    dict[str, _PublicationReservationEvidence],
    dict[str, _PublicationGateEvidence],
    dict[str, _PublicationGateEvidence],
]:
    placeholders = ",".join("?" for _ in _PUBLICATION_EVIDENCE_EVENT_TYPES)
    # The event inventory is an internal constant; interpolation only chooses the number of bound
    # parameter placeholders.
    evidence_query = (
        "SELECT id, run_id, event_type, details_json FROM events "
        f"WHERE event_type IN ({placeholders}) ORDER BY id LIMIT ?"
    )
    rows = connection.execute(
        evidence_query,
        (*_PUBLICATION_EVIDENCE_EVENT_TYPES, _MAX_PUBLICATION_EVIDENCE_EVENTS + 1),
    ).fetchall()
    if len(rows) > _MAX_PUBLICATION_EVIDENCE_EVENTS:
        raise StateError("Publication evidence exceeds the configured safety bound")

    reservations: dict[str, _PublicationReservationEvidence] = {}
    holds: dict[str, _PublicationGateEvidence] = {}
    releases: dict[str, _PublicationGateEvidence] = {}
    for row in rows:
        run_id_value = row["run_id"]
        event_type_value = row["event_type"]
        details_value = row["details_json"]
        if (
            not isinstance(run_id_value, str)
            or not run_id_value
            or event_type_value not in _PUBLICATION_EVIDENCE_EVENT_TYPES
            or not isinstance(details_value, str)
        ):
            raise StateError("Publication evidence contains invalid stored values")
        run_id = run_id_value
        event_type = str(event_type_value)
        try:
            parsed = json.loads(details_value)
        except json.JSONDecodeError as exc:
            raise StateError(
                f"Run {run_id} publication evidence contains malformed details"
            ) from exc
        if not isinstance(parsed, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in parsed.items()
        ):
            raise StateError(f"Run {run_id} publication evidence contains malformed details")
        details = cast(dict[str, str], parsed)

        if event_type in {"publication.reserved", "publication.reservation.legacy"}:
            if set(details) != {"repository", "reserved_at"}:
                raise StateError(f"Run {run_id} publication reservation evidence is incomplete")
            try:
                repository = _repository_identity(details["repository"])
            except (TypeError, ValueError) as exc:
                raise StateError(
                    f"Run {run_id} publication reservation evidence is invalid"
                ) from exc
            if repository != details["repository"]:
                raise StateError(f"Run {run_id} publication reservation evidence is not canonical")
            _stored_datetime(
                details["reserved_at"],
                field=f"run {run_id} publication reservation evidence time",
            )
            if run_id in reservations:
                raise StateError(f"Run {run_id} has duplicate publication reservation evidence")
            reservations[run_id] = _PublicationReservationEvidence(
                run_id=run_id,
                repository=repository,
                reserved_at=details["reserved_at"],
            )
            continue

        if event_type in {"publication.gate.held", "publication.gate.legacy"}:
            expected_keys = {"corpus_cursor", "held_at"}
            if event_type == "publication.gate.held":
                expected_keys.add("deployment_fingerprint")
            modern_keys = {*expected_keys, "outcome_corpus_cursor"}
            if frozenset(details) not in {frozenset(expected_keys), frozenset(modern_keys)}:
                raise StateError(f"Run {run_id} publication gate evidence is incomplete")
            fingerprint: str | None = None
            outcome_cursor: str | None = None
            if event_type == "publication.gate.held":
                fingerprint = _stored_event_hash(
                    details["deployment_fingerprint"],
                    field=f"run {run_id} publication gate evidence deployment fingerprint",
                )
            if "outcome_corpus_cursor" in details:
                if event_type != "publication.gate.held":
                    raise StateError(f"Run {run_id} legacy gate has outcome authority")
                outcome_cursor = _stored_event_hash(
                    details["outcome_corpus_cursor"],
                    field=f"run {run_id} publication gate evidence outcome cursor",
                )
            cursor = _stored_event_hash(
                details["corpus_cursor"],
                field=f"run {run_id} publication gate evidence corpus cursor",
            )
            _stored_datetime(
                details["held_at"],
                field=f"run {run_id} publication gate evidence time",
            )
            if run_id in holds:
                raise StateError(f"Run {run_id} has duplicate publication gate hold evidence")
            holds[run_id] = _PublicationGateEvidence(
                run_id=run_id,
                deployment_fingerprint=fingerprint,
                corpus_cursor=cursor,
                outcome_corpus_cursor=outcome_cursor,
                held_at=details["held_at"],
            )
            continue

        if event_type == "publication.gate.rebound":
            if set(details) != {
                "deployment_fingerprint",
                "corpus_cursor",
                "outcome_corpus_cursor",
                "held_at",
            }:
                raise StateError(f"Run {run_id} publication gate rebind evidence is incomplete")
            existing_hold = holds.get(run_id)
            if existing_hold is None:
                raise StateError(f"Run {run_id} publication gate rebind lacks hold evidence")
            if run_id in releases:
                raise StateError(f"Run {run_id} publication gate rebind follows its release")
            if existing_hold.outcome_corpus_cursor is None:
                raise StateError(f"Run {run_id} publication gate rebind targets a pre-v6 hold")
            rebind_fingerprint = _stored_event_hash(
                details["deployment_fingerprint"],
                field=f"run {run_id} publication gate rebind deployment fingerprint",
            )
            if existing_hold.deployment_fingerprint != rebind_fingerprint:
                raise StateError(
                    f"Run {run_id} publication gate rebind changes its deployment identity"
                )
            _stored_datetime(
                details["held_at"],
                field=f"run {run_id} publication gate rebind time",
            )
            # A rebind re-anchors an unreleased hold to rollout cursors that were verified
            # current in the same transaction; the latest rebind is the effective hold
            # evidence that durable rows and the eventual release must match exactly.
            holds[run_id] = _PublicationGateEvidence(
                run_id=run_id,
                deployment_fingerprint=rebind_fingerprint,
                corpus_cursor=_stored_event_hash(
                    details["corpus_cursor"],
                    field=f"run {run_id} publication gate rebind corpus cursor",
                ),
                outcome_corpus_cursor=_stored_event_hash(
                    details["outcome_corpus_cursor"],
                    field=f"run {run_id} publication gate rebind outcome cursor",
                ),
                held_at=details["held_at"],
            )
            continue

        expected_keys = {"outcome", "corpus_cursor", "held_at"}
        if "deployment_fingerprint" in details:
            expected_keys.add("deployment_fingerprint")
        if "outcome_corpus_cursor" in details:
            expected_keys.add("outcome_corpus_cursor")
        if set(details) != expected_keys or details["outcome"] not in {
            "pr_open",
            "verified_compensation",
        }:
            raise StateError(f"Run {run_id} publication gate release evidence is incomplete")
        release_fingerprint = None
        if "deployment_fingerprint" in details:
            release_fingerprint = _stored_event_hash(
                details["deployment_fingerprint"],
                field=f"run {run_id} publication gate release deployment fingerprint",
            )
        release_cursor = _stored_event_hash(
            details["corpus_cursor"],
            field=f"run {run_id} publication gate release corpus cursor",
        )
        release_outcome_cursor = None
        if "outcome_corpus_cursor" in details:
            release_outcome_cursor = _stored_event_hash(
                details["outcome_corpus_cursor"],
                field=f"run {run_id} publication gate release outcome cursor",
            )
        _stored_datetime(
            details["held_at"],
            field=f"run {run_id} publication gate release time",
        )
        if run_id in releases:
            raise StateError(f"Run {run_id} has duplicate publication gate release evidence")
        releases[run_id] = _PublicationGateEvidence(
            run_id=run_id,
            deployment_fingerprint=release_fingerprint,
            corpus_cursor=release_cursor,
            outcome_corpus_cursor=release_outcome_cursor,
            held_at=details["held_at"],
        )
    return reservations, holds, releases


def _publication_reservation_evidence_from_row(
    row: sqlite3.Row,
) -> _PublicationReservationEvidence:
    run_id_value = row["run_id"]
    repository_value = row["repository"]
    reserved_at_value = row["reserved_at"]
    if (
        not isinstance(run_id_value, str)
        or not run_id_value
        or not isinstance(repository_value, str)
        or not isinstance(reserved_at_value, str)
    ):
        raise StateError("Publication reservation contains invalid stored values")
    try:
        repository = _repository_identity(repository_value)
    except (TypeError, ValueError) as exc:
        raise StateError("Publication reservation contains an invalid repository") from exc
    if repository != repository_value:
        raise StateError(f"Publication reservation for run {run_id_value} is not canonical")
    _stored_datetime(
        reserved_at_value,
        field=f"publication reservation {run_id_value} time",
    )
    return _PublicationReservationEvidence(
        run_id=run_id_value,
        repository=repository,
        reserved_at=reserved_at_value,
    )


def _publication_gate_evidence_from_row(row: sqlite3.Row) -> _PublicationGateEvidence:
    hold = _publication_gate_hold_from_row(row)
    held_at_value = row["held_at"]
    if not isinstance(held_at_value, str):
        raise StateError("Publication gate hold contains invalid stored values")
    return _PublicationGateEvidence(
        run_id=hold.run_id,
        deployment_fingerprint=hold.deployment_fingerprint,
        corpus_cursor=hold.corpus_cursor,
        outcome_corpus_cursor=hold.outcome_corpus_cursor,
        held_at=held_at_value,
    )


def _publication_gate_outcome_projection(connection: sqlite3.Connection) -> str:
    columns = {
        str(row["name"])
        for row in connection.execute("PRAGMA table_info(publication_gate_holds)").fetchall()
    }
    return (
        "outcome_corpus_cursor"
        if "outcome_corpus_cursor" in columns
        else "NULL AS outcome_corpus_cursor"
    )


def _bounded_publication_rows(
    connection: sqlite3.Connection,
) -> tuple[
    dict[str, _PublicationReservationEvidence],
    dict[str, _PublicationGateEvidence],
]:
    reservation_rows = connection.execute(
        """
        SELECT run_id, repository, reserved_at FROM publication_reservations
        ORDER BY run_id LIMIT ?
        """,
        (_MAX_RUN_CORPUS + 1,),
    ).fetchall()
    outcome_projection = _publication_gate_outcome_projection(connection)
    # The projection helper returns one of two hard-coded SQL fragments after inspecting the
    # schema.  No stored or operator-controlled value is interpolated into this statement.
    hold_query = (
        "SELECT run_id, deployment_fingerprint, corpus_cursor, "
        f"{outcome_projection}, held_at "
        "FROM publication_gate_holds ORDER BY run_id LIMIT ?"
    )
    hold_rows = connection.execute(
        hold_query,
        (_MAX_RUN_CORPUS + 1,),
    ).fetchall()
    if len(reservation_rows) > _MAX_RUN_CORPUS:
        raise StateError("Publication reservation set exceeds the configured safety bound")
    if len(hold_rows) > _MAX_RUN_CORPUS:
        raise StateError("Publication gate hold set exceeds the configured safety bound")
    reservations = {
        evidence.run_id: evidence
        for evidence in map(_publication_reservation_evidence_from_row, reservation_rows)
    }
    holds = {
        evidence.run_id: evidence
        for evidence in map(_publication_gate_evidence_from_row, hold_rows)
    }
    if len(reservations) != len(reservation_rows) or len(holds) != len(hold_rows):
        raise StateError("Publication state contains duplicate run identities")
    return reservations, holds


def _migrate_legacy_publication_evidence(connection: sqlite3.Connection) -> None:
    """Attest canonical v3/v4 rows without blessing missing modern evidence."""

    _verify_event_anchors(connection)
    event_reservations, event_holds, releases = _publication_evidence_from_connection(connection)
    row_reservations, row_holds = _bounded_publication_rows(connection)

    for run_id, reservation in row_reservations.items():
        if run_id not in event_reservations:
            _append_event_to_ledger(
                connection,
                run_id,
                "publication.reservation.legacy",
                {
                    "repository": reservation.repository,
                    "reserved_at": reservation.reserved_at,
                },
            )

    for run_id, hold in row_holds.items():
        if run_id not in event_holds and run_id not in releases:
            if hold.deployment_fingerprint is not None:
                raise StateError(
                    f"Run {run_id} has a modern publication gate hold without ledger evidence"
                )
            _append_event_to_ledger(
                connection,
                run_id,
                "publication.gate.legacy",
                {"corpus_cursor": hold.corpus_cursor, "held_at": hold.held_at},
            )

    for run_id, release in releases.items():
        if run_id in event_holds:
            continue
        if run_id in row_holds:
            # Strict reconciliation below rejects released evidence with an active row.
            continue
        if release.deployment_fingerprint is not None:
            raise StateError(
                f"Run {run_id} has a modern publication gate release without hold evidence"
            )
        _append_event_to_ledger(
            connection,
            run_id,
            "publication.gate.legacy",
            {"corpus_cursor": release.corpus_cursor, "held_at": release.held_at},
        )


def _reconcile_publication_state(
    connection: sqlite3.Connection,
    *,
    repair_missing: bool,
    require_current_rollout_cursors: bool = True,
    currency_run_id: str | None = None,
) -> None:
    """Cross-check publication tables against their verified per-run ledger evidence.

    Recovery-capable schema validation and exact compensation may waive current rollout-cursor
    equality without granting constructive authority. Ledger anchors, durable rows, hold identity,
    and every recorded modern deployment scope remain mandatory.

    ``currency_run_id`` scopes the current-cursor requirement to that run's active hold, so one
    crashed run's drifted hold cannot poison an unrelated caller's own validated authority.
    """

    _verify_event_anchors(connection)
    event_reservations, event_holds, releases = _publication_evidence_from_connection(connection)
    row_reservations, row_holds = _bounded_publication_rows(connection)

    for run_id, reservation in event_reservations.items():
        row_reservation = row_reservations.get(run_id)
        if row_reservation is None:
            if not repair_missing:
                raise StateError(f"Run {run_id} publication reservation row is missing")
            connection.execute(
                """
                INSERT INTO publication_reservations(run_id, repository, reserved_at)
                VALUES (?, ?, ?)
                """,
                (run_id, reservation.repository, reservation.reserved_at),
            )
            row_reservations[run_id] = reservation
        elif row_reservation != reservation:
            raise StateError(f"Run {run_id} publication reservation disagrees with ledger evidence")
    for run_id in row_reservations.keys() - event_reservations.keys():
        raise StateError(f"Run {run_id} publication reservation lacks ledger evidence")

    for run_id, release in releases.items():
        hold = event_holds.get(run_id)
        if hold is None:
            raise StateError(f"Run {run_id} publication gate release lacks hold evidence")
        if hold != release:
            raise StateError(f"Run {run_id} publication gate release disagrees with hold evidence")
    for run_id in event_holds.keys() | releases.keys():
        if run_id not in event_reservations:
            raise StateError(f"Run {run_id} publication gate evidence lacks a reservation")

    for run_id, hold in event_holds.items():
        row_hold = row_holds.get(run_id)
        if run_id in releases:
            if row_hold is not None:
                raise StateError(f"Run {run_id} has a released publication gate hold row")
            continue
        if row_hold is None:
            if not repair_missing:
                raise StateError(f"Run {run_id} publication gate hold row is missing")
            connection.execute(
                """
                INSERT INTO publication_gate_holds(
                    run_id, deployment_fingerprint, corpus_cursor,
                    outcome_corpus_cursor, held_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    hold.deployment_fingerprint,
                    hold.corpus_cursor,
                    hold.outcome_corpus_cursor,
                    hold.held_at,
                ),
            )
            row_holds[run_id] = hold
        elif row_hold != hold:
            if row_hold.corpus_cursor != hold.corpus_cursor:
                raise StateError(
                    "Evaluation corpus differs from the active publication gate hold; "
                    "stored hold disagrees with the evaluation corpus"
                )
            raise StateError(f"Run {run_id} publication gate hold disagrees with ledger evidence")
    for run_id in row_holds.keys() - event_holds.keys():
        raise StateError(f"Run {run_id} publication gate hold lacks ledger evidence")

    active_holds = [hold for run_id, hold in row_holds.items() if run_id not in releases]
    for hold in active_holds:
        _validated_active_outcome_scope(connection, hold)
    if active_holds and require_current_rollout_cursors:
        currency_holds = (
            active_holds
            if currency_run_id is None
            else [hold for hold in active_holds if hold.run_id == currency_run_id]
        )
        if currency_holds:
            current_cursor = _evaluation_corpus_cursor_from_connection(connection)
            for hold in currency_holds:
                if hold.corpus_cursor != current_cursor:
                    raise StateError(
                        f"Publication gate hold for run {hold.run_id} disagrees with "
                        "the evaluation corpus"
                    )
                _verify_active_outcome_hold(connection, hold)


def _verify_publication_state(
    connection: sqlite3.Connection,
    *,
    require_current_rollout_cursors: bool,
    currency_run_id: str | None = None,
) -> None:
    _reconcile_publication_state(
        connection,
        repair_missing=False,
        require_current_rollout_cursors=require_current_rollout_cursors,
        currency_run_id=currency_run_id,
    )


def _verify_active_outcome_hold(
    connection: sqlite3.Connection,
    hold: PublicationGateHold | _PublicationGateEvidence,
) -> None:
    """Validate a v6 outcome cursor; a NULL cursor remains fenced legacy evidence."""

    scope = _validated_active_outcome_scope(connection, hold)
    if hold.outcome_corpus_cursor is None:
        return
    if scope is None:  # pragma: no cover - guarded by validated outcome authority
        raise StateError("Publication gate hold outcome scope is missing")
    actual = _upstream_outcome_corpus_cursor_from_connection(connection, *scope)
    if actual != hold.outcome_corpus_cursor:
        raise StateError(
            f"Publication gate hold for run {hold.run_id} disagrees with the "
            "upstream-outcome corpus"
        )


def _validated_active_outcome_scope(
    connection: sqlite3.Connection,
    hold: PublicationGateHold | _PublicationGateEvidence,
) -> tuple[str, str, str, str | None] | None:
    """Validate hold ownership and return its modern outcome scope without comparing cursors."""

    if hold.outcome_corpus_cursor is None:
        # Pre-v6 holds remain eligible only for exposure-reducing compensation. Their exact row
        # and ledger evidence is checked by reconciliation, but no outcome scope was ever held.
        return None
    if hold.deployment_fingerprint is None:
        raise StateError(
            f"Publication gate hold for run {hold.run_id} has outcome authority without a "
            "deployment fingerprint"
        )
    row = connection.execute(
        "SELECT manifest_json FROM runs WHERE run_id = ?",
        (hold.run_id,),
    ).fetchone()
    if row is None or not isinstance(row["manifest_json"], str):
        raise StateError(f"Publication gate hold for run {hold.run_id} lacks its run manifest")
    try:
        manifest = RunManifest.model_validate_json(row["manifest_json"])
    except (TypeError, ValueError) as exc:
        raise StateError(
            f"Publication gate hold for run {hold.run_id} has an invalid run manifest"
        ) from exc
    if manifest.run_id != hold.run_id:
        raise StateError("Publication gate hold manifest identity is inconsistent")
    creation_fingerprint = _run_creation_deployment_fingerprint(connection, hold.run_id)
    if (
        manifest.deployment_fingerprint != creation_fingerprint
        or creation_fingerprint != hold.deployment_fingerprint
    ):
        raise StateError(
            f"Publication gate hold for run {hold.run_id} belongs to a different deployment"
        )
    if manifest.publishing_login is None or manifest.publishing_api_origin is None:
        raise StateError(
            f"Publication gate hold for run {hold.run_id} lacks its publishing identity"
        )
    try:
        return _upstream_outcome_cursor_scope(
            hold.deployment_fingerprint,
            manifest.publishing_login,
            manifest.publishing_api_origin,
            exclude_run_id=hold.run_id,
        )
    except (TypeError, ValueError) as exc:
        raise StateError(
            f"Publication gate hold for run {hold.run_id} has an invalid publishing scope"
        ) from exc


def _publication_gate_hold_from_row(row: sqlite3.Row) -> PublicationGateHold:
    run_id_value = row["run_id"]
    if not isinstance(run_id_value, str) or not run_id_value:
        raise StateError("Publication gate hold contains an invalid run ID")
    fingerprint_value = row["deployment_fingerprint"]
    if fingerprint_value is not None:
        fingerprint_value = _stored_event_hash(
            fingerprint_value,
            field=f"publication gate hold {run_id_value} deployment fingerprint",
        )
    cursor = _stored_event_hash(
        row["corpus_cursor"],
        field=f"publication gate hold {run_id_value} corpus cursor",
    )
    held_at = _stored_datetime(
        row["held_at"],
        field=f"publication gate hold {run_id_value} time",
    )
    return PublicationGateHold(
        run_id=run_id_value,
        deployment_fingerprint=fingerprint_value,
        corpus_cursor=cursor,
        outcome_corpus_cursor=(
            _stored_event_hash(
                row["outcome_corpus_cursor"],
                field=f"publication gate hold {run_id_value} outcome corpus cursor",
            )
            if row["outcome_corpus_cursor"] is not None
            else None
        ),
        held_at=held_at,
    )


def _verify_publication_gate_holds(connection: sqlite3.Connection) -> None:
    outcome_projection = _publication_gate_outcome_projection(connection)
    # The projection is selected from two hard-coded fragments by schema introspection.
    hold_query = (
        "SELECT run_id, deployment_fingerprint, corpus_cursor, "
        f"{outcome_projection}, held_at "
        "FROM publication_gate_holds ORDER BY run_id LIMIT ?"
    )
    rows = connection.execute(
        hold_query,
        (_MAX_RUN_CORPUS + 1,),
    ).fetchall()
    if len(rows) > _MAX_RUN_CORPUS:
        raise StateError("Publication gate hold set exceeds the configured safety bound")
    if not rows:
        return
    current_cursor = _evaluation_corpus_cursor_from_connection(connection)
    for row in rows:
        hold = _publication_gate_hold_from_row(row)
        if hold.corpus_cursor != current_cursor:
            raise StateError(
                f"Publication gate hold for run {hold.run_id} disagrees with the evaluation corpus"
            )
        _verify_active_outcome_hold(connection, hold)


def _release_publication_gate_hold(
    store: RunStore,
    connection: sqlite3.Connection,
    run_id: str,
    *,
    outcome: str,
    required: bool,
) -> bool:
    """Release a publication gate hold with exact identity and outcome-scope validation.

    The release copies the hold's anchored cursors into its ledger evidence verbatim. Corpus
    drift observed after the held mutations completed must not wedge a finished publication:
    constructive authority was already revalidated immediately before every remote mutation,
    and releasing a hold grants no new authority.
    """

    _reconcile_publication_state(
        connection,
        repair_missing=True,
        require_current_rollout_cursors=False,
    )
    row = connection.execute(
        """
        SELECT run_id, deployment_fingerprint, corpus_cursor,
               outcome_corpus_cursor, held_at
        FROM publication_gate_holds WHERE run_id = ?
        """,
        (run_id,),
    ).fetchone()
    if row is None:
        if required:
            raise StateError(f"Run {run_id} does not have an active publication gate hold")
        return False
    hold = _publication_gate_hold_from_row(row)
    if hold.run_id != run_id:
        raise StateError("Publication gate hold identity changed during release")
    _validated_active_outcome_scope(connection, hold)
    release_details = {
        "outcome": outcome,
        "corpus_cursor": hold.corpus_cursor,
        "held_at": str(row["held_at"]),
    }
    if hold.deployment_fingerprint is not None:
        release_details["deployment_fingerprint"] = hold.deployment_fingerprint
    if hold.outcome_corpus_cursor is not None:
        release_details["outcome_corpus_cursor"] = hold.outcome_corpus_cursor
    store._append_event(
        connection,
        run_id,
        "publication.gate.released",
        release_details,
    )
    deletion = connection.execute(
        """
        DELETE FROM publication_gate_holds
        WHERE run_id = ? AND deployment_fingerprint IS ?
          AND corpus_cursor = ? AND outcome_corpus_cursor IS ? AND held_at = ?
        """,
        (
            run_id,
            row["deployment_fingerprint"],
            row["corpus_cursor"],
            row["outcome_corpus_cursor"],
            row["held_at"],
        ),
    )
    if deletion.rowcount != 1:
        raise StateError("Publication gate hold changed while it was being released")
    return True


def _release_publication_gate_hold_for_compensation(
    store: RunStore,
    connection: sqlite3.Connection,
    run_id: str,
    *,
    outcome: str,
    required: bool,
) -> bool:
    """Release an exact compensated hold without treating rollout drift as new authority."""

    return _release_publication_gate_hold(
        store,
        connection,
        run_id,
        outcome=outcome,
        required=required,
    )


def _assert_no_publication_gate_hold(connection: sqlite3.Connection) -> None:
    _reconcile_publication_state(
        connection,
        repair_missing=True,
        require_current_rollout_cursors=False,
    )
    row = connection.execute(
        "SELECT run_id FROM publication_gate_holds ORDER BY run_id LIMIT 1"
    ).fetchone()
    if row is not None:
        run_id = row["run_id"]
        if not isinstance(run_id, str) or not run_id:
            raise StateError("Publication gate hold contains invalid stored values")
        raise StateError(f"Evaluation corpus is held by active publication run {run_id}")


def _next_run_update_time(expected_updated_at: datetime) -> datetime:
    expected_utc = _aware_utc(expected_updated_at, field="manifest updated_at")
    saved_at = _aware_utc(utc_now(), field="run save time")
    if saved_at <= expected_utc:
        try:
            saved_at = expected_utc + timedelta(microseconds=1)
        except OverflowError as exc:
            raise StateError("Run update timestamp exhausted its supported range") from exc
    return saved_at


def _aware_utc(value: datetime, *, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware")
    return value.astimezone(UTC)


def _stored_datetime(value: object, *, field: str) -> datetime:
    if not isinstance(value, str):
        raise StateError(f"Stored {field} is not a timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise StateError(f"Stored {field} is not a valid timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise StateError(f"Stored {field} is not timezone-aware")
    return parsed.astimezone(UTC)


def _stored_canonical_utc_datetime(value: object, *, field: str) -> datetime:
    parsed = _stored_datetime(value, field=field)
    if not isinstance(value, str) or parsed.isoformat() != value:
        raise StateError(f"Stored {field} is not a canonical UTC timestamp")
    return parsed


def _stored_run_status(value: object, *, run_id: str) -> RunStatus:
    try:
        return RunStatus(str(value))
    except ValueError as exc:
        raise StateError(f"Run {run_id} contains an unknown status") from exc


def _generation(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("lease generation must be an integer")
    if not 1 <= value <= _MAX_GENERATION:
        raise ValueError("lease generation is outside the supported range")
    return value


def _stored_generation(value: object, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= _MAX_GENERATION:
        raise StateError(f"Stored {field} is invalid")
    return int(value)


def _stored_event_count(value: object, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise StateError(f"Stored {field} is invalid")
    return int(value)


def _stored_event_hash(value: object, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise StateError(f"Stored {field} is invalid")
    return value


def _stored_authorization_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 32
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise StateError("Candidate retry authorization ID is invalid")
    return value


def _candidate_retry_authorization(
    authorization: CandidateRetryAuthorization,
) -> tuple[str, str]:
    if not isinstance(authorization, CandidateRetryAuthorization):
        raise TypeError("candidate retry authorization has an unsupported type")
    actor = _bounded_text(
        authorization.actor,
        field="candidate retry actor",
        maximum=255,
    )
    reason = _bounded_text(
        authorization.reason,
        field="candidate retry reason",
        maximum=2_000,
    )
    if actor != authorization.actor or any(character in actor for character in ("\r", "\n")):
        raise ValueError("candidate retry actor must be a canonical single-line value")
    if reason != authorization.reason or any(character in reason for character in ("\r", "\n")):
        raise ValueError("candidate retry reason must be canonical single-line text")
    return actor, reason


def _assert_candidate_claim_lease(
    connection: sqlite3.Connection,
    lease: Lease,
    *,
    checked_at: datetime,
) -> None:
    """Fence a candidate claim inside the same write transaction as its row update."""

    if lease.name != _CANDIDATE_CLAIM_LEASE_NAME:
        raise StateError("Candidate claim uses the wrong lease")
    checked = _aware_utc(checked_at, field="candidate claim lease check time")
    row = connection.execute(
        """
        SELECT leases.owner, leases.generation, leases.expires_at,
               lease_generations.generation AS counter_generation
        FROM leases
        LEFT JOIN lease_generations USING(lease_name)
        WHERE leases.lease_name = ?
        """,
        (lease.name,),
    ).fetchone()
    if row is None:
        raise StateError("Candidate claim lease is no longer active")
    stored_generation = _stored_generation(
        row["generation"],
        field="candidate claim lease generation",
    )
    counter_generation = _stored_generation(
        row["counter_generation"],
        field="candidate claim lease generation counter",
    )
    expires_at = _stored_datetime(
        row["expires_at"],
        field="candidate claim lease expiry",
    )
    if (
        row["owner"] != lease.owner
        or stored_generation != lease.generation
        or counter_generation != lease.generation
        or expires_at <= checked
    ):
        raise StateError("Candidate claim lease ownership was lost")


def _sha256_identity(value: str, *, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string")
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"{field} must be a lowercase SHA-256 value")
    return value


def _stored_boolean(value: object, *, field: str) -> bool:
    if value not in (0, 1) or isinstance(value, bool):
        raise StateError(f"Stored {field} is invalid")
    return bool(value)


def _optional_stored_text(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise StateError("Stored circuit-breaker evidence is invalid")
    return value


def _bounded_text(value: str, *, field: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string")
    normalized = value.strip()
    if not normalized or "\0" in normalized or len(normalized) > maximum:
        raise ValueError(f"{field} must be 1-{maximum} non-NUL characters")
    return normalized


def _publication_reservation_request(
    run_id: str,
    repository: str,
    *,
    max_per_utc_day: int,
    repository_cooldown: timedelta,
    now: datetime | None,
    evaluation_corpus_cursor: str | None,
    evaluation_deployment_fingerprint: str | None,
    outcome_corpus_cursor: str | None,
    publishing_login: str | None,
    publishing_api_origin: str | None,
) -> _PublicationReservationRequest:
    normalized_run_id = _lease_identity(run_id, field="publication run id")
    normalized_repository = _repository_identity(repository)
    if isinstance(max_per_utc_day, bool) or not isinstance(max_per_utc_day, int):
        raise TypeError("daily publication maximum must be an integer")
    if not 1 <= max_per_utc_day <= 1_000:
        raise ValueError("daily publication maximum must be between 1 and 1000")
    if not isinstance(repository_cooldown, timedelta):
        raise TypeError("repository cooldown must be a timedelta")
    if repository_cooldown < timedelta(0):
        raise ValueError("repository cooldown cannot be negative")
    gate_values = (
        evaluation_corpus_cursor,
        evaluation_deployment_fingerprint,
        outcome_corpus_cursor,
    )
    if any(value is not None for value in gate_values) and not all(
        value is not None for value in gate_values
    ):
        raise ValueError(
            "evaluation cursor, outcome cursor, deployment fingerprint, publishing login, and "
            "API origin must be provided together"
        )
    expected_corpus_cursor: str | None = None
    expected_deployment_fingerprint: str | None = None
    expected_outcome_cursor: str | None = None
    expected_login: str | None = None
    expected_origin: str | None = None
    if (publishing_login is None) != (publishing_api_origin is None):
        raise ValueError("publishing login and API origin must be provided together")
    if publishing_login is not None and publishing_api_origin is not None:
        scope_deployment = evaluation_deployment_fingerprint or ("0" * 64)
        _, expected_login, expected_origin, _ = _upstream_outcome_cursor_scope(
            scope_deployment,
            publishing_login,
            publishing_api_origin,
            exclude_run_id=normalized_run_id,
        )
    if evaluation_corpus_cursor is not None:
        expected_corpus_cursor = _sha256_identity(
            evaluation_corpus_cursor,
            field="evaluation corpus cursor",
        )
        assert evaluation_deployment_fingerprint is not None
        expected_deployment_fingerprint = _sha256_identity(
            evaluation_deployment_fingerprint,
            field="evaluation deployment fingerprint",
        )
        assert outcome_corpus_cursor is not None
        expected_outcome_cursor = _sha256_identity(
            outcome_corpus_cursor,
            field="upstream-outcome corpus cursor",
        )
        if expected_login is None or expected_origin is None:
            raise ValueError("automatic publication requires a publishing login and API origin")
    reserved_at = _aware_utc(now or utc_now(), field="publication reservation time")
    day_start = reserved_at.replace(hour=0, minute=0, second=0, microsecond=0)
    day_end = day_start + timedelta(days=1)
    try:
        cooldown_start = reserved_at - repository_cooldown
    except OverflowError as exc:
        raise ValueError("repository cooldown exceeds the supported datetime range") from exc
    return _PublicationReservationRequest(
        run_id=normalized_run_id,
        repository=normalized_repository,
        max_per_utc_day=max_per_utc_day,
        reserved_at=reserved_at,
        day_start=day_start,
        day_end=day_end,
        cooldown_start=cooldown_start,
        enforce_cooldown=repository_cooldown > timedelta(0),
        evaluation_corpus_cursor=expected_corpus_cursor,
        evaluation_deployment_fingerprint=expected_deployment_fingerprint,
        outcome_corpus_cursor=expected_outcome_cursor,
        publishing_login=expected_login,
        publishing_api_origin=expected_origin,
    )


def _publication_intent(
    *,
    branch_name: str,
    publication_draft: bool,
    publication_ready_for_review: bool,
    publishing_login: str,
    publishing_api_origin: str,
    commit_author_name: str,
    commit_author_email: str,
    commit_committer_name: str,
    commit_committer_email: str,
) -> _PublicationIntent:
    if not isinstance(publication_draft, bool):
        raise TypeError("publication draft intent must be a boolean")
    if not isinstance(publication_ready_for_review, bool):
        raise TypeError("publication ready-for-review intent must be a boolean")
    if publication_ready_for_review and not publication_draft:
        raise ValueError("ready-for-review publication must be staged as a draft")
    return _PublicationIntent(
        branch_name=_canonical_publication_intent_text(
            branch_name,
            field="publication branch name",
            maximum=255,
        ),
        publication_draft=publication_draft,
        publication_ready_for_review=publication_ready_for_review,
        publishing_login=_canonical_publication_intent_text(
            publishing_login,
            field="publishing login",
            maximum=255,
        ),
        publishing_api_origin=_canonical_publication_intent_text(
            publishing_api_origin,
            field="publishing API origin",
            maximum=2_048,
        ),
        commit_author_name=_canonical_publication_intent_text(
            commit_author_name,
            field="commit author name",
            maximum=200,
        ),
        commit_author_email=_canonical_publication_intent_text(
            commit_author_email,
            field="commit author email",
            maximum=320,
        ),
        commit_committer_name=_canonical_publication_intent_text(
            commit_committer_name,
            field="commit committer name",
            maximum=200,
        ),
        commit_committer_email=_canonical_publication_intent_text(
            commit_committer_email,
            field="commit committer email",
            maximum=320,
        ),
    )


def _canonical_publication_intent_text(value: str, *, field: str, maximum: int) -> str:
    normalized = _bounded_text(value, field=field, maximum=maximum)
    if normalized != value or any(character in value for character in ("\r", "\n")):
        raise ValueError(f"{field} must be a canonical single-line value")
    return normalized


def _validated_snapshot_json(
    value: str,
    *,
    observed_at: datetime,
) -> PullRequestLifecycleSnapshot:
    if not isinstance(value, str):
        raise TypeError("lifecycle snapshot must be a JSON string")
    if len(value.encode("utf-8")) > _MAX_LIFECYCLE_SNAPSHOT_BYTES:
        raise ValueError("lifecycle snapshot exceeds the storage limit")
    return parse_lifecycle_snapshot_json(value, observed_at=observed_at)


def _lease_identity(value: str, *, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string")
    normalized = value.strip()
    if not normalized or "\0" in normalized or len(normalized) > 255:
        raise ValueError(f"{field} must be 1-255 non-NUL characters")
    return normalized


def _repository_identity(value: str) -> str:
    normalized = _lease_identity(value, field="publication repository").casefold()
    if normalized.count("/") != 1:
        raise ValueError("publication repository must use owner/name syntax")
    owner, name = normalized.split("/", 1)
    if not owner or not name:
        raise ValueError("publication repository must use owner/name syntax")
    return normalized


def _candidate_identity(repository: str, issue_number: int) -> tuple[str, int]:
    normalized_repository = _repository_identity(repository)
    if repository != repository.strip() or any(
        character.isspace() or not character.isprintable() for character in repository
    ):
        raise ValueError("candidate repository must be a canonical owner/name value")
    if _CANDIDATE_REPOSITORY.fullmatch(repository) is None:
        raise ValueError("candidate repository must use the GitHub ASCII owner/name syntax")
    owner, name = repository.split("/", 1)
    if owner in {".", ".."} or name in {".", ".."}:
        raise ValueError("candidate repository components cannot be dot paths")
    if isinstance(issue_number, bool) or not isinstance(issue_number, int) or issue_number < 1:
        raise ValueError("candidate issue number must be a positive integer")
    return normalized_repository, issue_number


def _lease_expiry(now: datetime, ttl: timedelta) -> datetime:
    if not isinstance(ttl, timedelta):
        raise TypeError("lease ttl must be a timedelta")
    if ttl <= timedelta(0):
        raise ValueError("lease ttl must be positive")
    try:
        return now + ttl
    except OverflowError as exc:
        raise ValueError("lease ttl exceeds the supported datetime range") from exc


def _fsync_directory(directory: Path) -> None:
    try:
        descriptor = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


__all__ = [
    "CURRENT_SCHEMA_VERSION",
    "RECOVERABLE_IN_FLIGHT_STATUSES",
    "CandidateAttemptDisposition",
    "CandidateAttemptState",
    "CandidateRetryAuthorization",
    "CircuitBreakerStatus",
    "Lease",
    "LifecycleSnapshot",
    "PublicationGateHold",
    "PublicationReservation",
    "RunStore",
]
