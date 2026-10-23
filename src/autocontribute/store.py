"""Durable run manifests and an append-only, hash-chained event ledger."""

from __future__ import annotations

import builtins
import hashlib
import json
import os
import re
import shutil
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Final, cast

from autocontribute.ai_policy import RepositoryAiPolicy
from autocontribute.domain import (
    ALLOWED_TRANSITIONS,
    TERMINAL_STATUSES,
    IssueCandidate,
    RunManifest,
    RunStatus,
    utc_now,
)
from autocontribute.exceptions import (
    CircuitBreakerTrigger,
    PolicyError,
    StateError,
    StopScope,
)
from autocontribute.issue_revision import compute_issue_revision
from autocontribute.lifecycle import parse_pull_request_url

CURRENT_SCHEMA_VERSION: Final = 9
_MAX_GENERATION: Final = 2**63 - 1
_MAX_ACTIVE_CIRCUIT_BREAKER_TRIGGERS: Final = 10_000
_MAX_RUN_CORPUS: Final = 10_000
_CANDIDATE_REPOSITORY: Final = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_GIT_SHA: Final = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SHA256: Final = re.compile(r"^[0-9a-f]{64}$")
_HTTPS_KEY: Final = re.compile(r"^https://[^\s/]+(?:/\S*)?$")
# Escalating holds in this many repositories within the window stop everything.
_ESCALATION_REPOSITORIES: Final = 2
_ESCALATION_WINDOW: Final = timedelta(days=30)
_INITIAL_EVENT_HASH: Final = "0" * 64
_METADATA_COLUMNS: Final = {"singleton", "schema_version", "migrated_at"}
_RUN_COLUMNS: Final = {
    "run_id",
    "status",
    "repository",
    "issue_number",
    "created_at",
    "updated_at",
    "manifest_json",
    "event_count",
    "event_head_hash",
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
_REPOSITORY_POLICY_COLUMNS: Final = {
    "repository",
    "policy_sha256",
    "policy_json",
    "recorded_at",
}
_HOLD_COLUMNS: Final = {
    "id",
    "scope",
    "scope_key",
    "source",
    "reason",
    "trigger_hash",
    "counts_toward_escalation",
    "created_at",
    "expires_at",
    "released_at",
    "released_by",
    "release_reason",
}
_REQUIRED_INDEXES: Final = {
    "runs_status_idx",
    "runs_candidate_idx",
    "events_run_idx",
    "leases_expiry_idx",
    "circuit_breaker_events_epoch_idx",
    "publication_reservations_reserved_at_idx",
    "publication_reservations_repository_idx",
    "runs_candidate_revision_idx",
    "runs_active_candidate_idx",
    "holds_active_idx",
}
# Development builds created schemas 1-8. That state is not migrated; opening it asks the
# operator to start a fresh state root.

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
    expires_at: datetime


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
class Hold:
    """A scoped stop that blocks only the work its scope names."""

    hold_id: int
    scope: StopScope
    scope_key: str
    source: str
    reason: str
    trigger_hash: str
    created_at: datetime
    expires_at: datetime | None


@dataclass(frozen=True, slots=True)
class PublicationReservation:
    run_id: str
    repository: str
    reserved_at: datetime


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


@dataclass(frozen=True, slots=True)
class _PublicationReservationEvidence:
    run_id: str
    repository: str
    reserved_at: str


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

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()
        self.runs_dir = self.root / "runs"
        self.workspaces_dir = self.root / "workspaces"
        self.database_path = self.root / "state.sqlite3"
        self.root.mkdir(parents=True, exist_ok=True)
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        self.workspaces_dir.mkdir(parents=True, exist_ok=True)
        self._initialize()
        self.synchronize_manifest_artifacts()

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
            self._supported_schema_version(connection)
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("BEGIN IMMEDIATE")
            if self._supported_schema_version(connection) == 0:
                self._create_schema(connection)
            _reconcile_publication_state(connection, repair_missing=True)
            self._validate_current_schema(connection)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _supported_schema_version(self, connection: sqlite3.Connection) -> int:
        """Return the stored schema version, refusing state this release cannot open."""

        version = self._detect_schema_version(connection)
        if version > CURRENT_SCHEMA_VERSION:
            raise StateError(
                f"State schema {version} is newer than supported schema {CURRENT_SCHEMA_VERSION}"
            )
        if self._is_development_schema(connection, version):
            raise StateError(
                f"State database {self.database_path} was created by an older development "
                f"version of Autocontribute (schema {version}) and cannot be migrated; delete "
                f"the state directory {self.root} and run again"
            )
        return version

    @classmethod
    def _is_development_schema(cls, connection: sqlite3.Connection, version: int) -> bool:
        """Whether stored state comes from a development build this release does not migrate."""

        return version not in {0, CURRENT_SCHEMA_VERSION}

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
            "circuit_breaker",
            "circuit_breaker_events",
            "publication_reservations",
            "manifest_artifact_sync",
            "candidate_retry_authorizations",
            "repository_policies",
            "holds",
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
        if "schema_metadata" not in tables:
            raise StateError("State database lacks schema metadata and is not supported")
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

    @staticmethod
    def _create_schema(connection: sqlite3.Connection) -> None:
        """Create the complete current schema in an empty database.

        The canonical schema manifest is derived from these statements, so any textual change
        here also changes what every existing state database must match.
        """

        statements = (
            f"""
            CREATE TABLE runs (
                run_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                repository TEXT,
                issue_number INTEGER,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                manifest_json TEXT NOT NULL,
                event_count INTEGER NOT NULL DEFAULT 0 CHECK(event_count >= 0),
                event_head_hash TEXT NOT NULL DEFAULT '{_INITIAL_EVENT_HASH}' CHECK(
                    length(event_head_hash) = 64
                    AND event_head_hash NOT GLOB '*[^0-9a-f]*'
                ),
                issue_revision TEXT CHECK(
                    issue_revision IS NULL OR (
                        length(issue_revision) = 64
                        AND issue_revision NOT GLOB '*[^0-9a-f]*'
                    )
                )
            )
            """,
            "CREATE INDEX runs_status_idx ON runs(status)",
            "CREATE INDEX runs_candidate_idx ON runs(repository, issue_number, status)",
            """
            CREATE INDEX runs_candidate_revision_idx
            ON runs(repository COLLATE NOCASE, issue_number, issue_revision, status)
            """,
            """
            CREATE UNIQUE INDEX runs_active_candidate_idx
            ON runs(repository COLLATE NOCASE, issue_number)
            WHERE issue_number IS NOT NULL
                AND status NOT IN ('cancelled', 'failed', 'rejected', 'skipped')
            """,
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
            """,
            "CREATE INDEX events_run_idx ON events(run_id, id)",
            """
            CREATE TABLE schema_metadata (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                schema_version INTEGER NOT NULL CHECK(schema_version >= 1),
                migrated_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE leases (
                lease_name TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                generation INTEGER NOT NULL CHECK(generation >= 1),
                acquired_at TEXT NOT NULL,
                heartbeat_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
            """,
            "CREATE INDEX leases_expiry_idx ON leases(expires_at)",
            """
            CREATE TABLE lease_generations (
                lease_name TEXT PRIMARY KEY,
                generation INTEGER NOT NULL CHECK(generation >= 1)
            )
            """,
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
            """,
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
            """,
            "CREATE INDEX circuit_breaker_events_epoch_idx ON circuit_breaker_events(epoch, id)",
            """
            CREATE TABLE publication_reservations (
                run_id TEXT PRIMARY KEY REFERENCES runs(run_id),
                repository TEXT NOT NULL,
                reserved_at TEXT NOT NULL
            )
            """,
            """
            CREATE INDEX publication_reservations_reserved_at_idx
            ON publication_reservations(reserved_at)
            """,
            """
            CREATE INDEX publication_reservations_repository_idx
            ON publication_reservations(repository, reserved_at)
            """,
            """
            CREATE TABLE manifest_artifact_sync (
                run_id TEXT PRIMARY KEY REFERENCES runs(run_id),
                updated_at TEXT NOT NULL,
                manifest_sha256 TEXT NOT NULL CHECK(
                    length(manifest_sha256) = 64
                    AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'
                )
            )
            """,
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
            """,
            """
            CREATE TABLE repository_policies (
                repository TEXT PRIMARY KEY COLLATE NOCASE,
                policy_sha256 TEXT NOT NULL CHECK(
                    length(policy_sha256) = 64
                    AND policy_sha256 NOT GLOB '*[^0-9a-f]*'
                ),
                policy_json TEXT NOT NULL,
                recorded_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE holds (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scope TEXT NOT NULL CHECK(
                    scope IN ('publication', 'repository', 'pull_request')
                ),
                scope_key TEXT NOT NULL COLLATE NOCASE,
                source TEXT NOT NULL,
                reason TEXT NOT NULL,
                trigger_hash TEXT NOT NULL UNIQUE,
                counts_toward_escalation INTEGER NOT NULL CHECK(
                    counts_toward_escalation IN (0, 1)
                ),
                created_at TEXT NOT NULL,
                expires_at TEXT,
                released_at TEXT,
                released_by TEXT,
                release_reason TEXT,
                CHECK(
                    (released_at IS NULL AND released_by IS NULL AND release_reason IS NULL)
                    OR (released_at IS NOT NULL AND released_by IS NOT NULL
                        AND release_reason IS NOT NULL)
                )
            )
            """,
            """
            CREATE INDEX holds_active_idx ON holds(scope, scope_key)
            WHERE released_at IS NULL
            """,
        )
        for statement in statements:
            connection.execute(statement)
        created_at = utc_now().isoformat()
        connection.execute(
            """
            INSERT INTO circuit_breaker(
                singleton, is_tripped, epoch, changed_at, source, reason, trigger_hash
            ) VALUES (1, 0, 1, ?, NULL, NULL, NULL)
            """,
            (created_at,),
        )
        connection.execute(
            """
            INSERT INTO schema_metadata(singleton, schema_version, migrated_at)
            VALUES (1, ?, ?)
            """,
            (CURRENT_SCHEMA_VERSION, created_at),
        )

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
    def _expected_schema_manifest(cls) -> tuple[tuple[str, str, str, str | None], ...]:
        expected = sqlite3.connect(":memory:")
        expected.row_factory = sqlite3.Row
        expected.execute("PRAGMA foreign_keys = ON")
        try:
            cls._create_schema(expected)
            return cls._schema_manifest(expected)
        finally:
            expected.close()

    @classmethod
    def _validate_current_schema(cls, connection: sqlite3.Connection) -> None:
        expected = {
            "schema_metadata": _METADATA_COLUMNS,
            "runs": _RUN_COLUMNS,
            "events": _EVENT_COLUMNS,
            "leases": _LEASE_COLUMNS,
            "lease_generations": _LEASE_GENERATION_COLUMNS,
            "circuit_breaker": _CIRCUIT_BREAKER_COLUMNS,
            "circuit_breaker_events": _CIRCUIT_BREAKER_EVENT_COLUMNS,
            "publication_reservations": _PUBLICATION_RESERVATION_COLUMNS,
            "manifest_artifact_sync": _MANIFEST_ARTIFACT_SYNC_COLUMNS,
            "candidate_retry_authorizations": _CANDIDATE_RETRY_AUTHORIZATION_COLUMNS,
            "repository_policies": _REPOSITORY_POLICY_COLUMNS,
            "holds": _HOLD_COLUMNS,
        }
        tables = cls._table_names(connection)
        if tables != set(expected):
            raise StateError("State database contains missing or unsupported tables")
        for table, columns in expected.items():
            if cls._table_columns(connection, table) != columns:
                raise StateError(f"State table {table} has an unsupported shape")
        if not _REQUIRED_INDEXES.issubset(cls._index_names(connection)):
            raise StateError("State database is missing one or more required indexes")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise StateError("State database contains invalid foreign-key references")
        version = cls._detect_schema_version(connection)
        if version != CURRENT_SCHEMA_VERSION:
            raise StateError(
                f"State schema {version} does not match supported schema {CURRENT_SCHEMA_VERSION}"
            )
        if cls._schema_manifest(connection) != cls._expected_schema_manifest():
            raise StateError("State database schema objects do not match the canonical manifest")
        _verify_circuit_breaker_evidence(connection)
        _verify_event_anchors(connection)
        _verify_manifest_artifact_sync(connection)
        _verify_publication_state(connection)
        _verify_issue_revision_evidence(connection)

    @property
    def schema_version(self) -> int:
        with self._connection() as connection:
            return self._detect_schema_version(connection)

    def create_run(self) -> RunManifest:
        now = utc_now()
        manifest = RunManifest(
            run_id=uuid.uuid4().hex[:16],
            status=RunStatus.QUEUED,
            created_at=now,
            updated_at=now,
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
            self._append_event(connection, manifest.run_id, "run.created", {"status": "queued"})
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

    def repository_ai_policy(
        self, repository: str, policy_sha256: str
    ) -> RepositoryAiPolicy | None:
        """Return the AI-policy reading cached for exactly these policy files, if there is one."""

        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT policy_json FROM repository_policies
                WHERE repository = ? AND policy_sha256 = ?
                """,
                (repository, policy_sha256),
            ).fetchone()
        if row is None:
            return None
        return RepositoryAiPolicy.model_validate_json(row["policy_json"])

    def record_repository_ai_policy(
        self,
        repository: str,
        policy_sha256: str,
        policy: RepositoryAiPolicy,
    ) -> None:
        """Cache an AI-policy reading, replacing the one for the repository's older files."""

        if not _CANDIDATE_REPOSITORY.fullmatch(repository) or not _SHA256.fullmatch(policy_sha256):
            raise StateError(
                "Repository policy cache keys must be an owner/name and a SHA-256 hex digest"
            )
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO repository_policies(
                    repository, policy_sha256, policy_json, recorded_at
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(repository) DO UPDATE SET
                    policy_sha256 = excluded.policy_sha256,
                    policy_json = excluded.policy_json,
                    recorded_at = excluded.recorded_at
                """,
                (repository, policy_sha256, policy.model_dump_json(), utc_now().isoformat()),
            )

    def list_open_pull_request_runs(self, *, limit: int = 1_000) -> builtins.list[RunManifest]:
        """Return every PR still open when last observed, failing instead of truncating the set.

        Merged and closed pull requests are never observed again, so they do not count toward
        the bound.
        """

        return self._list_runs_with_status(
            RunStatus.PR_OPEN,
            limit=limit,
            resource="open pull-request",
            open_pull_requests_only=True,
        )

    def list_merged_pull_request_runs(
        self, *, merged_since: datetime, limit: int = 1_000
    ) -> builtins.list[RunManifest]:
        """Return every run whose pull request merged at or after ``merged_since``."""

        return self._list_runs_with_status(
            RunStatus.PR_OPEN,
            limit=limit,
            resource="recently merged pull-request",
            merged_since=_aware_utc(merged_since, field="merge watch start"),
        )

    def list_submitting_runs(self, *, limit: int = 100) -> builtins.list[RunManifest]:
        """Return every ambiguous publication intent for remote reconciliation."""

        return self._list_runs_with_status(
            RunStatus.SUBMITTING,
            limit=limit,
            resource="submitting",
        )

    def _list_runs_with_status(
        self,
        status: RunStatus,
        *,
        limit: int,
        resource: str,
        open_pull_requests_only: bool = False,
        merged_since: datetime | None = None,
    ) -> builtins.list[RunManifest]:
        """Enumerate a complete bounded status set and validate row/manifest agreement."""

        if not 1 <= limit <= 10_000:
            raise ValueError(f"{resource} run limit must be between 1 and 10000")
        state_filter = ""
        parameters: builtins.list[str | int] = [status.value]
        if open_pull_requests_only:
            state_filter = (
                "AND coalesce(json_extract(manifest_json, '$.pull_request_state'), 'open') = 'open'"
            )
        elif merged_since is not None:
            state_filter = (
                "AND json_extract(manifest_json, '$.pull_request_state') = 'merged' "
                "AND julianday(json_extract(manifest_json, '$.pull_request_merged_at')) "
                ">= julianday(?)"
            )
            parameters.append(merged_since.isoformat())
        parameters.append(limit + 1)
        with self._connection() as connection:
            rows = connection.execute(
                # Only the fixed filters above are interpolated; values stay bound parameters.
                f"""
                SELECT run_id, manifest_json FROM runs
                WHERE status = ? {state_filter} ORDER BY created_at ASC, run_id ASC LIMIT ?
                """,
                parameters,
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
        if manifest.status in TERMINAL_STATUSES:
            self._remove_workspace(manifest.run_id)

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

    def finalize_merged_publication_compensation(
        self,
        manifest: RunManifest,
        *,
        pull_request_url: str,
        reason: str,
    ) -> RunManifest:
        """Adopt one exact already-merged compensating PR into lifecycle management.

        This is not a general PR_OPEN transition: the durable created-PR compensation marker and
        exact URL must remain intact in the committing transaction.
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
                _reconcile_publication_state(connection, repair_missing=True)
                _assert_merged_publication_compensation_events(
                    connection,
                    manifest,
                    pull_request_url=expected_pull_request_url,
                )
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
        self._remove_workspace(manifest.run_id)
        return manifest

    def finalize_publication_compensation(
        self,
        manifest: RunManifest,
        *,
        reason: str,
        evidence: dict[str, str],
    ) -> RunManifest:
        """Finalize verified compensation after exact remote cleanup evidence is durable."""

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
                _reconcile_publication_state(connection, repair_missing=True)
                _assert_failed_publication_compensation_events(
                    connection,
                    manifest,
                    reason=normalized_reason,
                    evidence=verified_details,
                )
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
        self._remove_workspace(manifest.run_id)
        return manifest

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
    ) -> RunManifest:
        """Atomically persist publication intent, capacity, and SUBMITTING."""

        if manifest.status not in {RunStatus.APPROVED, RunStatus.SUBMITTING}:
            raise StateError(
                f"Run {manifest.run_id} cannot begin publication from {manifest.status.value}"
            )
        request = _publication_reservation_request(
            manifest.run_id,
            repository,
            max_per_utc_day=max_per_utc_day,
            repository_cooldown=repository_cooldown,
            now=now,
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
    ) -> PublicationReservation:
        """Durably consume local publication capacity before the first remote mutation."""

        request = _publication_reservation_request(
            run_id,
            repository,
            max_per_utc_day=max_per_utc_day,
            repository_cooldown=repository_cooldown,
            now=now,
        )
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            return self._reserve_publication_in_transaction(connection, request)

    def _reserve_publication_in_transaction(
        self,
        connection: sqlite3.Connection,
        request: _PublicationReservationRequest,
    ) -> PublicationReservation:
        _reconcile_publication_state(connection, repair_missing=True)
        existing = connection.execute(
            """
            SELECT repository, reserved_at FROM publication_reservations
            WHERE run_id = ?
            """,
            (request.run_id,),
        ).fetchone()
        run = connection.execute(
            "SELECT repository FROM runs WHERE run_id = ?", (request.run_id,)
        ).fetchone()
        if run is None:
            raise StateError(f"Unknown run: {request.run_id}")
        run_repository = run["repository"]
        if run_repository is not None:
            if not isinstance(run_repository, str):
                raise StateError(f"Run {request.run_id} has an invalid repository")
            if _repository_identity(run_repository) != request.repository:
                raise StateError(f"Run {request.run_id} does not belong to {request.repository}")

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

        return PublicationReservation(
            run_id=request.run_id,
            repository=request.repository,
            reserved_at=effective_reserved_at,
        )

    def recover_stale_runs(
        self,
        *,
        stale_before: datetime,
        reason: str,
        limit: int = 100,
    ) -> builtins.list[RunManifest]:
        """Atomically fail abandoned local preparation stages and append ledger evidence."""

        return self._retire_runs(
            RECOVERABLE_IN_FLIGHT_STATUSES,
            RunStatus.FAILED,
            updated_before=stale_before,
            reason=reason,
            event="run.recovered",
            record_error=True,
            limit=limit,
        )

    def expire_ready_for_approval_runs(
        self,
        *,
        ready_before: datetime,
        reason: str,
        limit: int = 100,
    ) -> builtins.list[RunManifest]:
        """Cancel prepared runs that nobody approved in time.

        A run reaches ``ready_for_approval`` in its last save and is saved again only when it is
        approved or cancelled, so its update time is when it became ready.
        """

        return self._retire_runs(
            frozenset({RunStatus.READY_FOR_APPROVAL}),
            RunStatus.CANCELLED,
            updated_before=ready_before,
            reason=reason,
            event="run.expired",
            record_error=False,
            limit=limit,
        )

    def _retire_runs(
        self,
        statuses: frozenset[RunStatus],
        target: RunStatus,
        *,
        updated_before: datetime,
        reason: str,
        event: str,
        record_error: bool,
        limit: int,
    ) -> builtins.list[RunManifest]:
        """Move runs unchanged in ``statuses`` since the cutoff to ``target`` in one transaction."""

        cutoff = _aware_utc(updated_before, field="run cutoff")
        retire_reason = _bounded_text(reason, field=f"{event} reason", maximum=2_000)
        if not 1 <= limit <= 1_000:
            raise ValueError("run limit must be between 1 and 1000")
        retirable = tuple(sorted(status.value for status in statuses))
        placeholders = ",".join("?" for _ in retirable)
        retired_at = utc_now()
        retired: builtins.list[RunManifest] = []
        # Only placeholder tokens are interpolated; all status values remain bound parameters.
        query = (
            "SELECT run_id, status, updated_at, manifest_json FROM runs "
            f"WHERE status IN ({placeholders}) AND updated_at < ? "
            "ORDER BY updated_at ASC, run_id ASC LIMIT ?"
        )
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                query,
                (*retirable, cutoff.isoformat(), limit),
            ).fetchall()
            for row in rows:
                run_id = str(row["run_id"])
                previous_status = _stored_run_status(row["status"], run_id=run_id)
                if previous_status not in statuses:
                    continue
                try:
                    manifest = RunManifest.model_validate_json(row["manifest_json"])
                except (TypeError, ValueError) as exc:
                    raise StateError(f"Run {run_id} contains an invalid manifest") from exc
                if manifest.run_id != run_id or manifest.status != previous_status:
                    raise StateError(f"Run {run_id} manifest disagrees with its state row")
                manifest.status = target
                if record_error:
                    manifest.error = retire_reason
                manifest.updated_at = retired_at
                manifest_json = manifest.model_dump_json()
                result = connection.execute(
                    """
                    UPDATE runs SET status = ?, updated_at = ?, manifest_json = ?
                    WHERE run_id = ? AND status = ? AND updated_at = ?
                    """,
                    (
                        target.value,
                        retired_at.isoformat(),
                        manifest_json,
                        run_id,
                        previous_status.value,
                        str(row["updated_at"]),
                    ),
                )
                if result.rowcount != 1:
                    raise StateError(f"Run {run_id} changed while it was being retired")
                self._append_event(
                    connection,
                    run_id,
                    event,
                    {
                        "from": previous_status.value,
                        "to": target.value,
                        "reason": retire_reason,
                    },
                )
                _mark_manifest_artifact_sync(
                    connection,
                    run_id=run_id,
                    updated_at=retired_at.isoformat(),
                    manifest_json=manifest_json,
                )
                retired.append(manifest)
        self.synchronize_manifest_artifacts()
        for manifest in retired:
            self._remove_workspace(manifest.run_id)
        return retired

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
            _stored_datetime(row["acquired_at"], field=f"lease {lease_name} acquisition")
            return Lease(
                name=lease_name,
                owner=lease_owner,
                generation=lease_generation,
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
        _stored_datetime(row["acquired_at"], field=f"lease {lease_name} acquisition")
        _stored_datetime(row["heartbeat_at"], field=f"lease {lease_name} heartbeat")
        return Lease(
            name=lease_name,
            owner=str(row["owner"]),
            generation=lease_generation,
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

    def trip_circuit_breaker(self, *, source: str, reason: str, trigger_hash: str) -> bool:
        """Trip persistently and make each new immutable trigger the active revision."""

        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            return self._trip_circuit_breaker(
                connection,
                source=source,
                reason=reason,
                trigger_hash=trigger_hash,
            )

    def _trip_circuit_breaker(
        self,
        connection: sqlite3.Connection,
        *,
        source: str,
        reason: str,
        trigger_hash: str,
    ) -> bool:
        normalized_source = _bounded_text(source, field="circuit-breaker source", maximum=255)
        normalized_reason = _bounded_text(reason, field="circuit-breaker reason", maximum=2_000)
        normalized_hash = _lease_identity(trigger_hash, field="circuit-breaker trigger hash")
        occurred_at = utc_now()
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
                raise StateError("Circuit-breaker trigger hash was reused for different evidence")
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

    def record_stop(self, trigger: CircuitBreakerTrigger) -> bool:
        """Persist a safety event at its scope and return whether its evidence is new.

        A global event trips the circuit breaker; every other scope becomes a hold. As with the
        breaker, evidence recorded once never stops work again after it was released, so only new
        or edited evidence does.
        """

        if trigger.scope is StopScope.GLOBAL:
            if (
                trigger.scope_key
                or trigger.expires_at is not None
                or trigger.counts_toward_escalation
            ):
                raise ValueError("a global stop has no scope key, expiry, or escalation")
            return self.trip_circuit_breaker(
                source=trigger.source,
                reason=trigger.reason,
                trigger_hash=trigger.trigger_hash,
            )
        if trigger.counts_toward_escalation and trigger.scope is not StopScope.REPOSITORY:
            raise ValueError("only repository holds count toward escalation")
        scope_key = _hold_key(trigger.scope, trigger.scope_key)
        source = _bounded_text(trigger.source, field="hold source", maximum=255)
        reason = _bounded_text(trigger.reason, field="hold reason", maximum=2_000)
        trigger_hash = _lease_identity(trigger.trigger_hash, field="hold trigger hash")
        expires_at = (
            None
            if trigger.expires_at is None
            else _aware_utc(trigger.expires_at, field="hold expiry").isoformat()
        )
        created_at = utc_now()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            inserted = connection.execute(
                """
                INSERT INTO holds(
                    scope, scope_key, source, reason, trigger_hash, counts_toward_escalation,
                    created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(trigger_hash) DO NOTHING
                """,
                (
                    trigger.scope.value,
                    scope_key,
                    source,
                    reason,
                    trigger_hash,
                    int(trigger.counts_toward_escalation),
                    created_at.isoformat(),
                    expires_at,
                ),
            )
            if inserted.rowcount != 1:
                existing = connection.execute(
                    "SELECT scope, scope_key, source, reason FROM holds WHERE trigger_hash = ?",
                    (trigger_hash,),
                ).fetchone()
                if existing is None or (
                    str(existing["scope"]),
                    str(existing["scope_key"]).casefold(),
                    str(existing["source"]),
                    str(existing["reason"]),
                ) != (trigger.scope.value, scope_key.casefold(), source, reason):
                    raise StateError("Hold trigger hash was reused for different evidence")
                return False
            if trigger.counts_toward_escalation:
                held = connection.execute(
                    """
                    SELECT DISTINCT scope_key FROM holds
                    WHERE scope = 'repository' AND counts_toward_escalation = 1
                        AND released_at IS NULL AND created_at >= ?
                    """,
                    ((created_at - _ESCALATION_WINDOW).isoformat(),),
                ).fetchall()
                if len(held) >= _ESCALATION_REPOSITORIES:
                    self._trip_circuit_breaker(
                        connection,
                        source="escalation:maintainer_stops",
                        reason=(
                            f"Maintainers of {len(held)} repositories turned away automated "
                            f"contributions within 30 days, most recently {scope_key}"
                        ),
                        trigger_hash=hashlib.sha256(
                            f"maintainer-stop-escalation:{trigger_hash}".encode()
                        ).hexdigest(),
                    )
        return True

    def active_holds(self) -> builtins.list[Hold]:
        """Return holds that are neither released nor expired, oldest first."""

        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT id, scope, scope_key, source, reason, trigger_hash, created_at, expires_at
                FROM holds
                WHERE released_at IS NULL AND (expires_at IS NULL OR expires_at > ?)
                ORDER BY id
                """,
                (utc_now().isoformat(),),
            ).fetchall()
        return [
            Hold(
                hold_id=int(row["id"]),
                scope=StopScope(str(row["scope"])),
                scope_key=str(row["scope_key"]),
                source=str(row["source"]),
                reason=str(row["reason"]),
                trigger_hash=str(row["trigger_hash"]),
                created_at=_stored_datetime(row["created_at"], field="hold creation time"),
                expires_at=(
                    None
                    if row["expires_at"] is None
                    else _stored_datetime(row["expires_at"], field="hold expiry")
                ),
            )
            for row in rows
        ]

    def release_hold(self, hold_id: int, *, actor: str, reason: str) -> bool:
        """Release one hold after an operator review; return False if it was already released."""

        if isinstance(hold_id, bool) or not isinstance(hold_id, int) or hold_id < 1:
            raise ValueError("hold ID must be a positive integer")
        released_by = _bounded_text(actor, field="release actor", maximum=255)
        release_reason = _bounded_text(reason, field="release reason", maximum=2_000)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            known = connection.execute("SELECT 1 FROM holds WHERE id = ?", (hold_id,)).fetchone()
            if known is None:
                raise StateError(f"Unknown hold: {hold_id}")
            result = connection.execute(
                """
                UPDATE holds SET released_at = ?, released_by = ?, release_reason = ?
                WHERE id = ? AND released_at IS NULL
                """,
                (utc_now().isoformat(), released_by, release_reason, hold_id),
            )
        return result.rowcount == 1

    def assert_publication_not_held(
        self,
        repository: str,
        pull_request_url: str | None = None,
    ) -> None:
        """Refuse publication while a publication, repository, or pull-request hold applies.

        A publication hold names the API origin that blocked the account. One store serves one
        GitHub instance, so it holds every publication.
        """

        for hold in self.active_holds():
            if (
                hold.scope is StopScope.PUBLICATION
                or (
                    hold.scope is StopScope.REPOSITORY
                    and hold.scope_key.casefold() == repository.casefold()
                )
                or (
                    hold.scope is StopScope.PULL_REQUEST
                    and pull_request_url is not None
                    and hold.scope_key.casefold() == pull_request_url.casefold()
                )
            ):
                raise PolicyError(
                    f"Publication is held by {hold.source}: {hold.reason} (release it with "
                    f"`autocontribute safety release {hold.hold_id}` after review)"
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

    def artifact_dir(self, run_id: str) -> Path:
        path = self.runs_dir / run_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def workspace_dir(self, run_id: str) -> Path:
        path = self.workspaces_dir / run_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def remove_finished_workspaces(self) -> None:
        """Delete workspaces left behind by runs that finished before this call."""

        finished = tuple(sorted(status.value for status in TERMINAL_STATUSES))
        placeholders = ",".join("?" for _ in finished)
        # Only placeholder tokens are interpolated; all status values remain bound parameters.
        query = f"SELECT run_id FROM runs WHERE status IN ({placeholders}) ORDER BY run_id"
        with self._connection() as connection:
            rows = connection.execute(query, finished).fetchall()
        for row in rows:
            self._remove_workspace(str(row["run_id"]))

    def _remove_workspace(self, run_id: str) -> None:
        """Best-effort deletion of a finished run's clone; its evidence in runs/ stays."""

        path = self.workspaces_dir / run_id
        if path.parent != self.workspaces_dir or path.name == "..":
            raise StateError(f"Run identifier cannot name a workspace: {run_id!r}")
        if path.is_symlink() or not path.is_dir():
            return
        # A partial failure keeps the remainder; the next run's cleanup retries it.
        with suppress(OSError):
            shutil.rmtree(path)

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


def _verify_issue_revision_evidence(connection: sqlite3.Connection) -> None:
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
        if details.get("issue_revision") != revision:
            raise StateError(f"Run {run_id} candidate selection has a mismatched issue revision")
        expected_keys = {"issue", "issue_revision", "score"}
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
    covered_event_ids: set[int] = set()
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
        raise StateError("Candidate retry override event lacks durable authorization provenance")
    return authorized_runs


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


def _publication_evidence_from_connection(
    connection: sqlite3.Connection,
) -> dict[str, _PublicationReservationEvidence]:
    rows = connection.execute(
        """
        SELECT run_id, details_json FROM events
        WHERE event_type = 'publication.reserved' ORDER BY id LIMIT ?
        """,
        (_MAX_RUN_CORPUS + 1,),
    ).fetchall()
    if len(rows) > _MAX_RUN_CORPUS:
        raise StateError("Publication evidence exceeds the configured safety bound")

    reservations: dict[str, _PublicationReservationEvidence] = {}
    for row in rows:
        run_id_value = row["run_id"]
        details_value = row["details_json"]
        if (
            not isinstance(run_id_value, str)
            or not run_id_value
            or not isinstance(details_value, str)
        ):
            raise StateError("Publication evidence contains invalid stored values")
        run_id = run_id_value
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
        if set(details) != {"repository", "reserved_at"}:
            raise StateError(f"Run {run_id} publication reservation evidence is incomplete")
        try:
            repository = _repository_identity(details["repository"])
        except (TypeError, ValueError) as exc:
            raise StateError(f"Run {run_id} publication reservation evidence is invalid") from exc
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
    return reservations


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


def _bounded_publication_rows(
    connection: sqlite3.Connection,
) -> dict[str, _PublicationReservationEvidence]:
    reservation_rows = connection.execute(
        """
        SELECT run_id, repository, reserved_at FROM publication_reservations
        ORDER BY run_id LIMIT ?
        """,
        (_MAX_RUN_CORPUS + 1,),
    ).fetchall()
    if len(reservation_rows) > _MAX_RUN_CORPUS:
        raise StateError("Publication reservation set exceeds the configured safety bound")
    reservations = {
        evidence.run_id: evidence
        for evidence in map(_publication_reservation_evidence_from_row, reservation_rows)
    }
    if len(reservations) != len(reservation_rows):
        raise StateError("Publication state contains duplicate run identities")
    return reservations


def _reconcile_publication_state(
    connection: sqlite3.Connection,
    *,
    repair_missing: bool,
) -> None:
    """Cross-check publication reservations against their verified per-run ledger evidence."""

    _verify_event_anchors(connection)
    event_reservations = _publication_evidence_from_connection(connection)
    row_reservations = _bounded_publication_rows(connection)

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


def _verify_publication_state(connection: sqlite3.Connection) -> None:
    _reconcile_publication_state(connection, repair_missing=False)


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


def _hold_key(scope: StopScope, value: str) -> str:
    key = _lease_identity(value, field=f"{scope.value} hold key")
    pattern = {
        StopScope.REPOSITORY: _CANDIDATE_REPOSITORY,
        StopScope.PULL_REQUEST: _HTTPS_KEY,
        StopScope.PUBLICATION: _HTTPS_KEY,
    }[scope]
    if key != value or pattern.fullmatch(key) is None:
        raise ValueError(f"{scope.value} hold key is not canonical: {value!r}")
    return key


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
    "Hold",
    "Lease",
    "PublicationReservation",
    "RunStore",
]
