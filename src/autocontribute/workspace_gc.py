"""Bounded, fail-closed collection of disposable repository workspaces."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final, Literal, cast

from pydantic import BaseModel, ConfigDict, Field

from autocontribute.domain import TERMINAL_STATUSES, RunManifest, RunStatus
from autocontribute.exceptions import AutocontributeError, StateError
from autocontribute.github_origin import canonical_api_origin
from autocontribute.lifecycle import parse_pull_request_url
from autocontribute.preparation import (
    validate_preparation_fingerprint,
    validate_validation_artifact,
)
from autocontribute.store import RunStore

_MAX_RUNS: Final = 10_000
_MAX_LIMIT: Final = 1_000
_MAX_TREE_ENTRIES: Final = 525_000
_MAX_MANIFEST_BYTES: Final = 10_000_000
_MAX_PREPARATION_ARTIFACT_BYTES: Final = 250_000_000
_CANONICAL_COMMIT_LENGTHS: Final = frozenset({40, 64})
_QUARANTINE_PREFIX: Final = ".autocontribute-gc-"
_QUARANTINED_WORKSPACE: Final = "workspace"
_QUARANTINE_ATTEMPTS: Final = 16
_CANONICAL_PR_EVENTS: Final = frozenset(
    {
        "pull_request.created.response",
        "pull_request.discovered",
        "pull_request.reconciled",
    }
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class WorkspaceGCItem(_StrictModel):
    """One deterministic workspace disposition."""

    run_id: str
    status: RunStatus
    updated_at: datetime
    action: Literal["would_delete", "deleted", "retained"]
    reason: str
    entries: int = Field(ge=0)
    bytes: int = Field(ge=0)
    error: bool = False


class WorkspaceGCReport(_StrictModel):
    """Bounded cleanup result suitable for terminal or JSON reporting."""

    execute: bool
    cutoff: datetime
    limit: int
    terminal_candidates: int = Field(ge=0)
    selected: int = Field(ge=0)
    truncated: int = Field(ge=0)
    protected_nonterminal: int = Field(ge=0)
    younger_terminal: int = Field(ge=0)
    would_delete: int = Field(ge=0)
    deleted: int = Field(ge=0)
    retained: int = Field(ge=0)
    errors: int = Field(ge=0)
    items: list[WorkspaceGCItem]


def collect_terminal_workspaces(
    store: RunStore,
    *,
    older_than: timedelta,
    limit: int = 25,
    execute: bool = False,
    now: datetime | None = None,
) -> WorkspaceGCReport:
    """Report or remove old terminal workspaces without deleting durable run evidence.

    The default is a dry run. ``limit`` bounds workspace inspection, not merely successful
    deletion, so an unsafe old entry cannot cause an unbounded scan in one invocation.
    """

    if not isinstance(older_than, timedelta) or older_than <= timedelta(0):
        raise ValueError("workspace retention age must be a positive duration")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= _MAX_LIMIT:
        raise ValueError("workspace cleanup limit must be between 1 and 1000")
    observed_at = _aware_utc(now or datetime.now(UTC), field="workspace cleanup time")
    try:
        cutoff = observed_at - older_than
    except OverflowError as exc:
        raise ValueError("workspace retention age exceeds the supported datetime range") from exc

    workspace_root_descriptor = _open_safe_directory(
        store.workspaces_dir,
        description="workspace root",
    )
    try:
        # ``oldest_runs`` reads and validates the complete supported corpus before applying this
        # maximum. It raises above 10,000 runs instead of silently truncating, so old runs without
        # workspaces cannot starve a newer eligible workspace from this candidate set.
        manifests = store.oldest_runs(limit=_MAX_RUNS)
        candidates: list[tuple[RunManifest, os.stat_result | None, str | None]] = []
        protected_nonterminal = 0
        younger_terminal = 0
        for manifest in manifests:
            manifest_updated_at = _aware_utc(
                manifest.updated_at,
                field=f"run {manifest.run_id} update time",
            )
            component_error = _run_id_component_error(manifest.run_id)
            metadata: os.stat_result | None = None
            if component_error is None:
                metadata = _entry_metadata(workspace_root_descriptor, manifest.run_id)
            if manifest.status not in TERMINAL_STATUSES:
                if metadata is not None:
                    protected_nonterminal += 1
                continue
            if manifest_updated_at > cutoff:
                if metadata is not None:
                    younger_terminal += 1
                continue
            if component_error is not None:
                # An unsafe durable identifier is itself reportable corruption. Never join it to
                # the workspace root or try to infer where its files might be.
                candidates.append((manifest, None, component_error))
            elif metadata is not None:
                candidates.append((manifest, metadata, None))

        candidates.sort(
            key=lambda item: (
                _aware_utc(item[0].updated_at, field=f"run {item[0].run_id} update time"),
                item[0].run_id,
            )
        )
        selected_candidates = candidates[:limit]
        items: list[WorkspaceGCItem] = []
        for manifest, metadata, component_error in selected_candidates:
            if component_error is not None:
                items.append(
                    _retained_item(
                        manifest,
                        component_error,
                        error=True,
                    )
                )
                continue
            assert metadata is not None
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                items.append(
                    _retained_item(
                        manifest,
                        "workspace entry is not a real directory",
                        error=True,
                    )
                )
                continue

            eligibility_error = _deletion_blocker(store, manifest)
            if eligibility_error is not None:
                reason, is_error = eligibility_error
                items.append(_retained_item(manifest, reason, error=is_error))
                continue

            try:
                entries, size = _inspect_tree(
                    store.workspaces_dir / manifest.run_id,
                    expected=metadata,
                )
            except (OSError, StateError) as exc:
                items.append(
                    _retained_item(
                        manifest,
                        f"workspace tree is unsafe: {exc}",
                        error=True,
                    )
                )
                continue

            if not execute:
                items.append(
                    WorkspaceGCItem(
                        run_id=manifest.run_id,
                        status=manifest.status,
                        updated_at=manifest.updated_at,
                        action="would_delete",
                        reason=_safe_terminal_reason(manifest),
                        entries=entries,
                        bytes=size,
                    )
                )
                continue

            # Re-read both state and evidence after the potentially expensive tree walk. Terminal
            # statuses have no legal outgoing transition, but this closes manual-tampering and
            # stale-process races before the destructive call.
            fresh = store.get(manifest.run_id)
            if fresh != manifest:
                items.append(
                    _retained_item(
                        fresh,
                        "durable run state changed during workspace inspection",
                        error=True,
                        entries=entries,
                        size=size,
                    )
                )
                continue
            eligibility_error = _deletion_blocker(store, fresh)
            if eligibility_error is not None:
                reason, is_error = eligibility_error
                items.append(
                    _retained_item(
                        fresh,
                        reason,
                        error=is_error,
                        entries=entries,
                        size=size,
                    )
                )
                continue
            current = _entry_metadata(workspace_root_descriptor, fresh.run_id)
            if current is None or not _same_entry(metadata, current):
                items.append(
                    _retained_item(
                        fresh,
                        "workspace entry changed during cleanup",
                        error=True,
                        entries=entries,
                        size=size,
                    )
                )
                continue
            if not shutil.rmtree.avoids_symlink_attacks:
                raise StateError("This Python runtime lacks symlink-safe recursive deletion")
            try:
                entries, size = _delete_via_private_quarantine(
                    store.workspaces_dir,
                    workspace_root_descriptor,
                    fresh.run_id,
                    expected=metadata,
                )
            except OSError as exc:
                raise StateError(
                    f"Could not safely delete workspace for run {fresh.run_id}: {exc}"
                ) from exc
            items.append(
                WorkspaceGCItem(
                    run_id=fresh.run_id,
                    status=fresh.status,
                    updated_at=fresh.updated_at,
                    action="deleted",
                    reason=_safe_terminal_reason(fresh),
                    entries=entries,
                    bytes=size,
                )
            )
    finally:
        os.close(workspace_root_descriptor)

    return WorkspaceGCReport(
        execute=execute,
        cutoff=cutoff,
        limit=limit,
        terminal_candidates=len(candidates),
        selected=len(selected_candidates),
        truncated=max(0, len(candidates) - len(selected_candidates)),
        protected_nonterminal=protected_nonterminal,
        younger_terminal=younger_terminal,
        would_delete=sum(item.action == "would_delete" for item in items),
        deleted=sum(item.action == "deleted" for item in items),
        retained=sum(item.action == "retained" for item in items),
        errors=sum(item.error for item in items),
        items=items,
    )


def _deletion_blocker(
    store: RunStore,
    manifest: RunManifest,
) -> tuple[str, bool] | None:
    """Return a reason to retain, distinguishing expected protection from corruption."""

    if manifest.status not in TERMINAL_STATUSES:
        return ("run is not terminal", False)
    try:
        store.verify_event_chains(run_id=manifest.run_id)
        if store.has_active_publication_gate_hold(manifest.run_id):
            return ("run still owns a durable publication gate hold", True)
        _validate_manifest_artifact(store, manifest)
        _validate_prepared_artifacts(store, manifest)
        has_publication_intent = store.has_publication_reconstruction_evidence(manifest.run_id)
        if manifest.status == RunStatus.PR_OPEN:
            if not has_publication_intent:
                return ("published run lacks durable publication-intent evidence", True)
            _validate_published_identity(manifest)
            _validate_published_event_proof(store, manifest)
            return None
        if has_publication_intent or _has_manifest_publication_state(manifest):
            return (
                "non-published terminal run retains publication reconstruction evidence",
                False,
            )
    except (AutocontributeError, OSError, TypeError, ValueError) as exc:
        return (f"durable recovery evidence is incomplete or invalid: {exc}", True)
    return None


def _validate_manifest_artifact(store: RunStore, manifest: RunManifest) -> None:
    artifact_root = _safe_run_artifact_root(store, manifest.run_id)
    data = _read_regular_file(
        artifact_root / "manifest.json",
        maximum=_MAX_MANIFEST_BYTES,
        description="manifest artifact",
    )
    try:
        artifact = RunManifest.model_validate_json(data)
    except ValueError as exc:
        raise StateError("manifest artifact is invalid") from exc
    if artifact != manifest:
        raise StateError("manifest artifact disagrees with durable state")


def _validate_prepared_artifacts(store: RunStore, manifest: RunManifest) -> None:
    prepared = manifest.preparation_fingerprint is not None or manifest.status == RunStatus.PR_OPEN
    if not prepared:
        return
    artifact_root = _safe_run_artifact_root(store, manifest.run_id)
    patch = _read_regular_file(
        artifact_root / "contribution.patch",
        maximum=_MAX_PREPARATION_ARTIFACT_BYTES,
        description="contribution patch artifact",
    )
    validation = _read_regular_file(
        artifact_root / "validation.json",
        maximum=_MAX_PREPARATION_ARTIFACT_BYTES,
        description="validation artifact",
    )
    validate_preparation_fingerprint(manifest, diff=patch)
    validate_validation_artifact(manifest, artifact=validation)


def _validate_published_identity(manifest: RunManifest) -> None:
    if manifest.candidate is None or manifest.repository is None:
        raise StateError("published run is missing repository evidence")
    if not manifest.pull_request_url or not manifest.publishing_api_origin:
        raise StateError("published run is missing its canonical pull-request identity")
    if not manifest.branch_name or not manifest.publishing_login:
        raise StateError("published run is missing its durable branch identity")
    origin = canonical_api_origin(manifest.publishing_api_origin)
    if origin != manifest.publishing_api_origin:
        raise StateError("published run has a non-canonical GitHub API origin")
    repository, _number = parse_pull_request_url(
        manifest.pull_request_url,
        api_origin=origin,
    )
    expected_repository = manifest.candidate.repository
    if repository.casefold() != expected_repository.casefold():
        raise StateError("published pull-request URL does not match its candidate")
    if manifest.repository.full_name.casefold() != expected_repository.casefold():
        raise StateError("published repository evidence is internally inconsistent")
    if not _canonical_git_sha(manifest.commit_sha):
        raise StateError("published run is missing a canonical contribution commit SHA")
    if not _canonical_git_sha(manifest.base_sha):
        raise StateError("published run is missing a canonical base commit SHA")
    identities = (
        manifest.commit_author_name,
        manifest.commit_author_email,
        manifest.commit_committer_name,
        manifest.commit_committer_email,
    )
    if any(not value for value in identities):
        raise StateError("published run is missing its durable Git identity")
    if manifest.publication_draft is None:
        raise StateError("published run is missing its durable draft intent")


def _validate_published_event_proof(store: RunStore, manifest: RunManifest) -> None:
    """Require ordered, hash-chained intent, canonical PR, and terminal transition evidence."""

    assert manifest.candidate is not None
    assert manifest.pull_request_url is not None
    assert manifest.branch_name is not None
    assert manifest.publishing_login is not None
    assert manifest.publishing_api_origin is not None
    assert manifest.commit_author_name is not None
    assert manifest.commit_author_email is not None
    assert manifest.commit_committer_name is not None
    assert manifest.commit_committer_email is not None
    assert manifest.publication_draft is not None
    assert manifest.commit_sha is not None
    assert manifest.base_sha is not None

    events = store.events(manifest.run_id)
    intent_indices = [
        index
        for index, event in enumerate(events)
        if event["event_type"] == "publication.intent.begun"
    ]
    if len(intent_indices) != 1:
        raise StateError("published run lacks one unambiguous publication-intent event")
    intent_index = intent_indices[0]
    intent = _event_details(events[intent_index])
    expected_intent = {
        "repository": manifest.candidate.repository.casefold(),
        "branch": manifest.branch_name,
        "draft": "true" if manifest.publication_draft else "false",
        "publishing_login": manifest.publishing_login,
        "publishing_api_origin": manifest.publishing_api_origin,
        "commit_author_name": manifest.commit_author_name,
        "commit_author_email": manifest.commit_author_email,
        "commit_committer_name": manifest.commit_committer_name,
        "commit_committer_email": manifest.commit_committer_email,
    }
    if intent != expected_intent:
        raise StateError("published run's publication-intent event disagrees with its manifest")

    repository, number = parse_pull_request_url(
        manifest.pull_request_url,
        api_origin=manifest.publishing_api_origin,
    )
    canonical_indices: list[int] = []
    for index, event in enumerate(events):
        event_type = event["event_type"]
        if event_type not in _CANONICAL_PR_EVENTS:
            continue
        details = _event_details(event)
        if _canonical_pr_event_matches(
            event_type,
            details,
            manifest=manifest,
            repository=repository,
            number=number,
        ):
            canonical_indices.append(index)
    if not canonical_indices:
        raise StateError("published run lacks canonical pull-request persistence evidence")

    for transition_index, event in enumerate(events):
        if event["event_type"] != "run.transitioned":
            continue
        transition = _event_details(event)
        if (
            transition.get("from") == RunStatus.SUBMITTING.value
            and transition.get("to") == RunStatus.PR_OPEN.value
            and bool(transition.get("reason"))
            and any(
                intent_index < canonical_index < transition_index
                for canonical_index in canonical_indices
            )
        ):
            return
    raise StateError(
        "published run lacks an ordered submitting-to-pr_open transition after canonical "
        "PR evidence"
    )


def _event_details(event: dict[str, str]) -> dict[str, str]:
    try:
        value = json.loads(event["details"])
    except (KeyError, TypeError, ValueError) as exc:
        raise StateError("published run contains malformed publication event details") from exc
    if not isinstance(value, dict) or any(
        not isinstance(key, str) or not isinstance(item, str) for key, item in value.items()
    ):
        raise StateError("published run contains invalid publication event details")
    return cast(dict[str, str], value)


def _canonical_pr_event_matches(
    event_type: str,
    details: dict[str, str],
    *,
    manifest: RunManifest,
    repository: str,
    number: int,
) -> bool:
    if details.get("url") != manifest.pull_request_url:
        return False
    if event_type == "pull_request.created.response":
        return (
            details.get("repository", "").casefold() == repository.casefold()
            and details.get("number") == str(number)
            and details.get("head_sha", "").casefold() == manifest.commit_sha
            and details.get("base_sha", "").casefold() == manifest.base_sha
            and details.get("state") in {"open", "closed", "merged"}
        )
    if event_type == "pull_request.discovered":
        return (
            details.get("repository", "").casefold() == repository.casefold()
            and details.get("number") == str(number)
            and details.get("head_sha", "").casefold() == manifest.commit_sha
        )
    if event_type == "pull_request.reconciled":
        return details.get("base_sha", "").casefold() == manifest.base_sha and details.get(
            "state"
        ) in {"open", "closed_unmerged", "merged"}
    return False


def _has_manifest_publication_state(manifest: RunManifest) -> bool:
    return manifest.pull_request_creation_started or any(
        value is not None
        for value in (
            manifest.publishing_login,
            manifest.publishing_api_origin,
            manifest.commit_author_name,
            manifest.commit_author_email,
            manifest.commit_committer_name,
            manifest.commit_committer_email,
            manifest.publication_draft,
            manifest.branch_name,
            manifest.commit_sha,
            manifest.publication_compensation_reason,
            manifest.pull_request_url,
        )
    )


def _safe_run_artifact_root(store: RunStore, run_id: str) -> Path:
    component_error = _run_id_component_error(run_id)
    if component_error is not None:
        raise StateError(component_error)
    _require_real_directory(store.runs_dir, description="run-artifact root")
    path = store.runs_dir / run_id
    _require_real_directory(path, description="run artifact directory")
    return path


def _read_regular_file(path: Path, *, maximum: int, description: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise StateError(f"{description} is missing or unsafe") from exc
    if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        raise StateError(f"{description} is missing, unsafe, or oversized")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not _same_entry(before, opened):
            raise StateError(f"{description} changed while it was opened")
        with os.fdopen(descriptor, "rb") as source:
            descriptor = -1
            data = source.read(maximum + 1)
        if len(data) > maximum:
            raise StateError(f"{description} exceeds the safe size limit")
        return data
    except StateError:
        raise
    except OSError as exc:
        raise StateError(f"{description} could not be read safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _inspect_tree(path: Path, *, expected: os.stat_result) -> tuple[int, int]:
    """Bound one deletion and reject nested mounts before recursive removal."""

    current = path.lstat()
    if not stat.S_ISDIR(current.st_mode) or not _same_entry(expected, current):
        raise StateError("workspace root changed before inspection")
    if os.path.ismount(path):
        raise StateError("workspace entry is a mount point")
    entries = 1
    size = current.st_size

    def raise_walk_error(error: OSError) -> None:
        raise StateError(f"workspace tree could not be inspected: {error}") from error

    for directory, directories, filenames in os.walk(
        path,
        topdown=True,
        onerror=raise_walk_error,
        followlinks=False,
    ):
        directory_path = Path(directory)
        directory_metadata = directory_path.lstat()
        if directory_metadata.st_dev != expected.st_dev:
            raise StateError("workspace crosses a filesystem boundary")
        if directory_path != path and os.path.ismount(directory_path):
            raise StateError("workspace contains a nested mount point")
        for name in (*directories, *filenames):
            child = directory_path / name
            metadata = child.lstat()
            entries += 1
            size += metadata.st_size
            if entries > _MAX_TREE_ENTRIES:
                raise StateError("workspace tree exceeds the safe entry bound")
            if (
                stat.S_ISDIR(metadata.st_mode)
                and not stat.S_ISLNK(metadata.st_mode)
                and (metadata.st_dev != expected.st_dev or os.path.ismount(child))
            ):
                raise StateError("workspace contains a nested mount point")
    after = path.lstat()
    if not _same_entry(expected, after):
        raise StateError("workspace root changed during inspection")
    return entries, size


def _delete_via_private_quarantine(
    workspace_root: Path,
    workspace_root_descriptor: int,
    run_id: str,
    *,
    expected: os.stat_result,
) -> tuple[int, int]:
    """Atomically isolate one exact directory before descriptor-relative removal."""

    quarantine_name, quarantine_descriptor, quarantine_metadata = _create_private_quarantine(
        workspace_root_descriptor
    )
    quarantine_is_empty = True
    try:
        os.rename(
            run_id,
            _QUARANTINED_WORKSPACE,
            src_dir_fd=workspace_root_descriptor,
            dst_dir_fd=quarantine_descriptor,
        )
        quarantine_is_empty = False
        try:
            os.fsync(workspace_root_descriptor)
            os.fsync(quarantine_descriptor)
            moved = _entry_metadata(quarantine_descriptor, _QUARANTINED_WORKSPACE)
            if moved is None or not _same_entry(expected, moved):
                raise StateError("workspace identity changed while it was quarantined")
            named_quarantine = _entry_metadata(workspace_root_descriptor, quarantine_name)
            if named_quarantine is None or not _same_entry(quarantine_metadata, named_quarantine):
                raise StateError("private workspace quarantine changed during cleanup")
            entries, size = _inspect_tree(
                workspace_root / quarantine_name / _QUARANTINED_WORKSPACE,
                expected=moved,
            )
            named_quarantine = _entry_metadata(workspace_root_descriptor, quarantine_name)
            current = _entry_metadata(quarantine_descriptor, _QUARANTINED_WORKSPACE)
            if (
                named_quarantine is None
                or not _same_entry(quarantine_metadata, named_quarantine)
                or current is None
                or not _same_entry(moved, current)
            ):
                raise StateError("quarantined workspace changed during final inspection")
        except (OSError, StateError) as exc:
            current = _entry_metadata(quarantine_descriptor, _QUARANTINED_WORKSPACE)
            if current is None:
                raise StateError(
                    "Quarantined workspace changed and could not be restored; "
                    "no deletion was attempted"
                ) from exc
            try:
                _restore_quarantined_workspace(
                    workspace_root_descriptor,
                    quarantine_descriptor,
                    run_id,
                    expected=current,
                )
            except (OSError, StateError) as restore_exc:
                raise StateError(
                    "Quarantined workspace failed validation and could not be safely restored; "
                    "no deletion was attempted"
                ) from restore_exc
            quarantine_is_empty = True
            raise StateError(f"Quarantined workspace was restored without deletion: {exc}") from exc

        try:
            shutil.rmtree(_QUARANTINED_WORKSPACE, dir_fd=quarantine_descriptor)
            quarantine_is_empty = True
            os.fsync(quarantine_descriptor)
        except OSError as exc:
            raise StateError(
                "Recursive deletion failed after workspace isolation; the quarantine was preserved"
            ) from exc
        return entries, size
    finally:
        os.close(quarantine_descriptor)
        if quarantine_is_empty:
            _remove_empty_quarantine(
                workspace_root_descriptor,
                quarantine_name,
                expected=quarantine_metadata,
            )


def _create_private_quarantine(root_descriptor: int) -> tuple[str, int, os.stat_result]:
    root_metadata = os.fstat(root_descriptor)
    for _attempt in range(_QUARANTINE_ATTEMPTS):
        name = f"{_QUARANTINE_PREFIX}{secrets.token_hex(16)}"
        try:
            os.mkdir(name, mode=0o700, dir_fd=root_descriptor)
        except FileExistsError:
            continue
        metadata = _entry_metadata(root_descriptor, name)
        if (
            metadata is None
            or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or metadata.st_dev != root_metadata.st_dev
        ):
            raise StateError("Could not create a safe private workspace quarantine")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = -1
        try:
            descriptor = os.open(name, flags, dir_fd=root_descriptor)
            opened = os.fstat(descriptor)
            if not stat.S_ISDIR(opened.st_mode) or not _same_entry(metadata, opened):
                raise StateError("Private workspace quarantine changed while it was opened")
            os.fsync(root_descriptor)
            return name, descriptor, opened
        except Exception:
            if descriptor >= 0:
                os.close(descriptor)
            _remove_empty_quarantine(root_descriptor, name, expected=metadata)
            raise
    raise StateError("Could not allocate a unique private workspace quarantine")


def _restore_quarantined_workspace(
    workspace_root_descriptor: int,
    quarantine_descriptor: int,
    run_id: str,
    *,
    expected: os.stat_result,
) -> None:
    if _entry_metadata(workspace_root_descriptor, run_id) is not None:
        raise StateError("workspace path was repopulated before quarantine restoration")
    os.rename(
        _QUARANTINED_WORKSPACE,
        run_id,
        src_dir_fd=quarantine_descriptor,
        dst_dir_fd=workspace_root_descriptor,
    )
    restored = _entry_metadata(workspace_root_descriptor, run_id)
    if restored is None or not _same_entry(expected, restored):
        raise StateError("restored workspace identity is not the quarantined entry")
    os.fsync(quarantine_descriptor)
    os.fsync(workspace_root_descriptor)


def _remove_empty_quarantine(
    workspace_root_descriptor: int,
    name: str,
    *,
    expected: os.stat_result,
) -> None:
    current = _entry_metadata(workspace_root_descriptor, name)
    if current is None:
        raise StateError("private workspace quarantine disappeared during cleanup")
    if not _same_entry(expected, current):
        raise StateError("private workspace quarantine changed before removal")
    try:
        os.rmdir(name, dir_fd=workspace_root_descriptor)
        os.fsync(workspace_root_descriptor)
    except OSError as exc:
        raise StateError("Could not remove the empty private workspace quarantine") from exc


def _open_safe_directory(path: Path, *, description: str) -> int:
    metadata = _require_real_directory(path, description=description)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise StateError(f"{description} could not be opened safely") from exc
    opened = os.fstat(descriptor)
    if not stat.S_ISDIR(opened.st_mode) or not _same_entry(metadata, opened):
        os.close(descriptor)
        raise StateError(f"{description} changed while it was opened")
    return descriptor


def _require_real_directory(path: Path, *, description: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise StateError(f"{description} is missing or unsafe") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise StateError(f"{description} is missing or unsafe")
    try:
        if path.resolve(strict=True) != path:
            raise StateError(f"{description} must be an exact real path")
    except OSError as exc:
        raise StateError(f"{description} is missing or unsafe") from exc
    return metadata


def _entry_metadata(root_descriptor: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise StateError(f"Could not inspect workspace entry for run {name}: {exc}") from exc


def _run_id_component_error(run_id: str) -> str | None:
    if (
        not isinstance(run_id, str)
        or len(run_id) != 16
        or run_id != run_id.casefold()
        or any(character not in "0123456789abcdef" for character in run_id)
    ):
        return "durable run identifier is not a canonical 16-character run ID"
    return None


def _canonical_git_sha(value: str | None) -> bool:
    return bool(
        value
        and len(value) in _CANONICAL_COMMIT_LENGTHS
        and value == value.casefold()
        and all(character in "0123456789abcdef" for character in value)
    )


def _same_entry(first: os.stat_result, second: os.stat_result) -> bool:
    return first.st_dev == second.st_dev and first.st_ino == second.st_ino


def _safe_terminal_reason(manifest: RunManifest) -> str:
    if manifest.status == RunStatus.PR_OPEN:
        return "published run has complete durable PR and prepared-artifact evidence"
    return "terminal run has no ambiguous publication state"


def _retained_item(
    manifest: RunManifest,
    reason: str,
    *,
    error: bool,
    entries: int = 0,
    size: int = 0,
) -> WorkspaceGCItem:
    return WorkspaceGCItem(
        run_id=manifest.run_id,
        status=manifest.status,
        updated_at=manifest.updated_at,
        action="retained",
        reason=reason,
        entries=entries,
        bytes=size,
        error=error,
    )


def _aware_utc(value: datetime, *, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware")
    return value.astimezone(UTC)


__all__ = [
    "WorkspaceGCItem",
    "WorkspaceGCReport",
    "collect_terminal_workspaces",
]
