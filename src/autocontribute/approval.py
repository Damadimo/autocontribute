"""Exact, expiring approval fingerprints for outbound publication."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator

from autocontribute.config import PublishingConfig
from autocontribute.domain import Approval, RunManifest, utc_now
from autocontribute.exceptions import PolicyError

_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_GIT_SHA = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FINGERPRINT_DOMAIN = b"autocontribute.approval.v3\x00"


class ApprovalManifest(BaseModel):
    """The complete publication surface authorized by a user.

    This is intentionally separate from ``RunManifest``: run metadata can
    continue to evolve without silently changing the approval protocol.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(default=3, frozen=True)
    repository: str
    issue_number: int = Field(gt=0)
    base_sha: str
    preparation_fingerprint: str
    publishing_login: str
    publishing_api_origin: str
    commit_author_name: str
    commit_author_email: str
    commit_committer_name: str
    commit_committer_email: str
    base_branch: str
    draft: bool
    diff_sha256: str
    commit_message: str
    pull_request_title: str
    pull_request_body: str
    disclosure: str

    @field_validator("repository")
    @classmethod
    def valid_repository(cls, value: str) -> str:
        if not _REPOSITORY.fullmatch(value):
            raise ValueError("repository must use owner/name syntax")
        return value

    @field_validator("base_sha")
    @classmethod
    def valid_base_sha(cls, value: str) -> str:
        lowered = value.casefold()
        if not _GIT_SHA.fullmatch(lowered):
            raise ValueError("base_sha must be a full 40- or 64-character git SHA")
        return lowered

    @field_validator("preparation_fingerprint")
    @classmethod
    def valid_preparation_fingerprint(cls, value: str) -> str:
        lowered = value.casefold()
        if not _SHA256.fullmatch(lowered):
            raise ValueError("preparation_fingerprint must be a SHA-256 hex digest")
        return lowered

    @field_validator("publishing_login")
    @classmethod
    def canonical_publishing_login(cls, value: str) -> str:
        canonical = value.strip().casefold()
        if not canonical:
            raise ValueError("publishing_login cannot be blank")
        return canonical

    @field_validator("publishing_api_origin")
    @classmethod
    def canonical_publishing_api_origin(cls, value: str) -> str:
        try:
            parsed = urlparse(value)
            port = parsed.port
        except ValueError as exc:
            raise ValueError("publishing_api_origin must be a canonical HTTPS origin") from exc
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.params
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("publishing_api_origin must be a canonical HTTPS origin")
        host = parsed.hostname.casefold()
        if ":" in host:
            host = f"[{host}]"
        expected = f"https://{host}" + (f":{port}" if port is not None else "")
        if value != expected:
            raise ValueError("publishing_api_origin must be a canonical HTTPS origin")
        return value

    @field_validator(
        "commit_author_name",
        "commit_committer_name",
    )
    @classmethod
    def valid_git_name(cls, value: str) -> str:
        if (
            not value
            or value != value.strip()
            or len(value) > 200
            or any(character in value for character in ("\0", "\r", "\n"))
        ):
            raise ValueError("git identity names must be canonical single-line values")
        return value

    @field_validator(
        "commit_author_email",
        "commit_committer_email",
    )
    @classmethod
    def valid_git_email(cls, value: str) -> str:
        if (
            not value
            or value != value.strip()
            or len(value) > 320
            or "@" not in value
            or any(character in value for character in ("\0", "\r", "\n", "<", ">"))
        ):
            raise ValueError("git identity emails must be canonical single-line addresses")
        return value

    @field_validator("base_branch")
    @classmethod
    def base_branch_is_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("base_branch cannot be blank")
        return value

    @field_validator("diff_sha256")
    @classmethod
    def valid_diff_sha256(cls, value: str) -> str:
        lowered = value.casefold()
        if not _SHA256.fullmatch(lowered):
            raise ValueError("diff_sha256 must be a SHA-256 hex digest")
        return lowered

    @field_validator(
        "commit_message",
        "pull_request_title",
        "pull_request_body",
        "disclosure",
    )
    @classmethod
    def publication_text_is_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("approval publication fields cannot be blank")
        return value


@dataclass(frozen=True, slots=True)
class ApprovalReview:
    """One fully validated snapshot shown before a human approval."""

    run: RunManifest
    patch: bytes
    validation_artifact: bytes
    manifest: ApprovalManifest
    fingerprint: str


def hash_diff(diff: str | bytes) -> str:
    """Hash the exact diff bytes; newline or whitespace changes invalidate approval."""

    payload = diff.encode("utf-8") if isinstance(diff, str) else diff
    return hashlib.sha256(payload).hexdigest()


def build_approval_manifest(
    run: RunManifest,
    *,
    diff: str | bytes,
    disclosure: str,
    draft: bool,
) -> ApprovalManifest:
    """Extract the exact publishable fields from a ready run."""

    if run.candidate is None:
        raise PolicyError("Cannot approve a run without an issue candidate")
    if run.base_sha is None:
        raise PolicyError("Cannot approve a run without a pinned base SHA")
    if run.repository is None:
        raise PolicyError("Cannot approve a run without repository metadata")
    if run.proposal is None:
        raise PolicyError("Cannot approve a run without a patch proposal")
    required_context = {
        "preparation fingerprint": run.preparation_fingerprint,
        "publishing login": run.publishing_login,
        "publishing API origin": run.publishing_api_origin,
        "commit author name": run.commit_author_name,
        "commit author email": run.commit_author_email,
        "commit committer name": run.commit_committer_name,
        "commit committer email": run.commit_committer_email,
    }
    missing = [name for name, value in required_context.items() if not value]
    if missing:
        raise PolicyError(
            "Cannot approve a run without durable publication context: " + ", ".join(missing)
        )
    assert run.preparation_fingerprint is not None
    assert run.publishing_login is not None
    assert run.publishing_api_origin is not None
    assert run.commit_author_name is not None
    assert run.commit_author_email is not None
    assert run.commit_committer_name is not None
    assert run.commit_committer_email is not None
    return ApprovalManifest(
        repository=run.candidate.repository,
        issue_number=run.candidate.number,
        base_sha=run.base_sha,
        preparation_fingerprint=run.preparation_fingerprint,
        publishing_login=run.publishing_login,
        publishing_api_origin=run.publishing_api_origin,
        commit_author_name=run.commit_author_name,
        commit_author_email=run.commit_author_email,
        commit_committer_name=run.commit_committer_name,
        commit_committer_email=run.commit_committer_email,
        base_branch=run.repository.default_branch,
        draft=draft,
        diff_sha256=hash_diff(diff),
        commit_message=run.proposal.commit_message,
        pull_request_title=run.proposal.pull_request_title,
        pull_request_body=run.proposal.pull_request_body,
        disclosure=disclosure,
    )


def manifest_fingerprint(manifest: ApprovalManifest) -> str:
    """Return a domain-separated SHA-256 fingerprint of canonical JSON."""

    canonical = json.dumps(
        manifest.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(_FINGERPRINT_DOMAIN + canonical).hexdigest()


def create_approval(
    manifest: ApprovalManifest,
    *,
    actor: str,
    attestation: str,
    config: PublishingConfig,
    now: datetime | None = None,
) -> Approval:
    """Create an approval for the exact manifest using configured expiry."""

    if not actor.strip():
        raise PolicyError("Approval actor cannot be blank")
    if not attestation.strip():
        raise PolicyError("Approval attestation cannot be blank")
    approved_at = _aware_utc(now or utc_now(), field="approval time")
    return Approval(
        actor=actor,
        approved_at=approved_at,
        expires_at=approved_at + timedelta(hours=config.approval_expires_hours),
        manifest_hash=manifest_fingerprint(manifest),
        attestation=attestation,
    )


def validate_approval(
    approval: Approval,
    manifest: ApprovalManifest,
    *,
    now: datetime | None = None,
) -> None:
    """Require a live approval for this exact manifest or raise ``PolicyError``."""

    checked_at = _aware_utc(now or utc_now(), field="validation time")
    approved_at = _aware_utc(approval.approved_at, field="approved_at")
    expires_at = _aware_utc(approval.expires_at, field="expires_at")
    if expires_at <= approved_at:
        raise PolicyError("Approval has an invalid expiry interval")
    if checked_at < approved_at:
        raise PolicyError("Approval is not valid yet")
    if checked_at >= expires_at:
        raise PolicyError("Approval has expired")
    expected = manifest_fingerprint(manifest)
    if not hmac.compare_digest(approval.manifest_hash, expected):
        raise PolicyError("Approval does not match the exact publication manifest")
    if not approval.actor.strip() or not approval.attestation.strip():
        raise PolicyError("Approval is missing its actor or attestation")
    if approval.actor.strip().casefold() != manifest.publishing_login:
        raise PolicyError("Approval actor does not match the authorized GitHub publishing account")


def approval_is_valid(
    approval: Approval,
    manifest: ApprovalManifest,
    *,
    now: datetime | None = None,
) -> bool:
    """Boolean form for status displays; publication should call ``validate_approval``."""

    try:
        validate_approval(approval, manifest, now=now)
    except PolicyError:
        return False
    return True


def _aware_utc(value: datetime, *, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise PolicyError(f"{field} must be timezone-aware")
    return value.astimezone(UTC)


__all__ = [
    "ApprovalManifest",
    "ApprovalReview",
    "approval_is_valid",
    "build_approval_manifest",
    "create_approval",
    "hash_diff",
    "manifest_fingerprint",
    "validate_approval",
]
