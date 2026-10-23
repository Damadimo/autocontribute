"""Durable fingerprints for the exact preparation that passed quality gates."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Protocol

from autocontribute.config import AutocontributeConfig
from autocontribute.domain import RunManifest, RunModels
from autocontribute.exceptions import PolicyError

_FINGERPRINT_DOMAIN = b"autocontribute.preparation.v3\x00"
_FINGERPRINT_SCHEMA_VERSION = 3
_CONFIG_FINGERPRINT_DOMAIN = b"autocontribute.preparation-config.v3\x00"
_CONFIG_FINGERPRINT_SCHEMA_VERSION = 3


class _Digest(Protocol):
    def update(self, data: bytes, /) -> None: ...


def compute_preparation_fingerprint(
    manifest: RunManifest,
    *,
    diff: str | bytes,
) -> str:
    """Hash the exact patch bytes and stable evidence that authorized readiness.

    Mutable lifecycle fields are deliberately excluded. The length-prefixed
    framing keeps the patch and canonical evidence payload unambiguous. The evidence covers
    ``validation.json`` through its SHA-256.
    """

    if manifest.candidate is None:
        raise PolicyError("Cannot fingerprint a preparation without an issue candidate")
    if manifest.repository is None:
        raise PolicyError("Cannot fingerprint a preparation without repository metadata")
    if manifest.base_sha is None:
        raise PolicyError("Cannot fingerprint a preparation without a pinned base SHA")
    if manifest.proposal is None:
        raise PolicyError("Cannot fingerprint a preparation without a patch proposal")
    if manifest.models is None or manifest.environment is None:
        raise PolicyError("Cannot fingerprint a preparation without its models and environment")
    if manifest.autocontribute_version is None:
        raise PolicyError("Cannot fingerprint a preparation without the version that prepared it")
    if manifest.validation_sha256 is None:
        raise PolicyError("Cannot fingerprint a preparation without its validation evidence")
    if manifest.quality is None or not manifest.quality.ready:
        raise PolicyError("Cannot fingerprint a preparation that has not passed quality gates")

    evidence = {
        "schema_version": _FINGERPRINT_SCHEMA_VERSION,
        "run_id": manifest.run_id,
        "candidate": manifest.candidate.model_dump(mode="json"),
        "eligibility": (
            manifest.eligibility.model_dump(mode="json") if manifest.eligibility else None
        ),
        "repository": manifest.repository.model_dump(mode="json"),
        "base_sha": manifest.base_sha,
        "models": manifest.models.model_dump(mode="json"),
        "autocontribute_version": manifest.autocontribute_version,
        "environment": manifest.environment.model_dump(mode="json"),
        "proposal": manifest.proposal.model_dump(mode="json"),
        "validation_sha256": manifest.validation_sha256,
        "quality": manifest.quality.model_dump(mode="json"),
        "preparation_config_fingerprint": manifest.preparation_config_fingerprint,
    }
    canonical_evidence = json.dumps(
        evidence,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    patch = diff.encode("utf-8") if isinstance(diff, str) else diff

    digest = hashlib.sha256(_FINGERPRINT_DOMAIN)
    _add_frame(digest, b"diff", patch)
    _add_frame(digest, b"evidence", canonical_evidence)
    return digest.hexdigest()


def validate_preparation_fingerprint(
    manifest: RunManifest,
    *,
    diff: str | bytes,
) -> None:
    """Fail closed unless the patch and preparation evidence match the ready seal."""

    recorded = manifest.preparation_fingerprint
    if recorded is None:
        raise PolicyError("Run is missing its preparation fingerprint")
    expected = compute_preparation_fingerprint(manifest, diff=diff)
    if not hmac.compare_digest(recorded, expected):
        raise PolicyError("Preparation fingerprint does not match the exact validated patch")


def compute_preparation_config_fingerprint(
    config: AutocontributeConfig,
    *,
    repository: str,
    models: RunModels,
) -> str:
    """Seal the operator settings that made one repository preparation acceptable.

    ``models`` are the run's models after ``auto`` was resolved: the jobs that approve and
    publish have no model key to resolve them again.
    """

    override = config.environment_for(repository)
    payload = {
        "schema_version": _CONFIG_FINGERPRINT_SCHEMA_VERSION,
        "repository": repository.casefold(),
        "environment": None if override is None else override.model_dump(mode="json"),
        "models": models.model_dump(mode="json"),
        "sandbox": config.sandbox.model_dump(mode="json"),
        "quality": config.quality.model_dump(mode="json"),
        "policy": config.policy.model_dump(mode="json"),
        "publishing": config.publishing.model_dump(mode="json"),
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(_CONFIG_FINGERPRINT_DOMAIN + canonical).hexdigest()


def validate_preparation_config_fingerprint(
    manifest: RunManifest,
    config: AutocontributeConfig,
) -> None:
    """Require the target to remain allowed and its preparation gates to remain exact."""

    if manifest.candidate is None or manifest.repository is None:
        raise PolicyError("Run is missing repository evidence for configuration validation")
    candidate_repository = manifest.candidate.repository
    if candidate_repository.casefold() != manifest.repository.full_name.casefold():
        raise PolicyError("Run contains inconsistent repository identities")
    normalized = candidate_repository.casefold()
    configured_repositories = {repository.casefold() for repository in config.github.repositories}
    configured_owners = {owner.casefold() for owner in config.github.owners}
    owner = normalized.split("/", 1)[0]
    if normalized not in configured_repositories and owner not in configured_owners:
        raise PolicyError(
            f"Repository {candidate_repository} is no longer in the configured allowlist"
        )
    recorded = manifest.preparation_config_fingerprint
    if recorded is None or manifest.models is None:
        raise PolicyError("Run is missing its preparation configuration fingerprint")
    expected = compute_preparation_config_fingerprint(
        config,
        repository=candidate_repository,
        models=manifest.models,
    )
    if not hmac.compare_digest(recorded, expected):
        raise PolicyError(
            "Environment, sandbox, quality, policy, or publishing configuration changed after "
            "preparation"
        )


def validate_validation_artifact(
    manifest: RunManifest,
    *,
    artifact: bytes,
) -> None:
    """Require ``validation.json`` to be the evidence the run recorded when it became ready."""

    recorded = manifest.validation_sha256
    if recorded is None:
        raise PolicyError("Run is missing the digest of its validation evidence")
    if not hmac.compare_digest(recorded, hashlib.sha256(artifact).hexdigest()):
        raise PolicyError("Validation artifact does not match the run's validation evidence")


def _add_frame(digest: _Digest, label: bytes, payload: bytes) -> None:
    digest.update(len(label).to_bytes(8, "big"))
    digest.update(label)
    digest.update(len(payload).to_bytes(8, "big"))
    digest.update(payload)


__all__ = [
    "compute_preparation_config_fingerprint",
    "compute_preparation_fingerprint",
    "validate_preparation_config_fingerprint",
    "validate_preparation_fingerprint",
    "validate_validation_artifact",
]
