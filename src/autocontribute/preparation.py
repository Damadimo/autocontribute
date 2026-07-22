"""Durable fingerprints for the exact preparation that passed quality gates."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import NoReturn, Protocol

from autocontribute.config import AutocontributeConfig
from autocontribute.domain import RunManifest
from autocontribute.exceptions import PolicyError

_FINGERPRINT_DOMAIN = b"autocontribute.preparation.v2\x00"
_FINGERPRINT_SCHEMA_VERSION = 2
_CONFIG_FINGERPRINT_DOMAIN = b"autocontribute.preparation-config.v2\x00"
_CONFIG_FINGERPRINT_SCHEMA_VERSION = 2


class _Digest(Protocol):
    def update(self, data: bytes, /) -> None: ...


def compute_preparation_fingerprint(
    manifest: RunManifest,
    *,
    diff: str | bytes,
) -> str:
    """Hash the exact patch bytes and stable evidence that authorized readiness.

    Mutable lifecycle fields are deliberately excluded. The length-prefixed
    framing keeps the patch and canonical evidence payload unambiguous.
    """

    if manifest.candidate is None:
        raise PolicyError("Cannot fingerprint a preparation without an issue candidate")
    if manifest.repository is None:
        raise PolicyError("Cannot fingerprint a preparation without repository metadata")
    if manifest.base_sha is None:
        raise PolicyError("Cannot fingerprint a preparation without a pinned base SHA")
    if manifest.proposal is None:
        raise PolicyError("Cannot fingerprint a preparation without a patch proposal")
    if not manifest.patched_validation:
        raise PolicyError("Cannot fingerprint a preparation without patched validation evidence")
    if not all(result.passed for result in manifest.patched_validation):
        raise PolicyError("Cannot fingerprint a preparation with failed patched validation")
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
        "plan": manifest.plan.model_dump(mode="json") if manifest.plan else None,
        "proposal": manifest.proposal.model_dump(mode="json"),
        "baseline_validation": (
            manifest.baseline_validation.model_dump(mode="json")
            if manifest.baseline_validation
            else None
        ),
        "patched_validation": [
            result.model_dump(mode="json") for result in manifest.patched_validation
        ],
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
) -> str:
    """Seal the operator-owned gates that made one repository preparation acceptable."""

    commands = config.validation.commands_for(repository)
    if not commands:
        raise PolicyError(
            f"Repository has no operator-owned validation.required_commands entry: {repository}"
        )
    payload = {
        "schema_version": _CONFIG_FINGERPRINT_SCHEMA_VERSION,
        "repository": repository.casefold(),
        "required_commands": commands,
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
    if recorded is None:
        raise PolicyError("Run is missing its preparation configuration fingerprint")
    expected = compute_preparation_config_fingerprint(
        config,
        repository=candidate_repository,
    )
    if not hmac.compare_digest(recorded, expected):
        raise PolicyError(
            "Validation, quality, policy, sandbox, or publishing configuration changed "
            "after preparation"
        )


def render_validation_artifact(manifest: RunManifest) -> str:
    """Render the review sidecar from the validation evidence anchored in run state."""

    return json.dumps(_validation_evidence(manifest), indent=2, sort_keys=True) + "\n"


def validate_validation_artifact(
    manifest: RunManifest,
    *,
    artifact: str | bytes,
) -> None:
    """Require the validation sidecar to exactly represent durable run evidence."""

    try:
        encoded = artifact.encode("utf-8") if isinstance(artifact, str) else artifact
        parsed: object = json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
        actual = json.dumps(
            parsed,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (UnicodeDecodeError, ValueError) as exc:
        raise PolicyError("Validation artifact is not strict UTF-8 JSON") from exc
    expected = json.dumps(
        _validation_evidence(manifest),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    if not hmac.compare_digest(actual, expected):
        raise PolicyError("Validation artifact does not match durable command evidence")


def _validation_evidence(manifest: RunManifest) -> dict[str, object]:
    return {
        "baseline": (
            manifest.baseline_validation.model_dump(mode="json")
            if manifest.baseline_validation
            else None
        ),
        "patched": [result.model_dump(mode="json") for result in manifest.patched_validation],
    }


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> NoReturn:
    raise ValueError(f"invalid JSON constant: {value}")


def _add_frame(digest: _Digest, label: bytes, payload: bytes) -> None:
    digest.update(len(label).to_bytes(8, "big"))
    digest.update(label)
    digest.update(len(payload).to_bytes(8, "big"))
    digest.update(payload)


__all__ = [
    "compute_preparation_config_fingerprint",
    "compute_preparation_fingerprint",
    "render_validation_artifact",
    "validate_preparation_config_fingerprint",
    "validate_preparation_fingerprint",
    "validate_validation_artifact",
]
