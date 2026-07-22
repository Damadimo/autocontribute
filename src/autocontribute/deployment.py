"""Deployment identity for evidence-backed autonomous rollout cohorts."""

from __future__ import annotations

import hashlib
import hmac
import json
import platform
import re
import sys
from importlib.metadata import PackageNotFoundError, distribution, version
from pathlib import Path
from typing import Final, Protocol

from packaging.requirements import InvalidRequirement, Requirement

from autocontribute.config import AutocontributeConfig
from autocontribute.exceptions import PolicyError

_DEPLOYMENT_DOMAIN: Final = b"autocontribute.deployment.v1\x00"
_SOURCE_DOMAIN: Final = b"autocontribute.package-source.v1\x00"
_RUNTIME_DOMAIN: Final = b"autocontribute.runtime-environment.v1\x00"
_BUILD_IDENTITY_DOMAIN: Final = b"autocontribute.build-identity.v1\x00"
_BUILD_IDENTITY_FILE: Final = "_build_identity.json"
_MAX_SOURCE_FILES: Final = 1_000
_MAX_SOURCE_FILE_BYTES: Final = 5_000_000
_MAX_SOURCE_BYTES: Final = 50_000_000
_MAX_BUILD_IDENTITY_BYTES: Final = 4_096
_MAX_RUNTIME_DISTRIBUTIONS: Final = 10_000
_SHA256: Final = re.compile(r"^[0-9a-f]{64}$")
_RUNTIME_ROOT_DISTRIBUTIONS: Final = (
    "autocontribute",
    "httpx",
    "openai",
    "packaging",
    "pydantic",
    "PyYAML",
    "rich",
    "typer",
)


class _Digest(Protocol):
    def update(self, data: bytes, /) -> None: ...


def package_source_digest(package_root: Path | None = None) -> str:
    """Hash every runtime Python source file with deterministic path framing."""

    requested_root = package_root or Path(__file__).parent
    if requested_root.is_symlink():
        raise PolicyError("Autocontribute package source root is missing or unsafe")
    root = requested_root.resolve()
    if not root.is_dir():
        raise PolicyError("Autocontribute package source root is missing or unsafe")
    paths = sorted(root.rglob("*.py"), key=lambda path: path.relative_to(root).as_posix())
    if not paths or len(paths) > _MAX_SOURCE_FILES:
        raise PolicyError("Autocontribute package source inventory is invalid or unbounded")
    digest = hashlib.sha256(_SOURCE_DOMAIN)
    aggregate = 0
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise PolicyError("Autocontribute package source contains an unsafe file")
        data = path.read_bytes()
        if len(data) > _MAX_SOURCE_FILE_BYTES:
            raise PolicyError("Autocontribute package source file exceeds the safe digest limit")
        aggregate += len(data)
        if aggregate > _MAX_SOURCE_BYTES:
            raise PolicyError("Autocontribute package source exceeds the safe digest limit")
        relative = path.relative_to(root).as_posix().encode("utf-8")
        _frame(digest, relative)
        _frame(digest, data)
    return digest.hexdigest()


def runtime_environment_digest() -> str:
    """Hash Python, the installed runtime closure, and packaged build/lock identity."""

    pending = list(_RUNTIME_ROOT_DISTRIBUTIONS)
    dependency_versions: dict[str, str] = {}
    inspected: set[str] = set()
    while pending:
        requested = pending.pop()
        normalized = _normalized_distribution_name(requested)
        if normalized in inspected:
            continue
        inspected.add(normalized)
        if len(inspected) > _MAX_RUNTIME_DISTRIBUTIONS:
            raise PolicyError("Runtime dependency inventory is unbounded")
        try:
            installed = distribution(requested)
        except PackageNotFoundError:
            if normalized == "autocontribute":
                dependency_versions[normalized] = "uninstalled"
                continue
            # Conditional requirements for another platform can appear in metadata without being
            # installed. Direct runtime roots, however, must always be present.
            if requested in _RUNTIME_ROOT_DISTRIBUTIONS:
                raise PolicyError(f"Runtime dependency metadata is missing: {requested}") from None
            continue
        canonical_name = installed.metadata["Name"] or requested
        canonical_distribution = _normalized_distribution_name(canonical_name)
        dependency_versions[canonical_distribution] = installed.version
        for requirement_text in installed.requires or ():
            try:
                requirement = Requirement(requirement_text)
            except InvalidRequirement as exc:
                raise PolicyError(
                    f"Runtime dependency metadata is invalid: {canonical_name}"
                ) from exc
            if requirement.marker is not None and not requirement.marker.evaluate({"extra": ""}):
                continue
            pending.append(requirement.name)

    payload = {
        "schema_version": 2,
        "python": {
            "build": sys.version,
            "byte_order": sys.byteorder,
            "implementation": platform.python_implementation(),
            "implementation_name": sys.implementation.name,
            "cache_tag": sys.implementation.cache_tag,
            "machine": platform.machine(),
            "sys_platform": sys.platform,
            "version": platform.python_version(),
        },
        "dependencies": dependency_versions,
        "packaged_build_identity_sha256": packaged_build_identity_digest(),
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(_RUNTIME_DOMAIN + encoded).hexdigest()


def compute_deployment_fingerprint(
    config: AutocontributeConfig,
    *,
    source_digest: str | None = None,
    runtime_digest: str | None = None,
) -> str:
    """Bind a rollout cohort to code, models, and every material operating gate."""

    digest = source_digest or package_source_digest()
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise PolicyError("Deployment source digest must be a lowercase SHA-256 value")
    environment_digest = runtime_digest or runtime_environment_digest()
    if len(environment_digest) != 64 or any(
        character not in "0123456789abcdef" for character in environment_digest
    ):
        raise PolicyError("Deployment runtime digest must be a lowercase SHA-256 value")

    models = config.models.model_dump(mode="json")
    for profile in models.values():
        if isinstance(profile, dict):
            # Credential locations are deployment plumbing, not model behavior, and the values
            # themselves never enter configuration models.
            profile.pop("api_key_env", None)

    github = config.github.model_dump(mode="json")
    github.pop("token_env", None)
    github.pop("auth", None)

    publishing = config.publishing.model_dump(mode="json")
    # The exact same calibrated deployment must be able to move from review-only to the guarded
    # auto mode. Kill-switch variable names likewise do not change contribution quality.
    publishing.pop("mode", None)
    publishing.pop("auto_publish_env", None)

    try:
        package_version = version("autocontribute")
    except PackageNotFoundError:  # pragma: no cover - source tree without package metadata
        package_version = "uninstalled"
    payload = {
        "schema_version": 1,
        "package_source_sha256": digest,
        "runtime_environment_sha256": environment_digest,
        "package_version": package_version,
        "models": models,
        "budget": config.budget.model_dump(mode="json"),
        "discovery": github,
        "sandbox": config.sandbox.model_dump(mode="json"),
        "validation": config.validation.model_dump(mode="json"),
        "policy": config.policy.model_dump(mode="json"),
        "quality": config.quality.model_dump(mode="json"),
        "publishing_safety": publishing,
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(_DEPLOYMENT_DOMAIN + canonical).hexdigest()


def validate_deployment_fingerprint(
    recorded: str | None,
    config: AutocontributeConfig,
) -> str:
    """Fail closed when a run belongs to another code/model/config deployment."""

    if recorded is None:
        raise PolicyError("Run is missing its deployment fingerprint")
    expected = compute_deployment_fingerprint(config)
    if not hmac.compare_digest(recorded, expected):
        raise PolicyError("Run belongs to a different code, model, or policy deployment")
    return expected


def _frame(digest: _Digest, value: bytes) -> None:
    digest.update(len(value).to_bytes(8, "big"))
    digest.update(value)


def _normalized_distribution_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).casefold()


def packaged_build_identity_digest(manifest_path: Path | None = None) -> str:
    """Hash the required build manifest shipped identically in source and wheel installs."""

    path = manifest_path or Path(__file__).with_name(_BUILD_IDENTITY_FILE)
    if path.is_symlink() or not path.is_file():
        raise PolicyError("Packaged build identity manifest is missing or unsafe")
    data = path.read_bytes()
    if not data or len(data) > _MAX_BUILD_IDENTITY_BYTES:
        raise PolicyError("Packaged build identity manifest has an invalid size")
    try:
        payload = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PolicyError("Packaged build identity manifest is invalid") from exc
    required_keys = {
        "project",
        "pyproject_sha256",
        "schema_version",
        "uv_lock_sha256",
    }
    if not isinstance(payload, dict) or set(payload) != required_keys:
        raise PolicyError("Packaged build identity manifest has an invalid schema")
    if payload["schema_version"] != 1 or payload["project"] != "autocontribute":
        raise PolicyError("Packaged build identity manifest has an invalid schema")
    for field in ("pyproject_sha256", "uv_lock_sha256"):
        value = payload[field]
        if not isinstance(value, str) or not _SHA256.fullmatch(value):
            raise PolicyError("Packaged build identity manifest has an invalid digest")
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(_BUILD_IDENTITY_DOMAIN + canonical).hexdigest()


__all__ = [
    "compute_deployment_fingerprint",
    "package_source_digest",
    "packaged_build_identity_digest",
    "runtime_environment_digest",
    "validate_deployment_fingerprint",
]
