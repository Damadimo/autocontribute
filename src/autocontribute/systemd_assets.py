"""Release-bound verification for the operator-managed systemd deployment assets."""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from autocontribute.exceptions import PolicyError

_MANIFEST_FILE: Final = "_systemd_assets.json"
_MANIFEST_DOMAIN: Final = b"autocontribute.systemd-assets.v1\x00"
_MAX_MANIFEST_BYTES: Final = 64 * 1024
_MAX_ASSET_BYTES: Final = 2 * 1024 * 1024
_MAX_AGGREGATE_BYTES: Final = 16 * 1024 * 1024
_SHA256: Final = frozenset("0123456789abcdef")
_PRODUCTION_RELEASES_ROOT: Final = Path("/opt/autocontribute/releases")
_SERVICE_ACCOUNT: Final = "autocontribute"
_SERVICE_UID_TOKEN: Final = "{autocontribute_uid}"


@dataclass(frozen=True, slots=True)
class _ExpectedAsset:
    installed_path: str | None
    mode: str
    required: bool


# This inventory is deliberately duplicated in executable code. A damaged or edited manifest cannot
# silently omit a safety helper or redirect verification to another host path.
_EXPECTED_ASSETS: Final[dict[str, _ExpectedAsset]] = {
    "deploy/systemd/autocontribute-backup.service": _ExpectedAsset(
        "/etc/systemd/system/autocontribute-backup.service", "0644", True
    ),
    "deploy/systemd/autocontribute-backup.timer": _ExpectedAsset(
        "/etc/systemd/system/autocontribute-backup.timer", "0644", True
    ),
    "deploy/systemd/autocontribute-doctor.service": _ExpectedAsset(
        "/etc/systemd/system/autocontribute-doctor.service", "0644", True
    ),
    "deploy/systemd/autocontribute-failure@.service": _ExpectedAsset(
        "/etc/systemd/system/autocontribute-failure@.service", "0644", True
    ),
    "deploy/systemd/autocontribute-health.service": _ExpectedAsset(
        "/etc/systemd/system/autocontribute-health.service", "0644", True
    ),
    "deploy/systemd/autocontribute-health.timer": _ExpectedAsset(
        "/etc/systemd/system/autocontribute-health.timer", "0644", True
    ),
    "deploy/systemd/autocontribute-rootless-docker.service": _ExpectedAsset(
        "/etc/systemd/system/autocontribute-rootless-docker.service", "0644", True
    ),
    "deploy/systemd/autocontribute-worker.service": _ExpectedAsset(
        "/etc/systemd/system/autocontribute-worker.service", "0644", True
    ),
    "deploy/systemd/autocontribute-worker.timer": _ExpectedAsset(
        "/etc/systemd/system/autocontribute-worker.timer", "0644", True
    ),
    # This reviewed template is bound to the release but remains optional because journald policy is
    # host-wide and may need an operator-specific configuration instead.
    "deploy/systemd/autocontribute.journald.conf.example": _ExpectedAsset(None, "0644", False),
    "deploy/systemd/autocontribute.tmpfiles.conf": _ExpectedAsset(
        "/etc/tmpfiles.d/autocontribute.conf", "0644", True
    ),
    "deploy/systemd/autocontribute-user-manager.conf": _ExpectedAsset(
        "/etc/systemd/system/user@{autocontribute_uid}.service.d/50-autocontribute.conf",
        "0644",
        True,
    ),
    "deploy/systemd/libexec/autocontribute-backup": _ExpectedAsset(
        "/usr/local/libexec/autocontribute-backup", "0755", True
    ),
    "deploy/systemd/libexec/autocontribute-docker-data-check": _ExpectedAsset(
        "/usr/local/libexec/autocontribute-docker-data-check", "0755", True
    ),
    "deploy/systemd/libexec/autocontribute-healthcheck": _ExpectedAsset(
        "/usr/local/libexec/autocontribute-healthcheck", "0755", True
    ),
    "deploy/systemd/libexec/autocontribute-record-failure": _ExpectedAsset(
        "/usr/local/libexec/autocontribute-record-failure", "0755", True
    ),
    "deploy/systemd/libexec/autocontribute-rootless-docker": _ExpectedAsset(
        "/usr/local/libexec/autocontribute-rootless-docker", "0755", True
    ),
    "deploy/systemd/libexec/autocontribute-rootless-docker-check": _ExpectedAsset(
        "/usr/local/libexec/autocontribute-rootless-docker-check", "0755", True
    ),
    "deploy/systemd/libexec/autocontribute-rootless-dockerd": _ExpectedAsset(
        "/usr/local/libexec/autocontribute-rootless-dockerd", "0755", True
    ),
    "deploy/systemd/libexec/autocontribute-storage-capacity-check": _ExpectedAsset(
        "/usr/local/libexec/autocontribute-storage-capacity-check", "0755", True
    ),
    "deploy/systemd/libexec/autocontribute-worker": _ExpectedAsset(
        "/usr/local/libexec/autocontribute-worker", "0755", True
    ),
    "deploy/systemd/libexec/autocontribute-workspace-quota-check": _ExpectedAsset(
        "/usr/local/libexec/autocontribute-workspace-quota-check", "0755", True
    ),
    "deploy/systemd/user/autocontribute-rootless-docker-daemon.service": _ExpectedAsset(
        "/etc/systemd/user/autocontribute-rootless-docker-daemon.service", "0644", True
    ),
}

_RETIRED_ROOTLESS_DOCKER_PATHS: Final = (
    "/etc/systemd/system/user@.service.d/50-autocontribute.conf",
    "/etc/systemd/system/user@.service.d/delegate.conf",
    "/etc/systemd/user/docker.service",
    "/etc/systemd/user/docker.service.d",
    "/var/lib/autocontribute/.config/systemd/user/docker.service",
    "/var/lib/autocontribute/.config/systemd/user/docker.service.d",
    "/var/lib/autocontribute/.config/systemd/user/autocontribute-rootless-docker-daemon.service",
    "/var/lib/autocontribute/.config/systemd/user/autocontribute-rootless-docker-daemon.service.d",
    "/var/lib/autocontribute/.local/share/systemd/user/autocontribute-rootless-docker-daemon.service",
    "/var/lib/autocontribute/.local/share/systemd/user/autocontribute-rootless-docker-daemon.service.d",
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SystemdAsset(_StrictModel):
    """One exact source asset and its production installation contract."""

    source_path: str = Field(min_length=1, max_length=256, strict=True)
    installed_path: str | None = Field(default=None, max_length=256, strict=True)
    sha256: str = Field(min_length=64, max_length=64, strict=True)
    mode: str = Field(min_length=4, max_length=4, strict=True)
    required: bool = Field(strict=True)

    @field_validator("source_path")
    @classmethod
    def source_path_is_canonical(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            value != path.as_posix()
            or path.is_absolute()
            or path.parts[:2] != ("deploy", "systemd")
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ValueError("systemd asset source paths must be canonical deploy/systemd paths")
        return value

    @field_validator("installed_path")
    @classmethod
    def installed_path_is_canonical(cls, value: str | None) -> str | None:
        if value is None:
            return None
        path = PurePosixPath(value)
        if (
            value != path.as_posix()
            or not path.is_absolute()
            or value == "/"
            or any(part in {"", ".", ".."} for part in path.parts[1:])
        ):
            raise ValueError("systemd asset installed paths must be canonical absolute paths")
        return value

    @field_validator("sha256")
    @classmethod
    def digest_is_lowercase_sha256(cls, value: str) -> str:
        if len(value) != 64 or any(character not in _SHA256 for character in value):
            raise ValueError("systemd asset digests must be lowercase SHA-256 values")
        return value

    @field_validator("mode")
    @classmethod
    def mode_is_bounded_octal(cls, value: str) -> str:
        if (
            len(value) != 4
            or value[0] != "0"
            or any(character not in "01234567" for character in value)
        ):
            raise ValueError("systemd asset modes must be four-digit octal strings")
        return value


class SystemdAssetManifest(_StrictModel):
    """The complete release-to-host deployment asset binding."""

    project: Literal["autocontribute"]
    schema_version: int = Field(strict=True, ge=1, le=1)
    assets: tuple[SystemdAsset, ...] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def inventory_matches_executable_contract(self) -> SystemdAssetManifest:
        source_paths = [asset.source_path for asset in self.assets]
        if source_paths != sorted(source_paths) or len(source_paths) != len(set(source_paths)):
            raise ValueError("systemd asset manifest paths must be unique and sorted")
        if set(source_paths) != set(_EXPECTED_ASSETS):
            raise ValueError("systemd asset manifest inventory differs from executable policy")
        installed_paths = [asset.installed_path for asset in self.assets if asset.installed_path]
        if len(installed_paths) != len(set(installed_paths)):
            raise ValueError("systemd asset installed paths must be unique")
        for asset in self.assets:
            expected = _EXPECTED_ASSETS[asset.source_path]
            if (
                asset.installed_path != expected.installed_path
                or asset.mode != expected.mode
                or asset.required is not expected.required
            ):
                raise ValueError(
                    f"systemd asset installation contract differs for {asset.source_path}"
                )
        return self


@dataclass(frozen=True, slots=True)
class SystemdAssetVerification:
    """A successful verification summary safe to render in CLI and doctor output."""

    scope: Literal["source", "installed"]
    manifest_sha256: str
    checked_assets: int
    required_assets: int
    source_only_assets: int


@dataclass(frozen=True, slots=True)
class _LoadedManifest:
    manifest: SystemdAssetManifest
    data: bytes
    digest: str
    path: Path


def load_systemd_asset_manifest(path: Path | None = None) -> SystemdAssetManifest:
    """Load and fully validate the packaged deployment-asset manifest."""

    return _load_manifest(path).manifest


def packaged_systemd_asset_manifest_digest(path: Path | None = None) -> str:
    """Hash the exact validated manifest shipped with the selected Python release."""

    return _load_manifest(path).digest


def _resolve_service_uid(service_uid: int | None) -> int:
    if service_uid is None:
        try:
            resolved = pwd.getpwnam(_SERVICE_ACCOUNT).pw_uid
        except (KeyError, OSError) as exc:
            raise PolicyError(
                "Autocontribute service account is unavailable for systemd asset verification"
            ) from exc
    else:
        if isinstance(service_uid, bool) or not isinstance(service_uid, int):
            raise ValueError("systemd asset service UID must be an integer")
        resolved = service_uid
    if resolved <= 0 or resolved > 2**32 - 2:
        if service_uid is None:
            raise PolicyError("Autocontribute service account has an invalid UID")
        raise ValueError("systemd asset service UID must be a positive Linux UID")
    return resolved


def _resolved_installed_path(installed_path: str, service_uid: int) -> PurePosixPath:
    rendered = installed_path.replace(_SERVICE_UID_TOKEN, str(service_uid))
    if _SERVICE_UID_TOKEN in rendered or "{" in rendered or "}" in rendered:
        raise PolicyError("Systemd asset installed path contains an unresolved host token")
    return PurePosixPath(rendered)


def verify_source_systemd_assets(
    source_root: Path,
    *,
    manifest_path: Path | None = None,
) -> SystemdAssetVerification:
    """Verify a release checkout before any privileged deployment files are installed."""

    loaded = _load_manifest(manifest_path)
    root = _canonical_directory(source_root, label="systemd asset source root")
    source_manifest = root / "src" / "autocontribute" / _MANIFEST_FILE
    source_manifest_data, _ = _read_regular_file(
        source_manifest,
        label="source systemd asset manifest",
        maximum_bytes=_MAX_MANIFEST_BYTES,
    )
    if source_manifest_data != loaded.data:
        raise PolicyError("Source systemd asset manifest differs from the selected Python release")

    deployment_root = root / "deploy" / "systemd"
    if deployment_root.is_symlink() or not deployment_root.is_dir():
        raise PolicyError("Systemd deployment source directory is missing or unsafe")
    actual_paths: set[str] = set()
    for candidate in deployment_root.rglob("*"):
        if candidate.is_symlink():
            raise PolicyError("Systemd deployment source contains a symbolic link")
        if candidate.is_dir():
            continue
        if not candidate.is_file():
            raise PolicyError("Systemd deployment source contains a non-regular file")
        actual_paths.add(candidate.relative_to(root).as_posix())
    expected_paths = {asset.source_path for asset in loaded.manifest.assets}
    if actual_paths != expected_paths:
        missing = sorted(expected_paths - actual_paths)
        unexpected = sorted(actual_paths - expected_paths)
        detail = "; ".join(
            part
            for part in (
                f"missing: {', '.join(missing)}" if missing else "",
                f"unexpected: {', '.join(unexpected)}" if unexpected else "",
            )
            if part
        )
        raise PolicyError(f"Systemd deployment source inventory differs from manifest ({detail})")

    aggregate = 0
    for asset in loaded.manifest.assets:
        path = root.joinpath(*PurePosixPath(asset.source_path).parts)
        data, metadata = _read_regular_file(
            path,
            label=f"systemd source asset {asset.source_path}",
            maximum_bytes=_MAX_ASSET_BYTES,
        )
        aggregate = _checked_aggregate(aggregate, len(data))
        _verify_mode(metadata, asset)
        _verify_digest(data, asset)
    return _verification_summary("source", loaded)


def verify_installed_systemd_assets(
    *,
    manifest_path: Path | None = None,
    installed_root: Path = Path("/"),
    expected_uid: int = 0,
    expected_gid: int = 0,
    service_uid: int | None = None,
) -> SystemdAssetVerification:
    """Verify every required production asset at its exact root-owned host path."""

    if expected_uid < 0 or expected_gid < 0:
        raise ValueError("expected systemd asset ownership must be non-negative")
    resolved_service_uid = _resolve_service_uid(service_uid)
    loaded = _load_manifest(manifest_path)
    if manifest_path is None:
        _verify_packaged_manifest_trust(loaded.path)
    root = _canonical_directory(installed_root, label="installed filesystem root")
    _verify_installed_inventory(
        root,
        loaded.manifest,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        service_uid=resolved_service_uid,
    )
    _verify_retired_rootless_docker_paths(root)
    _verify_no_stale_manager_dropins(root, resolved_service_uid)
    aggregate = 0
    checked = 0
    for asset in loaded.manifest.assets:
        if asset.installed_path is None:
            continue
        installed_path = _resolved_installed_path(asset.installed_path, resolved_service_uid)
        path = root.joinpath(*installed_path.parts[1:])
        if not asset.required and not path.exists():
            continue
        data, metadata = _read_regular_file(
            path,
            label=f"installed systemd asset {asset.installed_path}",
            maximum_bytes=_MAX_ASSET_BYTES,
        )
        aggregate = _checked_aggregate(aggregate, len(data))
        if metadata.st_uid != expected_uid or metadata.st_gid != expected_gid:
            raise PolicyError(
                f"Installed systemd asset has unsafe ownership: {asset.installed_path}"
            )
        _verify_mode(metadata, asset)
        _verify_digest(data, asset)
        checked += 1
    required = sum(asset.required for asset in loaded.manifest.assets)
    if checked < required:
        raise PolicyError("Installed systemd asset verification omitted a required file")
    _verify_installed_inventory(
        root,
        loaded.manifest,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        service_uid=resolved_service_uid,
    )
    _verify_retired_rootless_docker_paths(root)
    _verify_no_stale_manager_dropins(root, resolved_service_uid)
    return SystemdAssetVerification(
        scope="installed",
        manifest_sha256=loaded.digest,
        checked_assets=checked,
        required_assets=required,
        source_only_assets=sum(asset.installed_path is None for asset in loaded.manifest.assets),
    )


def _load_manifest(path: Path | None) -> _LoadedManifest:
    manifest_path = path or Path(__file__).with_name(_MANIFEST_FILE)
    data, _ = _read_regular_file(
        manifest_path,
        label="packaged systemd asset manifest",
        maximum_bytes=_MAX_MANIFEST_BYTES,
        require_exact_path=False,
    )
    try:
        raw = json.loads(data, object_pairs_hook=_unique_json_object)
        manifest = SystemdAssetManifest.model_validate(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise PolicyError("Packaged systemd asset manifest is invalid") from exc
    digest = hashlib.sha256(_MANIFEST_DOMAIN + data).hexdigest()
    try:
        resolved_path = manifest_path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PolicyError("Packaged systemd asset manifest is unavailable") from exc
    return _LoadedManifest(manifest=manifest, data=data, digest=digest, path=resolved_path)


def _canonical_directory(path: Path, *, label: str) -> Path:
    try:
        requested = path.expanduser()
    except (OSError, RuntimeError) as exc:
        raise PolicyError(f"{label.capitalize()} is unavailable") from exc
    if requested.is_symlink():
        raise PolicyError(f"{label.capitalize()} is a symbolic link")
    try:
        resolved = requested.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PolicyError(f"{label.capitalize()} is unavailable") from exc
    if not resolved.is_dir():
        raise PolicyError(f"{label.capitalize()} is not a directory")
    return resolved


def _read_regular_file(
    path: Path,
    *,
    label: str,
    maximum_bytes: int,
    require_exact_path: bool = True,
) -> tuple[bytes, os.stat_result]:
    descriptor = -1
    try:
        if path.is_symlink():
            raise PolicyError(f"{label.capitalize()} is a symbolic link")
        resolved = path.resolve(strict=True)
        if require_exact_path and resolved != path.absolute():
            raise PolicyError(f"{label.capitalize()} is reachable through a path alias")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise PolicyError(f"{label.capitalize()} is not a regular file")
        if metadata.st_size < 1 or metadata.st_size > maximum_bytes:
            raise PolicyError(f"{label.capitalize()} has an invalid size")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_bytes:
                raise PolicyError(f"{label.capitalize()} has an invalid size")
        data = b"".join(chunks)
        final_metadata = os.fstat(descriptor)
        path_metadata = os.stat(path, follow_symlinks=False)
    except PolicyError:
        raise
    except (OSError, RuntimeError) as exc:
        raise PolicyError(f"{label.capitalize()} is unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if (
        len(data) != metadata.st_size
        or final_metadata.st_dev != metadata.st_dev
        or final_metadata.st_ino != metadata.st_ino
        or final_metadata.st_size != metadata.st_size
        or final_metadata.st_mtime_ns != metadata.st_mtime_ns
        or final_metadata.st_ctime_ns != metadata.st_ctime_ns
        or path_metadata.st_dev != metadata.st_dev
        or path_metadata.st_ino != metadata.st_ino
    ):
        raise PolicyError(f"{label.capitalize()} changed while it was verified")
    return data, metadata


def _verify_packaged_manifest_trust(manifest_path: Path) -> None:
    opt_root = Path("/opt")
    application_root = opt_root / "autocontribute"
    try:
        for fixed_path in (opt_root, application_root, _PRODUCTION_RELEASES_ROOT):
            if fixed_path.resolve(strict=True) != fixed_path:
                raise PolicyError("Production Python release contains a path alias")
        releases_root = _PRODUCTION_RELEASES_ROOT
        relative = manifest_path.relative_to(releases_root)
    except PolicyError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise PolicyError(
            "Packaged systemd asset manifest is outside the production release root"
        ) from exc
    if len(relative.parts) < 2:
        raise PolicyError("Packaged systemd asset manifest has no immutable release directory")

    release_root = releases_root / relative.parts[0]
    protected_paths = [opt_root, application_root, releases_root, release_root]
    protected_paths.extend(
        parent
        for parent in manifest_path.parents
        if parent != release_root and release_root in parent.parents
    )
    protected_paths.append(manifest_path)
    for protected in protected_paths:
        try:
            metadata = protected.stat(follow_symlinks=False)
        except OSError as exc:
            raise PolicyError("Production Python release ownership could not be verified") from exc
        if protected.is_symlink():
            raise PolicyError("Production Python release contains a symbolic path component")
        expected_type = stat.S_ISREG if protected == manifest_path else stat.S_ISDIR
        if (
            not expected_type(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise PolicyError("Production Python release ownership or permissions are unsafe")


def _verify_installed_inventory(
    root: Path,
    manifest: SystemdAssetManifest,
    *,
    expected_uid: int,
    expected_gid: int,
    service_uid: int,
) -> None:
    expected_by_directory: dict[str, set[str]] = {}
    for asset in manifest.assets:
        if asset.installed_path is None:
            continue
        installed = _resolved_installed_path(asset.installed_path, service_uid)
        expected_by_directory.setdefault(installed.parent.as_posix(), set()).add(installed.name)

    policies: tuple[tuple[str, str], ...] = (
        ("/etc/systemd/system", "prefix"),
        (f"/etc/systemd/system/user@{service_uid}.service.d", "all"),
        ("/etc/systemd/user", "prefix"),
        ("/usr/local/libexec", "prefix"),
        ("/etc/tmpfiles.d", "prefix"),
    )
    for directory_path, match_kind in policies:
        expected_names = expected_by_directory[directory_path]
        directory = root.joinpath(*PurePosixPath(directory_path).parts[1:])
        _verify_protected_directory_ancestry(
            directory,
            root=root,
            label=f"installed asset directory {directory_path}",
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        allowed_dropins = (
            {
                f"{name}.d"
                for name in expected_names
                if name.endswith((".service", ".timer"))
                and name != "autocontribute-rootless-docker.service"
            }
            if directory_path == "/etc/systemd/system"
            else set()
        )
        try:
            entries = tuple(directory.iterdir())
        except OSError as exc:
            raise PolicyError(
                f"Installed asset directory is unavailable: {directory_path}"
            ) from exc
        for entry in entries:
            managed = match_kind == "all" or (
                entry.name.startswith("autocontribute")
                if match_kind == "prefix"
                else "autocontribute" in entry.name
            )
            if not managed or entry.name in expected_names:
                continue
            if entry.name in allowed_dropins:
                _verify_operator_dropins(
                    entry,
                    expected_uid=expected_uid,
                    expected_gid=expected_gid,
                )
                continue
            raise PolicyError(f"Unexpected or retired systemd deployment asset: {entry}")


def _verify_retired_rootless_docker_paths(root: Path) -> None:
    for retired_path in _RETIRED_ROOTLESS_DOCKER_PATHS:
        path = root.joinpath(*PurePosixPath(retired_path).parts[1:])
        try:
            present = path.is_symlink() or path.exists()
        except OSError as exc:
            raise PolicyError("Retired rootless Docker deployment path is unavailable") from exc
        if present:
            raise PolicyError(
                f"Unexpected or retired rootless Docker deployment path: {retired_path}"
            )


def _verify_no_stale_manager_dropins(root: Path, service_uid: int) -> None:
    system_directory = root / "etc" / "systemd" / "system"
    try:
        entries = tuple(system_directory.iterdir())
    except OSError as exc:
        raise PolicyError("Systemd system-unit directory is unavailable") from exc
    expected_instance = str(service_uid)
    for entry in entries:
        name = entry.name
        if not name.startswith("user@") or not name.endswith(".service.d"):
            continue
        instance = name.removeprefix("user@").removesuffix(".service.d")
        if instance == expected_instance:
            continue
        stale_dropin = entry / "50-autocontribute.conf"
        try:
            present = stale_dropin.is_symlink() or stale_dropin.exists()
        except OSError as exc:
            raise PolicyError("Stale Autocontribute user-manager path is unavailable") from exc
        if present:
            raise PolicyError(
                "Unexpected or stale Autocontribute user-manager drop-in: "
                f"/etc/systemd/system/{name}/50-autocontribute.conf"
            )


def _verify_exact_directory(path: Path, *, label: str) -> os.stat_result:
    try:
        if path.is_symlink() or path.resolve(strict=True) != path.absolute():
            raise PolicyError(f"{label.capitalize()} is a symbolic link or path alias")
        metadata = path.stat()
    except PolicyError:
        raise
    except (OSError, RuntimeError) as exc:
        raise PolicyError(f"{label.capitalize()} is unavailable") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise PolicyError(f"{label.capitalize()} is not a directory")
    return metadata


def _verify_protected_directory_ancestry(
    path: Path,
    *,
    root: Path,
    label: str,
    expected_uid: int,
    expected_gid: int,
) -> None:
    if path != root and root not in path.parents:
        raise PolicyError(f"{label.capitalize()} escapes the installed filesystem root")
    current = path
    while True:
        metadata = _verify_exact_directory(current, label=label)
        if (
            metadata.st_uid != expected_uid
            or metadata.st_gid != expected_gid
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise PolicyError(f"{label.capitalize()} has unsafe ownership or permissions")
        if current == root:
            return
        current = current.parent


def _verify_operator_dropins(path: Path, *, expected_uid: int, expected_gid: int) -> None:
    metadata = _verify_exact_directory(path, label="systemd operator drop-in directory")
    if (
        metadata.st_uid != expected_uid
        or metadata.st_gid != expected_gid
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise PolicyError("Systemd operator drop-in directory has unsafe ownership or permissions")
    try:
        entries = tuple(path.iterdir())
    except OSError as exc:
        raise PolicyError("Systemd operator drop-in directory is unavailable") from exc
    for entry in entries:
        if not entry.name.endswith(".conf"):
            raise PolicyError(f"Systemd operator drop-in has an unexpected name: {entry}")
        _, entry_metadata = _read_regular_file(
            entry,
            label="systemd operator drop-in",
            maximum_bytes=_MAX_ASSET_BYTES,
        )
        if (
            entry_metadata.st_uid != expected_uid
            or entry_metadata.st_gid != expected_gid
            or stat.S_IMODE(entry_metadata.st_mode) != 0o644
        ):
            raise PolicyError("Systemd operator drop-in has unsafe ownership or permissions")


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _verify_mode(metadata: os.stat_result, asset: SystemdAsset) -> None:
    if stat.S_IMODE(metadata.st_mode) != int(asset.mode, 8):
        location = asset.installed_path or asset.source_path
        raise PolicyError(f"Systemd asset has an unexpected mode: {location}")


def _verify_digest(data: bytes, asset: SystemdAsset) -> None:
    if hashlib.sha256(data).hexdigest() != asset.sha256:
        location = asset.installed_path or asset.source_path
        raise PolicyError(f"Systemd asset content differs from its release manifest: {location}")


def _checked_aggregate(current: int, size: int) -> int:
    aggregate = current + size
    if aggregate > _MAX_AGGREGATE_BYTES:
        raise PolicyError("Systemd deployment assets exceed the aggregate verification limit")
    return aggregate


def _verification_summary(
    scope: Literal["source", "installed"],
    loaded: _LoadedManifest,
) -> SystemdAssetVerification:
    return SystemdAssetVerification(
        scope=scope,
        manifest_sha256=loaded.digest,
        checked_assets=len(loaded.manifest.assets),
        required_assets=sum(asset.required for asset in loaded.manifest.assets),
        source_only_assets=sum(asset.installed_path is None for asset in loaded.manifest.assets),
    )


__all__ = [
    "SystemdAsset",
    "SystemdAssetManifest",
    "SystemdAssetVerification",
    "load_systemd_asset_manifest",
    "packaged_systemd_asset_manifest_digest",
    "verify_installed_systemd_assets",
    "verify_source_systemd_assets",
]
