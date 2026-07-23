import json
import os
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

import autocontribute.systemd_assets as systemd_assets
from autocontribute.exceptions import PolicyError
from autocontribute.systemd_assets import (
    SystemdAsset,
    SystemdAssetManifest,
    SystemdAssetVerification,
    load_systemd_asset_manifest,
    verify_installed_systemd_assets,
    verify_source_systemd_assets,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = PROJECT_ROOT / "src" / "autocontribute" / "_systemd_assets.json"
TEST_SERVICE_UID = 12345


def _manifest() -> SystemdAssetManifest:
    return load_systemd_asset_manifest(MANIFEST_PATH)


def _asset(manifest: SystemdAssetManifest, source_path: str) -> SystemdAsset:
    return next(asset for asset in manifest.assets if asset.source_path == source_path)


def _installed_path(
    root: Path,
    asset: SystemdAsset,
    *,
    service_uid: int = TEST_SERVICE_UID,
) -> Path:
    assert asset.installed_path is not None
    rendered = asset.installed_path.replace("{autocontribute_uid}", str(service_uid))
    assert "{" not in rendered and "}" not in rendered
    return root / rendered.removeprefix("/")


def _verify_installed(root: Path) -> SystemdAssetVerification:
    return verify_installed_systemd_assets(
        manifest_path=MANIFEST_PATH,
        installed_root=root,
        expected_uid=os.getuid(),
        expected_gid=os.getgid(),
        service_uid=TEST_SERVICE_UID,
    )


@pytest.fixture
def source_release(tmp_path: Path) -> Path:
    release = tmp_path / "release"
    packaged_manifest = release / "src" / "autocontribute" / MANIFEST_PATH.name
    packaged_manifest.parent.mkdir(parents=True)
    shutil.copy2(MANIFEST_PATH, packaged_manifest)
    for asset in _manifest().assets:
        destination = release / asset.source_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(PROJECT_ROOT / asset.source_path, destination)
    return release


@pytest.fixture
def installed_root(tmp_path: Path) -> Path:
    root = tmp_path / "host"
    root.mkdir()
    for asset in _manifest().assets:
        if asset.installed_path is None:
            continue
        destination = _installed_path(root, asset)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(PROJECT_ROOT / asset.source_path, destination)
        destination.chmod(int(asset.mode, 8))
    return root


def test_manifest_and_project_source_have_complete_verified_inventory() -> None:
    manifest = _manifest()

    assert len(manifest.assets) == 26
    assert sum(asset.required for asset in manifest.assets) == 25

    result = verify_source_systemd_assets(PROJECT_ROOT, manifest_path=MANIFEST_PATH)

    assert result.scope == "source"
    assert result.checked_assets == 26
    assert result.required_assets == 25
    assert result.source_only_assets == 1


def test_installed_release_verifies_with_explicit_identity(installed_root: Path) -> None:
    result = _verify_installed(installed_root)

    assert result.scope == "installed"
    assert result.checked_assets == 25
    assert result.required_assets == 25
    assert result.source_only_assets == 1


def test_manager_policy_is_installed_only_for_the_resolved_service_uid(
    installed_root: Path,
) -> None:
    manager_policy = _asset(
        _manifest(),
        "deploy/systemd/autocontribute-user-manager.conf",
    )

    assert manager_policy.installed_path == (
        "/etc/systemd/system/user@{autocontribute_uid}.service.d/50-autocontribute.conf"
    )
    assert _installed_path(installed_root, manager_policy) == (
        installed_root
        / "etc"
        / "systemd"
        / "system"
        / f"user@{TEST_SERVICE_UID}.service.d"
        / "50-autocontribute.conf"
    )
    assert not (
        installed_root / "etc" / "systemd" / "system" / "user@.service.d" / "50-autocontribute.conf"
    ).exists()


@pytest.mark.parametrize(
    ("source_path", "installed_path", "mode"),
    [
        (
            "deploy/systemd/autocontribute-replication.service",
            "/etc/systemd/system/autocontribute-replication.service",
            "0644",
        ),
        (
            "deploy/systemd/autocontribute-replication.timer",
            "/etc/systemd/system/autocontribute-replication.timer",
            "0644",
        ),
        (
            "deploy/systemd/libexec/autocontribute-replication",
            "/usr/local/libexec/autocontribute-replication",
            "0755",
        ),
    ],
)
def test_replication_assets_are_required_release_bound_files(
    source_path: str,
    installed_path: str,
    mode: str,
) -> None:
    asset = _asset(_manifest(), source_path)

    assert asset.installed_path == installed_path
    assert asset.mode == mode
    assert asset.required


def test_installed_release_resolves_the_production_service_account_uid(
    installed_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    account_names: list[str] = []

    def resolve_account(account_name: str) -> SimpleNamespace:
        account_names.append(account_name)
        return SimpleNamespace(pw_uid=TEST_SERVICE_UID)

    monkeypatch.setattr(systemd_assets.pwd, "getpwnam", resolve_account)

    result = verify_installed_systemd_assets(
        manifest_path=MANIFEST_PATH,
        installed_root=installed_root,
        expected_uid=os.getuid(),
        expected_gid=os.getgid(),
    )

    assert result.scope == "installed"
    assert account_names == ["autocontribute"]


def test_installed_release_rejects_an_unavailable_service_account(
    installed_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing_account(_account_name: str) -> SimpleNamespace:
        raise KeyError("missing fixture account")

    monkeypatch.setattr(systemd_assets.pwd, "getpwnam", missing_account)

    with pytest.raises(PolicyError, match="service account is unavailable"):
        verify_installed_systemd_assets(
            manifest_path=MANIFEST_PATH,
            installed_root=installed_root,
            expected_uid=os.getuid(),
            expected_gid=os.getgid(),
        )


def test_installed_release_rejects_a_root_service_account(
    installed_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        systemd_assets.pwd,
        "getpwnam",
        lambda _account_name: SimpleNamespace(pw_uid=0),
    )

    with pytest.raises(PolicyError, match="service account has an invalid UID"):
        verify_installed_systemd_assets(
            manifest_path=MANIFEST_PATH,
            installed_root=installed_root,
            expected_uid=os.getuid(),
            expected_gid=os.getgid(),
        )


@pytest.mark.parametrize("service_uid", [True, "12345", 0, -1, 2**32 - 1])
def test_installed_release_rejects_an_invalid_explicit_service_uid(
    installed_root: Path,
    service_uid: object,
) -> None:
    with pytest.raises(ValueError, match="systemd asset service UID"):
        verify_installed_systemd_assets(
            manifest_path=MANIFEST_PATH,
            installed_root=installed_root,
            expected_uid=os.getuid(),
            expected_gid=os.getgid(),
            service_uid=service_uid,  # type: ignore[arg-type]
        )


def test_installed_release_invokes_packaged_manifest_trust_by_default(
    installed_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trusted_paths: list[Path] = []
    monkeypatch.setattr(
        systemd_assets,
        "_verify_packaged_manifest_trust",
        trusted_paths.append,
    )

    result = verify_installed_systemd_assets(
        installed_root=installed_root,
        expected_uid=os.getuid(),
        expected_gid=os.getgid(),
        service_uid=TEST_SERVICE_UID,
    )

    assert result.scope == "installed"
    packaged_manifest = Path(systemd_assets.__file__).with_name(MANIFEST_PATH.name).resolve()
    assert trusted_paths == [packaged_manifest]


def test_packaged_manifest_trust_accepts_only_immutable_root_owned_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_opt = tmp_path / "opt"
    releases_root = fake_opt / "autocontribute" / "releases"
    manifest = releases_root / "release-id" / "package" / MANIFEST_PATH.name
    manifest.parent.mkdir(parents=True)
    manifest.write_bytes(MANIFEST_PATH.read_bytes())

    real_path_type = type(fake_opt)
    real_stat = real_path_type.stat

    def root_owned_stat(
        path: Path,
        *,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        metadata = real_stat(path, follow_symlinks=follow_symlinks)
        if path == fake_opt or fake_opt in path.parents:
            fields = list(metadata)
            fields[4] = 0
            fields[5] = 0
            return os.stat_result(fields)
        return metadata

    monkeypatch.setattr(systemd_assets, "_PRODUCTION_RELEASES_ROOT", releases_root)
    monkeypatch.setattr(
        systemd_assets,
        "Path",
        lambda value: fake_opt if os.fspath(value) == "/opt" else Path(value),
    )
    monkeypatch.setattr(real_path_type, "stat", root_owned_stat)

    systemd_assets._verify_packaged_manifest_trust(manifest.resolve())

    (releases_root / "release-id").chmod(0o775)
    with pytest.raises(PolicyError, match="ownership or permissions are unsafe"):
        systemd_assets._verify_packaged_manifest_trust(manifest.resolve())


def test_packaged_manifest_trust_rejects_manifest_outside_release_root(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / MANIFEST_PATH.name
    manifest.write_bytes(MANIFEST_PATH.read_bytes())

    with pytest.raises(PolicyError, match="outside the production release root"):
        systemd_assets._verify_packaged_manifest_trust(manifest.resolve())


def test_installed_release_rejects_tampered_content(installed_root: Path) -> None:
    worker = _asset(_manifest(), "deploy/systemd/libexec/autocontribute-worker")
    target = _installed_path(installed_root, worker)
    target.write_bytes(target.read_bytes() + b"\n# tampered\n")

    with pytest.raises(PolicyError, match="content differs"):
        _verify_installed(installed_root)


def test_installed_release_rejects_wrong_mode(installed_root: Path) -> None:
    worker = _asset(_manifest(), "deploy/systemd/libexec/autocontribute-worker")
    _installed_path(installed_root, worker).chmod(0o700)

    with pytest.raises(PolicyError, match="unexpected mode"):
        _verify_installed(installed_root)


def test_installed_release_rejects_wrong_file_ownership(
    installed_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        systemd_assets,
        "_verify_protected_directory_ancestry",
        lambda *_args, **_kwargs: None,
    )

    with pytest.raises(
        PolicyError,
        match=r"^Installed systemd asset has unsafe ownership:",
    ):
        verify_installed_systemd_assets(
            manifest_path=MANIFEST_PATH,
            installed_root=installed_root,
            expected_uid=os.getuid() + 1,
            expected_gid=os.getgid(),
            service_uid=TEST_SERVICE_UID,
        )


def test_installed_release_rejects_missing_file(installed_root: Path) -> None:
    worker = _asset(_manifest(), "deploy/systemd/libexec/autocontribute-worker")
    _installed_path(installed_root, worker).unlink()

    with pytest.raises(PolicyError, match="unavailable"):
        _verify_installed(installed_root)


def test_installed_release_rejects_symbolic_link(installed_root: Path) -> None:
    manifest = _manifest()
    worker = _asset(manifest, "deploy/systemd/libexec/autocontribute-worker")
    healthcheck = _asset(manifest, "deploy/systemd/libexec/autocontribute-healthcheck")
    target = _installed_path(installed_root, worker)
    target.unlink()
    target.symlink_to(_installed_path(installed_root, healthcheck))

    with pytest.raises(PolicyError, match="symbolic link"):
        _verify_installed(installed_root)


def test_source_release_rejects_unexpected_asset(source_release: Path) -> None:
    unexpected = source_release / "deploy" / "systemd" / "autocontribute-retired.service"
    unexpected.write_text("[Unit]\nDescription=retired\n", encoding="utf-8")
    unexpected.chmod(0o644)

    with pytest.raises(PolicyError, match="unexpected: deploy/systemd/autocontribute-retired"):
        verify_source_systemd_assets(source_release, manifest_path=MANIFEST_PATH)


def test_source_release_rejects_tampered_content(source_release: Path) -> None:
    worker = source_release / "deploy" / "systemd" / "libexec" / "autocontribute-worker"
    worker.write_bytes(worker.read_bytes() + b"\n# tampered\n")

    with pytest.raises(PolicyError, match="content differs"):
        verify_source_systemd_assets(source_release, manifest_path=MANIFEST_PATH)


def test_source_release_rejects_wrong_mode(source_release: Path) -> None:
    worker = source_release / "deploy" / "systemd" / "libexec" / "autocontribute-worker"
    worker.chmod(0o700)

    with pytest.raises(PolicyError, match="unexpected mode"):
        verify_source_systemd_assets(source_release, manifest_path=MANIFEST_PATH)


def test_source_release_rejects_different_source_manifest(source_release: Path) -> None:
    source_manifest = source_release / "src" / "autocontribute" / MANIFEST_PATH.name
    source_manifest.write_bytes(source_manifest.read_bytes() + b"\n")

    with pytest.raises(PolicyError, match="Source systemd asset manifest differs"):
        verify_source_systemd_assets(source_release, manifest_path=MANIFEST_PATH)


def test_source_release_rejects_symbolic_link(source_release: Path) -> None:
    worker = source_release / "deploy" / "systemd" / "libexec" / "autocontribute-worker"
    worker.unlink()
    worker.symlink_to("autocontribute-healthcheck")

    with pytest.raises(PolicyError, match="source contains a symbolic link"):
        verify_source_systemd_assets(source_release, manifest_path=MANIFEST_PATH)


def test_source_release_reports_user_expansion_failure_as_policy_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_expansion(_path: Path) -> Path:
        raise RuntimeError("unknown fixture user")

    monkeypatch.setattr(Path, "expanduser", fail_expansion)

    with pytest.raises(PolicyError, match="Systemd asset source root is unavailable"):
        verify_source_systemd_assets(Path("~missing-fixture"), manifest_path=MANIFEST_PATH)


def test_installed_release_rejects_retired_helper(installed_root: Path) -> None:
    retired = installed_root / "usr" / "local" / "libexec" / "autocontribute-retired"
    retired.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    retired.chmod(0o755)

    with pytest.raises(PolicyError, match="Unexpected or retired systemd deployment asset"):
        _verify_installed(installed_root)


@pytest.mark.parametrize(
    "relative_path",
    [
        "etc/systemd/system/autocontribute-rootless-docker.service.d/99-reset.conf",
        "etc/systemd/user/autocontribute-rootless-docker-daemon.service.d/99-reset.conf",
        f"etc/systemd/system/user@{TEST_SERVICE_UID}.service.d/99-reset.conf",
    ],
)
def test_installed_release_rejects_unattested_rootless_docker_policy(
    installed_root: Path,
    relative_path: str,
) -> None:
    reset = installed_root / relative_path
    reset.parent.mkdir(parents=True, exist_ok=True)
    reset.write_text("[Service]\nExecStartPre=\n", encoding="utf-8")
    reset.chmod(0o644)

    with pytest.raises(PolicyError, match="Unexpected or retired systemd deployment asset"):
        _verify_installed(installed_root)


def test_installed_release_rejects_a_stale_service_uid_manager_policy(
    installed_root: Path,
) -> None:
    stale_uid = TEST_SERVICE_UID + 1
    stale_policy = (
        installed_root
        / "etc"
        / "systemd"
        / "system"
        / f"user@{stale_uid}.service.d"
        / "50-autocontribute.conf"
    )
    stale_policy.parent.mkdir(parents=True)
    stale_policy.write_bytes(
        (PROJECT_ROOT / "deploy/systemd/autocontribute-user-manager.conf").read_bytes()
    )
    stale_policy.chmod(0o644)

    with pytest.raises(PolicyError, match="stale Autocontribute user-manager drop-in"):
        _verify_installed(installed_root)


@pytest.mark.parametrize(
    "retired_path",
    [
        "etc/systemd/system/user@.service.d/50-autocontribute.conf",
        "etc/systemd/system/user@.service.d/delegate.conf",
        "etc/systemd/user/docker.service",
        "etc/systemd/user/docker.service.d",
        "var/lib/autocontribute/.config/systemd/user/docker.service",
        "var/lib/autocontribute/.config/systemd/user/docker.service.d",
        "var/lib/autocontribute/.config/systemd/user/autocontribute-rootless-docker-daemon.service",
        "var/lib/autocontribute/.config/systemd/user/autocontribute-rootless-docker-daemon.service.d",
        "var/lib/autocontribute/.local/share/systemd/user/autocontribute-rootless-docker-daemon.service",
        "var/lib/autocontribute/.local/share/systemd/user/autocontribute-rootless-docker-daemon.service.d",
    ],
)
def test_installed_release_rejects_retired_user_managed_docker_unit(
    installed_root: Path,
    retired_path: str,
) -> None:
    retired = installed_root / retired_path
    if retired.suffix in {".conf", ".service"}:
        retired.parent.mkdir(parents=True, exist_ok=True)
        retired.write_text("[Service]\nExecStart=/usr/bin/false\n", encoding="utf-8")
    else:
        retired.mkdir(parents=True)

    with pytest.raises(PolicyError, match="retired rootless Docker deployment path"):
        _verify_installed(installed_root)


def test_installed_release_allows_filesystem_safe_unattested_service_dropin(
    installed_root: Path,
) -> None:
    dropin = installed_root / "etc" / "systemd" / "system" / "autocontribute-worker.service.d"
    dropin.mkdir()
    dropin.chmod(0o755)
    override = dropin / "20-operator.conf"
    override.write_text("[Service]\nEnvironment=OPERATOR_OVERRIDE=1\n", encoding="utf-8")
    override.chmod(0o644)

    result = _verify_installed(installed_root)

    assert result.checked_assets == 25


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("writable-directory", "drop-in directory has unsafe ownership or permissions"),
        ("writable-file", "drop-in has unsafe ownership or permissions"),
        ("symbolic-link", "drop-in is a symbolic link"),
        ("unexpected-name", "drop-in has an unexpected name"),
    ],
)
def test_installed_release_rejects_unsafe_operator_dropins(
    installed_root: Path,
    mutation: str,
    message: str,
) -> None:
    dropin = installed_root / "etc" / "systemd" / "system" / "autocontribute-worker.service.d"
    dropin.mkdir()
    dropin.chmod(0o755)
    override = dropin / "20-operator.conf"
    override.write_text("[Service]\nEnvironment=OPERATOR_OVERRIDE=1\n", encoding="utf-8")
    override.chmod(0o644)

    if mutation == "writable-directory":
        dropin.chmod(0o775)
    elif mutation == "writable-file":
        override.chmod(0o664)
    elif mutation == "symbolic-link":
        override.unlink()
        override.symlink_to(installed_root / "usr" / "local" / "libexec" / "autocontribute-worker")
    elif mutation == "unexpected-name":
        override.rename(dropin / "20-operator.txt")
    else:
        raise AssertionError(f"unknown drop-in mutation: {mutation}")

    with pytest.raises(PolicyError, match=message):
        _verify_installed(installed_root)


def test_manifest_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    content = MANIFEST_PATH.read_text(encoding="utf-8").replace(
        '"project": "autocontribute",',
        '"project": "autocontribute",\n  "project": "autocontribute",',
        1,
    )
    duplicate.write_text(content, encoding="utf-8")

    with pytest.raises(PolicyError, match="manifest is invalid"):
        load_systemd_asset_manifest(duplicate)


@pytest.mark.parametrize(
    "mutation",
    [
        "redirect-installed-path",
        "weaken-required",
        "coerce-required-integer",
        "change-mode",
        "omit-asset",
        "duplicate-asset",
        "unsorted-assets",
        "extra-field",
        "coerce-schema-boolean",
    ],
)
def test_manifest_rejects_changes_to_executable_contract(
    tmp_path: Path,
    mutation: str,
) -> None:
    payload = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    assets = payload["assets"]
    assert isinstance(assets, list)
    assert isinstance(assets[0], dict)

    if mutation == "redirect-installed-path":
        assets[0]["installed_path"] = "/tmp/autocontribute-backup.service"
    elif mutation == "weaken-required":
        assets[0]["required"] = False
    elif mutation == "coerce-required-integer":
        assets[0]["required"] = 1
    elif mutation == "change-mode":
        assets[0]["mode"] = "0600"
    elif mutation == "omit-asset":
        assets.pop()
    elif mutation == "duplicate-asset":
        assets.insert(1, dict(assets[0]))
    elif mutation == "unsorted-assets":
        assets[0], assets[1] = assets[1], assets[0]
    elif mutation == "extra-field":
        assets[0]["unreviewed"] = True
    elif mutation == "coerce-schema-boolean":
        payload["schema_version"] = True
    else:
        raise AssertionError(f"unknown manifest mutation: {mutation}")

    changed_manifest = tmp_path / f"{mutation}.json"
    changed_manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(PolicyError, match="manifest is invalid"):
        load_systemd_asset_manifest(changed_manifest)


def test_installed_release_rejects_fifo_without_blocking(installed_root: Path) -> None:
    worker = _asset(_manifest(), "deploy/systemd/libexec/autocontribute-worker")
    target = _installed_path(installed_root, worker)
    target.unlink()
    os.mkfifo(target, mode=0o755)

    with pytest.raises(PolicyError, match="not a regular file"):
        _verify_installed(installed_root)


def test_installed_release_rejects_writable_managed_ancestry(installed_root: Path) -> None:
    helper_directory = installed_root / "usr" / "local" / "libexec"
    helper_directory.chmod(0o777)

    with pytest.raises(PolicyError, match="unsafe ownership or permissions"):
        _verify_installed(installed_root)
