import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import autocontribute.deployment as deployment
from autocontribute.config import AutocontributeConfig
from autocontribute.deployment import (
    compute_deployment_fingerprint,
    package_source_digest,
    packaged_build_identity_digest,
    runtime_environment_digest,
    validate_deployment_fingerprint,
)
from autocontribute.exceptions import PolicyError

SOURCE_DIGEST = "a" * 64


def _fingerprint(payload: dict[str, object] | None = None) -> str:
    config = AutocontributeConfig.model_validate(payload or {})
    return compute_deployment_fingerprint(config, source_digest=SOURCE_DIGEST)


@pytest.mark.parametrize(
    "payload",
    [
        {"models": {"builder": {"model": "different-builder"}}},
        {"models": {"builder": {"expected_response_model": "immutable-snapshot-v2"}}},
        {
            "models": {
                "builder": {
                    "expected_response_model": "immutable-snapshot-v2",
                    "immutable_response_model_attested": True,
                }
            }
        },
        {"budget": {"max_candidates_per_run": 24}},
        {"github": {"min_stars": 999}},
        {"sandbox": {"command_timeout_seconds": 899}},
        {"validation": {"required_commands": {"example/project": ["pytest -q"]}}},
        {"policy": {"require_contribution_guidelines": False}},
        {"quality": {"max_changed_lines": 399}},
        {"publishing": {"max_open_pull_requests": 1}},
    ],
)
def test_material_deployment_change_requires_new_fingerprint(
    payload: dict[str, object],
) -> None:
    assert _fingerprint(payload) != _fingerprint()


def test_storage_credentials_identity_and_review_to_auto_transition_are_normalized() -> None:
    base = AutocontributeConfig()
    changed = base.model_copy(deep=True)
    changed.storage.path = Path("/different/state")
    changed.identity.name = "Different Operator"
    changed.github.token_env = "OTHER_GITHUB_TOKEN"
    changed.models.builder.api_key_env = "OTHER_MODEL_KEY"
    changed.publishing.mode = "auto"
    changed.publishing.auto_publish_env = "OTHER_AUTO_SWITCH"

    assert compute_deployment_fingerprint(
        base, source_digest=SOURCE_DIGEST
    ) == compute_deployment_fingerprint(changed, source_digest=SOURCE_DIGEST)


def test_package_source_digest_is_path_stable_and_content_sensitive(tmp_path: Path) -> None:
    package = tmp_path / "autocontribute"
    package.mkdir()
    (package / "a.py").write_text("VALUE = 1\n", encoding="utf-8")
    nested = package / "nested"
    nested.mkdir()
    (nested / "b.py").write_text("VALUE = 2\n", encoding="utf-8")

    first = package_source_digest(package)
    assert first == package_source_digest(package)
    (nested / "b.py").write_text("VALUE = 3\n", encoding="utf-8")

    assert package_source_digest(package) != first


def test_packaged_build_identity_matches_exact_project_and_lock_material() -> None:
    project_root = Path(__file__).resolve().parents[1]
    manifest = project_root / "src" / "autocontribute" / "_build_identity.json"
    payload = json.loads(manifest.read_text(encoding="utf-8"))

    assert (
        payload["pyproject_sha256"]
        == hashlib.sha256((project_root / "pyproject.toml").read_bytes()).hexdigest()
    )
    assert (
        payload["uv_lock_sha256"]
        == hashlib.sha256((project_root / "uv.lock").read_bytes()).hexdigest()
    )
    assert len(packaged_build_identity_digest(manifest)) == 64


def test_packaged_build_identity_is_portable_and_ignores_ancestor_projects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_manifest = Path(deployment.__file__).with_name("_build_identity.json")
    installed_package = tmp_path / "unrelated-project" / "site-packages" / "autocontribute"
    installed_package.mkdir(parents=True)
    installed_manifest = installed_package / "_build_identity.json"
    installed_manifest.write_bytes(source_manifest.read_bytes())
    unrelated_project = tmp_path / "unrelated-project" / "pyproject.toml"
    unrelated_project.write_text("[project]\nname = 'first'\n", encoding="utf-8")
    monkeypatch.setattr(deployment, "__file__", str(installed_package / "deployment.py"))

    first = packaged_build_identity_digest()
    unrelated_project.write_text("[project]\nname = 'changed'\n", encoding="utf-8")

    assert packaged_build_identity_digest() == first
    assert first == packaged_build_identity_digest(source_manifest)


def test_packaged_build_identity_fails_closed_when_missing_or_malformed(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"
    with pytest.raises(PolicyError, match="missing or unsafe"):
        packaged_build_identity_digest(missing)

    malformed = tmp_path / "malformed.json"
    malformed.write_text('{"schema_version": 1}', encoding="utf-8")
    with pytest.raises(PolicyError, match="invalid schema"):
        packaged_build_identity_digest(malformed)


def test_runtime_environment_change_requires_new_fingerprint() -> None:
    config = AutocontributeConfig()

    first = compute_deployment_fingerprint(
        config,
        source_digest=SOURCE_DIGEST,
        runtime_digest="b" * 64,
    )
    second = compute_deployment_fingerprint(
        config,
        source_digest=SOURCE_DIGEST,
        runtime_digest="c" * 64,
    )

    assert first != second


def test_immutable_model_attestation_changes_the_deployment_fingerprint() -> None:
    base = AutocontributeConfig.model_validate(
        {"models": {"builder": {"expected_response_model": "immutable-snapshot-v2"}}}
    )
    attested = base.model_copy(deep=True)
    attested.models.builder.immutable_response_model_attested = True

    assert compute_deployment_fingerprint(
        base,
        source_digest=SOURCE_DIGEST,
        runtime_digest="b" * 64,
    ) != compute_deployment_fingerprint(
        attested,
        source_digest=SOURCE_DIGEST,
        runtime_digest="b" * 64,
    )


def test_runtime_digest_changes_with_installed_dependency_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    versions = {
        "autocontribute": "0.1.0",
        "httpx": "1",
        "openai": "1",
        "packaging": "1",
        "pydantic": "1",
        "pyyaml": "1",
        "rich": "1",
        "typer": "1",
    }

    def installed(name: str) -> SimpleNamespace:
        normalized = name.casefold()
        return SimpleNamespace(
            metadata={"Name": normalized},
            version=versions[normalized],
            requires=[],
        )

    monkeypatch.setattr("autocontribute.deployment.distribution", installed)
    first = runtime_environment_digest()
    versions["openai"] = "2"

    assert runtime_environment_digest() != first


def test_runtime_digest_ignores_installed_dependencies_behind_inactive_markers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    include_inactive = False
    versions = {
        "autocontribute": "0.1.0",
        "httpx": "1",
        "openai": "1",
        "packaging": "1",
        "pydantic": "1",
        "pyyaml": "1",
        "rich": "1",
        "typer": "1",
        "windows-only": "1",
    }

    def installed(name: str) -> SimpleNamespace:
        normalized = name.casefold()
        if normalized == "autocontribute":
            requirements = [
                'windows-only; platform_system == "Windows"'
                if include_inactive
                else 'windows-only; platform_system == "Plan9"'
            ]
        else:
            requirements = []
        return SimpleNamespace(
            metadata={"Name": normalized},
            version=versions[normalized],
            requires=requirements,
        )

    monkeypatch.setattr("autocontribute.deployment.distribution", installed)
    first = runtime_environment_digest()
    include_inactive = True

    assert runtime_environment_digest() == first


def test_runtime_digest_changes_with_python_interpreter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = runtime_environment_digest()
    monkeypatch.setattr("autocontribute.deployment.platform.python_version", lambda: "99.0.0")

    assert runtime_environment_digest() != first


def test_runtime_digest_changes_with_packaged_systemd_asset_manifest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = runtime_environment_digest()
    monkeypatch.setattr(
        deployment,
        "packaged_systemd_asset_manifest_digest",
        lambda: "f" * 64,
    )

    assert runtime_environment_digest() != first


def test_run_deployment_validation_fails_closed_for_missing_or_stale_identity() -> None:
    config = AutocontributeConfig()
    current = compute_deployment_fingerprint(config)

    assert validate_deployment_fingerprint(current, config) == current
    with pytest.raises(PolicyError, match="missing"):
        validate_deployment_fingerprint(None, config)
    with pytest.raises(PolicyError, match="different code, model, or policy"):
        validate_deployment_fingerprint("0" * 64, config)
