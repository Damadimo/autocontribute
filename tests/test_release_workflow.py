from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "release.yml"


def _workflow() -> dict[str, object]:
    return yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))


def _release_steps() -> list[dict[str, object]]:
    document = _workflow()
    return document["jobs"]["release"]["steps"]  # type: ignore[index,return-value]


def _step(name: str) -> dict[str, object]:
    return next(step for step in _release_steps() if step.get("name") == name)


def test_release_requires_a_tag_and_protected_environment() -> None:
    document = _workflow()
    triggers = document[True]
    job = document["jobs"]["release"]

    assert triggers == {"push": {"tags": ["v*"]}}
    assert document["permissions"] == {"contents": "read"}
    assert document["concurrency"] == {
        "group": "release-${{ github.ref }}",
        "cancel-in-progress": False,
    }
    assert job["environment"] == "release"
    assert job["runs-on"] == "ubuntu-24.04"
    assert job["timeout-minutes"] == 60
    assert job["permissions"] == {
        "actions": "read",
        "attestations": "write",
        "contents": "write",
        "id-token": "write",
    }

    checkout = _step("Check out complete tagged source")
    assert checkout["uses"] == ("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1")
    assert checkout["with"] == {
        "ref": "${{ github.ref }}",
        "fetch-depth": 0,
        "persist-credentials": False,
    }
    setup = _step("Install pinned uv and Python")
    assert setup["uses"] == ("astral-sh/setup-uv@c771a70e6277c0a99b617c7a806ffedaca235ff9")
    assert setup["with"] == {
        "version": "0.9.30",
        "python-version": "3.12.12",
        "enable-cache": False,
    }
    assert "secrets." not in WORKFLOW_PATH.read_text(encoding="utf-8")


def test_release_source_is_signed_version_matched_and_on_default_branch() -> None:
    step = _step("Verify signed release source")
    script = str(step["run"])

    assert step["env"] == {
        "GH_TOKEN": "${{ github.token }}",
        "TAG_NAME": "${{ github.ref_name }}",
    }
    assert "canonical stable semantic versions" in script
    assert '"v$project_version" != "$TAG_NAME"' in script
    assert '"$(git cat-file -t "refs/tags/$TAG_NAME")" != "tag"' in script
    assert 'gh api "repos/$GITHUB_REPOSITORY/git/ref/tags/$TAG_NAME"' in script
    assert 'gh api "repos/$GITHUB_REPOSITORY/git/tags/$tag_object_sha"' in script
    assert '"$tag_verified" != "true"' in script
    assert '"$tag_verification_reason" != "valid"' in script
    assert '"$tag_target_sha" != "$GITHUB_SHA"' in script
    assert '"$visibility" != "public"' in script
    assert 'git merge-base --is-ancestor "$GITHUB_SHA"' in script
    assert 'gh release view "$TAG_NAME"' in script
    assert "SOURCE_DATE_EPOCH" in script
    assert "UV_EXCLUDE_NEWER" in script


def test_release_requires_exact_sha_hosted_acceptance_and_security_gates() -> None:
    steps = _release_steps()
    verify = _step("Verify signed release source")
    install = _step("Install locked build environment")
    script = str(verify["run"])

    assert steps.index(verify) < steps.index(install)
    assert "actions/workflows/$workflow_file/runs" in script
    assert '-f branch="$default_branch"' in script
    assert "-f event=push" in script
    assert "-f status=completed" in script
    assert '-f head_sha="$GITHUB_SHA"' in script
    assert ".head_sha == $commit" in script
    assert ".head_branch == $branch" in script
    assert '.event == "push"' in script
    assert '.status == "completed"' in script
    assert '.conclusion == "success"' in script
    assert ".path == $workflow_path" in script
    assert ".repository.full_name == $repository" in script
    assert ".head_repository.full_name == $repository" in script
    assert "actions/runs/$run_id/jobs" in script
    assert "($required | length) == 1" in script
    assert "$required[0].run_attempt == $run_attempt" in script
    assert "$required[0].head_sha == $commit" in script
    assert "ci.yml" in script
    assert '"Ubuntu 24.04 deployment/recovery acceptance"' in script
    assert "security-integration.yml" in script
    assert '"Security integration gate"' in script


def test_release_builds_twice_offline_and_compares_exact_bytes() -> None:
    install = _step("Install locked build environment")
    build = _step("Build twice from clean source archives")
    install_script = str(install["run"])
    build_script = str(build["run"])

    assert "uv sync" in install_script
    assert "--locked" in install_script
    assert "--no-cache" in install_script
    assert "--no-install-project" in install_script
    assert "--no-sources" in install_script
    assert ".venv/bin/python tests/test_packaging.py" in install_script
    assert "git diff --exit-code -- ." in install_script

    assert "for build_id in first second" in build_script
    assert 'git archive --format=tar "$GITHUB_SHA"' in build_script
    assert build_script.count("uv build") == 2
    assert build_script.count("--no-build-isolation") == 2
    assert build_script.count("--offline") == 2
    assert build_script.count("--no-create-gitignore") == 2
    assert 'cmp --silent "$first_sdist" "$second_sdist"' in build_script
    assert 'cmp --silent "$first_wheel" "$second_wheel"' in build_script
    assert "unexpected artifact inventory" in build_script


def test_release_verifies_wheel_against_hashed_locked_runtime() -> None:
    steps = _release_steps()
    script = str(_step("Verify exact wheel and locked runtime closure")["run"])

    assert "uv export" in script
    assert "--locked" in script
    assert "--no-dev" in script
    assert "--no-emit-project" in script
    assert "--format requirements.txt" in script
    assert "--require-hashes" in script
    assert "--no-cache" in script
    assert "--no-deps" in script
    assert "uv pip check" in script
    assert "installed wheel metadata has the wrong version" in script
    assert "installed _build_identity.json differs from signed source" not in script
    assert "differs from signed source" in script
    assert "source distribution contains an unsafe path" in script
    assert "source distribution contains duplicate members" in script
    assert "source distribution contains a link or special member" in script
    assert "source distribution does not have one exact version root" in script
    assert 'archive.extractall(extract_root, filter="data")' in script
    assert "deployment verify-systemd-assets" in script
    assert '"$GITHUB_WORKSPACE/pyproject.toml"' in script
    assert '"$extracted_root/pyproject.toml"' in script
    assert '"$GITHUB_WORKSPACE/uv.lock"' in script
    assert '"$extracted_root/uv.lock"' in script
    assert '"$GITHUB_WORKSPACE/src/autocontribute/_build_identity.json"' in script
    assert '"$extracted_root/src/autocontribute/_build_identity.json"' in script
    assert '--source-root "$extracted_root"' in script

    acceptance = _step("Exercise deployment and recovery from exact sdist")
    acceptance_script = str(acceptance["run"])
    assert steps.index(_step("Verify exact wheel and locked runtime closure")) < steps.index(
        acceptance
    )
    assert steps.index(acceptance) < steps.index(_step("Audit locked runtime vulnerabilities"))
    assert "-u ACTIONS_ID_TOKEN_REQUEST_TOKEN" in acceptance_script
    assert "-u ACTIONS_ID_TOKEN_REQUEST_URL" in acceptance_script
    assert "-u GH_TOKEN" in acceptance_script
    assert "-u GITHUB_TOKEN" in acceptance_script
    assert "tests/acceptance/ubuntu_24_04_deployment_recovery.sh" in acceptance_script
    assert '--source-root "$extracted_root"' in acceptance_script


def test_release_audits_hash_locked_runtime_without_pip() -> None:
    script = str(_step("Audit locked runtime vulnerabilities")["run"])

    assert script.startswith("set -euo pipefail")
    assert "uv export" in script
    assert "--locked" in script
    assert "--no-dev" in script
    assert "--no-emit-project" in script
    assert "--format requirements.txt" in script
    assert "uvx --no-cache --from pip-audit==2.9.0 pip-audit" in script
    assert '--requirement "$audit_requirements"' in script
    assert "--disable-pip" in script
    assert "--strict" in script
    assert '| tee "$RUNNER_TEMP/autocontribute-pip-audit.txt"' in script

    steps = _release_steps()
    audit = _step("Audit locked runtime vulnerabilities")
    signing = _step("Keyless-sign and verify release subjects")
    assert steps.index(audit) < steps.index(signing)


def test_release_sbom_is_runtime_only_reproducible_and_artifact_bound() -> None:
    script = str(_step("Generate reproducible CycloneDX SBOM")["run"])

    assert "for sbom_path in" in script
    assert "--format cyclonedx1.5" in script
    assert "--locked" in script
    assert "--no-dev" in script
    assert 'document["serialNumber"]' in script
    assert 'metadata["timestamp"] = source_timestamp' in script
    assert "autocontribute:artifact:sdist:sha256" in script
    assert "autocontribute:artifact:wheel:sha256" in script
    assert "autocontribute:source:git_commit" in script
    assert "forbidden_development_components" in script
    assert "SBOM dependency graph contains a dangling reference" in script
    assert 'cmp --silent "$sbom_first" "$sbom_second"' in script

    checksum_script = str(_step("Create and verify subject checksums")["run"])
    assert 'sha256sum "$sdist" "$wheel" "$sbom" >SHA256SUMS' in checksum_script
    assert "sha256sum --check --strict SHA256SUMS" in checksum_script


def test_release_keyless_signs_attests_and_retains_exact_assets_before_publish() -> None:
    steps = _release_steps()
    signing = _step("Keyless-sign and verify release subjects")
    provenance = _step("Attest release build provenance")
    seal = _step("Seal release asset inventory")
    upload = _step("Retain exact release bundle")
    publish = _step("Stage verify and publish immutable-version GitHub Release")

    assert signing["uses"] == (
        "sigstore/gh-action-sigstore-python@790bc6befb9d733738f18d8f895854b453640ec9"
    )
    assert signing["with"] == {
        "inputs": ("release/*.tar.gz\nrelease/*.whl\nrelease/*.cdx.json\nrelease/SHA256SUMS\n"),
        "verify": True,
        "verify-cert-identity": (
            "https://github.com/${{ github.repository }}/.github/workflows/release.yml@"
            "${{ github.ref }}"
        ),
        "verify-oidc-issuer": "https://token.actions.githubusercontent.com",
        "upload-signing-artifacts": False,
        "release-signing-artifacts": False,
    }
    assert provenance["uses"] == (
        "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8"
    )
    assert provenance["with"] == {"subject-checksums": "release/SHA256SUMS"}
    assert "provenance.sigstore.json" in str(seal["run"])
    assert "release inventory differs" in str(seal["run"])

    assert upload["uses"] == ("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a")
    assert upload["with"] == {
        "name": "release-${{ github.ref_name }}",
        "path": "release/",
        "if-no-files-found": "error",
        "retention-days": 90,
        "compression-level": 0,
    }
    assert steps.index(signing) < steps.index(provenance) < steps.index(seal)
    assert steps.index(seal) < steps.index(upload) < steps.index(publish)

    publish_script = str(publish["run"])
    assert '"${#release_assets[@]}" -ne 9' in publish_script
    assert 'gh release create "$TAG_NAME" "${release_assets[@]}"' in publish_script
    assert "--verify-tag" in publish_script
    assert "--fail-on-no-commits" in publish_script
    assert "--draft" in publish_script
    assert 'gh release download "$TAG_NAME"' in publish_script
    assert "mapfile -d '' downloaded_assets" in publish_script
    assert '"${#downloaded_assets[@]}" -ne "${#release_assets[@]}"' in publish_script
    assert 'downloaded_asset="${downloaded_assets[$asset_index]}"' in publish_script
    assert '"$downloaded_name" != "$local_name"' in publish_script
    assert 'cmp --silent "$local_asset" "$downloaded_asset"' in publish_script
    assert 'gh release edit "$TAG_NAME"' in publish_script
    assert "--draft=false" in publish_script
    assert publish_script.index("gh release create") < publish_script.index("gh release download")
    assert publish_script.index("gh release download") < publish_script.index("gh release edit")


def test_release_verification_docs_bind_each_subject_to_its_sigstore_bundle() -> None:
    guide = (ROOT / "docs" / "releases.md").read_text(encoding="utf-8")

    assert '--bundle "$subject.sigstore.json"' in guide
