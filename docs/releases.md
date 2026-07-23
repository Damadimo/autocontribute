# Releases and supply-chain verification

The `Release` workflow turns one reviewed, signed version tag into reproducible Python
distributions and a verifiable GitHub Release. It uses no stored signing key or publishing secret.
GitHub's short-lived OpenID Connect identity produces both Sigstore bundles for the release subjects
and signed SLSA build provenance.

## One-time repository controls

Complete these controls before creating a version tag:

1. Make the repository public. The workflow requires public visibility so its GitHub provenance and
   Sigstore identity remain publicly verifiable without an Enterprise-only private attestation
   service.
2. Protect the default branch as described in [Scheduled operation](scheduled-operation.md): require
   CI, the exact `Security integration gate`, trusted approval, code-owner review for workflow
   changes, stale-review dismissal, and block force-push, deletion, and bypass.
3. Add a ruleset for `refs/tags/v*` that restricts tag creation to release managers and blocks tag
   update and deletion. The workflow additionally accepts only a GitHub-verified signed annotated
   tag whose target is already in the default-branch history.
4. Create a `release` environment and require a second trusted reviewer. Do not let the tag creator
   self-approve the release job.
5. Enable immutable releases in the repository settings. The workflow refuses to overwrite an
   existing version, and GitHub's immutable-release setting prevents later tag or asset replacement
   after publication.

The workflow scopes `actions: read`, `contents: write`, `id-token: write`, and
`attestations: write` to its single environment-protected job. It never receives the model token,
contribution token, state token, or any repository secret.

## Cut a release

Prepare the release on a pull request. Update `project.version` in `pyproject.toml`, regenerate
`uv.lock` only when its project entry changes, and refresh
`src/autocontribute/_build_identity.json` so its SHA-256 values match `pyproject.toml` and `uv.lock`.
The packaging tests reject any stale identity. Merge through the protected default branch and wait
for both CI and the security integration gate to pass.

From a clean, current default-branch checkout, create and push a signed annotated stable SemVer tag:

```bash
version=0.1.0
git tag --sign "v${version}" --message "autocontribute ${version}"
git push origin "v${version}"
unset version
```

Approve the pending `release` environment deployment only after confirming the tag, target commit,
and completed default-branch checks. The workflow then:

1. verifies the signed tag, exact project version, public repository, and default-branch ancestry,
   then requires exact-commit successful `push` runs and the named Ubuntu acceptance and security
   gate jobs from the expected hosted workflow files;
2. installs the exactly locked build backend with the fixed dependency-age snapshot;
3. builds the sdist and its wheel twice from separate `git archive` trees with the commit timestamp
   as `SOURCE_DATE_EPOCH`, then requires byte-for-byte equality;
4. installs the wheel over the hash-locked runtime dependency closure, safely extracts the sdist,
   binds its project metadata, lock, and build identity back to the signed tree, and uses the
   installed wheel to verify every release-bound systemd asset in that exact sdist;
5. installs that extracted sdist on the supported Ubuntu 24.04/systemd 255 host and exercises the
   fail-closed deployment, backup, tamper rejection, and complete-state recovery path without
   exposing the release job's OIDC capability to the acceptance process;
6. audits the exported, hash-locked runtime closure with pinned `pip-audit==2.9.0`, strict collection,
   and pip disabled;
7. emits the runtime-only CycloneDX 1.5 dependency graph twice, normalizes its timestamp and UUID,
   binds it to the commit and distribution hashes, and requires byte-for-byte equality;
8. signs the sdist, wheel, SBOM, and checksum manifest with the workflow's keyless Sigstore identity;
9. creates GitHub SLSA provenance for the three checksummed subjects and retains all nine files as a
   90-day workflow artifact;
10. uploads the nine files to a draft GitHub Release and downloads and byte-compares every asset while
   it remains non-public; and
11. publishes the verified draft and downloads no substitute asset after the visibility transition.

If a build, signature, attestation, upload, or comparison fails, fix source through a new reviewed
commit and use a new version. Never move or recreate a release tag. A failed upload or comparison
intentionally leaves a non-public GitHub draft for operator inspection. The preflight refuses to
overwrite that draft; remove it only after recording the failure and confirming that no asset was
published, then re-run the original immutable tag workflow if the failure was purely transient.

## Verify a release

Download only the workflow-produced assets. GitHub's automatically generated source archives are not
the attested Python source distribution.

```bash
repository=Damadimo/autocontribute
tag=v0.1.0
gh release download "$tag" --repo "$repository" --dir "$tag"
(
  cd "$tag"
  sha256sum --check --strict SHA256SUMS
)
```

Verify public GitHub provenance for the sdist, wheel, and SBOM:

```bash
for subject in \
  "$tag"/autocontribute-*.tar.gz \
  "$tag"/autocontribute-*.whl \
  "$tag"/autocontribute-*.cdx.json
do
  gh attestation verify "$subject" --repo "$repository"
done
```

Verify every adjacent Sigstore bundle against this workflow's exact tag identity:

```bash
certificate_identity="https://github.com/${repository}/.github/workflows/release.yml@refs/tags/${tag}"
for subject in \
  "$tag"/autocontribute-*.tar.gz \
  "$tag"/autocontribute-*.whl \
  "$tag"/autocontribute-*.cdx.json \
  "$tag"/SHA256SUMS
do
  uvx --from sigstore==4.3.0 sigstore verify identity \
    --bundle "$subject.sigstore.json" \
    --cert-identity "$certificate_identity" \
    --cert-oidc-issuer https://token.actions.githubusercontent.com \
    "$subject"
done
unset certificate_identity repository subject tag
```

`autocontribute-<version>.provenance.sigstore.json` is the retained signed provenance bundle. The
GitHub attestation command verifies the corresponding transparency-backed record and subject digest.

## Deliberate exclusions

This workflow publishes a GitHub Release, not a PyPI project. Add PyPI only after its project and
owner account are configured for trusted publishing, with a separately protected environment and no
API token. Release provenance also does not replace off-host immutable backup replication for live
scheduler state.
