# Releases

The **Release** workflow (`.github/workflows/release.yml`) turns a signed version tag into a GitHub
Release with reproducible Python distributions, a CycloneDX SBOM, Sigstore signatures and GitHub
build provenance. It holds no signing key or publishing secret: it signs with the workflow's GitHub
OIDC identity. There is no PyPI release.

## One-time repository setup

1. Make the repository public; the workflow refuses private ones so provenance stays verifiable.
2. Protect the default branch: require an approving review (authors cannot approve their own pull
   requests, so a sole maintainer needs a second trusted account), code-owner review for the paths
   in `.github/CODEOWNERS`, dismissal of stale approvals, passing CI jobs and the
   `Security integration gate` check. Block force pushes, deletion and bypass.
3. Add a ruleset for `refs/tags/v*` that lets only release managers create tags and blocks tag
   updates and deletion.
4. Create a `release` environment with a required reviewer and self-review prevented, so the person
   who pushed the tag cannot approve the release.
5. Turn on immutable releases in the repository settings.

## Cut a release

1. In a pull request, set `project.version` in `pyproject.toml`, run `uv lock`, and set
   `pyproject_sha256` and `uv_lock_sha256` in `src/autocontribute/_build_identity.json` to the
   output of `sha256sum pyproject.toml uv.lock`. `uv run python tests/test_packaging.py` checks
   them. After merging, wait for the `CI` and `Security integration` runs on the merged commit to
   succeed.
2. From an up-to-date default-branch checkout, push a signed annotated tag matching
   `project.version`. GitHub must show the tag's signature as verified.

   ```bash
   version=0.1.0
   git tag --sign "v${version}" --message "autocontribute ${version}"
   git push origin "v${version}"
   ```

3. Approve the `release` environment deployment after checking the tag, its commit and those runs.

The workflow stops unless the tag is `v` plus `project.version` in stable `X.Y.Z` form, carries a
GitHub-verified signature, points at a default-branch commit whose `push` runs passed the
`Ubuntu 24.04 deployment/recovery acceptance` and `Security integration gate` jobs, and has no
release yet. It then builds the sdist and wheel twice from clean source archives and requires
identical bytes, installs the wheel over the hash-locked dependencies, runs the Ubuntu
[acceptance test](../tests/acceptance/README.md) on the sdist, audits the runtime dependencies with
`pip-audit`, writes the SBOM, signs with Sigstore, records build provenance, and uploads everything
to a draft release, which it publishes after downloading and comparing every asset.

If the source is at fault, fix it in a new commit and release a new version; never move or recreate
a tag. For a transient failure, re-run the workflow for the same tag. A failure during upload or
comparison leaves a draft release, which you must delete before re-running.

## Verify a release

Each release has nine assets. GitHub's generated source archives are not among them and are not
attested.

| Asset | Contents |
|---|---|
| `autocontribute-<version>.tar.gz` | Source distribution |
| `autocontribute-<version>-py3-none-any.whl` | Wheel |
| `autocontribute-<version>.cdx.json` | CycloneDX SBOM of the runtime dependencies |
| `SHA256SUMS` | SHA-256 checksums of the three files above |
| `<file>.sigstore.json` | Sigstore bundle for each of the four files above |
| `autocontribute-<version>.provenance.sigstore.json` | Signed GitHub build provenance |

Download the assets and check the checksums, GitHub provenance and every Sigstore bundle:

```bash
repository=Damadimo/autocontribute
tag=v0.1.0
gh release download "$tag" --repo "$repository" --dir "$tag"
(cd "$tag" && sha256sum --check --strict SHA256SUMS)
for subject in "$tag"/autocontribute-*.tar.gz "$tag"/autocontribute-*.whl "$tag"/autocontribute-*.cdx.json
do
  gh attestation verify "$subject" --repo "$repository"
done
certificate_identity="https://github.com/${repository}/.github/workflows/release.yml@refs/tags/${tag}"
for subject in "$tag"/autocontribute-*.tar.gz "$tag"/autocontribute-*.whl \
  "$tag"/autocontribute-*.cdx.json "$tag"/SHA256SUMS
do
  uvx --from sigstore==4.3.0 sigstore verify identity \
    --bundle "$subject.sigstore.json" \
    --cert-identity "$certificate_identity" \
    --cert-oidc-issuer https://token.actions.githubusercontent.com \
    "$subject"
done
```

See [Install an immutable release](systemd-deployment.md#install-an-immutable-release) to deploy it.
