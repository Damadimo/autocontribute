# Sandbox toolchain images

Every validation command runs inside one digest-pinned Docker image with networking disabled
(`sandbox.network` is always `none`). Nothing can be downloaded or installed at validation time, so
the image must already contain the complete offline toolchain — interpreters, test runners, linters,
and every project dependency — for **all** configured repositories. `sandbox.image` is a single
global setting: if the configured repositories need different ecosystems, the one image must carry
the union of their toolchains, or the repository list must be split across separate deployments.

A bare interpreter base image such as `python:3.12-bookworm` satisfies only validation recipes that
use the standard library alone (the staging fixture is deliberately built this way). It cannot run
`python -m pytest` or install a real project's dependencies, and `doctor` fails such a configuration
before any contribution work starts: it launches the exact pinned image offline and probes the
executables and explicit `python -m` modules named by `validation.required_commands`. Treat a doctor
toolchain failure as a missing image ingredient, never as a reason to weaken the validation recipe
or to relax the offline boundary. Repository-relative entrypoints (for example `tools/lint.py`) are
deliberately not probed by doctor; they are exercised by the real isolated validation run.

## Requirements

- **Digest-pinned.** Configuration rejects a Docker image without `@sha256:<64 hex digits>`. A tag
  can be repointed upstream at any time; a digest cannot, so scheduled runs can never silently pick
  up a different toolchain.
- **Complete and offline.** Every executable and Python module named by any repository's
  `validation.required_commands` must already be importable/executable in the image, along with the
  full dependency closure the target repositories need to build and test.
- **Pre-pulled.** Pull the digest before running `doctor`. Sandbox and doctor containers launch
  with `--pull=never`, and the packaged systemd deployment runs Docker on a separately bounded
  filesystem sized for pre-pulled images.
- **Boring and reproducible.** Build from a digest-pinned base with pinned (ideally hash-verified)
  dependency versions so the image can be rebuilt and audited later.

## Build, pin, and verify

Build one image per deployment that layers the required toolchain onto a digest-pinned base:

```dockerfile
# Dockerfile.sandbox — example for Python repositories validated with pytest
FROM python:3.12-bookworm@sha256:<base-digest>
COPY requirements-sandbox.txt /tmp/requirements-sandbox.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements-sandbox.txt
```

`requirements-sandbox.txt` should pin exact versions with hashes and include the test toolchain
(`pytest` and friends) plus each configured repository's dependency closure. Regenerate it from the
target repositories' own lock/requirements files when they change.

Push the image to a registry you control, then record the immutable digest reference:

```bash
docker build -f Dockerfile.sandbox -t registry.example.com/autocontribute/sandbox:2026-08-14 .
docker push registry.example.com/autocontribute/sandbox:2026-08-14
docker inspect --format '{{index .RepoDigests 0}}' \
  registry.example.com/autocontribute/sandbox:2026-08-14
```

Put the printed `repository@sha256:…` reference into `sandbox.image`. Never put the tag form into
configuration; the digest is what makes the toolchain immutable.

## Pre-pull for the deployment that runs it

For local review use, `docker pull <repository@sha256:…>` as the operating user is enough. For the
packaged systemd deployment, the sandbox talks only to the dedicated rootless daemon, so pull as the
`autocontribute` service account through its socket before running doctor:

```bash
sudo -u autocontribute \
  DOCKER_HOST=unix:///run/autocontribute/docker.sock \
  docker pull registry.example.com/autocontribute/sandbox@sha256:<digest>
```

Confirm the bounded Docker filesystem retains comfortable headroom afterward; the deployment guide's
storage checks treat that filesystem as an aggregate ceiling across images, layers, and container
writable layers (see [systemd-deployment.md](systemd-deployment.md)).

## Rotation

To pick up new dependency versions, rebuild, push, record the new digest, pre-pull it, update
`sandbox.image`, and rerun `autocontribute doctor` before the next scheduled run. The sandbox block
is part of the preparation configuration fingerprint: changing the image is a material configuration
change, so a guarded-auto deployment starts a new calibration cohort and re-earns automatic
publication under the new toolchain. Keep the previous digest available until every in-flight
prepared contribution has been approved or expired, then prune old images from the bounded
filesystem deliberately.
