# Sandbox image

Validation commands run in a Docker container with no network, so the image in `sandbox.image` must
already contain each configured repository's toolchain and test dependencies. One image serves
every configured repository; give repositories with conflicting toolchains separate configuration
files. The starter configuration's `example.invalid` image is a placeholder: `config validate`,
`doctor`, `discover`, and `run` refuse it.

## Requirements

| The image must | Checked by |
| --- | --- |
| Be pinned by digest (`name@sha256:<64 hex digits>`); a tag alone is rejected | Configuration loading |
| Be pulled before use; containers never pull | `doctor`: `sandbox image` |
| Provide `/usr/bin/env`, `/bin/sh`, and `cat` (distroless images fail) | `doctor`: `sandbox private bind mount` |
| Contain every executable and `python -m` module named in `validation.required_commands` | `doctor`: `offline validation toolchain` |

Commands start in `/workspace`, where the patched checkout is mounted. The image's `ENTRYPOINT`,
`CMD`, `ENV`, `USER`, and `WORKDIR` are ignored: commands get `HOME=/tmp` and a standard `PATH`, so
install executables in `/usr/local/bin` or `/usr/bin` (a virtualenv on `ENV PATH` is not used). The
root filesystem is read-only; only `/workspace` and a 512 MB `/tmp` are writable. Doctor skips
repository scripts such as `tools/lint.py` and commands the model adds.

## Test the patched source

Tests must import the patched source in `/workspace`. If the image holds an installed copy of a
src-layout package (for example from `pip install .`), tests can import that copy and test unpatched
code. Install each repository's dependencies, not a regular copy of the repository, and use either:

- `PYTHONPATH=src` in `validation.required_commands`: `PYTHONPATH=src python -m pytest`.
  `ENV PYTHONPATH` in the Dockerfile has no effect.
- An editable install made from `/workspace` at build time (copy the repository there, then
  `pip install --no-deps -e /workspace`). It resolves to the patched checkout mounted over it.

## Build, pin, and pre-pull

```dockerfile
# Dockerfile.sandbox for Python repositories tested with pytest. requirements-sandbox.txt pins
# pytest and each repository's test dependencies with hashes (uv pip compile --generate-hashes).
FROM python:3.12-bookworm@sha256:<base-digest>
COPY requirements-sandbox.txt /tmp/
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements-sandbox.txt
```

```bash
docker build -f Dockerfile.sandbox -t registry.example.com/you/sandbox:2026-10-21 .
docker push registry.example.com/you/sandbox:2026-10-21
docker inspect --format '{{index .RepoDigests 0}}' registry.example.com/you/sandbox:2026-10-21
# Set sandbox.image to the printed reference, pull it where validation runs, then check:
docker pull registry.example.com/you/sandbox@sha256:<digest>
autocontribute doctor
```

## Rotate

1. Approve and publish, or cancel (`autocontribute runs cancel RUN_ID --reason "..."`), every run
   waiting for approval or publication: `approve` and `publish` refuse runs prepared with an older
   `sandbox.image`.
2. Build, push, and pre-pull the new image, update `sandbox.image`, and run `autocontribute doctor`.
3. Remove the old image with `docker image rm`.
