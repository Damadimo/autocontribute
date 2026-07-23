# Ubuntu deployment/recovery acceptance

`ubuntu_24_04_deployment_recovery.sh` exercises the operator-managed deployment on the exact
supported host baseline without model or GitHub credentials. It installs the committed release at
the production paths, verifies both the source and installed asset manifests, proves installed
drift is rejected, provisions disposable bounded ext4 state and backup filesystems, and starts the
real hardened backup service. It then rejects a checksummed-bundle tamper, restores the trusted
bundle into an absent recovery root, verifies the recovered ledger and evidence, and proves a
second restore cannot overwrite that generation.

The test is intentionally host-level rather than a container approximation. Run it only on a
disposable Ubuntu Server 24.04 amd64 host with systemd 255 as PID 1, loop-device support, `uv`, and
passwordless `sudo` for the invoking non-root administrator:

```bash
tests/acceptance/ubuntu_24_04_deployment_recovery.sh
```

The release is made from `git archive HEAD`, so commit the exact tree you intend to test first. The
script refuses to run if the `autocontribute` account or any managed production root already exists.
It never enables a timer or starts the worker, doctor, or rootless Docker service; only the
credential-free backup service is started. Every production tree that cleanup removes recursively
is tagged with a unique run marker, and cleanup refuses that removal when the marker differs. CI
runs the same script in the `ubuntu-deployment-recovery` job.

The signed-tag release workflow instead passes an already safely extracted sdist explicitly:

```bash
tests/acceptance/ubuntu_24_04_deployment_recovery.sh \
  --source-root /absolute/path/to/autocontribute-VERSION
```

That path must be an exact, non-symlinked source-distribution root with `PKG-INFO`, no Git or virtual
environment state, only regular files and directories, and a build-identity manifest matching its
exact `pyproject.toml` and `uv.lock`. This mode installs the extracted distribution itself and never
substitutes files from the checkout that launched the test.
