# Ubuntu deployment and recovery acceptance test

`ubuntu_24_04_deployment_recovery.sh` tests the operator-managed deployment without model or GitHub
credentials. It checks the installation assets, filesystem boundaries, the hardened backup service,
bundle tamper detection, recovery into an absent state root, and overwrite prevention.

## Requirements

Run it only on a disposable host with:

- Ubuntu Server 24.04 amd64
- systemd 255 as PID 1
- Loop-device support
- `uv`
- Passwordless `sudo` for the non-root administrator who runs it

The script stops if the `autocontribute` account or any managed production root already exists.

## Run from a checkout

The default mode builds the release with `git archive HEAD`, so commit the tree under test first.
CI runs this mode in the `ubuntu-deployment-recovery` job.

```bash
tests/acceptance/ubuntu_24_04_deployment_recovery.sh
```

## Run from a source distribution

The release workflow passes an extracted source distribution:

```bash
tests/acceptance/ubuntu_24_04_deployment_recovery.sh \
  --source-root /absolute/path/to/autocontribute-VERSION
```

The source root must be an absolute, non-symlinked directory that contains `PKG-INFO`, holds only
regular files and directories, has no Git or virtual-environment state, and has a build identity
matching its `pyproject.toml` and `uv.lock`. This mode installs only that distribution.

## Safety

The test starts only the credential-free backup service. It never enables a timer or starts the
worker, doctor, or rootless Docker service. Cleanup refuses to remove any production tree that does
not carry this run's unique marker.
