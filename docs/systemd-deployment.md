# Operator-managed systemd deployment

This bundle runs one Autocontribute installation on a Linux host: the worker at 09:17 and 21:17
UTC, a verified complete backup at 03:17 UTC, S3 replication retries hourly at `*:37 UTC`, and a
health check every 15 minutes. Worker, doctor, backup, and replication share the lock
`/var/lib/autocontribute/operation.lock`. Never run a second host or the hosted scheduler against
the same state. The units never enable automatic publication; start in `review_required` mode.

## Deployment boundary

| Path | Owner and mode | Purpose |
| --- | --- | --- |
| `/opt/autocontribute/releases/<revision>` | `root:root`, not writable by the service | Immutable release and virtual environment |
| `/opt/autocontribute/current` | `root:root` symlink | Selected release |
| `/etc/autocontribute/autocontribute.yml` | `root:autocontribute`, `0640` | Reviewed configuration, no secrets |
| `/etc/autocontribute/rootless-docker-daemon.json` | `root:autocontribute`, `0640` | Rootless Docker daemon configuration |
| `/etc/autocontribute/credentials/*.cred` | `root:root`, `0600` | Encrypted systemd credentials |
| `/etc/autocontribute/alert-webhook` | `root:root`, `0600`, optional | One `https://` failure-alert webhook URL; alerting is skipped while absent |
| `/etc/autocontribute/s3-replication.enabled` | `root:root`, `0400` | Marker that turns on the replication service |
| `/var/lib/autocontribute` | `root:autocontribute`, `0750` | Service home, not writable by the service |
| `/var/lib/autocontribute/state` | `autocontribute:autocontribute`, `0700` | SQLite, run evidence, and evaluations (dedicated mount) |
| `/var/lib/autocontribute/state/workspaces` | `autocontribute:autocontribute`, `0700` | Target repository checkouts (dedicated mount) |
| `/var/lib/autocontribute/docker` | `autocontribute:autocontribute`, `0710` | Rootless Docker images and layers (dedicated mount) |
| `/var/lib/autocontribute/tmp` | `autocontribute:autocontribute`, `0700` | Temporary files the rootless daemon can read |
| `/var/backups/autocontribute` | `autocontribute:autocontribute`, `0700` | Complete bundles awaiting off-host replication (dedicated mount) |
| `/run/autocontribute` | `autocontribute:autocontribute`, `0700` | Rootless Docker runtime directory and its only socket |

Each dedicated mount must be ext4 on its own fully allocated block device (no thin volume, sparse
loop file, or network filesystem), mounted at one path and not as a bind mount. The services check
these hard limits before they do any work and stop when one is not met:

- State, `rw,nodev,nosuid,noexec`: the state filesystem is capped at 8 GiB and 262,144 inodes and
  must keep at least 1 GiB and 32,768 inodes available.
- Backups, `rw,nodev,nosuid,noexec`: the backup filesystem is capped at 64 GiB and 524,288 inodes
  and must keep at least 20 GiB and 262,144 inodes available.
- Workspaces, `rw,nodev,nosuid`: at most 21,474,836,480 bytes (20 GiB) and 524,288 inodes. A run
  starts only with at least 4 GiB and 65,536 inodes available.
- Docker data, `rw,nodev,nosuid`: at most 32 GiB (34,359,738,368 bytes) and
  1,048,576 fixed inodes, with at least 1 GiB (1,073,741,824 bytes) and 16,384 inodes available.

## Host prerequisites

The supported host is Ubuntu Server 24.04 LTS on `amd64` with systemd 255; the rootless Docker
supervisor stops on any other systemd layout. The host also needs Python 3.11 or 3.12, Git, `flock`,
GNU coreutils, util-linux `findmnt`, e2fsprogs, rootless Docker on cgroup v2 with systemd controller
delegation, four dedicated block devices, time synchronization, and outbound HTTPS to GitHub, the
model API, and AWS S3.

Create the service account. Its home stays root-owned so it cannot install its own systemd user
units. Check the example subordinate ID range against `/etc/subuid` and `/etc/subgid` first:

```bash
sudo useradd --system \
  --user-group \
  --home-dir /var/lib/autocontribute \
  --shell /usr/sbin/nologin autocontribute
sudo install -d -o root -g autocontribute -m 0750 /var/lib/autocontribute
sudo usermod --add-subuids 200000-265535 --add-subgids 200000-265535 autocontribute
test "$(id -gn autocontribute)" = autocontribute
test "$(stat --format=%U:%G:%a -- /var/lib/autocontribute)" = root:autocontribute:750
getent group autocontribute
```

Never add the account to the `docker` group or give it `/var/run/docker.sock`: either is
root-equivalent, and the services refuse to start. Never change its UID; reprovision the host.

### Provision bounded state and local-backup filesystems

Reference sizes: 6 GiB for state and 48 GiB for backups. **`mkfs.ext4` destroys all data on its
argument. Verify both device names first:**

```bash
state_device=/dev/mapper/autocontribute-state
backup_device=/dev/mapper/autocontribute-backups
test -b "$state_device"
test -b "$backup_device"
test "$state_device" != "$backup_device"
test -z "$(findmnt --noheadings --source "$state_device")"
test -z "$(findmnt --noheadings --source "$backup_device")"
sudo mkfs.ext4 -L autocontribute-state -m 1 -N 131072 -- "$state_device"
sudo mkfs.ext4 -L autocontribute-backups -m 0 -N 393216 -- "$backup_device"
sudo install -d -o autocontribute -g autocontribute -m 0700 \
  /var/lib/autocontribute/state \
  /var/backups/autocontribute
sudo blkid --output value --match-tag UUID -- "$state_device"
sudo blkid --output value --match-tag UUID -- "$backup_device"
unset state_device backup_device
```

Add each UUID to `/etc/fstab`:

```fstab
UUID=STATE_UUID_FROM_BLKID /var/lib/autocontribute/state ext4 rw,nodev,nosuid,noexec 0 2
UUID=BACKUP_UUID_FROM_BLKID /var/backups/autocontribute ext4 rw,nodev,nosuid,noexec 0 2
```

Mount both, set ownership, and check the totals as the service account:

```bash
sudo mount /var/lib/autocontribute/state
sudo mount /var/backups/autocontribute
sudo chown autocontribute:autocontribute \
  /var/lib/autocontribute/state \
  /var/backups/autocontribute
sudo chmod 0700 \
  /var/lib/autocontribute/state \
  /var/backups/autocontribute
findmnt --target /var/lib/autocontribute/state --output TARGET,SOURCE,FSTYPE,OPTIONS
findmnt --target /var/backups/autocontribute --output TARGET,SOURCE,FSTYPE,OPTIONS
sudo -u autocontribute stat --file-system \
  --format='block_size=%S blocks=%b available=%a inodes=%c free_inodes=%d' \
  /var/lib/autocontribute/state \
  /var/backups/autocontribute
```

### Provision the bounded workspace filesystem

Create this only after the state mount is active. Reference size: 16 GiB. Verify the device first:

```bash
workspace_device=/dev/mapper/autocontribute-workspaces
test -b "$workspace_device"
test -z "$(findmnt --noheadings --source "$workspace_device")"
sudo mkfs.ext4 -L autocontribute-workspaces -m 0 -N 262144 -- "$workspace_device"
sudo install -d -o autocontribute -g autocontribute -m 0700 \
  /var/lib/autocontribute/state/workspaces
sudo blkid --output value --match-tag UUID -- "$workspace_device"
unset workspace_device
```

```fstab
UUID=UUID_FROM_BLKID /var/lib/autocontribute/state/workspaces ext4 rw,nodev,nosuid 0 2
```

```bash
sudo mount /var/lib/autocontribute/state/workspaces
sudo chown autocontribute:autocontribute /var/lib/autocontribute/state/workspaces
sudo chmod 0700 /var/lib/autocontribute/state/workspaces
findmnt --target /var/lib/autocontribute/state/workspaces \
  --output TARGET,SOURCE,FSTYPE,OPTIONS
stat --file-system \
  --format='block_size=%S blocks=%b inodes=%c available_blocks=%a free_inodes=%d' \
  /var/lib/autocontribute/state/workspaces
```

### Provision the bounded rootless Docker data filesystem

Reference size: 24 GiB; size it for your pinned sandbox images. Verify the device first:

```bash
docker_data_device=/dev/mapper/autocontribute-docker
test -b "$docker_data_device"
test -z "$(findmnt --noheadings --source "$docker_data_device")"
sudo mkfs.ext4 -L autocontribute-docker -m 0 -N 524288 -- "$docker_data_device"
sudo install -d -o autocontribute -g autocontribute -m 0710 \
  /var/lib/autocontribute/docker
sudo blkid --output value --match-tag UUID -- "$docker_data_device"
unset docker_data_device
```

```fstab
UUID=DOCKER_UUID_FROM_BLKID /var/lib/autocontribute/docker ext4 rw,nodev,nosuid 0 2
```

```bash
sudo mount /var/lib/autocontribute/docker
sudo chown autocontribute:autocontribute /var/lib/autocontribute/docker
sudo chmod 0710 /var/lib/autocontribute/docker
findmnt --target /var/lib/autocontribute/docker \
  --output TARGET,SOURCE,FSTYPE,OPTIONS
stat --file-system \
  --format='block_size=%S blocks=%b inodes=%c available_blocks=%a available_inodes=%d' \
  /var/lib/autocontribute/docker
```

Install your distribution's rootless Docker packages (`dockerd-rootless.sh`, `rootlesskit`,
`newuidmap`, `newgidmap`, `fuse-overlayfs`, a user D-Bus), binaries only. Never run
`dockerd-rootless-setuptool.sh install`: the services refuse the `docker.service` and socket it
creates. Check the binaries:

```bash
test -x /usr/bin/dockerd-rootless.sh
test -x /usr/bin/rootlesskit
test -x /usr/bin/newuidmap
test -x /usr/bin/newgidmap
test -x /usr/bin/fuse-overlayfs
test "$(stat --format=%U -- /usr/bin/dockerd-rootless.sh)" = root
```

`autocontribute-rootless-docker.service` starts and stops the daemon; never enable the user unit
`autocontribute-rootless-docker-daemon.service` yourself. Create the daemon configuration:

```bash
sudo install -d -o root -g autocontribute -m 0750 /etc/autocontribute
sudoedit /etc/autocontribute/rootless-docker-daemon.json
sudo chown root:autocontribute /etc/autocontribute/rootless-docker-daemon.json
sudo chmod 0640 /etc/autocontribute/rootless-docker-daemon.json
python3 -m json.tool /etc/autocontribute/rootless-docker-daemon.json >/dev/null
test "$(stat --format=%U:%G:%a -- \
  /etc/autocontribute/rootless-docker-daemon.json)" = root:autocontribute:640
```

```json
{
  "storage-driver": "fuse-overlayfs"
}
```

Do not add `group` (the launcher passes `--group=0`, and Docker refuses an option set twice) or a
TCP listener. Do not start the daemon yet.

## Install an immutable release

Extract a sanitized, provenance-attested Git archive or source distribution as `root:root` into a
new directory below `/opt/autocontribute/releases/`. Verify its digest and complete file inventory
against the attestation first. Never deploy a working checkout: `.git`, untracked files, hooks,
local uv configuration, and dotenv files can hold credentials or change a build that runs as root.
Install uv 0.9.30 at `/usr/local/bin/uv` (`root:root`, `0755`) after checking its vendor digest.
Replace `FULL_COMMIT` and run:

```bash
set -Eeuo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
application_root=/opt/autocontribute
releases_root="${application_root}/releases"
release="${releases_root}/FULL_COMMIT"
uv_binary=/usr/local/bin/uv
sudo test -f "$uv_binary"
sudo test ! -L "$uv_binary"
sudo test -x "$uv_binary"
test "$(sudo readlink --canonicalize-existing -- "$uv_binary")" = "$uv_binary"
test "$(sudo stat --format='%u:%g' -- "$uv_binary")" = 0:0
uv_mode="$(sudo stat --format='%a' -- "$uv_binary")" || exit 1
[[ "$uv_mode" =~ ^[0-7]{1,4}$ ]]
(( (8#$uv_mode & 8#7022) == 0 ))
test "$(
  sudo /usr/bin/env -i \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    "$uv_binary" --version
)" = "uv 0.9.30"
unset uv_mode
for trusted_directory in /opt "$application_root" "$releases_root"; do
  sudo test -d "$trusted_directory"
  sudo test ! -L "$trusted_directory"
  test "$(sudo readlink --canonicalize-existing -- "$trusted_directory")" = \
    "$trusted_directory"
  test "$(sudo stat --format='%u:%g' -- "$trusted_directory")" = 0:0
  trusted_mode="$(sudo stat --format='%a' -- "$trusted_directory")" || exit 1
  [[ "$trusted_mode" =~ ^[0-7]{1,4}$ ]]
  (( (8#$trusted_mode & 8#7022) == 0 ))
  (( (8#$trusted_mode & 8#0555) == 8#0555 ))
  sudo -u autocontribute test -x "$trusted_directory"
done
unset trusted_directory trusted_mode
sudo test -d "$release"
sudo test ! -L "$release"
test "$(sudo readlink --canonicalize-existing -- "$release")" = "$release"
release_identity="$(sudo stat --format='%d:%i' -- "$release")" || exit 1
[[ "$release_identity" =~ ^[0-9]+:[0-9]+$ ]]

release_mount_at_or_below() {
  /usr/bin/findmnt --noheadings --raw --output TARGET | \
    /usr/bin/awk -v root="$release" \
      '$0 == root || index($0, root "/") == 1 { print }'
}

release_mount="$(release_mount_at_or_below)" || exit 1
test -z "$release_mount"
unsafe_source_path="$(
  sudo find "$release" -xdev \( ! -uid 0 -o ! -gid 0 \) -print -quit
)" || exit 1
test -z "$unsafe_source_path"
unsafe_source_path="$(
  sudo find "$release" -xdev ! -type l -perm /7022 -print -quit
)" || exit 1
test -z "$unsafe_source_path"
preexisting_venv="$(
  sudo find "$release" -xdev -mindepth 1 -maxdepth 1 \
    -name .venv -print -quit
)" || exit 1
test -z "$preexisting_venv"
development_state="$(
  sudo find "$release" -xdev \
    \( -name .git -o -name .env -o -name '.env.*' -o -name uv.toml \) \
    -print -quit
)" || exit 1
test -z "$development_state"
unsafe_source_path="$(
  sudo find "$release" -xdev ! \( -type d -o -type f \) -print -quit
)" || exit 1
test -z "$unsafe_source_path"
unsafe_source_path="$(
  sudo find "$release" -xdev -type f -links +1 -print -quit
)" || exit 1
test -z "$unsafe_source_path"
unset development_state preexisting_venv release_mount unsafe_source_path

sudo find "$release" -xdev -exec chown -h root:root -- {} +
sudo find "$release" -xdev ! -type l -exec chmod u=rwX,go=rX -- {} +
test "$(sudo readlink --canonicalize-existing -- "$release")" = "$release"
test "$(sudo stat --format='%d:%i' -- "$release")" = "$release_identity"
release_mount="$(release_mount_at_or_below)" || exit 1
test -z "$release_mount"
unsafe_release_path="$(
  sudo find "$release" -xdev \( ! -uid 0 -o ! -gid 0 \) -print -quit
)" || exit 1
test -z "$unsafe_release_path"
unsafe_release_path="$(
  sudo find "$release" -xdev ! -type l -perm /7022 -print -quit
)" || exit 1
test -z "$unsafe_release_path"
unsafe_release_path="$(
  sudo find "$release" -xdev -type d ! -perm -0555 -print -quit
)" || exit 1
test -z "$unsafe_release_path"
unsafe_release_path="$(
  sudo find "$release" -xdev -type f ! -perm -0444 -print -quit
)" || exit 1
test -z "$unsafe_release_path"
preexisting_venv="$(
  sudo find "$release" -xdev -mindepth 1 -maxdepth 1 \
    -name .venv -print -quit
)" || exit 1
test -z "$preexisting_venv"
development_state="$(
  sudo find "$release" -xdev \
    \( -name .git -o -name .env -o -name '.env.*' -o -name uv.toml \) \
    -print -quit
)" || exit 1
test -z "$development_state"
unsafe_source_path="$(
  sudo find "$release" -xdev ! \( -type d -o -type f \) -print -quit
)" || exit 1
test -z "$unsafe_source_path"
unsafe_source_path="$(
  sudo find "$release" -xdev -type f -links +1 -print -quit
)" || exit 1
test -z "$unsafe_source_path"
unset development_state preexisting_venv release_mount unsafe_release_path unsafe_source_path

sudo /usr/bin/env -i \
  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  UV_LINK_MODE=copy \
  UV_PROJECT_ENVIRONMENT="$release/.venv" \
  "$uv_binary" sync \
    --project "$release" \
    --frozen --no-dev --no-editable \
    --no-config --no-python-downloads \
    --python /usr/bin/python3
test "$(sudo readlink --canonicalize-existing -- "$release")" = "$release"
test "$(sudo stat --format='%d:%i' -- "$release")" = "$release_identity"
release_mount="$(release_mount_at_or_below)" || exit 1
test -z "$release_mount"
unset release_mount
sudo find "$release" -xdev -exec chown -h root:root -- {} +
sudo find "$release" -xdev ! -type l -exec chmod u=rwX,go=rX -- {} +
test "$(sudo readlink --canonicalize-existing -- "$release")" = "$release"
test "$(sudo stat --format='%d:%i' -- "$release")" = "$release_identity"
release_mount="$(release_mount_at_or_below)" || exit 1
test -z "$release_mount"
unsafe_release_path="$(
  sudo find "$release" -xdev \( ! -uid 0 -o ! -gid 0 \) -print -quit
)" || exit 1
test -z "$unsafe_release_path"
unsafe_release_path="$(
  sudo find "$release" -xdev ! -type l -perm /7022 -print -quit
)" || exit 1
test -z "$unsafe_release_path"
unsafe_release_path="$(
  sudo find "$release" -xdev -type d ! -perm -0555 -print -quit
)" || exit 1
test -z "$unsafe_release_path"
unsafe_release_path="$(
  sudo find "$release" -xdev -type f ! -perm -0444 -print -quit
)" || exit 1
test -z "$unsafe_release_path"
unsafe_release_path="$(
  sudo find "$release" -xdev ! \( -type d -o -type f -o -type l \) -print -quit
)" || exit 1
test -z "$unsafe_release_path"
unsafe_release_path="$(
  sudo find "$release" -xdev -type f -links +1 -print -quit
)" || exit 1
test -z "$unsafe_release_path"
unset release_mount release_identity unsafe_release_path
sudo test -d "$release/.venv"
sudo test ! -L "$release/.venv"
test "$(sudo readlink --canonicalize-existing -- "$release/.venv")" = \
  "$release/.venv"
sudo test -d "$release/.venv/bin"
sudo test ! -L "$release/.venv/bin"
test "$(sudo readlink --canonicalize-existing -- "$release/.venv/bin")" = \
  "$release/.venv/bin"
sudo test -f "$release/.venv/bin/autocontribute"
sudo test ! -L "$release/.venv/bin/autocontribute"
sudo test -x "$release/.venv/bin/autocontribute"
test "$(sudo readlink --canonicalize-existing -- \
  "$release/.venv/bin/autocontribute")" = "$release/.venv/bin/autocontribute"
system_python="$(sudo readlink --canonicalize-existing -- /usr/bin/python3)" || exit 1
venv_python="$(sudo readlink --canonicalize-existing -- \
  "$release/.venv/bin/python")" || exit 1
test "$venv_python" = "$system_python"
unset system_python venv_python
sudo -u autocontribute /usr/bin/env -i \
  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  PYTHONNOUSERSITE=1 \
  "$release/.venv/bin/python" -I - "$release" <<'PY'
import os
import pwd
import sys
from pathlib import Path

release = Path(sys.argv[1]).resolve(strict=True)
venv = release / ".venv"
if os.getuid() != pwd.getpwnam("autocontribute").pw_uid:
    raise SystemExit("release import probe did not run as the service identity")

from autocontribute import store

module = Path(store.__file__).resolve(strict=True)
try:
    module.relative_to(venv)
except ValueError as exc:
    raise SystemExit("release import did not use the installed immutable package") from exc
PY
sudo -u autocontribute /usr/bin/env -i \
  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  PYTHONNOUSERSITE=1 \
  "$release/.venv/bin/autocontribute" \
  deployment verify-systemd-assets --source-root "$release"
```

The script stops at the first failed check. Its last command checks the release's `deploy/systemd`
files against the manifest shipped in the release. Never repoint `current` while a unit is active.

## Install configuration and encrypted credentials

Start from `autocontribute.example.yml` and replace its placeholders: `config validate`, `doctor`,
and `run` refuse to proceed until you do. [Configuration](configuration.md) describes every key.
For this deployment, set at least:

```yaml
github:
  auth: token
  token_env: AUTOCONTRIBUTE_GITHUB_TOKEN

sandbox:
  backend: docker
  image: repository/image@sha256:FULL_DIGEST

publishing:
  mode: review_required

storage:
  path: /var/lib/autocontribute/state

s3_replication:
  bundle_directory: /var/backups/autocontribute
  receipt_directory: /var/backups/autocontribute/receipts
  scratch_directory: /var/backups/autocontribute/replication-scratch
  bucket: your-object-lock-bucket
  expected_bucket_owner: "123456789012"
  region: ca-central-1
  prefix: production/worker-1
```

[Immutable S3 backup replication](s3-backup-replication.md) covers the other `s3_replication` keys
and the AWS setup. Install the file so the service can read but not change it:

```bash
sudo install -d -o root -g autocontribute -m 0750 /etc/autocontribute
sudo install -o root -g autocontribute -m 0640 \
  /path/to/reviewed-autocontribute.yml \
  /etc/autocontribute/autocontribute.yml
sudo install -d -o root -g root -m 0700 /etc/autocontribute/credentials
```

Encrypt each credential with `systemd-creds` without putting it in arguments, shell history, or the
environment. Leave the AWS session token empty only for a long-lived key that has none:

```bash
read -rsp 'OpenAI API key: ' autocontribute_secret
printf '%s' "$autocontribute_secret" | sudo systemd-creds encrypt \
  --name=OPENAI_API_KEY - \
  /etc/autocontribute/credentials/OPENAI_API_KEY.cred
unset autocontribute_secret
printf '\n'

read -rsp 'GitHub token: ' autocontribute_secret
printf '%s' "$autocontribute_secret" | sudo systemd-creds encrypt \
  --name=AUTOCONTRIBUTE_GITHUB_TOKEN - \
  /etc/autocontribute/credentials/AUTOCONTRIBUTE_GITHUB_TOKEN.cred
unset autocontribute_secret
printf '\n'

read -rsp 'AWS access key ID: ' autocontribute_secret
printf '%s' "$autocontribute_secret" | sudo systemd-creds encrypt \
  --name=AWS_ACCESS_KEY_ID - \
  /etc/autocontribute/credentials/AWS_ACCESS_KEY_ID.cred
unset autocontribute_secret
printf '\n'

read -rsp 'AWS secret access key: ' autocontribute_secret
printf '%s' "$autocontribute_secret" | sudo systemd-creds encrypt \
  --name=AWS_SECRET_ACCESS_KEY - \
  /etc/autocontribute/credentials/AWS_SECRET_ACCESS_KEY.cred
unset autocontribute_secret
printf '\n'

read -rsp 'AWS session token (empty only for a credential without one): ' autocontribute_secret
printf '%s' "$autocontribute_secret" | sudo systemd-creds encrypt \
  --name=AWS_SESSION_TOKEN - \
  /etc/autocontribute/credentials/AWS_SESSION_TOKEN.cred
unset autocontribute_secret
printf '\n'

sudo chmod 0600 /etc/autocontribute/credentials/*.cred
sudo chown root:root /etc/autocontribute/credentials/*.cred
```

Only the replication service loads the AWS credentials. Use a model project with a hard spend
limit, a dedicated expiring GitHub token limited to the target repositories, and the
`autocontribute` account for nothing else. Never put a secret in `Environment=` or
`EnvironmentFile=`.

For a model key with another variable name, change both the worker and the doctor:

```bash
sudo install -d -o root -g root -m 0755 \
  /etc/systemd/system/autocontribute-worker.service.d \
  /etc/systemd/system/autocontribute-doctor.service.d
sudoedit \
  /etc/systemd/system/autocontribute-worker.service.d/40-provider-credentials.conf \
  /etc/systemd/system/autocontribute-doctor.service.d/40-provider-credentials.conf
```

Put this identical content in each file:

```ini
[Service]
LoadCredentialEncrypted=
LoadCredentialEncrypted=VENDOR_API_KEY:/etc/autocontribute/credentials/VENDOR_API_KEY.cred
LoadCredentialEncrypted=AUTOCONTRIBUTE_GITHUB_TOKEN:/etc/autocontribute/credentials/AUTOCONTRIBUTE_GITHUB_TOKEN.cred
Environment="AUTOCONTRIBUTE_CREDENTIAL_NAMES=VENDOR_API_KEY AUTOCONTRIBUTE_GITHUB_TOKEN"
```

Encrypt the key with `systemd-creds encrypt --name=VENDOR_API_KEY`, set `models.*.api_key_env` to
`VENDOR_API_KEY`, and confirm the two drop-ins are identical:

```bash
sudo cmp --silent -- \
  /etc/systemd/system/autocontribute-worker.service.d/40-provider-credentials.conf \
  /etc/systemd/system/autocontribute-doctor.service.d/40-provider-credentials.conf
sudo systemctl daemon-reload
```

To rotate a credential, write the new encrypted file beside the old one, set its owner and mode,
rename it over the old path, and start `autocontribute-doctor.service`. Rotate the three AWS files
together, then start `autocontribute-replication.service` and check its result.

### Optional outbound alert webhook

To send failure alerts to Slack, Discord, or another webhook, store one `https://` URL as a secret:

```bash
read -rsp 'Alert webhook URL: ' autocontribute_secret
printf '%s\n' "$autocontribute_secret" | sudo install -o root -g root -m 0600 \
  /dev/stdin /etc/autocontribute/alert-webhook
unset autocontribute_secret
printf '\n'
```

`autocontribute-alert@.service` has `ConditionPathExists=/etc/autocontribute/alert-webhook`, so
every alert instance is skipped cleanly until the file exists. The sender validates the file, and
its error messages never contain the URL. Delete the file to stop alerts.

## Install and validate the units

Use these steps for the first install and every upgrade. First stop every timer, service, the
rootless Docker proxy, and the `autocontribute` user manager:

```bash
set -Eeuo pipefail
release=/opt/autocontribute/releases/FULL_COMMIT
autocontribute_uid="$(id -u autocontribute)"
if [[ ! "$autocontribute_uid" =~ ^[1-9][0-9]*$ ]]; then
  printf '%s\n' 'The Autocontribute service UID must be a nonzero numeric UID' >&2
  exit 1
fi
manager_uids=("$autocontribute_uid")
stale_manager_policy=0
shopt -s nullglob
for manager_policy in \
  /etc/systemd/system/user@[0-9]*.service.d/50-autocontribute.conf
do
  manager_uid="${manager_policy#/etc/systemd/system/user@}"
  manager_uid="${manager_uid%.service.d/50-autocontribute.conf}"
  if [[ ! "$manager_uid" =~ ^[1-9][0-9]*$ ]]; then
    printf 'Unsafe Autocontribute user-manager policy path: %s\n' \
      "$manager_policy" >&2
    exit 1
  fi
  manager_uids+=("$manager_uid")
  if [[ "$manager_uid" != "$autocontribute_uid" ]]; then
    stale_manager_policy=1
  fi
done
shopt -u nullglob
mapfile -t manager_uids < <(
  printf '%s\n' "${manager_uids[@]}" | LC_ALL=C sort -u
)
unset manager_policy manager_uid

for unit in \
  autocontribute-worker.timer \
  autocontribute-backup.timer \
  autocontribute-replication.timer \
  autocontribute-health.timer
do
  if sudo systemctl cat "$unit" >/dev/null 2>&1; then
    sudo systemctl disable --now "$unit"
    test "$(sudo systemctl show --property=ActiveState --value "$unit")" = inactive
  fi
done
for unit in \
  autocontribute-worker.service \
  autocontribute-backup.service \
  autocontribute-replication.service \
  autocontribute-doctor.service \
  autocontribute-health.service \
  autocontribute-rootless-docker.service
do
  if sudo systemctl cat "$unit" >/dev/null 2>&1; then
    sudo systemctl stop "$unit"
    test "$(sudo systemctl show --property=ActiveState --value "$unit")" = inactive
  fi
done
active_units="$(sudo systemctl list-units \
  --state=active,activating,deactivating,reloading \
  --no-legend --plain --no-pager \
  'autocontribute-*.service' 'autocontribute-*.timer')"
test -z "$active_units"
unset active_units
if sudo test -S "/run/user/${autocontribute_uid}/bus"; then
  for unit in docker.service autocontribute-rootless-docker-daemon.service; do
    if sudo -u autocontribute env \
      HOME=/var/lib/autocontribute \
      XDG_RUNTIME_DIR="/run/user/${autocontribute_uid}" \
      DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${autocontribute_uid}/bus" \
      systemctl --user cat "$unit" >/dev/null 2>&1
    then
      sudo -u autocontribute env \
        HOME=/var/lib/autocontribute \
        XDG_RUNTIME_DIR="/run/user/${autocontribute_uid}" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${autocontribute_uid}/bus" \
        systemctl --user stop "$unit"
    fi
  done
fi
for manager_uid in "${manager_uids[@]}"; do
  sudo systemctl stop "user@${manager_uid}.service"
  test "$(sudo systemctl show --property=ActiveState --value \
    "user@${manager_uid}.service")" = inactive
done
unset manager_uid
if [[ "$stale_manager_policy" -ne 0 ]]; then
  printf '%s\n' \
    'A stale Autocontribute user-manager UID was quiesced; restore the immutable service UID or reprovision the host' >&2
  exit 1
fi
unset manager_uids stale_manager_policy
```

If it reports a stale user-manager UID, restore the original UID or reprovision the host. Archive
and remove any retired unit files that `deployment verify-systemd-assets` reports, such as
`/etc/systemd/user/docker.service` or `/etc/systemd/system/user@.service.d/delegate.conf`.

Then install and verify the files, switch `current`, and start the rootless Docker proxy. Keep every
service stopped until this block succeeds:

```bash
set -Eeuo pipefail
release=/opt/autocontribute/releases/FULL_COMMIT
autocontribute_uid="$(id -u autocontribute)"
if [[ ! "$autocontribute_uid" =~ ^[1-9][0-9]*$ ]]; then
  printf '%s\n' 'The Autocontribute service UID must be a nonzero numeric UID' >&2
  exit 1
fi

sudo install -d -o root -g root -m 0755 \
  /etc/systemd/system \
  /etc/systemd/user \
  /etc/tmpfiles.d \
  /usr/local/libexec
manager_dropin_directory="/etc/systemd/system/user@${autocontribute_uid}.service.d"
sudo install -d -o root -g root -m 0755 "$manager_dropin_directory"

for source in \
  "$release"/deploy/systemd/*.service \
  "$release"/deploy/systemd/*.timer
do
  destination="/etc/systemd/system/${source##*/}"
  sudo install -o root -g root -m 0644 -- "$source" "${destination}.next"
  sudo mv -Tf -- "${destination}.next" "$destination"
done
for source in "$release"/deploy/systemd/libexec/*
do
  destination="/usr/local/libexec/${source##*/}"
  sudo install -o root -g root -m 0755 -- "$source" "${destination}.next"
  sudo mv -Tf -- "${destination}.next" "$destination"
done

destination=/etc/tmpfiles.d/autocontribute.conf
sudo install -o root -g root -m 0644 -- \
  "$release/deploy/systemd/autocontribute.tmpfiles.conf" \
  "${destination}.next"
sudo mv -Tf -- "${destination}.next" "$destination"

destination="$manager_dropin_directory/50-autocontribute.conf"
sudo install -o root -g root -m 0644 -- \
  "$release/deploy/systemd/autocontribute-user-manager.conf" \
  "${destination}.next"
sudo mv -Tf -- "${destination}.next" "$destination"

destination=/etc/systemd/user/autocontribute-rootless-docker-daemon.service
sudo install -o root -g root -m 0644 -- \
  "$release/deploy/systemd/user/autocontribute-rootless-docker-daemon.service" \
  "${destination}.next"
sudo mv -Tf -- "${destination}.next" "$destination"

sudo "$release/.venv/bin/autocontribute" deployment verify-systemd-assets
sudo systemd-tmpfiles --create /etc/tmpfiles.d/autocontribute.conf
sudo systemctl daemon-reload
sudo loginctl enable-linger autocontribute
sudo systemctl restart "user@${autocontribute_uid}.service"
user_systemctl=(
  sudo -u autocontribute env
  HOME=/var/lib/autocontribute
  XDG_RUNTIME_DIR="/run/user/${autocontribute_uid}"
  DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${autocontribute_uid}/bus"
  systemctl --user --no-pager
)
"${user_systemctl[@]}" daemon-reload

for unit in \
  autocontribute-worker.service \
  autocontribute-worker.timer \
  autocontribute-backup.service \
  autocontribute-backup.timer \
  autocontribute-replication.service \
  autocontribute-replication.timer \
  autocontribute-doctor.service \
  autocontribute-health.service \
  autocontribute-health.timer \
  autocontribute-rootless-docker.service \
  'autocontribute-failure@.service' \
  'autocontribute-alert@.service'
do
  test "$(sudo systemctl show --property=NeedDaemonReload --value "$unit")" = no
done
manager_dropins="$(sudo systemctl show "user@${autocontribute_uid}.service" \
  --property=DropInPaths --value)"
expected_manager_dropin_count=0
for manager_dropin in $manager_dropins; do
  case "$manager_dropin" in
    "$manager_dropin_directory/50-autocontribute.conf")
      expected_manager_dropin_count=$((expected_manager_dropin_count + 1))
      ;;
    /usr/lib/systemd/system/user@.service.d/*.conf) ;;
    *) exit 1 ;;
  esac
  test "$(stat --format=%U:%G:%a -- "$manager_dropin")" = root:root:644
done
test "$expected_manager_dropin_count" = 1
test "$(sudo systemctl show "user@${autocontribute_uid}.service" \
  --property=FragmentPath --value)" = /usr/lib/systemd/system/user@.service
test "$(sudo systemctl show "user@${autocontribute_uid}.service" \
  --property=Transient --value)" = no
test "$(sudo systemctl show "user@${autocontribute_uid}.service" \
  --property=Delegate --value)" = yes
test "$(sudo systemctl show "user@${autocontribute_uid}.service" \
  --property=ControlGroup --value)" = \
  "/user.slice/user-${autocontribute_uid}.slice/user@${autocontribute_uid}.service"
test "$(sudo systemctl show "user@${autocontribute_uid}.service" \
  --property=Environment --value)" = \
  'SYSTEMD_UNIT_PATH=/etc/systemd/user:/run/systemd/user:/usr/local/lib/systemd/user:/usr/lib/systemd/user'
test "$("${user_systemctl[@]}" show --property=UnitPath --value)" = \
  '/etc/systemd/user /run/systemd/user /usr/local/lib/systemd/user /usr/lib/systemd/user'
test "$("${user_systemctl[@]}" show \
  autocontribute-rootless-docker-daemon.service \
  --property=FragmentPath --value)" = \
  /etc/systemd/user/autocontribute-rootless-docker-daemon.service
test -z "$("${user_systemctl[@]}" show \
  autocontribute-rootless-docker-daemon.service \
  --property=DropInPaths --value)"
test "$("${user_systemctl[@]}" show \
  autocontribute-rootless-docker-daemon.service \
  --property=NeedDaemonReload --value)" = no
test "$("${user_systemctl[@]}" show \
  autocontribute-rootless-docker-daemon.service \
  --property=Transient --value)" = no
test "$("${user_systemctl[@]}" show \
  autocontribute-rootless-docker-daemon.service \
  --property=ActiveState --value)" = inactive
sudo -u autocontribute \
  /usr/local/libexec/autocontribute-rootless-docker-check --unit-only

sudo ln -s releases/FULL_COMMIT \
  /opt/autocontribute/.current.FULL_COMMIT.next
sudo mv -Tf \
  /opt/autocontribute/.current.FULL_COMMIT.next \
  /opt/autocontribute/current
test "$(readlink -f /opt/autocontribute/current)" = "$release"
sudo /opt/autocontribute/current/.venv/bin/autocontribute \
  deployment verify-systemd-assets

sudo systemctl enable --now autocontribute-rootless-docker.service
test "$(sudo systemctl show autocontribute-rootless-docker.service \
  --property=ActiveState --value)" = active
test "$(sudo systemctl show autocontribute-rootless-docker.service \
  --property=SubState --value)" = running
test "$("${user_systemctl[@]}" show \
  autocontribute-rootless-docker-daemon.service \
  --property=ActiveState --value)" = active
test "$("${user_systemctl[@]}" show \
  autocontribute-rootless-docker-daemon.service \
  --property=SubState --value)" = running
sudo -u autocontribute env \
  HOME=/var/lib/autocontribute \
  XDG_RUNTIME_DIR=/run/autocontribute \
  DOCKER_HOST=unix:///run/autocontribute/docker.sock \
  docker info --format \
    'root={{json .DockerRootDir}} security={{json .SecurityOptions}} cgroup={{.CgroupVersion}}/{{.CgroupDriver}}'
unset user_systemctl
unset expected_manager_dropin_count manager_dropin manager_dropins
unset manager_dropin_directory
unset autocontribute_uid
unset release
```

The last command must report `root="/var/lib/autocontribute/docker"`, `cgroup=2/systemd`, and one
`name=rootless` option. Every service except the failure recorder repeats the file verification
before it starts. It does not cover your own drop-ins; review them with `systemctl cat`.

Pull each digest-pinned sandbox image as `autocontribute` before you run `doctor`; the sandbox never
pulls images. See [Sandbox image](sandbox-image.md). Check the installed units:

```bash
sudo systemd-analyze verify \
  autocontribute-worker.service \
  autocontribute-worker.timer \
  autocontribute-backup.service \
  autocontribute-backup.timer \
  autocontribute-replication.service \
  autocontribute-replication.timer \
  autocontribute-doctor.service \
  autocontribute-health.service \
  autocontribute-health.timer \
  autocontribute-rootless-docker.service \
  'autocontribute-failure@.service' \
  'autocontribute-alert@.service'
sudo -u autocontribute env \
  HOME=/var/lib/autocontribute \
  XDG_RUNTIME_DIR="/run/user/$(id -u autocontribute)" \
  DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u autocontribute)/bus" \
  SYSTEMD_UNIT_PATH=/etc/systemd/user:/run/systemd/user:/usr/local/lib/systemd/user:/usr/lib/systemd/user \
  systemd-analyze --user verify autocontribute-rootless-docker-daemon.service
sudo systemd-analyze calendar '*-*-* 09,21:17:00 UTC'
sudo systemd-analyze calendar '*-*-* 03:17:00 UTC'
sudo systemd-analyze calendar '*-*-* *:37:00 UTC'
sudo systemd-analyze security autocontribute-worker.service
sudo systemd-analyze security autocontribute-replication.service
```

### First run

With `s3_replication` configured, `doctor` fails until a replicated bundle exists. Create the bucket
and IAM policy from [Immutable S3 backup replication](s3-backup-replication.md), then create the
enable marker and run one backup and one replication:

```bash
test "$(stat --format=%U:%G:%a -- /var/backups/autocontribute/receipts)" = \
  autocontribute:autocontribute:700
test "$(stat --format=%U:%G:%a -- /var/backups/autocontribute/replication-scratch)" = \
  autocontribute:autocontribute:700
sudo install -o root -g root -m 0400 /dev/null \
  /etc/autocontribute/s3-replication.enabled
sudo systemctl start autocontribute-backup.service
sudo systemctl start autocontribute-replication.service
test "$(sudo systemctl show --property=Result --value \
  autocontribute-backup.service)" = success
test "$(sudo systemctl show --property=Result --value \
  autocontribute-replication.service)" = success
sudo -u autocontribute \
  /opt/autocontribute/current/.venv/bin/autocontribute \
  state verify-latest-s3 \
  --config /etc/autocontribute/autocontribute.yml \
  --max-age-hours 36
```

Run the preflight. `doctor` sends one small paid request per distinct model profile:

```bash
sudo systemctl start autocontribute-doctor.service
test "$(sudo systemctl show --property=Result --value \
  autocontribute-doctor.service)" = success
test "$(sudo systemctl show --property=ExecMainStatus --value \
  autocontribute-doctor.service)" = 0
sudo journalctl -u autocontribute-doctor.service --since today
```

Fix every failed check. Then run one worker, back up and replicate, confirm the newest receipt is
newer than that worker attempt, and enable the timers:

```bash
sudo systemctl start autocontribute-worker.service
sudo systemctl start autocontribute-backup.service
sudo systemctl start autocontribute-replication.service
sudo -u autocontribute \
  /opt/autocontribute/current/.venv/bin/autocontribute \
  state verify-latest-s3 \
  --config /etc/autocontribute/autocontribute.yml \
  --max-age-hours 36 \
  --required-after /var/lib/autocontribute/health/worker-attempt
sudo systemctl enable --now \
  autocontribute-worker.timer \
  autocontribute-backup.timer \
  autocontribute-replication.timer \
  autocontribute-health.timer
sudo systemctl list-timers 'autocontribute-*'
```

The worker always runs `run --scheduled`, which cannot pin an issue or use a retry override. A safe
skip counts as success. Every worker run, successful or not, starts a backup.

## Routine operation and monitoring

Worker, backup, and replication are oneshot services and are normally inactive. Check them with:

```bash
systemctl list-timers 'autocontribute-*'
systemctl show autocontribute-worker.service \
  -p ActiveState -p Result -p ExecMainStatus -p ExecMainStartTimestamp -p ExecMainExitTimestamp
systemctl show autocontribute-backup.service \
  -p ActiveState -p Result -p ExecMainStatus -p ExecMainStartTimestamp -p ExecMainExitTimestamp
systemctl show autocontribute-replication.service \
  -p ActiveState -p Result -p ExecMainStatus -p ExecMainStartTimestamp -p ExecMainExitTimestamp
sudo -u autocontribute \
  /opt/autocontribute/current/.venv/bin/autocontribute \
  state verify-latest-s3 \
  --config /etc/autocontribute/autocontribute.yml \
  --if-configured \
  --max-age-hours 36
sudo systemctl start autocontribute-health.service
df --block-size=1 \
  /var/lib/autocontribute/state \
  /var/lib/autocontribute/state/workspaces \
  /var/lib/autocontribute/docker \
  /var/backups/autocontribute
df --inodes \
  /var/lib/autocontribute/state \
  /var/lib/autocontribute/state/workspaces \
  /var/lib/autocontribute/docker \
  /var/backups/autocontribute
sudo journalctl \
  -u autocontribute-worker.service \
  -u autocontribute-backup.service \
  -u autocontribute-replication.service \
  -u autocontribute-health.service \
  -u 'autocontribute-failure@*' \
  -u 'autocontribute-alert@*' \
  --since '24 hours ago'
```

The health service runs every 15 minutes and fails when:

| Check | Fails when |
| --- | --- |
| Worker | The last successful run is older than 18 hours |
| Backup | The last complete backup is older than 36 hours |
| Replication | The newest bundle or its S3 receipt is older than 36 hours (skipped only while `s3_replication` is absent in `review_required` mode) |
| Storage | State, backup, or Docker data storage is over its ceiling or under its reserve |
| Productivity | `/var/lib/autocontribute/health/contribution-prepared` is older than `AUTOCONTRIBUTE_CONTRIBUTION_MAX_AGE_SECONDS` (default 604800 seconds, 7 days) |

Only a scheduled run that leaves a contribution ready for approval, submitting, or open as a pull
request refreshes that stamp. The tmpfiles configuration creates the stamp at install without ever
refreshing an existing one. A stall alert means nothing passed discovery and the quality gates; read
recent run outcomes. To allow a longer gap, raise the variable in a drop-in for the health service.

Each failure of the worker, backup, replication, doctor, or health service writes the unit and time
to `/var/lib/autocontribute/health/last-failure`, logs an error-priority journal entry, and, with a
webhook installed, POSTs a JSON alert (up to three attempts). A failed delivery is only recorded
locally, so a broken webhook cannot recurse or mask the original failure. The webhook is a push
notification, not the system of record: also forward error-priority journal entries to your host
alerting, because a host that is down cannot send its own alert.

Alert when state, workspaces, or Docker data pass 75% of their bytes or inodes, and when backups
pass 50%. Never fix a capacity failure by moving files to the parent filesystem. Stop the worker
before you remove a workspace, and never remove a `submitting` one: it can hold the only copy of a
commit still to be pushed, and backups do not include workspaces.

The journal can contain issue text, diffs, and command output; restrict who can read it. Never run
shell tracing (`bash -x`) around the worker: it prints the credentials. For a persistent 30-day
journal, review `deploy/systemd/autocontribute.journald.conf.example` and install it as a `.conf`
file in `/etc/systemd/journald.conf.d/`; the setting applies to the whole host.

Check the safety state after every alert and before any resume:

```bash
sudo -u autocontribute /usr/bin/flock --exclusive \
  /var/lib/autocontribute/operation.lock \
  /opt/autocontribute/current/.venv/bin/autocontribute \
  safety status --config /etc/autocontribute/autocontribute.yml
```

Run every command that opens the state, such as `approve`, `publish`, `runs cancel`, `eval`,
`state restore`, or a manual `run`, under the same lock, or only while every service is stopped. To
retry an unchanged skipped, rejected, or cancelled issue, stop the worker timer and service, take
the lock, load credentials, and run:

```bash
autocontribute run \
  --issue owner/repository#123 \
  --retry-unchanged \
  --retry-actor "OPERATOR IDENTITY" \
  --retry-reason "PRIOR EVIDENCE REVIEWED; CONCRETE REASON FOR RETRY"
```

### Deliberately enabling automatic publication

Do not add the opt-in during installation. Before you switch to auto mode:

1. Keep `publishing.mode: review_required` and set the final pilot configuration. `config validate`
   on a copy set to `auto` lists every setting outside the allowed shape. Changing a setting that
   `publish` [rechecks](how-it-works.md#approval-and-publication) starts a new evaluation cohort.
2. Collect evaluation evidence until `autocontribute rollout report` passes; see
   [Scheduling](scheduling.md#automatic-publishing).
3. Complete a recovery drill ([Backups and recovery drills](#backups-and-recovery-drills)).

Then stop the worker. If this check fails, let the running worker finish first:

```bash
set -Eeuo pipefail
sudo systemctl disable --now autocontribute-worker.timer
test "$(sudo systemctl show --property=ActiveState --value \
  autocontribute-worker.timer)" = inactive
test "$(sudo systemctl show --property=ActiveState --value \
  autocontribute-worker.service)" = inactive
active_units="$(sudo systemctl list-units \
  --state=active,activating,deactivating,reloading \
  --no-legend --plain --no-pager \
  autocontribute-worker.service autocontribute-worker.timer)"
test -z "$active_units"
unset active_units
```

Set `publishing.mode: auto`, install a GitHub credential that can publish, and add the opt-in for
both services. The doctor makes no repository or GitHub writes and cannot publish, but opening the
store can repair local durable state, and its publication check needs the same opt-in:

```bash
sudo install -d -o root -g root -m 0755 \
  /etc/systemd/system/autocontribute-worker.service.d \
  /etc/systemd/system/autocontribute-doctor.service.d
sudoedit \
  /etc/systemd/system/autocontribute-worker.service.d/50-auto-publish.conf \
  /etc/systemd/system/autocontribute-doctor.service.d/50-auto-publish.conf
```

Put this identical content in each file, then reload systemd:

```ini
[Service]
Environment=AUTOCONTRIBUTE_ALLOW_AUTO_PUBLISH=1
```

```bash
sudo cmp --silent -- \
  /etc/systemd/system/autocontribute-worker.service.d/50-auto-publish.conf \
  /etc/systemd/system/autocontribute-doctor.service.d/50-auto-publish.conf
sudo systemctl daemon-reload
```

Run the doctor and one observed worker, back up and replicate, and verify the receipt before you
re-enable the timer:

```bash
sudo systemctl start autocontribute-doctor.service
sudo systemctl start autocontribute-worker.service
sudo systemctl start autocontribute-backup.service
sudo systemctl start autocontribute-replication.service
sudo -u autocontribute \
  /opt/autocontribute/current/.venv/bin/autocontribute \
  state verify-latest-s3 \
  --config /etc/autocontribute/autocontribute.yml \
  --max-age-hours 36 \
  --required-after /var/lib/autocontribute/health/worker-attempt
sudo systemctl enable --now autocontribute-worker.timer
```

## Kill switch and incident response

To stop new attempts, disable the timer and stop the worker. Stopping a running worker can leave a
`submitting` run or a container for the next controlled run to reconcile.

```bash
sudo systemctl disable --now autocontribute-worker.timer
sudo systemctl stop autocontribute-worker.service
```

In auto mode, also remove both opt-in drop-ins. A worker started without them makes no new GitHub
writes except to finish cleanup it had already recorded. Revoke the GitHub token if you doubt the
host's integrity.

```bash
sudo rm -- \
  /etc/systemd/system/autocontribute-worker.service.d/50-auto-publish.conf \
  /etc/systemd/system/autocontribute-doctor.service.d/50-auto-publish.conf
sudo systemctl daemon-reload
```

Record a persistent safety stop:

```bash
sudo -u autocontribute /usr/bin/flock --exclusive \
  /var/lib/autocontribute/operation.lock \
  /opt/autocontribute/current/.venv/bin/autocontribute \
  safety stop --actor OPERATOR --reason 'CONCRETE INCIDENT REASON' \
  --config /etc/autocontribute/autocontribute.yml
```

Do not resume just to clear an alert. `safety resume` requires the trigger hash that `safety status`
shows; see [How it works](how-it-works.md#lifecycle-sync-and-the-safety-stop).

## Workspace retention

Before each scheduled run, the worker runs:

```bash
autocontribute state gc-workspaces \
  --config /etc/autocontribute/autocontribute.yml \
  --older-than-days 7 \
  --limit 25 \
  --execute
```

Omit `--execute` for a dry run. The command never deletes database rows or run evidence, and keeps
the workspace of any run that is active, awaiting approval, approved, or still needed to reconcile a
publication. It exits with status 2 when it keeps an unsafe entry; the worker logs that and
continues. It ignores directories no run owns: inspect those with the worker stopped.

## Backups and recovery drills

The backup service writes one verified complete bundle with no network or credentials, then starts
the replication service, which uploads the oldest unreplicated bundle, reads it back, and runs
`state gc-bundles`. Bundles exclude configuration, credentials, Docker data, and workspaces; rebuild
Docker data from the daemon configuration and the pinned images.

Deleting a bundle without a verified receipt is an operator action, never a timer action.
`state gc-bundles` removes only bundles beyond the newest `local_keep_bundles` whose receipt proves
that S3 holds the same bytes. To delete one any other way, first record its SHA-256 digest, size,
off-host version ID, and retention expiry, read the off-host copy back and compare, and keep at
least two other restorable generations. For S3, `state replicate-s3` and `state replicate-next-s3`
implement this provider-specific replication/receipt protocol.

Start every drill or recovery from the receipt ([Recovery](s3-backup-replication.md#recovery)).
At least once per release, restore a copy on a non-production host with the same release and a
configuration whose `storage.path` does not exist yet:

```bash
sudo -u autocontribute \
  /opt/autocontribute/current/.venv/bin/autocontribute \
  state restore --complete \
  --input /path/to/copied-autocontribute-state.bundle.zip \
  --config /path/to/recovery-only-config.yml
sudo -u autocontribute \
  /opt/autocontribute/current/.venv/bin/autocontribute \
  runs list --config /path/to/recovery-only-config.yml
sudo -u autocontribute \
  /opt/autocontribute/current/.venv/bin/autocontribute \
  eval report --config /path/to/recovery-only-config.yml
```

A complete backup can fail while a `submitting` run has a stored commit; finish or reconcile that
publication on the live worker.

For a real recovery, keep all timers stopped and keep the damaged state device. Because
`state restore` writes only to an absent path and the live state root is a mount point, provision a
new state device [as above](#provision-bounded-state-and-local-backup-filesystems) but mount it
elsewhere, restore into an absent staging directory on it, and move the entries to its root while it
is offline:

```bash
recovery_mount=/mnt/autocontribute-state-recovery
test "$(findmnt --noheadings --raw --output TARGET --target "$recovery_mount")" = "$recovery_mount"
test ! -e "$recovery_mount/restored"
# recovery-only.yml must set storage.path to /mnt/autocontribute-state-recovery/restored.
sudo -u autocontribute \
  /opt/autocontribute/current/.venv/bin/autocontribute \
  state restore --complete \
  --input /trusted/autocontribute-state.bundle.zip \
  --config /path/to/recovery-only.yml
test -f "$recovery_mount/restored/state.sqlite3"
test -d "$recovery_mount/restored/runs"
test -d "$recovery_mount/restored/evaluations"
test -d "$recovery_mount/restored/workspaces"
sudo -u autocontribute mv -- \
  "$recovery_mount/restored/state.sqlite3" \
  "$recovery_mount/restored/runs" \
  "$recovery_mount/restored/evaluations" \
  "$recovery_mount/restored/workspaces" \
  "$recovery_mount/"
sudo -u autocontribute rmdir -- "$recovery_mount/restored"
sudo sync -f "$recovery_mount"
unset recovery_mount
```

If the move is interrupted, reformat the new device and start again. Then unmount it, put its UUID
in `/etc/fstab`, mount it at `/var/lib/autocontribute/state`, recreate the workspace filesystem, and
start in `review_required` mode without the opt-in. Create, replicate, and verify a fresh bundle,
run `doctor`, check `safety status`, and compare the restored runs with the pull requests on GitHub:
a restored bundle can miss a publication or a safety stop. After one observed worker, back up and
replicate again before you enable the worker timer.

## Upgrade and rollback

The application and its 27 installed deployment files form one release. To upgrade:

1. Disable the timers, let the worker finish, and create and replicate a complete backup.
2. [Install the new release](#install-an-immutable-release) into a new directory.
3. Run [Install and validate the units](#install-and-validate-the-units) with the new `release`. If
   any step fails, keep every service stopped.
4. Back up and replicate, verify the receipt, and run `doctor` before you re-enable timers. A code,
   dependency, model, or policy change starts a new evaluation cohort; check `rollout report`.

Never start an old `current` against new deployment files; to go back, rerun
[Install and validate the units](#install-and-validate-the-units) with the old release.
Never restart an old binary against state opened by a newer release. To roll back, restore the
pre-upgrade bundle into an absent state root with the old release, keep the newer state for
investigation, and never roll back across an unresolved publication. Keep auto mode off until you
have reviewed the restored state and pull requests.
