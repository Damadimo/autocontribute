# Operator-managed systemd deployment

This bundle runs one persistent Autocontribute installation on a Linux host. It schedules the
worker at 09:17 and 21:17 UTC, creates one verified complete backup at 03:17 UTC, and checks the
freshness of both. Before each scheduled attempt, the worker inspects at most 25 terminal workspaces
older than seven days and removes only those that pass the durable-evidence checks below.
The worker and backup take the same local `flock`, so they cannot read or change the state lineage
concurrently.

The units are intentionally inert until an operator installs them. They do not enable automatic
publication. Begin with `publishing.mode: review_required`; the automatic-publishing gate and its
separate environment opt-in still apply.

## Deployment boundary

Use this layout on one durable host:

| Path | Owner and mode | Purpose |
| --- | --- | --- |
| `/opt/autocontribute/releases/<revision>` | `root:root`, not writable by the worker | Immutable application release and virtual environment |
| `/opt/autocontribute/current` | `root:root` symlink | Atomically selected release |
| `/etc/autocontribute/autocontribute.yml` | `root:autocontribute`, `0640` | Reviewed, non-secret policy and repository configuration |
| `/etc/autocontribute/credentials/*.cred` | `root:root`, `0600` | Encrypted systemd credentials |
| `/var/lib/autocontribute/state` | `autocontribute:autocontribute`, `0700` | Live SQLite, evidence, and evaluations |
| `/var/lib/autocontribute/state/workspaces` | `autocontribute:autocontribute`, `0700` | Dedicated capacity-limited ext4 filesystem for target repositories and validation copies |
| `/var/lib/autocontribute/docker` | `autocontribute:autocontribute`, `0710` | Dedicated capacity-limited ext4 filesystem for rootless Docker images, layers, and metadata |
| `/var/lib/autocontribute/tmp` | `autocontribute:autocontribute`, `0700` | Private temporary files visible to the rootless Docker daemon |
| `/var/backups/autocontribute` | `autocontribute:autocontribute`, `0700` | Local immutable-name complete bundles awaiting off-host replication |

The shared lock is `/var/lib/autocontribute/operation.lock`, outside the captured state root. It
serializes the packaged worker, doctor, and backup services on this host. It is not a distributed
lock: never run a second host, an ad-hoc CLI writer, or the hosted scheduler against the same
lineage. Keep the state on a local filesystem with working SQLite locks; do not place it on NFS or an
eventually consistent mount.

The supplied services also require `state` and the local backup directory to be separate, exact,
non-bind ext4 mounts backed by whole filesystems and mounted nowhere else. Both must use
`rw,nodev,nosuid,noexec`. The state filesystem is capped at 8 GiB and 262,144 inodes and must keep
at least 1 GiB and 32,768 inodes available to the service account. The backup filesystem is capped
at 64 GiB and 524,288 inodes and must keep at least 20 GiB and 262,144 inodes available. The larger
backup reserve covers complete-bundle staging, a second SQLite consistency snapshot, the archive
being written, and cleanup margin even when state approaches its ceiling. State and backup mounts
must also be distinct from their parent filesystems and from one another, so either workload cannot
fill the host root filesystem or consume the other's finalization reserve.

Worker, doctor, and backup wrappers verify these boundaries before opening state or reading a
credential; the 15-minute health service repeats the capacity checks from its read-only namespace.
They stop rather than start new work below any reserve. The fixed ceilings are safety limits, not
sizing targets. Provision the smaller reference sizes below, alert well before a reserve is reached,
and expand only within the hard ceilings. The checked-in units never rotate or delete a backup.

Every host-backed path writable by repository code is below the dedicated `state/workspaces` mount;
the container's other writable path is its size-limited `/tmp` tmpfs. The supplied worker accepts
only an exact, non-bind ext4 mount backed by one whole block device, mounted nowhere else, with
`rw,nodev,nosuid`, at most 20 GiB of addressable blocks, and at most 524,288 fixed inodes. This is an
aggregate hard ceiling across durable repositories and disposable validation copies. It prevents
workspace writes from exhausting the filesystem that holds SQLite, evidence, or the service home.
It is not a per-run fairness limit. The wrapper first performs its structural mount and ceiling
checks, then binds the Python store to that exact path and runs credential-free workspace cleanup.
It repeats the check in headroom mode and requires at least 4 GiB available to the service account
and 65,536 free inodes before it reads credentials or begins billable/model work. A configuration
that redirects storage around the verified mount is rejected. Cleanup can retain recovery-critical
trees; if the remaining filesystem still lacks that fixed headroom, the worker fails safely before
starting a new attempt and requires operator review.
`doctor` creates its writable Docker probe below the same bounded mount.

The rootless daemon's data root has an independent, dedicated boundary. The supplied checks require
an exact, non-bind ext4 mount backed by one whole block device, mounted nowhere else, with
`rw,nodev,nosuid`, at most 32 GiB (34,359,738,368 bytes) of addressable blocks, and at most
1,048,576 fixed inodes. It also requires at least 1 GiB (1,073,741,824 bytes) and 16,384 inodes
available to the service account. The rootless Docker user service checks that mount before
`dockerd` starts, so a failed mount cannot silently move image writes onto the service home
filesystem. Before either credential-bearing service reads a credential, the wrapper also requires
Docker's structured `DockerRootDir` value to equal `/var/lib/autocontribute/docker` exactly. The
worker and doctor receive an explicitly read-only child view of that path despite their writable
service-state parent; the separately running rootless Docker service retains the writable host
mount. The Python sandbox repeats the structured equality and headroom check before every container
launch. This is an aggregate ceiling across images, layers, build cache, container writable layers,
and daemon metadata, not a per-image quota. Use only pre-pulled digest-pinned images and alert before
the filesystem fills. Sandbox and doctor containers use Docker's `none` log driver so untrusted
output cannot also accumulate there; attached stdout and stderr remain available directly to the
controlling process.

The sandbox daemon must be rootless and owned by the dedicated `autocontribute` account. Membership
in the host `docker` group or use of `/var/run/docker.sock` would give the worker root-equivalent
control and defeats this deployment boundary. Before either the worker or doctor reads a systemd
credential, the wrapper verifies that `/run/user/$UID` is an unsymlinked `0700` directory owned by
the service identity, that its Docker socket is owned by that identity with mode `0600` or `0660`,
and that the account cannot use the host socket. It then makes bounded daemon probes, requires one
exact `name=rootless` element in Docker's reported `SecurityOptions`, and verifies the exact bounded
data root. A failed or ambiguous check stops the service before the wrapper reads or exports any
credential.

The Python sandbox repeats a structured daemon check immediately before every container launch and
also requires cgroup v2, a non-`none` driver, and Docker-reported memory, swap, CPU-quota, and PID
control support. For this verified rootless daemon it selects container UID/GID `0:0`; rootless
Docker maps that namespace identity back to the unprivileged `autocontribute` host account, allowing
access to its private `0700` workspaces. The sandbox still drops all capabilities, sets
no-new-privileges, disables networking, and keeps the container root filesystem read-only. On a
rootful or desktop daemon it retains the caller's nonzero UID/GID. `doctor` additionally proves the
exact cgroup limits from inside a real container, performs a read/write probe through a fresh
service-owned `0700` bind, and verifies the resulting file's host ownership and content.

## Host prerequisites

The reference units target systemd 252 or newer and a Linux distribution with:

- Python 3.11 or 3.12, `uv`, Git, `flock`, GNU coreutils, util-linux `findmnt`, and e2fsprogs;
- rootless Docker on cgroup v2 with systemd resource-controller delegation, including `newuidmap`,
  `newgidmap`, and a unique subordinate UID/GID range;
- four dedicated, fully allocated (not thin-provisioned) block devices: no more than 8 GiB for
  state, 20 GiB for workspaces, 32 GiB for rootless Docker data, and 64 GiB for local backups; and
- persistent time synchronization and outbound HTTPS for GitHub and the configured model API.

Create a locked service account with a durable home. Allocate subordinate IDs that do not overlap
another account's ranges; the numbers below are examples and must be checked against
`/etc/subuid` and `/etc/subgid` first.

```bash
sudo useradd --system --create-home \
  --user-group \
  --home-dir /var/lib/autocontribute \
  --shell /usr/sbin/nologin autocontribute
sudo usermod --add-subuids 200000-265535 --add-subgids 200000-265535 autocontribute
test "$(id -gn autocontribute)" = autocontribute
getent group autocontribute
sudo loginctl enable-linger autocontribute
```

The explicit private user group is required by every supplied unit and tmpfiles rule. Do not add
the account to `docker`; the runtime preflight rejects that exact group even if a separately started
rootless daemon appears healthy.

### Provision bounded state and local-backup filesystems

Allocate separate, fully provisioned logical volumes or partitions for durable state and local
backups. Do not use a thin volume, sparse loopback file, network filesystem, or shared backing pool:
an apparent filesystem ceiling cannot reserve physical capacity in any of those arrangements. A
6 GiB state device and 48 GiB backup device are the reference sizes. They leave headroom under the
runtime ceilings while accommodating the fixed reserves and several maximum-size bundle
generations. Workload history determines the real retention window; capacity planning must use
observed bundle sizes and the off-host replication service-level objective.

The following destructive formatting example assumes an operator has already resolved two unused,
fully allocated devices. **`mkfs.ext4` destroys all data on its argument. Verify both exact devices
with the host storage tooling before running it.** The requested inode counts can be rounded by
ext4, so the runtime check verifies the actual superblock totals.

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

Add each returned, independently verified UUID to `/etc/fstab`. These mounts must precede the
nested workspace mount during boot and must never be mounted at a second path:

```fstab
UUID=STATE_UUID_FROM_BLKID /var/lib/autocontribute/state ext4 rw,nodev,nosuid,noexec 0 2
UUID=BACKUP_UUID_FROM_BLKID /var/backups/autocontribute ext4 rw,nodev,nosuid,noexec 0 2
```

Mount both, set the mounted filesystem roots' metadata, and verify the actual totals and available
capacity as the service account. GNU `stat` `%a` reports blocks available to an unprivileged user,
so it excludes ext4 blocks reserved for root.

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

Do not create the nested workspace filesystem until the state mount is active. A directory created
under an unmounted placeholder would be hidden later and can create a divergent state lineage.

### Provision the bounded workspace filesystem

Create a dedicated logical volume or partition no larger than 20 GiB. Its physical storage must be
fully allocated: do not use a thin-provisioned logical volume or a sparse loopback file. Exhausting
the shared thin pool or the loopback file's backing filesystem could still exhaust storage outside
the boundary this mount is intended to protect. The example below assumes an operator has allocated
an otherwise unused, fully allocated 16 GiB block device at
`/dev/mapper/autocontribute-workspaces`. **`mkfs.ext4` destroys all data on its argument. Resolve and
verify the exact device through the host's storage tooling before running it.** Never paste a device
name from this guide without that check.

Format it with a deliberately bounded, fixed inode table. `-N` is a requested count and ext4 can
round it, so the runtime ceiling leaves headroom and still verifies the actual superblock value.

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

Add the returned UUID to `/etc/fstab` only after checking that it is unique. The mount must be
durable across reboot and must not be mounted at any second path:

```fstab
UUID=UUID_FROM_BLKID /var/lib/autocontribute/state/workspaces ext4 rw,nodev,nosuid 0 2
```

Mount it, set the mounted filesystem root's ownership (not merely the covered directory), and verify
the actual byte and inode totals and current non-root availability. The reference 16
GiB/262,144-inode format is below the worker's hard ceilings of 21,474,836,480 bytes and 524,288 inodes
and leaves room above the 4 GiB/65,536-inode start-of-run floors.

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

The structural preflight rejects a missing mount, a bind, alias, mixed-device layer, or shared-device
mount, another filesystem type, missing `nodev`/`nosuid`, unsafe ownership or mode, and either actual
capacity above its hard ceiling. The post-cleanup headroom pass additionally rejects fewer than 4
GiB of blocks available to the non-root service or fewer than 65,536 free inodes.
Ext4 is required because its inode table is fixed at format time; a current `df -i` total on a
dynamically allocating filesystem would not prove an inode ceiling. A private systemd tmpfs is also
not sufficient: the separately running rootless Docker daemon resolves bind sources in the host
mount namespace and would not see the service's private mount.

CI exercises this preflight on a small loop-backed ext4 filesystem inside a hardened transient
systemd service. That loop device is only a disposable integration-test fixture; production must
use the fully allocated dedicated storage described above.

### Provision the bounded rootless Docker data filesystem

Choose a second dedicated, fully allocated logical volume or partition no larger than 32 GiB. The
operator chooses the actual size from the dependency-complete pinned image set and monitoring
headroom; the boundary does not assume that the full ceiling is available. Do not share the
workspace device, use a thin volume, or use a sparse loopback file. The example assumes an unused,
fully allocated 24 GiB device at `/dev/mapper/autocontribute-docker`. Resolve it independently and
apply the same destructive-device warning as the workspace device.

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

Add the independently verified UUID to `/etc/fstab`:

```fstab
UUID=DOCKER_UUID_FROM_BLKID /var/lib/autocontribute/docker ext4 rw,nodev,nosuid 0 2
```

Mount it and set the mounted filesystem root to Docker's private root-directory mode. The preflight
accepts `0700` and Docker's normal `0710`; both require the account's private primary group and deny
all access to other users.

```bash
sudo mount /var/lib/autocontribute/docker
sudo chown autocontribute:autocontribute /var/lib/autocontribute/docker
sudo chmod 0710 /var/lib/autocontribute/docker
findmnt --target /var/lib/autocontribute/docker \
  --output TARGET,SOURCE,FSTYPE,OPTIONS
stat --file-system --format='block_size=%S blocks=%b inodes=%c' \
  /var/lib/autocontribute/docker
```

The hard ceilings are 34,359,738,368 bytes and 1,048,576 inodes. The checker uses filesystem totals,
not free-space snapshots, and compares mount identity by `MAJ:MIN`, so alternate device names cannot
hide a second mount. It does not need access to the block node and therefore works with the supplied
services' `PrivateDevices=yes`. CI runs its mount-only path against a real loop-backed ext4
filesystem inside that same hardened service boundary; production still requires fully allocated
storage.

Install rootless Docker for that account using the distribution's supported procedure, but do not
enable or start its user service yet. Rootless
Docker can enforce the configured CPU, memory, swap, and PID limits only when cgroup v2 controllers
are delegated through systemd; a daemon reporting cgroup driver `none` ignores those limits. On the
dedicated host, install Docker's required user-manager delegation and restart the manager so the
setting is effective. This template drop-in applies to every systemd user manager on the host, so do
not install it on a shared machine without reviewing that wider delegation boundary.

```bash
sudo install -d -m 0755 /etc/systemd/system/user@.service.d
printf '%s\n' \
  '[Service]' \
  'Delegate=cpu cpuset io memory pids' \
  | sudo tee /etc/systemd/system/user@.service.d/delegate.conf >/dev/null
sudo chmod 0644 /etc/systemd/system/user@.service.d/delegate.conf
sudo systemctl daemon-reload
```

Configure the rootless daemon before its first start. Install the mount checker from the same audited
source revision that will supply the worker, then configure Docker's documented rootless
`daemon.json` path. If that file already contains reviewed settings, merge the single `data-root`
key instead of replacing them.

```bash
sudo install -d -o root -g root -m 0755 /usr/local/libexec
sudo install -o root -g root -m 0755 \
  deploy/systemd/libexec/autocontribute-docker-data-check \
  /usr/local/libexec/autocontribute-docker-data-check
sudo -u autocontribute \
  /usr/local/libexec/autocontribute-docker-data-check \
  --mount-only /var/lib/autocontribute/docker
sudo install -d -o root -g autocontribute -m 0750 \
  /var/lib/autocontribute/.config/docker
sudoedit /var/lib/autocontribute/.config/docker/daemon.json
sudo chown root:autocontribute /var/lib/autocontribute/.config/docker/daemon.json
sudo chmod 0640 /var/lib/autocontribute/.config/docker/daemon.json
python3 -m json.tool \
  /var/lib/autocontribute/.config/docker/daemon.json >/dev/null
sudo install -d -o root -g root -m 0755 /etc/systemd/user/docker.service.d
sudo install -o root -g root -m 0644 \
  deploy/systemd/rootless-docker.service.d/10-autocontribute-data-root.conf \
  /etc/systemd/user/docker.service.d/10-autocontribute-data-root.conf
```

The reviewed `daemon.json` must contain this exact absolute value (alongside any other reviewed
keys):

```json
{
  "data-root": "/var/lib/autocontribute/docker"
}
```

The system-wide user-service drop-in intentionally prevents any other account's rootless
`docker.service` from starting on this dedicated host: its mount check requires the data root to be
owned by the invoking UID and primary GID. Do not install this deployment on a shared host.

Start the account's user manager explicitly and verify its private bus before enabling the Docker
user service. This does not require changing the account's login shell:

```bash
autocontribute_uid="$(id -u autocontribute)"
sudo systemctl restart "user@${autocontribute_uid}.service"
test -S "/run/user/${autocontribute_uid}/bus"
test "$(stat -c %u "/run/user/${autocontribute_uid}/bus")" = "$autocontribute_uid"
sudo -u autocontribute env \
  HOME=/var/lib/autocontribute \
  XDG_RUNTIME_DIR="/run/user/${autocontribute_uid}" \
  DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${autocontribute_uid}/bus" \
  systemctl --user daemon-reload
sudo -u autocontribute env \
  HOME=/var/lib/autocontribute \
  XDG_RUNTIME_DIR="/run/user/${autocontribute_uid}" \
  DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${autocontribute_uid}/bus" \
  systemctl --user show-environment >/dev/null
sudo -u autocontribute env \
  HOME=/var/lib/autocontribute \
  XDG_RUNTIME_DIR="/run/user/${autocontribute_uid}" \
  DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${autocontribute_uid}/bus" \
  systemctl --user enable --now docker.service
sudo -u autocontribute env \
  HOME=/var/lib/autocontribute \
  XDG_RUNTIME_DIR="/run/user/${autocontribute_uid}" \
  DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${autocontribute_uid}/bus" \
  DOCKER_HOST="unix:///run/user/${autocontribute_uid}/docker.sock" \
  docker info --format \
    'root={{json .DockerRootDir}} security={{json .SecurityOptions}} cgroup={{.CgroupVersion}}/{{.CgroupDriver}}'
unset autocontribute_uid
```

Confirm that the smoke test reports the exact configured data root, cgroup v2 with a driver other
than `none`, and one exact `name=rootless` security option; `doctor` later proves the configured
limits inside a real container. The packaged services repeat the ownership, permission, mount,
capacity, group, host-socket, exact rootless-security-option, and exact `DockerRootDir` checks on
every invocation before the wrapper reads any file in the encrypted credential directory. Rootless
Docker commonly creates a `0660` socket; this remains private because its owning runtime directory
must be exactly `0700`.

Pre-pull every digest-pinned sandbox image as this user. Never use a tag in production. The service
sets `TMPDIR=/var/lib/autocontribute/tmp` because Docker's daemon must see the CID files created by
the client; systemd's private `/tmp` mount is deliberately not used for those files.

## Install an immutable release

Place an audited checkout or artifact in a new, never-reused directory below
`/opt/autocontribute/releases/`. Verify its full commit and build provenance before installation,
then install exactly the checked-in lock:

```bash
sudo uv sync \
  --project /opt/autocontribute/releases/FULL_COMMIT \
  --frozen --no-dev
sudo chown -R root:root /opt/autocontribute/releases/FULL_COMMIT
sudo chmod -R go-w /opt/autocontribute/releases/FULL_COMMIT
sudo ln -s releases/FULL_COMMIT /opt/autocontribute/.current.next
sudo mv -Tf /opt/autocontribute/.current.next /opt/autocontribute/current
```

Do not repoint `current` while any Autocontribute unit is active. Python may import files lazily, so
changing a release underneath a live process is not an atomic application upgrade.

## Install configuration and encrypted credentials

Copy `autocontribute.example.yml` to a temporary administrator-owned file and review every field.
For this deployment, the important settings are:

```yaml
github:
  auth: token
  token_env: AUTOCONTRIBUTE_GITHUB_TOKEN

sandbox:
  backend: docker
  network: none
  image: repository/image@sha256:FULL_DIGEST

publishing:
  mode: review_required

storage:
  path: /var/lib/autocontribute/state
```

Keep API keys and GitHub tokens out of YAML. Install the reviewed file so the service account can
read but not modify it:

```bash
sudo install -d -o root -g autocontribute -m 0750 /etc/autocontribute
sudo install -o root -g autocontribute -m 0640 \
  /path/to/reviewed-autocontribute.yml \
  /etc/autocontribute/autocontribute.yml
sudo install -d -o root -g root -m 0700 /etc/autocontribute/credentials
```

The supplied units use `LoadCredentialEncrypted=`. Create encrypted credentials without placing
their plaintext in command arguments, shell history, configuration, or the environment of PID 1:

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

sudo chmod 0600 /etc/autocontribute/credentials/*.cred
sudo chown root:root /etc/autocontribute/credentials/*.cred
```

Use a dedicated model project with hard provider-side spend limits. Use a dedicated, expiring
GitHub credential with only the target repositories and operations required by the configured mode.
The worker wrapper copies named systemd credentials into its process environment immediately before
`exec`; it never prints them. Because processes owned by the same Unix user can be a credential
boundary risk, keep this account locked and dedicated to Autocontribute and its rootless daemon.

For another API-key environment name, install the same drop-in for both the worker and doctor. Each
unit independently defines the default encrypted credentials, so changing only one leaves the two
execution paths inconsistent. Create both directories and edit both named files:

```bash
sudo install -d -o root -g root -m 0755 \
  /etc/systemd/system/autocontribute-worker.service.d \
  /etc/systemd/system/autocontribute-doctor.service.d
sudoedit \
  /etc/systemd/system/autocontribute-worker.service.d/40-provider-credentials.conf \
  /etc/systemd/system/autocontribute-doctor.service.d/40-provider-credentials.conf
```

Put this identical content in each file. The empty assignment resets the inherited encrypted-
credential list, and the later environment assignment replaces the default credential-name value.
The GitHub credential remains required:

```ini
[Service]
LoadCredentialEncrypted=
LoadCredentialEncrypted=VENDOR_API_KEY:/etc/autocontribute/credentials/VENDOR_API_KEY.cred
LoadCredentialEncrypted=AUTOCONTRIBUTE_GITHUB_TOKEN:/etc/autocontribute/credentials/AUTOCONTRIBUTE_GITHUB_TOKEN.cred
Environment="AUTOCONTRIBUTE_CREDENTIAL_NAMES=VENDOR_API_KEY AUTOCONTRIBUTE_GITHUB_TOKEN"
```

Create that credential with `systemd-creds encrypt --name=VENDOR_API_KEY` and make the configured
`models.*.api_key_env` match. The wrapper rejects process-control names and refuses empty or
multiline values. If encrypted credentials are unavailable, use a root-only plaintext source with a
carefully reviewed `LoadCredential=` drop-in; do not use `Environment=`, `EnvironmentFile=`, or a
world-readable shell profile for secrets.

After any provider drop-in change, verify that the two files are identical, reload systemd, then
start the doctor before the worker. Credential overrides are not complete until both services have
been updated.

```bash
sudo cmp --silent -- \
  /etc/systemd/system/autocontribute-worker.service.d/40-provider-credentials.conf \
  /etc/systemd/system/autocontribute-doctor.service.d/40-provider-credentials.conf
sudo systemctl daemon-reload
```

Credential rotation is atomic between invocations: write a new encrypted file beside the old one,
set its owner and mode, rename it over the old path, and start `autocontribute-doctor.service`.
Never inspect a credential with a command that writes the decrypted value to the terminal or journal.

## Install and validate the units

From the audited source tree:

```bash
sudo install -o root -g root -m 0644 deploy/systemd/*.service /etc/systemd/system/
sudo install -o root -g root -m 0644 deploy/systemd/*.timer /etc/systemd/system/
sudo install -o root -g root -m 0755 deploy/systemd/libexec/* /usr/local/libexec/
sudo install -o root -g root -m 0644 \
  deploy/systemd/autocontribute.tmpfiles.conf \
  /etc/tmpfiles.d/autocontribute.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/autocontribute.conf
sudo systemctl daemon-reload
```

Run `systemd-tmpfiles` only while all four filesystems are mounted so their filesystem roots receive
the required ownership and mode. Worker, doctor, backup, and health declare `RequiresMountsFor=` for
the storage they inspect, and the credential-bearing services require both the workspace and Docker
data mounts. Their wrappers still repeat exact mount and capacity verification at every invocation;
an accidentally unmounted directory on a parent filesystem is rejected rather than used as a
fallback. The worker and backup additionally bind the Python store to the preflight-verified state
root, so changing `storage.path` cannot redirect writes around these checks. The separately installed
rootless Docker drop-in performs the data-mount check before the daemon itself starts.

Validate the installed files on the target host. `systemd-analyze security` is advisory; review
every relaxation instead of chasing a score that breaks rootless Docker or durable state.
CI also parses every packaged unit with systemd 255 on Ubuntu 24.04 and fails on parser warnings.
It performs an offline security assessment of every service, with an exposure ceiling of 4.0 for
the networked worker and doctor and 3.0 for the private-network backup, health, and failure units.
These are regression ceilings, not a substitute for reviewing the full report or validating the
installed units against the target host's systemd version.

```bash
sudo systemd-analyze verify \
  autocontribute-worker.service \
  autocontribute-worker.timer \
  autocontribute-backup.service \
  autocontribute-backup.timer \
  autocontribute-doctor.service \
  autocontribute-health.service \
  autocontribute-health.timer \
  'autocontribute-failure@.service'
sudo systemd-analyze calendar '*-*-* 09,21:17:00 UTC'
sudo systemd-analyze calendar '*-*-* 03:17:00 UTC'
sudo systemd-analyze security autocontribute-worker.service
```

Run the secure preflight. This makes bounded, potentially billable model probes and Docker probes,
as documented for `autocontribute doctor`:

```bash
sudo systemctl start autocontribute-doctor.service
sudo systemctl status autocontribute-doctor.service
sudo journalctl -u autocontribute-doctor.service --since today
```

Fix every failed check before enabling timers. The normal activation sequence intentionally creates
real first-run and backup success stamps before enabling freshness alerts:

```bash
sudo systemctl start autocontribute-worker.service
sudo systemctl start autocontribute-backup.service
sudo systemctl enable --now \
  autocontribute-worker.timer \
  autocontribute-backup.timer \
  autocontribute-health.timer
sudo systemctl list-timers 'autocontribute-*'
```

After structural validation, credential-free cleanup, and the headroom gate, the scheduled run is
the worker's first credentialed and potentially billable command. A safe skip is success and
refreshes the worker stamp. A rejected or failed attempt is a service failure. The complete-backup command verifies the
SQLite snapshot, event chains, run manifests, evidence, evaluations, file sizes, and SHA-256 hashes
before it publishes the uniquely named bundle. It receives no credentials and has no network.

## Routine operation and monitoring

The worker and backup are `Type=oneshot`; they should normally be inactive between invocations. Use
timer state, last service result, journal priority, and the two success-stamp modification times as
monitoring signals:

```bash
systemctl list-timers 'autocontribute-*'
systemctl show autocontribute-worker.service \
  -p ActiveState -p Result -p ExecMainStatus -p ExecMainStartTimestamp -p ExecMainExitTimestamp
systemctl show autocontribute-backup.service \
  -p ActiveState -p Result -p ExecMainStatus -p ExecMainStartTimestamp -p ExecMainExitTimestamp
sudo -u autocontribute /usr/local/libexec/autocontribute-healthcheck
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
  -u autocontribute-health.service \
  -u 'autocontribute-failure@*' \
  --since '24 hours ago'
```

The health timer fails when the last successful worker is older than 18 hours, the last complete
backup is older than 36 hours, either durable filesystem violates its fixed ceiling, or state or
backup headroom falls below a fixed reserve. The worker, doctor, and backup apply the same writable
storage check before doing work; low backup capacity therefore stops new contributions even while a
recent backup stamp is still fresh. Every worker, backup, doctor, or health failure invokes
`autocontribute-failure@.service`, which writes the last failed unit and UTC time to
`/var/lib/autocontribute/health/last-failure` and emits an error-priority journal event. Forward
those events to the existing host alerting system, or add another `OnFailure=` target in a drop-in.
An on-host stamp alone is not a page and is lost with the host.

Alert on workspace and Docker-data byte or inode consumption before either reaches 75%; this
precedes the fixed start-of-run floors on the reference filesystems. Docker data
exhaustion stops new sandbox containers and must be resolved with both the worker and rootless daemon
stopped; remove only understood cache or unused image data, never live daemon files directly. Space
exhaustion is a safe worker failure, but workspace exhaustion can prevent publication recovery that
still depends on a local commit. Stop the worker timer and service before removing workspaces.
Inspect each run's durable status first;
never remove a `submitting` workspace unless remote reconciliation has proven the exact commit exists
or the contribution is being abandoned through the incident procedure. Complete state bundles
intentionally exclude target repositories, so deleting a workspace is not repaired by restoring a
normal backup.

Alert before state reaches 75% of either its byte or inode total and before local backups consume
half of either total. Those operational thresholds intentionally precede the hard reserves. Do not
"fix" a headroom failure by relaxing the checked-in constants or moving files onto the parent
filesystem. Quiesce the worker, complete off-host replication, and follow the acknowledged deletion
procedure below. If state itself approaches a reserve, keep the worker stopped, create a verified
backup if the reserve check still permits it, and investigate unexpected evidence growth rather
than deleting live lineage records.

Autocontribute redacts known credential forms, but issue text, proposed changes, command output, and
public URLs are operational evidence and may appear in the journal. Never log decrypted credentials
or run shell tracing around the worker. Restrict journal access and forward it only to an approved
system.

Journald retention is host-wide, not per unit. The example
`deploy/systemd/autocontribute.journald.conf.example` keeps a bounded persistent journal for 30 days.
Review its capacity and compliance impact before installing it as a drop-in under
`/etc/systemd/journald.conf.d/`; restart journald only under the host's normal change procedure.
Keep longer-lived evidence in verified state bundles, not by making the journal unbounded.

Inspect the durable safety state after every alert and before any resume:

```bash
sudo -u autocontribute /usr/bin/flock --exclusive \
  /var/lib/autocontribute/operation.lock \
  /opt/autocontribute/current/.venv/bin/autocontribute \
  safety status --config /etc/autocontribute/autocontribute.yml
```

All ad-hoc commands that can open or change the store must either run with the packaged lock as above
or run only after all Autocontribute services are stopped. Never run `approve`, `publish`, `eval`,
`state restore`, or a second `run` beside the timer service.

### Deliberately enabling automatic publication

Do not add the runtime opt-in during installation. First collect and grade the complete deterministic
100-run cohort in `review_required` mode, satisfy the measured gate, perform a successful recovery
drill, and review the automatic pilot constraints in [Scheduled operation](scheduled-operation.md).
The production configuration must use one explicit repository, immutable attested model IDs, draft
PRs, at most one new PR per UTC day, and a repository cooldown of at least seven days.

Only then change `publishing.mode` to `auto`, provision the narrowly scoped publication credential,
and install the same root-owned opt-in drop-in for both services. The doctor is non-mutating and
cannot publish; it needs the opt-in only so its automatic-publication kill-switch check validates the
exact environment that the worker will receive.

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

Run the doctor service and a manual worker under observation, create and replicate a new complete
backup, and only then re-enable the worker timer. The opt-in is intentionally absent from the
checked-in unit, so installing the bundle alone can never enable GitHub writes.

## Kill switch and incident response

To stop new attempts, first stop and disable the worker timer. If a worker is active, inspect its
journal and allow it to reach a safe boundary when possible. An emergency stop may leave a durable
`submitting` intent or a rootless container requiring exact reconciliation on the next controlled
run.

```bash
sudo systemctl disable --now autocontribute-worker.timer
sudo systemctl stop autocontribute-worker.service
```

For automatic mode, also remove both dedicated opt-in drop-ins and reload systemd. Removing the
worker copy prevents future scheduled GitHub writes, including resuming a stranded publication; a
future worker still performs read-only remote reconciliation. Removing the doctor copy keeps its
preflight consistent with the disabled worker. Revoke the GitHub credential if host integrity or
token secrecy is uncertain.

```bash
sudo rm -- \
  /etc/systemd/system/autocontribute-worker.service.d/50-auto-publish.conf \
  /etc/systemd/system/autocontribute-doctor.service.d/50-auto-publish.conf
sudo systemctl daemon-reload
```

Once the worker is quiescent, record a persistent safety stop under the shared lock:

```bash
sudo -u autocontribute /usr/bin/flock --exclusive \
  /var/lib/autocontribute/operation.lock \
  /opt/autocontribute/current/.venv/bin/autocontribute \
  safety stop --actor OPERATOR --reason 'CONCRETE INCIDENT REASON' \
  --config /etc/autocontribute/autocontribute.yml
```

Do not resume merely to clear monitoring. Review all active trigger evidence and use the exact
trigger-set hash as described in [Scheduled operation](scheduled-operation.md).

## Workspace retention

After structurally verifying the dedicated workspace mount, the checked-in worker runs the
equivalent of this command before it reads credential files or starts the scheduled contribution,
while the shared operation lock is held:

```bash
autocontribute state gc-workspaces \
  --config /etc/autocontribute/autocontribute.yml \
  --older-than-days 7 \
  --limit 25 \
  --execute
```

For an operator review, omit `--execute`; dry run is the CLI default. The report is deterministic by
terminal update time and run ID, includes the inspected entry/byte counts, and reports how many old
candidates were deferred by the bound. Candidate discovery validates the complete supported run
corpus and fails above its 10,000-run integrity bound, so older runs without workspaces cannot hide a
newer eligible entry. `--json` produces the same report as structured JSON. An
unsafe path, symlink workspace entry, nested mount, changed state, or invalid recovery artifact is
retained and makes the command fail so systemd failure signaling can alert the operator.

Cleanup never deletes SQLite rows, run evidence, patches, validation sidecars, or evaluations. It
never selects `queued` through `submitting`, `ready_for_approval`, or `approved` workspaces. This is
critical for `submitting`: after Git has created a commit but before GitHub confirms the branch, the
workspace may contain the only byte-for-byte object that can safely resume the approved push. A
failed, cancelled, rejected, or skipped run that contains any publication-intent event or stored
publishing identity, branch, commit, PR, compensation, or active evaluation hold is also retained
for reconciliation. A `pr_open` workspace is eligible only when the hash-chained ledger proves, in
order, `publication.intent.begun`, canonical PR persistence or reconciliation, and the
`submitting -> pr_open` transition, and when the canonical PR/base/head and publishing identity,
manifest artifact, patch fingerprint, and validation artifact all agree. Lifecycle recovery then
uses the durable PR URL and commit identity; complete backups continue to validate the same patch
and validation evidence after the checkout is gone.

Execution atomically renames the selected inode into a private random quarantine below the already
opened workspace root, verifies its device/inode identity, and repeats the bounded tree and mount
inspection there before descriptor-relative recursive deletion. If the selected directory was
swapped, it is restored without deletion. A recursive deletion error after isolation preserves the
quarantine and fails the service for operator review; automatic cleanup never adopts that orphan.

The collector does not infer ownership of filesystem entries absent from durable run state and does
not remove such orphan entries. Inspect those manually with the worker stopped; preserve or move
them as forensic data until their origin is understood. Do not use `rm -rf` as a response to a full
workspace filesystem while a publication is ambiguous.

## Backups and recovery drills

The backup timer retains every successful local generation; it deliberately performs no automatic
deletion. The service account can still delete its own `0400` files, so replicate each new bundle to
versioned, access-controlled off-host storage with retention lock. Monitor that replication and keep
more than one generation. Configuration, encrypted credential sources, rootless Docker data, and
target workspaces are excluded and require separate secure recovery procedures. The collector's
eligibility checks mirror the portable-evidence boundary: a prepared terminal workspace is not
removed unless its patch and validation artifact can be verified without the checkout. A complete
bundle taken afterward still validates the retained durable generation.

Rebuild Docker data on a freshly verified bounded filesystem by restoring the reviewed daemon
configuration and pre-pulling the exact digest-pinned image; do not copy an unverified live daemon
directory into the boundary.

Local deletion is an operator action, never a timer action. Before removing one exact bundle:

1. Compute and record its local SHA-256 digest, byte size, immutable off-host object/version ID, and
   retention-lock expiry.
2. Have the replication system acknowledge that exact version, then independently read the stored
   object back and verify the same byte size and SHA-256 digest. A successful upload command or an
   object-store ETag is not a cryptographic acknowledgement.
3. Persist that receipt outside this host, verify that at least two other restorable generations
   remain, and periodically prove them through the recovery drill below.
4. Stop `autocontribute-backup.service`, re-resolve the one intended local pathname without a glob,
   compare it to the receipt once more, and only then delete that exact file.

If the provider cannot return the original bytes for independent hashing, has no immutable version
identity, or has not acknowledged retention, do not delete the local generation. This project does
not yet ship a provider-specific replication/receipt protocol, so it cannot safely automate local
retention. The fixed backup reserve turns missing acknowledgement into a visible fail-closed stop
instead of silently discarding the last trustworthy recovery point.

At least once per release, restore a copied bundle into a fresh path on a non-production host using
the same packaged version and configuration except for `storage.path`. The restore target must not
exist:

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

Do not drill against the live state path. A complete backup may fail when a `submitting` run has a
stored commit because its workspace is intentionally excluded; reconcile or finish that exact
publication on the persistent worker rather than bypassing the check.

For real recovery, keep all timers stopped and preserve the damaged or newer state device as
forensic data. The live storage root is a mount point and therefore cannot itself satisfy the CLI's
absent-target rule. Provision a new compliant state device, mount it at a temporary recovery mount,
and restore into an absent staging directory on that replacement filesystem. After the command has
fully verified the bundle, promote only its four supported top-level entries to the replacement
filesystem root while it is still offline. Do not perform this promotion on the live device.

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

If this offline promotion is interrupted, discard or reformat only the new replacement device and
retry from the retained bundle; never guess which partial files are current. Once complete, unmount
the replacement, update `/etc/fstab` to its verified UUID, mount it at
`/var/lib/autocontribute/state`, recreate and mount a compliant workspace filesystem, and run the
packaged capacity checks before starting any service. Start in `review_required` mode without the
automatic-publish opt-in. Run `doctor`, inspect `safety status`, list every known upstream PR, and
reconcile lifecycle state before allowing another attempt. A stale restore can forget a publication
reservation, gate hold, lifecycle signal, or breaker event and must never be treated as safe merely
because its archive checksum passes.

## Upgrade and rollback

Before an upgrade:

1. Disable and stop all three timers, then wait for the worker, backup, doctor, and health services
   to become inactive.
2. Create and replicate a verified complete bundle with the currently installed release.
3. Install the new release in a new root-owned directory; never modify the old directory in place.
4. Atomically repoint `current`, run the doctor service, and create a new complete backup before
   enabling timers.
5. Re-review the deployment fingerprint. A material code, dependency, interpreter, model, or policy
   change starts a new evaluation cohort and cannot inherit an automatic-publication gate.

Database migrations are offline and one-way. Never restart an old binary against state opened by a
newer release. A safe rollback therefore restores the pre-upgrade bundle into an absent state root
with the old release; it does not merely repoint `current` over the new state. Preserve the new state
under a separate quarantine path for investigation, and do not roll back across an ambiguous or
in-flight publication until its exact remote state is reconciled.

After recovery or rollback, keep automatic publication disabled until the restored lineage,
upstream PRs, reservations, lifecycle observations, breaker state, and evaluation corpus have all
been reviewed. Re-enable timers only after a fresh doctor pass, a successful manual worker in the
intended mode, and a newly verified off-host backup.
