# Operator-managed systemd deployment

This bundle runs one persistent Autocontribute installation on a Linux host. It schedules the
worker at 09:17 and 21:17 UTC, creates one verified complete backup at 03:17 UTC, retries immutable
S3 replication hourly at `*:37 UTC`, and checks worker, backup, and replication freshness. Before
each scheduled attempt, the worker inspects at most 25 terminal workspaces older than seven days and
removes only those that pass the durable-evidence checks below. Worker, doctor, backup, and
replication take the same local `flock`, so they cannot inspect or change the state lineage
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
| `/etc/autocontribute/rootless-docker-daemon.json` | `root:autocontribute`, `0640` | Reviewed rootless-daemon configuration pinned by the launcher |
| `/etc/autocontribute/credentials/*.cred` | `root:root`, `0600` | Encrypted systemd credentials |
| `/var/lib/autocontribute` | `root:autocontribute`, `0750` | Non-writable service-home trust boundary |
| `/var/lib/autocontribute/state` | `autocontribute:autocontribute`, `0700` | Live SQLite, evidence, and evaluations |
| `/var/lib/autocontribute/state/workspaces` | `autocontribute:autocontribute`, `0700` | Dedicated capacity-limited ext4 filesystem for target repositories and validation copies |
| `/var/lib/autocontribute/docker` | `autocontribute:autocontribute`, `0710` | Dedicated capacity-limited ext4 filesystem for rootless Docker images, layers, and metadata |
| `/var/lib/autocontribute/tmp` | `autocontribute:autocontribute`, `0700` | Private temporary files visible to the rootless Docker daemon |
| `/var/backups/autocontribute` | `autocontribute:autocontribute`, `0700` | Local immutable-name complete bundles awaiting off-host replication |
| `/run/autocontribute` | `autocontribute:autocontribute`, `0700` | Proxy-owned ephemeral daemon runtime and sole Docker socket |

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
available to the service account. The root-owned rootless Docker system service checks that mount before
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
credential, the wrapper verifies that `/run/autocontribute` is an unsymlinked `0700` directory owned
by the service identity, that its Docker socket is owned by that identity, and that the account
cannot use the host socket. The supplied rootless topology requires exact socket mode `1660`: Docker
creates the group-private `0660` socket and intentionally adds the sticky bit below
`XDG_RUNTIME_DIR` so system cleanup does not remove it. The wrapper then makes bounded daemon probes,
requires one exact `name=rootless` element in Docker's reported `SecurityOptions`, and verifies the
exact bounded data root. A failed or ambiguous check stops the service before the wrapper reads or
exports any credential.

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

The supported production baseline is Ubuntu Server 24.04 LTS (Noble) on `amd64` with systemd 255.
The supervisor deliberately binds to that release's vendor `user@.service` fragment, vendor
drop-ins, delegated `init.scope`, and manager `UnitPath`; another systemd or distribution layout
fails closed and is unsupported until it has a reviewed port and equivalent live integration. The
host also requires:

- Python 3.11 or 3.12, `uv`, Git, `flock`, GNU coreutils, util-linux `findmnt`, and e2fsprogs;
- rootless Docker on cgroup v2 with systemd resource-controller delegation, including `newuidmap`,
  `newgidmap`, `/usr/bin/dockerd-rootless.sh`, and a unique subordinate UID/GID range;
- four dedicated, fully allocated (not thin-provisioned) block devices: no more than 8 GiB for
  state, 20 GiB for workspaces, 32 GiB for rootless Docker data, and 64 GiB for local backups; and
- persistent time synchronization and outbound HTTPS for GitHub and the configured model API.

Create a locked service account whose home path is a root-owned trust boundary. The account may
traverse that directory through its private group, but it cannot create a replacement user-unit
tree there. Writable state, Docker data, temporary files, and health markers are separate children
created by the packaged tmpfiles policy. Allocate subordinate IDs that do not overlap another
account's ranges; the numbers below are examples and must be checked against `/etc/subuid` and
`/etc/subgid` first.

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

The explicit private user group is required by every supplied unit and tmpfiles rule. Do not add
the account to `docker`; the runtime preflight rejects that exact group even if a separately started
rootless daemon appears healthy. Do not change the home back to service ownership: the deployment
uses `/var/lib/autocontribute/tmp` for runtime caches and never relies on a writable home root.
Treat the account's numeric UID as immutable for the lifetime of the host. It is part of the
instance-specific user-manager trust path and cgroup identity; changing it is not an in-place
upgrade. Reprovision a fresh host or restore the original UID instead of trying to adopt an old
manager or daemon under a new identity.

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
stat --file-system \
  --format='block_size=%S blocks=%b inodes=%c available_blocks=%a available_inodes=%d' \
  /var/lib/autocontribute/docker
```

The hard ceilings are 34,359,738,368 total bytes and 1,048,576 inodes total. The fail-closed
headroom floors are 1,073,741,824 bytes and 16,384 inodes available to the unprivileged service
account. The checker uses filesystem totals for the hard ceilings and current available values for
the headroom floors. It compares mount identity by `MAJ:MIN`, so alternate device names cannot hide
a second mount. It does not need access to the block node and therefore works with the supplied
services' `PrivateDevices=yes`. CI runs both its writable mount-only path and its read-only health
path against a real loop-backed ext4 filesystem inside hardened service boundaries; production
still requires fully allocated storage.

Install the distribution packages that provide rootless Docker's binaries and dependencies,
including `dockerd-rootless.sh`, `rootlesskit`, `newuidmap`, `newgidmap`, `fuse-overlayfs`, a user
D-Bus implementation, and the networking helpers supported by that distribution. Install binaries
only. Never run
`dockerd-rootless-setuptool.sh install`, its service-start path, or any equivalent setup command: it
would create a service-owned `docker.service`, choose the conventional `/run/user/<uid>/docker.sock`,
and bypass this release's root-owned unit and launcher. Verify the package-owned entry points without
starting them:

```bash
test -x /usr/bin/dockerd-rootless.sh
test -x /usr/bin/rootlesskit
test -x /usr/bin/newuidmap
test -x /usr/bin/newgidmap
test -x /usr/bin/fuse-overlayfs
test "$(stat --format=%U -- /usr/bin/dockerd-rootless.sh)" = root
```

Rootless Docker can enforce CPU, memory, swap, and PID limits only when cgroup v2 controllers are
delegated through the user manager; a daemon reporting cgroup driver `none` ignores those limits.
The release therefore supplies two distinct root-owned units:

- `/etc/systemd/system/autocontribute-rootless-docker.service` is a hardened system-service proxy
  running as `autocontribute`. It creates `/run/autocontribute`, verifies the effective user manager
  and daemon unit, starts and continuously monitors the daemon, and stops it whenever the proxy
  exits.
- `/etc/systemd/user/autocontribute-rootless-docker-daemon.service` is the static user unit beneath
  the delegated manager. It is deliberately not enabled and is started only by the system proxy.
  Its launcher pins the config, data root, cgroup driver, sole Unix socket, and namespace-side
  socket group on the command line.

The proxy gives the user manager one aggregate 120-second readiness window; an individual probe
cannot multiply that deadline. It waits up to 120 seconds for a daemon stop and 150 seconds for a
daemon start, leaving 30 seconds beyond the user unit's respective 90- and 120-second limits. Its
15-minute system-unit startup ceiling covers those operations, the batched manager/unit
attestations, and the release preflights with several minutes of margin. Its three-minute stop
ceiling likewise exceeds the cleanup client's 120-second wait plus ten-second kill grace.

The user unit intentionally avoids systemd filesystem, namespace, capability, security-label, and
seccomp sandbox directives. In a user manager the filesystem and namespace directives introduce an
outer user namespace, while seccomp directives such as `SystemCallArchitectures=` implicitly set
`NoNewPrivileges`. Capability, secure-bit, and security-label controls can likewise remove or
confine the privilege transition required by the setuid `newuidmap` and `newgidmap` helpers. The
daemon remains unprivileged; the root-owned system proxy and unit/config paths provide the control
boundary. Worker and doctor retain their stricter system-unit sandboxes and `ProtectHome=yes`, so
they cannot reach the user bus below `/run/user`.

Create the root-owned daemon configuration at its dedicated system path before the first start. The
reference configuration pins the storage driver exercised by the production-topology integration;
the launcher supplies every security-critical location explicitly and fixes the Unix socket group
to namespace GID 0. That GID maps back to the dedicated account's private primary group on the host
instead of Docker's default group mapping into the subordinate-GID range. Any additional daemon
option is an operator-owned policy change and must be reviewed offline; never add a TCP listener.

```bash
sudo install -d -o root -g autocontribute -m 0750 /etc/autocontribute
sudoedit /etc/autocontribute/rootless-docker-daemon.json
sudo chown root:autocontribute /etc/autocontribute/rootless-docker-daemon.json
sudo chmod 0640 /etc/autocontribute/rootless-docker-daemon.json
python3 -m json.tool /etc/autocontribute/rootless-docker-daemon.json >/dev/null
test "$(stat --format=%U:%G:%a -- \
  /etc/autocontribute/rootless-docker-daemon.json)" = root:autocontribute:640
```

Use this initial content:

```json
{
  "storage-driver": "fuse-overlayfs"
}
```

Do not add `group` to this file. The launcher already supplies `--group=0`, and Docker rejects an
option supplied in both its configuration file and on the command line.

Do not start the user manager or daemon yet. The release installation below first installs and
attests the root-owned user unit and the exact
`/etc/systemd/system/user@<uid>.service.d/50-autocontribute.conf` manager drop-in for the resolved
`autocontribute` UID. That drop-in delegates
`cpu`, `cpuset`, `io`, `memory`, and `pids`, and replaces the manager's lookup path with exactly:

```text
/etc/systemd/user:/run/systemd/user:/usr/local/lib/systemd/user:/usr/lib/systemd/user
```

There is intentionally no trailing colon and no home-owned unit directory. The drop-in is
instance-specific: never install it at the template-wide `user@.service.d` path, which would alter
every account's manager. Linger is enabled later only to keep this account's delegated manager and
cgroup scopes available after boot; it does not enable the daemon user unit. The system proxy
remains the only daemon lifecycle entry point.

The later smoke test must report `/var/lib/autocontribute/docker`, cgroup v2 with the `systemd`
driver, and one exact `name=rootless` security option. `doctor` then proves the configured limits
inside a real container. The packaged services repeat the ownership, permission, mount, capacity,
group, host-socket, security-option, and `DockerRootDir` checks before reading an encrypted
credential. The only supported socket is `/run/autocontribute/docker.sock`; any legacy
`/run/user/<uid>/docker.sock` path makes startup fail closed.

## Install an immutable release

Extract a sanitized, provenance-attested Git archive or source distribution as `root:root`, without
group/other write permission, into a new, never-reused directory below
`/opt/autocontribute/releases/`. Verify its digest and complete file inventory against the
attestation before installation. Never deploy a working checkout: `.git`, untracked files, hooks,
local uv configuration, and dotenv files can contain credentials or alter a privileged build.
Install the reviewed uv 0.9.30 binary at `/usr/local/bin/uv`, owned by `root:root` and mode `0755`,
after checking its vendor digest. The build backend declared by the attested source is an explicit
privileged trust boundary. Do not select the release with `current` yet:

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

Run this source verification before installing any file from `deploy/systemd`. It binds the selected
Python package to the complete checked-out deployment inventory and rejects missing, extra,
symlinked, non-regular, incorrectly mode-set, or content-mismatched assets. The manifest contains 26
source assets: 25 have mandatory production paths and the journald example is deliberately
source-bound but optional to install because retention is host policy.

`--no-editable` keeps runtime imports inside the installed virtual environment. `--no-config`
prevents local or administrator uv configuration from changing the operation, and
`--no-python-downloads` binds it to the reviewed system interpreter. The explicit mode normalization
makes the root-owned release readable and traversable by the unprivileged service identity even when
the administrator or `sudo` policy uses `umask 077`; it still removes every group/other write bit
and every special mode bit. The ancestry, identity, mount, and `find` checks reject path aliases,
parent replacement, mounted subtrees, inspection failures, unsafe ownership, modes, file types,
development state, source symlinks, and multiply linked regular files. Source invariants are
rechecked after ownership hardening, and mount/identity invariants are checked before every recursive
root operation. `UV_PROJECT_ENVIRONMENT` binds installation to the checked path, while
`UV_LINK_MODE=copy` prevents the immutable release from sharing package inodes with uv's external
cache. The isolated service probe proves that the selected module is the installed copy beneath
this exact virtual environment, and checks the service UID before importing it. The attested
packaging backend already ran at the explicitly accepted privileged build boundary; no installed
application import or CLI runs before this probe.

Keep `release` set for the installation steps below. Do not repoint `current` while any
Autocontribute unit is active, and do not repoint it before the new deployment assets have passed
host verification. Python may import files lazily, so changing a release underneath a live process
is not an atomic application upgrade.

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

s3_replication:
  bundle_directory: /var/backups/autocontribute
  receipt_directory: /var/backups/autocontribute/receipts
  scratch_directory: /var/backups/autocontribute/replication-scratch
  bucket: your-object-lock-bucket
  expected_bucket_owner: "123456789012"
  region: ca-central-1
  prefix: production/worker-1
  retention_days: 90
  timeout_seconds: 21600
  max_age_hours: 48
  local_keep_bundles: 9
```

The S3 block is non-secret. All three directories, the bucket, independently verified 12-digit
bucket owner, and standard commercial AWS region are required. `prefix` defaults to
`autocontribute`; retention defaults to 90 days (allowed 30–3650), request timeout to 21600 seconds
(allowed 10–86400), receipt age to 48 hours (allowed 1–8760), and local bundle retention to the
newest 9 bundles (allowed 1–1000). After each replication pass the replication service runs
`autocontribute state gc-bundles`, which deletes older local bundles only when their receipts prove
the exact bundle bytes reached the configured S3 boundary; older bundles without receipts are kept
and reported as awaiting replication, so local disk usage stays bounded without ever discarding the
only copy of a backup. See
[Immutable S3 backup replication](s3-backup-replication.md) for the bucket, Object Lock, IAM, and
recovery requirements. A local/manual `review_required` configuration may omit the block, in which
case the packaged verification command reports an explicit skip. `publishing.mode: auto` rejects a
missing block, and this production deployment should configure it before enabling any timer.

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

Use a dedicated model project with hard provider-side spend limits. Use a dedicated, expiring
GitHub credential with only the target repositories and operations required by the configured mode.
The worker wrapper copies named systemd credentials into its process environment immediately before
`exec`; it never prints them. Because processes owned by the same Unix user can be a credential
boundary risk, keep this account locked and dedicated to Autocontribute and its rootless daemon.

The AWS triplet is loaded only by `autocontribute-replication.service`; it is never exposed to the
worker, doctor, local backup, sandbox, or model subprocess. The replication service receives no
GitHub or model credential. Its wrapper unsets AWS profile/shared-file, container, role, and web-
identity discovery variables and disables EC2 instance metadata before exporting only the
validated credential files. All three encrypted files must exist, but `AWS_SESSION_TOKEN.cred` may
hold an empty value for a long-lived access key that issues no session token (press Enter at its
prompt above); the wrapper then exports only the key pair and leaves `AWS_SESSION_TOKEN` unset.
Conversely, the local backup service has no credential and runs with `PrivateNetwork=yes`. Rotate
the AWS credential set as one unit and rerun replication under observation before relying on the
next timer.

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

Use the verified immutable release, not another checkout. These steps apply to first installation and
every upgrade. Before replacing an installed asset, disable all four timers and stop worker,
backup, replication, doctor, health, and the system rootless-Docker proxy. Stopping the proxy synchronously stops
the daemon user unit. On a migration from an older deployment, also stop any generic
`docker.service` while the old user manager is still reachable. Then stop the user manager itself so
no user unit can execute during the trust-path replacement. First-install commands skip units that
do not exist.

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

Before continuing, archive and remove every retired generic or home-owned unit path reported by
`deployment verify-systemd-assets`. In particular, neither `/etc/systemd/user/docker.service` nor
its drop-in directory may remain, and the service home must contain no `docker.service` or
`autocontribute-rootless-docker-daemon.service` below `.config/systemd/user` or
`.local/share/systemd/user`. Also remove the superseded generic
`/etc/systemd/system/user@.service.d/delegate.conf`. Preserve anything needed for audit in a
root-only archive outside all systemd lookup paths; do not copy settings forward implicitly.
Any numeric `user@<old-uid>.service.d/50-autocontribute.conf` is evidence of an unsupported service
UID change. The quiescence block stops that old manager and then aborts; do not remove the evidence
and continue under the new UID.

Keep every service stopped throughout the following replacement window. Stage each file beside its
final path and rename it over that path; do not copy the whole tree directly into live locations.
Each rename is atomic on its destination filesystem. A host crash can still leave a mixed release,
which is why the complete installed set is verified before anything is restarted.

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
  'autocontribute-failure@.service'
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

Confirm that the Docker smoke test reports `/var/lib/autocontribute/docker`, cgroup v2 with the
`systemd` driver, and exactly one `name=rootless` security option. Pre-pull every digest-pinned
sandbox image as the `autocontribute` user before doctor; never use a tag in production. The service
sets `TMPDIR=/var/lib/autocontribute/tmp` because Docker's daemon must see the CID files created by
the client; systemd's private `/tmp` mount is deliberately not used for those files.

The installed verifier checks all 25 mandatory paths against the manifest shipped by the selected
Python release. It requires exact path, SHA-256 content, mode, and `root:root` ownership and rejects
symlinks and non-regular files. The user-manager drop-in directory and root-owned user-unit inventory
are exact: an unreviewed second manager drop-in, a home-owned replacement, or a retired generic
Docker unit is a verification failure. Consequently, a partial copy, a mixture of old and new
assets, or a stale helper fails closed before `current` is switched and again before an operational
service can run. Worker, backup, replication, doctor, health, the system proxy, and the daemon user unit execute
the same verifier as a fixed pre-start check. The
failure recorder intentionally does not: it remains available through `OnFailure=` to record an
asset-mismatch failure and emit its journal alert.

The system proxy requires the user manager to be the active `user@<uid>.service` process beneath its
exact delegated cgroup. It binds the user-bus owner PID back to that system unit, checks the process
identity, executable, environment, controllers, and the manager's actual ordered `UnitPath`, and
requires the daemon to be a non-transient unit loaded from the exact root-owned fragment with no
drop-ins or pending reload. It repeats those checks for the lifetime of the daemon. Worker and doctor
independently require the exact active system proxy, private runtime directory and socket, rootless
security option, and bounded data root before they read credentials.

The attestation covers the checked-in base units, not the effective configuration assembled from
unit drop-ins. The documented root-owned `40-provider-credentials.conf` and
`50-auto-publish.conf` drop-ins remain allowed but are not content-attested. Review them separately,
keep their directories root-owned and non-writable by the service account, compare the worker and
doctor copies as instructed, and inspect `systemctl cat` output after every change.

Run `systemd-tmpfiles` only while all four filesystems are mounted so their filesystem roots receive
the required ownership and mode. Worker, doctor, backup, replication, and health declare `RequiresMountsFor=` for
the storage they inspect, and the credential-bearing services require both the workspace and Docker
data mounts. Their wrappers still repeat exact mount and capacity verification at every invocation;
an accidentally unmounted directory on a parent filesystem is rejected rather than used as a
fallback. The worker and backup additionally bind the Python store to the preflight-verified state
root, so changing `storage.path` cannot redirect writes around these checks. The separately installed
rootless Docker daemon user unit performs the data-mount check before the daemon itself starts.

Validate the installed files on the target host. `systemd-analyze security` is advisory; review
every relaxation instead of chasing a score that breaks rootless Docker or durable state.
CI also parses all eleven system units and the protected user unit with systemd 255 on Ubuntu 24.04
and fails on parser warnings. It performs an offline security assessment of the seven system services,
with an exposure ceiling of 4.0 for the networked worker and doctor and 3.0 for replication and the
private-network backup, health, failure, and rootless-Docker proxy units. The user daemon is deliberately assessed
separately because filesystem/mount, namespace, capability, security-label, and seccomp sandbox
directives can break subordinate-ID mapping. These are regression ceilings, not a substitute for
reviewing the full report or validating the installed units against the target host's systemd
version.

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
  'autocontribute-failure@.service'
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

Bootstrap immutable replication before the credential-bearing preflight. Independently provision and
verify the Object Lock bucket and least-privilege IAM policy described in
[Immutable S3 backup replication](s3-backup-replication.md), install the complete configuration and
AWS credential triplet above, and check the directories created by tmpfiles. The enable marker is a
deliberate root-owned switch: without it, both the backup's `OnSuccess=` activation and the retry
timer leave the conditioned replication service inert.

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

`autocontribute-backup.service` is credential-free and private-networked. Its successful completion
activates `autocontribute-replication.service`, which alone loads the AWS credentials, uploads at
most the oldest pending complete bundle, and independently reads back the exact bundle and receipt
versions. The separate hourly timer retries failures at `*:37 UTC`; it does not create another
backup.

Now run the secure preflight. This makes bounded, potentially billable model probes and Docker
probes, as documented for `autocontribute doctor`:

```bash
sudo systemctl start autocontribute-doctor.service
test "$(sudo systemctl show --property=Result --value \
  autocontribute-doctor.service)" = success
test "$(sudo systemctl show --property=ExecMainStatus --value \
  autocontribute-doctor.service)" = 0
sudo journalctl -u autocontribute-doctor.service --since today
```

Fix every failed check before enabling timers. The normal activation sequence intentionally creates
real first-run, backup, and replication evidence before enabling freshness alerts. The worker writes
`worker-attempt` before credential loading; after that marker exists, both the newest bundle and its
receipt must postdate it. Let the worker's success/failure-triggered backup chain complete, then
explicitly run both idempotent services and verify that postdating condition before enabling timers:

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

After structural validation, credential-free cleanup, and the headroom gate, the scheduled run is
the worker's first credentialed and potentially billable command. A safe skip is success and
refreshes the worker stamp. The packaged wrapper always uses `run --scheduled`, so it cannot pin an
issue or request a retry authorization. The typed orchestration boundary also marks that call as
`SCHEDULED`, which rejects an explicit issue or authorization even below the CLI. Active and
unchanged-suppressed candidates are filtered before model work and discovery continues to another
candidate; an exhausted search is still a successful safe skip. A rejected or failed attempt is a
service failure. The complete-backup command verifies the SQLite snapshot, event chains, run
manifests, evidence, evaluations, file sizes, and SHA-256 hashes before it publishes the uniquely
named bundle. It receives no credentials and has no network. Each production model request runs in
a fresh private process group with only its model credential and a minimal environment. The parent
owns an absolute monotonic deadline covering startup and bounded JSON IPC, rejects late output, and
terminates, escalates, and reaps a timed-out group. A hard timeout retains its conservative budget
reservation and records `model.call.timed_out` for a contribution-run call; it cannot produce a
completed call artifact.

## Routine operation and monitoring

Worker, backup, and replication are `Type=oneshot`; they should normally be inactive between
invocations. Use timer state, last service result, journal priority, worker/backup stamp times, and
the newest exact replication receipt as monitoring signals:

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
  -u autocontribute-replication.service \
  -u autocontribute-health.service \
  -u 'autocontribute-failure@*' \
  --since '24 hours ago'
```

The health timer runs every 15 minutes. It fails when the last successful worker is older than 18
hours, the last complete backup is older than 36 hours, either durable filesystem violates its
fixed ceiling, state or backup falls below its fixed reserve, or Docker data has less than 1 GiB or
16,384 inodes available. Before those checks, the health service also requires the newest bundle and
exact S3 receipt to be no older than 36 hours. It deliberately does not require them to postdate
`worker-attempt`: the worker refreshes that marker at the start of every run, so during a normal
in-flight worker/backup/replication window the newest evidence legitimately predates it. The
postdating check runs race-free at the worker preflight instead — before cleanup, credential
loading, or model work, and before the marker is refreshed — where it verifies the previous
attempt's evidence. Both invoke `verify-latest-s3 --if-configured`: only an absent block in `review_required`
produces an explicit skip, while a configured-but-invalid/stale block fails and auto mode cannot omit
the block. The health service's storage checks receive read-only namespace views; the Docker check
requires an explicit read-only layer over the same safe writable ext4 mount. The worker, doctor, and
backup apply the corresponding writable checks before doing work, so low capacity stops new
contributions even while a success stamp is still fresh. Every worker, backup, replication, doctor,
or health failure invokes `autocontribute-failure@.service`, which writes the last failed unit and UTC time to
`/var/lib/autocontribute/health/last-failure` and emits an error-priority journal event. Forward those
events to the existing host alerting system, or add another `OnFailure=` target in a drop-in. An
on-host stamp alone is not a page and is lost with the host.

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
The source verifier binds this example to the release, but the installed verifier deliberately has
no mandatory journald path and does not attest an operator-installed copy. Keep longer-lived evidence
in verified state bundles, not by making the journal unbounded.

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

If an operator deliberately retries an unchanged `skipped`, `rejected`, or `cancelled` issue, stop
the timer/worker, acquire the same operation lock, and invoke the manual CLI through the deployment's
approved credential-loading path with all four options:

```bash
autocontribute run \
  --issue owner/repository#123 \
  --retry-unchanged \
  --retry-actor "OPERATOR IDENTITY" \
  --retry-reason "PRIOR EVIDENCE REVIEWED; CONCRETE REASON FOR RETRY"
```

Inspect the prior evidence and then verify the new durable authorization and
`candidate.retry_override` ledger event. The authorization binds actor/reason to the exact prior
run/status/revision atomically with the lease-fenced, unique candidate claim. The new seven-field
event and authorization row must form a one-to-one pair; a migration-only marker for a historical v7
event is not retry authority. This escape hatch does not bypass an active run or any
eligibility/quality gate and must never be added to the unit or timer.

### Deliberately enabling automatic publication

Do not add the runtime opt-in during installation. First configure the final pilot shape while
keeping `publishing.mode: review_required`: one explicit repository, immutable attested model IDs,
draft staging followed by the durable exact ready-for-review transition, at most one new PR per UTC
day, a repository cooldown of at least seven days, and the complete final `s3_replication` policy.
Auto mode is rejected when that replication block is absent. Those settings are part of the deployment
fingerprint, so changing them later requires new cohorts. Under that fixed shape, collect and grade
the complete deterministic 100-run expert cohort and the fixed first 20 manually approved,
published PRs. Every fixed manual member must have both an anchored expert `accept_as_is` grade and
verified upstream `merged_as_is` history; a failed member is not replaceable. Confirm the combined
scoped decision with `autocontribute rollout report`, perform a successful recovery drill, and
review the automatic pilot constraints in [Scheduled operation](scheduled-operation.md).

Only then quiesce automatic scheduling before changing the final configuration. Disabling the timer
does not stop an already triggered worker. If the worker-inactivity assertion fails, reconcile it and
let it reach a safe terminal boundary before continuing; do not edit auto-mode configuration while
it is running.

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

With the worker proven inactive, change `publishing.mode` to `auto`, provision the narrowly scoped
publication credential, and install the same root-owned opt-in drop-in for both services. The doctor
makes no repository or GitHub writes and cannot publish, although opening the store can migrate or
repair local durable state; it needs the opt-in only so its automatic-publication kill-switch check
validates the exact environment that the worker will receive.

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
backup, and require the newest exact receipt to postdate that worker's attempt marker:

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

Do not re-enable the worker timer until every command succeeds. The opt-in is intentionally absent
from the checked-in unit, so installing the bundle alone can never enable GitHub writes.

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
worker copy prevents constructive GitHub writes after the worker is restarted; it does not alter the
environment of an already-running process. A future worker still performs read-only remote
reconciliation and, once exact compensation evidence has been durably marked, may finish only its
exposure-reducing cleanup despite the missing opt-in. An exact PR that already merged may instead be
adopted into lifecycle management without a GitHub write. The stopped service/timer above, not the
opt-in alone, is the boundary that prevents every scheduled remote write. Removing the doctor copy
keeps its preflight consistent with the disabled worker. Revoke the GitHub credential if host
integrity or token secrecy is uncertain.

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
candidates were deferred by the bound. `--limit` bounds actionable deletions; retained entries —
whether protected for reconciliation or held back as corrupt — are reported without consuming that
budget, and the total scan is separately bounded at five times the limit, so a persistent unsafe
backlog cannot starve younger deletable workspaces. Candidate discovery validates the complete
supported run corpus and fails above its 10,000-run integrity bound, so older runs without
workspaces cannot hide a newer eligible entry. `--json` produces the same report as structured
JSON. An unsafe path, symlink workspace entry, nested mount, changed state, or invalid recovery
artifact is retained and reported as an error, and the command exits with status 2 so monitoring
can alert the operator. The checked-in worker treats that exit as reported hygiene, logs it, and
continues to the scheduled contribution run: cleanup errors never wedge the scheduler, and disk
exhaustion is enforced separately by the workspace quota headroom check that follows.

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
quarantine and reports a retained error for that one workspace; the remaining candidates still
proceed. Each invocation also reclaims quarantine directories preserved by an earlier failed
deletion: only entries with the exact private quarantine shape (canonical `.autocontribute-gc-`
name, real `0700` directory on the workspace filesystem, not a mount point) that are at least six
hours old are removed, so a concurrent collection's live quarantine is never raced.

The collector does not infer ownership of filesystem entries absent from durable run state and does
not remove such orphan entries. Inspect those manually with the worker stopped; preserve or move
them as forensic data until their origin is understood. Do not use `rm -rf` as a response to a full
workspace filesystem while a publication is ambiguous.

## Backups and recovery drills

The backup timer retains every successful local generation; it deliberately performs no automatic
deletion. A successful backup immediately activates the separately credentialed replication service,
and the `*:37 UTC` timer retries the oldest pending bundle hourly. The service account can still
delete its own `0400` files, so monitor exact receipt creation and keep more than one versioned,
retention-locked off-host generation. Configuration, encrypted credential sources, rootless Docker data, and
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
identity, or has not acknowledged retention, do not delete the local generation. The AWS S3
provider-specific replication/receipt protocol is available through `state replicate-s3`; it
compliance-locks and independently reads back both the exact bundle version and its receipt. See
[Immutable S3 backup replication](s3-backup-replication.md). The packaged
`autocontribute-replication.service` invokes the configured one-at-a-time form but deliberately does
not automate local retention. The fixed backup reserve turns missing acknowledgement into a visible fail-closed
stop instead of silently discarding the last trustworthy recovery point.

For every drill or real recovery, begin from the receipt rather than an S3 latest-object lookup.
Fetch the receipt object by the exact immutable receipt version recorded in the local locator,
validate its bytes and hash against that locator when available, then fetch the bundle by the exact
immutable bucket, key, and version recorded in the receipt. Independently verify the recorded byte
count and SHA-256 before presenting that download to `state restore --complete`.

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
automatic-publish opt-in. Create a fresh complete bundle from the promoted live lineage, replicate
and read back its exact bundle and receipt versions, and require `state verify-latest-s3` to succeed.
Then run `doctor`, inspect `safety status`, list every known upstream PR, and reconcile lifecycle
state before allowing another attempt. After any observed manual worker, repeat the fresh
backup/replication cycle and verify that both files postdate `worker-attempt` before re-enabling the
worker timer. A stale restore can forget a publication reservation, gate hold, lifecycle signal, or
breaker event and must never be treated as safe merely because its archive checksum passes.

## Upgrade and rollback

Treat the application, eleven system units, eleven helpers, tmpfiles policy, instance-specific user-
manager drop-in, and protected daemon user unit as one release. An upgrade is complete only when the
new release's packaged manifest verifies all 25 installed assets. Use this order:

1. Disable all four timers. Reconcile any in-flight publication, let the worker reach a safe
   boundary, and create and replicate a verified complete bundle with the currently selected
   release. Stop worker, backup, replication, doctor, and health, wait for every failure-recorder instance to
   finish, then stop the system rootless-Docker proxy. The proxy stops the daemon user unit. Stop the
   `autocontribute` user manager before replacing its unit or manager drop-in.
2. Install the new application into a new, never-reused, root-owned release directory. Do not modify
   the old release in place and leave `current` pointing to it. Run the new release executable's
   `deployment verify-systemd-assets --source-root NEW_RELEASE` check before copying any deployment
   asset.
3. Follow **Install and validate the units** with `release=NEW_RELEASE`: stage and rename each base
   unit, helper, tmpfiles file, user unit, and resolved-UID manager drop-in at its final filesystem,
   then verify all
   installed paths with `NEW_RELEASE/.venv/bin/autocontribute deployment verify-systemd-assets`.
   Keep every service stopped if any replacement or verification fails.
4. Reload the system manager, restart the lingering `autocontribute` user manager so the delegated
   instance policy is present in its process environment, and reload that manager. Require
   `NeedDaemonReload=no` for every packaged system unit and
   `autocontribute-rootless-docker-daemon.service`, and re-run the exact manager/UnitPath checks.
   Only then atomically repoint `current` and repeat installed verification through the new
   executable.
5. Start the system rootless-Docker proxy, create and replicate a new complete backup, verify its
   fresh exact receipt, run doctor, and fix every failure before re-enabling any timer. Re-review the
   deployment fingerprint: a material
   code, dependency, interpreter, model, deployment-asset, or policy change starts a new evaluation
   cohort and cannot inherit an automatic-publication gate. Re-enable timers only after these checks
   and any required observed manual worker run succeed.

Per-file rename prevents a reader from seeing a partially written individual file; it does not make
the 25-file set atomic. Quiescence prevents that intermediate set from executing, and manifest
verification detects any interrupted, stale, or mixed installation. Never work around a mismatch by
starting an old `current` against new assets. Either finish the new installation, or reinstall the
complete old asset set from its verified immutable release, reload both managers, prove no reload is
pending, and reverify it before resuming the old release.

Database migrations are offline and one-way. Never restart an old binary against state opened by a
newer release. A safe rollback therefore restores the pre-upgrade bundle into an absent state root
with the old release and its complete manifest-matched deployment assets; it does not merely repoint
`current` over the new state. Preserve the new state under a separate quarantine path for
investigation, and do not roll back across an ambiguous or in-flight publication until its exact
remote state is reconciled.

After recovery or rollback, keep automatic publication disabled until the restored lineage,
upstream PRs, reservations, lifecycle observations, breaker state, and evaluation corpus have all
been reviewed. Re-enable timers only after a fresh doctor pass, a successful manual worker in the
intended mode, and a newly verified off-host backup whose exact receipt postdates that worker
attempt.
