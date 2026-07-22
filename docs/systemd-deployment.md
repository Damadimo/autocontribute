# Operator-managed systemd deployment

This bundle runs one persistent Autocontribute installation on a Linux host. It schedules the
worker at 09:17 and 21:17 UTC, creates one verified complete backup at 03:17 UTC, and checks the
freshness of both. The worker and backup take the same local `flock`, so they cannot read or change
the state lineage concurrently.

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
| `/var/lib/autocontribute/state` | `autocontribute:autocontribute`, `0700` | Live SQLite, evidence, evaluations, and workspaces |
| `/var/lib/autocontribute/tmp` | `autocontribute:autocontribute`, `0700` | Private temporary files visible to the rootless Docker daemon |
| `/var/backups/autocontribute` | `autocontribute:autocontribute`, `0700` | Local immutable-name complete bundles awaiting off-host replication |

The shared lock is `/var/lib/autocontribute/operation.lock`, outside the captured state root. It
serializes the packaged worker, doctor, and backup services on this host. It is not a distributed
lock: never run a second host, an ad-hoc CLI writer, or the hosted scheduler against the same
lineage. Keep the state on a local filesystem with working SQLite locks; do not place it on NFS or an
eventually consistent mount.

The sandbox daemon must be rootless and owned by the dedicated `autocontribute` account. Membership
in the host `docker` group or use of `/var/run/docker.sock` would give the worker root-equivalent
control and defeats this deployment boundary.

## Host prerequisites

The reference units target systemd 252 or newer and a Linux distribution with:

- Python 3.11 or 3.12, `uv`, Git, `flock`, and GNU coreutils;
- rootless Docker, including `newuidmap`, `newgidmap`, and a unique subordinate UID/GID range;
- enough durable disk for the live workspaces and several backup generations; and
- persistent time synchronization and outbound HTTPS for GitHub and the configured model API.

Create a locked service account with a durable home. Allocate subordinate IDs that do not overlap
another account's ranges; the numbers below are examples and must be checked against
`/etc/subuid` and `/etc/subgid` first.

```bash
sudo useradd --system --create-home \
  --home-dir /var/lib/autocontribute \
  --shell /usr/sbin/nologin autocontribute
sudo usermod --add-subuids 200000-265535 --add-subgids 200000-265535 autocontribute
sudo loginctl enable-linger autocontribute
```

Install rootless Docker for that account using the distribution's supported procedure. Start its
user manager and user service without changing the account's login shell:

```bash
autocontribute_uid="$(id -u autocontribute)"
sudo systemctl start "user@${autocontribute_uid}.service"
sudo -u autocontribute env \
  HOME=/var/lib/autocontribute \
  XDG_RUNTIME_DIR="/run/user/${autocontribute_uid}" \
  DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${autocontribute_uid}/bus" \
  systemctl --user enable --now docker.service
sudo -u autocontribute env \
  HOME=/var/lib/autocontribute \
  XDG_RUNTIME_DIR="/run/user/${autocontribute_uid}" \
  DOCKER_HOST="unix:///run/user/${autocontribute_uid}/docker.sock" \
  docker info
unset autocontribute_uid
```

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

For another API-key environment name, add a service drop-in that resets and rebuilds both lists. The
GitHub credential remains required. For example:

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

Validate the installed files on the target host. `systemd-analyze security` is advisory; review
every relaxation instead of chasing a score that breaks rootless Docker or durable state.

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

The first worker command is a real, billable attempt. A safe skip is success and refreshes the worker
stamp. A rejected or failed attempt is a service failure. The complete-backup command verifies the
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
sudo journalctl \
  -u autocontribute-worker.service \
  -u autocontribute-backup.service \
  -u autocontribute-health.service \
  -u 'autocontribute-failure@*' \
  --since '24 hours ago'
```

The health timer fails when the last successful worker is older than 18 hours or the last complete
backup is older than 36 hours. Every worker, backup, doctor, or health failure invokes
`autocontribute-failure@.service`, which writes the last failed unit and UTC time to
`/var/lib/autocontribute/health/last-failure` and emits an error-priority journal event. Forward
those events to the existing host alerting system, or add another `OnFailure=` target in a drop-in.
An on-host stamp alone is not a page and is lost with the host.

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
and add this root-owned drop-in with `systemctl edit autocontribute-worker.service`:

```ini
[Service]
Environment=AUTOCONTRIBUTE_ALLOW_AUTO_PUBLISH=1
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

For automatic mode, also remove the `AUTOCONTRIBUTE_ALLOW_AUTO_PUBLISH=1` drop-in and reload systemd.
Removing it prevents future scheduled GitHub writes, including resuming a stranded publication; a
future worker still performs read-only remote reconciliation. Revoke the GitHub credential if host
integrity or token secrecy is uncertain.

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

## Backups and recovery drills

The backup timer retains every successful local generation; it deliberately performs no automatic
deletion. The service account can still delete its own `0400` files, so replicate each new bundle to
versioned, access-controlled off-host storage with retention lock. Monitor that replication and keep
more than one generation. Configuration, encrypted credential sources, rootless Docker data, and
target workspaces are excluded and require separate secure recovery procedures.

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

For real recovery, keep all timers stopped, preserve the damaged or newer state as forensic data,
and restore into an absent `/var/lib/autocontribute/state`. Start in `review_required` mode without
the automatic-publish opt-in. Run `doctor`, inspect `safety status`, list every known upstream PR,
and reconcile lifecycle state before allowing another attempt. A stale restore can forget a
publication reservation, gate hold, lifecycle signal, or breaker event and must never be treated as
safe merely because its archive checksum passes.

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
