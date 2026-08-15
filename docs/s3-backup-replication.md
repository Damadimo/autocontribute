# Immutable S3 backup replication

`autocontribute state replicate-s3` is the networked half of the production backup boundary. It
consumes a complete bundle created by `state backup --complete`; it does not create state, mutate a
run, delete a local generation, or share credentials with the credential-free backup service.

A successful command proves all of the following before it returns:

- the local input is a fully restorable complete bundle, not merely a readable ZIP;
- the destination bucket has versioning and S3 Object Lock enabled;
- every signed bucket and object request is restricted to one explicit 12-digit AWS owner account;
- the uploaded bundle has an immutable version ID, a SHA-256 checksum, AES256 server-side
  encryption, and a future `COMPLIANCE` retention deadline at least as long as requested;
- an independent GET of that exact version has the same byte count and SHA-256 digest and again
  passes the complete restore validation;
- a JSON receipt binding that evidence is itself uploaded with compliance retention, then read back
  by its exact immutable version ID and byte-compared; and
- the local receipt locator is created as a new `0400` file and never replaces an existing record.

An upload response, ETag, latest object name, or HEAD response alone is not accepted as proof. The
command uses content-addressed keys and sends `If-None-Match: *`. On a retry collision, it adopts the
latest version only if its size, SHA-256 checksum, metadata, encryption, and compliance retention all
match. A failure can therefore leave an additional locked object, but never weakens or deletes an
existing recovery point.

## AWS boundary

Create a dedicated AWS S3 general-purpose bucket with Object Lock enabled at bucket creation. The
bucket name must be lowercase DNS-safe text without dots; this lets the client use one fixed Amazon
virtual-host endpoint with TLS hostname validation. Custom S3-compatible endpoints and redirects
are deliberately unsupported. Only the standard commercial `aws` partition is supported; GovCloud,
China, ISO, and other isolated partitions use different endpoint boundaries and are rejected. Keep
the bucket in one explicit region and reserve a distinct key prefix for each Autocontribute state
lineage.

Record the bucket owner's 12-digit AWS account ID independently of the runtime credentials. Pass it
on every invocation with `--expected-bucket-owner`. The client signs
`x-amz-expected-bucket-owner` into every bucket inspection, upload, acknowledgement, and read-back
request, and binds that account ID into both immutable-object receipts. A deleted/recreated bucket,
mistyped name, or overly broad cross-account policy therefore fails instead of receiving backup
bytes. Also constrain the IAM policy with `s3:ResourceAccount` and exact bucket/prefix resources.

Use `COMPLIANCE`, not governance mode. Give the replication identity only the key-prefix and bucket
inspection actions it needs:

- `s3:GetBucketVersioning`
- `s3:GetBucketObjectLockConfiguration`
- `s3:PutObject` and `s3:PutObjectRetention` on the deployment prefix
- `s3:GetObject`, `s3:GetObjectVersion`, and `s3:GetObjectRetention` on the deployment prefix

`PutObjectRetention` authorizes the per-object compliance deadline sent with each upload, and
`GetObjectRetention` allows the client to acknowledge the returned retention evidence. Keep both
even though this implementation observes the lock through version-bound HEAD/GET responses rather
than issuing separate retention mutations after upload. `GetObject` is needed for a collision check
against the latest key; `GetObjectVersion` is needed for every immutable-version read-back.

Do not grant `s3:DeleteObject`, `s3:DeleteObjectVersion`, `s3:BypassGovernanceRetention`, bucket
policy administration, lifecycle administration, or Object Lock configuration writes. Add the
organization's normal explicit-deny controls for non-TLS access and unauthorized principals. The
command sets per-object retention itself, so the principal must be allowed to include the Object
Lock headers on `PutObject`. Validate the exact policy in a disposable bucket before production.

The client performs one signed `PutObject` per artifact, so the complete bundle must fit S3's
single-request object limit. It does not implement multipart upload because an incomplete multipart
state complicates immutable acknowledgement. The existing complete-bundle bound fits that limit.

## Configuration

Automated selection, replication, and verification use one strict non-secret policy block:

```yaml
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

The three directories, `bucket`, `expected_bucket_owner`, and `region` are required. `prefix`
defaults to `autocontribute`; it must be a non-empty safe namespace with no leading or trailing
slash. `retention_days` accepts 30 through 3650 and defaults to 90. `timeout_seconds` accepts 10
through 86400 seconds and defaults to 21600. `max_age_hours` accepts 1 through 8760 and defaults to
48; `doctor` and the application-level scheduled-auto preflight use it when checking the latest
bundle and receipt. `local_keep_bundles` accepts 1 through 1000 and defaults to 9; `state
gc-bundles` uses it to bound how many complete bundles stay on local disk. Relative directory paths
resolve from the configuration file, but production deployments should use the explicit dedicated
paths above. Credentials never belong in YAML.

This block is optional for local or manual `publishing.mode: review_required` use. The strict
configuration validator rejects `publishing.mode: auto` when it is absent. A configured block is
always checked: invalid, missing, or stale evidence fails `doctor`, even in review mode. The
`state verify-latest-s3 --if-configured` option skips only when the block is absent *and* the mode is
`review_required`; it is not a general bypass and cannot skip verification in auto mode.

`state replicate-next-s3` selects at most the oldest complete bundle without a matching receipt and
applies this policy. `state verify-latest-s3` then proves that the newest complete bundle and its
local receipt describe the exact configured bucket, account, region, prefix, hashes, and immutable
version IDs within the allowed age.

## Run a replication

Run replication only after the local backup command has finished, preferably under the same
operator-managed lock used for other state operations. Use an exact pathname, never a glob. Supply
short-lived AWS role credentials through the standard environment names without writing their
values into configuration, arguments, shell history, or chat. For an interactive drill, read them
from the terminal without echo; production should inject them from an approved secret manager:

```bash
sudo install -d -o autocontribute -g autocontribute -m 0700 \
  /var/backups/autocontribute/receipts \
  /var/backups/autocontribute/replication-scratch

read -r -p 'AWS access key ID: ' AWS_ACCESS_KEY_ID
read -r -s -p 'AWS secret access key: ' AWS_SECRET_ACCESS_KEY
printf '\n'
read -r -s -p 'AWS session token (empty only for a credential without one): ' AWS_SESSION_TOKEN
printf '\n'
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN

bundle=/var/backups/autocontribute/autocontribute-state-EXACT.bundle.zip
record=/var/backups/autocontribute/receipts/autocontribute-state-EXACT.s3.json
scratch=/var/backups/autocontribute/replication-scratch
expected_bucket_owner=123456789012

sudo -u autocontribute --preserve-env=AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY,AWS_SESSION_TOKEN \
  /opt/autocontribute/current/.venv/bin/autocontribute state replicate-s3 \
  --input "$bundle" \
  --bucket YOUR_OBJECT_LOCK_BUCKET \
  --expected-bucket-owner "$expected_bucket_owner" \
  --region ca-central-1 \
  --scratch-directory "$scratch" \
  --prefix production/worker-1 \
  --retention-days 90 \
  --record-output "$record"

unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN \
  bundle expected_bucket_owner record scratch
```

`AWS_SESSION_TOKEN` is optional only for credential types that do not issue one. The command refuses
to start without the access-key ID and secret-access key. Expected failures report an HTTP status
and bounded AWS error code; credential values, authorization headers, and response bodies are never
included in the error.

Both the record parent and scratch directory must already exist, be owned by the invoking
replication identity, and not be writable by group or other users. The local record is created with
`O_EXCL`, fsynced, and then committed by fsyncing that pre-existing parent; the command never
recursively creates a directory chain whose durability is unknown. Scratch data lives in a private
per-run subdirectory and is removed after the command. Before copying, the command requires free
scratch capacity for two complete compressed bundle copies, the maximum 5 GB expanded recovery
generation, and a 512 MiB safety reserve. At the maximum bundle bound this is 15.2 GB plus the
reserve, in addition to the original bundle. Put scratch on the dedicated, monitored backup
filesystem, never on `/tmp` or the host root filesystem, and serialize replication attempts so two
preflights cannot consume the same reserve.

The local record identifies both exact S3 version IDs and the receipt SHA-256. Preserve it with the
host's operational evidence, but do not treat it as the only receipt: the receipt JSON is already in
the locked off-host bucket. A host loss can recover receipts by listing versions under the
content-addressed `receipts/sha256/` prefix using a separately controlled recovery identity.

## Retention and recovery

`state replicate-next-s3` never removes local backups. Local retention is the separate
`state gc-bundles` command: it keeps the newest `local_keep_bundles` complete bundles
unconditionally and deletes an older bundle (with its receipt) only after re-verifying that the
receipt binds that bundle's exact bytes to the configured bucket, account, region, and prefix. An
older bundle without a receipt is never deleted; it is reported as awaiting replication so the only
local copy of a backup cannot be discarded. An invalid receipt fails the command instead of being
skipped. Compliance retention prevents even the normal AWS account from deleting an uploaded
version before expiry; it does not replace account recovery, cross-account controls, monitoring, or
a second-region/cross-account replication policy.

For a recovery drill, fetch the receipt and bundle by their exact immutable version IDs—not by a
latest object name. Use the receipt's `bucket`, `key`, and `version_id`, independently compare the
bundle byte size and SHA-256 to the receipt, and then run:

```bash
autocontribute state restore --complete \
  --input /path/to/exact-version-download.bundle.zip \
  --config /path/to/recovery-only-config.yml
```

Restore only into an absent state root and continue with the full recovery procedure in
[Operator-managed systemd deployment](systemd-deployment.md#backups-and-recovery-drills).

Keep automatic publication disabled throughout recovery. After restoring and validating the exact
generation into an absent root, create a fresh complete bundle, let the replication service upload
and independently read it back, and run `state verify-latest-s3` successfully before re-enabling the
worker timer. This creates evidence for the recovered live lineage instead of resuming from only an
old off-host acknowledgement.

## Packaged systemd replication

The packaged deployment keeps local backup creation and networked replication in separate services.
`autocontribute-backup.service` has no credentials, uses a private network namespace, and triggers
`autocontribute-replication.service` with `OnSuccess=` only after a complete bundle succeeds. The
replication service is inert unless the root-owned
`/etc/autocontribute/s3-replication.enabled` marker exists. Its timer retries one pending bundle
hourly at `*:37 UTC` (plus its fixed randomized delay), so a network or credential failure does not
require another state mutation or backup.

Only the replication service loads the encrypted `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and
`AWS_SESSION_TOKEN` credential files. As in the interactive drill above, `AWS_SESSION_TOKEN` may be
stored as an encrypted empty value for a long-lived access key that issues no session token; the
wrapper then leaves the variable unset instead of exporting an empty one. Its wrapper rejects
unsafe credential paths, unsets alternate AWS profile, shared-file, container, role, and
web-identity discovery variables, and sets `AWS_EC2_METADATA_DISABLED=true` before invoking
`state replicate-next-s3`. After a successful replication pass the wrapper runs
`state gc-bundles`, so a freshly proven receipt frees its older local bundle in the same run and
the hourly retry timer keeps local disk usage bounded. The backup remains
credential-free and private-networked. Worker and doctor receive GitHub/model credentials but no AWS
credentials; the replication service receives the AWS triplet but no GitHub or model credential.

Before every packaged scheduled attempt, the worker runs `state verify-latest-s3` with a maximum age
of 36 hours. Once `/var/lib/autocontribute/health/worker-attempt` exists, both the newest complete
bundle and its receipt must also postdate that marker, proving the prior attempt was captured and
replicated before another begins. The health service requires the same freshness but deliberately
not the postdating condition: the worker refreshes the marker at the start of every run, so a
polling check would fail by design for the whole in-flight worker/backup/replication window. Both
use `--if-configured`, which explicitly skips an absent block only in `review_required`; an auto
configuration cannot omit the block. The Python scheduled-auto preflight separately enforces the
configured `max_age_hours` before rollout evaluation or model work.

Bootstrap in this order: provision and independently verify the Object Lock bucket and least-
privilege IAM policy; add the complete `s3_replication` block; create the bundle, receipt, and scratch
directories; install the encrypted AWS credentials; and create the enable marker. Run the backup
service once, allow its immediate replication service to finish, and verify the newest exact receipt.
Only then enable the worker, backup, replication, and health timers. The operator must still provide
the AWS bucket, IAM policy, credential rotation, monitoring, and recovery identity; the repository
does not provision cloud resources.
