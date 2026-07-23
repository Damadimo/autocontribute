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

This command never removes local backups. Local deletion remains an explicit operator action after
the exact record is reviewed, at least two other restorable generations are confirmed, and the
retention deadline satisfies policy. Compliance retention prevents even the normal AWS account from
deleting that version before expiry; it does not replace account recovery, cross-account controls,
monitoring, or a second-region/cross-account replication policy.

For a recovery drill, fetch the bundle by the `bucket`, `key`, and `version_id` in the record—not by
the latest key—and independently compare its byte size and SHA-256 to the receipt. Then run:

```bash
autocontribute state restore --complete \
  --input /path/to/exact-version-download.bundle.zip \
  --config /path/to/recovery-only-config.yml
```

Restore only into an absent state root and continue with the full recovery procedure in
[Operator-managed systemd deployment](systemd-deployment.md#backups-and-recovery-drills).

The repository does not yet install a credential-bearing replication systemd unit or provision an
AWS bucket/IAM policy. Automating this CLI therefore still requires the operator to provide a
separately reviewed service, short-lived credential delivery, alerting, and bucket policy. Keep that
networked service separate from `autocontribute-backup.service`, which intentionally remains
credential-free and network-isolated.
