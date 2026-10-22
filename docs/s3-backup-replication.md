# Immutable S3 backup replication

Autocontribute can copy each complete state bundle to an AWS S3 bucket under Object Lock in
compliance mode, where no AWS user can delete a version or shorten its lock before its retention
date. The [systemd deployment](systemd-deployment.md) runs replication after every backup.

A replication succeeds only when the bundle passes restore validation, the bucket has versioning and
Object Lock enabled and belongs to the expected account, the stored version is AES256-encrypted and
locked in `COMPLIANCE` mode for at least `retention_days`, and a download of that version matches
the local size and SHA-256 and passes restore validation again. Its JSON receipt is stored under the
same lock and read back. A failed attempt can leave an extra locked object in S3; it never deletes
or weakens an existing one.

## AWS prerequisites

1. Create a dedicated general-purpose bucket with Object Lock enabled at creation, which also turns
   on versioning. The name must be 3 to 63 lowercase letters, digits, or hyphens, with no dots.
2. Use a region in the standard `aws` partition. GovCloud, China, other partitions, custom
   endpoints, and S3-compatible services are not supported.
3. Record the bucket owner's 12-digit account ID from a source other than the replication
   credentials. Every request requires that owner, so a recreated or mistyped bucket that another
   account owns is refused.
4. Reserve one key prefix per host. Receipts are stored under `PREFIX/receipts/sha256/`.
5. Create a dedicated IAM identity for replication with only the actions below, limited with the
   `s3:ResourceAccount` condition and exact bucket and prefix resources.

| Action | Resource |
| --- | --- |
| `s3:GetBucketVersioning`, `s3:GetBucketObjectLockConfiguration` | The bucket |
| `s3:PutObject`, `s3:PutObjectRetention` | Objects under the prefix |
| `s3:GetObject`, `s3:GetObjectVersion`, `s3:GetObjectRetention` | Objects under the prefix |

Do not grant `s3:DeleteObject`, `s3:DeleteObjectVersion`, `s3:BypassGovernanceRetention`, or any
bucket policy, lifecycle, or Object Lock configuration change. Test the policy on a disposable
bucket first.

## Configuration

```yaml
s3_replication:
  bundle_directory: /var/backups/autocontribute
  receipt_directory: /var/backups/autocontribute/receipts
  scratch_directory: /var/backups/autocontribute/replication-scratch
  bucket: your-object-lock-bucket
  expected_bucket_owner: "123456789012"
  region: ca-central-1
  prefix: production/worker-1
```

| Key | Default | Allowed |
| --- | --- | --- |
| `bundle_directory`, `receipt_directory`, `scratch_directory` | Required | Existing directories |
| `bucket`, `expected_bucket_owner`, `region` | Required | See [AWS prerequisites](#aws-prerequisites) |
| `prefix` | `autocontribute` | No leading, trailing, or doubled `/` |
| `retention_days` | `90` | 30 to 3650 |
| `timeout_seconds` | `21600` | 10 to 86400, per S3 request |
| `max_age_hours` | `48` | 1 to 8760 |
| `local_keep_bundles` | `9` | 1 to 1000 |

The three directories must belong to the user that runs replication and must not be writable by
group or others. Relative paths resolve from the configuration file's directory. Keep the scratch
directory on the backup filesystem, never `/tmp`: each replication needs free space there for twice
the bundle size plus 5 GB plus 512 MiB. Credentials never go in the YAML.

The block is optional in `review_required` mode and required in `auto` mode. When it is present,
`doctor` and scheduled auto runs fail unless the newest bundle has a valid receipt no older than
`max_age_hours`.

## Commands

| Command | What it does |
| --- | --- |
| `state backup --complete` | Writes a verified bundle of the database, run evidence, and evaluations. Needs no network or credentials. |
| `state replicate-next-s3` | Replicates the oldest bundle in `bundle_directory` that has no receipt. Does nothing when every bundle has one. |
| `state replicate-s3 --input BUNDLE` | Replicates one bundle using `--bucket`, `--region`, `--expected-bucket-owner`, `--scratch-directory`, and optional `--prefix`, `--retention-days`, `--timeout-seconds`, and `--record-output` flags instead of the configuration. Without `--record-output`, it writes the receipt beside the bundle; in `bundle_directory`, that file makes the configured commands refuse to run. |
| `state verify-latest-s3` | Read-only. Fails unless the newest bundle has a valid receipt within `--max-age-hours` (default `max_age_hours`) and, with `--required-after FILE`, both are newer than `FILE`. |
| `state gc-bundles` | Keeps the newest `local_keep_bundles` bundles (or `--keep N`), deletes each older bundle whose receipt matches its bytes, and lists older bundles without a receipt as awaiting replication. |

All but `replicate-s3` take `--config PATH`. With `--if-configured`, `verify-latest-s3` and
`gc-bundles` succeed without checking while the block is absent in `review_required` mode.

The configured commands use only bundles named like the packaged backup's output
(`autocontribute-state-<UTC time>-<pid>.bundle.zip`) and refuse to run when another file in
`bundle_directory` looks like a bundle. Each bundle's local receipt is
`<receipt_directory>/<bundle name>.s3-replication.json`.

Replication reads `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and, for temporary credentials,
`AWS_SESSION_TOKEN` from the environment; an empty session token is refused. The replication service
loads them from encrypted credentials. Errors never include them. To run one pass by hand:

```bash
read -r -p 'AWS access key ID: ' AWS_ACCESS_KEY_ID
read -r -s -p 'AWS secret access key: ' AWS_SECRET_ACCESS_KEY; printf '\n'
read -r -s -p 'AWS session token (empty if none): ' AWS_SESSION_TOKEN; printf '\n'
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
if [[ -n "$AWS_SESSION_TOKEN" ]]; then export AWS_SESSION_TOKEN; else unset AWS_SESSION_TOKEN; fi
sudo -u autocontribute \
  --preserve-env=AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY,AWS_SESSION_TOKEN \
  /usr/bin/flock --exclusive /var/lib/autocontribute/operation.lock \
  /opt/autocontribute/current/.venv/bin/autocontribute state replicate-next-s3 \
  --config /etc/autocontribute/autocontribute.yml
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
```

## Recovery

Start from a receipt, never from the newest object name. On a surviving host, the local receipt's
`receipt_object` gives the receipt's key and version ID; after a host loss, list the versions under
`PREFIX/receipts/sha256/` with a separate recovery identity. Download the receipt by version ID,
then the bundle by the `bundle.bucket`, `bundle.key`, and `bundle.version_id` it records. Check the
file against `bundle.size` and `bundle.sha256`, then restore it into an absent `storage.path`:

```bash
autocontribute state restore --complete \
  --input /path/to/exact-version-download.bundle.zip \
  --config /path/to/recovery-only-config.yml
```

Use the release that created the bundle; a release with a different state format refuses it. Then
follow [Backups and recovery drills](systemd-deployment.md#backups-and-recovery-drills).
