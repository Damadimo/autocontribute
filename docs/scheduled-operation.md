# Scheduled operation

The included workflow runs at 09:17 and 21:17 UTC. It is inert until the repository variable
`AUTOCONTRIBUTE_ENABLED` is set to `true`.

## Setup

1. Copy `autocontribute.example.yml` to `autocontribute.yml`, choose a small explicit repository
   allowlist, and set `github.auth: token` for CI. Commit `autocontribute.yml` to the default branch
   before enabling the workflow. The workflow does not synthesize configuration and fails closed if
   the file is absent.
2. Choose a pinned sandbox image that already contains the toolchain and dependencies needed by those
   repositories. The hosted workflow requires the Docker backend, disabled validation networking,
   and no unsafe-local opt-in. Its configured aggregate model ceiling plus worst-case sandbox command
   budget must not exceed 180 minutes; the four-hour job timeout reserves the remaining hour for
   preflight and fail-closed state finalization.
3. Protect the control repository's default branch before storing any hosted credential. Require pull
   requests and passing CI, apply the rule to administrators where supported, and block force pushes
   and deletion. If the account plan cannot enforce these controls for the repository, keep hosted
   secrets and the schedule disabled; use a trusted persistent worker or move a sanitized control
   repository to a visibility/plan that supports protection.
4. Add `OPENAI_API_KEY` and `AUTOCONTRIBUTE_GITHUB_TOKEN` as GitHub Actions secrets. Prefer an expiring
   GitHub App user token in hosted systems. This prepare-only workflow needs only the read permissions
   required for discovery and lifecycle polling. Provision a separate, short-lived write-capable
   credential only on the trusted persistent worker that performs an approved publication. Also add
   `AUTOCONTRIBUTE_STATE_TOKEN`: use an expiring fine-grained PAT restricted to this control repository
   with only **Variables: Read and write** (plus GitHub's implicit metadata read). Grant it no contents,
   issues, pull-request, or Actions access, and rotate it independently from the target-repository
   credential.
5. Leave `publishing.mode: review_required`. The hosted workflow validates this setting and rejects
   `auto`; it is a permanent prepare-and-review boundary, not an autonomous publisher.
6. Set the repository variable `AUTOCONTRIBUTE_ENABLED=true`.
7. Before waiting for a schedule, manually dispatch **Prepare contribution** from the default branch
   with `bootstrap_state=true`. This explicit dispatch creates the first state lineage. After that
   first successful run, leave `bootstrap_state=false`; normal dispatches and schedules must restore
   the existing lineage.

The workflow's `GITHUB_TOKEN` has only `contents: read`; it cannot maintain repository variables.
Only the dedicated state token is exposed to the three lineage-control steps that read, claim, and
commit `AUTOCONTRIBUTE_STATE_LINEAGE`. The first bootstrap creates the variable; operators must not
edit or delete it to bypass a failed run. For a longer-lived deployment, mint an equivalent
short-lived GitHub App installation token from an app installed only on the control repository with
**Variables: Read and write**, instead of broadening either repository token.

The workflow preloads the configured Docker image, reconciles interrupted publications and open-PR
lifecycle state, runs `doctor`, prepares one attempt, and uploads evidence even when the attempt
skips or rejects a candidate. Reconciliation deliberately precedes `doctor`: an ambiguity may trip
the persistent breaker, but that breaker must not prevent a later scheduler invocation from safely
observing or compensating the already-authorized publication.

The first run cannot be a scheduled event: schedules have no `bootstrap_state` input, and a cache
miss fails closed. Use bootstrap only for the first-ever lineage. If an established cache is missing
or evicted, disable the schedule and recover a known-good backup instead of silently bootstrapping
away duplicate, evaluation, lifecycle, or circuit-breaker history.

## Lifecycle sync and persistent safety stop

`autocontribute run --scheduled` starts by running the equivalent of:

```bash
uv run autocontribute lifecycle sync
```

The sync polls every PR represented by a durable `pr_open` run before candidate discovery. It stores
immutable observations and trips the global circuit breaker for any of these signals:

- the PR head differs from the prepared commit;
- a maintainer's latest effective review requests changes;
- a non-bot owner, member, or collaborator explicitly asks the contribution or automation to stop;
- the latest CI check or commit status fails;
- the PR is closed without merge; or
- a later merged PR explicitly reverts the contribution.

If polling is incomplete or inconsistent, the scheduled attempt fails closed. If a signal trips the
breaker, the following preparation is rejected before discovery or model work. The same breaker is
checked throughout publication, including immediately before GitHub writes. Lifecycle sync itself
prints the evidence and exits with status 2 while a stop is active.

Operators can inspect or activate the stop without running a contribution attempt:

```bash
uv run autocontribute safety status
uv run autocontribute safety status --json
uv run autocontribute safety stop \
  --actor "OPERATOR" \
  --reason "CONCRETE REASON"
```

The stop applies globally to preparation and publication. It does not expire and must not be cleared
just to make the schedule green. First inspect the source and reason from `safety status`, review the
PR/review/check evidence printed by lifecycle sync, and determine the safe operational response.
Only then record the operator and reviewed resolution:

```bash
uv run autocontribute lifecycle sync
uv run autocontribute safety resume \
  --actor "OPERATOR" \
  --reason "EVIDENCE REVIEWED AND CONDITION RESOLVED" \
  --expected-trigger-hash "ACTIVE REVISION FROM safety status"
```

Resume is explicit, audited, and bound to the complete active trigger-set revision; it does not erase
lifecycle snapshots or prior trip events. Every distinct stop changes that revision. If new
qualifying evidence arrives after review, the old revision is rejected and the operator must inspect
the complete active evidence set again.

## State continuity and human approval

GitHub-hosted runners are ephemeral. Each job first resolves the external
`committed:<exact-cache-key>` lineage without changing it. It restores only that exact cache
key—never an older prefix match—installs the locked application, validates the hosted configuration,
and promotes and verifies the snapshot in the runner's local storage. The lineage key declares v3,
v4, or v5; the job verifies that the canonical snapshot has that exact schema, then opens it and
completes any required migration to v5. A cache, setup, configuration, dependency, or local-restore failure therefore
leaves the external committed generation unchanged and retryable.

Immediately before lifecycle/model work—or the snapshot-only handoff—the job rereads the lineage,
requires it to equal the value resolved before preflight, and changes it to an `in-progress` claim.
At the end, `autocontribute state backup` uses SQLite's online-backup API to fold committed WAL pages
into `.autocontribute/snapshots/state.sqlite3`, checks the snapshot's integrity and schema, and
publishes it atomically. That snapshot,
`.autocontribute/runs/`, and `.autocontribute/evaluations/` are saved under a unique, immutable cache
key and uploaded as one evidence artifact. Because the cache save action reports some upload failures
as warnings, the job independently performs an exact-key, lookup-only restore and requires a cache
hit. Only after that verification and the artifact upload succeed does it advance the variable to the
new committed key. If a runner stops after the claim or either persistence operation fails, the
variable remains `in-progress`; every later run refuses to restore an older generation. This carries
the run ledger, active-candidate history, evidence bundles, and expert corpus forward without silent
rollback. The concurrency group prevents two scheduler jobs from racing to extend that history.

Expert evaluations are immutable JSON revision files under `.autocontribute/evaluations/`; they are
not rows in SQLite and are not embedded in a state snapshot. The initial `<run-id>.json` may be
superseded only by `eval amend`, which appends `<run-id>.revision-000002.json` and records a mandatory
reason and the previous revision hash. Content hashes, reviewed-subject hashes, verdicts, schema
metadata, revision numbers, and predecessor hashes are anchored in the hash-chained SQLite event
ledger. Evaluation loading rejects edited, added, deleted, duplicated, renamed, non-consecutive,
predecessor-mismatched, or artifact-mismatched records and recomputes every run event's hash and
predecessor link. The latest valid revision drives metrics, but every historical revision must
validate. The resulting event count and terminal hash must match the durable event anchor on the run
row, so deleting a negative grade and its tail event cannot turn the remaining prefix into a valid
shorter chain. The rollout gate uses only the
first 100 runs for the current deployment fingerprint in deterministic creation-time/run-ID order and
requires all 100 grades. That fingerprint binds exact package source, Python interpreter, installed
runtime dependency closure and the packaged build/lock manifest to the material model, budget,
discovery, sandbox, validation, policy, quality, and publishing-safety configuration. Evidence from
another fingerprint never unlocks automatic publication; a material code, model, or configuration
change requires a fresh calibration cohort. A usable backup or migration must therefore preserve the
verified SQLite snapshot, run bundles, and evaluation directory from the same generation. The
commands without `--complete` cover only SQLite; operator-managed deployments should use the
complete bundle mode described below.

Legacy evaluation JSON without a matching ledger anchor does not silently carry into the rollout
gate. Keep it only as historical material outside the active `evaluations/` directory and build the
measured gate from newly sealed, ledger-anchored cases; do not manufacture anchors or rewrite old
grades.

The cache is operational continuity, not an approval record or permanent backup. GitHub may evict
caches. The live SQLite database and its WAL/SHM files, target-repository workspaces,
`autocontribute.yml`, API keys, and GitHub credentials are never cached. Current jobs write exact
`autocontribute-state-v5-...` keys selected by the external lineage variable. They accept an exact
v5 key or exact repository- and runner-bound v4/v3 keys already committed in that variable. The
older keys are one-way upgrade bridges: their snapshots must match the declared schema, are migrated
before work, and are replaced by a newly saved v5 generation. There is no prefix fallback, arbitrary legacy-key
acceptance, or externally pointed v2 cache path; do not rename a cache or rewrite the variable to
force acceptance.

The current schema is v5. Restore accepts only an exact canonical v5, v4, v3, or v2 database,
including the expected tables and indexes and the absence of extra views or triggers. A v4/v5 snapshot's full event
ledger is recomputed and compared with every run's count/head anchor before promotion. A v2 or v3
snapshot is structurally validated and promoted unchanged; the next command that opens `RunStore`
migrates it transactionally through v3, v4, and v5. The v2-to-v3 step backfills durable publication
reservations for `submitting` and `pr_open` runs at migration time, intentionally making the current
UTC-day limit and repository cooldown conservative. The v3-to-v4 step validates every legacy event
chain, creates the atomic count/head anchors, seeds persistent lease-generation counters from active
leases, and conservatively holds the evaluation corpus for ambiguous submitting publications. The
v4-to-v5 step adds a transactional manifest-artifact synchronization outbox and validates the
materialized reservation/hold tables against their hash-chained events so incomplete state cannot
reset capacity or silently remove an automatic gate hold. Stop every older worker before this
offline, one-way cutover and never restart one against the migrated lineage. Preserve a new v5
snapshot before the next ephemeral job.

> [!IMPORTANT]
> The circuit breaker is persistent only within this durable state lineage. GitHub-hosted runners do
> not retain a stop by themselves: if the verified snapshot is not saved and restored—or its cache is
> evicted—the new runner has no local breaker or lifecycle history. Treat the cache as convenience,
> keep operator-managed backups, and use `AUTOCONTRIBUTE_ENABLED=false` (and remove
> `AUTOCONTRIBUTE_ALLOW_AUTO_PUBLISH`) as the out-of-band stop while continuity is uncertain. Never
> resume from a replacement or stale database without reviewing the known upstream PRs directly.

Every job that successfully creates and caches its verified snapshot uploads a 14-day evidence
artifact named
`autocontribute-<workflow-run-id>-<run-attempt>`. That immutable artifact contains the same verified
snapshot, run bundles, and separate evaluation files and is the review handoff. Command output and
reports are credential-redacted, but the manifest and ledger retain the public issue text and
proposed contribution text; handle the artifact as review data, not as a sanitized public export.
Missing artifact files are a hard failure and prevent the lineage from being committed.

Do not publish directly from an ordinary artifact while the hosted scheduler remains active; that
would create a divergent local state lineage which hosted lifecycle polling cannot see. First
manually dispatch **Prepare contribution** with `lock_for_handoff=true` and no bootstrap flag. The
handoff run restores the committed generation, skips lifecycle/model work, saves it under a new exact
key, and uploads the sealed artifact. Only after that upload succeeds does it mark the external
lineage `handoff:<key>`. All later hosted runs refuse to start. Set
`AUTOCONTRIBUTE_ENABLED=false`, then download that handoff run on a trusted machine, verify and
atomically restore the snapshot, and inspect and approve the exact run:

```bash
if [ -e .autocontribute ] || [ -L .autocontribute ]; then
  echo ".autocontribute must not exist before handoff extraction" >&2
  exit 1
fi
mkdir -m 700 .autocontribute
gh run download HANDOFF_WORKFLOW_RUN_ID \
  --name autocontribute-HANDOFF_WORKFLOW_RUN_ID-RUN_ATTEMPT \
  --dir .autocontribute
test ! -e .autocontribute/state.sqlite3
read -rsp "Write-capable target-repository token: " AUTOCONTRIBUTE_GITHUB_TOKEN
export AUTOCONTRIBUTE_GITHUB_TOKEN
printf '\n'
uv run autocontribute state restore \
  --input .autocontribute/snapshots/state.sqlite3
uv run autocontribute runs show AUTOCONTRIBUTE_RUN_ID
uv run autocontribute approve AUTOCONTRIBUTE_RUN_ID
uv run autocontribute publish AUTOCONTRIBUTE_RUN_ID
unset AUTOCONTRIBUTE_GITHUB_TOKEN
```

The `handoff:<key>` marker is irreversible by design. The workflow writes it only after the complete
artifact is available; once written, do not change `AUTOCONTRIBUTE_STATE_LINEAGE` back to `committed`
or restart the hosted schedule after local approval/publication. Continue from the handed-off state
on an operator-managed persistent worker so the resulting `submitting`/`pr_open` run, lifecycle
observations, reservations, and circuit breaker stay in one durable lineage.

SQLite-only `state restore` accepts only a regular, non-symlink snapshot, copies it into the
configured storage root, verifies SQLite integrity and an exact v5, v4, v3, or v2 schema, and atomically
promotes it. For v4 and v5,
it also validates the complete event ledger against the durable run anchors. It refuses to overwrite
an existing live database or its WAL, SHM, or journal files. Remove nothing to force a restore: point
a fresh storage root at the recovered snapshot or investigate the existing state first. After restoring
v2 or v3, run `uv run autocontribute safety status`, `uv run autocontribute runs list`, or
`uv run autocontribute doctor` to open and migrate the store. `state backup` also opens and migrates
the store before snapshotting it. Take a new v5 backup before relying on the recovered lineage.

Use the same committed `autocontribute.yml` when reviewing. The approval hash binds the issue, base
commit, patch, checks, and proposed PR text; publication reconstructs the target workspace from the
approved patch. A separate preparation fingerprint binds the exact patch bytes to the candidate,
pinned repository/base, proposal, baseline-validation, complete scrubbed patched-command results,
and quality evidence that made it ready. Approval and publication verify that `validation.json`
matches those durable results before recomputing the fingerprint. Cloned target repositories
therefore do not belong in either the cache or artifact. Approval still expires and publication
still performs the upstream freshness and duplicate checks.

`runs show` and `approve` deliberately ignore the downloaded `report.md`: for an approval-ready run
they reconstruct the review from restored SQLite state and safely reopened `contribution.patch` and
`validation.json`. Authenticate the intended GitHub publishing account before either command. Verify
the displayed issue discussion, full patch, complete command stdout/stderr, commit author/committer
and message, PR title/body, and approval fingerprint. The `approve` command reloads and revalidates
that evidence after confirmation, so any concurrent change fails and must be reviewed again.

For an operator-managed deployment, stop every worker first and create one complete bundle. It folds
committed WAL pages into a verified snapshot, copies run evidence and evaluations, validates their
ledger/manifests, and records every included file's size and SHA-256. Existing bundles are never
replaced unless `--overwrite` is present. Configuration, credentials, target-repository workspaces,
and the live WAL/SHM files are deliberately excluded:

```bash
uv run autocontribute state backup --complete \
  --output /trusted/backups/autocontribute-state.bundle.zip
```

If any `submitting` run has a stored commit SHA, this command refuses to create or replace a bundle.
That commit depends on the omitted workspace unless current remote state is reconciled; finish or
reconcile publication on the persistent worker, then retry the backup.

Exercise recovery before enabling automatic publication. Point an otherwise identical configuration
at a fresh, absent storage path, restore the bundle, and make the integrity loaders walk the recovered
lineage. Never use the live path for a drill and never delete live state to make a restore fit:

```bash
cp autocontribute.yml /tmp/autocontribute-recovery.yml
# Edit only storage.path in the copied file to a new, absent directory.
uv run autocontribute state restore --complete \
  --config /tmp/autocontribute-recovery.yml \
  --input /trusted/backups/autocontribute-state.bundle.zip
uv run autocontribute runs list --config /tmp/autocontribute-recovery.yml
uv run autocontribute eval report --config /tmp/autocontribute-recovery.yml
```

The restore rejects symlinks, traversal, duplicate or unsupported members, unsafe file types, limit
violations, checksum mismatches, unexpected SQLite schemas, broken event chains, stale run manifests,
and missing or unanchored evaluations. It promotes only into an absent storage root. Retain multiple
immutable generations off-host and periodically perform this drill with the packaged version you
intend to deploy.

The SQLite-only form remains available for the hosted workflow and specialist database snapshots:

```bash
uv run autocontribute state backup --output /trusted/backups/autocontribute.sqlite3
```

When using that form, archive the matching `runs/` and `evaluations/` directories from the same
quiesced generation; restoring only the database does not restore evidence or the expert corpus.

A stale or partial restore is not safe merely because its SQLite file passes integrity checks. It can
forget publication reservations made after the snapshot, omit evaluation anchors or their matching
files, roll back lifecycle/breaker evidence, or lose newer event-head and lease-generation history.
Keep automatic publication disabled after continuity loss; reconcile every known upstream PR and
restore the latest matching three-part generation rather than editing SQLite or using
`bootstrap_state=true` to reset history.

## Deliberately enabling automatic PRs

The included GitHub-hosted Actions workflow cannot be switched to automatic publication: it rejects
any configuration whose `publishing.mode` is not `review_required`. Run an autonomous pilot only from
an operator-managed, non-ephemeral deployment with a persistent storage volume and tested backups for
the live SQLite database, `runs/`, and `evaluations/`. Its safety decisions depend on durable
duplicate history, leases, publication reservations, lifecycle snapshots, circuit-breaker state, and
ledger-anchored evaluation records; an evictable runner cache is not an acceptable source of truth.

Only after `autocontribute eval report` confirms that the deterministic first-100-run cohort is fully
reviewed, contains at least 20 prepared cases, has at least 95% accept-as-is precision, and has zero
policy, security, or etiquette failures should you consider the guarded pilot shape:

```yaml
github:
  repositories: [owner/repository]
  owners: []

models:
  scout:
    model: provider-routing-name
    expected_response_model: exact-immutable-provider-model-id
    immutable_response_model_attested: true
  builder:
    model: provider-routing-name
    expected_response_model: exact-immutable-provider-model-id
    immutable_response_model_attested: true
  critic:
    model: provider-routing-name
    expected_response_model: exact-immutable-provider-model-id
    immutable_response_model_attested: true

publishing:
  mode: auto
  draft: true
  max_open_pull_requests: 1
  max_new_pull_requests_per_day: 1
  repository_cooldown_days: 7
```

The expected response ID and explicit immutable-identity attestation are mandatory for every role in
auto mode, and the ID must match the API response exactly. Set the attestation only after verifying
the provider contract guarantees that value identifies an immutable deployment. Autocontribute does
not infer immutability from a naming pattern. If a provider or compatible gateway cannot make that
guarantee, keep that deployment in `review_required` mode. The bounded `doctor` probe prints the
resolved model ID to use for this verification.

and the durable worker's runtime environment variable:

```text
AUTOCONTRIBUTE_ALLOW_AUTO_PUBLISH=1
```

Set that variable only in the durable worker's runtime environment and schedule `autocontribute run
--scheduled` there. The scheduled path synchronizes lifecycle evidence before preparation, and auto
mode synchronizes it again immediately before publication. Keep the included hosted workflow in
review mode for evidence collection or disable it to avoid two schedulers operating the same
identity.

Configuration rejects automatic mode unless exactly one repository is explicitly allowlisted, owner
discovery is disabled, PRs remain drafts, at most one PR may be open or created per UTC day, and the
repository cooldown is at least seven days. This deliberately keeps the first autonomous pilot to one
repository and one global sandbox/toolchain recipe. The durable expert-evaluation gate and
environment gate are also required; passing the evaluation gate does not enable publication by
itself. Automatic mode still performs all quality, account, duplicate, and freshness checks.
Immediately before any GitHub mutation, it transactionally records the run's reservation; this
SQLite ledger is the source of truth for the UTC daily limit and repository cooldown even if GitHub
Search lags. Reservations are idempotent for the same run and survive failed or ambiguous attempts.
For automatic mode, that same transaction installs a non-expiring hold over the exact validated
evaluation-corpus cursor. Evaluation records and amendments are rejected until the matching run is
durably `pr_open` or exact remote compensation is verified and durably finalized; process crashes and
lease expiry do not clear the hold.
Removing the variable is the kill switch. It prevents scheduled mutation resumption for durable
`submitting` intents left by an interrupted worker as well as publication of newly prepared work.
Read-only reconciliation still runs and can adopt a pull request that already exists remotely; it
does not issue a new GitHub write. In `review_required` mode, use an explicitly confirmed
`autocontribute publish RUN_ID` command to resume a stranded intent. Do not raise cadence to
compensate for skipped runs.

API credentials pay for API usage and are separate from ChatGPT/Codex product subscriptions. Put the
OpenAI key in a dedicated project with spend and rate limits. Also configure conservative per-model
token prices and `budget.max_model_cost_usd_per_run`; the local ledger cannot infer reliable prices
for arbitrary compatible endpoints, and the provider-project limit protects ambiguous network
failures that may have been billed remotely.
