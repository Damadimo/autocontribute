# Staging and live end-to-end checks

Never use a third-party upstream repository for the first live run. Create a dedicated fixture
repository owned by the operator, give it realistic contribution guidance and small synthetic issues,
and use `.github/workflows/staging.yml` to perform read-only shadow runs against it.

## Required setup

1. Create a repository used only for Autocontribute fixtures. Do not point staging at a real upstream.
2. Copy `autocontribute.staging.example.yml` to `autocontribute.staging.yml`, replace the repository
   placeholder with that exact fixture repository, and review the pinned sandbox image and validation
   recipe. Verify the model pricing ceilings against the dedicated provider project before running;
   they are operator-maintained conservative inputs, not a bundled pricing table. The hosted workflow
   requires the Docker backend, disabled validation networking, and no unsafe-local opt-in. Its
   aggregate model ceiling plus worst-case sandbox command budget must not exceed 180 minutes; the
   four-hour job timeout leaves the remaining hour for preflight and state finalization.
3. Add `OPENAI_API_KEY` and a read-only `AUTOCONTRIBUTE_STAGING_GITHUB_TOKEN` as repository secrets.
   Use a dedicated provider project and GitHub App installation where possible. Also add
   `AUTOCONTRIBUTE_STAGING_STATE_TOKEN`, using an expiring fine-grained PAT restricted to this control
   repository with only **Variables: Read and write** (plus implicit metadata read). Grant it no
   contents, issues, pull-request, or Actions access, and rotate it independently.
4. Set `AUTOCONTRIBUTE_STAGING_REPOSITORY` to the fixture's `owner/repository` name.
5. Set `AUTOCONTRIBUTE_STAGING_ENABLED=true`, then manually dispatch **Staging shadow run** from the
   default branch with a fixture issue reference and `bootstrap_state=true`. This flag is required
   only for the first-ever state lineage; leave it `false` on later dispatches so a missing cache
   fails closed instead of silently discarding history.

The shadow workflow's `GITHUB_TOKEN` has only `contents: read`. Only the dedicated state token is
exposed to the three steps that resolve, claim, and commit
`AUTOCONTRIBUTE_STAGING_STATE_LINEAGE`; use an equivalently scoped short-lived GitHub App installation
token for a longer-lived deployment. The workflow restores the committed exact cache generation,
validates the local state and all live dependencies while leaving that pointer unchanged, then rereads
and claims the same generation immediately before preparation. Preflight failures are retryable
without changing the committed pointer. After saving the replacement cache, it independently requires
an exact-key, lookup-only cache hit because the save action can reduce upload failures to warnings. It
advances the variable only after that verification and the evidence artifact are successful. An
`in-progress` value means a post-claim run did not commit; investigate that run and its evidence instead
of editing the variable.

The workflow enforces one explicit repository, disables owner-wide discovery, requires
`review_required` mode, requires draft publication configuration, and never invokes the publication
command. It uploads the evidence bundle for expert grading.

Staging state uses the same three-part persistence contract as production review runs: a verified
SQLite snapshot, run bundles under `.autocontribute-staging/runs/`, and separate immutable expert
evaluation files under `.autocontribute-staging/evaluations/`. The workflow caches and uploads all
three. `autocontribute state restore --config autocontribute.staging.yml --input SNAPSHOT` validates
and restores only SQLite; keep the matching run and evaluation directories beside it. Evaluation
files must match their immutable hashes and subject anchors in the SQLite event ledger, so restoring
either side from a different generation fails closed.

For operator-managed staging backups, stop the staging worker and prefer `state backup --complete`.
The matching `state restore --complete` verifies and promotes SQLite, run bundles, and evaluations as
one generation into an absent storage root. The hosted workflow continues to use SQLite-only mode
because its immutable cache and evidence artifact already persist all three parts together.

The staging cache writes unique `autocontribute-staging-state-v5-...` keys and restores only the key
named by the external lineage variable. Exact repository- and runner-bound v4 or v3 keys already
committed in that variable are one-way legacy inputs: the workflow checks that each snapshot matches
its declared schema, migrates it, and saves the replacement under a v5 key. It never falls back to a stale
prefix or accepts arbitrary legacy keys. Never use `bootstrap_state=true` or edit the variable to
bypass a failed save, migration, or missing lineage. Although the shadow workflow never publishes,
preserve the matching snapshot, run bundles, and evaluation records together for any later
operator-reviewed fixture publication.

## What each fixture must exercise

- a clear issue that should be solved and a superficially attractive issue that should be skipped;
- maintainer comments that claim work, alter scope, or ask automation to stop;
- repository instructions and a completed pull-request template;
- a regression test that fails for the intended assertion on the base commit;
- required lint, type, unit, and integration validation commands;
- prompt-injection text, symlinks, ignored files, large files, and planted fake credentials;
- upstream movement between preparation and attempted publication;
- failing CI and requested-changes lifecycle events.

Successful preparation is not sufficient. Archive the expert decision, any human edits, validation
evidence, token cost, latency, and eventual fixture PR lifecycle outcome for the evaluation corpus.
Before grading a prepared run, verify that its preparation fingerprint still binds the exact patch
and readiness evidence; evaluation loading and any later publication repeat this check.

## Lifecycle safety drill

The shadow workflow never publishes, so it cannot create lifecycle-managed PR state by itself. Once
an operator-reviewed fixture run has been deliberately published to the operator-owned repository,
exercise lifecycle behavior only against that fixture. Introduce one signal at a time—such as a
changes-requested review, failing check, head change, explicit maintainer stop, closed-unmerged PR, or
later explicit revert—then run:

```bash
uv run autocontribute lifecycle sync --config autocontribute.staging.yml
uv run autocontribute safety status --config autocontribute.staging.yml
```

Confirm that the signal, source URL, and persistent global stop match the fixture evidence, and that
a subsequent preparation and publication are blocked. Preserve the state snapshot for the corpus.
After independently reviewing and resolving the fixture condition, exercise the audited operator
path rather than editing SQLite:

```bash
uv run autocontribute safety resume \
  --config autocontribute.staging.yml \
  --actor "STAGING OPERATOR" \
  --reason "FIXTURE EVIDENCE REVIEWED; SAFE OPERATIONAL RESPONSE CONFIRMED" \
  --expected-trigger-hash "ACTIVE REVISION FROM safety status"
```

Do not perform this drill on a third-party repository. On hosted runners, also verify that the
verified snapshot is restored: a fresh ephemeral database cannot preserve or demonstrate a prior
stop.

The separate **Security integration** workflow runs repository-controlled commands inside a real
Docker daemon each week. It verifies that host environment values, network access, Linux
capabilities, the container root filesystem, and Git metadata remain isolated.
