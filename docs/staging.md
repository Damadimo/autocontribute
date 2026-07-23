# Staging and live end-to-end checks

Never use a third-party upstream repository for the first live run. Create a dedicated, entirely
synthetic fixture repository owned by the operator, give it realistic contribution guidance and
small synthetic issues, and use `.github/workflows/staging.yml` to perform read-only shadow runs
against it. The fixture must currently be public: Autocontribute deliberately rejects private
repositories as contribution targets and performs unauthenticated source fetches. Do not place real
credentials, private code, personal data, or other non-public material in the fixture.

## Required setup

1. Create a public repository used only for non-sensitive Autocontribute fixtures. Do not point
   staging at a real upstream. A private fixture is not a supported shortcut: it would require an
   explicit allowlist plus a host-bound authenticated-clone design.
2. For this deployment, review the checked-in `autocontribute.staging.yml`. For another account, copy
   `autocontribute.staging.example.yml` to that path and replace the repository placeholder with the
   exact fixture repository. Review the pinned sandbox image and validation recipe. Verify the model
   pricing ceilings against the dedicated provider project before running; they are
   operator-maintained conservative inputs, not a bundled pricing table. The hosted workflow requires
   the Docker backend, disabled validation networking, and no unsafe-local opt-in. Its aggregate model
   ceiling plus worst-case sandbox command budget must not exceed 180 minutes; the four-hour job timeout
   leaves the remaining hour for preflight and state finalization.
   Keep the fixture's 11-command budget: it covers one baseline reproduction and the five-command
   deduplicated validation suite both before and after the single bounded validation- or
   critic-driven repair pass.
3. Protect the control repository's default branch before storing any hosted credential. Require pull
   requests, passing CI, and the exact **Security integration gate** check; apply the rule to
   administrators where supported, require at least one trusted approval for every pull request, and
   block force pushes and deletion. Require code-owner review for `.github/workflows/` and
   `.github/CODEOWNERS`, dismiss stale approvals after new commits, and require approval of the most
   recent reviewable push. Ensure two distinct trusted identities can author and approve control-plane
   changes: a code owner cannot approve their own pull request. Add another trusted collaborator, or
   have a separately controlled bot author workflow changes for the owner to review; do not use an
   administrator bypass as the normal path. Require branches to be up to date with `main`, or use a
   merge queue; the security workflow runs its full matrix for `merge_group` candidates. A same-named
   check can be defined by pull-request workflow content, so the check name is not a trust boundary by
   itself; use required-workflow governance as well when the account supports it. Require only the
   stable aggregate security check, not its rootful or rootless matrix jobs, because the matrix is
   deliberately skipped for documentation-only pull requests. GitHub Free does not provide branch
   protection for a private repository: make the control repository public or upgrade its plan before
   treating this as an enforceable production gate. Until the account plan can enforce these controls,
   keep hosted secrets and staging disabled; run the shadow check from a trusted worker or move a
   sanitized control repository to a visibility/plan that supports protection.
4. Add `OPENAI_API_KEY` and a read-only `AUTOCONTRIBUTE_STAGING_GITHUB_TOKEN` as repository secrets.
   Use a dedicated provider project. The target token must be either an expiring fine-grained PAT or a
   GitHub App **user access token** because preflight identifies its account with `GET /user`; a plain
   installation token is not sufficient. Restrict it to the fixture repository with read-only metadata,
   contents, issues, and pull-request access. Also add `AUTOCONTRIBUTE_STAGING_STATE_TOKEN`, using an
   expiring fine-grained PAT restricted to this control repository with only **Variables: Read and
   write** (plus implicit metadata read). Grant it no contents, issues, pull-request, or Actions access,
   and rotate it independently.
5. Set `AUTOCONTRIBUTE_STAGING_REPOSITORY` to the fixture's `owner/repository` name.
6. Set `AUTOCONTRIBUTE_STAGING_ENABLED=true`, then manually dispatch **Staging shadow run** from the
   default branch with a fixture issue reference and `bootstrap_state=true`. This flag is required
   only for the first-ever state lineage; leave it `false` on later dispatches so a missing cache
   fails closed instead of silently discarding history.

The shadow workflow's `GITHUB_TOKEN` has only `contents: read`. Only the dedicated state token is
exposed to the three steps that resolve, claim, and commit
`AUTOCONTRIBUTE_STAGING_STATE_LINEAGE`; unlike the target token, this credential may be an equivalently
scoped short-lived GitHub App installation token for a longer-lived deployment. The workflow restores
the committed exact cache generation, validates its local state and configuration, and preloads the
sandbox image while leaving that pointer unchanged. Failures before the claim are retryable without
changing the committed pointer. The workflow then rereads and claims the same generation before it
syncs lifecycle state, validates the live GitHub and model dependencies, and attempts preparation.
After a claim, it snapshots the resulting state even when one of those steps fails. It independently
requires an exact-key, lookup-only cache hit because the save action can reduce upload failures to
warnings, and advances the variable only after that verification and the evidence artifact are
successful. An `in-progress` value means a post-claim run did not commit; investigate that run and its
evidence instead of editing the variable.

The workflow enforces one explicit repository, disables owner-wide discovery, requires
`review_required` mode, requires draft publication configuration, and never invokes the publication
command. It uploads the evidence bundle for expert grading.

## Retry-policy staging drill

Use separate synthetic issues to verify the durable retry policy before enabling any unattended
worker:

1. Let one fixture revision finish as `skipped`, `rejected`, or `cancelled`, then dispatch the same
   unchanged issue again. The preparation run must finish as `skipped`, contain a
   `candidate.retry_deferred` event naming the prior run/status and issue revision, and contain no
   model-call records.
2. Edit semantic issue evidence—for example, add a maintainer comment that clarifies acceptance
   criteria--and dispatch it again. With no active run, the new revision must be evaluated normally;
   it is not required to pass the eligibility gates.
3. On a separate fixture with no earlier conservative terminal outcome for that revision, retain a
   `failed` run and dispatch the unchanged issue again. The failure must not suppress the new
   attempt.
4. Retain a `ready_for_approval` fixture run, change the issue, and dispatch it again. Active work
   must still win: the new run records `candidate.active_deferred` and makes no model calls.

The zero-call assertion above applies to the `autocontribute run` preparation stage. The hosted
workflow runs `doctor` first, and that independent preflight intentionally makes its documented
bounded model probe. Inspect the run manifest/events rather than using the workflow's total provider
traffic as the retry assertion.

The hosted staging workflow deliberately does not expose `--retry-unchanged`. If the override itself
must be tested, use a separate operator-managed fixture lineage on a trusted worker while hosted
staging is disabled:

```bash
uv run autocontribute run \
  --config autocontribute.staging.yml \
  --issue owner/fixture#123 \
  --retry-unchanged \
  --retry-actor "STAGING OPERATOR" \
  --retry-reason "UNCHANGED FIXTURE RETRY AUTHORIZED FOR THE STAGING DRILL"
```

Confirm the authorization table row and `candidate.retry_override` event contain the actor, reason,
authorization ID, exact issue revision, and exact prior run/status, then confirm fresh deterministic
eligibility evidence. The authorization, event, and candidate claim must be one atomic operation;
there must never be an authorization detached from its run or two active claims for the same fixture
issue. Never add the override to a schedule: scheduled mode rejects both pinned issues and retry
overrides, and an override cannot bypass active work. Do not merge a locally advanced fixture lineage
back into the hosted lineage or resume the hosted workflow from its older parent.

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

The staging cache writes unique `autocontribute-staging-state-v7-...` keys and restores only the key
named by the external lineage variable. Exact repository- and runner-bound v6, v5, v4, or v3 keys
already committed in that variable are one-way legacy inputs: the workflow checks that each snapshot
matches its declared schema, migrates it, and saves the replacement under a v7 key. The v6-to-v7
migration transactionally verifies historical candidate rows against their manifests and backfills
durable issue revisions. It also creates the durable retry-authorization table, case-insensitive
revision lookup, and case-insensitive unique-active-candidate index after rejecting any duplicate
active claim; a mismatch or duplicate leaves the v6 source unchanged. The workflow never falls back
to a stale prefix or accepts arbitrary legacy keys. Never use `bootstrap_state=true` or edit the
variable to bypass a failed save, migration, or missing lineage. Although the shadow workflow never
publishes, preserve the matching snapshot, run bundles, and evaluation records together for any
later operator-reviewed fixture publication.

If staging is left at an `in-progress` claim, set `AUTOCONTRIBUTE_STAGING_ENABLED=false` and use
**Recover staging hosted state** from the default branch; never rewrite
`AUTOCONTRIBUTE_STAGING_STATE_LINEAGE`. Copy the exact claim and try `promote_claimed` first. Recovery
uses only its exact destination cache or the unexpired
`autocontribute-staging-<run-id>-<attempt>` artifact, then verifies and persists a fresh generation
before compare-and-swapping the unchanged claim. Use `restore_parent_stopped` only when claimant
evidence is absent or has failed validation, with an operator identity and incident reason; if
unusable evidence still exists, explicitly attest that fact with
`restore_over_unusable_claimant=true`. Parent recovery activates a persistent safety stop. Keep
staging disabled and inspect the recovered complete bundle on a trusted worker before any audited
resume. The detailed procedure and legacy-claim rules are in
[Scheduled operation](scheduled-operation.md#recovering-a-stranded-hosted-claim).

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

The separate **Security integration** workflow runs repository-controlled commands against both
rootful and rootless Docker daemons on its weekly schedule, on manual dispatch, on pull requests and
merge-queue candidates, and after pushes to `main`. Every main push and `merge_group` candidate
requires the live matrix. The non-cancelling concurrency group includes the event name and immutable
workflow commit. GitHub can therefore supersede only a pending run for the same event and tree; an old
manual re-run or another commit cannot displace a newer pending main run.

For pull requests, a cheap classifier reads the complete local Git diff rather than GitHub's
path-filter result, which can inspect only the first 300 changed files. It skips the live matrix only
when every changed path is under `docs/` or is exactly `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, or
`LICENSE`. Renames are considered as a deletion plus an addition, so moving runtime material into an
allowed documentation path still runs the matrix. Invalid or unavailable event SHAs, a missing merge
base, a diff error, an unsupported event, or any other classification uncertainty also runs both live
modes.

The always-present **Security integration gate** job accepts either a successful live matrix or a
classifier-confirmed documentation-only pull-request skip. Use that stable job name as the required
branch check, together with trusted code-owner review of workflow changes; trigger-level path filters
would omit it entirely and can leave a required check pending. The live tests verify numeric identity
and host file ownership, effective cgroup v2 resource limits,
host-environment and network denial, zero Linux capabilities, no-new-privileges, and read-only
container-root and Git-metadata mounts. This hosted regression check does not replace deployed-host
verification of the dedicated rootless socket, systemd delegation, private runtime paths, or the
service account's inability to reach the rootful host socket; the packaged preflight and deployment
procedure remain authoritative for those host-specific boundaries.
