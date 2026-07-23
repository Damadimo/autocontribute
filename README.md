# Autocontribute

Autocontribute is a quality-gated agent that prepares narrowly scoped open-source contributions on
your behalf. It searches only for maintainer-signaled work, implements one candidate in an isolated
workspace, runs the project's checks, asks a fresh model to review the complete diff, and produces an
auditable approval bundle.

The scheduler creates **attempts, not a PR quota**. “No suitable contribution found” is a successful
outcome. By default, no scheduled job can write to GitHub; a person must approve the exact issue,
base commit, diff, commit message, and PR text before publication.

> [!WARNING]
> This is an early alpha. Run it against repositories you deliberately allowlist, inspect every
> artifact, and keep `publishing.mode: review_required` until you have measured its results. The
> included GitHub-hosted Actions workflows enforce `review_required` and cannot publish
> autonomously.

## Why this is different

- Issue-first: requires an open, maintainer-signaled, unassigned issue with testable acceptance
  criteria.
- Fail-closed: ambiguous work, security reports, competing PRs, broad refactors, dependency churn,
  and unverifiable changes are rejected.
- Maker-checker: planning/implementation and final review are separate model calls; the critic gets
  fresh evidence rather than trusting the builder's claims.
- Bounded self-correction: one actionable validation failure or one critic rejection may receive a
  single repair pass, never both; infrastructure failures are not misrepresented as code defects.
- Deterministic gates: diff size, forbidden paths, secrets, binaries, validation results, minimum
  dimension scores, and upstream freshness cannot be waived by a model.
- Operator-owned checks: every allowlisted repository has mandatory validation commands that model
  output can supplement but never replace or skip.
- Red/green evidence: behavioral fixes must use the same reproduction command that fails on pristine
  upstream and passes with the patch; missing tools, files, tests, permissions, or networking do not
  count as a reproduced defect.
- Credential isolation: model calls happen in the control process; repository commands run in a
  credential-free Docker sandbox with networking disabled and a disposable working-tree copy.
- Exact approval: an expiring hash binds approval to the complete outbound artifact. Any drift
  invalidates it.
- Provider choice: first-class OpenAI Responses API support and an OpenAI-compatible structured-output
  adapter. Model names and endpoints are configuration, not hard-coded behavior.

## Quick start

Requirements: Python 3.11+, [`uv`](https://docs.astral.sh/uv/), Git, Docker, and the GitHub CLI.

```bash
git clone https://github.com/Damadimo/autocontribute.git
cd autocontribute
uv sync --extra dev
uv run autocontribute init
gh auth login
export OPENAI_API_KEY="..."
docker pull python:3.12-bookworm@sha256:9bed8554e926c07c6f908841d5ee88c33e8df9236b191526bbce81a9062ab43a

# Inspect authentication, Docker, model credentials, and configuration.
uv run autocontribute doctor

# Read-only discovery, or pin the run to one issue.
uv run autocontribute discover
uv run autocontribute run --issue owner/repository#123

# If that repository has a CLA or DCO, inspect its exact policy snapshot first.
uv run autocontribute policy inspect owner/repository

# Inspect the generated evidence, then explicitly attest and publish.
uv run autocontribute runs show RUN_ID
uv run autocontribute approve RUN_ID
uv run autocontribute publish RUN_ID
```

A normal pinned run does not repeatedly spend model budget on an unchanged issue that already ended
as `skipped`, `rejected`, or `cancelled`. After reviewing the prior evidence, an operator can make a
deliberate manual exception:

```bash
uv run autocontribute run \
  --issue owner/repository#123 \
  --retry-unchanged \
  --retry-actor "OPERATOR IDENTITY" \
  --retry-reason "PRIOR EVIDENCE REVIEWED; CONCRETE REASON FOR RETRY"
```

The retry flag is valid only when paired with an issue, actor, and reason. A scheduled invocation
rejects both pinned issues and the retry override, and the override never bypasses an active run for
the issue.

`doctor` is an active preflight, not a purely static configuration check. It sends one bounded,
potentially billable strict-schema request per distinct model profile (at most 1,024 output tokens
and 60 seconds), with no model tools or repository credentials. Its GitHub probes use only `GET`
requests: prepare-only deployments verify target reads and warn about excess or unreportable token
scopes; guarded automatic publication also verifies an existing fork's reported push permission, or
clearly labels classic-scope evidence as inferred without attempting fork creation. For Docker,
`doctor` verifies the daemon's exact structured security options, then launches the pinned image with
networking and Linux capabilities disabled. It proves a service-owned `0700` bind mount can be read
and written with the expected host ownership and confirms effective cgroup v2 memory, swap, CPU, and
PID limits before checking the entrypoints and explicit Python modules named by operator-owned
validation commands. The same structured resource-support and daemon-identity check runs immediately
before every later container launch. The packaged systemd deployment also requires that structured
probe's `DockerRootDir` to remain on its separately bounded filesystem; ordinary local and rootful
review use keeps operator-managed Docker storage. Repository-local scripts and project-dependent
behavior remain the responsibility of the real isolated validation run. An explicitly configured
unsafe-local backend checks the host toolchain and does not require Docker.

Copy [`autocontribute.example.yml`](autocontribute.example.yml) to `autocontribute.yml` and replace
the example repositories with projects you understand. Define `validation.required_commands` for
every explicit repository; those commands and the pinned Docker image must provide its complete
offline toolchain. Configuration stores environment-variable *names* only; never place tokens in
YAML. Docker images must be pinned by digest so scheduled checks cannot silently change toolchains
between runs.

For the included hosted workflow, the first enabled Actions run must be a manual **Prepare
contribution** dispatch from the default branch with `bootstrap_state=true`. Scheduled runs and later
dispatches resolve an external generation variable, restore and verify only its exact immutable cache
key, and claim that still-current generation immediately before stateful work. Preflight failures
leave the committed pointer retryable; a failed cache verification or evidence upload after the claim
leaves the lineage locked instead of rolling back. The lineage steps require a separate
`AUTOCONTRIBUTE_STATE_TOKEN` scoped only to **Variables: Read and write** on the control repository;
that credential is never exposed to model or target-repository work. If a stranded `in-progress`
value needs recovery, disable scheduling and use the default-branch
**Recover production hosted state** workflow to promote its exact cache or retained evidence artifact;
the continuity-loss fallback restores only its exact parent and persists a safety stop. Never rewrite
the lineage variable directly. Before downloading state for local approval/publication, use the
workflow's `lock_for_handoff=true`
dispatch; it uploads the complete handoff artifact before writing the irreversible marker that
permanently stops the hosted lineage, so lifecycle state cannot fork. See
[Scheduled operation](docs/scheduled-operation.md). For a durable Linux worker with rootless Docker,
encrypted systemd credentials, mutually exclusive complete backups, and health signaling, see the
[operator-managed systemd deployment](docs/systemd-deployment.md).

## The contribution pipeline

```text
discover -> deterministic eligibility -> plan -> exact edits -> sandbox checks
         -> fresh-context critic -> hard quality gates -> approval -> freshness recheck -> PR
```

Every transition is written to SQLite and to a hash-chained event ledger. Since schema v4, each run
stores its authoritative event count and terminal event hash on the run row, and advances that
anchor in the same transaction as the event append. Full ledger validation recomputes every hash and
predecessor and compares the resulting count and head with that anchor, so deleting a tail event
fails closed. Run
manifest saves use an `updated_at` compare-and-swap so a stale worker cannot overwrite newer
publication or lifecycle evidence. Each run also writes a portable bundle under
`.autocontribute/runs/<run-id>/` containing the issue snapshot, pinned upstream SHA, patch, command
evidence, model metadata, quality report, and proposed PR text. Hidden model reasoning and credentials
are never recorded.

When a run passes every quality gate, Autocontribute seals the exact patch bytes together with the
candidate, eligibility decision, pinned repository/base, plan, proposal, baseline validation, and
complete scrubbed patched-command results and quality evidence in a preparation fingerprint.
`validation.json` is rendered from those durable results; approval and publication require it to
match before recomputing the seal, and fail closed if either artifact or readiness evidence changed.
`runs show` and `approve` rebuild approval-ready output from the SQLite manifest and freshly validated
`contribution.patch` and `validation.json`; they never use the mutable `report.md` summary as review
evidence. The approval review includes the complete issue discussion, full patch, every command's
stdout/stderr, exact PR and commit text, publishing identity, and the resulting approval fingerprint.
After confirmation, approval reloads and revalidates all three inputs and refuses to persist if the
fingerprint differs from the one the operator reviewed.

The default state machine intentionally ends many runs as `skipped` or `rejected`. A contribution
becomes `ready_for_approval` only when all hard gates and the configured readiness threshold pass.
Issue discussions are included in the evidence, and explicit work claims or maintainer stop requests
block selection before model work.

Candidate retry decisions are durable. On selection, schema v7 stores a domain-separated SHA-256
revision of the complete canonical issue evidence, including its title, body, state, labels,
assignees, timestamps, and full discussion, while excluding derived ranking fields. Any active run
for an issue blocks another attempt regardless of revision. With no active run, the same revision is
suppressed after `skipped`, `rejected`, or `cancelled`; `failed` does not itself suppress a retry, and
a changed issue revision becomes available again. Unpinned discovery falls through active or
suppressed candidates and keeps searching within its bounded candidate scan rather than treating the
first duplicate as the result.

Pinned active and unchanged-suppressed decisions finish as audited skips before eligibility or model
work, with `candidate.active_deferred` or `candidate.retry_deferred` evidence naming the issue
revision, prior run, and prior status. A deliberate manual override additionally requires a
non-empty operator identity and reason. Its durable authorization row and
`candidate.retry_override` event bind those fields to the exact prior run, prior status, and issue
revision in the same fenced transaction that claims the candidate. It then reruns every normal
deterministic gate; it does not force the issue to pass. These deferrals make zero model calls. Their
run and event records remain part of the state lineage so repeated scheduler invocations cannot
forget the decision.

Candidate claims are protected by the generation-fenced run lease and a case-insensitive unique
active-candidate index, so a stale or concurrent worker cannot turn a read-then-write race into two
active attempts. Candidate repository identities are restricted to one ASCII `owner/name`: each
component may contain only letters, digits, `_`, `.`, or `-`, and neither component may be `.` or
`..`. This keeps application identity normalization and SQLite `NOCASE` comparisons equivalent. The
orchestration API also uses a typed invocation mode below the CLI: explicit issues and retry
authorizations are rejected unless the caller supplies `MANUAL`, so a direct caller cannot reproduce
the old bare-boolean bypass.

Published pull requests remain part of the safety loop. `autocontribute lifecycle sync` records an
immutable snapshot of every locally tracked open PR and persistently stops all preparation and
publication if it detects head drift, a maintainer changes-requested review or stop request, failing
CI, closure without merge, or an explicit later revert. `autocontribute run --scheduled` performs
this sync before discovery; an observation failure also fails the attempt closed.

## Models

The default quality-first profile uses `gpt-5.6` through the OpenAI Responses API with high reasoning.
The final critic uses pro mode; scout and builder use standard mode. You can choose a model exposed by
the configured endpoint when it supports that adapter's strict schema and reasoning requirements:

```yaml
models:
  builder:
    provider: openai
    model: gpt-5.6
    # Required for auto mode: the exact immutable model ID returned by the provider.
    # expected_response_model: gpt-5.6-YYYY-MM-DD
    # immutable_response_model_attested: true  # only after verifying the provider contract
    api_key_env: OPENAI_API_KEY
    reasoning_effort: high
    reasoning_mode: standard
    max_input_tokens: 500000
    max_output_tokens: 40000
    pricing: # operator-maintained conservative USD ceilings per million tokens
      input_usd_per_million_tokens: 10
      output_usd_per_million_tokens: 100
  critic:
    provider: openai
    model: gpt-5.6
    api_key_env: OPENAI_API_KEY
    reasoning_effort: high
    reasoning_mode: pro
```

Servers that implement OpenAI-compatible Chat Completions plus strict JSON Schema can use
`provider: openai_compatible` and `base_url`. Critical stages fail closed if the endpoint cannot
enforce the response schema. Reasoning effort is forwarded, while the Responses-specific `pro` mode
is rejected for compatible endpoints; configure `reasoning_mode: standard` or `null`. Other provider
families need an OpenAI-compatible gateway. API-key billing is independent of a ChatGPT or Codex
subscription.

Review-only runs may observe and record the provider-returned model ID without pinning it. The bounded
`doctor` probe reports that resolved ID. Guarded automatic publication requires both
`expected_response_model` and an explicit `immutable_response_model_attested: true` for every role,
then rejects every response whose model ID differs. The attestation means the operator has verified
the provider contract makes that exact returned value an immutable deployment—not merely a mutable
routing alias. Autocontribute does not guess immutability from provider-specific naming conventions;
providers and compatible gateways that cannot make that guarantee are supported only in review mode.

Each run enforces aggregate input-token, output-token, model-time, and configured USD ceilings.
Before an API request, Autocontribute durably records a conservative reservation and forwards the
remaining output/time limits to the provider. Successful calls reconcile that reservation against
reported usage; missing or inconsistent usage fails closed, while an ambiguous failed call retains
its reservation. Model prices are deliberately operator-supplied because compatible endpoints and
custom model names cannot be priced safely from a hard-coded table.

## GitHub publication safety

Scheduled runs are prepare-only by default. `publishing.mode: auto` is supported for deliberate,
calibrated deployments, but configuration validation restricts the initial pilot to exactly one
explicit repository, no owner-wide discovery, PRs staged as drafts before an exact ready-for-review
transition, one new PR per day, and at least a seven-day same-repository cooldown. It also requires
`AUTOCONTRIBUTE_ALLOW_AUTO_PUBLISH=1` at runtime. Rate
limits, maximum open/new PR counts, same-repository cooldowns, duplicate checks, issue assignment,
policy changes, or base-branch drift stop publication.

Before branch or pull-request mutation, the broker durably binds the upstream and fork to GitHub's
immutable database and GraphQL node IDs and records the created PR's node ID. Every later write
revalidates those identities; compensation fails closed instead of closing or deleting through a
reused owner/name.

Starting or restarting a worker without that runtime variable prevents new or resumed constructive
GitHub mutation; removing a systemd drop-in does not change the environment of a process that is
already running. Scheduled runs still perform read-only reconciliation and may adopt an already-open
remote pull request. One deliberately narrow exception remains: once exact compensation evidence is
durably marked, the worker may finish closing or deleting only that immutable remote identity to
reduce exposure, even if the breaker had already tripped while detecting the base race. If that exact
PR has already merged, reconciliation may instead record it as `pr_open` for lifecycle observation
without another GitHub write. Stop both the scheduler and worker when an operator must prohibit
every remote write. In `review_required` mode, resume any other stranded intent only with an
explicitly confirmed `autocontribute publish RUN_ID` command.

The publication recheck refetches the complete issue and repository, reruns deterministic
eligibility, and requires the sealed issue title/body/labels/discussion to be unchanged. Repository
and organization policy files are reread and compared through a digest recorded at discovery, so a
new or edited policy stops the run even when it contains no recognized prohibition phrase.

### CLA and DCO onboarding

Any non-negated or ambiguous CLA/DCO reference, legal checklist, or named legal policy/configuration
file blocks discovery unless the operator has created an exact repository-scoped attestation.
Autocontribute never treats repository prose, a PR-template checkbox, a generic boolean, or an
owner-wide setting as legal assent. Start with the read-only inspection above. After personally
reviewing the displayed policy surface, use only the flags that match its detected requirements:

```bash
# Account-level CLA enrollment must already be complete outside Autocontribute.
uv run autocontribute policy attest owner/repository --cla-completed

# DCO requires explicit identity.name/email and authorizes that exact commit trailer.
uv run autocontribute policy attest owner/repository --authorize-dco-signoff

# Supply both flags only when both requirements are detected.
```

The command displays fixed authorization language, the authenticated GitHub account, current
immutable repository/organization refs and review URLs, the detected requirement set, and a stable
legal-policy digest before asking for personal confirmation. It does not edit configuration. Read
every linked policy file, then paste its generated record under `policy.legal_attestations` only after
confirming that no per-contribution CLA signature or assent remains. Consult the policy owner or
qualified counsel when the effect is unclear.

The stable digest binds the exact repository, organization-policy repository presence, complete
bounded policy-path inventories, and every policy file's contents or absence. Moving source commits
with an identical policy surface do not force repeated assent; any policy path/content change,
organization-policy repository appearance, or detected CLA/DCO requirement change does. The refs
reviewed during onboarding remain audit fields, while every run records its newly observed immutable
refs and the existing ref-sensitive freshness digest. Publication re-fetches that evidence and also
requires the current publishing login, attestation fingerprint, and detected requirements to match.

For DCO repositories, the model may supply only a one-line commit subject. Autocontribute appends the
configured signatory's exact `Signed-off-by` trailer before preparation is fingerprinted, displays it
in approval, and verifies the exact committed message before pushing. A model-supplied, altered, or
unauthorized trailer fails closed. Removing or changing the attestation or Git identity invalidates
prepared work.

Immediately before the first GitHub mutation, the worker transactionally consumes a durable SQLite
publication reservation. Those reservations—not eventually consistent GitHub Search results—are the
local source of truth for the UTC daily limit and same-repository cooldown. A retry of the same run is
idempotent; a failed or ambiguous attempt keeps its reservation. GitHub account searches remain a
separate conservative check for externally created and open pull requests.

Automatic publication also remains locked until the first 100 runs for the current deployment
fingerprint, in persisted creation-time order with run ID as the tie-breaker, all have completed
outcomes and anchored expert reviews. The fingerprint binds the cohort to the exact packaged Python
source, Python interpreter, installed runtime dependency closure, packaged build/lock manifest, and
release-bound systemd deployment-asset manifest, plus material model, budget, discovery, sandbox,
validation, policy, quality, and publishing safety settings. That fixed cohort must contain at least
20 prepared cases, at least 95% accept-as-is
precision, and zero policy, security, or etiquette failures. Runs or reviews from another deployment
cannot fill the cohort. Any material code, model, or configuration change starts a new calibration
cohort; later favorable reviews cannot replace a missing or unfavorable member. That expert gate is
necessary but not sufficient. The exact publishing account and API origin must also have a fixed
first-20 cohort of manually approved pull requests that were both graded `accept_as_is` and verified
`merged_as_is`; every earlier automatic pull request must still prove `merged_as_is` as well. Adverse
lifecycle evidence is permanent for this decision. Use `autocontribute rollout report` to inspect the
combined result. A scheduled auto invocation observes lifecycle state and evaluates this result before
creating a run, performing discovery, or invoking a model, so an unready cohort incurs no model bill.
Configuration and environment opt-ins remain independently required.

The build/lock identity comes from the validated `_build_identity.json` packaged beside the Python
modules. CI requires its SHA-256 values to match this project's `pyproject.toml` and `uv.lock`, and the
same manifest ships in editable-source and wheel installs. Runtime identity also binds the validated
`_systemd_assets.json` that attests the complete operator-managed deployment bundle. It never
searches parent directories, so an unrelated ancestor project cannot silently change or impersonate
a cohort.

`autocontribute eval record` prints every field and its content hash before requiring an explicit
reviewer attestation; `--yes` supplies that attestation non-interactively but still prints the preview
and preserves the post-preview drift check. Expert grades are immutable JSON files under
`.autocontribute/evaluations/`, separate from the SQLite database and run bundles. A mistaken grade is
corrected with `autocontribute eval amend --reason ...`, which appends a complete replacement revision
linked to the prior content hash instead of editing history. The latest valid revision drives the
gate, while every revision must remain present and valid.

Each revision's content and reviewed subject are anchored in the hash-chained SQLite event ledger;
edited, added, deleted, duplicated, non-consecutive, predecessor-mismatched, or artifact-mismatched
records make corpus loading fail closed. Before computing the gate, every event hash and predecessor
link for every run is recomputed, and the resulting count and terminal hash must match the run's
durable event anchor. Preserve all three parts of the corpus as one generation: a verified SQLite snapshot,
`.autocontribute/runs/`, and `.autocontribute/evaluations/`. After quiescing writers, use
`autocontribute state backup --complete` to verify those parts into one checksummed bundle, and
`state restore --complete` to promote that bundle into an absent storage root. The backward-compatible commands
without `--complete` intentionally handle only the SQLite snapshot.
For an independently read-back, compliance-locked AWS S3 version and an immutable off-host receipt,
use `state replicate-s3` after bundle creation; see
[Immutable S3 backup replication](docs/s3-backup-replication.md).

An automatic publisher binds both exact validated evaluation and upstream-outcome corpus cursors,
plus their deployment and publishing scope, in a non-expiring SQLite hold in the same transaction
that reserves publication capacity. New grades and amendments fail closed while any such hold is
active. Constructive recovery must recompute both gates and match that hold before another GitHub
write. Once exact compensation evidence is hash-chained, cleanup may only reduce its bound remote
state despite cursor or opt-in drift, or despite the breaker already being active; it cannot perform
a constructive GitHub mutation. If the bound PR already merged, the read-only reconciliation path
may adopt that exact PR into lifecycle management. Lease expiry or a worker crash never clears the
hold: it is released only with a durable `pr_open` transition or after the exact PR/branch
compensation is verified and durably marks the attempt failed.

Target-repository workspaces are not included. If a `submitting` run already has a stored commit,
complete backup fails closed because that exact Git object cannot be reconstructed from the bundle;
reconcile or finish publication on the persistent worker before retrying the backup.

Repository workspaces are therefore collected separately with
`autocontribute state gc-workspaces`. The command is a bounded dry run unless `--execute` is passed.
It never deletes run manifests, patches, validation evidence, evaluations, or SQLite state. It also
never collects a nonterminal run. Old `pr_open` workspaces are eligible only after their hash-chained
ledger proves the ordered publication intent, canonical PR persistence/reconciliation, and
`submitting -> pr_open` transition, and its canonical PR/commit identity, manifest, patch, and
validation artifact all verify. Any non-published terminal run carrying commit, branch, PR,
publication-hold, or other
publication reconstruction evidence is retained. Unsafe paths, symlink workspace entries, nested
mounts, incomplete artifacts, and ambiguous state fail closed and are reported instead of followed.
The systemd worker collects at most 25 eligible workspaces older than seven days before each
scheduled run, without credentials, then requires 4 GiB and 65,536 free inodes before loading secrets
or beginning model work. Operators can run the dry form first at any time under the shared lock.

The included GitHub-hosted Actions workflow permanently requires
`publishing.mode: review_required`; setting the auto-publish environment opt-in does not bypass that
check. A guarded `auto` pilot must run on an operator-managed, non-ephemeral worker whose live SQLite
state, run bundles, and evaluation files survive restarts and are backed up. Do not use an evictable
Actions cache as the durability boundary for autonomous publication.

The hosted review workflow uses `AUTOCONTRIBUTE_STATE_LINEAGE` as an external fail-closed pointer to
one exact cache generation. It advances that pointer only after a verified snapshot is saved and
the evidence artifact uploads, and refuses both stale prefix fallback and unfinished generations.
It accepts the exact current v8 key or exact, repository-bound v7, v6, v5, v4, or v3 keys as one-way
migration sources, checks that each key and snapshot schema agree, and writes every new generation
under a v8 key. Its explicit handoff is one-way: after state is downloaded for publication, continue
on persistent
operator-managed storage rather than restarting the hosted schedule from an older cache.

The current state/cache lineage is schema v8. Restore accepts an exact canonical v8, v7, v6, v5, v4,
v3, or v2 snapshot; older schemas migrate when the next command opens the store. Schema v3 introduced
durable publication reservations; v4 added atomic per-run event anchors, persistent lease
generations, and crash-persistent evaluation-gate holds. Schema v5 adds durable manifest-artifact
synchronization and cross-checks reservation/hold rows against their hash-chained ledger evidence.
Schema v6 adds
`publication_gate_holds.outcome_corpus_cursor`: every new automatic hold atomically binds both
evaluation and outcome cursors, while migrated v2-v5 holds retain a null outcome cursor and cannot
authorize automatic recovery. Schema v7 adds the durable issue-revision column and the original
`runs_candidate_revision_idx`. Its migration validates every bounded run row against its manifest and
transactionally backfills revisions for rows that selected a candidate. Schema v8 adds
`candidate_retry_authorizations`, the migration-provenance-only
`legacy_candidate_retry_overrides` table, and the case-insensitive partial unique
`runs_active_candidate_idx`; it also rebuilds `runs_candidate_revision_idx` with `NOCASE`. A fresh v8
lineage contains an empty legacy-marker table. During v7 migration, an old four-field
`candidate.retry_override` event is marked only after its exact event ID/hash, run and prior run,
issue revision, and suppressed prior status validate. The migration does not invent an operator or
authorization. Every seven-field v8 override instead requires exactly one matching
`candidate_retry_authorizations` row; an orphan or mismatched modern override, or an unmarked legacy
override, fails validation. The validated migration also rejects duplicate active attempts before
installing the unique index; malformed or mismatched evidence rolls the migration back. The upgrade
is an offline, one-way cutover: stop all older workers before opening restored state with v8, never
restart them against the migrated lineage, and take a fresh v8 backup before continuing. Never resume
automatic publication from a stale or partial restore, because missing reservation, gate-hold,
outcome-cursor, issue-revision, retry-authorization, active-claim, artifact-sync, evaluation-anchor,
or lease-generation history can invalidate safety decisions.

Autocontribute never autonomously creates issues, comments, reactions, reviews, stars, merges, or
maintainer messages. Follow-up changes require a fresh evidence bundle and approval.

The operational stop is durable and auditable in the configured SQLite state:

```bash
uv run autocontribute lifecycle sync
uv run autocontribute safety status
uv run autocontribute safety stop --actor OPERATOR --reason "REASON"
# Review and resolve the recorded evidence before resuming.
uv run autocontribute safety resume \
  --actor OPERATOR \
  --reason "RESOLUTION" \
  --expected-trigger-hash "ACTIVE REVISION FROM safety status"
```

A stop is global, not limited to the PR that triggered it. Every distinct stop changes the active
trigger-set revision shown by `safety status`. Resume is never automatic; inspect every active source,
reason, and trigger hash, review the linked GitHub evidence, resolve the conditions, and pass that
exact set revision when recording a concrete justification. A stale revision is rejected. On an ephemeral runner, this
persistence depends on restoring the verified state snapshot. A lost or evicted cache loses local
breaker history, so stop the active worker, set `AUTOCONTRIBUTE_ENABLED=false`, and remove
`AUTOCONTRIBUTE_ALLOW_AUTO_PUBLISH` before restarting it. A worker started without the publication
variable blocks constructive recovery writes for existing `submitting` intents; read-only
reconciliation remains enabled, and only a compensation already bound to exact hash-chained remote
evidence may continue. Keep both the scheduler and worker stopped to prohibit that final
exposure-reducing write as well.

See [SECURITY.md](SECURITY.md) before enabling a schedule and [CONTRIBUTING.md](CONTRIBUTING.md) before
working on the agent itself.

Design details live in [Architecture](docs/architecture.md), [Quality policy](docs/quality-policy.md),
[Staging](docs/staging.md), [Scheduled operation](docs/scheduled-operation.md), and the
[operator-managed systemd deployment](docs/systemd-deployment.md). The signed, reproducible artifact
process and independent verification commands are documented in [Releases](docs/releases.md).

## Development

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest --cov=autocontribute --cov-report=term-missing
```

Dependency resolution uses the fixed `tool.uv.exclude-newer` snapshot in `pyproject.toml` so local
development and CI reject newly published packages consistently. A dependency-update PR may advance
that RFC 3339 cutoff, regenerate `uv.lock`, and refresh `_build_identity.json`, but the new cutoff
must be at least seven days old when the PR is created.
Release artifacts are built without isolation only after CI installs the exactly pinned Hatchling
backend from that lockfile, so packaging does not perform a second, unrecorded dependency resolution.
Signed stable-version tags also run the environment-protected release workflow. It requires two
byte-identical clean-tree builds, audits the hash-locked runtime closure, verifies the wheel and its
source-distribution deployment assets, emits a runtime-only CycloneDX SBOM, and publishes keyless
Sigstore signatures plus GitHub SLSA provenance. The workflow requires a public repository, a
GitHub-verified signed annotated tag, and a second trusted reviewer on the `release` environment; see
[Releases](docs/releases.md) before tagging.

The test suite never creates a real public PR. A credential-free security workflow exercises Docker
isolation weekly, on manual dispatch, on pull requests and merge-queue candidates, and after pushes to
`main`. Main pushes and merge-queue candidates always run both Docker modes so the newest integrated
tree is tested. Concurrency is keyed to the event and immutable workflow commit, so a re-run of an
older tree cannot displace a newer pending run. On pull requests, a full local-diff classifier skips
the live matrix only for a narrow set of documentation-only changes and otherwise fails closed to
running both modes. Configure its stable **Security integration gate** job as a required branch check,
require a trusted approval for every pull request, and require code-owner review for workflow changes;
the check name alone does not bind a pull request to trusted workflow logic. Live GitHub/provider
shadow runs are manual opt-ins and restricted to an operator-owned fixture repository; see
[Staging](docs/staging.md).

## License

MIT
