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

# Inspect the generated evidence, then explicitly attest and publish.
uv run autocontribute runs show RUN_ID
uv run autocontribute approve RUN_ID
uv run autocontribute publish RUN_ID
```

`doctor` is an active preflight, not a purely static configuration check. It sends one bounded,
potentially billable strict-schema request per distinct model profile (at most 1,024 output tokens
and 60 seconds), with no model tools or repository credentials. Its GitHub probes use only `GET`
requests: prepare-only deployments verify target reads and warn about excess or unreportable token
scopes; guarded automatic publication also verifies an existing fork's reported push permission, or
clearly labels classic-scope evidence as inferred without attempting fork creation. For Docker,
`doctor` launches the pinned image with networking and Linux capabilities disabled and verifies the
entrypoints and explicit Python modules named by operator-owned validation commands. Repository-local
scripts and project-dependent behavior remain the responsibility of the real isolated validation
run. An explicitly configured unsafe-local backend checks the host toolchain and does not require
Docker.

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
that credential is never exposed to model or target-repository work. Before
downloading state for local approval/publication, use the workflow's `lock_for_handoff=true`
dispatch; it uploads the complete handoff artifact before writing the irreversible marker that
permanently stops the hosted lineage, so lifecycle state cannot fork. See
[Scheduled operation](docs/scheduled-operation.md).

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
explicit repository, no owner-wide discovery, draft PRs, one new PR per day, and at least a seven-day
same-repository cooldown. It also requires `AUTOCONTRIBUTE_ALLOW_AUTO_PUBLISH=1` at runtime. Rate
limits, maximum open/new PR counts, same-repository cooldowns, duplicate checks, issue assignment,
policy changes, or base-branch drift stop publication.

Removing that runtime variable immediately prevents scheduled GitHub mutation, including recovery
of a durable `submitting` publication intent left by an interrupted worker. Scheduled runs still
perform read-only reconciliation and may adopt an already-open remote pull request. In
`review_required` mode, resume a stranded intent only with an explicitly confirmed
`autocontribute publish RUN_ID` command.

The publication recheck refetches the complete issue and repository, reruns deterministic
eligibility, and requires the sealed issue title/body/labels/discussion to be unchanged. Repository
and organization policy files are reread and compared through a digest recorded at discovery, so a
new or edited policy stops the run even when it contains no recognized prohibition phrase.

Immediately before the first GitHub mutation, the worker transactionally consumes a durable SQLite
publication reservation. Those reservations—not eventually consistent GitHub Search results—are the
local source of truth for the UTC daily limit and same-repository cooldown. A retry of the same run is
idempotent; a failed or ambiguous attempt keeps its reservation. GitHub account searches remain a
separate conservative check for externally created and open pull requests.

Automatic publication also remains locked until the first 100 runs for the current deployment
fingerprint, in persisted creation-time order with run ID as the tie-breaker, all have completed
outcomes and anchored expert reviews. The fingerprint binds the cohort to the exact packaged Python
source, Python interpreter, installed runtime dependency closure, and the packaged build/lock manifest,
plus material model, budget, discovery, sandbox, validation, policy, quality, and publishing safety
settings. That fixed cohort must contain at least 20 prepared cases, at least 95% accept-as-is
precision, and zero policy, security, or etiquette failures. Runs or reviews from another deployment
cannot fill the cohort. Any material code, model, or configuration change starts a new calibration
cohort; later favorable reviews cannot replace a missing or unfavorable member. Passing that measured
gate does not enable publication; the configuration and environment opt-ins are still required.

The build/lock identity comes from the validated `_build_identity.json` packaged beside the Python
modules. CI requires its SHA-256 values to match this project's `pyproject.toml` and `uv.lock`, and the
same manifest ships in editable-source and wheel installs. Runtime identity never searches parent
directories, so an unrelated ancestor project cannot silently change or impersonate a cohort.

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

An automatic publisher binds the exact validated evaluation-corpus cursor in a non-expiring SQLite
hold in the same transaction that reserves publication capacity. New grades and amendments fail
closed while any such hold is active. Lease expiry or a worker crash never clears it: the matching
hold is released only with a durable `pr_open` transition or after exact PR/branch compensation is
verified and durably marks the attempt failed.

Target-repository workspaces are not included. If a `submitting` run already has a stored commit,
complete backup fails closed because that exact Git object cannot be reconstructed from the bundle;
reconcile or finish publication on the persistent worker before retrying the backup.

The included GitHub-hosted Actions workflow permanently requires
`publishing.mode: review_required`; setting the auto-publish environment opt-in does not bypass that
check. A guarded `auto` pilot must run on an operator-managed, non-ephemeral worker whose live SQLite
state, run bundles, and evaluation files survive restarts and are backed up. Do not use an evictable
Actions cache as the durability boundary for autonomous publication.

The hosted review workflow uses `AUTOCONTRIBUTE_STATE_LINEAGE` as an external fail-closed pointer to
one exact cache generation. It advances that pointer only after a verified snapshot is saved and
the evidence artifact uploads, and refuses both stale prefix fallback and unfinished generations.
It accepts exact, repository-bound v4 or v3 cache keys only as one-way migration sources, checks
that each key and snapshot schema agree, and writes the next generation under a v5 key. Its
explicit handoff is one-way: after state is downloaded for publication, continue on persistent
operator-managed storage rather than restarting the hosted schedule from an older cache.

The current state/cache lineage is schema v5. Restore accepts an exact canonical v5, v4, v3, or v2
snapshot for migration on the next command that opens the store. Schema v3 introduced durable
publication reservations; v4 added atomic per-run event anchors, persistent lease generations, and
crash-persistent evaluation-gate holds. Schema v5 adds durable manifest-artifact synchronization and
cross-checks reservation/hold rows against their hash-chained ledger evidence. The upgrade is an
offline, one-way cutover: stop all older workers before opening restored state with v5, never restart
them against the migrated lineage, and take a fresh v5 backup before continuing. Never resume
automatic publication from a stale or partial restore, because missing reservation, gate-hold,
artifact-sync, evaluation-anchor, or lease-generation history can invalidate safety decisions.

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
persistence depends on restoring the
verified state snapshot. A lost or evicted cache loses local breaker history, so set
`AUTOCONTRIBUTE_ENABLED=false` and remove `AUTOCONTRIBUTE_ALLOW_AUTO_PUBLISH` for an out-of-band stop.
The removed publication variable also blocks scheduled recovery writes for existing `submitting`
intents; read-only remote reconciliation remains enabled.

See [SECURITY.md](SECURITY.md) before enabling a schedule and [CONTRIBUTING.md](CONTRIBUTING.md) before
working on the agent itself.

Design details live in [Architecture](docs/architecture.md), [Quality policy](docs/quality-policy.md),
[Staging](docs/staging.md), and [Scheduled operation](docs/scheduled-operation.md).

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

The test suite never creates a real public PR. A weekly security workflow exercises Docker isolation
without credentials. Live GitHub/provider shadow runs are manual opt-ins and restricted to an
operator-owned fixture repository; see [Staging](docs/staging.md).

## License

MIT
