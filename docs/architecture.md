# Architecture

Autocontribute is deliberately split into a credentialed control plane, an uncredentialed execution
plane, and a narrow publication broker.

```text
GitHub read API ──> discovery/policy ──> model planner ──> exact edit proposal
                                                    │
                                                    v
                                      pinned local repository
                                                    │
                                                    v
                                      offline Docker validation
                                                    │
                                                    v
                                  fresh model critic + hard gates
                                                    │
                                                    v
                                      immutable approval bundle
                                                    │
                                                    v
                                    GitHub publication broker
```

## Trust boundaries

The issue, repository, contribution documents, package metadata, command output, and model output are
all untrusted. Repository text is quoted as data in prompts and cannot change the control policy.
Every dynamic prompt section uses the same static JSON envelope with an explicit `untrusted` marker;
XML metacharacters are Unicode-escaped so repository text cannot forge section boundaries. Derived
plans and review findings remain untrusted when passed into later stages. Immediately before each API
request, likely credentials and conventionally sensitive file contents are redacted. Model output must
match strict Pydantic schemas. File edits use exact, unique search/replace operations and paths that
cannot escape the workspace.

Guidance discovery is complete within explicit input ceilings. Named contribution, policy, AI,
security, legal/conduct, and pull-request-template files are repository-wide inputs; root
`AGENTS.md` and README files are also always included. Nested `AGENTS.md` and README files are
resolved root-to-leaf only for model-visible literal-reference, planned, selected-context,
affected-review, and proposed-edit paths they govern. Any applicable file-count/character overflow
or safe-read/UTF-8 failure aborts preparation. A model cannot move an edit into a previously unseen
`AGENTS.md` scope: the orchestrator checks the complete tracked guidance inventory before mutating
the workspace. When the initial scout selects a newly governed path, one bounded scout replan sees
that expanded guidance before builder work; any further scope expansion fails closed.

Model calls use a durable per-run budget ledger. Before crossing the provider boundary, the worker
records conservative input/output, cost, and timeout reservations in the manifest. It clamps the
provider's output and timeout to the remaining aggregate budget, then reconciles input/output usage,
configured Decimal token pricing, and monotonic elapsed time before using the response. Missing or
inconsistent usage is an error. A request that fails ambiguously keeps its reservation, so a recovered
run cannot treat uncertain billed work as free. Provider-project spend limits remain the final guard
against a transport failure whose server-side billing cannot be observed locally.

Model and GitHub credentials exist only in the control process. Each validation command receives a
fresh disposable copy of the target working tree; mutations never become part of the authoritative
patch or leak into later checks. Docker receives a read/write bind of that copy, a read-only `.git`
directory, a fresh temporary home, no inherited environment, no network, no capabilities, no Docker
socket, no persistent Docker log driver, and explicit CPU/memory/PID/time/output limits. Attached
stdout and stderr remain available to the controller's bounded capture. Local command execution is
rejected unless the user opts into `allow_unsafe_local: true`.

The persistent systemd deployment additionally places every authoritative repository and disposable
validation copy on one dedicated ext4 filesystem with verified aggregate byte and fixed-inode
ceilings. Its wrapper rejects a missing, oversized, shared, bind, or incorrectly mounted filesystem
before loading credentials, and the store rejects any configured workspace path outside that checked
mount. This host-storage boundary is deployment-specific; ordinary CLI and hosted runs must provide
their own host disk controls.

That deployment also gives the rootless daemon a separate dedicated ext4 data filesystem with
verified aggregate byte and fixed-inode ceilings plus minimum free-byte and free-inode headroom. A
mount-only preflight stops the daemon before it can fall back to the service home, while the
credential-bearing wrapper compares structured `DockerRootDir` output to the exact checked mount
before loading credentials. The worker and doctor see that daemon-owned path through an explicitly
read-only child mount while the separate rootless Docker service retains its writable host view. The
wrapper exports a non-secret boundary marker that makes every later structured sandbox probe repeat
the exact comparison and headroom check. The scheduled health service also checks the filesystem
through an explicitly read-only namespace view. The marker is absent for ordinary local and rootful
review use, so those environments retain their own operator-managed disk policy.

Immediately before every Docker launch, the control process parses one bounded structured daemon
probe. It requires an absolute Docker data-root report, cgroup v2, a real cgroup driver, and reported
memory, swap, CPU-quota, and PID-limit support, then recognizes rootless operation only from one exact
`name=rootless` security option. A
rootful daemon runs repository code as the caller's nonzero UID/GID. A verified rootless daemon
instead uses UID/GID `0:0` inside its user namespace, which maps to the unprivileged daemon owner and
is the only identity able to use that owner's private bind mounts. Namespace root does not relax the
sandbox: all Linux capabilities remain dropped, no-new-privileges remains set, and the container root
filesystem remains read-only. Malformed, duplicated, unsupported user-namespace-remapping,
unenforced resource controls, or failed daemon probes stop the run.

Mandatory commands are operator-owned and resolved by canonical repository name before model work.
Model-proposed commands are supplementary. The complete suite must fit the command budget and every
required command must be observed passing; the orchestrator never truncates checks to manufacture a
successful result.

The publication broker is the only component with GitHub mutation methods. The model cannot invoke
it. Readiness creates a preparation fingerprint over the exact patch bytes and the candidate,
eligibility, repository/base, plan, proposal, baseline-validation, complete scrubbed patched-command
results, and quality evidence. The human-readable `validation.json` sidecar is derived from the
manifest copy and must match it exactly at approval and publication. Both review and automatic
publication recompute this immutable seal before continuing. In review mode, the broker additionally
requires an unexpired user approval over a canonical hash of the repository, issue, base SHA, patch
bytes, commit message, PR title/body, and disclosure. Publication also rechecks that the PR body
contains the exact disclosure in the current configuration.

The approval UI does not consume `report.md`. It resolves the authenticated publication identity,
loads a fresh validated manifest from SQLite, safely opens regular non-symlink patch and validation
artifacts, and renders the exact issue title/body/discussion, complete patch and command streams, PR
text, commit identity/text, and resulting approval fingerprint. Once the operator confirms, the
broker repeats that entire load and validation and constant-time compares the reviewed fingerprint
before recording approval. A concurrent evidence change therefore requires a new human review.

Publication does not rely on the discovery-time view of upstream state. Before reserving capacity or
mutating GitHub, it refetches the canonical repository and complete issue, requires the sealed issue
scope, labels, discussion, and update timestamp to be unchanged, and reruns deterministic eligibility
and duplicate checks. Eligibility evidence includes a SHA-256 digest over every bounded repository
and organization policy path read by the selector, including missing files; the publication read must
produce the same digest. It also requires the repository identity/default branch and tested base SHA
to remain unchanged.

Legal onboarding uses a second domain-separated digest. It includes the exact target repository,
organization-policy repository presence, bounded policy inventories, and policy contents/absences,
but excludes moving commit IDs. A repository-scoped CLA/DCO attestation binds that stable digest and
the detected requirement set; immutable refs remain audit and per-run freshness evidence. This keeps
an attestation valid across unrelated source commits without allowing any policy-path, content,
organization-presence, requirement, configured identity, or publishing-account drift. Authorized DCO
trailers are added before the preparation and approval fingerprints are computed.
The inventory includes named CLA/DCO Markdown, text, YAML, JSON, and extensionless policy/configuration
files. Every non-negated or ambiguous legal reference fails closed for explicit operator review.

## Run state

```text
queued -> discovering -> candidate_selected -> eligibility_checked -> planning
       -> implementing -> validating -> critiquing -> ready_for_approval
       -> approved -> submitting -> pr_open

Normal side exits: skipped, rejected, cancelled, failed
```

The critic may trigger one bounded `critiquing -> implementing` repair loop. Every transition is
persisted before subsequent work. Events form a per-run SHA-256 hash chain. The run row stores the
authoritative event count and terminal hash; appending an event and advancing that anchor are one
transaction. Full validation recomputes the chain and compares both values, which makes tail
truncation detectable. Manifest updates use an `updated_at` compare-and-swap so a stale in-memory copy
cannot replace newer state or pull-request evidence. GitHub publication uses a stable branch, records
mutation intent before the first write, never force-pushes, and reconciles an existing branch/PR after
uncertain failures. The manifest and hash-chained publication events bind the upstream and fork
database/node IDs plus the PR node ID. Constructive writes and compensating close/delete operations
re-read those immutable identities at the mutation boundary, so an owner/name rename or reuse fails
closed; historical `submitting` compensation without that evidence is not mutated autonomously.

Leases carry fencing generations from a durable per-name counter. A clean release removes only the
active lease, not its counter; takeover or reacquisition advances the counter, so an earlier token
cannot become valid again even when the owner string is reused.

Immediately before entering `submitting` or making the first remote mutation, publication acquires a
transactional reservation in SQLite. The reservation table is authoritative for the worker's UTC-day
and repository-cooldown accounting, so concurrent workers cannot both pass a stale read and GitHub
Search lag cannot reopen local capacity. Reservations are idempotent by run ID and are never released
after a failed or ambiguous attempt. GitHub searches remain an additional conservative account-state
check rather than the durable limit ledger.

Durable state has three coordinated parts: `state.sqlite3` stores run, lease, persistent fencing
generation, lifecycle, breaker, publication-reservation, and evaluation-gate-hold state;
`runs/<run-id>/` stores portable
evidence bundles; and `evaluations/` stores immutable expert-grade revision files separately from
SQLite. The initial `<run-id>.json` and each append-only `revision-NNNNNN` correction form a content-
hash chain; only the latest valid judgment is effective, while every predecessor remains required.
Each orchestrated run records its deployment fingerprint in both the manifest and its first
hash-chained creation event. The evaluation gate selects the earliest 100 runs whose immutable
creation evidence matches the current package source, interpreter, installed dependency closure,
packaged build/lock manifest, attested exact response-model, and material-configuration fingerprint,
so a changed runtime or
model deployment cannot inherit an older deployment's calibration. Evaluation hashes, subject hashes, and
verdict and revision metadata are anchored in each run's hash-chained SQLite event ledger, so an
added, edited, deleted, duplicated, renamed, non-consecutive, predecessor-mismatched, or artifact-
mismatched grade fails corpus validation.
This fixed expert cohort must pass before, but cannot by itself authorize, automatic publication.
The second fixed cohort is scoped by that exact deployment fingerprint together with the canonical
publishing login and canonical GitHub API origin. It contains the first 20 manually approved,
published pull requests in global durable `SUBMITTING -> PR_OPEN` ledger-sequence order, not run
creation order. Each member requires both an anchored expert `accept_as_is` verdict and an upstream
`merged_as_is` result. A failed member remains in place permanently, and every prior automatic pull
request in the same scope must also remain `merged_as_is` before the next automatic publication.
Both cohorts are built through `review_required`; auto mode cannot calibrate itself.

The upstream classifier treats adverse history as monotone. Any observed prepared-head drift or
force push, maintainer changes request or stop instruction, CI failure, close/reopen sequence,
unmerged closure, or later revert permanently disqualifies `merged_as_is`; later healthy state cannot
erase the immutable evidence. Lifecycle `observed_at` records when local storage occurred and is not
an authoritative source timestamp. GitHub timestamps establish upstream chronology, while hash-chain
and global publication-ledger order establish local evidence chronology. `autocontribute rollout
report` combines this outcome decision with the first-100 expert decision and must pass in full
before auto is usable.
The build/lock component is a required, schema-validated `_build_identity.json` shipped inside the
package. CI verifies its `pyproject.toml` and `uv.lock` SHA-256 values before building, so source and
wheel installs use the same explicit identity without searching or trusting unrelated ancestor files.
An online SQLite snapshot captures committed WAL pages and verifies integrity, the exact v6 schema,
and every event chain against its durable count/head anchor, but it does not include either
directory. `state backup --complete` additionally copies both directories, validates their run
manifests and evaluation anchors against that snapshot, inventories every file by size and SHA-256,
and emits one bounded archive. Because repository workspaces are excluded, bundle creation refuses a
`submitting` run with a stored commit: the exact commit cannot be reproduced byte-for-byte after
restore. Publication must be reconciled or finished on the persistent worker first. Its matching
restore verifies paths, types, limits, checksums, schema,
event chains, manifests, and evaluations before atomically promoting an absent storage root.
Production backup and migration procedures should quiesce writers and use this complete generation;
the SQLite-only mode remains for hosted-workflow persistence that already carries the two directories
in the same immutable cache and artifact.

Repository checkouts under `workspaces/<run-id>/` are deliberately outside that durable generation.
Workspace collection first validates the run's hash chain and exact `manifest.json`; a prepared run
must also retain a matching patch and validation sidecar. Nonterminal runs are never eligible. In
particular, `submitting` can hold the only local Git object that permits an exact retry after an
uncertain push, so neither age nor a stored remote-looking identifier makes it disposable. A
non-published terminal run with any publication intent, branch, commit, PR, compensation, or active
gate-hold evidence is likewise retained. `pr_open` is the sole publication-bearing terminal state
eligible for collection, and only after its hash-chained ledger proves ordered publication intent,
canonical PR persistence/reconciliation, and the `submitting -> pr_open` transition, and its
canonical repository, PR URL, branch, base/head commits, publishing identity, and prepared artifacts
verify. Lifecycle recovery thereafter uses that durable PR URL and commit identity, while complete
backups validate the patch and validation sidecar without the checkout. Deletion atomically moves
the selected device/inode into a private random quarantine, re-inspects it, and removes it
descriptor-relative; an identity mismatch is restored without deletion. The collector is
symlink-resistant, rejects nested mounts, and is bounded by both retention age and an inspection
limit. It removes only the checkout; the database, evidence bundle, and evaluation lineage remain.

The current SQLite schema is v6. `state restore` accepts only exact canonical v2, v3, v4, v5, or v6 schemas,
rejecting unexpected tables, indexes, views, and triggers as well as missing objects, and refuses to
replace live SQLite state. A v4, v5, or v6 snapshot's complete event ledger, run anchors, and
publication state are validated before atomic promotion. A v2 or v3 snapshot receives its exact
historical structural and evidence validation and is promoted unchanged; the next command that
constructs `RunStore` migrates it transactionally through v3, v4, v5, and v6. The v2-to-v3 step
conservatively backfills reservations for durable `submitting` and `pr_open` runs at migration time.
The v3-to-v4 step first verifies every legacy hash chain, then backfills event count/head anchors,
seeds persistent generation counters from active leases, and conservatively holds the evaluation
corpus for ambiguous submitting publications. The v4-to-v5 step adds an explicit manifest-artifact
sync outbox and reconciles materialized reservation/hold rows with their hash-chained evidence. The
v5-to-v6 step adds `publication_gate_holds.outcome_corpus_cursor`. New automatic holds atomically
bind that cursor with the evaluation cursor; migrated v2-v5 holds retain a null outcome cursor and
cannot confer automatic recovery authority. Because older schemas did not retain every
v6 invariant after a clean release, the cutover must be offline and one-way: quiesce every older
worker before the first v6 open and never let one resume against the migrated lineage. A stale
restore can omit reservations, gate holds, outcome cursors, artifact-sync intent, evaluation anchors,
event heads, or lease generations, so SQLite integrity alone does not make it a safe
autonomous-publication recovery point.

Automatic publication computes exact cursors over the globally ordered, hash-chained evaluation
anchors and the scoped upstream-outcome evidence. The publication reservation and both cursor holds
are one SQLite transaction, so a concurrent evidence change either wins first and invalidates the
publisher's cursor or loses to the hold and is rejected. Recovery recomputes and revalidates both
cursors before it may continue the held publication. The hold has no TTL. A successful PR releases it
atomically with `pr_open`; a base-race path releases it only after the exact PR is confirmed closed,
the exact expected branch SHA is conditionally deleted and verified absent, and the compensated run
is durably failed. Crashes and ambiguous cleanup retain both `submitting` and the hold for
reconciliation.

## Lifecycle feedback and circuit breaker

Publication does not end the safety boundary. The lifecycle observer reads every durable `pr_open`
run, validates its canonical PR URL and prepared commit, then takes one bounded, internally
consistent snapshot of the PR, reviews, issue and review comments, checks, commit statuses, and
cross-references. Snapshots are immutable and content-deduplicated. The observer uses deterministic
rules, not a model, to detect:

- a PR head that no longer matches the prepared contribution commit;
- the latest effective maintainer review requesting changes;
- a non-bot owner, member, or collaborator explicitly asking the contribution or automation to stop;
- a latest CI check or commit status that has failed;
- a PR closed without merge; or
- a merged contribution explicitly reverted by a later merged PR.

Any signal appends deduplicated audit evidence and trips one global circuit breaker in SQLite.
Preparation checks the breaker at orchestration stage boundaries; publication checks it at entry and
again before GitHub mutations. A scheduled invocation first runs lifecycle synchronization, before
candidate discovery, so new adverse evidence prevents model work. Inconsistent, incomplete, or
unbounded lifecycle evidence fails closed.

Lifecycle evidence format 2 explicitly retains the complete bounded commit chain, timeline count,
state-changing timeline events, and immutable node identities needed to establish an upstream
outcome. Canonical unversioned snapshots written before those fields existed remain verifiable and
restorable as `legacy_partial` evidence, preserving their original JSON and fingerprint. Their
missing history is represented as unavailable rather than an empty history, and they can still be
inspected for safety signals, but they can never prove a successful upstream outcome. A fresh
format-2 observation is required before outcome authority can be granted.

Lifecycle synchronization first observes every tracked `pr_open` pull request, then attempts every
bounded ambiguous `submitting` reconciliation while retaining any failures. Thus stale outcome or
safety evidence cannot authorize recovery, and one stranded publication cannot suppress fresh
signals from other open contributions. A pull request newly adopted from `submitting` becomes part
of the next observation cycle; reconciliation itself remains read-only unless an explicitly
authorized publication-resume path is entered. Constructive resumption revalidates the exact rollout
hold, breaker, lease, opt-in, and immutable remote identities at each write boundary. Once a
compensation is bound to exact hash-chained PR/branch evidence, it is narrower: it may continue only
the exposure-reducing close/delete despite cursor or opt-in drift, or despite the breaker already
being active, and its finalizer must validate the ordered same-run evidence before releasing the
hold. If the exact PR already merged, it may instead be adopted into lifecycle management without a
GitHub write. Stopping the scheduler and worker, rather than only removing the constructive opt-in,
is the operator boundary that forbids every remote write.

The breaker never clears itself. `safety stop` lets an operator activate it without GitHub access;
every distinct trip changes the hash of the complete active trigger set. `safety resume` requires an
operator identity, a reason, and that exact set revision and appends a new audit epoch. Resume is an
operational assertion, so the operator must first inspect every stored source, reason, and hash, review
the linked upstream evidence, and resolve the condition. A concurrent newer trip makes the reviewed
set revision stale and prevents resume. This state is durable only when the configured
SQLite database—or a verified online-backup snapshot of it—is durable.

## Model boundary

`ModelProvider.generate()` accepts instructions, one evidence prompt, and an output type. The OpenAI
adapter uses the Responses API and native Structured Outputs. The compatible adapter requires Chat
Completions servers with strict JSON Schema support; critical stages do not fall back to “please emit
JSON.” Reasoning effort is forwarded to compatible endpoints, but the Responses-specific `pro` mode
is rejected because it cannot be enforced portably. Scout, builder, and critic are stateless calls,
and critic uses a separate profile and fresh context.

Current OpenAI implementation choices follow the official documentation:

- [Latest model guidance](https://developers.openai.com/api/docs/guides/latest-model)
- [Responses API migration](https://developers.openai.com/api/docs/guides/migrate-to-responses)
- [Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs)
- [Reasoning models](https://developers.openai.com/api/docs/guides/reasoning)
- [Production best practices](https://developers.openai.com/api/docs/guides/production-best-practices)

## Deliberate MVP boundaries

The alpha is a single-user worker, not a multi-tenant service. It does not autonomously comment,
reply to reviews, sign a DCO, accept a CLA, report security issues, merge code, or browse arbitrary
websites. Dependency acquisition is not run with open network access; users should provide a pinned
sandbox image containing the target project's toolchain and dependencies. Unsupported validation
means rejection, not a waived check.
