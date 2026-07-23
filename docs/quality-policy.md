# Quality policy

No system can honestly guarantee that a maintainer will accept a contribution. Autocontribute calls
its scores *readiness* scores rather than model-predicted acceptance probabilities. Expert shadow
grades are stored separately from model scores and drive the rollout gate.

## Candidate readiness

A candidate needs a public, recently active, non-archived allowlisted repository; contribution
guidance; an open, unassigned, maintainer-signaled issue; no excluded/security label; no likely
competing PR; clear acceptance language; recent activity; and a score of at least 85 by default. The
complete issue discussion is loaded before selection. Claimed work, maintainer stop requests,
security-sensitive work, stale issues, broad scope, and policy conflicts are skipped before a model
call whenever possible.

The same canonical issue revision is not reconsidered indefinitely. An active run for an issue
always blocks another attempt, including when upstream evidence changed. With no active run, an
unchanged revision from a prior `skipped`, `rejected`, or `cancelled` run is suppressed; a prior
`failed` run does not itself suppress another attempt, and changed issue evidence creates an
available revision. This policy prevents repeated model spend on a stable conservative decision
without converting infrastructure failure into a permanent quality judgment.

Discovery fetches the canonical issue, applies this disposition before eligibility or model work,
and falls through to later candidates. A pinned deferral writes the current revision, prior run ID,
and status to the hash-chained event ledger and makes zero model calls. The manual-only
`--issue ... --retry-unchanged` exception is an operator decision, not a quality waiver: active work
still blocks, the override is audited, and every deterministic gate is rerun. Scheduled invocations
cannot pin an issue or request this override.

The deterministic score is:

| Dimension | Weight |
| --- | ---: |
| Maintainer signal | 25 |
| Issue clarity | 20 |
| Reproducibility | 20 |
| Scope | 15 |
| Activity | 10 |
| Policy fit | 10 |

## Patch hard gates

All gates must pass. A high model score cannot override one.

- A non-empty, reconstructable diff of no more than eight files and 400 added/deleted lines.
- No binaries, symlinks, submodules, file-mode changes, unsafe paths, generated/vendor files, secrets,
  dependency/lock changes, or CI workflow changes unless the global owner explicitly changes policy.
- For a bugfix, the same bounded reproduction must fail on pristine upstream and pass with the patch.
  Missing tools/files/modules, no-test discovery, timeouts, permission errors, and unavailable
  networking are infrastructure failures rather than regression evidence.
- Every operator-owned repository validation command passes in a disposable offline sandbox copy;
  model-suggested commands cannot replace it and command-budget truncation fails closed.
- A positively recognized assertion, test-runner failure, source-located compiler/type-checker error, or
  linter diagnostic may consume the run's one repair opportunity before independent review. An
  unknown nonzero result is not presumed actionable. Timeouts, unavailable commands, missing
  files/modules/scripts, incompatible dependencies or toolchains, empty test discovery, permission
  errors, and networking or proxy failures are
  infrastructure failures and are never offered to the builder. Docker launch failures, host-signal
  termination, and resource-limit termination are also non-actionable. Output that exceeds either
  the bounded sandbox capture or the 100,000-character-per-stream model artifact limit is too
  incomplete to classify and is likewise not repairable, even when the retained prefix contains a
  diagnostic. Infrastructure classification uses the bounded raw command result before the
  persisted model evidence is redacted and truncated. The same positive actionable classification
  must remain in that scrubbed model-visible evidence. The controller preflights the exact optional
  repair prompt against the builder input limit and skips a repair that cannot fit.
  Any repair reruns the exact initial validation suite; repair output cannot add, remove, or replace
  commands. A validation-driven repair and a critic-driven repair can never both occur in one run.
- Repository guidance is an exhaustive bounded input, never a best-effort sample. Before planning,
  every tracked contribution, policy, AI, security, conduct/legal, and pull-request-template file is
  loaded in full together with root `AGENTS.md` and README guidance. Ancestor `AGENTS.md` and README
  files are resolved for paths quoted in literal-reference evidence and, after planning, every
  planned or selected context path. File-count, character, read, type, or UTF-8 failures stop the run
  instead of dropping or truncating a document. Nested READMEs outside those path scopes are not
  treated as repository-wide instructions. Repository and applicable organization-template inputs
  share one ceiling of 30 files and 80,000 characters per model stage.
- If the first plan selects a path governed by guidance that was not visible to that planner, one
  bounded scout replan runs with the expanded complete guidance set before implementation. A second
  plan that enters another unseen scope fails closed; scoped instructions are never retroactively
  treated as if the planner had seen them.
- Before either initial or repair edits are applied, every edit path must remain inside the exact
  repository-guidance scopes supplied to that builder call. The critic receives the same complete
  scoped set, and additional affected context that would enter an unseen scope fails closed.
- A fresh-context critic reports no blocker or missing issue requirement.
- Every critic dimension is at least 80 and weighted readiness is at least 90.
- The exact patch bytes and all evidence that authorized readiness match the immutable preparation
  fingerprint created when the run passed its gates.
- Complete scrubbed patched-command results are stored in the run manifest, bound by that
  fingerprint, and exactly match the `validation.json` review artifact.
- Human approval is based only on a fresh SQLite manifest plus validated regular, non-symlink
  `contribution.patch` and `validation.json` artifacts. The displayed review contains the entire
  issue discussion, patch, validation stdout/stderr, PR and commit text, publication identity, and
  approval fingerprint; `report.md` is never authoritative. Approval reloads everything after the
  confirmation prompt and rejects a changed fingerprint.
- Commit and PR text are bounded, credential-free, non-broadcast, and contain the configured
  disclosure; publication rechecks the exact current disclosure rather than trusting preparation.
- Immediately before publication, the canonical repository and issue are fetched again. The issue's
  title, body, labels, complete discussion, and update timestamp must still match the sealed
  candidate. The same deterministic eligibility rules are rerun against current repository metadata,
  no competing PR may exist, and the default branch must still equal the tested base SHA.
- Every bounded repository and organization contribution-policy input (including a file's absence)
  is hashed into eligibility evidence. Publication rereads those sources and requires the digest to
  match, so even a policy edit that does not trigger a known prohibition requires fresh preparation.
- A detected CLA/DCO requirement needs a fixed, explicit attestation for exactly one repository.
  The record binds a ref-independent digest of repository identity, organization-policy presence,
  bounded path inventories and contents/absences, plus the exact detected requirement set. Unrelated
  commits therefore preserve onboarding, while policy-surface or requirement drift invalidates it.
  Named Markdown, text, YAML, JSON, and extensionless legal files are inventoried; non-negated or
  ambiguous CLA/DCO references require review rather than being guessed away.
  Reviewed refs remain audit evidence. Publication also requires the authenticated GitHub login to
  equal the attesting identity. DCO authorization binds the configured Git identity and exact
  `Signed-off-by` trailer sealed into the proposal; account-level CLA authorization is accepted only
  when the operator attests that no per-contribution signature or assent remains.

Critic dimensions are weighted as follows: correctness 25%, issue alignment 25%, tests 15%, repository
conventions 15%, diff/security hygiene 10%, and maintainer clarity 10%.

## Publication limits

Defaults allow at most one new PR per day, two open PRs, and no same-repository submission while an
existing PR is open or for seven days after a recent close/update. A `403`, `429`, stale approval,
base drift, duplicate, assignment race, or unexpected existing branch stops publication. The broker
never force-pushes.

The daily and repository-cooldown limits use durable SQLite publication reservations as their local
source of truth. Capacity is consumed transactionally immediately before the first remote mutation,
is idempotent for a retry of the same run, and is not returned after a failed or ambiguous attempt.
GitHub account searches independently catch open or externally created PRs, but eventual search
consistency cannot grant local capacity. Losing or rolling back the reservation ledger is therefore
unsafe for automatic publication.

“No suitable contribution,” “could not reproduce,” and “validation environment unavailable” are
healthy outcomes. The project must never optimize for daily PR count, profile activity, company
prestige, or stars at the expense of maintainer value.

## Production rollout gates

Use `autocontribute eval record` to bind one immutable expert judgment to each exact run artifact and
`autocontribute eval report` to inspect aggregate evidence for the current deployment fingerprint.
Before `eval record` writes anything, it prints every stored field, the exact subject hash, and the
record content hash with terminal-control characters visibly JSON-escaped. The reviewer must confirm
that complete preview. `--yes` is the non-interactive form of the same attestation: it still prints
the preview and does not weaken the post-preview subject-drift check.
Autonomous rollout remains blocked until the first 100 persisted runs with that fingerprint, ordered
by creation timestamp and then run ID, all have an evaluable completed outcome and an anchored expert
grade. The fingerprint covers exact package source, the Python interpreter, the installed runtime
dependency closure, packaged build/lock manifest, release-bound systemd deployment-asset manifest,
and material model, budget, discovery, sandbox, validation, policy, quality, and publishing-safety
configuration. This fixed cohort must include at
least 20 prepared cases, at least 95% accept-as-is precision among prepared cases, and zero policy,
security, or etiquette failures. Other deployments cannot contribute cases. Any material code, model,
or configuration change requires a new 100-run calibration; later grades are still validated but
cannot replace an omitted early matching run or alter the fixed cohort's metrics. This expert gate is
necessary but not sufficient for automatic publication.

A separate upstream-outcome gate is scoped to the exact deployment fingerprint, canonical publishing
login, and canonical GitHub API origin. Its fixed cohort is the first 20 manually approved, published
pull requests in that scope, ordered by the global durable ledger sequence of their canonical
`SUBMITTING -> PR_OPEN` transitions rather than run creation time. Every one of those 20 must have an
anchored expert `accept_as_is` verdict and a verified upstream `merged_as_is` outcome. A failed or
ambiguous fixed member is permanent; a later successful pull request never replaces it. In addition,
every earlier automatically published pull request in the scope must still prove `merged_as_is`
before another automatic publication is allowed.

Upstream success is monotone and deliberately strict. Any retained evidence of prepared-head drift
or a force push, maintainer-requested changes, a maintainer stop request, CI failure, close followed
by reopen, closure without merge, or a later revert permanently prevents `merged_as_is`, even if a
newer snapshot looks healthy. Local lifecycle `observed_at` is storage metadata, not authoritative
ordering evidence; the classifier uses GitHub source timestamps and the durable ledger order. Run
`autocontribute rollout report` for the combined expert and upstream-outcome decision. The report
must pass both fixed cohorts and the complete prior-automatic history before auto mode is usable.
Collect calibration evidence only in `review_required` mode; automatic publication is not a
calibration path and cannot bootstrap either gate.

The first grade is `<run-id>.json` under `<storage.path>/evaluations/`, not part of SQLite. If a
reviewer made a mistake, `autocontribute eval amend` appends a complete replacement judgment as
`<run-id>.revision-000002.json` (and so on); it requires a non-empty reason and the same full-preview
attestation. Never edit or delete the earlier file. Each amendment records the previous content hash,
and an atomic SQLite predecessor check prevents two corrections from forking the history. Aggregate
metrics use only the latest valid revision, but corpus loading validates every historical revision.

Recording the initial judgment or an amendment also appends an immutable anchor containing its
content hash, reviewed-subject hash, verdict, schema metadata, and, for amendments, revision and
predecessor hash to the run's hash-chained SQLite event ledger. Corpus validation rejects added,
edited, deleted, duplicated, renamed, missing, non-consecutive, or predecessor-mismatched records,
as well as prepared records whose exact patch or preparation fingerprint no longer matches. It also
recomputes every event hash and every predecessor link across the complete run ledger before trusting
the cohort. Preserve all evaluation revisions, referenced run bundles, and the matching verified
SQLite snapshot together as one generation.

The guarded automatic publisher records both exact validated corpus cursors--expert evaluation and
upstream outcome--in a non-expiring SQLite hold atomically with its publication reservation. Initial
evaluations and amendments are rejected while any hold remains. Both cursors are recomputed and
revalidated before constructive recovery. A process crash or expired coordination lease cannot
reopen either corpus. Once exact compensation evidence is durably marked, it may only close/delete
that already-bound PR/branch despite cursor or opt-in drift, or despite the breaker already being
active; after its remote result is reverified and hash-chained, it may release the hold. An exact PR
that already merged may instead be adopted into lifecycle management without a GitHub mutation. No
drift can authorize a constructive write.

Autonomous mode also requires an operator-managed, non-ephemeral deployment; the included hosted
Actions workflow remains permanently `review_required` and an evictable cache cannot serve as the
pilot's source of truth.
