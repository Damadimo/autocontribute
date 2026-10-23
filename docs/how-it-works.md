# How Autocontribute works

A run picks one issue and prepares a patch. It reaches `ready_for_approval` only if every rule and
gate below passes; many runs end `skipped` or `rejected`. Nothing is written to GitHub until you
approve. [Configuration](configuration.md) lists every key.

## Pipeline

| Stage | Role | Sees | Returns |
| --- | --- | --- | --- |
| `planning` | scout | The issue and every comment, repository metadata, contribution guidance, the list of tracked files, and code-search matches for terms in the issue | `proceed` or `skip`; the kind (`bugfix`, `documentation`, or `test`); files to read; a reproduction command for a bug fix; suggested checks |
| `implementing` | builder | The issue, the plan, guidance, and the selected files | Exact edits (replace one unique string, create a file, or delete one), suggested checks, a one-line commit subject, PR title and body |
| `critiquing` | critic | A fresh request: issue, plan, guidance, full diff, affected files, commit and PR text, every command result | `approve` or `reject`, six scores, blocking findings, missing issue requirements |

Every call is stateless, uses its role's `models.<role>` profile, and must return JSON matching a
strict schema. The scout call comes before any sandbox command; for a bug fix, the reproduction
command runs before the builder call. Guidance is every tracked contribution, policy, AI, security,
conduct, legal, and PR-template file, plus the root and relevant nested `AGENTS.md` and README
files. It is sent whole: over 30 files or 80,000 characters stops the run. A nested `AGENTS.md` or
README the scout did not see triggers one replan.

Per-call limits are in [`models`](configuration.md#models), per-run limits in
[`budget`](configuration.md#budget), and context limits in [`quality`](configuration.md#quality). A
run needs at most six calls (plan, replan, edit, review, one repair and its re-review); the other
calls that `budget.max_model_calls_per_run` allows cover retries after timeouts, connection
failures, and HTTP 408, 429, 500, 502, 503, and 504. Runs fail on repositories with over 5,000
tracked files, a file over 1,000,000 bytes, over 32,000,000 bytes in total, or a file list (path,
size, and line count per file) over 140,000 characters, and when a code search for issue or plan
terms finds more than 160 matches. Any limit fails the run, except that a repair that would not fit
is skipped.

## Choosing an issue

`autocontribute discover` shows the pick without cloning or changing GitHub; `run` picks the same
way. Both read `github.repositories` and the `github.repository_limit_per_owner` (8) most recently
pushed public repositories of each `github.owners` entry, most stars first. Each repository gets one
search for open issues with an invitation label, newest first, and discovery reads up to
`github.issue_limit_per_repository` (10) of them in full, skipping results that already fail a rule
needing only the issue. Of the first `budget.max_candidates_per_run` (25) eligible issues, the
highest score wins. `run --issue owner/repo#N` skips the search, not the rules, which all run before
any model call. Issues with an active run, or unchanged since a `skipped`, `rejected`, or
`cancelled` one, are passed over ([Run states](#run-states)). A repository or issue that GitHub
cannot serve is reported and skipped, and `discover --explain` lists every issue with its score and
blockers.

| Rule | Key (default) |
| --- | --- |
| Repository is public, not archived or disabled, has enough stars, and was pushed to recently | `github.min_stars` (0), `github.max_repository_inactivity_days` (180) |
| No PR this tool opened in the repository is still open | |
| Issue is open, updated recently, and unassigned | `github.max_issue_age_days` (365), `github.require_unassigned` (true), `policy.allow_assigned_issues` (false) |
| Issue has an invitation label, or a maintainer comment inviting a pull request, and no excluded label | `policy.require_maintainer_signal` (true), `github.include_labels`, `github.exclude_labels`, `github.labels` ([Configuration](configuration.md#github)) |
| Title, body, comments, and labels show no sign of a vulnerability (CVE, injection, XSS, ...) | `policy.allow_security_issues` (false) |
| The issue does not ask contributors to stay away; no open PR in the repository links it with a closing keyword or was updated in the last 90 days; no comment from the last 30 days claims the work ("I'm working on this") unless a maintainer has since offered it to anyone ("still up for grabs") or invited a PR after the claimant had been quiet for a week (a quick "Thanks! Feel free to open a PR." accepts the claim); and no maintainer comment asks contributors to stop or hold off. A maintainer comment that turns away automated or AI contributions [holds](#lifecycle-sync-holds-and-the-safety-stop) the whole repository | |
| The repository takes pull requests from people who are not collaborators and has no `.github/VOUCHED.td` vouch list | |
| Every policy file could be read; the repository or its owner's `.github` repository has contribution guidelines; the AI policy does not ban agent-made contributions and, unless you opt in, does not ask for human-written PR text; and a detected CLA or DCO has a matching attestation ([Legal attestations](configuration.md#legal-attestations)) | `policy.require_contribution_guidelines` (true), `policy.allow_conditional_ai_policy`, `policy.legal_attestations` |
| The score below reaches 60 (search only: `run --issue` and `publish` do not apply it, so a prepared run does not go stale as the issue ages) | |

Policy files are read at the pinned commit from the root, `.github/`, and `docs/` of the
repository and of its owner's `.github` repository: contribution guides, AI policies, `AGENTS.md`,
`CLAUDE.md`, `GEMINI.md`, `.github/copilot-instructions.md`, PR templates, security, conduct,
support, and governance files, CLA and DCO files, and the top-level README. Pages that a
contribution guide links to in the same repository are read too, one link deep. A file that cannot
be read, more than 128 files, or more than 4,000,000 bytes skips the repository.

The AI policy is read sentence by sentence, HTML comments included. A sentence about contributing
that names agentic, autonomous, or fully automated tools, or AI- or LLM-generated work, together
with "not accepted", "will be closed", "not allowed", "prohibited", "refrain from", "ban", or
"decline" is a ban. Rules about disclosing AI use or writing PR text yourself make the policy
conditional; the quotes are kept with the run for the approval review.

| Score part | Points | Earned by |
| --- | ---: | --- |
| Invitation | 25 | an invitation label or a maintainer comment inviting a PR (15 for a `bug` label alone) |
| Specificity | 25 | expected versus actual behavior (10), a code block (5), a file or code reference (5), reproduction steps or error output (5); documentation and test issues get the behavior and reproduction points |
| Smallness | 20 | a small, easy, or typo label, or "typo" in the title (10), fewer than 15 comments (5), at most one source file named (5) |
| Freshness | 15 | created in the last 2 years (5), updated in the last 90 days (5), a maintainer comment in the last 90 days (5) |
| Testability | 15 | a code block or reproduction steps (10; documentation and test issues get these), tests named (5) |
| Kind of work | -15 to +15 | docs, CI, build, test, or typing work (+10); a reproduction and a named file or function (+5); performance, feature, UI, platform-specific, or concurrency work, unless a maintainer comment states the expected behavior (-15) |

## Validation

With the default `sandbox.backend: docker`, each command runs on a fresh copy of the patched
checkout with no network, a read-only root filesystem (except that copy and `/tmp`), no
capabilities, no credentials, none of your environment, and the `sandbox` time, memory, CPU, and
process limits. Nothing can be downloaded, so the image must hold every toolchain
([Sandbox image](sandbox-image.md)). The suite runs in this order, stops at the first
failure, must pass in full, and must fit in `sandbox.max_commands` (8 per run, also counting the
baseline run and a repair rerun) or the run fails.

1. `validation.required_commands` for the repository. You own these; models cannot drop or change
   them. A repository reached through `github.owners` without an entry fails the run.
2. For a bug fix, the scout's reproduction command, which must also fail on the unpatched base.
3. Checks suggested by the scout and builder.

Infrastructure failures and cut-off output are never sent back to the builder: a timeout; exit
code 125 (Docker could not start), 126 or 127 (command not executable or not found), 130, 137, or
143, or another signal; output over the 2,000,000-byte capture or 100,000-character stored limit;
or output showing a missing command, file, module, script, dependency, or toolchain, no tests
collected, a test-runner internal error, no disk space or memory, permission denied, failed DNS or
network access, or an unreachable Docker daemon.

A run gets at most one repair: after validation, for an assertion, a failing test, a syntax error,
a compiler or type-checker error with a source location, or a linter diagnostic; or after review,
when every command passed and the critic rejected with blocking findings. It is skipped unless one
more builder and critic call, the full suite, and the request fit the remaining limits, and it
reruns the same suite. A run whose validation still fails is reviewed anyway and ends `rejected`.

## Gates

| Gate | Passes when | Key (default) |
| --- | --- | --- |
| `diff_present`, `file_count`, `changed_lines` | 1 to N files change, with at most M added plus deleted lines | `quality.max_files_changed` (8), `quality.max_changed_lines` (400) |
| `no_binary_files`, `no_symlinks`, `no_submodules`, `no_mode_changes`, `safe_paths` | no binary files, symlinks, submodules, or mode changes; no absolute paths or `..` | |
| `forbidden_paths` | no changed path matches a glob | `quality.forbidden_paths` (`.github/workflows/**`, `.github/actions/**`, `**/*.pem`, `**/*.key`, `**/generated/**`, `vendor/**`) |
| `dependency_policy`, `workflow_policy` | no manifest or lock file (`pyproject.toml`, `package.json`, `go.mod`, `requirements*.txt`, `uv.lock`, ...) and no CI file (`.github/workflows/`, `.github/actions/`, `.circleci/`, `.buildkite/`, `.gitlab-ci.yml`, `azure-pipelines.yml`, `Jenkinsfile`) changes | `policy.allow_dependency_changes` (false), `policy.allow_workflow_changes` (false) |
| `secret_scan` | no credential-like text in added lines; a hit fails the run and activates the safety stop | |
| `required_validation`, `validation`, `regression_evidence` | every command passed; for a bug fix, the reproduction also failed on the base, not by a timeout or infrastructure failure | `validation.required_commands`, `quality.require_regression_evidence_for_bugfix` (true) |
| `critic_verdict`, `critic_blockers`, `issue_requirements` | the critic approved, with no blocking findings or missing issue requirements | |
| `minimum_review_dimension`, `readiness_score` | every critic score is at least N, and the weighted score at least M | `quality.min_dimension_score` (80), `quality.min_readiness_score` (90) |

Critic scores run 0 to 100, weighted: correctness 25%, issue alignment 25%, tests 15%, repository
conventions 15%, diff hygiene 10%, maintainer clarity 10%. A failed gate ends the run `rejected`.
The run fails unless the commit subject is one line of at most 200 characters (plus any DCO
trailer), the PR title at most 200 and the body 50,000 characters, none with credentials,
`@everyone`, or `@here`, and the body keeps every heading and checklist item of the PR template. A
template checklist item in the first person ("I have read ...") or about legal terms, or a pick-one
list such as "Type of change", fails the run.

## Approval and publication

`autocontribute runs show RUN_ID` prints the review of a `ready_for_approval` run, `approve RUN_ID`
prints it again and asks you to confirm, and `publish RUN_ID` opens the PR. The review is rebuilt
from `state.sqlite3`, `contribution.patch`, and `validation.json`, not `report.md`: the issue and
comments, the full patch, all command output, the commit message and author, the PR title and body,
the target repository and base commit, the publishing account, and a fingerprint over all of it.
`approve` refuses if any of it changed. Only the approving GitHub account can publish, within
`publishing.approval_expires_hours` (72, at most 168). `publish` refuses unless:

- the approval is current and matches the stored patch and command results;
- the repository is still in `github.repositories`, or its owner in `github.owners`;
- the repository's `validation.required_commands` and the `sandbox`, `policy`, `quality`, and
  `publishing` settings match those the run was prepared with;
- the PR body still shows the current `policy.ai_disclosure`, which preparation appends;
- your account is within the [publication limits](configuration.md#publishing);
- the base commit, policy files, CLA/DCO evidence, and issue (state, title, body, labels, comments,
  assignees, update time) are unchanged, and the issue still passes every rule with no linked PR.

A failed recheck pushes nothing and leaves the run `approved`: retry `publish` after a limit clears,
or run `autocontribute runs cancel RUN_ID --reason "TEXT"` and [retry the issue](#run-states) (also
the way past an expired approval). Once the rechecks pass, the attempt uses that day's slot and
starts the cooldown even if a later step fails. `publish` creates or reuses your fork
(`<login>/<repository>`), commits as `identity.name` and `identity.email` (if empty, your login and
`<login>@users.noreply.github.com`), and pushes the new branch
`<publishing.branch_prefix>/issue-<number>-<run ID prefix>`, never overwriting an existing one. If
the base, issue, or policy files changed meanwhile, it deletes the branch and the run ends `failed`;
otherwise it opens a PR against the default branch. With `publishing.draft: true` it opens a draft
and then marks it ready for review if `publishing.ready_for_review` is true.

## Run states

```text
queued → discovering → candidate_selected → eligibility_checked → planning → implementing → validating → critiquing → ready_for_approval → approved → submitting → pr_open
```

| Side exit | When | The issue afterwards |
| --- | --- | --- |
| `skipped` | no eligible issue, a pinned issue fails a rule or is blocked, or the scout returns `skip` | passed over until updated |
| `rejected` | a gate failed | passed over until updated |
| `failed` | an error, a limit, a GitHub rate limit that outlasts the run's waits, or the safety stop; also preparation left unfinished for 2 hours | open to the next run |
| `cancelled` | `autocontribute runs cancel` on a `ready_for_approval` or `approved` run, or, at the start of each `run`, a `ready_for_approval` run nobody approved within `publishing.approval_expires_hours` plus 7 days | passed over until updated |

The one repair goes back to `implementing`. A run in any other state, `pr_open` included, keeps
other runs off its issue. Lifecycle sync records on a `pr_open` run whether its PR is open, merged,
or closed. To retry an unchanged issue (every rule and gate runs again; `--scheduled`
runs cannot do this):

```bash
autocontribute run --issue owner/repo#123 --retry-unchanged --retry-actor NAME --retry-reason "TEXT"
```

## Lifecycle sync, holds, and the safety stop

`autocontribute lifecycle sync` reads every open PR this tool opened and re-checks runs left in
`submitting`. It runs first in every `run --scheduled` ([Scheduling](../README.md#scheduling)) and
`publish`, and exits with code 2 while the safety stop is active. Once a PR is closed, sync stops
reading it. For 30 days after a PR is merged, sync reads only whether another merged PR reverts it.
A PR that GitHub cannot serve gets an `observation_failed` note, and sync goes on to the next one.

Routine events stop nothing. Each one is noted once on its run (`pull_request_attention` in
`manifest.json`) for you to handle:

- a maintainer (owner, member, or collaborator, not a bot) requests changes in their latest review;
- a check's latest run ends `failure`, `timed_out`, or `startup_failure`, or a commit status fails
  (`action_required`, `cancelled`, `neutral`, `skipped`, and `stale` are ignored);
- another GitHub account pushes commits on top of the prepared commit.

A hold stops work on one repository or PR, or stops all publication, until it expires or you
release it. Discovery skips held repositories. `publish` refuses held repositories and PRs, and
refuses everything while publication is held.

| Event | Hold |
| --- | --- |
| The PR is closed without being merged | repository, 30 days |
| A maintainer asks to close or stop this PR | the PR, and the repository for 30 days |
| A maintainer turns away automated, AI, or bot contributions ("stop opening AI-generated PRs", "PRs from bots will be closed") on a PR or on a candidate issue, or says on a PR that outside contributions are not accepted | repository, until released |
| The PR is reverted | repository and all publication, until released |
| GitHub blocks the account from creating content | all publication, until released |

The safety stop is one global switch that never clears itself: while it is on, `run` and
`publish` refuse for every repository, though a cleanup that an earlier `publish` started
(deleting its branch or closing its PR) still finishes. It turns on when:

- a published PR's head changed, and GitHub's push record for the branch does not show that every
  push since the prepared commit was a plain (not force) push by another account; commit authors
  are not trusted for this, because anyone can set an author email (this tool never pushes to an
  open PR);
- maintainers of two repositories turn away your PRs as automated contributions within 30 days,
  counting only holds you have not released (a comment on a candidate issue holds its repository
  but does not count, because it is addressed to every contributor);
- the secret scanner finds credential-like text in a patch, GitHub reports the account suspended,
  or publishing cannot confirm what GitHub did;
- three `run` invocations in a row end on a GitHub secondary rate limit;
- you run `autocontribute safety stop --actor NAME --reason "TEXT"`.

A GitHub rate limit stops only the command that hit it. After a secondary rate limit, a command
waits at least 1, then 2, then 4 minutes, and 10 minutes at most in total. If GitHub still refuses,
the command ends with an error (a run ends `failed`), and the next run retries. When three `run`
invocations in a row end this way, the schedule itself keeps provoking GitHub, and the safety stop
turns on.

```bash
autocontribute safety status   # the safety stop, its triggers, and every active hold
autocontribute safety resume --actor NAME --reason "TEXT" --expected-trigger-hash REVISION
autocontribute safety release HOLD_ID --actor NAME --reason "TEXT"
```

`REVISION` is the active trigger-set revision from `safety status`; a newer trigger changes it and
`resume` refuses. A trigger you resumed or a hold you released does not fire again; new or edited
evidence does.

## Where evidence is written

| Path under `storage.path` (default `.autocontribute`, next to the config file) | Contents |
| --- | --- |
| `state.sqlite3` | run records and audit events, approvals, safety-stop state and history, holds, the reservations behind the daily limit and cooldown |
| `runs/<run-id>/manifest.json` | the full run record: issue and comments, eligibility evidence, plan, proposal, command results, gate results, approval, PR URL |
| `runs/<run-id>/contribution.patch` | the exact diff that gets committed |
| `runs/<run-id>/validation.json` | baseline and patched command results, with stdout and stderr |
| `runs/<run-id>/context-search.txt` | code-search matches used to choose context files |
| `runs/<run-id>/model-calls.json` | each completed model call: role, returned model ID, token usage, cost, duration |
| `runs/<run-id>/report.md` | a readable summary; approval does not use it |
| `workspaces/<run-id>/` | the repository checkout, deleted when the run reaches `pr_open`, `skipped`, `rejected`, `failed`, or `cancelled`; the next `run` retries a deletion that failed |

Never delete or roll back `state.sqlite3`; the limits and the safety stop depend on it. Delete the
state directory only when a newer version says it cannot migrate it.
