# How Autocontribute works

A run picks one issue and prepares a fix. It reaches `ready_for_approval` only if the fix passes
every check below and a review; many runs end `skipped` or `rejected`. Nothing is written to GitHub
until you approve. [Configuration](configuration.md) lists every key.

## Pipeline

`autocontribute run` goes through these steps. The names in code that start a step are the run's
[states](#run-states).

1. `run --scheduled` starts with [lifecycle sync](#lifecycle-sync-holds-and-the-safety-stop).
2. `discovering`: the run is skipped with reason `daily budget` unless the last 24 hours leave at
   least a quarter of `budget.max_cost_usd_per_run` within `budget.max_cost_usd_per_day`. The run
   may spend the per-run cap or what the day has left, whichever is less. Discovery then picks an
   issue ([Choosing an issue](#choosing-an-issue)).
3. `candidate_selected`, `eligibility_checked`: the run claims the issue, so no other run takes
   it, and clones the repository at the default-branch commit discovery read, which stays the base
   of the change.
4. `setting_up`: the repository's test environment is built and its tests run on the unchanged
   code ([Setting up](#setting-up)).
5. `implementing`: the agent fixes the issue ([The agent](#the-agent)). Every submit runs the
   [fix checks](#fix-checks).
6. `critiquing`: a fresh critic reviews the fix ([Review](#review)), in at most two rounds.
7. The controller writes the [pull request text](#pull-request-text), and the run becomes
   `ready_for_approval`.

Four models take part, each in its own transcript ([`models`](configuration.md#models)):

| Model | Step | Sees | Can do | Turns |
| --- | --- | --- | --- | ---: |
| triage | discovery | one issue with its comments, or a repository's policy files that mention AI | answer with `submit_triage` or `submit_policy` | 1 |
| setup | `setting_up`, after a recipe failed | the failed recipe, why it failed, the end of its log, and the repository's build and test files | run commands and edit files in a setup container whose network goes through a proxy, then `submit_setup` | 40 |
| agent | `implementing` | the issue and its comments, recent commit titles, the contributing guide, `AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md`, the PR template, the AI-policy quotes, and the test command with its results before any change | run commands and edit files in a container with no network, then `submit` | 100 over all rounds |
| critic | `critiquing` | the issue, the patch, the PR text, the agent's summary marked as claims, every check result, and the AI-policy quotes; never the agent's transcript | run commands on a throwaway copy of the patched repository with no network, then `submit_review` | 40 per round |

Text from the issue, the repository, and other models reaches a model marked as untrusted data.
Each guidance file is cut to 20,000 characters and all of them together to 50,000; the issue body
is cut to 20,000 characters and each comment to 4,000, with 24,000 for all comments. A nested
`AGENTS.md` reaches the agent when it first edits a file under that directory.

Every model request reserves its worst-case cost before it is sent
([`budget`](configuration.md#budget)). Setup may spend at most 15% of the run's cap, triage 10%,
and the agent 55%, which leaves the critic at least 20%. A request that could pass 200,000 input tokens ends the transcript with one
last turn. Timeouts, connection errors, and HTTP 408, 409, 429, 500, 502, 503, 504, and 529 are
retried, up to 3 attempts per turn; quota and provider-policy errors are not.

## Choosing an issue

`autocontribute discover` shows the pick without cloning, calling a model, or changing GitHub. It
applies the same rules as `run` but skips triage and uses only AI-policy readings cached by earlier
runs, so its pick can differ. Both read `github.repositories` and the
`github.repository_limit_per_owner` (8) most recently pushed public repositories of each
`github.owners` entry, most stars first. Each repository gets one search for open issues with an
invitation label, newest first, and discovery reads up to `github.issue_limit_per_repository` (10)
of them in full, skipping results that already fail a rule needing only the issue. Discovery stops
after `budget.max_candidates_per_run` (25) eligible issues and ranks them by score.
`run --issue owner/repo#N` skips the search and triage, not the rules. Issues with an active run,
or unchanged since a `skipped`, `rejected`, or `cancelled` one, are passed over
([Run states](#run-states)). A repository or issue that GitHub cannot serve is reported and
skipped, and `discover --explain` lists every issue with its score and blockers.

| Rule | Key (default) |
| --- | --- |
| Repository is public, not archived or disabled, has enough stars, and was pushed to recently | `github.min_stars` (0), `github.max_repository_inactivity_days` (180) |
| No PR this tool opened in the repository is still open | |
| The repository's test environment did not fail in the last 7 days ([Test environments](environments.md#the-7-day-block)); `run --issue` checks this when setting up | `environments` (an entry lifts the block) |
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
be read, a file over 256,000 bytes, more than 128 files, or more than 4,000,000 bytes in total
skips the repository.

The AI policy is read sentence by sentence, HTML comments included. A sentence about contributing
that names agentic, autonomous, or fully automated tools, or AI- or LLM-generated work, together
with "not accepted", "will be closed", "not allowed", "prohibited", "refrain from", "ban", or
"decline" is a ban. Rules about disclosing AI use or writing PR text yourself make the policy
conditional. `run` also asks the triage model to classify the policy files that mention AI, and any
`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, or `copilot-instructions.md`, as `ban`, `conditional`,
`permissive`, or `none`, quoting the sentences it relies on. That reading counts only when every
quote appears verbatim in the file it names; otherwise the sentence reading counts, and a ban whose
quotes cannot be found skips the repository. The reading is cached in `state.sqlite3` until those
files change. The quotes are kept with the run for the approval review.

| Score part | Points | Earned by |
| --- | ---: | --- |
| Invitation | 25 | an invitation label or a maintainer comment inviting a PR (15 for a `bug` label alone) |
| Specificity | 25 | expected versus actual behavior (10), a code block (5), a file or code reference (5), reproduction steps or error output (5); documentation and test issues get the behavior and reproduction points |
| Smallness | 20 | a small, easy, or typo label, or "typo" in the title (10), fewer than 15 comments (5), at most one source file named (5) |
| Freshness | 15 | created in the last 2 years (5), updated in the last 90 days (5), a maintainer comment in the last 90 days (5) |
| Testability | 15 | a code block or reproduction steps (10; documentation and test issues get these), tests named (5) |
| Kind of work | -15 to +15 | docs, CI, build, test, or typing work (+10); a reproduction and a named file or function (+5); performance, feature, UI, platform-specific, or concurrency work, unless a maintainer comment states the expected behavior (-15) |

`run` then shows the five highest-scoring eligible issues, in order, to the triage model, each with
its comments, and takes the first one it accepts. Triage turns down an issue it judges unsuitable,
already fixed, in need of a design decision, or large. An issue whose triage request fails is passed
over. When triage accepts none of the five, the run ends `skipped`.

## Setting up

`setting_up` builds a Docker image with the repository's dependencies and runs its tests on the
unchanged code. Detection reads the repository's CI files, task runners, and manifests without
running anything; when its recipe fails, the setup model may propose another, which is replayed
from scratch. Install commands run with network through a proxy that allows only package
registries, GitHub, and `environments.<repo>.allow_hosts`; everything after setup runs with no
network. The tests run two or three times, and the environment is accepted only when they show a
working suite. This baseline is what the fix checks compare against. A repository without an
accepted environment ends the run `skipped` with reason `environment` and is not tried again for 7
days. [Test environments](environments.md) has the details and how to override detection.

## The agent

In `implementing`, the agent works on the clone in a container started from the environment image,
with no network. Each shell command starts in a fresh shell in `/workspace` and gets at most 300
seconds, or `sandbox.command_timeout_seconds` when that is lower. The editor writes on the host and
refuses paths outside the clone, inside `.git`, or through a symlink; after each edit of a Python
file, the file's syntax is checked. Output over 10,000 characters is cut to its head and tail, and
the container keeps the whole of it under `/tmp/ac-out`.

The agent finishes with `submit`: outcome `fixed` with a PR title and body, a one-line commit
message of at most 200 characters, and the tests it added; or outcome `skip` with a reason, which
ends the run `skipped`. A turn without a tool call gets a reminder to continue, at most twice.
Three turns in a row with only invalid calls, the same failing command three times in a row, or
running out of turns, budget, time, or context ends the transcript without a fix.

## Fix checks

Every `submit` with outcome `fixed` runs these checks, and the agent gets the result: its full
diff, each gate, the test runs, and a checklist of what a maintainer would remove.

1. The patch is every change to a tracked file and every new file Git does not ignore, against the
   base commit. It must be UTF-8 text.
2. The [gates](#gates) read only the patch. When one fails, no test runs.
3. **Fails before, passes after.** When the patch changes source files and tests, the new or
   changed tests run on the post-setup workspace with only the test part of the patch, and at
   least one must fail with an assertion; an import, syntax, or collection error or a timeout does
   not count. With the whole patch, they must pass 3 runs in a row. A patch of tests alone must
   pass 3 runs in a row. A patch with no test skips this step, and the [review](#review) decides
   whether it needed one.
4. **No new failures.** With the whole patch, the tests related to the changed files run first,
   then the full suite if its baseline duration fits the time left. A new failure is a test that
   passed in every baseline run and now fails, errors, is skipped, or is missing, and still does in
   two more runs. Tests that failed or gave different results in the baseline are ignored. When the
   full suite does not fit, the related tests decide; when there are none, the step is recorded as
   not run, never as passed, and the PR's testing note says so.

Test files are those under a `test`, `tests`, or `__tests__` directory or named `test_*.py`,
`*_test.py`, `*_test.go`, `*.test.*`, or `*.spec.*`, plus Rust hunks inside `#[cfg(test)]`. Each
test run starts a fresh container with no network on a copy of the post-setup workspace with the
patch applied, so files the agent left outside the patch never reach a check. A run gets
`sandbox.command_timeout_seconds` or the time the run has left, whichever is less. A run that
breaks, for example when a build command fails or the test report cannot be read, fails the check,
except that a broken run of the related tests leaves the decision to the full suite.

When every check passes, the agent must submit the same diff again to confirm it; a changed diff is
checked again. Each round of work allows 4 submits, the confirming one included, so a failed check
goes back to the agent at most twice. A round that ends without a confirmed fix ends the run
`rejected`.

## Gates

| Gate | Passes when | Key (default) |
| --- | --- | --- |
| `diff_present`, `file_count`, `changed_lines` | 1 to N files change, with at most M added plus deleted lines | `quality.max_files_changed` (8), `quality.max_changed_lines` (400) |
| `source_file_count`, `source_changed_lines` | at most N files that are not tests change, with at most M added plus deleted lines | `quality.max_source_files` (3), `quality.max_source_lines` (150) |
| `no_binary_files`, `no_symlinks`, `no_submodules`, `no_mode_changes`, `safe_paths` | no binary files, symlinks, submodules, or mode changes; no absolute paths or `..` | |
| `forbidden_paths` | no changed path matches a glob | `quality.forbidden_paths` (`.github/**`, `**/*.pem`, `**/*.key`, `**/generated/**`, `vendor/**`, commit and install hooks, build scripts such as `build.rs`) |
| `sensitive_paths` | no credential file changes, such as `.env`, `.netrc`, `id_rsa`, or a `.pem`, `.key`, or `.p12` file | |
| `dependency_policy`, `workflow_policy` | no manifest or lock file (`pyproject.toml`, `package.json`, `go.mod`, `requirements*.txt`, `uv.lock`, ...) and no CI file (`.github/workflows/`, `.github/actions/`, `.circleci/`, `.buildkite/`, `.gitlab-ci.yml`, `azure-pipelines.yml`, `Jenkinsfile`) changes | `policy.allow_dependency_changes` (false), `policy.allow_workflow_changes` (false) |
| `existing_tests` | no existing test is deleted, renamed, skipped, or focused (such as `it.only`) | |
| `secrets` | no credential-like text in added lines | |
| `pull_request_text` | the title is one line of at most 200 characters, the body has at most 45,000 characters, and no text mentions `@everyone` or `@here` | |

A failed gate goes back to the agent like any other failed check. An exact secret value of this
machine, such as the GitHub token or a model API key, in an added line also starts the
[safety stop](#lifecycle-sync-holds-and-the-safety-stop) and fails the run.

## Review

After the agent confirms a fix, a fresh critic reviews it
([`models.critic`](configuration.md#models)). It has a shell in a container with no network, on a copy of the patched repository that is thrown
away afterwards, and no editor. It ends with `submit_review`: a verdict of `approve`,
`request_changes`, or `abandon`, a list of blockers, notes, and whether the change needs no test.

A blocker counts only once the controller confirms it. A blocker with a check command stands when
that command fails on a clean copy of the patched repository in a fresh container, or times out
for a `regression` or `issue_not_fixed` blocker; one whose command passes or cannot run is dropped.
A `scope_creep`, `policy_violation`, or `misleading_text` blocker needs no command: it stands when
the passage it quotes is in the patch, the policy file it names, or the PR text. Any other blocker
without a command is dropped. A change to source files without a test, outside documentation,
typing stubs, and build and CI files, gets a `weak_test` blocker unless the critic says it needs no
test.

- No confirmed blocker and no `abandon`: the round approves, even when the verdict was
  `request_changes`.
- Confirmed blockers in round 1: they go back to the agent on its own transcript, and its next
  confirmed fix gets a new critic, which also sees the round-1 blockers.
- `abandon`, or any confirmed blocker in round 2: the run ends `rejected`.

## Pull request text

After the critic approves, the controller builds the PR body without a model:

```text
<the agent's body, with "Fixes #N" first when it does not link the issue>

Testing (run by autocontribute):
- Tests: tests/test_x.py::test_y fails before this change and passes after it (3 runs).
- Full suite: no new failures (1,234 passed).

---

<policy.ai_disclosure, with {version} and {model} filled in>
```

The title is the agent's. A body that fixes only part of the issue says `Part of #N` and gets no
`Fixes` line; `Refs #N` and `Related to #N` also count as a link. The testing note states only what
the controller ran. The disclosure must show outside comments and code blocks; an unclosed comment
or code block in the body is closed first. The commit message is the agent's line, plus an
`Assisted-by:` or `Generated-by:` trailer when the repository's AI policy names one, and a
`Signed-off-by` trailer when you attested a DCO. An AI `Co-authored-by` trailer is refused, and
template checkboxes stay as the agent left them. Text that cannot be published (a body over 50,000
characters, a credential, `@everyone` or `@here`, or a hidden disclosure) ends the run `rejected`.

## Approval and publication

`autocontribute runs show RUN_ID` prints the review of a `ready_for_approval` run, `approve RUN_ID`
prints it again and asks you to confirm, and `publish RUN_ID` opens the PR. The review is rebuilt
from `state.sqlite3`, `contribution.patch`, and `validation.json`, not `report.md`: the issue and
comments, the full patch, the test environment and every test run with the end of its output, the
agent's summary as its claims, each review round, the AI-policy quotes, the commit message and
author, the PR title and body, the target repository and base commit, the publishing account, and a
fingerprint over all of it. `approve` refuses if any of it changed.
`approve RUN_ID --yes --fingerprint HEX` approves without a prompt, and only when HEX is the
fingerprint or at least its first 12 characters, so a script can approve only a review you read; it
exits 3 when the fingerprint no longer matches. `--source URL` records where you approved, such as an issue comment,
in the run's ledger and the approval, and repeating an approval that is already recorded succeeds
without writing anything. `--json` prints the outcome instead of the review.

`runs review RUN_ID --format github --output-dir DIR` writes the same review as `DIR/body.md`, at
most 60,000 characters, to post as a GitHub issue: the `/approve` line with the first 12 characters
of the fingerprint, a summary table, the exact PR title, body, and commit message, the patch, and
the test, review, and AI-policy evidence. A patch too long for the body continues in `part-1.md` up
to `part-5.md`, to post as comments. Evidence is shortened first, with a note; the PR text, commit
message, and patch never are, and the command exits 4 when they do not fit. Issue and PR text sits
in code blocks and code spans, so the issue mentions nobody and links nothing upstream.

Only the approving GitHub account can publish, within `publishing.approval_expires_hours` (72, at
most 168). `publish` refuses unless:

- the approval is current and matches the stored patch and test results;
- the repository is still in `github.repositories`, or its owner in `github.owners`;
- the repository's `environments` entry and the `sandbox`, `quality`, `policy`, and `publishing`
  settings match those the run was prepared with;
- the PR body shows the current `policy.ai_disclosure`, filled with the run's version and agent
  model;
- your account is within the [publication limits](configuration.md#publishing);
- the policy files and CLA/DCO evidence are unchanged, and the default branch has not changed any
  file the patch touches or any policy file since the prepared base commit (the PR commit stays on
  that base);
- the issue still passes every rule with no linked PR: edits, label changes, and comments are fine
  unless they close or lock it, assign it to someone else, or add a claim or a stop request.

`runs check RUN_ID` runs the safety-stop and approval checks and every step `publish` runs before
it writes anything to GitHub, and lists each result (`--json` for scripts); it exits 3 when one
fails and 5 during a safety stop. It publishes nothing, but as in discovery, a stop request it
reads from a maintainer starts a safety stop.

A failed recheck pushes nothing and leaves the run `approved`: retry `publish` after a limit clears,
or run `autocontribute runs cancel RUN_ID --reason "TEXT"` and [retry the issue](#run-states) (also
the way past an expired approval). Once the rechecks pass, the attempt uses that day's slot and
starts the cooldown even if a later step fails. The review shows where the branch goes: the
repository itself when your account owns it, otherwise your fork `<login>/<repository>`, which
`publish` creates or reuses. Push access alone does not count, because many projects want even
their collaborators to use forks. Set `publishing.head_strategy: fork` to always use the fork. A
branch in the repository itself may not change CI configuration, because its push workflows run
with the repository's secrets. `publish` commits as `identity.name` and `identity.email` (if empty,
your login and `<account ID>+<login>@users.noreply.github.com`) with the time publishing started as
the commit date, so a later `publish` rebuilds the identical commit if the checkout is gone, and
pushes the new branch `<publishing.branch_prefix>/issue-<number>-<run ID prefix>`, never
overwriting an existing one. If the base, issue, or policy files changed meanwhile, it deletes the
branch and the run ends `failed`; otherwise it opens a PR against the default branch. With
`publishing.draft: true` it opens a draft and then marks it ready for review if
`publishing.ready_for_review` is true.

If GitHub refuses the PR (for example, the repository accepts PRs only from collaborators or caps
open PRs), `publish` deletes the branch and the run ends `failed` with GitHub's message. If GitHub's
answer is lost, that run stays `submitting` and never sends a second request. Other runs still
publish; the stuck run counts toward the limits until `publish` finds its PR or `runs abandon` ends
it.

A `submitting` run that can never finish ends with `runs abandon RUN_ID --reason TEXT`, which then
releases its issue. For a run whose PR request went unanswered, it deletes the run's branch, so a
request GitHub has not processed yet cannot open a PR, checks that no PR exists, and ends the run
`failed`. Any other run, such as one stuck in an older version, must have neither its branch nor a
PR on GitHub. If GitHub has the PR, or that branch, `runs abandon` exits 4; resume the run with
`publish` instead.

`publish RUN_ID --yes --json` prints the outcome as JSON, and the exit code tells a script what to
do next: 0 the PR is open, 3 a limit (`limit`) or a failed recheck (`stale`) refused it, so wait
for the limit or cancel the run and prepare the issue again, 4 an interrupted publication needs
another `publish` after review, 5 a safety stop is active, and 1 anything else.

## Run states

```text
queued → discovering → candidate_selected → eligibility_checked → setting_up → implementing → validating → critiquing → ready_for_approval → approved → submitting → pr_open
```

The fix checks run inside `implementing`, at each submit; `validating` marks the hand-over of a
confirmed fix to the critic. Blockers from round 1 send the run from `critiquing` back to
`implementing`.

| Side exit | When | The issue afterwards |
| --- | --- | --- |
| `skipped` | no eligible issue, or triage accepted none; the day's budget is used up; a pinned issue fails a rule, has an active run, or is unchanged since an earlier run; no test environment could be built, now or in the last 7 days (reason `environment`); the agent submitted outcome `skip` | passed over until updated |
| `rejected` | the agent did not finish: its turns, budget, time, or context ran out, it stopped calling tools, or its submits ended without a confirmed fix; the critic abandoned the change, or blockers remained after round 2; the review did not finish; the PR text cannot be published | passed over until updated |
| `failed` | an error: a model provider failing after its retries, Docker failing, a GitHub error or rate limit that outlasts the run's waits, a secret value of this machine in the patch, the safety stop, or an interruption; also a run still being prepared when the next `run` starts, because its worker stopped | open to the next run |
| `cancelled` | `autocontribute runs cancel` on a `ready_for_approval` or `approved` run, or, at the start of each `run`, a `ready_for_approval` run nobody approved within `publishing.approval_expires_hours` plus 7 days | passed over until updated |

A run in any other state, `pr_open` included, keeps other runs off its issue. Lifecycle sync
records on a `pr_open` run whether its PR is open, merged, or closed. To retry an unchanged issue
(every rule, check, and review runs again; `--scheduled` runs cannot do this):

```bash
autocontribute run --issue owner/repo#123 --retry-unchanged --retry-actor NAME --retry-reason "TEXT"
```

## Lifecycle sync, holds, and the safety stop

`autocontribute lifecycle sync` reads every open PR this tool opened and re-checks runs left in
`submitting`. It runs first in every `run --scheduled` ([README](../README.md#run-it-locally)) and
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
- a patch the agent submits contains an exact secret value of this machine, such as the GitHub
  token or a model API key; GitHub reports the account suspended; or publishing cannot confirm
  what GitHub did;
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
| `state.sqlite3` | run records and audit events, each model call's usage and cost included; approvals; safety-stop state and history; holds; the reservations behind the daily limit and cooldown; cached test environments and their failures; cached AI-policy readings |
| `runs/<run-id>/manifest.json` | the full run record: issue and comments, eligibility evidence, models, test environment, proposal, gate results and the last review's summary, approval, PR URL |
| `runs/<run-id>/contribution.patch` | the exact diff that gets committed; written when the run becomes ready |
| `runs/<run-id>/validation.json` | the environment's recipe, the baseline, the last check of the agent's fix (gates, test runs with the end of their output), and every review round with its confirmed and dropped blockers; written once, for every run whose environment was accepted |
| `runs/<run-id>/<kind>-<n>.jsonl` | each model transcript, redacted: `triage-<n>` and `policy-<n>` from discovery, `setup-1`, `agent-1`, `critic-1`, and `critic-2`; the first line names the model, its effort, and the system prompt |
| `runs/<run-id>/report.md` | a readable summary; approval does not use it |
| `workspaces/<run-id>/` | the clone and its copies (the post-setup workspace, the copies the checks and the critic use), deleted when preparation ends; a later `run` retries a deletion that failed once the run has finished |

Docker keeps each environment image as `autocontribute-env/<owner>__<repo>:<key>`
([Test environments](environments.md#the-recipe-cache)).

Never delete or roll back `state.sqlite3`; the limits and the safety stop depend on it. Delete the
state directory only when a newer version says it cannot migrate it.

To keep state on a machine that has no disk between jobs, such as a GitHub Actions runner,
`state export --output FILE` writes one `.tar.gz` with a consistent copy of `state.sqlite3` and the
`runs/<run-id>/` files of runs that are not finished yet; workspaces are left out. Exporting the
same state twice gives the same bytes. `state import FILE` unpacks it beside `storage.path`,
checks the database and every audit chain, and only then makes it the state; it refuses to replace
existing state without `--force`. `--release-leases` drops the locks a crashed job left behind; use
it only when no job that wrote the archive can still be running.
