# Configuration

Autocontribute reads one YAML file: `autocontribute.yml` in the current directory, or the file you pass with `--config`. `autocontribute init` writes a starter file, and the [README](../README.md#minimal-configuration) shows a minimal one. A key you leave out keeps the default listed here; an unknown key is an error. `autocontribute config validate` checks the file, and `autocontribute config show` prints it with every default filled in.

Secrets never go in this file. Model API keys come from `OPENAI_API_KEY` and `ANTHROPIC_API_KEY`, and the GitHub token from the variable `github.token_env` names, or from `gh`. The file loads without any key; `run` and `doctor` need one.

## identity

| Key | Default | Meaning |
| --- | --- | --- |
| `name` | empty | Git author and committer name. Empty uses your GitHub login. |
| `email` | empty | Git author and committer email. Empty uses your GitHub noreply address, `<account ID>+<login>@users.noreply.github.com`. |

A DCO attestation needs both keys set, because the `Signed-off-by` trailer must match them.

## github

| Key | Default | Meaning |
| --- | --- | --- |
| `auth` | `gh` | `gh` uses the token in `token_env` if it is set, otherwise `gh auth token`. `token` requires the token in `token_env`. |
| `token_env` | `AUTOCONTRIBUTE_GITHUB_TOKEN` | Environment variable that holds a GitHub token. |
| `api_url` | `https://api.github.com` | GitHub API URL. Must use HTTPS. |
| `repositories` | `[]` | Repositories to search, as `owner/name`. |
| `owners` | `[]` | Users or organizations whose most recently pushed public repositories are searched too. |
| `include_labels` | `help wanted`, `bug`, `confirmed`, `accepted`, `status: help wanted`, `contributions welcome`, `pr welcome` | Discovery searches only open issues that carry one of these labels. Labels match regardless of case, hyphens, underscores, emoji and a category prefix, so `Help-Wanted`, `Help wanted 🙏` and `E-help-wanted` all match `help wanted`, and `kind/bug` matches `bug`. Discovery also searches for `status: help wanted`, `sprintable`, `E-easy`, `contributions welcome`, `PR welcome`, `accepted`, and `confirmed` when a repository defines them, even if you change this list. |
| `exclude_labels` | `security`, `breaking change`, `needs-*`, `question`, `discussion`, `design`, `rfc`, `proposal`, `wontfix`, `duplicate`, `invalid`, `stale`, `blocked`, `good first issue`, `first-timers-only`, `beginner` | Skip issues that carry any of these labels. A `*` matches any text, so `needs-*` covers `Needs Triage` and `needs-decision`. Maintainers keep `good first issue`, `first-timers-only`, and `beginner` issues for people making their first contribution. |
| `labels` | `{}` | Labels for one repository, as `owner/name: {include: [...], exclude: [...]}`. A list you set replaces `include_labels` or `exclude_labels` for that repository, and a set `include` list also turns off the extra labels above. |
| `min_stars` | `0` | Skip repositories with fewer stars, including ones listed in `repositories`. |
| `repository_limit_per_owner` | `8` | Repositories searched for each entry in `owners` (1–30). |
| `issue_limit_per_repository` | `10` | Issues read in full per repository, newest first (1–50). Discovery skips search results that are assigned, carry an excluded label, or fail another check that needs only the issue itself, and reads at most 300 search results per repository. |
| `require_unassigned` | `true` | Skip assigned issues. `false`, or `policy.allow_assigned_issues: true`, allows them. |
| `max_issue_age_days` | `365` | Skip issues not updated for this many days (1–3650). |
| `max_repository_inactivity_days` | `180` | Skip repositories with no push for this many days (1–3650). |

Private, archived, and disabled repositories are always skipped.

## models

The agent fixes the issue and writes its test. The critic reviews each fix that passed the checks, in a fresh context, and can send blockers back or reject the change. The setup model writes a recipe for a test environment when detection fails, and the triage model judges candidate issues and reads AI policies.

| Key | Default | Meaning |
| --- | --- | --- |
| `agent` | `auto` | Model id from the table below, or `auto`: an Anthropic model when `ANTHROPIC_API_KEY` is set, otherwise an OpenAI model when `OPENAI_API_KEY` is set. |
| `critic` | `auto` | `auto` uses the agent's model, or the other provider's agent model when both keys are set, so the review does not come from the model that wrote the change. |
| `setup` | `auto` | `auto` uses the provider's middle tier. |
| `triage` | `auto` | `auto` uses the provider's cheapest tier. |
| `effort` | `{}` | Reasoning effort per role, such as `{agent: xhigh}`: `low`, `medium`, `high`, `xhigh`, or `max` (not on `gpt-5.5`). Defaults: agent and critic `high`, setup `medium`, triage `low`. |

`auto` resolves when `run` or `doctor` starts, and each run records the models it used. A model you name needs its provider's key.

| Model | Provider | `auto` role | USD per million tokens: input / cached input / cache write / output |
| --- | --- | --- | --- |
| `gpt-5.6-sol` | OpenAI | agent, critic | 5.00 / 0.50 / 6.25 / 30.00; above 272,000 input tokens 10.00 / 1.00 / 12.50 / 45.00 |
| `gpt-5.6-terra` | OpenAI | setup | 2.00 / 0.20 / 2.50 / 12.00; above 272,000 input tokens 4.00 / 0.40 / 5.00 / 18.00 |
| `gpt-5.6-luna` | OpenAI | triage | 0.20 / 0.02 / 0.25 / 1.20; above 272,000 input tokens 0.40 / 0.04 / 0.50 / 1.80 |
| `gpt-5.5` | OpenAI | | 5.00 / 0.50 / 5.00 / 30.00; above 272,000 input tokens 10.00 / 1.00 / 10.00 / 45.00 |
| `claude-opus-5-5` | Anthropic | agent, critic | 4.00 / 0.20 / 5.00 / 20.00 |
| `claude-sonnet-5-5` | Anthropic | setup | 2.00 / 0.20 / 2.50 / 10.00 |
| `claude-haiku-5-5` | Anthropic | triage | 0.10 / 0.01 / 0.125 / 0.50; above 100,000 input tokens 0.50 / 0.05 / 0.625 / 2.50 |

Costs use these list prices, so a promotional price lowers what you pay but not what the budget counts.

## environments

Autocontribute detects how to install each repository and run its tests. Where it guesses wrong, set the fields it should use, per repository; detection fills the rest. An entry also lets a repository whose environment failed in the last 7 days be tried again.

```yaml
environments:
  owner/repo:
    image: python:3.12-bookworm        # base image, by tag
    setup: ["pip install -e .[test]"]  # runs with network, through an allowlisting proxy
    test: python -m pytest -q          # runs offline
    allow_hosts: ["files.example.org"] # hosts the proxy allows beyond the package registries
```

| Key | Default | Meaning |
| --- | --- | --- |
| `image` | detected | Base image. Setup records the digest the tag resolved to. |
| `setup` | detected | Commands that install the project and its test dependencies. `[]` installs nothing. |
| `test` | detected | Command that runs the test suite without network. A pytest, unittest, jest, vitest, mocha, `go test` or `cargo test` command gets a report option added, so results count per test. |
| `allow_hosts` | `[]` | Host names, not URLs or addresses. |

## sandbox

| Key | Default | Meaning |
| --- | --- | --- |
| `command_timeout_seconds` | `900` | Time limit per test run and setup step (10–3600). Agent commands get at most 300 seconds. |
| `memory` | `6g` | Container memory limit, in Docker syntax. Swap is disabled. |
| `cpus` | `2.0` | CPU limit (above 0, at most 16). |
| `pids_limit` | `1024` | Process limit (32–4096). |

Repository code runs only in Docker. Tests and the agent's commands run with no network; setup reaches the package registries through a proxy that refuses every other host.

## policy

| Key | Default | Meaning |
| --- | --- | --- |
| `require_maintainer_signal` | `true` | Issues must carry one of the `github.include_labels` (or `github.labels`) labels, or have a maintainer comment that invites a pull request. |
| `require_contribution_guidelines` | `true` | The repository, or the owner's `.github` repository, must have a contribution guide (`CONTRIBUTING`, `CONTRIBUTE`, `HOW_TO_CONTRIBUTE`, ...) in its root, `.github/`, or `docs/`. |
| `allow_assigned_issues` | `false` | `true` allows assigned issues. |
| `allow_security_issues` | `false` | `true` allows issues that look security-related. |
| `allow_dependency_changes` | `false` | `true` allows changes to dependency manifests and lock files, such as `pyproject.toml` or `package-lock.json`. |
| `allow_workflow_changes` | `false` | `true` allows changes to CI configuration. Also remove those paths from `quality.forbidden_paths`. |
| `ai_disclosure` | `AI assistance: an AI coding agent (autocontribute {version}, {model}) drafted this change and its test and ran the tests listed above in a sandbox. I reviewed the diff and the test results before opening this PR and will handle the review.` | Text added to every PR body, after a testing note. `{version}` and `{model}` are filled in when the change is prepared, and the approval binds the result. It cannot be empty. |
| `legal_attestations` | `{}` | See [Legal attestations](#legal-attestations). |
| `allow_conditional_ai_policy` | `[]` | Repositories, as `owner/name`, to contribute to even though their AI policy asks for pull request text written by a person. Discovery skips such repositories unless they are listed; list one only if you will write that text yourself. |

## quality

| Key | Default | Meaning |
| --- | --- | --- |
| `max_files_changed` | `8` | Most files a patch may change, tests included (1–100). |
| `max_changed_lines` | `400` | Most added plus deleted lines in a patch (1–10000). |
| `max_source_files` | `3` | Most files other than tests a patch may change (1–100). |
| `max_source_lines` | `150` | Most added plus deleted lines outside tests (1–10000). |
| `forbidden_paths` | `.github/**` (with `.github/workflows/**` and `.github/actions/**`), `**/*.pem`, `**/*.key`, `**/generated/**`, `vendor/**`, commit and install hooks (`**/.husky/**`, `**/.githooks/**`, `**/.pre-commit-config.yaml`, `**/lefthook.yml`), build scripts (`**/build.rs`, `**/binding.gyp`, `**/.cargo/config`, `**/.cargo/config.toml`) | Glob patterns. A patch that touches a match goes back to the agent. |

A bug fix needs a test that fails before the change and passes after it; a change to source files with no test passes only when the critic finds no test necessary, as for documentation or typing.

## publishing

| Key | Default | Meaning |
| --- | --- | --- |
| `login` | empty | GitHub account that publishes. Empty uses the account that owns the GitHub token. When set, preparing and showing a review does not need that account's token, and `approve` and `publish` refuse a token that belongs to a different account. |
| `head_strategy` | `auto` | `auto` pushes the branch to the repository itself when the publishing account owns it, and to your fork otherwise, even where the account can push. `fork` always uses your fork. |
| `approval_expires_hours` | `72` | Hours an approval stays valid (1–168). |
| `branch_prefix` | `autocontribute` | Branches are named `<prefix>/issue-<number>-<first 8 characters of the run ID>`. |
| `draft` | `false` | Open PRs as drafts. |
| `ready_for_review` | `true` | Mark a draft ready for review right after opening it. Has no effect when `draft` is `false`, because the PR is then ready from the start. |
| `max_new_pull_requests_per_day` | `1` | Refuse to publish once Autocontribute has opened this many PRs in the current UTC day (1–5). |
| `max_open_pull_requests` | `3` | Refuse to publish while this many Autocontribute PRs are open or still being published (1–20). |
| `repository_cooldown_days` | `7` | Refuse a repository where an Autocontribute PR is open, or one was updated in this many days (0–365). |

The limits count only PRs Autocontribute opened, recognized by their `<branch_prefix>/issue-` branch names; PRs you open yourself never count.

## budget

| Key | Default | Meaning |
| --- | --- | --- |
| `max_cost_usd_per_run` | `10` | Dollar cap for one run's model calls (above 0, at most 1000). Every request reserves its worst case first. |
| `max_cost_usd_per_day` | `25` | Dollar cap over the last 24 hours (above 0, at most 10000). A run starts only while a quarter of `max_cost_usd_per_run` is left; otherwise it is skipped with reason `daily budget`. |
| `max_model_calls_per_run` | `200` | Model requests per run, retries included (10–1000). |
| `max_run_minutes` | `90` | Time for one run, model and tool time together (5–360). |
| `max_candidates_per_run` | `25` | Discovery stops after this many eligible issues and picks the highest score (1–200). |

The per-run cap is split between phases: setup at most 15%, triage 10% and the agent 55%, which leaves the critic at least 20%.

## storage

| Key | Default | Meaning |
| --- | --- | --- |
| `path` | `.autocontribute` | Directory for run state and evidence. A relative path is resolved from the config file's directory. With Colima on macOS, keep it under your home directory: Colima shares only `$HOME` with containers. |

[How it works](how-it-works.md#where-evidence-is-written) lists what it holds. Deleting it erases the history that retries, publication limits, and `safety stop` rely on.

## Legal attestations

`policy.legal_attestations` is empty by default. Discovery skips a repository whose policy files mention a CLA or DCO until this map holds an entry for it that matches those files. Do not write entries by hand: run `autocontribute policy inspect owner/repo` and read every policy file it links, then run `autocontribute policy attest owner/repo` with `--cla-completed` (your account already completed the CLA, and no per-contribution signature remains), `--authorize-dco-signoff` (adds a `Signed-off-by` trailer for `identity.name` and `identity.email`), or both, as the inspection requires. Paste the entry it prints under `policy.legal_attestations`. The entry stops matching when a CLA or DCO file changes, when a section of another policy file that names a CLA or DCO changes, or when the detected requirements change; other policy edits leave it valid. Publishing requires the same GitHub account that made the attestation.
