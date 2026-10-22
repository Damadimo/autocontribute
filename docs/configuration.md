# Configuration

Autocontribute reads one YAML file: `autocontribute.yml` in the current directory, or the file you pass with `--config`. `autocontribute init` writes a starter file, and the [README](../README.md#minimal-configuration) shows a minimal one. A key you leave out keeps the default listed here; an unknown key is an error. `autocontribute config validate` checks the file, and `autocontribute config show` prints it with every default filled in.

Secrets never go in this file. It holds only the names of the environment variables that contain them: `github.token_env` and each `models.<role>.api_key_env`.

## identity

| Key | Default | Meaning |
| --- | --- | --- |
| `name` | empty | Git author and committer name. Empty uses your GitHub login. |
| `email` | empty | Git author and committer email. Empty uses `<your-login>@users.noreply.github.com`. |

A DCO attestation needs both keys set, because the `Signed-off-by` trailer must match them.

## github

| Key | Default | Meaning |
| --- | --- | --- |
| `auth` | `gh` | `gh` uses the token in `token_env` if it is set, otherwise `gh auth token`. `token` requires the token in `token_env`. |
| `token_env` | `AUTOCONTRIBUTE_GITHUB_TOKEN` | Environment variable that holds a GitHub token. |
| `api_url` | `https://api.github.com` | GitHub API URL. Must use HTTPS. |
| `repositories` | `[]` | Repositories to search, as `owner/name`. Each needs a `validation.required_commands` entry. |
| `owners` | `[]` | Users or organizations whose most recently pushed public repositories are searched too. If the chosen issue's repository has no `validation.required_commands` entry, the run stops before any model call. |
| `include_labels` | `help wanted`, `bug`, `confirmed`, `accepted`, `status: help wanted`, `contributions welcome`, `pr welcome` | Discovery searches only open issues that carry one of these labels. Labels match regardless of case, hyphens, and underscores, so `Help-Wanted` matches `help wanted`. Discovery also searches for `status: help wanted`, `sprintable`, `E-easy`, `contributions welcome`, `PR welcome`, `accepted`, and `confirmed` when a repository defines them, even if you change this list. |
| `exclude_labels` | `security`, `breaking change`, `needs design`, `discussion`, `blocked`, `good first issue`, `first-timers-only` | Skip issues that carry any of these labels. Maintainers keep `good first issue` and `first-timers-only` issues for people making their first contribution. |
| `labels` | `{}` | Labels for one repository, as `owner/name: {include: [...], exclude: [...]}`. A list you set replaces `include_labels` or `exclude_labels` for that repository, and a set `include` list also turns off the extra labels above. |
| `min_stars` | `0` | Skip repositories with fewer stars, including ones listed in `repositories`. |
| `repository_limit_per_owner` | `8` | Repositories searched for each entry in `owners` (1–30). |
| `issue_limit_per_repository` | `10` | Issues read in full per repository, newest first (1–50). Discovery skips search results that are assigned, carry an excluded label, or fail another check that needs only the issue itself, and reads at most 300 search results per repository. |
| `require_unassigned` | `true` | Skip assigned issues. `false`, or `policy.allow_assigned_issues: true`, allows them. |
| `max_issue_age_days` | `365` | Skip issues not updated for this many days (1–3650). |
| `max_repository_inactivity_days` | `180` | Skip repositories with no push for this many days (1–3650). |

Private, archived, and disabled repositories are always skipped.

## models

The scout reads the issue and the repository, then plans a change or decides to skip; the builder writes the edits and any repair. The critic reviews the finished diff, check output, and PR text in a fresh context and can reject the change.

Each role (`models.scout`, `models.builder`, `models.critic`) takes these keys:

| Key | Default | Meaning |
| --- | --- | --- |
| `provider` | `openai` | `openai` calls the OpenAI Responses API. `openai_compatible` calls a Chat Completions endpoint at `base_url` that supports strict JSON schema output. |
| `model` | `gpt-5.6` | Model name sent to the provider. |
| `api_key_env` | `OPENAI_API_KEY` | Environment variable that holds the API key. |
| `base_url` | none | HTTPS endpoint. Required for `openai_compatible`. |
| `reasoning_effort` | `high` | `none`, `minimal`, `low`, `medium`, `high`, `xhigh`, or `max`. |
| `reasoning_mode` | `standard`; critic `pro` | `standard`, `pro`, or `null` to send no mode. `openai_compatible` does not accept `pro`. |
| `max_input_tokens` | `500000` | Input limit per call (1,000–2,000,000). |
| `max_output_tokens` | `40000` | Output limit per call (1,000–128,000). |
| `timeout_seconds` | `900` | Time limit per call (10–3600). |
| `pricing` | none | Your prices in USD per million tokens, used for the dollar cap. Set it on all three roles or on none. |
| `expected_response_model` | none | Exact model ID the provider must report; any other ID is refused. |

`pricing` takes `input_usd_per_million_tokens` and `output_usd_per_million_tokens`, both required, plus `cached_input_usd_per_million_tokens` and `cache_write_usd_per_million_tokens`, which default to the input price. There is no built-in price table: use your provider's current prices.

## sandbox

| Key | Default | Meaning |
| --- | --- | --- |
| `backend` | `docker` | `docker`, or `local` to run repository commands on your machine with no isolation. |
| `image` | a pinned `python:3.12-bookworm` | Image for every check, pinned as `name@sha256:<64 hex digits>`. The default has no pytest or project dependencies, so build your own ([sandbox-image.md](sandbox-image.md)). |
| `command_timeout_seconds` | `900` | Time limit per command (10–3600). |
| `memory` | `4g` | Container memory limit, in Docker syntax. Swap is disabled. |
| `cpus` | `2.0` | CPU limit (above 0, at most 16). |
| `pids_limit` | `256` | Process limit (32–4096). |
| `allow_unsafe_local` | `false` | Must be `true` for `backend: local`. Repository code can then read and change your machine. |
| `max_commands` | `8` | Commands per run, counting model-suggested checks, the bug reproduction, and reruns after a repair (1–30). Each repository's `validation.required_commands` must fit. |

There is no network setting: the `docker` backend always runs checks with no network.

## validation

| Key | Default | Meaning |
| --- | --- | --- |
| `required_commands` | `{}` | Map of `owner/name` to a list of shell commands. They run in the sandbox after every change and must all pass. The model can add checks but cannot remove these. |

[sandbox-image.md](sandbox-image.md) explains how commands run and what the image must contain.

## policy

| Key | Default | Meaning |
| --- | --- | --- |
| `require_maintainer_signal` | `true` | Issues must carry one of the `github.include_labels` (or `github.labels`) labels, or have a maintainer comment that invites a pull request. |
| `require_contribution_guidelines` | `true` | The repository, or the owner's `.github` repository, must have a CONTRIBUTING file. |
| `allow_assigned_issues` | `false` | `true` allows assigned issues. |
| `allow_security_issues` | `false` | `true` allows issues that look security-related. |
| `allow_dependency_changes` | `false` | `true` allows changes to dependency manifests and lock files, such as `pyproject.toml` or `package-lock.json`. |
| `allow_workflow_changes` | `false` | `true` allows changes to CI configuration. Also remove those paths from `quality.forbidden_paths`. |
| `ai_disclosure` | `This contribution was prepared autonomously by an AI agent. Its validation evidence comes from Autocontribute's configured automated checks; no human review is implied.` | Text added to every PR body. It cannot be empty. |
| `legal_attestations` | `{}` | See [Legal attestations](#legal-attestations). |

## quality

| Key | Default | Meaning |
| --- | --- | --- |
| `min_readiness_score` | `90` | Lowest weighted critic score, out of 100, that passes. |
| `min_dimension_score` | `80` | Lowest critic score allowed in any one dimension, out of 100. |
| `max_files_changed` | `8` | Most files a patch may change (1–100). |
| `max_changed_lines` | `400` | Most added plus deleted lines in a patch (1–10000). |
| `max_context_files` | `20` | Most repository files loaded as model context (1–100). |
| `max_context_characters` | `160000` | Most characters across those files (10,000–2,000,000). |
| `require_regression_evidence_for_bugfix` | `true` | A bug fix needs a reproduction command that fails before the change and passes after it. |
| `forbidden_paths` | `.github/workflows/**`, `.github/actions/**`, `**/*.pem`, `**/*.key`, `**/generated/**`, `vendor/**` | Glob patterns. A patch that touches a match is rejected. |

## publishing

| Key | Default | Meaning |
| --- | --- | --- |
| `approval_expires_hours` | `24` | Hours an approval stays valid (1–168). |
| `branch_prefix` | `autocontribute` | Branches are named `<prefix>/issue-<number>-<first 8 characters of the run ID>`. |
| `draft` | `true` | Open PRs as drafts. |
| `ready_for_review` | `false` | Mark the draft ready for review right after opening it. Needs `draft: true`. |
| `max_new_pull_requests_per_day` | `1` | Refuse to publish once your GitHub account has opened this many PRs in the current UTC day (1–5). |
| `max_open_pull_requests` | `2` | Refuse to publish while your account has this many open PRs (1–20). |
| `repository_cooldown_days` | `7` | Refuse a repository where your account has an open PR, or a closed one updated in this many days (0–365). |

The three limits count every PR your GitHub account authored, including ones you opened yourself.

## budget

Each limit applies to one run, and the run stops when it reaches a model limit.

| Key | Default | Meaning |
| --- | --- | --- |
| `max_model_calls_per_run` | `9` | Model calls, retries included (3–30). |
| `max_candidates_per_run` | `25` | Discovery stops after this many eligible issues and picks the highest score (1–200). |
| `max_input_tokens_per_run` | `3000000` | Input tokens (1,000–20,000,000). |
| `max_output_tokens_per_run` | `240000` | Output tokens (1,000–4,000,000). |
| `max_model_seconds_per_run` | `3600` | Seconds of model time (10–86,400). |
| `max_model_cost_usd_per_run` | none | Dollar cap, computed from `pricing`, which every model role then needs. |

## storage

| Key | Default | Meaning |
| --- | --- | --- |
| `path` | `.autocontribute` | Directory for run state and evidence. A relative path is resolved from the config file's directory. |

[How it works](how-it-works.md#where-evidence-is-written) lists what it holds. Deleting it erases the history that retries, publication limits, and `safety stop` rely on.

## Legal attestations

`policy.legal_attestations` is empty by default. Discovery skips a repository whose policy files mention a CLA or DCO until this map holds an entry for it that matches those files. Do not write entries by hand: run `autocontribute policy inspect owner/repo` and read every policy file it links, then run `autocontribute policy attest owner/repo` with `--cla-completed` (your account already completed the CLA, and no per-contribution signature remains), `--authorize-dco-signoff` (adds a `Signed-off-by` trailer for `identity.name` and `identity.email`), or both, as the inspection requires. Paste the entry it prints under `policy.legal_attestations`. The entry stops matching when the repository's policy files or detected requirements change, and publishing requires the same GitHub account that made the attestation.
