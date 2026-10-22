# Autocontribute

Autocontribute finds open issues in GitHub repositories you choose, prepares a small fix in an isolated workspace, runs the repository's checks in a Docker sandbox with no network, has a critic model review the diff in a fresh context, and opens a pull request only after you approve the exact diff.

> [!WARNING]
> This is an early alpha. Check every artifact before you approve it.

## How it works

1. **Discover:** find open issues that carry your labels in your repositories, using only GitHub reads.
2. **Filter:** fixed rules drop assigned, claimed, stale, or security-related issues, issues that already have an open PR or score below 85, and repositories whose policies appear to refuse AI contributions.
3. **Plan:** the scout model reads the issue and the repository's contribution guidance, then plans a small change or skips.
4. **Edit:** the builder model writes exact edits in a local checkout.
5. **Check:** your validation commands run in Docker with no network. A bug fix also needs a reproduction that fails before the change and passes after it.
6. **Review:** a critic model reviews the diff, check output, and PR text in a fresh context, and hard gates on size, paths, secrets, and scores must all pass.
7. **Approve:** you read the exact diff, check output, and PR text, then approve.
8. **Publish:** Autocontribute rechecks that the issue, policy files, and base commit are unchanged, then opens a draft PR from your fork.

[docs/how-it-works.md](docs/how-it-works.md) covers each step, the hard gates, and the run states.

## Requirements

You need Python 3.11+ and [uv](https://docs.astral.sh/uv/), Git, Docker with cgroup v2 (rootless or rootful), the [GitHub CLI](https://cli.github.com/) or a GitHub token, and an OpenAI API key or an OpenAI-compatible endpoint that supports strict JSON schema output. CI runs on Ubuntu only; macOS is untested, and Windows is not supported.

## Install

```bash
uv tool install git+https://github.com/Damadimo/autocontribute
```

This installs the `autocontribute` command. There is no PyPI release yet. To work from a clone instead, run `uv sync` in it and put `uv run` before each command.

## Set up

1. Run `autocontribute init`. It writes `autocontribute.yml`, which commands read from the current directory unless you pass `--config PATH`.
2. Edit the file. Replace `your-org/your-repo` in `github.repositories` and `validation.required_commands` with a public repository you own or one that welcomes AI-assisted PRs, lower `github.min_stars` (1000) if it has fewer stars, and replace the `example.invalid` image in `sandbox.image`. `config validate`, `doctor`, `discover`, and `run` refuse to start while a placeholder remains.
3. Build a sandbox image that already contains every tool and dependency your validation commands need, because checks run offline. Pin it by digest and `docker pull` it: see [docs/sandbox-image.md](docs/sandbox-image.md).
4. Run `gh auth login` (or set `github.auth: token` and export `AUTOCONTRIBUTE_GITHUB_TOKEN`), export `OPENAI_API_KEY`, then run `autocontribute doctor` and fix each failed check. `doctor` sends one small paid model request per distinct model profile (two with the defaults), each capped at 1,024 output tokens.

## Minimal configuration

```yaml
github:
  repositories: [your-name/your-project]
  min_stars: 0                     # the default, 1000, also skips repositories you list
validation:
  required_commands:               # run in the sandbox after every change
    your-name/your-project:
      - python -m pytest -q
sandbox:                           # your image, pinned by digest
  image: ghcr.io/your-name/autocontribute-sandbox@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
models:                            # your provider's USD prices per million tokens
  scout: &priced
    pricing:
      input_usd_per_million_tokens: 10
      output_usd_per_million_tokens: 100
  builder: *priced
  critic: *priced
budget:
  max_model_cost_usd_per_run: 50   # needs pricing on all three roles
```

This is a complete file for one repository: replace the names and the image digest with your own. Every key you leave out keeps its default, listed in [docs/configuration.md](docs/configuration.md). Discovery only considers issues labeled `help wanted` or `good first issue`, and needs a CONTRIBUTING file in the repository or in the owner's `.github` repository.

## Use it

```bash
autocontribute discover                     # best candidate now; no model calls, no GitHub writes
autocontribute run                          # prepare the best candidate
autocontribute run --issue owner/repo#123   # or prepare one specific issue
autocontribute runs list                    # recent runs and their status
autocontribute runs show RUN_ID             # the evidence for one run
autocontribute approve RUN_ID               # read the exact diff, checks, and PR text, then approve
autocontribute publish RUN_ID               # fork, push one branch, open the PR
```

Many runs end `skipped` or `rejected`: no issue passed the rules, the plan found nothing safe to change, a check failed, or the critic objected. These are normal outcomes; `failed` means an error stopped the run. Each run's evidence is in `.autocontribute/runs/RUN_ID/` next to your config file (set by `storage.path`): the patch, every command's output, the model-call records, and a `report.md` summary.

`approve` shows the full issue discussion, patch, check output, and commit and PR text; the approval covers exactly that and expires after 24 hours. To drop a run that is ready for approval or approved, run `runs cancel RUN_ID --reason TEXT`; this releases its issue. An issue whose last run ended `skipped`, `rejected`, or `cancelled` is not retried until it changes; to retry it anyway, add `--retry-unchanged --retry-actor NAME --retry-reason TEXT` to `run --issue`.

## Safety defaults

- **Review required.** Nothing reaches GitHub until you approve the exact diff, and `publish` asks again before it writes. It never comments, reviews, reacts, merges, or opens issues.
- **Isolated checks.** Repository commands run in Docker with no network, no credentials, no Linux capabilities, and CPU, memory, process, and time limits. Model calls run in a separate process that never sees your GitHub token.
- **Disclosure.** Every PR body includes the `policy.ai_disclosure` text, and PRs open as drafts.
- **Limits.** At most 1 new PR per UTC day and 2 open PRs, and no new PR to a repository where your account has an open PR or a closed one updated in the last 7 days. Every PR your account authored counts, including ones you opened yourself.
- **Repository policies.** It skips repositories whose policy files appear to prohibit AI-assisted or automated contributions, and repositories that require a CLA or DCO until you attest with `policy attest` ([details](docs/configuration.md#legal-attestations)).
- **Stops.** `lifecycle sync` checks the PRs Autocontribute opened and stops all work after a maintainer requests changes or asks you to stop, CI fails, the PR branch changes, or a PR is closed unmerged or reverted; `publish` syncs first. A maintainer's stop request on a candidate issue, repeated GitHub abuse-limit responses, or `safety stop --actor NAME --reason TEXT` also stop all work. `safety status` shows why, and `safety resume` restarts work once you pass it the trigger hash from `safety status`.

## Costs

Each run stops at the first `budget` limit it reaches: 9 model calls, 3,000,000 input tokens, 240,000 output tokens, or 3,600 seconds of model time. A dollar cap applies only when all three model roles have `pricing` and `budget.max_model_cost_usd_per_run` is set; `autocontribute init` sets $50 per run at $10 input and $100 output per million tokens. Replace those prices with your provider's (there is no built-in price table), and set a spending limit with your provider too. A run pays for the scout and builder calls before your validation commands first run, so run `doctor` first.

## Scheduling

`autocontribute run --scheduled` makes one unattended attempt. It runs `lifecycle sync` first, picks the issue itself, refuses `--issue` and `--retry-unchanged`, and never publishes. An attempt that starts while another is running is refused. This crontab line (`crontab -e`) runs it at 09:17 and 21:17 in the machine's time zone:

```cron
17 9,21 * * * . "$HOME/.autocontribute.env" && autocontribute run --scheduled --config /path/to/autocontribute.yml >>/path/to/autocontribute.log 2>&1
```

cron starts with an almost empty environment. In `~/.autocontribute.env` (`chmod 600`), export a `PATH` on which `autocontribute`, `docker`, `git`, and `gh` resolve, and `OPENAI_API_KEY` (plus `AUTOCONTRIBUTE_GITHUB_TOKEN` with `github.auth: token`). With the starter config, this schedule can spend up to $100 a day on models.

A GitHub Actions runner is planned.

## Command reference

| Command | What it does |
| --- | --- |
| `init` | Write a starter `autocontribute.yml` (`--path`, `--force`). |
| `doctor` | Check config, credentials, GitHub access, Git, Docker, and the sandbox image; sends small paid model probes. |
| `discover` | Show the best current candidate issue without cloning, model calls, or GitHub writes. |
| `run` | Prepare one contribution or skip; `--issue owner/repo#N` pins an issue, `--scheduled` makes an [unattended attempt](#scheduling). |
| `approve RUN_ID` | Show the exact diff, check output, and PR text, then record your approval. |
| `publish RUN_ID` | Create or reuse your fork, push one branch, and open one pull request. |
| `version` | Print the installed version. |
| `runs list` | List recent runs and their status. |
| `runs show RUN_ID` | Show the evidence for one run. |
| `runs cancel RUN_ID --reason TEXT` | Cancel a run that is ready for approval or approved, and release its issue. |
| `config validate` | Check the config file and print a summary. |
| `config show` | Print the config with defaults filled in; it shows secret names, never values. |
| `lifecycle sync` | Check the PRs Autocontribute opened and stop all work on an adverse signal. |
| `safety status` | Show whether work is stopped, why, and the trigger hash. |
| `safety stop` | Stop all preparation and publication (`--actor`, `--reason`). |
| `safety resume` | Resume after you resolve the cause (`--actor`, `--reason`, `--expected-trigger-hash`). |
| `policy inspect REPO` | Link a repository's policy files and show the CLA or DCO requirements it detects. |
| `policy attest REPO` | After you confirm, print a `policy.legal_attestations` entry (`--cla-completed`, `--authorize-dco-signoff`). |

## Documentation

- [How it works](docs/how-it-works.md): the pipeline, hard gates, and run states.
- [Configuration](docs/configuration.md): every config key and its default.
- [Sandbox image](docs/sandbox-image.md): build and pin the image your checks run in.
- [Security policy](SECURITY.md): reporting vulnerabilities and safe use.
- [Contributing](CONTRIBUTING.md): working on Autocontribute itself.

## Development

Install the dev tools in a clone and run the four checks CI runs. Read [CONTRIBUTING.md](CONTRIBUTING.md) before you open a pull request.

```bash
uv sync --extra dev
uv run ruff check . && uv run ruff format --check . && uv run mypy src && uv run pytest
```

## License

[MIT](LICENSE)
