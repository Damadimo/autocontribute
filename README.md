# Autocontribute

Autocontribute finds open issues in public GitHub repositories you choose and prepares a small, tested fix for one of them. You read the exact diff, the test results and the pull request text, and nothing reaches the repository until you approve it.

> [!WARNING]
> This is an early alpha. Read every change before you approve it.

## How a run works

1. **Pick an issue.** Discovery searches your repositories for open issues with an invitation label such as `help wanted`, drops the ones that are assigned, claimed, stale or already have a pull request, and skips repositories whose policies ban AI-made contributions. A small model then reads the best candidates and turns down any that are unclear, already fixed, or waiting on a design decision.
2. **Build the test environment.** It reads the repository's CI files and manifests to work out how to install the project and run its tests, installs everything in Docker through a proxy that only reaches package registries, then runs the tests twice offline to record which pass before any change.
3. **Fix it.** An agent works in that container with no network: it reads the code, writes a test that fails because of the bug, makes the smallest change that fixes it, and runs the tests.
4. **Check it.** Each fix must pass size and path rules, the new test must fail on the original code and pass with the fix, and no test that passed before may fail. Problems go back to the agent.
5. **Review it.** A critic model, in a fresh session with read-only access, looks for a fix that misses the issue, breaks something, or claims more than it does. An objection counts only once it is confirmed, usually by running a command.
6. **Approve and publish.** You see the issue, the diff, the test results and the pull request text. After you approve, it checks the issue and the repository again and opens the pull request from your account, with a note that an AI agent drafted it.

Most runs end without a fix, because no issue qualified or the change did not pass. That is the normal outcome. [How it works](docs/how-it-works.md) has the details.

## Set up in GitHub Actions

This runs a daily attempt on GitHub's machines and asks for your approval in an issue.

1. Install the [GitHub CLI](https://cli.github.com/) and [uv](https://docs.astral.sh/uv/), then run:
   ```bash
   uvx --from git+https://github.com/Damadimo/autocontribute autocontribute init --actions
   ```
   It creates a private repository, `autocontribute-runner`, from the [template](template/).
2. Add two repository secrets there: `AUTOCONTRIBUTE_GITHUB_TOKEN`, a classic token with only the `public_repo` scope ([create one](https://github.com/settings/tokens/new?scopes=public_repo&description=autocontribute)), and `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`.
3. List the repositories you want to contribute to under `github.repositories` in the runner's `autocontribute.yml`, and push.

When a fix is ready, an issue in the runner repository shows it. Comment the `/approve` line it gives to open the pull request. [GitHub Actions](docs/actions.md) covers the workflows, costs of public and private runners, and how to fix a stuck run.

## Run it locally

You need Python 3.11+ with uv, Git, Docker with cgroup v2, the GitHub CLI (or a token in `AUTOCONTRIBUTE_GITHUB_TOKEN`), and an OpenAI or Anthropic API key. CI runs on Ubuntu; on macOS, Colima works if `storage.path` stays under your home directory. Windows is not supported.

```bash
uv tool install git+https://github.com/Damadimo/autocontribute
autocontribute init          # writes autocontribute.yml; list your repositories in it
gh auth login
export OPENAI_API_KEY=...    # or ANTHROPIC_API_KEY
autocontribute doctor        # checks everything; sends one small paid request per model
```

```bash
autocontribute discover                     # the best candidate now; no model calls, no writes
autocontribute run                          # prepare the best candidate, or skip
autocontribute run --issue owner/repo#123   # prepare one specific issue
autocontribute runs list                    # recent runs and their status
autocontribute approve RUN_ID               # read the exact diff, tests and text, then approve
autocontribute publish RUN_ID               # push one branch and open the pull request
```

Each run's evidence is in `.autocontribute/runs/RUN_ID/`: the patch, the test results, the model transcripts and a `report.md` summary. To run unattended, call `autocontribute run --scheduled` from cron; it never publishes.

## Safety

- **You approve every pull request.** The approval covers the exact diff and text and expires after 72 hours. Autocontribute never comments, reviews, merges or replies to maintainers; you answer reviews yourself.
- **Repository code runs only in Docker**, with no Linux capabilities and CPU, memory, process and time limits. Tests, the agent and the critic have no network. Your GitHub token and model keys never enter a container, and model calls run in a separate process that never sees the GitHub token.
- **It respects maintainers.** It skips repositories whose policy files ban AI-made contributions, that take pull requests only from collaborators, or that need a CLA or DCO until you attest with `policy attest`. It skips `good first issue` issues, and every pull request says an AI agent drafted it.
- **Limits.** At most 1 new pull request a day and 3 open at once, and none to a repository where one of its pull requests is open or was updated in the last 7 days.
- **It stops when maintainers push back.** A pull request closed unmerged or a request to stop holds that repository, and a revert holds all publishing. An unexpected push to one of its branches stops all work until you check it and run `safety resume`.

## Costs

Every model request reserves its worst-case cost first. By default a run may spend up to $10 and all runs together $25 in 24 hours (`budget` in [Configuration](docs/configuration.md#budget)). In testing, turning down a candidate issue cost about a tenth of a cent, and a complete fix for a sqlfluff issue cost $1.75 with OpenAI's models: 40 requests in a 39-minute run. Set a spending limit with your model provider too.

## Commands

| Command | What it does |
| --- | --- |
| `init` | Write a starter `autocontribute.yml`, or with `--actions` create a runner repository. |
| `doctor` | Check the config, credentials, GitHub access, Git, Docker and each model. |
| `discover` | Show the best candidate issue; `--explain` lists every issue with its score and blockers. |
| `run` | Prepare one fix or skip; `--issue owner/repo#N`, `--scheduled`, `--json`. |
| `approve RUN_ID` | Show the exact diff, tests and text, then approve; `--yes --fingerprint HEX` for scripts. |
| `publish RUN_ID` | Push one branch and open one pull request. |
| `runs list` / `show` / `review` / `check` / `cancel` / `abandon` | List runs, show one, render its review, check it could publish, cancel it, or end a stuck one. |
| `state export` / `import` | Copy the state to and from one archive. |
| `config validate` / `show` | Check the config, or print it with defaults filled in. |
| `lifecycle sync` | Check the pull requests it opened and hold or stop work on adverse events. |
| `safety status` / `stop` / `resume` / `release` | Show or change the safety stop and the holds. |
| `policy inspect` / `attest` | Show a repository's CLA or DCO requirements and record your attestation. |
| `actions ...` | The commands the runner's workflows call. |

## Documentation

- [How it works](docs/how-it-works.md): each step, the checks and the run states.
- [Test environments](docs/environments.md): how a repository's tests are set up and how to override it.
- [GitHub Actions](docs/actions.md): the runner repository and its workflows.
- [Configuration](docs/configuration.md): every key and its default.
- [Security](SECURITY.md) and [Contributing](CONTRIBUTING.md).

## License

[MIT](LICENSE)
