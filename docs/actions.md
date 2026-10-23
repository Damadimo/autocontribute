# Run Autocontribute in GitHub Actions

A runner repository runs Autocontribute on GitHub's machines. It prepares one fix a day, opens an
issue in the runner repository that shows the exact diff, and opens the pull request when you
comment `/approve` on that issue. The files come from [`template/`](../template).

## Set up

```bash
autocontribute init --actions                 # private repository autocontribute-runner
autocontribute init --actions --repo NAME --public
```

`init --actions` needs an authenticated `gh`. It creates the repository, pushes the template, and
prints the rest:

1. Create a classic token with only the `public_repo` scope
   ([link](https://github.com/settings/tokens/new?scopes=public_repo&description=autocontribute))
   and save it as the secret `AUTOCONTRIBUTE_GITHUB_TOKEN`. The account that owns the runner
   repository must own the token.
2. Save a model API key as the secret `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`.
3. List repositories under `github.repositories` in the runner's `autocontribute.yml` and push.

Fine-grained tokens and GitHub Apps cannot open pull requests on repositories you do not own, so
the token has to be a classic one. Without the `workflow` scope, GitHub also refuses any push
that changes a target's CI files.

## The workflows

| Workflow | When | What it does |
| --- | --- | --- |
| `setup.yml` | Every push to `main`, or by hand | Checks the secrets, the token's owner and scope, the configuration and Docker. Creates the labels and the `autocontribute-state` branch. Turns `prepare.yml` on only when every check passes; otherwise it keeps a "Finish setup" issue with the checklist. |
| `prepare.yml` | Daily at 06:37 UTC, or by hand | Job `prepare` restores the state, reads the open pull requests, makes one attempt as `run --scheduled` does, and keeps the run's evidence as the `evidence` artifact for 30 days. Job `record` checks the result, saves the state and opens one issue per prepared fix. |
| `approve.yml` | A new comment on an issue | Starts only for the owner's `/approve` comment on an open approval issue. Approves, publishes, comments the pull request link and closes the issue. |

Each workflow installs the version of Autocontribute set in
`.github/actions/install-autocontribute/action.yml` and calls one `autocontribute actions`
command.

## What each job may do

- `prepare` runs the target repository's code and the agent. It gets read access to the runner
  repository, the workflow's own `GITHUB_TOKEN` for reading public GitHub data, and the model
  key. It never sees the publishing token.
- `record` runs on a fresh machine and runs no repository code. It accepts only `state.tar.gz`
  and `prepared.json` from `prepare`, checks their sizes and hashes, opens the state and verifies
  its records, and renders each issue from that state, so the issue shows what the approval
  fingerprint covers. It saves the state only if it keeps everything the saved state holds: a
  preparation may add runs, start a safety stop, and cancel runs waiting for approval, but never
  approve, publish, or end a stop.
- `approve` checks the comment again from the event file and from GitHub: the issue is open,
  this runner opened it, it carries the `autocontribute:awaiting-approval` label, your account
  wrote the comment, nobody edited it, and it reads exactly `/approve` and 12 characters of the
  fingerprint. Only this job and `setup` see the publishing token.
- Every write to the runner repository uses `GITHUB_TOKEN`.

## State

The `autocontribute-state` branch holds one `state.tar.gz` from `autocontribute state export`.
A job commits it only when it changed and never force-pushes. `setup`, `record` and `approve`
share one queue, so they never write the state at the same time.

`prepare` can take an hour or more, and an approval may land meanwhile. `record` then finds a newer
state than the one `prepare` started from. It keeps the newer state, drops that preparation's
result, and fails; the next run prepares again.

## Fix a run by hand

Some things need you and the state on your own machine: ending a safety stop, or ending a run
whose pull-request request GitHub never answered (the approval issue says so). In a checkout of
the runner repository, with your publishing token in `AUTOCONTRIBUTE_GITHUB_TOKEN`:

```bash
git fetch origin autocontribute-state && git show origin/autocontribute-state:state.tar.gz >state.tar.gz
autocontribute state import state.tar.gz --release-leases
autocontribute safety status
autocontribute safety resume --actor NAME --reason TEXT --expected-trigger-hash REVISION
autocontribute runs abandon RUN_ID --reason TEXT
autocontribute state export --output state.tar.gz
```

Run only the commands you need: `safety status` and `safety resume` end a safety stop, and
`runs abandon` ends a stuck run once GitHub shows no pull request from it. Then commit
`state.tar.gz` to the `autocontribute-state` branch while no workflow runs.

## Public or private

A private runner uses Actions minutes: GitHub Free includes 2,000 a month, about an hour a day, and
runs stop when they run out. A public runner gets free minutes and larger machines, but anyone can
read its issues, diffs and state, and GitHub turns scheduled workflows off after 60 days without
activity in the repository. Never add collaborators: anyone with write access can read the
secrets.

GitHub's terms limit hosted runners to work on the repository's own software, and a runner that
prepares fixes for other projects is a borderline case. Keep the volume low; the default limits
allow one new pull request a day.

## Commands

| Command | Used by |
| --- | --- |
| `init --actions [--repo NAME] [--public]` | You, once |
| `actions setup` | `setup.yml` |
| `actions prepare --state DIR --output DIR` | `prepare.yml`, job `prepare` |
| `actions record --input DIR --state DIR` | `prepare.yml`, job `record` |
| `actions approve --issue N --comment-id C --state DIR` | `approve.yml` |

The `actions` commands read the GitHub Actions environment and fail elsewhere.
