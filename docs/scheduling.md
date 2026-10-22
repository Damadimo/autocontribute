# Scheduling

Cron and the included GitHub Actions workflow run autocontribute unattended and prepare
contributions for you to review; only the [systemd deployment](systemd-deployment.md) may publish
[automatically](#automatic-publishing). Each attempt can spend up to
`budget.max_model_cost_usd_per_run` on model calls, priced with your `models.*.pricing` values. The
starter config sets 50 USD: up to 100 USD a day at two runs a day.

## Local schedule

`autocontribute run --scheduled` makes one unattended attempt. This crontab line (`crontab -e`)
runs it at 09:17 and 21:17 in the machine's time zone:

```cron
17 9,21 * * * . "$HOME/.autocontribute.env" && autocontribute run --scheduled --config /path/to/autocontribute.yml >>/path/to/autocontribute.log 2>&1
```

cron starts with an almost empty environment. In `~/.autocontribute.env` (`chmod 600`), export a
`PATH` on which `autocontribute`, `docker`, `git` and `gh` resolve, and `OPENAI_API_KEY` (plus
`AUTOCONTRIBUTE_GITHUB_TOKEN` with `github.auth: token`). From a checkout, `cd` into it and use
`uv run autocontribute`. If an attempt is still working when the next starts, the new one is refused.

`--scheduled` changes what `run` does:

- It runs `autocontribute lifecycle sync` first, which polls the pull requests autocontribute
  opened and can turn on the [safety stop](how-it-works.md#lifecycle-sync-and-the-safety-stop).
  While the stop is on, the run refuses before discovery or any model call, until you review the
  triggers and resume as described there.
- It picks the issue itself and refuses `--issue` and the retry override (`--retry-unchanged` with
  `--retry-actor` and `--retry-reason`). An issue whose last run ended `skipped`, `rejected` or
  `cancelled` waits until the issue changes; only a manual run with the
  [override](how-it-works.md#run-states) retries it as is.

With `publishing.mode: review_required` (the default), scheduled runs only prepare. Review them with
`runs list`, `runs show`, `approve` and `publish`, or drop one you will not publish with
`autocontribute runs cancel RUN_ID --reason "WHY"`.

## GitHub Actions

The **Prepare contribution** workflow (`.github/workflows/autocontribute.yml`) runs at 09:17 and
21:17 UTC from the default branch while `AUTOCONTRIBUTE_ENABLED` is `true`. Each run restores saved
state, runs `lifecycle sync` and `doctor --non-interactive` (one small paid request per distinct
model profile), makes one `run --scheduled` attempt (`run --issue` when dispatched with the `issue`
input), and saves state. It never publishes.

### Set up

1. Use your own copy of this repository as the control repository; the workflow installs
   autocontribute from it. Commit `autocontribute.yml` at its root on the default branch. The
   workflow refuses it unless `storage.path` is `.autocontribute`, `publishing.mode` is
   `review_required`, `sandbox.backend` is `docker` without `sandbox.allow_unsafe_local`, and
   `budget.max_model_seconds_per_run` + `sandbox.command_timeout_seconds` × `sandbox.max_commands` is
   at most 10,800 seconds. Set `github.auth: token` and keep `github.token_env` and
   `models.*.api_key_env` at their defaults: the workflow provides only `AUTOCONTRIBUTE_GITHUB_TOKEN`
   and `OPENAI_API_KEY`. `sandbox.image` must be pullable without a registry login.
2. Protect the default branch before you add secrets, because the workflow runs from it with those
   secrets. Require reviewed pull requests and passing checks, and block force pushes and deletion.
   GitHub Free offers branch protection only for public repositories.
3. Add these repository secrets:

   | Secret | Value |
   |---|---|
   | `OPENAI_API_KEY` | Model API key, from a provider project with spend limits. |
   | `AUTOCONTRIBUTE_GITHUB_TOKEN` | Read-only token for the target repositories: an expiring fine-grained personal access token or a GitHub App user access token. `doctor` identifies the account with `GET /user`, which installation tokens cannot call. |
   | `AUTOCONTRIBUTE_STATE_TOKEN` | Expiring fine-grained personal access token for the control repository only, with just **Variables: Read and write**. Only the state steps receive it. |

4. Turn the workflow on and bootstrap. The first run must be this manual dispatch, which creates the
   state and makes a normal attempt. Bootstrapping works only while `AUTOCONTRIBUTE_STATE_LINEAGE`
   does not exist.

   ```bash
   gh variable set AUTOCONTRIBUTE_ENABLED --body true
   gh workflow run autocontribute.yml -f bootstrap_state=true
   ```

### How state persists

Each run restores the files the previous run saved in the Actions cache, saves a new cache entry,
and uploads the same files as the artifact `autocontribute-<workflow-run-id>-<attempt>`, kept 14
days. To read a result, download the artifact and open `runs/<run-id>/report.md`.

The repository variable `AUTOCONTRIBUTE_STATE_LINEAGE` names the current cache entry: normally
`committed:<cache key>`, and `handoff:<cache key>` after a handoff. While a run works it reads
`in-progress:...`; if the run stops before saving, it stays that way and later runs refuse until you
[recover](#recover-a-stranded-run). The workflow manages this variable; never edit or delete it.

GitHub deletes caches unused for 7 days. If the current entry is gone, for example after a long
pause, runs stop. Starting over would forget attempted issues and safety stops. Instead, restore the
newest artifact on your machine with the handoff commands from `mkdir` on.

### Hand off state for approval and publishing

You approve and publish on your own machine, from state the workflow hands off. A handoff run saves
state without preparing anything, uploads the artifact, and sets the variable to `handoff:...`,
which ends hosted scheduling so the state and your pull requests stay together. `publish` refuses a
run prepared under a different Python build, platform or dependency set
([How it works](how-it-works.md#approval-and-publication)), so use Linux x86_64 with the runner's
Python 3.12 build. Work in a checkout of the control repository at the commit that prepared the run
you will publish, with no `.autocontribute` directory, and a GitHub token that can publish:

```bash
gh workflow run autocontribute.yml -f lock_for_handoff=true
gh run list --workflow autocontribute.yml --limit 1   # wait for success; note the run ID
gh variable set AUTOCONTRIBUTE_ENABLED --body false
mkdir -m 700 .autocontribute
gh run download WORKFLOW_RUN_ID --name autocontribute-WORKFLOW_RUN_ID-ATTEMPT --dir .autocontribute
uv run autocontribute state restore --input .autocontribute/snapshots/state.sqlite3
read -rsp "GitHub token: " AUTOCONTRIBUTE_GITHUB_TOKEN && export AUTOCONTRIBUTE_GITHUB_TOKEN
uv run autocontribute runs list
uv run autocontribute runs show RUN_ID
uv run autocontribute approve RUN_ID
uv run autocontribute publish RUN_ID
```

Continue here on a [local schedule](#local-schedule), which watches the pull requests you open.

### Recover a stranded run

If a run stops after claiming the state (for example, the runner was lost or saving failed), the
variable stays `in-progress:...` and later runs refuse. Use the **Recover production hosted state**
workflow (`.github/workflows/recover-production-lineage.yml`). It refuses while scheduling is on.
Turn scheduling off, confirm no **Prepare contribution** run is still in progress, and promote the
stranded run's own state:

```bash
gh variable set AUTOCONTRIBUTE_ENABLED --body false
claim="$(gh variable get AUTOCONTRIBUTE_STATE_LINEAGE)"
gh workflow run recover-production-lineage.yml \
  -f recovery_action=promote_claimed -f expected_claim="$claim"
```

This restores the stranded run's cache entry, or its artifact if the cache is gone, verifies it, and
saves it as a new entry and a 30-day `autocontribute-lineage-recovery-<workflow-run-id>-<attempt>`
artifact. The variable then reads `committed:...` and you can turn scheduling back on (a stranded
handoff reads `handoff:...` instead).

If the stranded run left no cache entry or artifact, or `promote_claimed` rejected them, restore the
state from before that run. Add `-f restore_over_unusable_claimant=true` only when the entry or
artifact exists but was rejected:

```bash
gh workflow run recover-production-lineage.yml -f recovery_action=restore_parent_stopped \
  -f expected_claim="$claim" -f recovery_reason="ONE-LINE INCIDENT REASON"
```

This records a safety stop under your GitHub login, which the workflow cannot clear, so leave hosted
scheduling off. Download the recovery artifact and, in a checkout with no `.autocontribute`
directory, run `uv run autocontribute state restore --complete --input PATH` on its
`hosted-lineage-recovery.bundle.zip`. Check every pull request autocontribute opened,
[resume](how-it-works.md#lifecycle-sync-and-the-safety-stop), and continue on a local schedule.

## Automatic publishing

With `publishing.mode: auto`, a scheduled run publishes a ready contribution without `approve`. Run
it only from the persistent [systemd deployment](systemd-deployment.md); the GitHub Actions workflow
refuses auto mode. [How it works](how-it-works.md#automatic-publishing) lists the configuration it
needs. Each scheduled attempt in auto mode also needs `AUTOCONTRIBUTE_ALLOW_AUTO_PUBLISH=1` in the
worker's environment, fresh S3 backup evidence and a passing `autocontribute rollout report`, or it
stops before any model call.

To pass `rollout report`, run the final release and configuration in `review_required` mode first.
Changing anything other than `publishing.mode` that the `publish` check in
[How it works](how-it-works.md#approval-and-publication) compares starts the counts over.

- Grade runs with `autocontribute eval record RUN_ID --reviewer NAME --verdict VERDICT`. The first
  100 runs must all be graded, include at least 20 prepared contributions, have at least 95% of
  those graded `accept_as_is`, and have no policy, security or etiquette failure.
- Approve and publish by hand. Each of the first 20 published pull requests must be graded
  `accept_as_is` and merged unchanged.
- After auto mode starts, every earlier automatic pull request must also be merged unchanged.
