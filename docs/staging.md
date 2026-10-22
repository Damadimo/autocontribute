# Staging

Maintainers use staging to test the agent end to end against a fixture repository they own, never
against a third-party project. The **Staging shadow run** workflow (`.github/workflows/staging.yml`)
prepares one contribution for a fixture issue you name. It never publishes.

## Required setup

1. Create a public repository you own as the fixture; autocontribute refuses private targets. Put
   no real credentials, private code or personal data in it. Give it synthetic code, contribution
   guidelines, a pull-request template, and small synthetic issues labeled `autocontribute-e2e` (the
   config's `github.include_labels`) that together cover:
   - a clear issue that should be solved, and an attractive issue that should be skipped;
   - maintainer comments that claim the work, change the scope, or ask automation to stop;
   - repository instructions, and a regression test that fails on the base commit for the
     intended reason;
   - required lint, type, unit and integration commands;
   - prompt-injection text, symlinks, ignored files, large files and planted fake credentials.
2. Commit `autocontribute.staging.yml` to the control repository's default branch. The checked-in
   file targets `Damadimo/autocontribute-staging-fixture`. For your own fixture, copy
   `autocontribute.staging.example.yml` over it, replace `YOUR_ACCOUNT` and the identity, and run
   `uv run autocontribute config validate --config autocontribute.staging.yml`. Check the
   `models.*.pricing` values against your provider account.
3. The workflow refuses the config unless `storage.path` is `.autocontribute-staging`,
   `github.repositories` is exactly `AUTOCONTRIBUTE_STAGING_REPOSITORY` with no `github.owners`,
   `publishing.mode` is `review_required` with `publishing.draft: true`, and the sandbox and time
   budget meet the [production rules](scheduling.md#set-up). It provides only `OPENAI_API_KEY` and
   `AUTOCONTRIBUTE_STAGING_GITHUB_TOKEN` (the checked-in `github.token_env`). Protect the default
   branch as described there.
4. Add these repository secrets and variables:

| Name | Kind | Value |
|---|---|---|
| `OPENAI_API_KEY` | Secret | Model API key, from a provider project with spend limits. |
| `AUTOCONTRIBUTE_STAGING_GITHUB_TOKEN` | Secret | Expiring fine-grained personal access token or GitHub App user access token (not an installation token), limited to the fixture with read-only Metadata, Contents, Issues and Pull requests. |
| `AUTOCONTRIBUTE_STAGING_STATE_TOKEN` | Secret | Expiring fine-grained personal access token for the control repository only, with just **Variables: Read and write**. |
| `AUTOCONTRIBUTE_STAGING_REPOSITORY` | Variable | The fixture's `owner/repository`. |
| `AUTOCONTRIBUTE_STAGING_ENABLED` | Variable | `true` allows runs; anything else blocks them. |

## Dispatch a run

The first dispatch creates the staging state. Later dispatches leave out `bootstrap_state`, which
works only while `AUTOCONTRIBUTE_STAGING_STATE_LINEAGE` does not exist.

```bash
gh variable set AUTOCONTRIBUTE_STAGING_ENABLED --body true
gh workflow run staging.yml -f issue=OWNER/FIXTURE#1 -f bootstrap_state=true
gh workflow run staging.yml -f issue=OWNER/FIXTURE#2
```

The issue must belong to `AUTOCONTRIBUTE_STAGING_REPOSITORY`. Each run runs `lifecycle sync`,
`doctor` (one small paid request per distinct model profile) and `run --issue`. State persists
[as in production](scheduling.md#how-state-persists), through `AUTOCONTRIBUTE_STAGING_STATE_LINEAGE`;
the evidence artifact is `autocontribute-staging-<workflow-run-id>-<attempt>`, kept 30 days.
Recover a stranded run [as in production](scheduling.md#recover-a-stranded-run), using the **Recover
staging hosted state** workflow (`recover-staging-lineage.yml`) and the staging variables.

## What to check

For each fixture case, download the artifact and read `runs/<run-id>/report.md`: status, skip
reason or error, model usage, plan, proposed pull request, validation results and independent review.

```bash
gh run download WORKFLOW_RUN_ID --name autocontribute-staging-WORKFLOW_RUN_ID-ATTEMPT --dir evidence
```

### Retry policy

Dispatch the same issue again after each setup below. Check the report's model usage; `doctor`
sends its own requests in every run.

| Before the new dispatch | Expected report |
|---|---|
| The issue's last run ended `skipped`, `rejected` or `cancelled`; the issue is unchanged | `skipped`, the skip reason names the prior run, 0 model tokens |
| As above, after a new comment on the issue | A normal attempt |
| The issue's last run `failed`; the issue is unchanged | A normal attempt |
| A run for the issue is `ready_for_approval`, even if the issue changed | `skipped`, the skip reason names the active run, 0 model tokens |

### Local drills

The workflow cannot pass `--retry-unchanged` or publish. Test both on a local copy of the staging
state, in a checkout with no `.autocontribute-staging` directory. For the override, pick an
unchanged issue whose last run ended `skipped`, `rejected` or `cancelled`: it must get a normal
attempt, while an issue with an active run must still be skipped.

```bash
mkdir -m 700 .autocontribute-staging
gh run download WORKFLOW_RUN_ID --name autocontribute-staging-WORKFLOW_RUN_ID-ATTEMPT --dir .autocontribute-staging
uv run autocontribute state restore --config autocontribute.staging.yml --input .autocontribute-staging/snapshots/state.sqlite3
uv run autocontribute run --config autocontribute.staging.yml --issue OWNER/FIXTURE#1 \
  --retry-unchanged --retry-actor "YOUR NAME" --retry-reason "STAGING RETRY DRILL"
```

To test lifecycle stops, prepare a fixture run in this copy (`publish` refuses a run prepared under
another Python environment, such as the runner's), then `approve` and `publish` it with
`AUTOCONTRIBUTE_STAGING_GITHUB_TOKEN` set to a token that can publish. Use an account that does not
own the fixture: publishing goes through a fork, and an owner cannot fork its own repository. Then
introduce one signal at a time (a changes-requested review, a failing check, a push to the pull
request branch, a maintainer comment asking automation to stop, closing without merge, a merged
revert) and run:

```bash
uv run autocontribute lifecycle sync --config autocontribute.staging.yml
uv run autocontribute safety status --config autocontribute.staging.yml
```

Check that the stop names the signal and pull request, that `run` refuses, and that
[`safety resume`](how-it-works.md#lifecycle-sync-and-the-safety-stop) clears it after review. Also
push to the fixture's default branch between preparation and `publish`: `publish` must refuse
because the base moved.
