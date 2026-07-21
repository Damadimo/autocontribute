# Scheduled operation

The included workflow runs at 09:17 and 21:17 UTC. It is inert until the repository variable
`AUTOCONTRIBUTE_ENABLED` is set to `true`.

## Setup

1. Copy `autocontribute.example.yml` to `autocontribute.yml`, choose a small explicit repository
   allowlist, and set `github.auth: token` for CI. Commit `autocontribute.yml` to the default branch
   before enabling the workflow. The workflow does not synthesize configuration and fails closed if
   the file is absent.
2. Choose a pinned sandbox image that already contains the toolchain and dependencies needed by those
   repositories. Validation networking stays disabled.
3. Add `OPENAI_API_KEY` and `AUTOCONTRIBUTE_GITHUB_TOKEN` as GitHub Actions secrets. Prefer an expiring
   GitHub App user token in hosted systems; if using a token for an MVP, grant only the repository
   permissions publication actually needs.
4. Set the repository variable `AUTOCONTRIBUTE_ENABLED=true`.
5. Leave `publishing.mode: review_required`. Each scheduled run uploads the run bundle and SQLite
   ledger, but not the cloned workspace.

The workflow preloads the configured Docker image, runs `doctor`, prepares one attempt, and uploads
evidence even when the attempt skips or rejects a candidate.

## State continuity and human approval

GitHub-hosted runners are ephemeral. At the start of each job, the workflow restores the newest
scheduler-state cache for this repository. At the end, it saves `.autocontribute/state.sqlite3` and
`.autocontribute/runs/` under a unique, immutable key. This carries the run ledger and active-candidate
history forward so a later schedule does not unknowingly prepare the same issue again. The concurrency
group prevents two scheduler jobs from racing to extend that history.

The cache is operational continuity, not an approval record or permanent backup. GitHub may evict
caches. Target-repository workspaces, `autocontribute.yml`, API keys, and GitHub credentials are never
cached. Changing the `autocontribute-state-v1-` prefix intentionally starts a fresh cache lineage after
an incompatible state-format change.

Every job separately uploads a 14-day evidence artifact named `autocontribute-<workflow-run-id>`.
That immutable artifact is the review handoff. Command output and reports are credential-redacted,
but the manifest and ledger retain the public issue text and proposed contribution text; handle the
artifact as review data, not as a sanitized public export. To review a ready run on a trusted machine,
download the artifact contents into `.autocontribute/`, then inspect and approve the exact run:

```bash
mkdir -p .autocontribute
gh run download WORKFLOW_RUN_ID \
  --name autocontribute-WORKFLOW_RUN_ID \
  --dir .autocontribute
uv run autocontribute runs show AUTOCONTRIBUTE_RUN_ID
uv run autocontribute approve AUTOCONTRIBUTE_RUN_ID
uv run autocontribute publish AUTOCONTRIBUTE_RUN_ID
```

Use the same committed `autocontribute.yml` when reviewing. The approval hash binds the issue, base
commit, patch, checks, and proposed PR text; publication reconstructs the target workspace from the
approved patch, so cloned target repositories do not belong in either the cache or artifact. Approval
still expires and publication still performs the upstream freshness and duplicate checks.

## Deliberately enabling automatic PRs

Only after measuring prepared patches should you set both:

```yaml
publishing:
  mode: auto
```

and the repository variable:

```text
AUTOCONTRIBUTE_ALLOW_AUTO_PUBLISH=1
```

Both gates are required. Automatic mode still performs all quality, account, cooldown, duplicate, and
freshness checks. Removing the variable is the kill switch. Do not raise cadence to compensate for
skipped runs.

API credentials pay for API usage and are separate from ChatGPT/Codex product subscriptions. Put the
OpenAI key in a dedicated project with spend and rate limits.
