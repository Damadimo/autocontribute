# Autocontribute

Autocontribute is a quality-gated agent that prepares narrowly scoped open-source contributions on
your behalf. It searches only for maintainer-signaled work, implements one candidate in an isolated
workspace, runs the project's checks, asks a fresh model to review the complete diff, and produces an
auditable approval bundle.

The scheduler creates **attempts, not a PR quota**. “No suitable contribution found” is a successful
outcome. By default, no scheduled job can write to GitHub; a person must approve the exact issue,
base commit, diff, commit message, and PR text before publication.

> [!WARNING]
> This is an early alpha. Run it against repositories you deliberately allowlist, inspect every
> artifact, and keep `publishing.mode: review_required` until you have measured its results.

## Why this is different

- Issue-first: requires an open, maintainer-signaled, unassigned issue with testable acceptance
  criteria.
- Fail-closed: ambiguous work, security reports, competing PRs, broad refactors, dependency churn,
  and unverifiable changes are rejected.
- Maker-checker: planning/implementation and final review are separate model calls; the critic gets
  fresh evidence rather than trusting the builder's claims.
- Deterministic gates: diff size, forbidden paths, secrets, binaries, validation results, minimum
  dimension scores, and upstream freshness cannot be waived by a model.
- Red/green evidence: behavioral fixes must use the same reproduction command that fails on pristine
  upstream and passes with the patch.
- Credential isolation: model calls happen in the control process; repository commands run in a
  credential-free Docker sandbox with networking disabled.
- Exact approval: an expiring hash binds approval to the complete outbound artifact. Any drift
  invalidates it.
- Provider choice: first-class OpenAI Responses API support and an OpenAI-compatible structured-output
  adapter. Model names and endpoints are configuration, not hard-coded behavior.

## Quick start

Requirements: Python 3.11+, [`uv`](https://docs.astral.sh/uv/), Git, Docker, and the GitHub CLI.

```bash
git clone https://github.com/Damadimo/autocontribute.git
cd autocontribute
uv sync --extra dev
uv run autocontribute init
gh auth login
export OPENAI_API_KEY="..."
docker pull python:3.12-bookworm@sha256:9bed8554e926c07c6f908841d5ee88c33e8df9236b191526bbce81a9062ab43a

# Inspect authentication, Docker, model credentials, and configuration.
uv run autocontribute doctor

# Read-only discovery, or pin the run to one issue.
uv run autocontribute discover
uv run autocontribute run --issue owner/repository#123

# Inspect the generated evidence, then explicitly attest and publish.
uv run autocontribute runs show RUN_ID
uv run autocontribute approve RUN_ID
uv run autocontribute publish RUN_ID
```

Copy [`autocontribute.example.yml`](autocontribute.example.yml) to `autocontribute.yml` and replace
the example repositories with projects you understand. Configuration stores environment-variable
*names* only; never place tokens in YAML. Docker images must be pinned by digest so scheduled checks
cannot silently change toolchains between runs.

## The contribution pipeline

```text
discover -> deterministic eligibility -> plan -> exact edits -> sandbox checks
         -> fresh-context critic -> hard quality gates -> approval -> freshness recheck -> PR
```

Every transition is written to SQLite and to a hash-chained event ledger. Each run also writes a
portable bundle under `.autocontribute/runs/<run-id>/` containing the issue snapshot, pinned upstream
SHA, patch, command evidence, model metadata, quality report, and proposed PR text. Hidden model
reasoning and credentials are never recorded.

The default state machine intentionally ends many runs as `skipped` or `rejected`. A contribution
becomes `ready_for_approval` only when all hard gates and the configured readiness threshold pass.

## Models

The default quality-first profile uses `gpt-5.6` through the OpenAI Responses API with high reasoning.
The final critic uses pro mode; scout and builder use standard mode. You can choose a model exposed by
the configured endpoint when it supports that adapter's strict schema and reasoning requirements:

```yaml
models:
  builder:
    provider: openai
    model: gpt-5.6
    api_key_env: OPENAI_API_KEY
    reasoning_effort: high
    reasoning_mode: standard
  critic:
    provider: openai
    model: gpt-5.6
    api_key_env: OPENAI_API_KEY
    reasoning_effort: high
    reasoning_mode: pro
```

Servers that implement OpenAI-compatible Chat Completions plus strict JSON Schema can use
`provider: openai_compatible` and `base_url`. Critical stages fail closed if the endpoint cannot
enforce the response schema. Reasoning effort is forwarded, while the Responses-specific `pro` mode
is rejected for compatible endpoints; configure `reasoning_mode: standard` or `null`. Other provider
families need an OpenAI-compatible gateway. API-key billing is independent of a ChatGPT or Codex
subscription.

## GitHub publication safety

Scheduled runs are prepare-only by default. `publishing.mode: auto` is supported for deliberate,
calibrated deployments, but it also requires `AUTOCONTRIBUTE_ALLOW_AUTO_PUBLISH=1` at runtime. Rate
limits, maximum open/new PR counts, same-repository cooldowns, duplicate checks, issue assignment,
policy changes, or base-branch drift stop publication.

Autocontribute never autonomously creates issues, comments, reactions, reviews, stars, merges, or
maintainer messages. Follow-up changes require a fresh evidence bundle and approval.

See [SECURITY.md](SECURITY.md) before enabling a schedule and [CONTRIBUTING.md](CONTRIBUTING.md) before
working on the agent itself.

Design details live in [Architecture](docs/architecture.md), [Quality policy](docs/quality-policy.md),
and [Scheduled operation](docs/scheduled-operation.md).

## Development

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest --cov=autocontribute --cov-report=term-missing
```

The test suite never creates a real public PR. Live provider smoke tests, when added, must be explicit
opt-ins and are not part of CI.

## License

MIT
