# Contributing

Open an issue, or comment on an existing one, before you start work. Report vulnerabilities
privately as described in [SECURITY.md](SECURITY.md).

## Set up

```bash
git clone https://github.com/Damadimo/autocontribute.git
cd autocontribute
uv sync --extra dev --locked
```

## Pull requests

- Keep each pull request small and tied to one issue. Leave out unrelated refactors, generated
  files, and dependency changes the issue does not need.
- Add or update tests for every behavior change.
- Use fixtures or mocked APIs in tests; never write to real GitHub.
- Update the docs when behavior or configuration changes.
- Run the four checks from CI's `test` job and fix every failure.

```bash
uv run --no-sync ruff check .
uv run --no-sync ruff format --check .
uv run --no-sync mypy src
uv run --no-sync pytest
```

## Live tests

`pytest` skips the tests that need Docker or a model API key. The Docker tests need Docker with
cgroup v2 and network access to pull images; run them when you change the sandbox, the test
environments, the agent loop, or the run itself:

```bash
AUTOCONTRIBUTE_RUN_DOCKER_TESTS=1 uv run --no-sync pytest -q tests/test_sandbox_live.py \
  tests/test_environments_live.py tests/test_agent_loop_live.py tests/test_validation_live.py \
  tests/test_orchestrator_live.py
```

The `Security integration` workflow runs them on rootful Docker for every push to `main` and every
pull request that changes more than documentation. The model tests send a short tool loop to each provider whose key is set and cost a
few cents:

```bash
AUTOCONTRIBUTE_RUN_MODEL_TESTS=1 uv run --no-sync pytest -rs tests/test_model_live.py
```

The `Model canary` workflow runs them when started by hand or on a pull request labeled
`model-canary`.

## End-to-end check

The `E2E` workflow (`.github/workflows/e2e.yml`) prepares one real issue with the repository secret
`OPENAI_API_KEY` and keeps the run's evidence as the `e2e-evidence` artifact for 14 days. It never
publishes: its only GitHub token is the workflow's read-only token. Start it from the Actions tab
with an issue (`owner/repository#number`) or with repositories for discovery and triage to pick
from, or push a branch under `e2e/` that holds `e2e/issue.txt` or `e2e/repositories.txt`. A run
costs up to the default per-run budget of 10 USD.

To run one locally, `autocontribute.staging.example.yml` configures runs against a public fixture
repository you own, named `autocontribute-staging-fixture`. The fixture needs a CONTRIBUTING file,
issues labeled `autocontribute-e2e`, and tests that `python -m unittest discover -s tests -v` runs
with only the Python standard library: the example's `environments` entry runs them on
`python:3.12-bookworm` with no setup. Copy the example, replace `YOUR_ACCOUNT` and the identity,
export `AUTOCONTRIBUTE_STAGING_GITHUB_TOKEN` and `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`, and pass
the copy with `--config`.

## Safety changes

- Keep defaults conservative. Do not loosen a default such as the publication limits or the
  approval expiry, and do not add a way to publish without approval.
- When a safety check cannot reach a decision, the code must stop or refuse.
- Model output or scores must never override credential isolation, approval binding, secret
  scanning, repository policy, upstream freshness, publication limits, or sandbox restrictions.
- In the pull request, say what the change refuses and which tests cover it.
