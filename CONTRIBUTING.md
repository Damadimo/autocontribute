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

## End-to-end check

`autocontribute.staging.example.yml` configures runs against a public fixture repository you own,
named `autocontribute-staging-fixture`. The fixture needs a CONTRIBUTING file, issues labeled
`autocontribute-e2e`, and the files the example's checks run: `tools/lint.py`,
`tools/typecheck.py`, `tests/unit/`, and `tests/integration/`. These must use only the Python
standard library, because the example's sandbox image is plain Python. Copy the example, replace
`YOUR_ACCOUNT` and the identity, export `AUTOCONTRIBUTE_STAGING_GITHUB_TOKEN` and `OPENAI_API_KEY`,
and pass the copy with `--config`.

## Safety changes

- Keep defaults conservative. Do not loosen a default such as draft pull requests or the
  publication limits, and do not add a way to publish without approval.
- When a safety check cannot reach a decision, the code must stop or refuse.
- Model output or scores must never override credential isolation, approval binding, secret
  scanning, repository policy, upstream freshness, publication limits, or sandbox restrictions.
- In the pull request, say what the change refuses and which tests cover it.
