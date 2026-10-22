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
- Run the four checks from CI's `test` job and fix every failure. CI runs on Ubuntu only;
  macOS is untested.

```bash
uv run --no-sync ruff check .
uv run --no-sync ruff format --check .
uv run --no-sync mypy src
uv run --no-sync pytest
```

## Safety changes

- Keep defaults conservative. Do not loosen a default such as `publishing.mode: review_required`,
  draft pull requests, or the publication limits.
- When a safety check cannot reach a decision, the code must stop or refuse.
- Model output or scores must never override credential isolation, approval binding, secret
  scanning, repository policy, upstream freshness, publication limits, or sandbox restrictions.
- In the pull request, say what the change refuses and which tests cover it.
