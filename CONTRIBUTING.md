# Contributing to Autocontribute

Thank you for helping make autonomous contribution tooling useful to maintainers rather than noisy.

Before opening a PR, create or reference an issue, keep the change narrowly scoped, add tests for
behavioral changes, and run:

```bash
uv sync --extra dev
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest
```

Security boundaries must fail closed. A model score must never override credential isolation,
approval binding, secret scanning, repository policy, upstream freshness, or sandbox restrictions.
Tests must use fixtures or mocked APIs and must never create a real contribution on GitHub.

By participating, you agree to follow the project's code of conduct once one is adopted. Report
security issues through the private process described in [SECURITY.md](SECURITY.md).
