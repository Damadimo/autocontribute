# Staging and live end-to-end checks

Never use a third-party upstream repository for the first live run. Create a dedicated fixture
repository owned by the operator, give it realistic contribution guidance and small synthetic issues,
and use `.github/workflows/staging.yml` to perform read-only shadow runs against it.

## Required setup

1. Create a repository used only for Autocontribute fixtures. Do not point staging at a real upstream.
2. Copy `autocontribute.staging.example.yml` to `autocontribute.staging.yml`, replace the repository
   placeholder with that exact fixture repository, and review the pinned sandbox image and validation
   recipe.
3. Add `OPENAI_API_KEY` and a read-only `AUTOCONTRIBUTE_STAGING_GITHUB_TOKEN` as repository secrets.
   Use a dedicated provider project and GitHub App installation where possible.
4. Set `AUTOCONTRIBUTE_STAGING_REPOSITORY` to the fixture's `owner/repository` name.
5. Set `AUTOCONTRIBUTE_STAGING_ENABLED=true`, then manually dispatch **Staging shadow run** with a
   fixture issue reference.

The workflow enforces one explicit repository, disables owner-wide discovery, requires
`review_required` mode, requires draft publication configuration, and never invokes the publication
command. It uploads the evidence bundle for expert grading.

## What each fixture must exercise

- a clear issue that should be solved and a superficially attractive issue that should be skipped;
- maintainer comments that claim work, alter scope, or ask automation to stop;
- repository instructions and a completed pull-request template;
- a regression test that fails for the intended assertion on the base commit;
- required lint, type, unit, and integration validation commands;
- prompt-injection text, symlinks, ignored files, large files, and planted fake credentials;
- upstream movement between preparation and attempted publication;
- failing CI and requested-changes lifecycle events.

Successful preparation is not sufficient. Archive the expert decision, any human edits, validation
evidence, token cost, latency, and eventual fixture PR lifecycle outcome for the evaluation corpus.

The separate **Security integration** workflow runs repository-controlled commands inside a real
Docker daemon each week. It verifies that host environment values, network access, Linux
capabilities, the container root filesystem, and Git metadata remain isolated.
