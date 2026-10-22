# Security policy

## Report a vulnerability

Do not open a public issue. Use GitHub's private vulnerability reporting for this repository:
<https://github.com/Damadimo/autocontribute/security/advisories/new>. Include the affected commit,
steps to reproduce, and the impact, but no live credentials or other people's data. There are no
releases yet; only the `main` branch is supported.

## Scope

In scope: this repository's code, systemd deployment files, and GitHub Actions workflows. Examples:
escaping the validation sandbox or reaching the network from it; exposing a GitHub token or model
API key to the sandbox, the model, logs, run evidence, or a pull request; publishing without a valid
approval, or publishing anything other than the approved diff; bypassing publication limits, policy
checks, secret scanning, or `safety stop`; and state or backup tampering that `state restore`
misses. Out of scope: the repositories Autocontribute contributes to; Docker, GitHub, and model
provider services (report those upstream); and anything that needs the `local` sandbox backend.

## Deployment expectations

- Keep `sandbox.backend: docker`; the `local` backend runs repository code on your host.
- Keep tokens and API keys in environment variables or a secret manager; the configuration holds
  only their names. Give the GitHub token the fewest permissions that work, and for hosted runs
  prefer an expiring GitHub App user token.
- Before adding credentials to GitHub Actions, protect the default branch as described in the
  [scheduling guide](docs/scheduling.md), or use a [persistent worker](docs/systemd-deployment.md).
- Keep `publishing.mode: review_required` until evaluation results justify automatic publication.
- After a GitHub `403` or `429`, an abuse warning, a maintainer's stop request, or a secret-scanner
  finding, run `safety stop --actor NAME --reason TEXT` and investigate before resuming.
