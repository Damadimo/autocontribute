# Security policy

Autocontribute processes hostile repositories, issue text, model output, package metadata, and test
output. Do not run it with host execution enabled on code you do not fully trust.

## Supported versions

Only the latest release on the default branch receives security fixes during the alpha.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private vulnerability
reporting for this repository. Include the affected version, reproduction steps, impact, and any
suggested mitigation. Please do not include live credentials or data belonging to another person.

## Deployment expectations

- Keep model and GitHub credentials in a secret manager or environment variables.
- Before storing credentials in GitHub Actions, protect the default branch that controls the
  workflows: require pull requests and passing CI, apply the rules to administrators where supported,
  and block force pushes and deletion. If the repository plan cannot enforce those controls, keep the
  credentials out of hosted Actions and use a trusted persistent worker instead.
- Prefer an expiring GitHub App user token with minimum permissions for hosted deployments.
- Never mount a home directory, Docker socket, SSH agent, cloud credentials, or provider keys into
  the repository sandbox.
- Keep every sandbox image pinned to an audited `sha256` digest; mutable tags are rejected.
- Keep sandbox networking disabled during validation and use a separate, credential-free dependency
  acquisition stage if a project requires downloads.
- Keep human approval enabled until acceptance, revision, and incident metrics justify a narrower
  automated policy.
- Treat a GitHub `403`, `429`, abuse warning, maintainer stop request, or secret-scanner finding as a
  global circuit breaker.
