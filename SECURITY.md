# Security policy

## Report a vulnerability

Do not open a public issue. Use GitHub's private vulnerability reporting for this repository:
<https://github.com/Damadimo/autocontribute/security/advisories/new>. Include the affected commit,
steps to reproduce, and the impact, but no live credentials or other people's data. There are no
releases yet; only the `main` branch is supported.

## Scope

In scope: this repository's code, its GitHub Actions workflows, and the runner template in
`template/`. Examples: escaping a container; reaching the network from a container that has none,
or a host the setup proxy should refuse; exposing a GitHub token or model API key to a container,
a model, logs, run evidence, or a pull request; publishing without a valid approval, or publishing
anything other than the approved diff and text; and bypassing publication limits, policy checks,
secret scanning, or `safety stop`. Out of scope: the repositories Autocontribute contributes to,
and Docker, GitHub, and model provider services (report those upstream).

## Trust boundaries

Repository code, issue text, and model output are untrusted.

- Repository code runs only in Docker containers that drop every capability, set
  `no-new-privileges`, run under the `sandbox` memory, CPU, and process limits, mount `.git`
  read-only, and get none of your environment variables. Setup installs dependencies through a
  proxy that allows only package registries, GitHub, and `environments.<repo>.allow_hosts`. The
  tests and the agent's and critic's commands run with no network and a read-only root filesystem
  ([Test environments](docs/environments.md#what-runs-with-network)).
- The agent's edits are written on the host by code that refuses paths outside the workspace,
  inside `.git`, or through a symlink.
- The GitHub token and model API keys stay on the host. Each model request runs in a separate
  process that gets only its provider's key. Exact values of your secret environment variables,
  and text that looks like a token, are replaced before any text reaches a model or a transcript. A
  patch that contains one of those exact values starts the safety stop.
- Nothing reaches GitHub until a person approves the exact diff and text, and `publish` checks them
  again.
- In GitHub Actions, the job that runs repository code and the agent never receives the publishing
  token.

## Safe use

- Run Autocontribute where a container escape would expose nothing else, such as a GitHub-hosted
  runner or a machine or VM used only for it.
- Keep tokens and API keys in environment variables or a secret manager; they never go in the
  configuration. Give the GitHub token the fewest permissions that work.
- Add to `environments.<repo>.allow_hosts` only the hosts a repository's install needs.
- After a GitHub `403` or `429`, an abuse warning, a maintainer's stop request, or a secret-scanner
  finding, run `safety stop --actor NAME --reason TEXT` and investigate before resuming.
