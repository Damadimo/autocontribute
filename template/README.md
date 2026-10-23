# Autocontribute runner

This repository runs [autocontribute](https://github.com/Damadimo/autocontribute) in GitHub
Actions. Once a day it picks an open issue in the repositories you list, prepares a small fix,
and opens an issue here that shows the exact diff, the pull request text and the test results.
You comment `/approve` on that issue, and the pull request opens from your account.

## Set up

1. Create this repository with `autocontribute init --actions`, or copy these files into a new
   repository.
2. Add two repository secrets (Settings, Secrets and variables, Actions; or `gh secret set NAME`):
   - `AUTOCONTRIBUTE_GITHUB_TOKEN`: a classic token of the account that owns this repository,
     with only the `public_repo` scope and an expiry date.
     [Create it](https://github.com/settings/tokens/new?scopes=public_repo&description=autocontribute).
   - `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`: a model API key. Set a spending limit with the
     provider too.
3. List the repositories you want to contribute to under `github.repositories` in
   `autocontribute.yml`, and push to `main`.

Every push to `main` runs the setup workflow. Until everything is in place, it keeps preparation
off and lists what is missing in a "Finish setup" issue.

## Day to day

- The prepare workflow runs every day at 06:37 UTC. Run it at other times from the Actions tab.
- Each prepared fix gets an issue labelled `autocontribute:awaiting-approval`.
- To publish it, comment exactly the `/approve` line that the issue shows. Only a new comment from
  the owner of this repository counts; edited comments are ignored. An approval lasts 72 hours.
- Once the pull request is open, the issue closes with its link.
- Answer the maintainers' reviews and questions on your pull requests yourself. Autocontribute
  never replies to them or pushes more commits; when a pull request needs you, it comments on its
  issue here.

## Public or private

| | Private (default) | Public |
| --- | --- | --- |
| Actions minutes | 2,000 a month on GitHub Free, about an hour a day; runs stop when they run out | Free |
| Runner | 2 CPUs, 8 GB memory | 4 CPUs, 16 GB memory |
| Issues, diffs and state | Only you can read them | Anyone can read them |
| Scheduled runs | Keep running | GitHub turns them off after 60 days without activity |

In a public repository anyone can comment, but only your comments approve. Do not add
collaborators to either kind: anyone with write access can read the secrets.

## Maintenance

- The autocontribute version is set in `.github/actions/install-autocontribute/action.yml`.
- The `autocontribute-state` branch holds the runner's state. Do not edit it.
- A repository whose tests cannot be set up is skipped for 7 days.
  [Test environments](https://github.com/Damadimo/autocontribute/blob/main/docs/environments.md)
  says how to set them in `autocontribute.yml`.
