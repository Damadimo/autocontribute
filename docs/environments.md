# Test environments

Before the agent starts, each run builds the repository's test environment: a Docker image with
the project and its test dependencies installed. It then runs the tests on the unchanged code to
record which pass. The agent, the fix checks, and the critic all work in that image, with no
network ([How it works](how-it-works.md#setting-up)).

## How the environment is found

A recipe names a base image, system packages, setup commands, build commands, and a test command.
Autocontribute tries recipes in this order and uses the first one that is [accepted](#acceptance):

1. With an `environments.<owner/repo>` entry: the detected recipe, with the fields you set in place
   of the detected ones ([Override detection](#override-detection)).
2. Without one: the cached recipe, when its [cache key](#the-recipe-cache) still matches; then the
   detected recipe.
3. When a recipe fails: the setup agent's recipe.

Detection runs nothing. It reads the repository at the base commit: CI workflows, task runners
(tox, nox, Makefile, justfile, `package.json` scripts), manifests and lockfiles, version pins such
as `.python-version`, `.nvmrc`, and `rust-toolchain`, dev container and agent instruction files,
and the scripts these call. It handles a Python, Go, Rust, or JavaScript project at the repository
root, in that order; a maturin project counts as Rust, and Bun is not supported. It follows the
install and test steps of the CI job that runs the tests where it can read them, and picks a full
Debian image for the language version: `python:3.X-bookworm`, `node:N-bookworm`,
`golang:X.Y-bookworm`, or `rust:<channel>-bookworm`. The test command runs the whole suite without
stop-at-first-failure or coverage options. A pytest, Jest, Vitest, Mocha, `go test`, or
`cargo test` command gets a report option added, so results count per test; any other command,
such as `make test` or `python -m unittest`, counts the whole suite as one test that passes or
fails.

The setup agent runs only after a recipe was tried and failed. It works in a setup container on
the failed recipe's base image, with the same network rules, and sees the failed recipe, why it
failed, the last 200 lines of its log, and the repository's build and test files. It has 40 turns
and at most 15% of the run's budget. Its recipe is refused when it uses `sudo`, pipes a download
into a shell, installs a package the repository does not declare (beyond a fixed set of tools such
as pip, uv, poetry, tox, nox, pnpm, and yarn), installs from a URL or another package index, sets a
variable such as `PYTEST_ADDOPTS` or `LD_PRELOAD`, or has a test command other than pytest, Jest,
Vitest, Mocha, `go test`, or `cargo test` with its per-test report. A recipe that is not refused
is replayed from scratch in a fresh container, and fails if it changes tracked files. A repository
with no Python, Go, Rust, or JavaScript project at its root and no cached recipe fails without the
setup agent.

## What runs with network

Setup containers sit on an internal Docker network whose only way out is a proxy in its own
container (a pinned `python:3.12-alpine` image). The proxy allows HTTPS, and plain GET and HEAD
requests on port 80, to these hosts and the ones in `environments.<owner/repo>.allow_hosts`, and
refuses IP addresses and names that resolve only to private addresses:

`archive.ubuntu.com`, `codeload.github.com`, `crates.io`, `deb.debian.org`,
`dl-cdn.alpinelinux.org`, `files.pythonhosted.org`, `github.com`, `index.crates.io`, `nodejs.org`,
`objects.githubusercontent.com`, `plugins.gradle.org`, `proxy.golang.org`, `pypi.org`,
`registry.npmjs.org`, `registry.yarnpkg.com`, `repo.maven.apache.org`, `rubygems.org`,
`security.debian.org`, `services.gradle.org`, `static.crates.io`, `static.rust-lang.org`,
`sum.golang.org`.

| What runs | Network | Where |
| --- | --- | --- |
| Installing the recipe's system packages with apt | through the proxy | a container of its own, as root, which gets back only the capabilities apt needs |
| Setup commands, and for Python a check that the project imports from `/workspace` | through the proxy | the setup container |
| The setup agent's commands | through the proxy | a setup container |
| The baseline, each test run of the fix checks, and each blocker's check command | none | a fresh container per run, on a copy of the workspace |
| The agent's and the critic's commands | none | one container per session |

Every other container drops all Linux capabilities. Every container sets `no-new-privileges`, runs
under the `sandbox` memory, CPU, and process limits, mounts `.git` read-only, and gets none of your
environment variables. Commands run as your user with rootful Docker, and as root inside the user
namespace with rootless Docker. Containers without network also have a read-only root filesystem:
only `/workspace`, a 1 GB `/tmp`, and the image's `/opt/ac` are writable. Each setup step gets
`sandbox.command_timeout_seconds`. Fetching Git tags and submodules, when the project needs them,
runs on the host before setup. After setup, host Git restores any tracked file setup changed and
deletes any new file Git does not ignore, so neither reaches a patch. The proxy's refusals are
added to a failed step's log.

## Acceptance

The baseline runs the recipe's build and test commands on a copy of the post-setup workspace, with
no network, twice, and a third time when any test's result differs. Each run gets
`sandbox.command_timeout_seconds`, at most 900 seconds. The environment is accepted when:

- every run finished in time and its test report could be read; a suite that does not finish within
  the limit is refused;
- at least one test ran, and not every test was skipped;
- at least 80% of the tests that were not skipped passed in every run;
- at most one test gave different results, or fewer than 2% of the tests did;
- the failures are not mostly one sign of a broken environment: more than 5 failing tests, and more
  than half of them, showing the same error, such as a missing module, a failed network lookup, or
  no disk space.

For a Python project, setup also checks that the project imports from `/workspace`, so the tests
exercise the working tree and not an installed copy. The baseline is what the fix checks compare
against: tests that failed or gave different results in it are ignored later, and the agent is told
which tests already failed.

## The recipe cache

An accepted recipe is saved in `state.sqlite3` with its cache key: a hash of the recipe format, the
setup logic version, the language, the machine architecture, the digest the base image's tag
resolved to, and the Git object IDs of the dependency files (manifests, lockfiles, version pins).
The next run for the repository tries the cached recipe first while the key matches; a changed
dependency file or a new image behind the tag falls back to detection. The baseline runs again in
every run.

Docker keeps each environment image as `autocontribute-env/<owner>__<repo>:<key>`, where `<key>`
is the first 12 characters of the cache key, and a later run with the same recipe reuses it instead
of running setup again. List the images with
`docker image ls --filter 'reference=autocontribute-env/*'` and remove ones you no longer need with
`docker image rm`. In GitHub Actions every job starts on a fresh machine, so setup runs each time;
the recipe cache and the 7-day blocks travel with the [state](actions.md#state).

## The 7-day block

When no recipe is accepted, the repository is recorded as failed with the last reason, and the run
ends `skipped` with reason `environment`. For 7 days discovery skips the repository
(`discover --explain` says why), and `run --issue` skips its issues when setting up. An
`environments.<owner/repo>` entry lifts the block at once; `owner/repo: {}` is enough to make
detection try again. Docker itself failing, such as a stopped daemon, fails the run and blocks
nothing.

## Override detection

Set the fields detection gets wrong under `environments.<owner/repo>`; detection fills the rest.
[Configuration](configuration.md#environments) lists the keys `image`, `setup`, `test`, and
`allow_hosts`.

```yaml
environments:
  owner/repo:
    image: python:3.12-bookworm
    setup: ["pip install -e .[test]"]
    test: python -m pytest -q
```

- An entry replaces the cached recipe. It is part of what an approval binds, so changing it makes
  `approve` and `publish` refuse runs prepared before the change.
- When detection finds no supported project, set all of `image`, `setup`, and `test`.
- System packages come from detection, so pick an `image` that already has any others the tests
  need.
- `test` runs without network, and gets a report option only when it is one pytest, Jest, Vitest,
  Mocha, `go test`, or `cargo test` call.
- `allow_hosts` takes host names, not URLs or addresses. Add only the hosts the install needs.

## Docker requirements

- Docker with cgroup v2 that enforces memory, swap, CPU, and process limits.
  `autocontribute doctor` checks this, and GitHub-hosted `ubuntu-24.04` runners meet it.
- Rootful or rootless Docker; user-namespace remapping (`userns-remap`) is not supported. With
  rootful Docker, run Autocontribute as a regular user: it refuses to run containers as host root.
- Network access for Autocontribute to pull the base images and the proxy image. Containers never
  pull images themselves.
- On macOS with Colima, keep `storage.path` under your home directory: Colima shares only `$HOME`
  with its VM, and containers cannot see a workspace outside it.

## When a repository's environment fails

1. Read the reason. `autocontribute runs show RUN_ID` and the run's `report.md` give it, such as
   `Setup step pip install -e .[test] exited with 1`, or a baseline where only 12 of 40 tests
   passed. `discover --explain` lists blocked repositories with their reason. If the setup agent
   ran, `runs/<run-id>/setup-1.jsonl` shows what it tried.
2. If the tests need a service such as a database or a browser, network access while they run, or
   a toolchain these images lack, leave the repository out of `github.repositories`.
3. Otherwise add an `environments.<owner/repo>` entry with what detection got wrong, and any host
   the install needs to `allow_hosts`. The entry lifts the 7-day block.
4. The skipped run's issue is passed over until it changes. Prepare it again:

   ```bash
   autocontribute run --issue owner/repo#N --retry-unchanged --retry-actor NAME --retry-reason "TEXT"
   ```
