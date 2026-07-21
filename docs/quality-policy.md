# Quality policy

No system can honestly guarantee that a maintainer will accept a contribution. Autocontribute calls
its scores *readiness* scores rather than model-predicted acceptance probabilities. Expert shadow
grades are stored separately from model scores and drive the rollout gate.

## Candidate readiness

A candidate needs a public, recently active, non-archived allowlisted repository; contribution
guidance; an open, unassigned, maintainer-signaled issue; no excluded/security label; no likely
competing PR; clear acceptance language; recent activity; and a score of at least 85 by default. The
complete issue discussion is loaded before selection. Claimed work, maintainer stop requests,
security-sensitive work, stale issues, broad scope, and policy conflicts are skipped before a model
call whenever possible.

The deterministic score is:

| Dimension | Weight |
| --- | ---: |
| Maintainer signal | 25 |
| Issue clarity | 20 |
| Reproducibility | 20 |
| Scope | 15 |
| Activity | 10 |
| Policy fit | 10 |

## Patch hard gates

All gates must pass. A high model score cannot override one.

- A non-empty, reconstructable diff of no more than eight files and 400 added/deleted lines.
- No binaries, symlinks, submodules, file-mode changes, unsafe paths, generated/vendor files, secrets,
  dependency/lock changes, or CI workflow changes unless the global owner explicitly changes policy.
- For a bugfix, the same bounded reproduction must fail on pristine upstream and pass with the patch.
  Missing tools/files/modules, no-test discovery, timeouts, permission errors, and unavailable
  networking are infrastructure failures rather than regression evidence.
- Every operator-owned repository validation command passes in a disposable offline sandbox copy;
  model-suggested commands cannot replace it and command-budget truncation fails closed.
- A fresh-context critic reports no blocker or missing issue requirement.
- Every critic dimension is at least 80 and weighted readiness is at least 90.
- Commit and PR text are bounded, credential-free, non-broadcast, and contain the configured
  disclosure.
- Immediately before publication, the issue remains open/unassigned, no competing PR exists, and the
  default branch still equals the tested base SHA.

Critic dimensions are weighted as follows: correctness 25%, issue alignment 25%, tests 15%, repository
conventions 15%, diff/security hygiene 10%, and maintainer clarity 10%.

## Publication limits

Defaults allow at most one new PR per day, two open PRs, and no same-repository submission while an
existing PR is open or for seven days after a recent close/update. A `403`, `429`, stale approval,
base drift, duplicate, assignment race, or unexpected existing branch stops publication. The broker
never force-pushes.

“No suitable contribution,” “could not reproduce,” and “validation environment unavailable” are
healthy outcomes. The project must never optimize for daily PR count, profile activity, company
prestige, or stars at the expense of maintainer value.

## Shadow rollout gate

Use `autocontribute eval record` to bind one immutable expert judgment to each exact run artifact and
`autocontribute eval report` to inspect aggregate evidence. Autonomous rollout remains blocked until
there are at least 100 reviewed shadow cases, at least 20 prepared cases, at least 95% accept-as-is
precision among prepared cases, and zero policy, security, or etiquette failures. Passing this gate
permits a controlled pilot; it is not permission for owner-wide or quota-driven publication.
