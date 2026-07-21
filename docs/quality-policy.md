# Quality policy

No system can honestly guarantee that a maintainer will accept a contribution. Autocontribute calls
its scores *readiness* scores and treats merge/revision outcomes as future calibration data, not
model-predicted acceptance probabilities.

## Candidate readiness

A candidate needs a public, active, non-archived allowlisted repository; contribution guidance; an
open, unassigned, maintainer-signaled issue; no excluded/security label; no likely competing PR; clear
acceptance language; recent activity; and a score of at least 85 by default. Security-sensitive,
assigned, stale, broad, or policy-incompatible work is skipped before a model call whenever possible.

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
- Every configured repository validation command passes in the offline sandbox.
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
