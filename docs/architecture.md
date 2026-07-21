# Architecture

Autocontribute is deliberately split into a credentialed control plane, an uncredentialed execution
plane, and a narrow publication broker.

```text
GitHub read API ──> discovery/policy ──> model planner ──> exact edit proposal
                                                    │
                                                    v
                                      pinned local repository
                                                    │
                                                    v
                                      offline Docker validation
                                                    │
                                                    v
                                  fresh model critic + hard gates
                                                    │
                                                    v
                                      immutable approval bundle
                                                    │
                                                    v
                                    GitHub publication broker
```

## Trust boundaries

The issue, repository, contribution documents, package metadata, command output, and model output are
all untrusted. Repository text is quoted as data in prompts and cannot change the control policy.
Model output must match strict Pydantic schemas. File edits use exact, unique search/replace operations
and paths that cannot escape the workspace.

Model and GitHub credentials exist only in the control process. Docker receives a read/write bind of
the target working tree, a read-only `.git` directory, a fresh temporary home, no inherited
environment, no network, no capabilities, no Docker socket, and explicit CPU/memory/PID/time limits.
Local command execution is rejected unless the user opts into `allow_unsafe_local: true`.

The publication broker is the only component with GitHub mutation methods. The model cannot invoke
it. In review mode, the broker requires an unexpired user approval over a canonical hash of the
repository, issue, base SHA, patch bytes, commit message, PR title/body, and disclosure.

## Run state

```text
queued -> discovering -> candidate_selected -> eligibility_checked -> planning
       -> implementing -> validating -> critiquing -> ready_for_approval
       -> approved -> submitting -> pr_open

Normal side exits: skipped, rejected, cancelled, failed
```

The critic may trigger one bounded `critiquing -> implementing` repair loop. Every transition is
persisted before subsequent work. Events form a per-run SHA-256 hash chain. GitHub publication uses a
stable branch, records mutation intent before the first write, never force-pushes, and reconciles an
existing branch/PR after uncertain failures.

## Model boundary

`ModelProvider.generate()` accepts instructions, one evidence prompt, and an output type. The OpenAI
adapter uses the Responses API and native Structured Outputs. The compatible adapter requires Chat
Completions servers with strict JSON Schema support; critical stages do not fall back to “please emit
JSON.” Reasoning effort is forwarded to compatible endpoints, but the Responses-specific `pro` mode
is rejected because it cannot be enforced portably. Scout, builder, and critic are stateless calls,
and critic uses a separate profile and fresh context.

Current OpenAI implementation choices follow the official documentation:

- [Latest model guidance](https://developers.openai.com/api/docs/guides/latest-model)
- [Responses API migration](https://developers.openai.com/api/docs/guides/migrate-to-responses)
- [Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs)
- [Reasoning models](https://developers.openai.com/api/docs/guides/reasoning)
- [Production best practices](https://developers.openai.com/api/docs/guides/production-best-practices)

## Deliberate MVP boundaries

The alpha is a single-user worker, not a multi-tenant service. It does not autonomously comment,
reply to reviews, sign a DCO, accept a CLA, report security issues, merge code, or browse arbitrary
websites. Dependency acquisition is not run with open network access; users should provide a pinned
sandbox image containing the target project's toolchain and dependencies. Unsupported validation
means rejection, not a waived check.
