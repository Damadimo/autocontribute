"""Bounded discovery-to-approval orchestration with no implicit GitHub writes."""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import asdict
from datetime import timedelta
from decimal import ROUND_FLOOR, Decimal
from typing import Literal, TypeVar, cast

from pydantic import BaseModel

from autocontribute.config import AutocontributeConfig, ModelProfile
from autocontribute.context import (
    issue_search_queries,
    plan_search_queries,
    rank_matching_paths,
    render_text_matches,
)
from autocontribute.coordination import LeaseHeartbeatGuard
from autocontribute.deployment import compute_deployment_fingerprint
from autocontribute.discovery import DiscoveryService, parse_issue_reference
from autocontribute.domain import (
    CommandResult,
    ContributionPlan,
    CriticReview,
    IssueCandidate,
    ModelBudgetReservation,
    PatchProposal,
    RunManifest,
    RunStatus,
    utc_now,
)
from autocontribute.exceptions import (
    AutocontributeError,
    CircuitBreakerTrigger,
    PolicyError,
    RepositoryError,
    StateError,
)
from autocontribute.github import GitHubClient
from autocontribute.pr_template import select_pull_request_template, validate_pull_request_template
from autocontribute.preparation import (
    compute_preparation_config_fingerprint,
    compute_preparation_fingerprint,
    render_validation_artifact,
)
from autocontribute.prompts import (
    BUILDER_INSTRUCTIONS,
    CRITIC_INSTRUCTIONS,
    PLANNER_INSTRUCTIONS,
    implementation_prompt,
    planning_prompt,
    repair_prompt,
    review_prompt,
)
from autocontribute.providers import ModelProvider, ModelResult, create_provider
from autocontribute.publication import has_visible_disclosure, validate_publication_text
from autocontribute.quality import QualityEvaluator, secret_findings
from autocontribute.redaction import redact_model_input, redact_text, truncate_artifact
from autocontribute.reporting import render_run_report
from autocontribute.repository import ContextEntry, RepositoryWorkspace, TextMatch
from autocontribute.sandbox import SandboxRunner
from autocontribute.store import RunStore

OutputT = TypeVar("OutputT", bound=BaseModel)
ProviderFactory = Callable[[object], ModelProvider]

_WORD = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{2,}")
_RUN_LEASE_TTL = timedelta(minutes=5)
_RUN_HEARTBEAT_INTERVAL = timedelta(minutes=1)
_STALE_RUN_AGE = timedelta(hours=2)


class Orchestrator:
    """Prepare at most one evidence-backed contribution attempt."""

    def __init__(
        self,
        config: AutocontributeConfig,
        *,
        store: RunStore | None = None,
        github: GitHubClient | None = None,
        providers: Mapping[str, ModelProvider] | None = None,
        provider_factory: ProviderFactory | None = None,
        sandbox: SandboxRunner | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.config = config
        self.store = store or RunStore(config.storage.path)
        self.github = github or GitHubClient(
            config.github,
            safety_trigger_handler=self.store.trip_circuit_breaker_trigger,
        )
        if isinstance(self.github, GitHubClient):
            self.github.bind_safety_trigger_handler(self.store.trip_circuit_breaker_trigger)
        self._owns_github = github is None
        self._providers = dict(providers or {})
        self._owned_provider_roles: set[str] = set()
        self._closed_provider_ids: set[int] = set()
        self._provider_factory = provider_factory or cast("ProviderFactory", create_provider)
        self.sandbox = sandbox or SandboxRunner(config.sandbox)
        self._clock = clock or time.monotonic
        self._model_events: list[dict[str, object]] = []
        self._lease_guard: LeaseHeartbeatGuard | None = None

    def close(self) -> None:
        errors: list[Exception] = []
        for role in sorted(self._owned_provider_roles):
            provider = self._providers.get(role)
            if provider is None or id(provider) in self._closed_provider_ids:
                continue
            close = getattr(provider, "close", None)
            if not callable(close):
                close = getattr(getattr(provider, "client", None), "close", None)
            try:
                if callable(close):
                    close()
            except Exception as exc:  # pragma: no cover - provider-specific cleanup failures
                errors.append(exc)
            finally:
                self._closed_provider_ids.add(id(provider))
        if self._owns_github:
            try:
                self.github.close()
            except Exception as exc:  # pragma: no cover - transport-specific cleanup failures
                errors.append(exc)
        if errors:
            raise errors[0]

    def __enter__(self) -> Orchestrator:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def run(self, *, issue_reference: str | None = None) -> RunManifest:
        self._model_events = []
        self.store.assert_circuit_breaker_clear()
        with LeaseHeartbeatGuard(
            self.store,
            "autocontribute.run",
            ttl=_RUN_LEASE_TTL,
            heartbeat_interval=_RUN_HEARTBEAT_INTERVAL,
        ) as guard:
            self._lease_guard = guard
            try:
                self._assert_operational()
                self.store.recover_stale_runs(
                    stale_before=utc_now() - _STALE_RUN_AGE,
                    reason="A previous worker stopped before completing this preparation run.",
                )
                self._assert_operational()
                manifest = self.store.create_run(
                    deployment_fingerprint=compute_deployment_fingerprint(self.config)
                )
                commands: list[CommandResult] = []
                try:
                    manifest = self._prepare(
                        manifest,
                        issue_reference=issue_reference,
                        commands=commands,
                    )
                except Exception as exc:
                    self._assert_run_lease_owned()
                    safe_error = self._safe_error(exc)
                    manifest.error = safe_error
                    allowed = RunStatus.FAILED in self._allowed_targets(manifest)
                    if allowed:
                        self._assert_run_lease_owned()
                        self.store.transition(manifest, RunStatus.FAILED, reason=safe_error)
                    else:
                        manifest.status = RunStatus.FAILED
                        self._assert_run_lease_owned()
                        self.store.save(manifest, event="run.failed", details={"error": safe_error})
                finally:
                    self._assert_run_lease_owned()
                    self._write_artifacts(manifest, commands)
                return manifest
            finally:
                self._lease_guard = None

    def _prepare(
        self,
        manifest: RunManifest,
        *,
        issue_reference: str | None,
        commands: list[CommandResult],
    ) -> RunManifest:
        self._assert_operational()
        self.store.transition(manifest, RunStatus.DISCOVERING, reason="starting candidate search")
        discovery = DiscoveryService(self.config, self.github, self.store)

        if issue_reference:
            repository_name, issue_number = parse_issue_reference(issue_reference)
            self._require_configured_target(repository_name)
            repository = self.github.get_repository(repository_name)
            self._require_configured_target(repository.full_name)
            issue = self.github.get_issue(repository.full_name, issue_number)
            if issue.repository.casefold() != repository.full_name.casefold():
                raise PolicyError("Pinned issue resolved outside its configured repository")
            base_sha = self.github.default_branch_sha(
                repository.full_name,
                repository.default_branch,
            )
            eligibility = discovery.evaluate(
                issue,
                repository,
                repository_ref=base_sha,
            )
        else:
            selection = discovery.discover()
            if selection is None:
                manifest.skip_reason = "No candidate passed deterministic discovery gates."
                self._assert_operational()
                self.store.transition(manifest, RunStatus.SKIPPED, reason=manifest.skip_reason)
                return manifest
            issue, repository, eligibility = selection
            base_sha = discovery.pinned_repository_ref(repository.full_name)

        self._assert_operational()
        issue.score = eligibility.score
        issue.score_evidence = eligibility.evidence
        manifest.candidate = issue
        manifest.repository = repository
        self._assert_operational()
        self.store.save(
            manifest,
            event="candidate.selected",
            details={"issue": issue.reference, "score": str(eligibility.score)},
        )
        self._assert_operational()
        self.store.transition(
            manifest,
            RunStatus.CANDIDATE_SELECTED,
            reason=f"selected {issue.reference}",
        )
        manifest.eligibility = eligibility
        self._assert_operational()
        self.store.save(
            manifest,
            event="candidate.evaluated",
            details={"eligible": str(eligibility.eligible), "score": str(eligibility.score)},
        )
        if not eligibility.eligible:
            manifest.skip_reason = "; ".join(eligibility.blockers)
            self._assert_operational()
            self.store.transition(manifest, RunStatus.SKIPPED, reason=manifest.skip_reason)
            return manifest
        self._assert_operational()
        self.store.transition(
            manifest,
            RunStatus.ELIGIBILITY_CHECKED,
            reason="candidate passed deterministic eligibility",
        )

        required_validation_commands = self.config.validation.commands_for(repository.full_name)
        if not required_validation_commands:
            raise PolicyError(
                "Repository has no operator-owned validation.required_commands entry: "
                f"{repository.full_name}"
            )

        self._assert_operational()
        manifest.base_sha = base_sha
        self._assert_operational()
        workspace_root = self.store.workspace_dir(manifest.run_id) / "repository"
        self._assert_operational()
        workspace = RepositoryWorkspace.clone(
            repository.clone_url,
            base_sha,
            workspace_root,
        )
        self._assert_operational()
        guidance = workspace.guidance(max_characters=80_000)
        if select_pull_request_template(guidance) is None:
            guidance = {
                **discovery.organization_pull_request_templates(repository.full_name),
                **guidance,
            }
        self._assert_operational()
        index = self._render_index(
            workspace.context_index(), issue_text=f"{issue.title} {issue.body}"
        )
        initial_matches = self._search_context(workspace, issue_search_queries(issue))

        self._assert_operational()
        self.store.transition(manifest, RunStatus.PLANNING, reason="building a bounded plan")
        plan_result = self._call_model(
            manifest,
            role="scout",
            instructions=PLANNER_INSTRUCTIONS,
            prompt=planning_prompt(
                issue,
                repository,
                guidance=guidance,
                repository_index=index,
                repository_references=render_text_matches(initial_matches),
            ),
            output_type=ContributionPlan,
        )
        plan = plan_result.output
        manifest.plan = plan
        self._assert_operational()
        self.store.save(
            manifest,
            event="plan.created",
            details={"decision": plan.decision, "reason": plan.decision_reason},
        )
        if plan.decision == "skip":
            manifest.skip_reason = plan.decision_reason
            self._assert_operational()
            self.store.transition(manifest, RunStatus.SKIPPED, reason=plan.decision_reason)
            return manifest

        context_paths, context_matches = self._expanded_context_paths(
            workspace,
            issue=issue,
            plan=plan,
            initial_matches=initial_matches,
        )
        selected_files = self._read_context(
            workspace,
            context_paths,
            required_paths=plan.files_to_read,
        )
        context_search = redact_text(
            render_text_matches(context_matches) + "\n",
            secret_env_names=self._secret_env_names(),
        )
        self._assert_operational()
        self.store.write_artifact(
            manifest.run_id,
            "context-search.txt",
            context_search,
        )
        if plan.contribution_kind == "bugfix":
            if not plan.reproduction_command:
                raise PolicyError("Bugfix plan omitted a baseline reproduction command")
            manifest.baseline_validation = self._run_command_isolated(
                workspace, plan.reproduction_command
            )
            self._assert_operational()
            self.store.save(
                manifest,
                event="baseline.reproduced",
                details={
                    "command": plan.reproduction_command,
                    "failed_as_expected": str(not manifest.baseline_validation.passed),
                },
            )
        self._assert_operational()
        self.store.transition(manifest, RunStatus.IMPLEMENTING, reason="applying exact model edits")
        proposal_result = self._call_model(
            manifest,
            role="builder",
            instructions=BUILDER_INSTRUCTIONS,
            prompt=implementation_prompt(
                issue,
                plan,
                guidance=guidance,
                files=selected_files,
            ),
            output_type=PatchProposal,
        )
        proposal = self._with_disclosure(proposal_result.output)
        manifest.proposal = proposal
        validate_publication_text(manifest)
        validate_pull_request_template(proposal.pull_request_body, guidance)
        self._assert_operational()
        workspace.apply_edits(proposal.edits)
        self._stop_for_secret_findings(manifest, workspace, workspace.diff())
        self._assert_operational()
        self.store.save(
            manifest,
            event="patch.applied",
            details={"changed_paths": ",".join(workspace.changed_paths())},
        )

        self._assert_operational()
        self.store.transition(manifest, RunStatus.VALIDATING, reason="running isolated checks")
        commands[:] = self._validate(
            workspace,
            plan,
            proposal,
            required_commands=required_validation_commands,
        )
        manifest.patched_validation = list(commands)
        self._assert_operational()
        self.store.save(
            manifest,
            event="validation.completed",
            details={
                "passed": str(all(result.passed for result in commands)),
                "commands": str(len(commands)),
            },
        )

        self._assert_operational()
        self.store.transition(manifest, RunStatus.CRITIQUING, reason="fresh-context review")
        review = self._review(manifest, workspace, guidance, commands)

        if (
            review.verdict == "reject"
            and review.blocking_findings
            and all(result.passed for result in commands)
            and self._has_model_capacity(manifest, ("builder", "critic"))
        ):
            self._assert_operational()
            self.store.transition(
                manifest,
                RunStatus.IMPLEMENTING,
                reason="one bounded repair pass for critic blockers",
            )
            current_files = self._read_context(
                workspace,
                list(dict.fromkeys([*plan.files_to_read, *workspace.changed_paths()])),
            )
            repair_result = self._call_model(
                manifest,
                role="builder",
                instructions=BUILDER_INSTRUCTIONS,
                prompt=repair_prompt(
                    issue,
                    plan,
                    guidance=guidance,
                    files=current_files,
                    current_diff=workspace.diff(),
                    blocking_findings=review.blocking_findings,
                ),
                output_type=PatchProposal,
            )
            proposal = self._with_disclosure(repair_result.output)
            manifest.proposal = proposal
            validate_publication_text(manifest)
            validate_pull_request_template(proposal.pull_request_body, guidance)
            self._assert_operational()
            workspace.apply_edits(proposal.edits)
            self._stop_for_secret_findings(manifest, workspace, workspace.diff())
            self._assert_operational()
            self.store.transition(
                manifest,
                RunStatus.VALIDATING,
                reason="revalidating repaired patch",
            )
            commands[:] = self._validate(
                workspace,
                plan,
                proposal,
                required_commands=required_validation_commands,
            )
            manifest.patched_validation = list(commands)
            self._assert_operational()
            self.store.transition(
                manifest,
                RunStatus.CRITIQUING,
                reason="reviewing repaired patch from fresh evidence",
            )
            review = self._review(manifest, workspace, guidance, commands)

        diff = workspace.diff()
        quality = QualityEvaluator(self.config).evaluate(
            diff=diff,
            command_results=commands,
            required_commands=required_validation_commands,
            review=review,
            baseline_result=manifest.baseline_validation,
            contribution_kind=plan.contribution_kind,
        )
        manifest.quality = quality
        self._stop_for_secret_findings(manifest, workspace, diff)
        self._assert_operational()
        patch_path = self.store.write_artifact(manifest.run_id, "contribution.patch", diff)
        self._assert_operational()
        self.store.save(
            manifest,
            event="quality.evaluated",
            details={
                "ready": str(quality.ready),
                "score": str(quality.readiness_score),
                "failed_gates": ",".join(gate.gate for gate in quality.failed_gates),
            },
        )
        if not quality.ready:
            reason = ", ".join(gate.gate for gate in quality.failed_gates)
            self._assert_operational()
            self.store.transition(
                manifest,
                RunStatus.REJECTED,
                reason=f"quality gates failed: {reason}",
            )
            return manifest

        manifest.preparation_config_fingerprint = compute_preparation_config_fingerprint(
            self.config,
            repository=repository.full_name,
        )
        manifest.preparation_fingerprint = compute_preparation_fingerprint(
            manifest,
            diff=patch_path.read_bytes(),
        )
        self._assert_operational()
        self.store.transition(
            manifest,
            RunStatus.READY_FOR_APPROVAL,
            reason=f"all gates passed at readiness {quality.readiness_score}",
        )
        return manifest

    def _review(
        self,
        manifest: RunManifest,
        workspace: RepositoryWorkspace,
        guidance: Mapping[str, str],
        commands: list[CommandResult],
    ) -> CriticReview:
        assert manifest.candidate is not None and manifest.plan is not None
        assert manifest.proposal is not None
        affected_paths, _ = self._expanded_context_paths(
            workspace,
            issue=manifest.candidate,
            plan=manifest.plan,
            initial_matches=[],
            changed_paths=workspace.changed_paths(),
        )
        affected_context = self._read_context(
            workspace,
            affected_paths,
            required_paths=[
                path
                for path in manifest.plan.files_to_read
                if path not in workspace.changed_paths()
            ],
        )
        result = self._call_model(
            manifest,
            role="critic",
            instructions=CRITIC_INSTRUCTIONS,
            prompt=review_prompt(
                manifest.candidate,
                manifest.plan,
                guidance=guidance,
                diff=workspace.diff(),
                command_results=commands,
                baseline_result=manifest.baseline_validation,
                affected_context=affected_context,
                publication_text={
                    "commit_message": manifest.proposal.commit_message,
                    "pull_request_title": manifest.proposal.pull_request_title,
                    "pull_request_body": manifest.proposal.pull_request_body,
                },
            ),
            output_type=CriticReview,
        )
        return result.output

    def _validate(
        self,
        workspace: RepositoryWorkspace,
        plan: ContributionPlan,
        proposal: PatchProposal,
        *,
        required_commands: Sequence[str],
    ) -> list[CommandResult]:
        self._assert_operational()
        commands = list(
            dict.fromkeys(
                [
                    *required_commands,
                    *([plan.reproduction_command] if plan.reproduction_command else []),
                    *plan.validation_commands,
                    *proposal.validation_commands,
                ]
            )
        )
        if not commands:
            raise PolicyError("No operator-owned validation commands are configured")
        remaining = getattr(self.sandbox, "remaining_commands", self.config.sandbox.max_commands)
        if len(commands) > remaining:
            raise PolicyError(
                f"Complete validation suite requires {len(commands)} command(s), but only "
                f"{remaining} sandbox command(s) remain; refusing to truncate validation"
            )
        results = self.sandbox.run_all_isolated(workspace, commands, stop_on_failure=True)
        self._assert_operational()
        return [self._scrub_command(result) for result in results]

    def _run_command_isolated(self, workspace: RepositoryWorkspace, command: str) -> CommandResult:
        self._assert_operational()
        result = self._scrub_command(self.sandbox.run_isolated(workspace, command))
        self._assert_operational()
        return result

    def _scrub_command(self, result: CommandResult) -> CommandResult:
        secret_names = self._secret_env_names()
        return result.model_copy(
            update={
                "stdout": truncate_artifact(
                    redact_text(result.stdout, secret_env_names=secret_names)
                ),
                "stderr": truncate_artifact(
                    redact_text(result.stderr, secret_env_names=secret_names)
                ),
            }
        )

    def _call_model(
        self,
        manifest: RunManifest,
        *,
        role: Literal["scout", "builder", "critic"],
        instructions: str,
        prompt: str,
        output_type: type[OutputT],
    ) -> ModelResult[OutputT]:
        self._assert_operational()
        if manifest.model_reservation is not None:
            raise PolicyError("A previous model-call reservation is still unresolved")
        if manifest.model_calls >= self.config.budget.max_model_calls_per_run:
            raise PolicyError("Model-call budget exhausted")

        profile = self.config.model_for(role)
        input_reservation = self._input_token_reservation(
            profile,
            instructions=instructions,
            prompt=prompt,
            output_type=output_type,
        )
        remaining_input = self.config.budget.max_input_tokens_per_run - manifest.model_input_tokens
        if input_reservation > remaining_input:
            raise PolicyError("Aggregate model input-token budget exhausted")

        remaining_output = (
            self.config.budget.max_output_tokens_per_run - manifest.model_output_tokens
        )
        if remaining_output < 1:
            raise PolicyError("Aggregate model output-token budget exhausted")
        output_limit = min(profile.max_output_tokens, remaining_output)

        remaining_seconds = self.config.budget.max_model_seconds_per_run - manifest.model_seconds
        if remaining_seconds <= 0:
            raise PolicyError("Aggregate model wall-clock budget exhausted")
        timeout_seconds = min(profile.timeout_seconds, remaining_seconds)

        reservation_cost = Decimal("0")
        cost_is_known = profile.pricing is not None
        if profile.pricing is not None:
            cost_limit = self.config.budget.max_model_cost_usd_per_run
            if cost_limit is not None:
                remaining_cost = cost_limit - manifest.model_cost_usd
                input_cost = profile.pricing.upper_bound_cost(
                    input_tokens=input_reservation,
                    output_tokens=0,
                )
                affordable_output_cost = remaining_cost - input_cost
                if affordable_output_cost <= 0:
                    raise PolicyError("Aggregate model cost budget exhausted")
                affordable_output = int(
                    (
                        affordable_output_cost
                        * Decimal(1_000_000)
                        / profile.pricing.output_usd_per_million_tokens
                    ).to_integral_value(rounding=ROUND_FLOOR)
                )
                if affordable_output < 1:
                    raise PolicyError("Aggregate model cost budget exhausted")
                output_limit = min(output_limit, affordable_output)
            reservation_cost = profile.pricing.upper_bound_cost(
                input_tokens=input_reservation,
                output_tokens=output_limit,
            )

        manifest.model_calls += 1
        manifest.model_reservation = ModelBudgetReservation(
            call=manifest.model_calls,
            role=role,
            input_tokens=input_reservation,
            output_tokens=output_limit,
            cost_usd=reservation_cost,
            timeout_seconds=timeout_seconds,
            started_at=utc_now(),
        )
        self._assert_operational()
        self.store.save(
            manifest,
            event="model.call.started",
            details={
                "role": role,
                "call": str(manifest.model_calls),
                "reserved_input_tokens": str(input_reservation),
                "reserved_output_tokens": str(output_limit),
                "reserved_cost_usd": str(reservation_cost) if cost_is_known else "unknown",
                "timeout_seconds": str(timeout_seconds),
            },
        )
        provider = self._providers.get(role)
        if provider is None:
            provider = self._provider_factory(profile)
            self._providers[role] = provider
            self._owned_provider_roles.add(role)
        started = self._clock()
        try:
            result = provider.generate(
                instructions=instructions,
                prompt=prompt,
                output_type=output_type,
                max_output_tokens=output_limit,
                timeout_seconds=timeout_seconds,
            )
        except Exception:
            self._assert_run_lease_owned()
            elapsed = max(0.0, self._clock() - started)
            manifest.model_seconds += elapsed
            self._assert_run_lease_owned()
            self.store.save(
                manifest,
                event="model.call.failed",
                details={
                    "role": role,
                    "call": str(manifest.model_calls),
                    "elapsed_seconds": str(elapsed),
                    "reservation_retained": "true",
                },
            )
            raise

        self._assert_run_lease_owned()
        elapsed = max(0.0, self._clock() - started)
        usage = result.usage
        usage_error = self._model_usage_error(usage)
        charged_input_tokens = max(usage.input_tokens, 0)
        charged_output_tokens = max(usage.output_tokens, 0)
        actual_cost = Decimal("0")
        if usage_error is not None:
            charged_input_tokens = max(charged_input_tokens, input_reservation)
            charged_output_tokens = max(charged_output_tokens, output_limit)
            actual_cost = reservation_cost
        elif profile.pricing is not None:
            actual_cost = profile.pricing.cost(
                input_tokens=usage.input_tokens,
                cached_input_tokens=usage.cached_input_tokens,
                cache_write_tokens=usage.cache_write_tokens,
                output_tokens=usage.output_tokens,
            )
        manifest.model_input_tokens += charged_input_tokens
        manifest.model_output_tokens += charged_output_tokens
        manifest.model_cost_usd += actual_cost
        manifest.model_seconds += elapsed
        manifest.model_reservation = None

        violations = [usage_error] if usage_error else []
        if profile.deployment_model is not None and result.model != profile.deployment_model:
            violations.append("provider resolved a model ID outside the calibrated deployment")
        if usage.input_tokens > input_reservation:
            violations.append("provider input usage exceeded its durable reservation")
        if usage.output_tokens > output_limit:
            violations.append("provider output usage exceeded its durable reservation")
        if manifest.model_input_tokens > self.config.budget.max_input_tokens_per_run:
            violations.append("aggregate model input-token budget exceeded")
        if manifest.model_output_tokens > self.config.budget.max_output_tokens_per_run:
            violations.append("aggregate model output-token budget exceeded")
        if manifest.model_seconds > self.config.budget.max_model_seconds_per_run:
            violations.append("aggregate model wall-clock budget exceeded")
        cost_limit = self.config.budget.max_model_cost_usd_per_run
        if cost_limit is not None and manifest.model_cost_usd > cost_limit:
            violations.append("aggregate model cost budget exceeded")

        self._model_events.append(
            {
                "role": role,
                "response_id": result.response_id,
                "model": result.model,
                "usage": asdict(result.usage),
                "cost_usd": str(actual_cost) if cost_is_known else "unknown",
                "elapsed_seconds": elapsed,
            }
        )
        self._assert_run_lease_owned()
        self.store.save(
            manifest,
            event="model.call.budget_exceeded" if violations else "model.call.completed",
            details={
                "role": role,
                "response_id": result.response_id,
                "model": result.model,
                "input_tokens": str(result.usage.input_tokens),
                "output_tokens": str(result.usage.output_tokens),
                "total_tokens": str(result.usage.total_tokens),
                "cost_usd": str(actual_cost) if cost_is_known else "unknown",
                "elapsed_seconds": str(elapsed),
                "budget_violations": "; ".join(violations),
            },
        )
        if violations:
            raise PolicyError("; ".join(violations))
        self._assert_operational()
        return result

    def _input_token_reservation(
        self,
        profile: ModelProfile,
        *,
        instructions: str,
        prompt: str,
        output_type: type[BaseModel],
    ) -> int:
        """Return a tokenizer-independent byte ceiling for all model-controlled request text."""

        secret_names = (profile.api_key_env,)
        safe_instructions = redact_model_input(instructions, secret_env_names=secret_names)
        safe_prompt = redact_model_input(prompt, secret_env_names=secret_names)
        schema = json.dumps(
            output_type.model_json_schema(),
            sort_keys=True,
            separators=(",", ":"),
        )
        envelope_bytes = sum(
            len(value.encode("utf-8")) for value in (safe_instructions, safe_prompt, schema)
        )
        reservation = max(1, envelope_bytes + 1_024)
        if reservation > profile.max_input_tokens:
            raise PolicyError(
                f"Model request needs a {reservation}-token conservative input reservation, "
                f"above the {profile.max_input_tokens}-token profile ceiling"
            )
        return reservation

    @staticmethod
    def _model_usage_error(usage: object) -> str | None:
        fields = (
            "input_tokens",
            "cached_input_tokens",
            "cache_write_tokens",
            "output_tokens",
            "reasoning_tokens",
            "total_tokens",
        )
        counts: dict[str, int] = {}
        for field in fields:
            value = getattr(usage, field, None)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                return f"model provider returned invalid usage field: {field}"
            counts[field] = value
        if counts["cached_input_tokens"] + counts["cache_write_tokens"] > counts["input_tokens"]:
            return "model provider returned input-token details above input_tokens"
        if counts["reasoning_tokens"] > counts["output_tokens"]:
            return "model provider returned reasoning_tokens above output_tokens"
        if counts["total_tokens"] != counts["input_tokens"] + counts["output_tokens"]:
            return "model provider returned inconsistent total_tokens"
        return None

    def _has_model_capacity(
        self,
        manifest: RunManifest,
        roles: Sequence[Literal["scout", "builder", "critic"]],
    ) -> bool:
        """Conservatively decide whether an optional multi-call repair can finish."""

        if manifest.model_reservation is not None:
            return False
        if manifest.model_calls + len(roles) > self.config.budget.max_model_calls_per_run:
            return False
        profiles = [self.config.model_for(role) for role in roles]
        if manifest.model_input_tokens + sum(profile.max_input_tokens for profile in profiles) > (
            self.config.budget.max_input_tokens_per_run
        ):
            return False
        if manifest.model_output_tokens + sum(profile.max_output_tokens for profile in profiles) > (
            self.config.budget.max_output_tokens_per_run
        ):
            return False
        if manifest.model_seconds + sum(profile.timeout_seconds for profile in profiles) > (
            self.config.budget.max_model_seconds_per_run
        ):
            return False
        cost_limit = self.config.budget.max_model_cost_usd_per_run
        if cost_limit is None:
            return True
        maximum_cost = manifest.model_cost_usd
        for profile in profiles:
            if profile.pricing is None:  # guarded by configuration validation
                return False
            maximum_cost += profile.pricing.upper_bound_cost(
                input_tokens=profile.max_input_tokens,
                output_tokens=profile.max_output_tokens,
            )
        return maximum_cost <= cost_limit

    def _read_context(
        self,
        workspace: RepositoryWorkspace,
        paths: list[str],
        *,
        required_paths: Sequence[str] | None = None,
    ) -> dict[str, str]:
        unique = list(dict.fromkeys(paths))
        if len(unique) > self.config.quality.max_context_files:
            raise PolicyError(
                f"Plan requested {len(unique)} files; maximum is "
                f"{self.config.quality.max_context_files}"
            )
        remaining = self.config.quality.max_context_characters
        files: dict[str, str] = {}
        required = {path.casefold() for path in (required_paths or paths)}
        for path in unique:
            try:
                content = workspace.read_file(path, max_bytes=max(remaining, 1))
            except RepositoryError:
                if path.casefold() in required:
                    raise
                continue
            if len(content) > remaining:
                if path.casefold() in required:
                    raise PolicyError(
                        "Selected repository context exceeds configured character budget"
                    )
                continue
            files[path] = content
            remaining -= len(content)
        if not files:
            raise RepositoryError("Plan selected no repository files")
        return files

    def _search_context(
        self,
        workspace: RepositoryWorkspace,
        queries: Sequence[str],
    ) -> list[TextMatch]:
        if not queries:
            return []
        return workspace.search_text(queries, max_matches=160, max_total_bytes=32_000_000)

    def _expanded_context_paths(
        self,
        workspace: RepositoryWorkspace,
        *,
        issue: IssueCandidate,
        plan: ContributionPlan,
        initial_matches: Sequence[TextMatch],
        changed_paths: Sequence[str] = (),
    ) -> tuple[list[str], list[TextMatch]]:
        matches = [
            *initial_matches,
            *self._search_context(workspace, plan_search_queries(issue, plan)),
        ]
        required_paths = list(dict.fromkeys([*plan.files_to_read, *changed_paths]))
        additional_limit = max(0, self.config.quality.max_context_files - len(required_paths))
        additional = (
            rank_matching_paths(
                matches,
                exclude=required_paths,
                limit=additional_limit,
            )
            if additional_limit
            else []
        )
        return [*required_paths, *additional], matches

    def _assert_operational(self) -> None:
        self.store.assert_circuit_breaker_clear()
        self._assert_run_lease_owned()

    def _stop_for_secret_findings(
        self,
        manifest: RunManifest,
        workspace: RepositoryWorkspace,
        diff: str,
    ) -> None:
        findings = secret_findings(diff)
        if not findings:
            return
        safe_evidence = ", ".join(findings)
        manifest.proposal = None
        self.store.trip_circuit_breaker_trigger(
            CircuitBreakerTrigger(
                source=f"secret_scanner:{manifest.run_id}",
                reason=(
                    "The deterministic patch secret scanner found credential-like material; "
                    f"matched values were not retained. Findings: {safe_evidence}"
                ),
                trigger_hash=hashlib.sha256(
                    json.dumps(
                        {
                            "diff_sha256": hashlib.sha256(diff.encode()).hexdigest(),
                            "findings": findings,
                            "run_id": manifest.run_id,
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode()
                ).hexdigest(),
            )
        )
        with suppress(RepositoryError):
            workspace.discard()
        raise StateError("A secret-scanner finding activated the global circuit breaker")

    def _assert_run_lease_owned(self) -> None:
        """Fence durable run writes without blocking failure bookkeeping on a safety stop."""

        if self._lease_guard is not None:
            self._lease_guard.assert_owned()

    def _render_index(self, entries: list[ContextEntry], *, issue_text: str) -> str:
        incomplete = [entry.path for entry in entries if not entry.content_inspected]
        if incomplete:
            raise PolicyError(
                "Repository index exceeded configured byte limits; context is incomplete at "
                f"{incomplete[0]}"
            )
        terms = {word.casefold() for word in _WORD.findall(issue_text) if len(word) >= 4}

        def relevance(entry: ContextEntry) -> tuple[int, str]:
            path = entry.path.casefold()
            matches = sum(term in path for term in terms)
            return (-matches, entry.path)

        ranked = sorted(entries, key=relevance)
        lines = [
            f"{entry.path}\t{entry.size} bytes\t"
            f"{'binary' if entry.binary else f'{entry.lines or 0} lines'}"
            for entry in ranked
        ]
        rendered = "\n".join(lines)
        if len(rendered) > 140_000:
            raise PolicyError(
                "Repository index exceeds the safe prompt limit; context would be incomplete"
            )
        return rendered

    def _with_disclosure(self, proposal: PatchProposal) -> PatchProposal:
        disclosure = self.config.policy.ai_disclosure.strip()
        if not disclosure:
            raise PolicyError("policy.ai_disclosure cannot be blank")
        if has_visible_disclosure(proposal.pull_request_body, disclosure):
            return proposal
        return proposal.model_copy(
            update={
                "pull_request_body": proposal.pull_request_body.rstrip()
                + "\n\n---\n\n"
                + disclosure
            }
        )

    def _write_artifacts(self, manifest: RunManifest, commands: list[CommandResult]) -> None:
        secret_names = self._secret_env_names()
        validation_artifact = redact_text(
            render_validation_artifact(manifest),
            secret_env_names=secret_names,
        )
        self._assert_run_lease_owned()
        self.store.write_artifact(
            manifest.run_id,
            "validation.json",
            validation_artifact,
        )
        model_events_artifact = json.dumps(self._model_events, indent=2, sort_keys=True) + "\n"
        self._assert_run_lease_owned()
        self.store.write_artifact(
            manifest.run_id,
            "model-calls.json",
            model_events_artifact,
        )
        report_artifact = redact_text(
            render_run_report(
                manifest,
                commands,
                model_cost_known=all(
                    profile.pricing is not None
                    for profile in (
                        self.config.models.scout,
                        self.config.models.builder,
                        self.config.models.critic,
                    )
                ),
            ),
            secret_env_names=secret_names,
        )
        self._assert_run_lease_owned()
        self.store.write_artifact(
            manifest.run_id,
            "report.md",
            report_artifact,
        )

    def _secret_env_names(self) -> set[str]:
        return {
            self.config.github.token_env,
            self.config.models.scout.api_key_env,
            self.config.models.builder.api_key_env,
            self.config.models.critic.api_key_env,
        }

    def _require_configured_target(self, repository: str) -> None:
        normalized = repository.casefold()
        repositories = {item.casefold() for item in self.config.github.repositories}
        owners = {item.casefold() for item in self.config.github.owners}
        owner = normalized.split("/", 1)[0]
        if normalized not in repositories and owner not in owners:
            raise PolicyError(
                f"Repository {repository} is not in github.repositories or an allowed owner"
            )

    def _safe_error(self, exc: Exception) -> str:
        if isinstance(exc, AutocontributeError):
            message = str(exc)
        else:
            message = f"Unexpected {type(exc).__name__}: {exc}"
        return truncate_artifact(
            redact_text(message, secret_env_names=self._secret_env_names()), limit=4_000
        )

    @staticmethod
    def _allowed_targets(manifest: RunManifest) -> set[RunStatus]:
        from autocontribute.domain import ALLOWED_TRANSITIONS

        return ALLOWED_TRANSITIONS.get(manifest.status, set())


__all__ = ["Orchestrator"]
