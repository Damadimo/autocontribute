"""Bounded discovery-to-approval orchestration with no implicit GitHub writes.

One run picks and claims an issue, sets up the repository's test environment, lets the agent fix
the issue in a network-less session, has a fresh critic review every fix that passed its checks,
and assembles the pull request text (DESIGN §1). It ends ready for approval, or skipped, rejected
or failed. Nothing reaches GitHub without a person's approval of the exact result.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from contextlib import suppress
from datetime import timedelta
from enum import StrEnum

from autocontribute import __version__
from autocontribute.agent_loop import (
    DidNotFinish,
    LoopFailure,
    SkippedIssue,
    Solver,
    SolverOutcome,
    SubmittedFix,
)
from autocontribute.agent_tools import SessionTools
from autocontribute.ai_policy import RepositoryAiPolicy
from autocontribute.budget import RunBudget, daily_budget_allows_run
from autocontribute.config import AutocontributeConfig, ResolvedModels
from autocontribute.coordination import LeaseHeartbeatGuard
from autocontribute.critic import Critic, CriticRound
from autocontribute.discovery import (
    AI_POLICY_EVIDENCE_KEY,
    DiscoveryService,
    apply_legal_commit_message,
    parse_issue_reference,
)
from autocontribute.domain import (
    ALLOWED_TRANSITIONS,
    EligibilityResult,
    PatchProposal,
    QualityReport,
    RunEnvironment,
    RunManifest,
    RunModels,
    RunStatus,
    utc_now,
)
from autocontribute.environment_builder import EnvironmentBuilder, PreparedEnvironment
from autocontribute.evidence import ValidationEvidence, render_validation_evidence
from autocontribute.exceptions import (
    AutocontributeError,
    EnvironmentUnavailable,
    ModelError,
    PolicyError,
    SandboxError,
    StateError,
)
from autocontribute.fix_checks import FixCheckResult, FixChecks
from autocontribute.github import GitHubClient
from autocontribute.instructions import load_instructions
from autocontribute.pr_text import assemble_pull_request, fill_disclosure
from autocontribute.preparation import (
    compute_preparation_config_fingerprint,
    compute_preparation_fingerprint,
)
from autocontribute.pricing import ModelSpec
from autocontribute.providers import SubprocessTurnProvider, TurnProvider
from autocontribute.publication import validate_publication_text
from autocontribute.redaction import host_secret_values, redact_text, truncate_artifact
from autocontribute.reporting import render_run_report
from autocontribute.repository import RepositoryWorkspace
from autocontribute.sandbox import remove_leftover_containers
from autocontribute.setup_agent import ModelSetupAgent
from autocontribute.store import (
    CandidateAttemptDisposition,
    CandidateAttemptState,
    CandidateRetryAuthorization,
    Lease,
    RunStore,
)
from autocontribute.task_messages import (
    RunFacts,
    agent_task,
    nested_agent_guidance,
    read_guidance,
)
from autocontribute.transcript import start_transcript
from autocontribute.triage import ModelIssueTriage, ModelPolicyClassifier
from autocontribute.validation_sandbox import DockerValidation
from autocontribute.workspace_files import WorkspaceFiles

ProviderFactory = Callable[[ModelSpec, frozenset[str]], TurnProvider]

_RUN_LEASE_TTL = timedelta(minutes=5)
_RUN_HEARTBEAT_INTERVAL = timedelta(minutes=1)
_WORKSPACE = "repository"


class RunInvocationMode(StrEnum):
    MANUAL = "manual"
    SCHEDULED = "scheduled"


class Orchestrator:
    """Prepare at most one evidence-backed contribution attempt per run.

    The models are resolved once, when the orchestrator is created, from the API keys in the
    environment; each run records them. ``provider_factory`` makes the turn provider of one
    model from its spec and the host secret values.
    """

    def __init__(
        self,
        config: AutocontributeConfig,
        *,
        store: RunStore | None = None,
        github: GitHubClient | None = None,
        provider_factory: ProviderFactory = SubprocessTurnProvider,
    ) -> None:
        self.config = config
        self.models: ResolvedModels = config.models.resolve(os.environ)
        self.store = store or RunStore(config.storage.path)
        self.github = github or GitHubClient(
            config.github,
            safety_trigger_handler=self.store.record_stop,
        )
        if isinstance(self.github, GitHubClient):
            self.github.bind_safety_trigger_handler(self.store.record_stop)
        self._owns_github = github is None
        # The token may come from `gh` rather than the environment.
        environ = {**os.environ, config.github.token_env: self.github.token}
        self._host_values = host_secret_values(config.secret_env_names(), environ)
        self._provider_factory = provider_factory
        self._providers: dict[str, TurnProvider] = {}
        self._lease_guard: LeaseHeartbeatGuard | None = None
        # What validation.json will hold, from the moment the environment is accepted until the
        # file is written.
        self._evidence: ValidationEvidence | None = None

    def close(self) -> None:
        if self._owns_github:
            self.github.close()

    def __enter__(self) -> Orchestrator:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def run(
        self,
        *,
        invocation_mode: RunInvocationMode,
        issue_reference: str | None = None,
        retry_authorization: CandidateRetryAuthorization | None = None,
    ) -> RunManifest:
        if not isinstance(invocation_mode, RunInvocationMode):
            raise TypeError("invocation_mode must be a RunInvocationMode")
        if retry_authorization is not None and not isinstance(
            retry_authorization, CandidateRetryAuthorization
        ):
            raise TypeError("retry_authorization must be a CandidateRetryAuthorization")
        if issue_reference is not None and invocation_mode != RunInvocationMode.MANUAL:
            raise ValueError("explicit issue references require manual invocation mode")
        if retry_authorization is not None and issue_reference is None:
            raise ValueError("retry authorization requires an explicit issue reference")
        if retry_authorization is not None and invocation_mode != RunInvocationMode.MANUAL:
            raise ValueError("retry authorization is forbidden outside manual invocation mode")
        self._evidence = None
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
                # Only the holder of this lease prepares runs, so every run still in flight now
                # belongs to a worker that stopped.
                self.store.recover_stale_runs(
                    stale_before=utc_now(),
                    reason="A previous worker stopped before completing this preparation run.",
                )
                self.store.remove_finished_workspaces()
                remove_leftover_containers(self.store.root, self.store.unfinished_run_ids())
                self._assert_operational()
                manifest = self.store.create_run()
                try:
                    manifest = self._prepare(
                        manifest,
                        issue_reference=issue_reference,
                        retry_authorization=retry_authorization,
                    )
                except Exception as exc:
                    self._record_failure(manifest, self._safe_error(exc))
                except BaseException:
                    # Ctrl-C, or SIGTERM through the CLI's handler: release the issue now, not
                    # when the next run recovers this one. The interruption itself goes on.
                    with suppress(AutocontributeError):
                        self._record_failure(manifest, "The run was interrupted before it finished")
                    raise
                finally:
                    self._assert_run_lease_owned()
                    self._write_artifacts(manifest)
                    # Publication clones the repository again and applies the patch (§5.4).
                    self.store.remove_workspace(manifest.run_id)
                return manifest
            finally:
                self._lease_guard = None

    def _record_failure(self, manifest: RunManifest, error: str) -> None:
        self._assert_run_lease_owned()
        durable_manifest = self.store.get(manifest.run_id)
        if durable_manifest.candidate is None and manifest.candidate is not None:
            # A failed atomic claim must not attach candidate evidence through the
            # generic failure path. Keep the durable pre-claim identity authoritative.
            manifest.candidate = None
            manifest.repository = durable_manifest.repository
        manifest.error = error
        allowed = RunStatus.FAILED in ALLOWED_TRANSITIONS.get(manifest.status, set())
        if allowed:
            self._assert_run_lease_owned()
            self.store.transition(manifest, RunStatus.FAILED, reason=error)
        else:
            manifest.status = RunStatus.FAILED
            self._assert_run_lease_owned()
            self.store.save(manifest, event="run.failed", details={"error": error})

    def _prepare(
        self,
        manifest: RunManifest,
        *,
        issue_reference: str | None,
        retry_authorization: CandidateRetryAuthorization | None,
    ) -> RunManifest:
        models = self.models
        manifest.models = RunModels(
            agent=models.agent.id,
            critic=models.critic.id,
            setup=models.setup.id,
            triage=models.triage.id,
        )
        self._assert_operational()
        self.store.transition(manifest, RunStatus.DISCOVERING, reason="starting candidate search")
        budget_config = self.config.budget
        if not daily_budget_allows_run(
            self.store,
            max_cost_usd_per_day=budget_config.max_cost_usd_per_day,
            max_cost_usd_per_run=budget_config.max_cost_usd_per_run,
        ):
            return self._end(
                manifest,
                RunStatus.SKIPPED,
                "daily budget: the runs of the last 24 hours leave less than a quarter of "
                "budget.max_cost_usd_per_run within budget.max_cost_usd_per_day",
            )
        budget = RunBudget(
            self.store,
            manifest,
            max_cost_usd=budget_config.max_cost_usd_per_run,
            max_model_calls=budget_config.max_model_calls_per_run,
            max_run_minutes=budget_config.max_run_minutes,
            assert_lease=self._assert_run_lease_owned,
        )
        discovery = DiscoveryService(
            self.config,
            self.github,
            self.store,
            triage=ModelIssueTriage(
                provider=self._provider(models.triage),
                model=models.triage.id,
                budget=budget,
                store=self.store,
                host_values=self._host_values,
                effort=models.efforts["triage"],
            ),
            policy_classifier=ModelPolicyClassifier(
                provider=self._provider(models.triage),
                model=models.triage.id,
                budget=budget,
                store=self.store,
                host_values=self._host_values,
                effort=models.efforts["triage"],
            ),
        )
        retry_override: CandidateAttemptDisposition | None = None

        if issue_reference:
            repository_name, issue_number = parse_issue_reference(issue_reference)
            self._require_configured_target(repository_name)
            repository = self.github.get_repository(repository_name)
            self._require_configured_target(repository.full_name)
            issue = self.github.get_issue(repository.full_name, issue_number)
            if issue.repository.casefold() != repository.full_name.casefold():
                raise PolicyError("Pinned issue resolved outside its configured repository")
            retry_override = self.store.candidate_attempt_disposition(issue)
            if retry_override.state == CandidateAttemptState.ACTIVE:
                if retry_override.prior_run_id is None or retry_override.prior_status is None:
                    raise StateError("Active candidate disposition lacks prior-run evidence")
                manifest.skip_reason = (
                    f"{issue.reference} already has active run {retry_override.prior_run_id} "
                    f"in status {retry_override.prior_status.value}; explicit retry was not "
                    "started."
                )
                self._assert_operational()
                self.store.save(
                    manifest,
                    event="candidate.active_deferred",
                    details={
                        "issue": issue.reference,
                        "issue_revision": retry_override.issue_revision,
                        "prior_run_id": retry_override.prior_run_id,
                        "prior_status": retry_override.prior_status.value,
                    },
                )
                self._assert_operational()
                self.store.transition(manifest, RunStatus.SKIPPED, reason=manifest.skip_reason)
                return manifest
            if (
                retry_override.state == CandidateAttemptState.SUPPRESSED
                and retry_authorization is None
            ):
                if retry_override.prior_run_id is None or retry_override.prior_status is None:
                    raise StateError("Suppressed candidate disposition lacks prior-run evidence")
                manifest.skip_reason = (
                    f"{issue.reference} is unchanged since prior "
                    f"{retry_override.prior_status.value} run {retry_override.prior_run_id}; "
                    "pass --retry-unchanged with --issue to retry it deliberately."
                )
                self._assert_operational()
                self.store.save(
                    manifest,
                    event="candidate.retry_deferred",
                    details={
                        "issue": issue.reference,
                        "issue_revision": retry_override.issue_revision,
                        "prior_run_id": retry_override.prior_run_id,
                        "prior_status": retry_override.prior_status.value,
                    },
                )
                self._assert_operational()
                self.store.transition(manifest, RunStatus.SKIPPED, reason=manifest.skip_reason)
                return manifest
            if retry_override.state == CandidateAttemptState.SUPPRESSED:
                if retry_override.prior_run_id is None or retry_override.prior_status is None:
                    raise StateError("Suppressed candidate disposition lacks prior-run evidence")
                assert retry_authorization is not None
                manifest.candidate = issue
                manifest.repository = repository
                self.store.claim_candidate(
                    manifest,
                    lease=self._candidate_claim_lease(),
                    retry_authorization=retry_authorization,
                )
            elif retry_authorization is not None:
                raise StateError(
                    "Retry authorization no longer matches an unchanged suppressed candidate"
                )
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
            outcome = discovery.discover()
            if outcome.selection is None:
                manifest.skip_reason = outcome.no_candidate_reason
                self._assert_operational()
                self.store.save(
                    manifest,
                    event="candidate.discovery_exhausted",
                    details={
                        "active_candidates": str(outcome.active_candidates),
                        "ineligible_candidates": str(outcome.ineligible_candidates),
                        "suppressed_candidates": str(outcome.suppressed_candidates),
                    },
                )
                self._assert_operational()
                self.store.transition(manifest, RunStatus.SKIPPED, reason=manifest.skip_reason)
                return manifest
            issue, repository, eligibility = outcome.selection
            base_sha = discovery.pinned_repository_ref(repository.full_name)

        self._assert_operational()
        issue.score = eligibility.score
        issue.score_evidence = eligibility.evidence
        manifest.candidate = issue
        manifest.repository = repository
        if retry_override is not None and retry_override.state == CandidateAttemptState.SUPPRESSED:
            self._assert_operational()
            self.store.save(
                manifest,
                event="candidate.selected",
                details={"issue": issue.reference, "score": str(eligibility.score)},
            )
        else:
            self.store.claim_candidate(
                manifest,
                lease=self._candidate_claim_lease(),
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

        manifest.base_sha = base_sha
        self._assert_operational()
        workspace = RepositoryWorkspace.clone(
            repository.clone_url,
            base_sha,
            self.store.workspace_dir(manifest.run_id) / _WORKSPACE,
        )
        self._assert_operational()
        self.store.transition(
            manifest, RunStatus.SETTING_UP, reason="building the test environment"
        )
        prepared = self._set_up(manifest, workspace, budget)
        if prepared is None:
            return manifest
        return self._solve(manifest, workspace, prepared, budget, discovery)

    def _set_up(
        self, manifest: RunManifest, workspace: RepositoryWorkspace, budget: RunBudget
    ) -> PreparedEnvironment | None:
        """Build and accept the test environment; None when the run is skipped without one."""

        assert manifest.repository is not None
        repository = manifest.repository.full_name
        override = self.config.environment_for(repository)
        setup_agent = ModelSetupAgent(
            workspace,
            self.config.sandbox,
            provider=self._provider(self.models.setup),
            model=self.models.setup.id,
            budget=budget,
            store=self.store,
            host_values=self._host_values,
            allow_hosts=() if override is None else override.allow_hosts,
            effort=self.models.efforts["setup"],
        )
        builder = EnvironmentBuilder(self.config.sandbox, self.store, run_id=manifest.run_id)
        try:
            prepared = builder.prepare(repository, workspace, override, setup_agent)
        except EnvironmentUnavailable as exc:
            self._end(manifest, RunStatus.SKIPPED, f"environment: {exc}")
            return None
        image = prepared.image
        manifest.environment = RunEnvironment(
            recipe_source=prepared.recipe.source,
            image_id=image.image_id,
            base_image=image.base_image,
            base_digest=image.base_digest,
            test_command=prepared.recipe.test_command,
        )
        self._evidence = ValidationEvidence(
            recipe=prepared.recipe, baseline=prepared.baseline, check=None, critic_rounds=[]
        )
        self._assert_operational()
        self.store.save(
            manifest,
            event="environment.accepted",
            details={
                "recipe_source": prepared.recipe.source,
                "image_id": image.image_id,
                "base_digest": image.base_digest,
                "reused": str(image.reused).lower(),
            },
        )
        return prepared

    def _solve(
        self,
        manifest: RunManifest,
        workspace: RepositoryWorkspace,
        prepared: PreparedEnvironment,
        budget: RunBudget,
        discovery: DiscoveryService,
    ) -> RunManifest:
        """Run the agent and the critic rounds until a fix is approved or the run ends."""

        issue, repository = manifest.candidate, manifest.repository
        eligibility, base_sha = manifest.eligibility, manifest.base_sha
        assert issue is not None and repository is not None
        assert eligibility is not None and base_sha is not None
        sandbox = self.config.sandbox
        models = self.models
        validation = DockerValidation(
            sandbox, prepared.image.image_id, prepared.recipe, manifest.run_id, self.store.root
        )
        checks = FixChecks(
            workspace,
            prepared,
            validation,
            store=self.store,
            run_id=manifest.run_id,
            quality=self.config.quality,
            policy=self.config.policy,
            command_timeout_seconds=sandbox.command_timeout_seconds,
            seconds_left=budget.seconds_left,
            host_values=self._host_values,
        )
        facts = RunFacts(
            issue,
            repository,
            base_sha,
            prepared.recipe,
            prepared.baseline,
            _ai_policy(eligibility),
        )
        guidance = read_guidance(workspace)
        if not guidance.pull_request_templates:
            guidance = read_guidance(
                workspace,
                organization_templates=discovery.organization_pull_request_templates(
                    repository.full_name
                ),
            )
        transcript = start_transcript(
            model=models.agent.id,
            effort=models.efforts["agent"],
            kind="agent",
            run_id=manifest.run_id,
            instructions=load_instructions("agent"),
            task=agent_task(
                facts,
                guidance,
                commit_titles=self.github.recent_commit_titles(repository.full_name, base_sha),
                host_values=self._host_values,
            ),
            host_values=self._host_values,
        )
        critic = Critic(
            facts,
            validation,
            provider=self._provider(models.critic),
            model=models.critic.id,
            budget=budget,
            store=self.store,
            host_values=self._host_values,
            command_timeout_seconds=sandbox.command_timeout_seconds,
            guidance_paths=guidance.paths,
            effort=models.efforts["critic"],
        )
        self._assert_operational()
        self.store.transition(
            manifest, RunStatus.IMPLEMENTING, reason="the agent works on the issue"
        )
        build_timeout = budget.command_timeout(sandbox.command_timeout_seconds)
        if build_timeout < 1:
            return self._end(
                manifest, RunStatus.REJECTED, "agent did not finish: the run reached its time limit"
            )
        with validation.session(workspace.path, timeout_seconds=build_timeout) as session:
            solver = Solver(
                transcript,
                checker=checks,
                provider=self._provider(models.agent),
                budget=budget,
                store=self.store,
                host_values=self._host_values,
                tools=SessionTools(
                    session,
                    WorkspaceFiles(workspace.path),
                    command_timeout_seconds=sandbox.command_timeout_seconds,
                    seconds_left=budget.seconds_left,
                    environment=validation.environment,
                ),
                nested_guidance=nested_agent_guidance(workspace, host_values=self._host_values),
            )
            outcome = solver.run()
            while True:
                fix = self._agent_fix(manifest, outcome, checks)
                if fix is None:
                    return manifest
                check = checks.results[fix.check.diff_sha256]
                self._assert_operational()
                self.store.transition(
                    manifest, RunStatus.VALIDATING, reason="the fix passed the controller's checks"
                )
                self._assert_operational()
                self.store.transition(
                    manifest, RunStatus.CRITIQUING, reason=f"review round {len(critic.rounds) + 1}"
                )
                review = critic.review(
                    fix, check, patch=_patch_text(workspace), validated=checks.validated
                )
                if isinstance(review, LoopFailure):
                    raise _loop_error(review)
                if isinstance(review, DidNotFinish):
                    return self._end(
                        manifest, RunStatus.REJECTED, f"the review did not finish: {review.detail}"
                    )
                self._record_review(manifest, check, critic.rounds)
                if review.decision == "approve":
                    return self._ready(manifest, workspace, fix, check, critic.rounds, facts)
                if review.decision == "reject":
                    return self._end(manifest, RunStatus.REJECTED, review.reason)
                self._assert_operational()
                self.store.transition(
                    manifest,
                    RunStatus.IMPLEMENTING,
                    reason=f"the agent addresses the blockers of review round {review.number}",
                )
                outcome = solver.address_blockers(review.confirmed)

    def _agent_fix(
        self, manifest: RunManifest, outcome: SolverOutcome, checks: FixChecks
    ) -> SubmittedFix | None:
        """Return the agent's confirmed fix, or end the run when the agent gave none."""

        assert self._evidence is not None
        self._evidence.check = _latest_check(checks)
        if isinstance(outcome, SubmittedFix):
            self._evidence.check = checks.results[outcome.check.diff_sha256]
            return outcome
        if isinstance(outcome, SkippedIssue):
            self._end(manifest, RunStatus.SKIPPED, f"the agent skipped the issue: {outcome.reason}")
        elif isinstance(outcome, DidNotFinish):
            self._end(manifest, RunStatus.REJECTED, f"agent did not finish: {outcome.detail}")
        else:
            raise _loop_error(outcome)
        return None

    def _record_review(
        self, manifest: RunManifest, check: FixCheckResult, rounds: list[CriticRound]
    ) -> None:
        assert self._evidence is not None
        last = rounds[-1]
        self._evidence.check = check
        self._evidence.critic_rounds = list(rounds)
        manifest.quality = QualityReport(
            ready=last.decision == "approve",
            gates=check.gates,
            review_rounds=len(rounds),
            review_summary=last.review.summary,
            review_notes=last.review.notes,
        )
        self._assert_operational()
        self.store.save(
            manifest,
            event="critic.reviewed",
            details={
                "round": str(last.number),
                "decision": last.decision,
                "confirmed_blockers": str(len(last.confirmed)),
                "dropped_blockers": str(len(last.dropped)),
            },
        )

    def _ready(
        self,
        manifest: RunManifest,
        workspace: RepositoryWorkspace,
        fix: SubmittedFix,
        check: FixCheckResult,
        rounds: list[CriticRound],
        facts: RunFacts,
    ) -> RunManifest:
        """Assemble the pull request text, seal the evidence and wait for approval."""

        eligibility, models = manifest.eligibility, manifest.models
        assert eligibility is not None and models is not None
        patch = workspace.patch_bytes()
        if hashlib.sha256(patch).hexdigest() != fix.check.diff_sha256:
            raise StateError("The workspace changed after its fix was checked")
        submission = fix.submission
        assistant = f"autocontribute {__version__}, {models.agent}"
        try:
            text = assemble_pull_request(
                submission,
                issue_number=facts.issue.number,
                check=check,
                disclosure=fill_disclosure(
                    self.config.policy.ai_disclosure, version=__version__, model=models.agent
                ),
                commit_message=apply_legal_commit_message(
                    self.config,
                    eligibility,
                    facts.repository.full_name,
                    (submission.commit_message or "").strip(),
                ),
                ai_policy=facts.ai_policy,
                assistant=assistant,
            )
            manifest.proposal = PatchProposal(
                summary=submission.summary,
                commit_message=text.commit_message,
                pull_request_title=text.title,
                pull_request_body=text.body,
                test_files=list(submission.test_files),
                test_command=submission.test_command,
                disclosure=text.disclosure,
            )
            validate_publication_text(manifest, check_disclosure=True)
        except PolicyError as exc:
            return self._end(
                manifest, RunStatus.REJECTED, f"the pull request text cannot be published: {exc}"
            )
        self._assert_operational()
        patch_path = self.store.write_artifact(
            manifest.run_id, "contribution.patch", patch.decode("utf-8")
        )
        manifest.validation_sha256 = self._write_evidence(manifest.run_id)
        manifest.preparation_config_fingerprint = compute_preparation_config_fingerprint(
            self.config, repository=facts.repository.full_name, models=models
        )
        manifest.preparation_fingerprint = compute_preparation_fingerprint(
            manifest, diff=patch_path.read_bytes()
        )
        self._assert_operational()
        self.store.transition(
            manifest,
            RunStatus.READY_FOR_APPROVAL,
            reason=f"the critic approved the fix in review round {len(rounds)}",
        )
        return manifest

    def _end(self, manifest: RunManifest, status: RunStatus, reason: str) -> RunManifest:
        """End the run as skipped or rejected, with the reason a person reads."""

        if status == RunStatus.SKIPPED:
            manifest.skip_reason = reason
        else:
            manifest.reject_reason = reason
        self._assert_operational()
        self.store.transition(manifest, status, reason=reason)
        return manifest

    def _provider(self, spec: ModelSpec) -> TurnProvider:
        provider = self._providers.get(spec.id)
        if provider is None:
            provider = self._provider_factory(spec, self._host_values)
            self._providers[spec.id] = provider
        return provider

    def _write_evidence(self, run_id: str) -> str | None:
        """Write validation.json once; return its SHA-256, or None when there is none to write."""

        evidence = self._evidence
        if evidence is None:
            return None
        text = render_validation_evidence(evidence)
        self._assert_run_lease_owned()
        self.store.write_artifact(run_id, "validation.json", text)
        self._evidence = None
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def _write_artifacts(self, manifest: RunManifest) -> None:
        self._write_evidence(manifest.run_id)
        report = redact_text(
            render_run_report(manifest), secret_env_names=self.config.secret_env_names()
        )
        self._assert_run_lease_owned()
        self.store.write_artifact(manifest.run_id, "report.md", report)

    def _assert_operational(self) -> None:
        self.store.assert_circuit_breaker_clear()
        self._assert_run_lease_owned()

    def _assert_run_lease_owned(self) -> None:
        """Fence durable run writes without blocking failure bookkeeping on a safety stop."""

        if self._lease_guard is not None:
            self._lease_guard.assert_owned()

    def _candidate_claim_lease(self) -> Lease:
        if self._lease_guard is None:
            raise StateError("Autocontribute run lease is not active")
        return self._lease_guard.assert_owned()

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
            redact_text(message, secret_env_names=self.config.secret_env_names()), limit=4_000
        )


def _ai_policy(eligibility: EligibilityResult) -> RepositoryAiPolicy | None:
    raw = eligibility.evidence.get(AI_POLICY_EVIDENCE_KEY)
    return None if raw is None else RepositoryAiPolicy.model_validate_json(raw)


def _latest_check(checks: FixChecks) -> FixCheckResult | None:
    return next(reversed(checks.results.values()), None)


def _patch_text(workspace: RepositoryWorkspace) -> str:
    # The fix passed its checks, which refuse a patch that is not UTF-8 text.
    return workspace.patch_bytes().decode("utf-8")


def _loop_error(failure: LoopFailure) -> AutocontributeError:
    if failure.source == "sandbox":
        return SandboxError(failure.message)
    return ModelError(failure.message)


__all__ = ["Orchestrator", "ProviderFactory", "RunInvocationMode"]
