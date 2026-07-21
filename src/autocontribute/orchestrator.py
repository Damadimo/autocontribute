"""Bounded discovery-to-approval orchestration with no implicit GitHub writes."""

from __future__ import annotations

import json
import re
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import asdict
from pathlib import Path
from typing import Literal, TypeVar, cast

from pydantic import BaseModel

from autocontribute.config import AutocontributeConfig
from autocontribute.discovery import DiscoveryService, parse_issue_reference
from autocontribute.domain import (
    CommandResult,
    ContributionPlan,
    CriticReview,
    PatchProposal,
    RunManifest,
    RunStatus,
)
from autocontribute.exceptions import AutocontributeError, PolicyError, RepositoryError
from autocontribute.github import GitHubClient
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
from autocontribute.publication import validate_publication_text
from autocontribute.quality import QualityEvaluator
from autocontribute.redaction import redact_text, truncate_artifact
from autocontribute.reporting import render_run_report
from autocontribute.repository import ContextEntry, RepositoryWorkspace
from autocontribute.sandbox import SandboxRunner
from autocontribute.store import RunStore

OutputT = TypeVar("OutputT", bound=BaseModel)
ProviderFactory = Callable[[object], ModelProvider]

_WORD = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{2,}")


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
    ) -> None:
        self.config = config
        self.store = store or RunStore(config.storage.path)
        self.github = github or GitHubClient(config.github)
        self._owns_github = github is None
        self._providers = dict(providers or {})
        self._provider_factory = provider_factory or cast("ProviderFactory", create_provider)
        self.sandbox = sandbox or SandboxRunner(config.sandbox)
        self._model_events: list[dict[str, object]] = []

    def close(self) -> None:
        if self._owns_github:
            self.github.close()

    def __enter__(self) -> Orchestrator:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def run(self, *, issue_reference: str | None = None) -> RunManifest:
        manifest = self.store.create_run()
        commands: list[CommandResult] = []
        try:
            manifest = self._prepare(manifest, issue_reference=issue_reference, commands=commands)
        except Exception as exc:
            safe_error = self._safe_error(exc)
            manifest.error = safe_error
            allowed = RunStatus.FAILED in self._allowed_targets(manifest)
            if allowed:
                self.store.transition(manifest, RunStatus.FAILED, reason=safe_error)
            else:
                manifest.status = RunStatus.FAILED
                self.store.save(manifest, event="run.failed", details={"error": safe_error})
        finally:
            self._write_artifacts(manifest, commands)
        return manifest

    def _prepare(
        self,
        manifest: RunManifest,
        *,
        issue_reference: str | None,
        commands: list[CommandResult],
    ) -> RunManifest:
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
            eligibility = discovery.evaluate(issue, repository)
        else:
            selection = discovery.discover()
            if selection is None:
                manifest.skip_reason = "No candidate passed deterministic discovery gates."
                self.store.transition(manifest, RunStatus.SKIPPED, reason=manifest.skip_reason)
                return manifest
            issue, repository, eligibility = selection

        issue.score = eligibility.score
        issue.score_evidence = eligibility.evidence
        manifest.candidate = issue
        manifest.repository = repository
        self.store.save(
            manifest,
            event="candidate.selected",
            details={"issue": issue.reference, "score": str(eligibility.score)},
        )
        self.store.transition(
            manifest,
            RunStatus.CANDIDATE_SELECTED,
            reason=f"selected {issue.reference}",
        )
        manifest.eligibility = eligibility
        self.store.save(
            manifest,
            event="candidate.evaluated",
            details={"eligible": str(eligibility.eligible), "score": str(eligibility.score)},
        )
        if not eligibility.eligible:
            manifest.skip_reason = "; ".join(eligibility.blockers)
            self.store.transition(manifest, RunStatus.SKIPPED, reason=manifest.skip_reason)
            return manifest
        self.store.transition(
            manifest,
            RunStatus.ELIGIBILITY_CHECKED,
            reason="candidate passed deterministic eligibility",
        )

        base_sha = self.github.default_branch_sha(repository.full_name, repository.default_branch)
        manifest.base_sha = base_sha
        workspace_root = self.store.workspace_dir(manifest.run_id) / "repository"
        workspace = RepositoryWorkspace.clone(
            repository.clone_url,
            base_sha,
            workspace_root,
        )
        guidance = workspace.guidance(max_characters=80_000)
        index = self._render_index(
            workspace.context_index(), issue_text=f"{issue.title} {issue.body}"
        )

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
            ),
            output_type=ContributionPlan,
        )
        plan = plan_result.output
        manifest.plan = plan
        self.store.save(
            manifest,
            event="plan.created",
            details={"decision": plan.decision, "reason": plan.decision_reason},
        )
        if plan.decision == "skip":
            manifest.skip_reason = plan.decision_reason
            self.store.transition(manifest, RunStatus.SKIPPED, reason=plan.decision_reason)
            return manifest

        selected_files = self._read_context(workspace, plan.files_to_read)
        if plan.contribution_kind == "bugfix":
            if not plan.reproduction_command:
                raise PolicyError("Bugfix plan omitted a baseline reproduction command")
            # Reproduction code is untrusted and may write into its checkout. Run it in a disposable
            # clone so generated files or malicious mutations cannot leak into the proposed patch.
            with tempfile.TemporaryDirectory(
                prefix="baseline-", dir=self.store.workspace_dir(manifest.run_id)
            ) as baseline_parent:
                baseline_workspace = RepositoryWorkspace.clone(
                    repository.clone_url,
                    base_sha,
                    Path(baseline_parent) / "repository",
                )
                manifest.baseline_validation = self._run_command(
                    baseline_workspace, plan.reproduction_command
                )
            self.store.save(
                manifest,
                event="baseline.reproduced",
                details={
                    "command": plan.reproduction_command,
                    "failed_as_expected": str(not manifest.baseline_validation.passed),
                },
            )
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
        workspace.apply_edits(proposal.edits)
        self.store.save(
            manifest,
            event="patch.applied",
            details={"changed_paths": ",".join(workspace.changed_paths())},
        )

        self.store.transition(manifest, RunStatus.VALIDATING, reason="running isolated checks")
        commands[:] = self._validate(workspace, plan, proposal)
        self.store.save(
            manifest,
            event="validation.completed",
            details={
                "passed": str(all(result.passed for result in commands)),
                "commands": str(len(commands)),
            },
        )

        self.store.transition(manifest, RunStatus.CRITIQUING, reason="fresh-context review")
        review = self._review(manifest, workspace, guidance, commands)

        if (
            review.verdict == "reject"
            and review.blocking_findings
            and all(result.passed for result in commands)
            and manifest.model_calls + 2 <= self.config.budget.max_model_calls_per_run
        ):
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
            workspace.apply_edits(proposal.edits)
            self.store.transition(
                manifest,
                RunStatus.VALIDATING,
                reason="revalidating repaired patch",
            )
            commands[:] = self._validate(workspace, plan, proposal)
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
            review=review,
            baseline_result=manifest.baseline_validation,
            contribution_kind=plan.contribution_kind,
        )
        manifest.quality = quality
        self.store.write_artifact(manifest.run_id, "contribution.patch", diff)
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
            self.store.transition(
                manifest,
                RunStatus.REJECTED,
                reason=f"quality gates failed: {reason}",
            )
            return manifest

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
            ),
            output_type=CriticReview,
        )
        return result.output

    def _validate(
        self,
        workspace: RepositoryWorkspace,
        plan: ContributionPlan,
        proposal: PatchProposal,
    ) -> list[CommandResult]:
        commands = list(dict.fromkeys([*plan.validation_commands, *proposal.validation_commands]))
        if plan.reproduction_command:
            commands.insert(0, plan.reproduction_command)
            commands = list(dict.fromkeys(commands))
        remaining = getattr(self.sandbox, "remaining_commands", self.config.sandbox.max_commands)
        commands = commands[:remaining]
        if not commands:
            return [
                CommandResult(
                    command="repository validation command required",
                    exit_code=2,
                    duration_seconds=0,
                    stdout="",
                    stderr="The plan supplied no repository-specific validation command.",
                )
            ]
        results = self.sandbox.run_all(workspace, commands, stop_on_failure=True)
        return [self._scrub_command(result) for result in results]

    def _run_command(self, workspace: RepositoryWorkspace, command: str) -> CommandResult:
        return self._scrub_command(self.sandbox.run(workspace, command))

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
        if manifest.model_calls >= self.config.budget.max_model_calls_per_run:
            raise PolicyError("Model-call budget exhausted")
        manifest.model_calls += 1
        self.store.save(
            manifest,
            event="model.call.started",
            details={"role": role, "call": str(manifest.model_calls)},
        )
        provider = self._providers.get(role)
        if provider is None:
            provider = self._provider_factory(self.config.model_for(role))
            self._providers[role] = provider
        result = provider.generate(
            instructions=instructions,
            prompt=prompt,
            output_type=output_type,
        )
        self._model_events.append(
            {
                "role": role,
                "response_id": result.response_id,
                "model": result.model,
                "usage": asdict(result.usage),
            }
        )
        self.store.save(
            manifest,
            event="model.call.completed",
            details={
                "role": role,
                "response_id": result.response_id,
                "model": result.model,
                "total_tokens": str(result.usage.total_tokens),
            },
        )
        return result

    def _read_context(self, workspace: RepositoryWorkspace, paths: list[str]) -> dict[str, str]:
        unique = list(dict.fromkeys(paths))
        if len(unique) > self.config.quality.max_context_files:
            raise PolicyError(
                f"Plan requested {len(unique)} files; maximum is "
                f"{self.config.quality.max_context_files}"
            )
        remaining = self.config.quality.max_context_characters
        files: dict[str, str] = {}
        for path in unique:
            content = workspace.read_file(path, max_bytes=max(remaining, 1))
            if len(content) > remaining:
                raise PolicyError("Selected repository context exceeds configured character budget")
            files[path] = content
            remaining -= len(content)
        if not files:
            raise RepositoryError("Plan selected no repository files")
        return files

    def _render_index(self, entries: list[ContextEntry], *, issue_text: str) -> str:
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
        return truncate_artifact("\n".join(lines), limit=140_000)

    def _with_disclosure(self, proposal: PatchProposal) -> PatchProposal:
        disclosure = self.config.policy.ai_disclosure.strip()
        if not disclosure:
            raise PolicyError("policy.ai_disclosure cannot be blank")
        if disclosure in proposal.pull_request_body:
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
        validation = {
            "baseline": (
                manifest.baseline_validation.model_dump(mode="json")
                if manifest.baseline_validation
                else None
            ),
            "patched": [result.model_dump(mode="json") for result in commands],
        }
        self.store.write_artifact(
            manifest.run_id,
            "validation.json",
            redact_text(
                json.dumps(validation, indent=2, sort_keys=True) + "\n",
                secret_env_names=secret_names,
            ),
        )
        self.store.write_artifact(
            manifest.run_id,
            "model-calls.json",
            json.dumps(self._model_events, indent=2, sort_keys=True) + "\n",
        )
        self.store.write_artifact(
            manifest.run_id,
            "report.md",
            redact_text(
                render_run_report(manifest, commands),
                secret_env_names=secret_names,
            ),
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
