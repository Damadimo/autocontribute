"""Command-line interface for preparation, approval, and publication."""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated
from urllib.parse import quote

import typer
import yaml
from rich.console import Console
from rich.table import Table
from rich.text import Text

from autocontribute import __version__
from autocontribute.backup import create_state_bundle, restore_state_bundle
from autocontribute.backup_replication import replicate_state_bundle_to_s3
from autocontribute.config import (
    CLA_ATTESTATION_STATEMENT,
    DCO_ATTESTATION_STATEMENT,
    AutocontributeConfig,
    LegalAttestation,
    auto_publish_opt_in_enabled,
    example_config,
    load_config,
)
from autocontribute.coordination import (
    PUBLICATION_HEARTBEAT_INTERVAL,
    PUBLICATION_LEASE_NAME,
    PUBLICATION_LEASE_TTL,
    LeaseHeartbeatGuard,
)
from autocontribute.deployment import compute_deployment_fingerprint
from autocontribute.discovery import DiscoveryService, PolicySnapshot
from autocontribute.doctor import run_doctor
from autocontribute.domain import RunManifest, RunStatus
from autocontribute.evaluation import (
    EvaluationRevision,
    EvaluationStore,
    EvaluationVerdict,
    evaluation_hash,
)
from autocontribute.exceptions import (
    AutocontributeError,
    AutomaticRolloutBlocked,
    ConfigurationError,
    PublicationResumeRequired,
    StateError,
)
from autocontribute.github import GitHubClient
from autocontribute.github_origin import web_origin_for_api
from autocontribute.lifecycle import LifecycleSyncResult, sync_open_pull_requests
from autocontribute.orchestrator import Orchestrator, RunInvocationMode
from autocontribute.publication import Publisher, approve_run, build_approval_review
from autocontribute.reporting import render_approval_review, render_run_report
from autocontribute.rollout import RolloutGate, RolloutSummary
from autocontribute.store import CandidateRetryAuthorization, RunStore
from autocontribute.systemd_assets import (
    verify_installed_systemd_assets,
    verify_source_systemd_assets,
)
from autocontribute.upstream_outcomes import UpstreamPublicationScope
from autocontribute.workspace_gc import WorkspaceGCReport, collect_terminal_workspaces

app = typer.Typer(
    name="autocontribute",
    help="Prepare issue-backed open-source contributions behind hard quality gates.",
    no_args_is_help=True,
)
runs_app = typer.Typer(help="Inspect durable contribution runs.", no_args_is_help=True)
config_app = typer.Typer(help="Inspect configuration safely.", no_args_is_help=True)
evaluation_app = typer.Typer(
    help="Record expert shadow-run grades and inspect rollout gates.",
    no_args_is_help=True,
)
rollout_app = typer.Typer(
    help="Inspect the complete evidence-backed autonomous rollout decision.",
    no_args_is_help=True,
)
state_app = typer.Typer(
    help="Manage durable state, verified backups, and bounded workspace cleanup.",
    no_args_is_help=True,
)
lifecycle_app = typer.Typer(
    help="Observe published pull requests and persist maintainer/CI safety signals.",
    no_args_is_help=True,
)
safety_app = typer.Typer(
    help="Inspect or explicitly change the persistent operational circuit breaker.",
    no_args_is_help=True,
)
policy_app = typer.Typer(
    help="Inspect immutable repository policy and create scoped legal attestations.",
    no_args_is_help=True,
)
deployment_app = typer.Typer(
    help="Verify release-bound production deployment assets.",
    no_args_is_help=True,
)
app.add_typer(runs_app, name="runs")
app.add_typer(config_app, name="config")
app.add_typer(evaluation_app, name="eval")
app.add_typer(rollout_app, name="rollout")
app.add_typer(state_app, name="state")
app.add_typer(lifecycle_app, name="lifecycle")
app.add_typer(safety_app, name="safety")
app.add_typer(policy_app, name="policy")
app.add_typer(deployment_app, name="deployment")

console = Console()
DEFAULT_CONFIG = Path("autocontribute.yml")
ConfigOption = Annotated[
    Path,
    typer.Option("--config", "-c", help="Path to the YAML configuration."),
]
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


@app.command()
def init(
    path: Annotated[
        Path,
        typer.Option("--path", "-p", help="Configuration file to create."),
    ] = DEFAULT_CONFIG,
    force: Annotated[bool, typer.Option(help="Replace an existing file.")] = False,
) -> None:
    """Create a safe starter configuration with no credentials."""

    target = path.expanduser().resolve()
    if target.exists() and not force:
        _fail(f"{target} already exists; pass --force to replace it")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(example_config(), encoding="utf-8")
    console.print(f"Created [bold]{target}[/bold]")
    console.print("Edit the repository allowlist, then run `autocontribute doctor`.")


@app.command()
def doctor(
    config: ConfigOption = DEFAULT_CONFIG,
    non_interactive: Annotated[
        bool,
        typer.Option(help="Emit checks without prompting; useful in CI."),
    ] = False,
) -> None:
    """Check configuration, credentials, GitHub, Git, and sandbox availability."""

    del non_interactive  # The doctor never prompts; the flag documents CI intent.
    settings = _config(config)
    checks = run_doctor(settings, store=RunStore(settings.storage.path))
    table = Table("Check", "Result", "Detail")
    for check in checks:
        if check.passed and check.warning:
            result = "[yellow]WARN[/yellow]"
        elif check.passed:
            result = "[green]PASS[/green]"
        else:
            result = "[red]FAIL[/red]"
        table.add_row(check.name, result, check.detail)
    console.print(table)
    if any(not check.passed for check in checks):
        raise typer.Exit(1)


@deployment_app.command(name="verify-systemd-assets")
def verify_systemd_deployment_assets(
    source_root: Annotated[
        Path | None,
        typer.Option(
            "--source-root",
            help=(
                "Verify an immutable release checkout before installation; omit to verify the "
                "exact production host paths."
            ),
        ),
    ] = None,
) -> None:
    """Fail unless every systemd deployment asset matches this Python release."""

    try:
        if source_root is None:
            result = verify_installed_systemd_assets()
        else:
            result = verify_source_systemd_assets(source_root)
    except (AutocontributeError, OSError, ValueError) as exc:
        _fail(str(exc))
    console.print(
        "[green]Verified[/green] "
        f"{result.checked_assets} {result.scope} systemd deployment asset(s) "
        f"against manifest {result.manifest_sha256}."
    )


@app.command()
def discover(config: ConfigOption = DEFAULT_CONFIG) -> None:
    """Find the strongest current candidate without cloning or changing GitHub."""

    settings = _config(config)
    store = RunStore(settings.storage.path)
    try:
        with _github_client(settings, store) as github:
            outcome = DiscoveryService(settings, github, store).discover()
    except AutocontributeError as exc:
        _fail(str(exc))
    if outcome.selection is None:
        console.print(f"[yellow]{outcome.no_candidate_reason}[/yellow]")
        return
    issue, repository, eligibility = outcome.selection
    console.print(f"[bold green]{issue.reference}[/bold green] — {issue.title}")
    console.print(issue.html_url)
    console.print(f"Repository: {repository.full_name} ({repository.stars:,} stars)")
    console.print(f"Candidate readiness: {eligibility.score}/100")
    for name, evidence in eligibility.evidence.items():
        console.print(f"  {name}: {evidence}")


@app.command(name="run")
def run_once(
    config: ConfigOption = DEFAULT_CONFIG,
    issue: Annotated[
        str | None,
        typer.Option(help="Pin the attempt to owner/repository#number."),
    ] = None,
    retry_unchanged: Annotated[
        bool,
        typer.Option(
            help="Deliberately retry an unchanged skipped, rejected, or cancelled --issue."
        ),
    ] = False,
    retry_actor: Annotated[
        str | None,
        typer.Option(help="Human/operator identity authorizing --retry-unchanged."),
    ] = None,
    retry_reason: Annotated[
        str | None,
        typer.Option(help="Auditable reason for --retry-unchanged."),
    ] = None,
    scheduled: Annotated[
        bool,
        typer.Option(
            help="Mark invocation as scheduler-driven; behavior remains policy-controlled."
        ),
    ] = False,
) -> None:
    """Prepare one candidate, or skip safely when evidence is insufficient."""

    if scheduled and retry_unchanged:
        _fail("--retry-unchanged cannot be used by a scheduled invocation")
    if scheduled and issue is not None:
        _fail("--scheduled cannot be combined with --issue; pinned retries must be manual")
    if retry_unchanged and issue is None:
        _fail("--retry-unchanged requires --issue owner/repository#number")
    if retry_unchanged and (retry_actor is None or retry_reason is None):
        _fail("--retry-unchanged requires both --retry-actor and --retry-reason")
    if not retry_unchanged and (retry_actor is not None or retry_reason is not None):
        _fail("--retry-actor and --retry-reason require --retry-unchanged")
    try:
        retry_authorization = (
            CandidateRetryAuthorization(actor=retry_actor, reason=retry_reason)
            if retry_actor is not None and retry_reason is not None
            else None
        )
    except (TypeError, ValueError) as exc:
        _fail(str(exc))
    settings = _config(config)
    store = RunStore(settings.storage.path)
    github: GitHubClient | None = None
    try:
        github = _github_client(settings, store)
        if scheduled:
            _sync_lifecycle(
                settings,
                store,
                github,
                resume_submitting_publications=(
                    settings.publishing.mode == "auto"
                    and auto_publish_opt_in_enabled(settings.publishing)
                ),
                scheduled_preflight=True,
            )
            store.assert_circuit_breaker_clear()
            if not _scheduled_auto_preflight(settings, store, github):
                return
        with Orchestrator(settings, store=store, github=github) as orchestrator:
            manifest = orchestrator.run(
                issue_reference=issue,
                invocation_mode=(
                    RunInvocationMode.SCHEDULED if scheduled else RunInvocationMode.MANUAL
                ),
                retry_authorization=retry_authorization,
            )
        if manifest.status == RunStatus.READY_FOR_APPROVAL and settings.publishing.mode == "auto":
            _sync_lifecycle(settings, store, github)
            manifest = Publisher(settings, store, github).publish(manifest.run_id)
    except (AutocontributeError, ValueError) as exc:
        _fail(str(exc))
    finally:
        if github is not None:
            github.close()
    _print_outcome(manifest, store)
    if manifest.status == RunStatus.FAILED:
        raise typer.Exit(1)


@app.command()
def approve(
    run_id: Annotated[str, typer.Argument(help="Run identifier to approve.")],
    config: ConfigOption = DEFAULT_CONFIG,
    yes: Annotated[
        bool,
        typer.Option("--yes", help="Confirm the review attestation non-interactively."),
    ] = False,
) -> None:
    """Attest that you reviewed the exact diff, checks, and proposed PR."""

    settings = _config(config)
    store = RunStore(settings.storage.path)
    try:
        with _github_client(settings, store) as github:
            actor = github.authenticated_login()
        review = build_approval_review(settings, store, run_id, actor=actor)
        console.print(render_approval_review(review), markup=False)
    except AutocontributeError as exc:
        _fail(str(exc))
    if not yes and not typer.confirm(
        "I reviewed the exact diff, validation evidence, and PR text and authorize publication"
    ):
        raise typer.Abort()
    try:
        manifest = approve_run(
            settings,
            store,
            run_id,
            actor=actor,
            attestation="Reviewed exact diff, validation evidence, and pull-request text.",
            reviewed_fingerprint=review.fingerprint,
        )
    except AutocontributeError as exc:
        _fail(str(exc))
    _refresh_report(store, manifest)
    assert manifest.approval is not None
    console.print(
        f"[green]Approved[/green] `{run_id}` until {manifest.approval.expires_at.isoformat()}"
    )


@app.command()
def publish(
    run_id: Annotated[str, typer.Argument(help="Approved or auto-authorized run identifier.")],
    config: ConfigOption = DEFAULT_CONFIG,
    yes: Annotated[
        bool,
        typer.Option("--yes", help="Perform the authorized GitHub write without another prompt."),
    ] = False,
) -> None:
    """Create/reuse a fork, push one branch, and open one pull request."""

    settings = _config(config)
    store = RunStore(settings.storage.path)
    manifest = store.get(run_id)
    _show_report(store, manifest)
    if not yes and not typer.confirm("Publish this exact approved artifact to GitHub"):
        raise typer.Abort()
    try:
        with _github_client(settings, store) as github:
            _sync_lifecycle(
                settings,
                store,
                github,
                publication_retry_run_id=(
                    manifest.run_id if manifest.status == RunStatus.SUBMITTING else None
                ),
            )
            manifest = store.get(run_id)
            if manifest.status != RunStatus.PR_OPEN:
                manifest = Publisher(settings, store, github).publish(run_id)
    except AutocontributeError as exc:
        _fail(str(exc))
    _refresh_report(store, manifest)
    console.print(f"[bold green]Pull request opened:[/bold green] {manifest.pull_request_url}")


@runs_app.command(name="list")
def list_runs(
    config: ConfigOption = DEFAULT_CONFIG,
    limit: Annotated[int, typer.Option(min=1, max=200)] = 20,
) -> None:
    """List recent runs and terminal outcomes."""

    settings = _config(config)
    manifests = RunStore(settings.storage.path).list(limit=limit)
    table = Table("Run", "Status", "Issue", "Updated")
    for manifest in manifests:
        table.add_row(
            manifest.run_id,
            manifest.status.value,
            manifest.candidate.reference if manifest.candidate else "—",
            manifest.updated_at.isoformat(timespec="seconds"),
        )
    console.print(table)


@runs_app.command(name="show")
def show_run(
    run_id: Annotated[str, typer.Argument(help="Run identifier.")],
    config: ConfigOption = DEFAULT_CONFIG,
) -> None:
    """Show the human-reviewable evidence summary for one run."""

    settings = _config(config)
    store = RunStore(settings.storage.path)
    try:
        manifest = store.get(run_id)
        if manifest.status == RunStatus.READY_FOR_APPROVAL:
            with _github_client(settings, store) as github:
                actor = github.authenticated_login()
            review = build_approval_review(settings, store, run_id, actor=actor)
            console.print(render_approval_review(review), markup=False)
        else:
            _show_report(store, manifest)
    except AutocontributeError as exc:
        _fail(str(exc))


@config_app.command(name="validate")
def validate_config(config: ConfigOption = DEFAULT_CONFIG) -> None:
    """Parse configuration and print a credential-free summary."""

    settings = _config(config)
    console.print("[green]Configuration is valid.[/green]")
    console.print(f"Repositories: {len(settings.github.repositories)}")
    console.print(f"Owners: {len(settings.github.owners)}")
    console.print(f"Publishing mode: {settings.publishing.mode}")
    console.print(
        "Models: "
        + ", ".join(
            [
                settings.models.scout.model,
                settings.models.builder.model,
                settings.models.critic.model,
            ]
        )
    )


@config_app.command(name="show")
def show_config(config: ConfigOption = DEFAULT_CONFIG) -> None:
    """Print normalized configuration; it contains secret names, never values."""

    settings = _config(config)
    console.print(yaml.safe_dump(settings.model_dump(mode="json"), sort_keys=False))


@policy_app.command(name="inspect")
def inspect_policy(
    repository: Annotated[
        str,
        typer.Argument(help="Exact configured owner/repository to inspect."),
    ],
    config: ConfigOption = DEFAULT_CONFIG,
) -> None:
    """Show the immutable policy refs, digest, and detected legal requirements."""

    settings = _config(config)
    _require_configured_policy_target(settings, repository)
    store = RunStore(settings.storage.path)
    try:
        with _github_client(settings, store) as github:
            metadata = github.get_repository(repository)
            if metadata.full_name.casefold() != repository.casefold():
                raise ConfigurationError("GitHub resolved a different repository identity")
            snapshot = DiscoveryService(settings, github, store).policy_snapshot(metadata)
    except AutocontributeError as exc:
        _fail(str(exc))
    console.print(
        _render_policy_snapshot(
            snapshot,
            web_origin=web_origin_for_api(settings.github.api_url),
        ),
        markup=False,
        soft_wrap=True,
    )


@policy_app.command(name="attest")
def attest_policy(
    repository: Annotated[
        str,
        typer.Argument(help="Exact configured owner/repository to attest for."),
    ],
    config: ConfigOption = DEFAULT_CONFIG,
    cla_completed: Annotated[
        bool,
        typer.Option(
            "--cla-completed",
            help="Attest that all account-level CLA enrollment is already complete.",
        ),
    ] = False,
    authorize_dco_signoff: Annotated[
        bool,
        typer.Option(
            "--authorize-dco-signoff",
            help="Authorize the configured identity's exact Signed-off-by trailer.",
        ),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option(
            "--yes",
            help="Make the displayed legal attestation non-interactively.",
        ),
    ] = False,
) -> None:
    """Preview and emit a config stanza for one exact legal-policy snapshot."""

    settings = _config(config)
    _require_configured_policy_target(settings, repository)
    store = RunStore(settings.storage.path)
    try:
        with _github_client(settings, store) as github:
            metadata = github.get_repository(repository)
            if metadata.full_name.casefold() != repository.casefold():
                raise ConfigurationError("GitHub resolved a different repository identity")
            snapshot = DiscoveryService(settings, github, store).policy_snapshot(metadata)
            login = github.authenticated_login().strip().casefold()
    except AutocontributeError as exc:
        _fail(str(exc))

    console.print(
        _render_policy_snapshot(
            snapshot,
            web_origin=web_origin_for_api(settings.github.api_url),
        ),
        markup=False,
        soft_wrap=True,
    )
    required = set(snapshot.legal_requirements)
    if not required:
        _fail("No CLA or DCO requirement was detected in this exact policy snapshot")
    if ("cla" in required) != cla_completed:
        option = "--cla-completed" if "cla" in required else "omit --cla-completed"
        _fail(f"Exact detected requirements require you to {option}")
    if ("dco" in required) != authorize_dco_signoff:
        option = "--authorize-dco-signoff" if "dco" in required else "omit --authorize-dco-signoff"
        _fail(f"Exact detected requirements require you to {option}")
    if "dco" in required and (not settings.identity.name or not settings.identity.email):
        _fail("DCO authorization requires explicit identity.name and identity.email in the config")

    console.print("Exact legal authorization to be recorded:", markup=False)
    if "cla" in required:
        console.print(f"CLA: {CLA_ATTESTATION_STATEMENT}", markup=False)
    if "dco" in required:
        console.print(f"DCO: {DCO_ATTESTATION_STATEMENT}", markup=False)
        console.print(
            f"Trailer: Signed-off-by: {settings.identity.name} <{settings.identity.email}>",
            markup=False,
        )
    console.print(f"Attesting GitHub account: {login}", markup=False)
    if not yes and not typer.confirm(
        "I personally make every displayed legal attestation for only this repository and snapshot"
    ):
        raise typer.Abort()

    raw_attestation: dict[str, object] = {
        "repository": snapshot.repository.casefold(),
        "reviewed_repository_ref": snapshot.repository_ref,
        "reviewed_organization_policy_ref": snapshot.organization_ref_evidence,
        "legal_policy_sha256": snapshot.legal_policy_sha256,
        "legal_requirements": list(snapshot.legal_requirements),
        "attested_by": login,
        "attested_at": datetime.now(UTC),
    }
    if "cla" in required:
        raw_attestation["cla"] = {"statement": CLA_ATTESTATION_STATEMENT}
    if "dco" in required:
        raw_attestation["dco"] = {
            "statement": DCO_ATTESTATION_STATEMENT,
            "signoff_name": settings.identity.name,
            "signoff_email": settings.identity.email,
        }
    try:
        attestation = LegalAttestation.model_validate(raw_attestation)
    except ValueError as exc:
        _fail(f"Generated legal attestation is invalid: {exc}")
    snippet = {
        "policy": {
            "legal_attestations": {
                snapshot.repository.casefold(): attestation.model_dump(mode="json")
            }
        }
    }
    console.print(
        "Merge this exact stanza into your configuration, replacing any stale record for the "
        "repository:",
        markup=False,
    )
    console.print(yaml.safe_dump(snippet, sort_keys=False), markup=False)


@evaluation_app.command(name="record")
def record_evaluation(
    run_id: Annotated[
        str,
        typer.Argument(help="Run identifier whose exact artifact was reviewed."),
    ],
    reviewer: Annotated[str, typer.Option(help="Expert reviewer identity for the audit record.")],
    verdict: Annotated[
        EvaluationVerdict,
        typer.Option(help="Independent judgment of the prepared artifact or abstention."),
    ],
    config: ConfigOption = DEFAULT_CONFIG,
    notes: Annotated[str, typer.Option(help="Concise evidence supporting the judgment.")] = "",
    policy_failure: Annotated[
        bool,
        typer.Option(help="Mark any repository-policy or legal-process failure."),
    ] = False,
    security_failure: Annotated[
        bool,
        typer.Option(help="Mark any credential, isolation, or security failure."),
    ] = False,
    etiquette_failure: Annotated[
        bool,
        typer.Option(help="Mark spam, claimed-work, disclosure, or maintainer-time harm."),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option(
            "--yes",
            help="Attest to the displayed expert judgment without an interactive prompt.",
        ),
    ] = False,
) -> None:
    """Review and bind one immutable expert grade to a shadow-run artifact."""

    settings = _config(config)
    evaluations = EvaluationStore(RunStore(settings.storage.path))
    try:
        preview = evaluations.preview_record(
            run_id,
            reviewer=reviewer,
            verdict=verdict,
            notes=notes,
            policy_failure=policy_failure,
            security_failure=security_failure,
            etiquette_failure=etiquette_failure,
        )
    except (AutocontributeError, ValueError) as exc:
        _fail(str(exc))
    console.print(_render_evaluation_preview(preview), markup=False)
    if not yes and not typer.confirm(
        "I reviewed every field above and attest that this expert judgment is accurate"
    ):
        raise typer.Abort()
    try:
        evaluation = evaluations.commit_preview(preview)
    except (AutocontributeError, ValueError) as exc:
        _fail(str(exc))
    console.print(
        f"[green]Recorded[/green] {evaluation.verdict.value} for `{evaluation.run_id}` "
        f"(subject `{evaluation.subject_hash}`)."
    )


@evaluation_app.command(name="amend")
def amend_evaluation(
    run_id: Annotated[
        str,
        typer.Argument(help="Run identifier whose latest expert grade needs correction."),
    ],
    reviewer: Annotated[str, typer.Option(help="Expert reviewer identity for the audit record.")],
    verdict: Annotated[
        EvaluationVerdict,
        typer.Option(help="Complete replacement judgment for the same reviewed subject."),
    ],
    amendment_reason: Annotated[
        str,
        typer.Option(
            "--reason",
            help="Required explanation of why the previous judgment was incorrect.",
        ),
    ],
    config: ConfigOption = DEFAULT_CONFIG,
    notes: Annotated[
        str,
        typer.Option(help="Complete replacement evidence supporting the corrected judgment."),
    ] = "",
    policy_failure: Annotated[
        bool,
        typer.Option(help="Corrected repository-policy or legal-process failure value."),
    ] = False,
    security_failure: Annotated[
        bool,
        typer.Option(help="Corrected credential, isolation, or security failure value."),
    ] = False,
    etiquette_failure: Annotated[
        bool,
        typer.Option(help="Corrected spam, disclosure, or maintainer-time harm value."),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option(
            "--yes",
            help="Attest to the displayed correction without an interactive prompt.",
        ),
    ] = False,
) -> None:
    """Append a reviewed correction without mutating or deleting prior grades."""

    settings = _config(config)
    evaluations = EvaluationStore(RunStore(settings.storage.path))
    try:
        preview = evaluations.preview_amendment(
            run_id,
            reviewer=reviewer,
            verdict=verdict,
            amendment_reason=amendment_reason,
            notes=notes,
            policy_failure=policy_failure,
            security_failure=security_failure,
            etiquette_failure=etiquette_failure,
        )
    except (AutocontributeError, ValueError) as exc:
        _fail(str(exc))
    console.print(_render_evaluation_preview(preview), markup=False)
    if not yes and not typer.confirm(
        "I reviewed every field above and attest that this correction is accurate"
    ):
        raise typer.Abort()
    try:
        evaluation = evaluations.commit_preview(preview)
    except (AutocontributeError, ValueError) as exc:
        _fail(str(exc))
    console.print(
        f"[green]Appended revision {evaluation.revision}[/green] "
        f"{evaluation.verdict.value} for `{evaluation.run_id}` "
        f"(record `{evaluation_hash(evaluation)}`)."
    )


@evaluation_app.command(name="report")
def evaluation_report(
    config: ConfigOption = DEFAULT_CONFIG,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit the machine-readable summary."),
    ] = False,
) -> None:
    """Report whether measured evidence satisfies the conservative shadow gate."""

    settings = _config(config)
    try:
        summary = EvaluationStore(RunStore(settings.storage.path)).summary(
            deployment_fingerprint=compute_deployment_fingerprint(settings)
        )
    except AutocontributeError as exc:
        _fail(str(exc))
    if json_output:
        console.print(summary.model_dump_json(indent=2), markup=False, soft_wrap=True)
        return
    marker = "PASS" if summary.shadow_gate_passed else "NOT READY"
    color = "green" if summary.shadow_gate_passed else "yellow"
    console.print(f"[{color}]Shadow rollout gate: {marker}[/{color}]")
    for evidence in summary.gate_evidence:
        console.print(f"- {evidence}")


@rollout_app.command(name="report")
def rollout_report(
    config: ConfigOption = DEFAULT_CONFIG,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit the complete machine-readable decision."),
    ] = False,
) -> None:
    """Report every gate required before autonomous publication is authorized."""

    settings = _config(config)
    store = RunStore(settings.storage.path)
    try:
        with _github_client(settings, store) as github:
            summary = _rollout_summary(settings, store, github)
    except (AutocontributeError, ValueError) as exc:
        _fail(str(exc))
    if json_output:
        console.print(summary.model_dump_json(indent=2), markup=False, soft_wrap=True)
        return
    marker = "PASS" if summary.overall_gate_passed else "NOT READY"
    color = "green" if summary.overall_gate_passed else "yellow"
    console.print(f"[{color}]Combined autonomous rollout gate: {marker}[/{color}]")
    console.print(
        "Scope: "
        f"{summary.scope.publishing_login} at {summary.scope.publishing_api_origin} "
        f"(deployment {summary.scope.deployment_fingerprint})",
        markup=False,
    )
    for evidence in summary.gate_evidence:
        console.print(f"- {evidence}", markup=False)


@state_app.command(name="backup")
def backup_state(
    config: ConfigOption = DEFAULT_CONFIG,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help=(
                "Destination. Defaults to <storage.path>/snapshots/state.sqlite3, or "
                "state.bundle.zip with --complete."
            ),
        ),
    ] = None,
    overwrite: Annotated[
        bool,
        typer.Option(help="Atomically replace an existing snapshot or bundle."),
    ] = False,
    complete: Annotated[
        bool,
        typer.Option(
            "--complete",
            help="Include SQLite, run evidence, and expert evaluations in one checksummed bundle.",
        ),
    ] = False,
) -> None:
    """Create a verified SQLite snapshot or complete portable state bundle."""

    settings = _config(config)
    store = RunStore(settings.storage.path)
    default_name = "state.bundle.zip" if complete else "state.sqlite3"
    destination = output or settings.storage.path / "snapshots" / default_name
    try:
        snapshot = (
            create_state_bundle(store, destination, overwrite=overwrite)
            if complete
            else store.create_snapshot(destination, overwrite=overwrite)
        )
    except AutocontributeError as exc:
        _fail(str(exc))
    kind = "complete state bundle" if complete else "state snapshot"
    console.print(f"[green]Verified {kind}:[/green] {snapshot}")


@state_app.command(name="restore")
def restore_state(
    input_path: Annotated[
        Path,
        typer.Option(
            "--input",
            "-i",
            help="Snapshot or complete bundle to verify and promote into absent live state.",
        ),
    ],
    config: ConfigOption = DEFAULT_CONFIG,
    complete: Annotated[
        bool,
        typer.Option(
            "--complete",
            help="Restore SQLite, run evidence, and expert evaluations from a complete bundle.",
        ),
    ] = False,
) -> None:
    """Verify and atomically promote a snapshot or complete state generation."""

    settings = _config(config)
    try:
        restored = (
            restore_state_bundle(settings.storage.path, input_path)
            if complete
            else RunStore.restore_snapshot(settings.storage.path, input_path)
        )
    except AutocontributeError as exc:
        _fail(str(exc))
    kind = "complete state" if complete else "state"
    console.print(f"[green]Verified {kind} restored:[/green] {restored}")


@state_app.command(name="replicate-s3")
def replicate_state_s3(
    input_path: Annotated[
        Path,
        typer.Option(
            "--input",
            "-i",
            help="Verified complete state bundle to replicate and read back.",
        ),
    ],
    bucket: Annotated[
        str,
        typer.Option(help="Dedicated AWS S3 Object Lock bucket name."),
    ],
    region: Annotated[
        str,
        typer.Option(help="AWS region containing the backup bucket."),
    ],
    expected_bucket_owner: Annotated[
        str,
        typer.Option(
            "--expected-bucket-owner",
            help="Exact 12-digit AWS account ID that must own the backup bucket.",
        ),
    ],
    scratch_directory: Annotated[
        Path,
        typer.Option(
            "--scratch-directory",
            help="Pre-existing trusted directory with capacity for verified read-back.",
        ),
    ],
    prefix: Annotated[
        str,
        typer.Option(help="Object-key prefix reserved for this deployment."),
    ] = "autocontribute",
    retention_days: Annotated[
        int,
        typer.Option(
            "--retention-days",
            min=30,
            max=3_650,
            help="Compliance-mode retention applied to both bundle and receipt.",
        ),
    ] = 90,
    record_output: Annotated[
        Path | None,
        typer.Option(
            "--record-output",
            help="Exclusive local locator for the immutable off-host receipt version.",
        ),
    ] = None,
    timeout_seconds: Annotated[
        float,
        typer.Option(
            min=10,
            max=86_400,
            help="Per-request timeout for large bundle upload and read-back.",
        ),
    ] = 21_600,
) -> None:
    """Compliance-lock a complete bundle in S3, read it back, and persist its receipt."""

    access_key_id = os.environ.get("AWS_ACCESS_KEY_ID")
    secret_access_key = os.environ.get("AWS_SECRET_ACCESS_KEY")
    if not access_key_id or not secret_access_key:
        _fail(
            "AWS S3 replication credentials are missing; set AWS_ACCESS_KEY_ID and "
            "AWS_SECRET_ACCESS_KEY"
        )
    assert access_key_id is not None and secret_access_key is not None
    destination = record_output or input_path.with_name(f"{input_path.name}.s3-replication.json")
    try:
        record = replicate_state_bundle_to_s3(
            input_path,
            bucket=bucket,
            expected_bucket_owner=expected_bucket_owner,
            region=region,
            prefix=prefix,
            retain_until=datetime.now(UTC) + timedelta(days=retention_days),
            scratch_directory=scratch_directory,
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            session_token=os.environ.get("AWS_SESSION_TOKEN"),
            record_destination=destination,
            timeout_seconds=timeout_seconds,
        )
    except AutocontributeError as exc:
        _fail(str(exc))
    console.print("[green]Verified immutable S3 backup replica and receipt.[/green]")
    console.print(
        f"Bundle: s3://{record.receipt.bundle.bucket}/{record.receipt.bundle.key} "
        f"(version {record.receipt.bundle.version_id})",
        markup=False,
    )
    console.print(
        f"Receipt: s3://{record.receipt_object.bucket}/{record.receipt_object.key} "
        f"(version {record.receipt_object.version_id})",
        markup=False,
    )
    console.print(f"Local record: {destination}", markup=False)


@state_app.command(name="gc-workspaces")
def gc_workspaces(
    config: ConfigOption = DEFAULT_CONFIG,
    older_than_days: Annotated[
        int,
        typer.Option(
            "--older-than-days",
            min=1,
            max=3_650,
            help="Only inspect terminal workspaces older than this many days.",
        ),
    ] = 7,
    limit: Annotated[
        int,
        typer.Option(
            min=1,
            max=1_000,
            help="Maximum old terminal workspace entries inspected in this invocation.",
        ),
    ] = 25,
    execute: Annotated[
        bool,
        typer.Option(
            "--execute",
            help="Delete entries that pass every safety check; the default is a dry run.",
        ),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit the machine-readable cleanup report."),
    ] = False,
) -> None:
    """Report or safely remove old terminal repository workspaces."""

    settings = _config(config)
    try:
        report = collect_terminal_workspaces(
            RunStore(settings.storage.path),
            older_than=timedelta(days=older_than_days),
            limit=limit,
            execute=execute,
        )
    except (AutocontributeError, ValueError) as exc:
        _fail(str(exc))
    if json_output:
        console.print(report.model_dump_json(indent=2), markup=False, soft_wrap=True)
    else:
        _print_workspace_gc_report(report)
    if report.errors:
        raise typer.Exit(2)


@lifecycle_app.command(name="sync")
def lifecycle_sync(config: ConfigOption = DEFAULT_CONFIG) -> None:
    """Poll every durable open pull request and activate any hard safety stop."""

    settings = _config(config)
    store = RunStore(settings.storage.path)
    try:
        with _github_client(settings, store) as github:
            result = _sync_lifecycle(settings, store, github)
    except (AutocontributeError, ValueError) as exc:
        _fail(str(exc))
    _print_lifecycle_result(result)
    status = store.circuit_breaker_status()
    if status.is_tripped:
        console.print(
            f"Safety stop active: {status.source}: {status.reason}",
            style="red",
            markup=False,
        )
        raise typer.Exit(2)


@safety_app.command(name="status")
def safety_status(
    config: ConfigOption = DEFAULT_CONFIG,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit the machine-readable breaker status."),
    ] = False,
) -> None:
    """Show whether autonomous preparation and publication are persistently stopped."""

    settings = _config(config)
    try:
        status = RunStore(settings.storage.path).circuit_breaker_status()
    except AutocontributeError as exc:
        _fail(str(exc))
    if json_output:
        console.print(
            json.dumps(
                {
                    "is_tripped": status.is_tripped,
                    "epoch": status.epoch,
                    "changed_at": status.changed_at.isoformat(),
                    "source": status.source,
                    "reason": status.reason,
                    "trigger_hash": status.trigger_hash,
                    "active_revision": status.active_revision,
                    "active_triggers": [
                        {
                            "source": trigger.source,
                            "reason": trigger.reason,
                            "trigger_hash": trigger.trigger_hash,
                        }
                        for trigger in status.active_triggers
                    ],
                },
                indent=2,
                sort_keys=True,
            ),
            markup=False,
            soft_wrap=True,
        )
        return
    if status.is_tripped:
        console.print("[red]STOPPED[/red]")
        console.print(f"Source: {status.source}", markup=False)
        console.print(f"Reason: {status.reason}", markup=False)
        console.print(f"Latest trigger hash: {status.trigger_hash}", markup=False)
        console.print(f"Active trigger-set revision: {status.active_revision}", markup=False)
        console.print("Active trigger evidence:")
        for index, trigger in enumerate(status.active_triggers, start=1):
            console.print(
                f"  {index}. {trigger.source}: {trigger.reason} [{trigger.trigger_hash}]",
                markup=False,
            )
    else:
        console.print("[green]OPERATIONAL[/green]")
    console.print(f"Safety epoch: {status.epoch}")
    console.print(f"Changed: {status.changed_at.isoformat()}")


@safety_app.command(name="stop")
def safety_stop(
    actor: Annotated[str, typer.Option(help="Operator identity recorded in the audit trail.")],
    reason: Annotated[str, typer.Option(help="Concrete reason autonomous work must stop.")],
    config: ConfigOption = DEFAULT_CONFIG,
) -> None:
    """Persistently stop preparation and publication without requiring GitHub access."""

    settings = _config(config)
    store = RunStore(settings.storage.path)
    actor = actor.strip()
    reason = reason.strip()
    if not actor:
        _fail("operator identity cannot be blank")
    if not reason:
        _fail("safety-stop reason cannot be blank")
    trigger_hash = hashlib.sha256(
        json.dumps(
            {"actor": actor, "nonce": uuid.uuid4().hex, "reason": reason},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    try:
        store.trip_circuit_breaker(
            source=f"operator:{actor}",
            reason=reason,
            trigger_hash=trigger_hash,
        )
    except (AutocontributeError, TypeError, ValueError) as exc:
        _fail(str(exc))
    status = store.circuit_breaker_status()
    console.print(
        f"Safety stop activated: {status.source}: {status.reason}",
        style="red",
        markup=False,
    )


@safety_app.command(name="resume")
def safety_resume(
    actor: Annotated[str, typer.Option(help="Operator identity recorded in the audit trail.")],
    reason: Annotated[
        str,
        typer.Option(help="Reviewed evidence supporting an explicit operational resume."),
    ],
    expected_trigger_hash: Annotated[
        str,
        typer.Option(
            "--expected-trigger-hash",
            help="Exact active trigger-set revision shown by `safety status` after review.",
        ),
    ],
    config: ConfigOption = DEFAULT_CONFIG,
) -> None:
    """Resume only after an operator has reviewed and resolved the stop evidence."""

    settings = _config(config)
    store = RunStore(settings.storage.path)
    try:
        resumed = store.resume_circuit_breaker(
            actor=actor,
            reason=reason,
            expected_trigger_hash=expected_trigger_hash,
        )
    except (AutocontributeError, TypeError, ValueError) as exc:
        _fail(str(exc))
    if not resumed:
        console.print("[yellow]Safety stop was not active.[/yellow]")
        return
    console.print("[green]Safety stop explicitly resumed.[/green]")


@app.command()
def version() -> None:
    """Print the installed version."""

    console.print(__version__)


def _render_evaluation_preview(evaluation: EvaluationRevision) -> str:
    """Render every persisted field without allowing terminal control sequences."""

    payload = json.dumps(
        evaluation.model_dump(mode="json"),
        ensure_ascii=True,
        indent=2,
        sort_keys=True,
    )
    revision = evaluation.schema_version if evaluation.schema_version == 1 else evaluation.revision
    return "\n".join(
        [
            f"# Exact expert-evaluation preview (revision {revision})",
            "",
            "Every stored field is shown below. Terminal-control and non-ASCII characters are ",
            "JSON escaped. Confirmation binds this exact object and fails if its subject or ",
            "revision predecessor changes before the append.",
            "",
            f"Content SHA-256: {evaluation_hash(evaluation)}",
            "----- BEGIN COMPLETE EVALUATION JSON -----",
            payload,
            "----- END COMPLETE EVALUATION JSON -----",
            "",
        ]
    )


def _require_configured_policy_target(
    settings: AutocontributeConfig,
    repository: str,
) -> None:
    normalized = repository.casefold()
    configured_repositories = {value.casefold() for value in settings.github.repositories}
    configured_owners = {value.casefold() for value in settings.github.owners}
    if not _REPOSITORY.fullmatch(repository):
        _fail("repository must use owner/name syntax")
    owner = normalized.split("/", 1)[0]
    if normalized not in configured_repositories and owner not in configured_owners:
        _fail("repository is outside the configured repository/owner allowlist")


def _render_policy_snapshot(snapshot: PolicySnapshot, *, web_origin: str) -> str:
    requirements = ", ".join(snapshot.legal_requirements) or "none"
    lines = [
        "# Immutable contribution-policy snapshot",
        f"Repository: {snapshot.repository}",
        f"Repository policy ref: {snapshot.repository_ref}",
        f"Organization policy repository: {snapshot.organization_repository}",
        f"Organization policy ref: {snapshot.organization_ref_evidence}",
        f"Policy sources SHA-256: {snapshot.policy_sources_sha256}",
        f"Stable legal-policy SHA-256: {snapshot.legal_policy_sha256}",
        f"Repository policy files: {len(snapshot.repository_paths)}",
        f"Organization policy files: {len(snapshot.organization_paths)}",
        f"Detected legal requirements: {requirements}",
        "Repository policy review URLs:",
        *_immutable_policy_urls(
            web_origin,
            snapshot.repository,
            snapshot.repository_ref,
            snapshot.repository_paths,
        ),
        "Organization policy review URLs:",
        *_immutable_policy_urls(
            web_origin,
            snapshot.organization_repository,
            snapshot.organization_ref,
            snapshot.organization_paths,
        ),
    ]
    return "\n".join(lines)


def _immutable_policy_urls(
    web_origin: str,
    repository: str,
    ref: str | None,
    paths: tuple[str, ...],
) -> list[str]:
    if ref is None or not paths:
        return ["  (none)"]
    return [f"  - {web_origin}/{repository}/blob/{ref}/{quote(path, safe='/')}" for path in paths]


def _config(path: Path):  # type: ignore[no-untyped-def]
    try:
        return load_config(path)
    except ConfigurationError as exc:
        _fail(str(exc))


def _github_client(
    settings: AutocontributeConfig,
    store: RunStore,
) -> GitHubClient:
    """Create a production client whose GitHub safety signals are durable before failure."""

    return GitHubClient(
        settings.github,
        safety_trigger_handler=store.trip_circuit_breaker_trigger,
    )


def _rollout_summary(
    settings: AutocontributeConfig,
    store: RunStore,
    github: GitHubClient,
    *,
    exclude_run_id: str | None = None,
) -> RolloutSummary:
    """Compute one decision for the exact deployed code and publishing identity."""

    scope = UpstreamPublicationScope(
        deployment_fingerprint=compute_deployment_fingerprint(settings),
        publishing_login=github.authenticated_login().strip().casefold(),
        publishing_api_origin=github.api_origin,
    )
    return RolloutGate.for_store(store).summary(
        scope,
        exclude_run_id=exclude_run_id,
    )


def _scheduled_auto_preflight(
    settings: AutocontributeConfig,
    store: RunStore,
    github: GitHubClient,
) -> bool:
    """Defer scheduled automatic work before a run or model call when authority is absent."""

    if settings.publishing.mode != "auto":
        return True
    summary = _rollout_summary(settings, store, github)
    switch_enabled = auto_publish_opt_in_enabled(settings.publishing)
    if switch_enabled and summary.overall_gate_passed:
        return True

    blockers: list[str] = []
    if not switch_enabled:
        blockers.append(
            f"{settings.publishing.auto_publish_env} is not enabled as the dedicated "
            "automatic-publication switch"
        )
    if not summary.evaluation_gate_passed:
        blockers.append("expert-evaluation shadow cohort")
    if not summary.manual_cohort_passed:
        blockers.append("fixed manual upstream-outcome cohort")
    if not summary.prior_automatic_passed:
        blockers.append("prior automatic upstream outcomes")
    if (
        not summary.upstream_outcome_gate_passed
        and summary.manual_cohort_passed
        and summary.prior_automatic_passed
    ):
        blockers.append("complete upstream-outcome evidence")
    console.print(
        "[yellow]Scheduled automatic run deferred before model use:[/yellow] " + ", ".join(blockers)
    )
    return False


def _sync_lifecycle(
    settings: AutocontributeConfig,
    store: RunStore,
    github: GitHubClient,
    *,
    publication_retry_run_id: str | None = None,
    resume_submitting_publications: bool = False,
    scheduled_preflight: bool = False,
) -> LifecycleSyncResult:
    publisher = Publisher(settings, store, github)
    reconciliation_failures: list[tuple[str, AutocontributeError]] = []
    with LeaseHeartbeatGuard(
        store,
        PUBLICATION_LEASE_NAME,
        ttl=PUBLICATION_LEASE_TTL,
        heartbeat_interval=PUBLICATION_HEARTBEAT_INTERVAL,
    ) as lease_guard:
        lease_guard.assert_owned()
        result = sync_open_pull_requests(
            github,
            store,
            assert_owned=lease_guard.assert_owned,
        )
        lease_guard.assert_owned()
        for manifest in store.list_submitting_runs():
            lease_guard.assert_owned()
            try:
                reconcile_owned = getattr(publisher, "_reconcile_submitting", None)
                if callable(reconcile_owned):
                    reconcile_owned(
                        manifest.run_id,
                        lease_guard=lease_guard,
                    )
                else:  # Narrow compatibility path for injected CLI test doubles.
                    publisher.reconcile_submitting(manifest.run_id)
            except PublicationResumeRequired:
                lease_guard.assert_owned()
                retry_this_run = manifest.run_id == publication_retry_run_id
                scheduled_resume_allowed = (
                    resume_submitting_publications
                    and settings.publishing.mode == "auto"
                    and auto_publish_opt_in_enabled(settings.publishing)
                )
                if not (scheduled_resume_allowed or retry_this_run):
                    if scheduled_preflight:
                        continue
                    if settings.publishing.mode != "auto":
                        reason = "publishing.mode is review_required"
                    elif not auto_publish_opt_in_enabled(settings.publishing):
                        reason = (
                            f"{settings.publishing.auto_publish_env} is not enabled as the "
                            "dedicated automatic-publication switch"
                        )
                    else:
                        reason = "this lifecycle sync has no publication-resume authorization"
                    reconciliation_failures.append(
                        (
                            manifest.run_id,
                            PublicationResumeRequired(
                                f"Run {manifest.run_id} requires publication resumption, but "
                                f"GitHub writes are disabled because {reason}; use "
                                f"`autocontribute publish {manifest.run_id}` after review"
                            ),
                        )
                    )
                    continue
                lease_guard.assert_owned()
                try:
                    publish_owned = getattr(publisher, "_publish", None)
                    if callable(publish_owned):
                        publish_owned(manifest.run_id, lease_guard=lease_guard)
                    else:  # Narrow compatibility path for injected CLI test doubles.
                        publisher.publish(manifest.run_id)
                except AutomaticRolloutBlocked as resume_exc:
                    lease_guard.assert_owned()
                    if not scheduled_preflight:
                        reconciliation_failures.append((manifest.run_id, resume_exc))
                except AutocontributeError as resume_exc:
                    lease_guard.assert_owned()
                    reconciliation_failures.append((manifest.run_id, resume_exc))
                else:
                    lease_guard.assert_owned()
            except AutocontributeError as exc:
                lease_guard.assert_owned()
                reconciliation_failures.append((manifest.run_id, exc))
            else:
                lease_guard.assert_owned()
    if len(reconciliation_failures) == 1:
        raise reconciliation_failures[0][1]
    if reconciliation_failures:
        details = "; ".join(f"{run_id}: {failure}" for run_id, failure in reconciliation_failures)
        raise StateError(
            "Multiple submitting runs could not be reconciled after lifecycle observation: "
            + details
        ) from reconciliation_failures[0][1]
    return result


def _print_lifecycle_result(result: LifecycleSyncResult) -> None:
    console.print(
        "Lifecycle sync: "
        f"{result.runs_checked} PR(s), "
        f"{result.snapshots_recorded} new snapshot(s), "
        f"{result.signals_detected} safety signal(s), "
        f"{result.newly_tripped} new trigger(s)."
    )
    for item in result.observations:
        for signal in item.observation.signals:
            console.print(
                f"- {signal.kind.value}: {signal.repository}#{signal.pull_request_number}: "
                f"{signal.reason} ({signal.source_url})",
                markup=False,
            )


def _print_workspace_gc_report(report: WorkspaceGCReport) -> None:
    mode = "EXECUTE" if report.execute else "DRY RUN"
    color = "green" if report.execute else "yellow"
    console.print(
        f"[{color}]Workspace cleanup: {mode}[/{color}] "
        f"(terminal cutoff {report.cutoff.isoformat()}, inspection limit {report.limit})"
    )
    if report.items:
        table = Table("Run", "Status", "Action", "Entries", "Bytes", "Reason")
        for item in report.items:
            table.add_row(
                Text(json.dumps(item.run_id, ensure_ascii=True)[1:-1]),
                item.status.value,
                item.action,
                f"{item.entries:,}",
                f"{item.bytes:,}",
                item.reason,
                style="red" if item.error else None,
            )
        console.print(table)
    console.print(
        "Summary: "
        f"{report.deleted} deleted, {report.would_delete} would delete, "
        f"{report.retained} retained, {report.errors} error(s), "
        f"{report.protected_nonterminal} nonterminal workspace(s) protected, "
        f"{report.younger_terminal} terminal workspace(s) inside retention, "
        f"{report.truncated} old terminal candidate(s) deferred."
    )


def _print_outcome(manifest: RunManifest, store: RunStore) -> None:
    colors = {
        RunStatus.READY_FOR_APPROVAL: "green",
        RunStatus.PR_OPEN: "green",
        RunStatus.SKIPPED: "yellow",
        RunStatus.REJECTED: "yellow",
        RunStatus.FAILED: "red",
    }
    color = colors.get(manifest.status, "white")
    console.print(f"[{color}]Run {manifest.run_id}: {manifest.status.value}[/{color}]")
    console.print(f"Evidence: {store.artifact_dir(manifest.run_id)}")
    if manifest.pull_request_url:
        console.print(manifest.pull_request_url)
    if manifest.skip_reason:
        console.print(manifest.skip_reason)
    if manifest.error:
        console.print(f"[red]{manifest.error}[/red]")


def _show_report(store: RunStore, manifest: RunManifest) -> None:
    del store
    console.print(
        render_run_report(manifest, manifest.patched_validation),
        markup=False,
    )


def _refresh_report(store: RunStore, manifest: RunManifest) -> None:
    store.write_artifact(
        manifest.run_id,
        "report.md",
        render_run_report(manifest, manifest.patched_validation),
    )


def _fail(message: str) -> None:
    console.print(f"[red]Error:[/red] {message}")
    raise typer.Exit(1)


if __name__ == "__main__":  # pragma: no cover
    app()
