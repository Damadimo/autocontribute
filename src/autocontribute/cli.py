"""Command-line interface for preparation, approval, and publication."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Annotated, NoReturn
from urllib.parse import quote

import typer
import yaml
from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from autocontribute import __version__
from autocontribute.approval import FINGERPRINT_PREFIX, fingerprint_matches
from autocontribute.config import (
    CLA_ATTESTATION_STATEMENT,
    DCO_ATTESTATION_STATEMENT,
    AutocontributeConfig,
    LegalAttestation,
    example_config,
    load_config,
    starter_placeholders,
)
from autocontribute.coordination import (
    PUBLICATION_HEARTBEAT_INTERVAL,
    PUBLICATION_LEASE_NAME,
    PUBLICATION_LEASE_TTL,
    LeaseHeartbeatGuard,
)
from autocontribute.discovery import DiscoveryOutcome, DiscoveryService, PolicySnapshot
from autocontribute.doctor import run_doctor
from autocontribute.domain import RunManifest, RunStatus
from autocontribute.exceptions import (
    ApprovalMismatchError,
    AutocontributeError,
    ConfigurationError,
    PolicyError,
    PublicationLimitError,
    PublicationResumeRequired,
    ReviewTooLargeError,
    StateError,
)
from autocontribute.github import GitHubClient
from autocontribute.github_origin import web_origin_for_api
from autocontribute.lifecycle import LifecycleSyncResult, sync_open_pull_requests
from autocontribute.orchestrator import Orchestrator, RunInvocationMode
from autocontribute.publication import Publisher, approve_run, build_approval_review
from autocontribute.reporting import (
    render_approval_review,
    render_github_review,
    render_run_report,
)
from autocontribute.state_archive import export_state, import_state
from autocontribute.store import CandidateRetryAuthorization, RunStore

app = typer.Typer(
    name="autocontribute",
    help="Prepare issue-backed open-source contributions behind hard quality gates.",
    no_args_is_help=True,
)
runs_app = typer.Typer(help="List, show, or cancel contribution runs.", no_args_is_help=True)
config_app = typer.Typer(help="Inspect configuration safely.", no_args_is_help=True)
lifecycle_app = typer.Typer(
    help="Observe published pull requests and persist maintainer/CI safety signals.",
    no_args_is_help=True,
)
safety_app = typer.Typer(
    help="Inspect or explicitly change the global safety stop and the scoped holds.",
    no_args_is_help=True,
)
policy_app = typer.Typer(
    help="Inspect immutable repository policy and create scoped legal attestations.",
    no_args_is_help=True,
)
app.add_typer(runs_app, name="runs")
app.add_typer(config_app, name="config")
app.add_typer(lifecycle_app, name="lifecycle")
app.add_typer(safety_app, name="safety")
state_app = typer.Typer(
    help="Copy the local state to and from one archive, for runners without a disk.",
    no_args_is_help=True,
)
app.add_typer(policy_app, name="policy")
app.add_typer(state_app, name="state")

console = Console()
DEFAULT_CONFIG = Path("autocontribute.yml")
ConfigOption = Annotated[
    Path,
    typer.Option("--config", "-c", help="Path to the YAML configuration."),
]
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
# Prepared work that has not started publishing. Earlier stages belong to a live worker, and a
# submitting run must be reconciled with GitHub before its state can change.
_CANCELLABLE_STATUSES = frozenset({RunStatus.READY_FOR_APPROVAL, RunStatus.APPROVED})
# How long a prepared run may wait for approval beyond the approval lifetime itself.
_UNAPPROVED_RUN_GRACE = timedelta(days=7)


# Statuses whose approval is already on record, so a repeated approval of it is a no-op.
_APPROVAL_RECORDED_STATUSES = frozenset(
    {RunStatus.APPROVED, RunStatus.SUBMITTING, RunStatus.PR_OPEN}
)


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
    console.print(
        "Replace the placeholder repository and sandbox image, then run `autocontribute doctor`."
    )


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
    settings = _actionable_config(config)
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


@app.command()
def discover(
    config: ConfigOption = DEFAULT_CONFIG,
    explain: Annotated[
        bool,
        typer.Option(
            "--explain",
            help=(
                "Also list every evaluated issue with its score and blockers, and every "
                "repository that was skipped or could not be searched."
            ),
        ),
    ] = False,
) -> None:
    """Find the strongest current candidate without cloning or changing GitHub."""

    settings = _actionable_config(config)
    store = RunStore(settings.storage.path)
    try:
        with _github_client(settings, store) as github:
            outcome = DiscoveryService(settings, github, store).discover()
    except AutocontributeError as exc:
        _fail(str(exc))
    if explain:
        console.print(_render_discovery_explanation(outcome), markup=False, soft_wrap=True)
    if outcome.selection is None:
        console.print(f"[yellow]{outcome.no_candidate_reason}[/yellow]")
        return
    issue, repository, eligibility = outcome.selection
    console.print(f"[bold green]{issue.reference}[/bold green] — {escape(issue.title)}")
    console.print(issue.html_url)
    console.print(f"Repository: {repository.full_name} ({repository.stars:,} stars)")
    console.print(f"Candidate readiness: {eligibility.score}/100")
    # Evidence quotes repository files verbatim; markup parsing would alter or reject them.
    for name, evidence in eligibility.evidence.items():
        console.print(f"  {name}: {evidence}", markup=False, soft_wrap=True)
    console.print(outcome.summary, markup=False)


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
            help="Make one unattended attempt: run lifecycle sync, pick the issue, never publish."
        ),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Print the run outcome as JSON."),
    ] = False,
) -> None:
    """Prepare one candidate, or skip safely when evidence is insufficient."""

    if scheduled and retry_unchanged:
        _fail("--retry-unchanged cannot be used by a scheduled invocation", json_output=json_output)
    if scheduled and issue is not None:
        _fail(
            "--scheduled cannot be combined with --issue; pinned retries must be manual",
            json_output=json_output,
        )
    if retry_unchanged and issue is None:
        _fail("--retry-unchanged requires --issue owner/repository#number", json_output=json_output)
    if retry_unchanged and (retry_actor is None or retry_reason is None):
        _fail(
            "--retry-unchanged requires both --retry-actor and --retry-reason",
            json_output=json_output,
        )
    if not retry_unchanged and (retry_actor is not None or retry_reason is not None):
        _fail(
            "--retry-actor and --retry-reason require --retry-unchanged",
            json_output=json_output,
        )
    try:
        retry_authorization = (
            CandidateRetryAuthorization(actor=retry_actor, reason=retry_reason)
            if retry_actor is not None and retry_reason is not None
            else None
        )
    except (TypeError, ValueError) as exc:
        _fail(str(exc), json_output=json_output)
    settings = _actionable_config(config, json_output=json_output)
    store = RunStore(settings.storage.path)
    github: GitHubClient | None = None
    try:
        _expire_unapproved_runs(settings, store)
        github = _github_client(settings, store)
        if scheduled:
            _sync_lifecycle(settings, store, github, scheduled_preflight=True)
            store.assert_circuit_breaker_clear()
        with Orchestrator(settings, store=store, github=github) as orchestrator:
            manifest = orchestrator.run(
                issue_reference=issue,
                invocation_mode=(
                    RunInvocationMode.SCHEDULED if scheduled else RunInvocationMode.MANUAL
                ),
                retry_authorization=retry_authorization,
            )
    except (AutocontributeError, ValueError) as exc:
        _fail(str(exc), json_output=json_output)
    finally:
        if github is not None:
            github.close()
            if (
                store.record_run_rate_limits(
                    ended_on_secondary_limit=github.secondary_limit_exhausted
                )
                and not json_output
            ):
                console.print(
                    "[red]Three runs in a row ended on a GitHub secondary rate limit; the safety "
                    "stop is now active.[/red]"
                )
    if json_output:
        _emit_json(_run_summary(manifest))
    else:
        _print_outcome(manifest, store)
    if manifest.status == RunStatus.FAILED:
        raise typer.Exit(1)


@app.command()
def approve(
    run_id: Annotated[str, typer.Argument(help="Run identifier to approve.")],
    config: ConfigOption = DEFAULT_CONFIG,
    fingerprint: Annotated[
        str | None,
        typer.Option(
            "--fingerprint",
            help="Fingerprint of the review you read, or its first 12 or more characters.",
        ),
    ] = None,
    source: Annotated[
        str | None,
        typer.Option(
            "--source",
            help="https URL where you gave the approval, such as an issue comment.",
        ),
    ] = None,
    yes: Annotated[
        bool,
        typer.Option("--yes", help="Approve without a prompt; requires --fingerprint."),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Print the outcome as JSON instead of the review."),
    ] = False,
) -> None:
    """Attest that you reviewed the exact diff, checks, and proposed PR.

    Exit codes: 0 approved (or already approved with this fingerprint), 3 the fingerprint no
    longer matches the run, 1 anything else.
    """

    context: dict[str, object] = {"run_id": run_id}
    if yes and fingerprint is None:
        _fail(
            "--yes needs --fingerprint, so the approval binds the review you actually read",
            json_output=json_output,
            context=context,
        )
    if json_output and not yes:
        _fail(
            "--json cannot prompt; pass --yes and --fingerprint", json_output=True, context=context
        )
    if fingerprint is not None and not FINGERPRINT_PREFIX.fullmatch(fingerprint):
        _fail(
            "--fingerprint must be 12 to 64 lowercase hex characters",
            json_output=json_output,
            context=context,
        )
    settings = _config(config, json_output=json_output)
    store = RunStore(settings.storage.path)
    outcome = "already_approved"
    try:
        manifest = store.get(run_id)
        if fingerprint is None or not _already_approved(manifest, fingerprint):
            with _github_client(settings, store) as github:
                if fingerprint is None or not json_output:
                    review = build_approval_review(settings, store, run_id, github=github)
                    console.print(render_approval_review(review), markup=False)
                    if not yes and not typer.confirm(
                        "I reviewed the exact diff, validation evidence, and PR text and "
                        "authorize publication"
                    ):
                        raise typer.Abort()
                    reviewed = fingerprint or review.fingerprint
                else:
                    reviewed = fingerprint
                manifest = approve_run(
                    settings,
                    store,
                    run_id,
                    github=github,
                    attestation="Reviewed exact diff, validation evidence, and pull-request text.",
                    reviewed_fingerprint=reviewed,
                    source=source,
                )
            outcome = "approved"
            _refresh_report(store, manifest)
    except ApprovalMismatchError as exc:
        _fail(
            str(exc),
            exit_code=3,
            json_output=json_output,
            outcome="fingerprint_mismatch",
            context=context,
        )
    except AutocontributeError as exc:
        _fail(str(exc), json_output=json_output, context=context)
    approval = manifest.approval
    assert approval is not None
    if json_output:
        _emit_json(
            {
                "run_id": run_id,
                "outcome": outcome,
                "status": manifest.status.value,
                "fingerprint": approval.manifest_hash,
                "actor": approval.actor,
                "approved_at": approval.approved_at.isoformat(),
                "expires_at": approval.expires_at.isoformat(),
            }
        )
    elif outcome == "approved":
        console.print(f"[green]Approved[/green] `{run_id}` until {approval.expires_at.isoformat()}")
    else:
        console.print(
            f"Run `{run_id}` was already approved with this fingerprint until "
            f"{approval.expires_at.isoformat()}."
        )


@app.command()
def publish(
    run_id: Annotated[str, typer.Argument(help="Approved run identifier.")],
    config: ConfigOption = DEFAULT_CONFIG,
    yes: Annotated[
        bool,
        typer.Option("--yes", help="Perform the authorized GitHub write without another prompt."),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Print the outcome as JSON; requires --yes."),
    ] = False,
) -> None:
    """Push one branch to the reviewed head repository and open one pull request.

    Exit codes: 0 the pull request is open, 3 a limit or stale evidence refused it (wait, or
    prepare the issue again), 4 an interrupted publication needs `publish` again after review,
    5 a safety stop is active, 1 anything else.
    """

    if json_output and not yes:
        _fail("--json cannot prompt; pass --yes", json_output=True, context={"run_id": run_id})
    settings = _config(config, json_output=json_output)
    store = RunStore(settings.storage.path)
    try:
        manifest = store.get(run_id)
    except AutocontributeError as exc:
        _fail(str(exc), json_output=json_output, context={"run_id": run_id})
    if not json_output:
        _show_report(manifest)
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
        state = _publication_state(store, run_id)
        outcome, exit_code = _publication_failure(
            store,
            exc,
            submitting=state["status"] == RunStatus.SUBMITTING.value,
        )
        _fail(
            str(exc), exit_code=exit_code, json_output=json_output, outcome=outcome, context=state
        )
    _refresh_report(store, manifest)
    if json_output:
        _emit_json(
            {
                **_publication_state(store, run_id),
                "outcome": "pr_open",
                "message": "Pull request opened",
            }
        )
    else:
        console.print(f"[bold green]Pull request opened:[/bold green] {manifest.pull_request_url}")


@runs_app.command(name="list")
def list_runs(
    config: ConfigOption = DEFAULT_CONFIG,
    limit: Annotated[
        int,
        typer.Option(
            min=1,
            max=200,
            help="Most runs to list. With --status, more matches fail instead of truncating.",
        ),
    ] = 20,
    status: Annotated[
        str | None,
        typer.Option(
            "--status",
            help="List every run in these comma-separated statuses, oldest first.",
        ),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Print the runs as a JSON array."),
    ] = False,
) -> None:
    """List recent runs and terminal outcomes."""

    statuses = None if status is None else _parse_statuses(status, json_output=json_output)
    settings = _config(config, json_output=json_output)
    try:
        store = RunStore(settings.storage.path)
        manifests = (
            store.list(limit=limit)
            if statuses is None
            else store.list_with_statuses(statuses, limit=limit, resource="selected")
        )
    except AutocontributeError as exc:
        _fail(str(exc), json_output=json_output)
    if json_output:
        _emit_json([_run_summary(manifest) for manifest in manifests])
        return
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
                review = build_approval_review(settings, store, run_id, github=github)
            console.print(render_approval_review(review), markup=False)
        else:
            _show_report(manifest)
    except AutocontributeError as exc:
        _fail(str(exc))


class ReviewFormat(StrEnum):
    GITHUB = "github"


@runs_app.command(name="review")
def review_run(
    run_id: Annotated[str, typer.Argument(help="Run identifier waiting for approval.")],
    review_format: Annotated[
        ReviewFormat,
        typer.Option(
            "--format",
            help="github: an issue body of at most 60,000 characters plus patch parts.",
        ),
    ],
    output_dir: Annotated[
        Path,
        typer.Option("--output-dir", help="New or empty directory for body.md and part-K.md."),
    ],
    config: ConfigOption = DEFAULT_CONFIG,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Print the written files as JSON."),
    ] = False,
) -> None:
    """Write the approval review of a ready run as files to post on GitHub.

    Exit codes: 0 written, 4 the review cannot fit in the body and five parts, 1 anything else.
    """

    context: dict[str, object] = {"run_id": run_id}
    target = output_dir.expanduser().resolve()
    if target.exists() and (not target.is_dir() or any(target.iterdir())):
        _fail(
            f"{target} must be a new or empty directory", json_output=json_output, context=context
        )
    settings = _config(config, json_output=json_output)
    store = RunStore(settings.storage.path)
    try:
        with _github_client(settings, store) as github:
            review = build_approval_review(settings, store, run_id, github=github)
        rendered = render_github_review(
            review,
            approval_expires_hours=settings.publishing.approval_expires_hours,
        )
    except ReviewTooLargeError as exc:
        _fail(
            str(exc),
            exit_code=4,
            json_output=json_output,
            outcome="too_large",
            context=context,
        )
    except AutocontributeError as exc:
        _fail(str(exc), json_output=json_output, context=context)
    target.mkdir(parents=True, exist_ok=True)
    files = [("body.md", rendered.body)] + [
        (f"part-{index}.md", part) for index, part in enumerate(rendered.parts, start=1)
    ]
    for name, text in files:
        (target / name).write_text(text, encoding="utf-8")
    if json_output:
        _emit_json(
            {
                "run_id": run_id,
                "fingerprint": review.fingerprint,
                "approval_command": f"/approve {review.fingerprint[:12]}",
                "body": str(target / "body.md"),
                "body_characters": len(rendered.body),
                "parts": [
                    {"path": str(target / name), "characters": len(text)}
                    for name, text in files[1:]
                ],
                "shortened": list(rendered.shortened),
            }
        )
        return
    console.print(
        f"Wrote body.md and {len(rendered.parts)} part file(s) to {target}. "
        f"Approve with: /approve {review.fingerprint[:12]}",
        markup=False,
    )


@runs_app.command(name="check")
def check_run(
    run_id: Annotated[str, typer.Argument(help="Run identifier to check.")],
    config: ConfigOption = DEFAULT_CONFIG,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Print the checks as JSON."),
    ] = False,
) -> None:
    """Check, without publishing, whether a ready or approved run could publish now.

    Exit codes: 0 every check passed, 3 a check failed, 5 a safety stop is active, 1 the
    checks could not run.
    """

    settings = _config(config, json_output=json_output)
    store = RunStore(settings.storage.path)
    try:
        with _github_client(settings, store) as github:
            checks = Publisher(settings, store, github).check(run_id)
        manifest = store.get(run_id)
    except AutocontributeError as exc:
        outcome, exit_code = _publication_failure(store, exc, submitting=False)
        _fail(
            str(exc),
            exit_code=exit_code,
            json_output=json_output,
            outcome=outcome,
            context={"run_id": run_id},
        )
    failed = {check.name for check in checks if not check.passed}
    if json_output:
        _emit_json(
            {
                "run_id": run_id,
                "status": manifest.status.value,
                "publishable": not failed,
                "checks": [
                    {"name": check.name, "passed": check.passed, "detail": check.detail}
                    for check in checks
                ],
            }
        )
    else:
        table = Table("Check", "Result", "Detail")
        for check in checks:
            result = "[green]PASS[/green]" if check.passed else "[red]FAIL[/red]"
            table.add_row(check.name, result, Text(check.detail))
        console.print(table)
    if "safety_stop" in failed:
        raise typer.Exit(5)
    if failed:
        raise typer.Exit(3)


@runs_app.command(name="cancel")
def cancel_run(
    run_id: Annotated[str, typer.Argument(help="Run identifier to cancel.")],
    reason: Annotated[
        str,
        typer.Option("--reason", help="Why the run is cancelled; recorded in the run ledger."),
    ],
    config: ConfigOption = DEFAULT_CONFIG,
    yes: Annotated[
        bool,
        typer.Option("--yes", help="Cancel without asking for confirmation."),
    ] = False,
) -> None:
    """Cancel a prepared run that is waiting for approval or publication."""

    normalized_reason = reason.strip()
    if not normalized_reason:
        _fail("--reason must explain why the run is cancelled")
    settings = _config(config)
    store = RunStore(settings.storage.path)
    try:
        manifest = store.get(run_id)
    except AutocontributeError as exc:
        _fail(str(exc))
    if manifest.status not in _CANCELLABLE_STATUSES:
        _fail(
            f"Run {run_id} is {manifest.status.value}; only ready_for_approval or approved runs "
            "can be cancelled"
        )
    _show_report(manifest)
    if not yes and not typer.confirm(f"Cancel run {run_id} and release its issue"):
        raise typer.Abort()
    try:
        manifest = store.transition(manifest, RunStatus.CANCELLED, reason=normalized_reason)
    except AutocontributeError as exc:
        _fail(str(exc))
    _refresh_report(store, manifest)
    console.print(f"[yellow]Cancelled[/yellow] `{run_id}`.")


@runs_app.command(name="abandon")
def abandon_run(
    run_id: Annotated[str, typer.Argument(help="Submitting run identifier to abandon.")],
    reason: Annotated[
        str,
        typer.Option("--reason", help="Why the publication is abandoned; recorded in the ledger."),
    ],
    config: ConfigOption = DEFAULT_CONFIG,
    yes: Annotated[
        bool,
        typer.Option("--yes", help="Abandon without asking for confirmation."),
    ] = False,
) -> None:
    """Fail a submitting run whose publication left no branch or pull request on GitHub.

    Exit codes: 0 abandoned, 4 GitHub has the branch or pull request, so resume it with
    `publish`, 1 anything else.
    """

    normalized_reason = reason.strip()
    if not normalized_reason:
        _fail("--reason must explain why the publication is abandoned")
    settings = _config(config)
    store = RunStore(settings.storage.path)
    try:
        manifest = store.get(run_id)
    except AutocontributeError as exc:
        _fail(str(exc))
    if manifest.status != RunStatus.SUBMITTING:
        _fail(f"Run {run_id} is {manifest.status.value}; only submitting runs can be abandoned")
    _show_report(manifest)
    if not yes and not typer.confirm(
        f"Check that run {run_id} left nothing on GitHub, then mark it failed and release its issue"
    ):
        raise typer.Abort()
    try:
        with _github_client(settings, store) as github:
            manifest = Publisher(settings, store, github).abandon(run_id, reason=normalized_reason)
    except PublicationResumeRequired as exc:
        _fail(f"{exc}; resume it with `autocontribute publish {run_id}`", exit_code=4)
    except AutocontributeError as exc:
        _fail(str(exc))
    _refresh_report(store, manifest)
    console.print(f"[yellow]Abandoned[/yellow] `{run_id}`; its issue is released.")


@config_app.command(name="validate")
def validate_config(config: ConfigOption = DEFAULT_CONFIG) -> None:
    """Parse configuration and print a credential-free summary."""

    settings = _actionable_config(config)
    console.print("[green]Configuration is valid.[/green]")
    console.print(f"Repositories: {len(settings.github.repositories)}")
    console.print(f"Owners: {len(settings.github.owners)}")
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
    if snapshot.problems:
        _fail("The policy files could not all be read, so no attestation can cover them")
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
        typer.Option("--json", help="Emit the machine-readable breaker status and holds."),
    ] = False,
) -> None:
    """Show whether preparation and publication are stopped or held, and why."""

    settings = _config(config)
    try:
        store = RunStore(settings.storage.path)
        status = store.circuit_breaker_status()
        holds = store.active_holds()
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
                    "holds": [
                        {
                            "id": hold.hold_id,
                            "scope": hold.scope.value,
                            "scope_key": hold.scope_key,
                            "source": hold.source,
                            "reason": hold.reason,
                            "trigger_hash": hold.trigger_hash,
                            "created_at": hold.created_at.isoformat(),
                            "expires_at": (
                                hold.expires_at.isoformat() if hold.expires_at else None
                            ),
                        }
                        for hold in holds
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
    if not holds:
        console.print("Active holds: none")
        return
    console.print("Active holds (release with `safety release HOLD_ID`):")
    for hold in holds:
        until = f"until {hold.expires_at.isoformat()}" if hold.expires_at else "until released"
        console.print(
            f"  {hold.hold_id}. {hold.scope.value} {hold.scope_key} ({until}): "
            f"{hold.source}: {hold.reason}",
            markup=False,
            soft_wrap=True,
        )


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


@safety_app.command(name="release")
def safety_release(
    hold_id: Annotated[int, typer.Argument(help="Hold ID shown by `safety status`.", min=1)],
    actor: Annotated[str, typer.Option(help="Operator identity recorded in the audit trail.")],
    reason: Annotated[str, typer.Option(help="Reviewed evidence supporting the release.")],
    config: ConfigOption = DEFAULT_CONFIG,
) -> None:
    """Release one hold after review; the same evidence never holds again, new evidence does."""

    settings = _config(config)
    store = RunStore(settings.storage.path)
    try:
        released = store.release_hold(hold_id, actor=actor, reason=reason)
    except (AutocontributeError, TypeError, ValueError) as exc:
        _fail(str(exc))
    if not released:
        console.print(f"[yellow]Hold {hold_id} was already released.[/yellow]")
        return
    console.print(f"[green]Released hold {hold_id}.[/green]")


@state_app.command(name="export")
def state_export(
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="The .tar.gz archive to write."),
    ],
    config: ConfigOption = DEFAULT_CONFIG,
) -> None:
    """Write the database and the evidence of unfinished runs to one archive."""

    settings = _config(config)
    try:
        exported = export_state(RunStore(settings.storage.path), output)
    except (AutocontributeError, OSError) as exc:
        _fail(str(exc))
    console.print(
        f"Exported state with {exported.unfinished_runs} unfinished run(s) to {output} "
        f"(SHA-256 {exported.sha256})",
        markup=False,
    )


@state_app.command(name="import")
def state_import(
    archive: Annotated[Path, typer.Argument(help="An archive written by `state export`.")],
    config: ConfigOption = DEFAULT_CONFIG,
    release_leases: Annotated[
        bool,
        typer.Option(
            "--release-leases",
            help="Drop leases held when the archive was written; only when none of those "
            "processes can still be running.",
        ),
    ] = False,
    force: Annotated[
        bool,
        typer.Option("--force", help="Replace state that already exists."),
    ] = False,
) -> None:
    """Verify an archive from `state export`, then make it the local state."""

    settings = _config(config)
    try:
        released = import_state(
            archive,
            settings.storage.path,
            force=force,
            release_leases=release_leases,
        )
    except (AutocontributeError, OSError) as exc:
        _fail(str(exc))
    console.print(
        f"Imported {archive} into {settings.storage.path}; released {released} lease(s).",
        markup=False,
    )


@app.command()
def version() -> None:
    """Print the installed version."""

    console.print(__version__)


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
        *(f"Problem: {problem}" for problem in snapshot.problems),
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


def _render_discovery_explanation(outcome: DiscoveryOutcome) -> str:
    lines = ["Repositories skipped or failed:"]
    lines.extend(f"  {name}: skipped: {reason}" for name, reason in outcome.skipped_repositories)
    lines.extend(f"  {name}: error: {error}" for name, error in outcome.repository_errors)
    if len(lines) == 1:
        lines.append("  (none)")
    lines.append("Issues:")
    for evaluation in outcome.evaluations:
        eligibility = evaluation.eligibility
        verdict = "eligible" if eligibility.eligible else "blocked"
        lines.append(
            f"  {evaluation.issue.reference} (score {eligibility.score}, {verdict}): "
            f"{evaluation.issue.title}"
        )
        lines.extend(f"    - {blocker}" for blocker in eligibility.blockers)
        lines.extend(f"    note: {note}" for note in evaluation.notes)
    lines.extend(f"  {reference}: error: {error}" for reference, error in outcome.issue_errors)
    if not outcome.evaluations and not outcome.issue_errors:
        lines.append("  (none evaluated)")
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


def _config(path: Path, *, json_output: bool = False) -> AutocontributeConfig:
    try:
        return load_config(path)
    except ConfigurationError as exc:
        _fail(str(exc), json_output=json_output)


def _actionable_config(path: Path, *, json_output: bool = False) -> AutocontributeConfig:
    """Load a configuration that commands may act on: no starter placeholder may remain."""

    settings = _config(path, json_output=json_output)
    placeholders = starter_placeholders(settings)
    if placeholders:
        _fail(
            f"{path} still contains starter placeholders. Replace each one, then run the "
            "command again:\n" + "\n".join(f"  - {placeholder}" for placeholder in placeholders),
            json_output=json_output,
        )
    return settings


def _github_client(
    settings: AutocontributeConfig,
    store: RunStore,
) -> GitHubClient:
    """Create a production client whose GitHub safety signals are durable before failure."""

    return GitHubClient(
        settings.github,
        safety_trigger_handler=store.record_stop,
    )


def _expire_unapproved_runs(settings: AutocontributeConfig, store: RunStore) -> None:
    """Cancel prepared runs left unapproved well past the approval lifetime."""

    expired = store.expire_ready_for_approval_runs(
        ready_before=datetime.now(UTC)
        - timedelta(hours=settings.publishing.approval_expires_hours)
        - _UNAPPROVED_RUN_GRACE,
        reason=(
            "Nobody approved the prepared run within publishing.approval_expires_hours plus 7 days"
        ),
    )
    for manifest in expired:
        _refresh_report(store, manifest)
        console.print(f"[yellow]Expired[/yellow] unapproved run `{manifest.run_id}`.")


def _sync_lifecycle(
    settings: AutocontributeConfig,
    store: RunStore,
    github: GitHubClient,
    *,
    publication_retry_run_id: str | None = None,
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
                publisher._reconcile_submitting(manifest.run_id, lease_guard=lease_guard)
            except PublicationResumeRequired:
                lease_guard.assert_owned()
                if manifest.run_id != publication_retry_run_id:
                    if scheduled_preflight:
                        continue
                    reconciliation_failures.append(
                        (
                            manifest.run_id,
                            PublicationResumeRequired(
                                f"Run {manifest.run_id} requires publication resumption; use "
                                f"`autocontribute publish {manifest.run_id}` after review"
                            ),
                        )
                    )
                    continue
                lease_guard.assert_owned()
                try:
                    publisher._publish(manifest.run_id, lease_guard=lease_guard)
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
        f"{result.signals_detected} signal(s), "
        f"{result.newly_recorded} new stop(s), "
        f"{len(result.failures)} unreadable PR(s)."
    )
    for item in result.observations:
        for signal in item.signals:
            console.print(
                f"- {signal.kind.value}: {signal.repository}#{signal.pull_request_number}: "
                f"{signal.reason} ({signal.source_url})",
                markup=False,
            )
    for failure in result.failures:
        console.print(
            f"- observation failed: run {failure.run_id} ({failure.pull_request_url}): "
            f"{failure.error}",
            markup=False,
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


def _show_report(manifest: RunManifest) -> None:
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


def _publication_failure(
    store: RunStore,
    error: AutocontributeError,
    *,
    submitting: bool,
) -> tuple[str, int]:
    """Name a failed publication and its exit code, so a runner knows whether to wait.

    Lifecycle sync can report another run's interrupted publication; only this run being
    ``submitting`` makes it this run's to resume.
    """

    if store.circuit_breaker_status().is_tripped:
        return "safety_stop", 5
    if isinstance(error, PublicationResumeRequired) and submitting:
        return "resume_required", 4
    if isinstance(error, PublicationLimitError):
        return "limit", 3
    if isinstance(error, PolicyError):
        return "stale", 3
    return "error", 1


def _publication_state(store: RunStore, run_id: str) -> dict[str, object]:
    try:
        manifest = store.get(run_id)
    except AutocontributeError:
        return {"run_id": run_id, "status": None, "pull_request_url": None}
    return {
        "run_id": run_id,
        "status": manifest.status.value,
        "pull_request_url": manifest.pull_request_url,
    }


def _already_approved(manifest: RunManifest, fingerprint: str) -> bool:
    """Whether a repeated approval names the approval this run already recorded."""

    approval = manifest.approval
    if (
        approval is None
        or manifest.status not in _APPROVAL_RECORDED_STATUSES
        or not fingerprint_matches(fingerprint, approval.manifest_hash)
    ):
        return False
    if manifest.status == RunStatus.APPROVED and approval.expires_at <= datetime.now(UTC):
        raise PolicyError(
            f"Run {manifest.run_id} was approved with this fingerprint, but the approval expired "
            f"at {approval.expires_at.isoformat()}; cancel the run and prepare it again"
        )
    return True


def _parse_statuses(value: str, *, json_output: bool) -> frozenset[RunStatus]:
    try:
        return frozenset(RunStatus(name.strip()) for name in value.split(","))
    except ValueError:
        _fail(
            "--status takes comma-separated statuses from: "
            + ", ".join(status.value for status in RunStatus),
            json_output=json_output,
        )


def _run_summary(manifest: RunManifest) -> dict[str, object]:
    candidate = manifest.candidate
    return {
        "run_id": manifest.run_id,
        "status": manifest.status.value,
        "repository": candidate.repository if candidate else None,
        "issue_number": candidate.number if candidate else None,
        "issue_url": candidate.html_url if candidate else None,
        "created_at": manifest.created_at.isoformat(),
        "updated_at": manifest.updated_at.isoformat(),
        "approval_expires_at": (
            manifest.approval.expires_at.isoformat() if manifest.approval else None
        ),
        "pull_request_url": manifest.pull_request_url,
        "skip_reason": manifest.skip_reason,
        "error": manifest.error,
    }


def _emit_json(value: object) -> None:
    # Rich wraps long lines at the console width, which would corrupt machine-read output.
    typer.echo(json.dumps(value, indent=2, sort_keys=True))


def _fail(
    message: str,
    *,
    exit_code: int = 1,
    json_output: bool = False,
    outcome: str = "error",
    context: dict[str, object] | None = None,
) -> NoReturn:
    if json_output:
        _emit_json({**(context or {}), "outcome": outcome, "message": message})
    else:
        # Text is never parsed, so brackets and :name: in a message print as written.
        console.print(Text.assemble(("Error:", "red"), f" {message}"))
    raise typer.Exit(exit_code)


if __name__ == "__main__":  # pragma: no cover
    app()
