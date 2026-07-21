"""Command-line interface for preparation, approval, and publication."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
import yaml
from rich.console import Console
from rich.table import Table

from autocontribute import __version__
from autocontribute.config import example_config, load_config
from autocontribute.discovery import DiscoveryService
from autocontribute.doctor import run_doctor
from autocontribute.domain import CommandResult, RunManifest, RunStatus
from autocontribute.exceptions import AutocontributeError, ConfigurationError
from autocontribute.github import GitHubClient
from autocontribute.orchestrator import Orchestrator
from autocontribute.publication import Publisher, approve_run
from autocontribute.reporting import render_run_report
from autocontribute.store import RunStore

app = typer.Typer(
    name="autocontribute",
    help="Prepare issue-backed open-source contributions behind hard quality gates.",
    no_args_is_help=True,
)
runs_app = typer.Typer(help="Inspect durable contribution runs.", no_args_is_help=True)
config_app = typer.Typer(help="Inspect configuration safely.", no_args_is_help=True)
app.add_typer(runs_app, name="runs")
app.add_typer(config_app, name="config")

console = Console()
DEFAULT_CONFIG = Path("autocontribute.yml")
ConfigOption = Annotated[
    Path,
    typer.Option("--config", "-c", help="Path to the YAML configuration."),
]


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
    checks = run_doctor(settings)
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
def discover(config: ConfigOption = DEFAULT_CONFIG) -> None:
    """Find the strongest current candidate without cloning or changing GitHub."""

    settings = _config(config)
    store = RunStore(settings.storage.path)
    try:
        with GitHubClient(settings.github) as github:
            selection = DiscoveryService(settings, github, store).discover()
    except AutocontributeError as exc:
        _fail(str(exc))
    if selection is None:
        console.print("[yellow]No candidate passed every deterministic discovery gate.[/yellow]")
        return
    issue, repository, eligibility = selection
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
    scheduled: Annotated[
        bool,
        typer.Option(
            help="Mark invocation as scheduler-driven; behavior remains policy-controlled."
        ),
    ] = False,
) -> None:
    """Prepare one candidate, or skip safely when evidence is insufficient."""

    del scheduled  # Kept explicit for audit-friendly workflow invocations.
    settings = _config(config)
    store = RunStore(settings.storage.path)
    github: GitHubClient | None = None
    try:
        github = GitHubClient(settings.github)
        with Orchestrator(settings, store=store, github=github) as orchestrator:
            manifest = orchestrator.run(issue_reference=issue)
        if manifest.status == RunStatus.READY_FOR_APPROVAL and settings.publishing.mode == "auto":
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
    manifest = store.get(run_id)
    _show_report(store, manifest)
    if not yes and not typer.confirm(
        "I reviewed the exact diff, validation evidence, and PR text and authorize publication"
    ):
        raise typer.Abort()
    try:
        with GitHubClient(settings.github) as github:
            actor = github.authenticated_login()
        manifest = approve_run(
            settings,
            store,
            run_id,
            actor=actor,
            attestation="Reviewed exact diff, validation evidence, and pull-request text.",
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
        with GitHubClient(settings.github) as github:
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
    _show_report(store, store.get(run_id))


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


@app.command()
def version() -> None:
    """Print the installed version."""

    console.print(__version__)


def _config(path: Path):  # type: ignore[no-untyped-def]
    try:
        return load_config(path)
    except ConfigurationError as exc:
        _fail(str(exc))


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
    path = store.artifact_dir(manifest.run_id) / "report.md"
    if path.is_file() and not path.is_symlink():
        console.print(path.read_text(encoding="utf-8"), markup=False)
    else:
        console.print(manifest.model_dump_json(indent=2), markup=False)


def _refresh_report(store: RunStore, manifest: RunManifest) -> None:
    validation_path = store.artifact_dir(manifest.run_id) / "validation.json"
    commands: list[CommandResult] = []
    if validation_path.is_file() and not validation_path.is_symlink():
        try:
            payload = json.loads(validation_path.read_text(encoding="utf-8"))
            values = payload.get("patched", []) if isinstance(payload, dict) else payload
            commands = [CommandResult.model_validate(value) for value in values]
        except (ValueError, OSError):
            commands = []
    store.write_artifact(
        manifest.run_id,
        "report.md",
        render_run_report(manifest, commands),
    )


def _fail(message: str) -> None:
    console.print(f"[red]Error:[/red] {message}")
    raise typer.Exit(1)


if __name__ == "__main__":  # pragma: no cover
    app()
