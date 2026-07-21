"""Human-reviewable summaries generated from machine-readable run evidence."""

from __future__ import annotations

from autocontribute.domain import CommandResult, RunManifest


def render_run_report(manifest: RunManifest, commands: list[CommandResult]) -> str:
    lines = [
        f"# Autocontribute run `{manifest.run_id}`",
        "",
        f"- Status: `{manifest.status.value}`",
        f"- Created: {manifest.created_at.isoformat()}",
        f"- Updated: {manifest.updated_at.isoformat()}",
    ]
    if manifest.candidate:
        lines.extend(
            [
                f"- Issue: [{manifest.candidate.reference}]({manifest.candidate.html_url})",
                f"- Candidate readiness: {manifest.candidate.score}/100",
            ]
        )
    if manifest.base_sha:
        lines.append(f"- Pinned base: `{manifest.base_sha}`")
    if manifest.quality:
        lines.extend(
            [
                f"- Patch readiness: {manifest.quality.readiness_score}/100",
                f"- Changed scope: {manifest.quality.changed_files} files, "
                f"{manifest.quality.changed_lines} lines",
            ]
        )

    if manifest.skip_reason:
        lines.extend(["", "## Skip reason", "", manifest.skip_reason])
    if manifest.error:
        lines.extend(["", "## Error", "", manifest.error])
    if manifest.plan:
        lines.extend(
            [
                "",
                "## Plan",
                "",
                manifest.plan.issue_understanding,
                "",
                *[f"- {step}" for step in manifest.plan.implementation_steps],
            ]
        )
    if manifest.proposal:
        lines.extend(
            [
                "",
                "## Proposed pull request",
                "",
                f"**{manifest.proposal.pull_request_title}**",
                "",
                manifest.proposal.pull_request_body,
                "",
                f"Commit: `{manifest.proposal.commit_message}`",
            ]
        )
    if commands:
        lines.extend(["", "## Validation evidence", ""])
        if manifest.baseline_validation:
            baseline = manifest.baseline_validation
            marker = "EXPECTED FAIL" if not baseline.passed else "UNEXPECTED PASS"
            lines.append(
                f"- **{marker} (pristine upstream)** `{baseline.command}` — "
                f"exit {baseline.exit_code}, {baseline.duration_seconds:.2f}s"
            )
        for result in commands:
            marker = "PASS" if result.passed else "FAIL"
            lines.append(
                f"- **{marker}** `{result.command}` — exit {result.exit_code}, "
                f"{result.duration_seconds:.2f}s"
            )
    if manifest.quality:
        lines.extend(["", "## Hard gates", ""])
        for gate in manifest.quality.gates:
            marker = "PASS" if gate.passed else "FAIL"
            lines.append(f"- **{marker} {gate.gate}** — {gate.evidence}")
        lines.extend(
            [
                "",
                "## Independent review",
                "",
                manifest.quality.review.summary,
            ]
        )
        if manifest.quality.review.blocking_findings:
            lines.extend(
                ["", "Blocking findings:", ""]
                + [f"- {finding}" for finding in manifest.quality.review.blocking_findings]
            )
    if manifest.approval:
        lines.extend(
            [
                "",
                "## Approval",
                "",
                f"Approved by `{manifest.approval.actor}` until "
                f"{manifest.approval.expires_at.isoformat()}.",
                f"Bound manifest: `{manifest.approval.manifest_hash}`",
            ]
        )
    if manifest.pull_request_url:
        lines.extend(["", f"Pull request: {manifest.pull_request_url}"])
    lines.append("")
    return "\n".join(lines)


__all__ = ["render_run_report"]
