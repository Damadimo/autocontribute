"""Human-reviewable summaries generated from machine-readable run evidence."""

from __future__ import annotations

import hashlib
import unicodedata

from autocontribute.approval import ApprovalReview
from autocontribute.domain import CommandResult, RunManifest
from autocontribute.exceptions import PolicyError


def render_run_report(
    manifest: RunManifest,
    commands: list[CommandResult],
    *,
    model_cost_known: bool | None = None,
) -> str:
    if model_cost_known is None:
        model_cost_known = not (
            manifest.model_calls > 0
            and manifest.model_cost_usd == 0
            and (manifest.model_reservation is None or manifest.model_reservation.cost_usd == 0)
        )
    cost_summary = (
        f"${manifest.model_cost_usd}"
        if model_cost_known
        else "unknown (token pricing was not configured)"
    )
    lines = [
        f"# Autocontribute run `{manifest.run_id}`",
        "",
        f"- Status: `{manifest.status.value}`",
        f"- Created: {manifest.created_at.isoformat()}",
        f"- Updated: {manifest.updated_at.isoformat()}",
        f"- Model usage: {manifest.model_input_tokens} input, "
        f"{manifest.model_output_tokens} output tokens",
        f"- Model time: {manifest.model_seconds:.2f}s",
        f"- Recorded model cost: {cost_summary}",
    ]
    if manifest.model_reservation:
        reservation = manifest.model_reservation
        lines.append(
            "- Unresolved model reservation: "
            f"call {reservation.call} ({reservation.role}), {reservation.input_tokens} input, "
            f"{reservation.output_tokens} output tokens, "
            f"{'$' + str(reservation.cost_usd) if model_cost_known else 'unknown cost'}, "
            f"{reservation.timeout_seconds:.2f}s"
        )
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


def render_approval_review(review: ApprovalReview) -> str:
    """Render every human-reviewed field from one freshly validated snapshot."""

    run = review.run
    candidate = run.candidate
    proposal = run.proposal
    if candidate is None or proposal is None:
        raise PolicyError("Approval review is missing its issue candidate or proposal")
    try:
        patch = review.patch.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PolicyError(
            "Contribution patch is not valid UTF-8 and cannot be reviewed safely"
        ) from exc

    approval = review.manifest
    lines = [
        f"# Exact approval review for `{run.run_id}`",
        "",
        "This output was rebuilt from the authoritative SQLite manifest and freshly validated ",
        "`contribution.patch` and `validation.json`; `report.md` is not an input.",
        "Evidence lines are prefixed with `|`; backslashes and terminal-control characters are ",
        "visibly escaped without changing the bytes bound by the fingerprint.",
        "",
        "## Resulting approval fingerprint",
        "",
        review.fingerprint,
        "",
        "## Publication target and identity",
        "",
        f"- Repository: {approval.repository}",
        f"- Issue: {approval.repository}#{approval.issue_number}",
        f"- Base branch: {approval.base_branch}",
        f"- Base commit: {approval.base_sha}",
        f"- Draft pull request: {str(approval.draft).lower()}",
        f"- Publishing account: {approval.publishing_login}",
        f"- Publishing API origin: {approval.publishing_api_origin}",
        f"- Preparation fingerprint: {approval.preparation_fingerprint}",
        f"- Patch SHA-256: {approval.diff_sha256}",
        "- Validated validation.json SHA-256: "
        f"{hashlib.sha256(review.validation_artifact).hexdigest()}",
        "",
        "## Exact issue snapshot",
    ]
    _append_exact_text(lines, "Issue title", candidate.title)
    _append_exact_text(lines, "Issue body", candidate.body)
    lines.extend(
        [
            "",
            "## Exact issue discussion",
            "",
            f"Recorded comments: {len(candidate.discussion)} of {candidate.comments}",
        ]
    )
    if not candidate.discussion:
        lines.extend(["", "(no discussion comments)"])
    for index, comment in enumerate(candidate.discussion, start=1):
        lines.extend(
            [
                "",
                f"### Discussion comment {index}",
                "",
                f"- Author: {comment.author}",
                f"- Author association: {comment.author_association}",
                f"- URL: {comment.html_url}",
                f"- Created: {comment.created_at.isoformat()}",
                f"- Updated: {comment.updated_at.isoformat()}",
            ]
        )
        _append_exact_text(lines, f"Discussion comment {index} body", comment.body, level=4)

    lines.extend(["", "## Full contribution patch"])
    _append_exact_text(lines, "contribution.patch", patch)

    lines.extend(["", "## Complete validation output"])
    if run.baseline_validation is None:
        lines.extend(["", "No baseline command was recorded."])
    else:
        _append_command_result(lines, "Baseline command", run.baseline_validation)
    for index, result in enumerate(run.patched_validation, start=1):
        _append_command_result(lines, f"Patched command {index}", result)

    lines.extend(["", "## Exact commit identity and message", ""])
    _append_exact_text(lines, "Commit author name", approval.commit_author_name)
    _append_exact_text(lines, "Commit author email", approval.commit_author_email)
    _append_exact_text(lines, "Commit committer name", approval.commit_committer_name)
    _append_exact_text(lines, "Commit committer email", approval.commit_committer_email)
    _append_exact_text(lines, "Commit message", approval.commit_message)

    lines.extend(["", "## Exact pull request text"])
    _append_exact_text(lines, "Pull request title", approval.pull_request_title)
    _append_exact_text(lines, "Pull request body", approval.pull_request_body)
    lines.extend(
        [
            "",
            "## Authorization boundary",
            "",
            "Approval authorizes only the publication surface bound by this fingerprint:",
            "",
            review.fingerprint,
            "",
        ]
    )
    return "\n".join(lines)


def _append_command_result(lines: list[str], heading: str, result: CommandResult) -> None:
    lines.extend(
        [
            "",
            f"### {heading}",
            "",
            f"- Command: {result.command}",
            f"- Exit code: {result.exit_code}",
            f"- Timed out: {str(result.timed_out).lower()}",
            f"- Duration seconds: {result.duration_seconds}",
        ]
    )
    _append_exact_text(lines, f"{heading} stdout", result.stdout, level=4)
    _append_exact_text(lines, f"{heading} stderr", result.stderr, level=4)


def _append_exact_text(
    lines: list[str],
    heading: str,
    value: str,
    *,
    level: int = 3,
) -> None:
    encoded = value.encode("utf-8")
    marker = "#" * level
    displayed = _escape_review_value(value)
    lines.extend(
        [
            "",
            f"{marker} {heading}",
            "",
            f"UTF-8 bytes: {len(encoded)}; "
            f"ends with newline: {str(value.endswith(chr(10))).lower()}",
            "----- BEGIN EXACT VALUE (TERMINAL-SAFE DISPLAY) -----",
            *[f"| {line}" for line in displayed.split("\n")],
            "----- END EXACT VALUE -----",
        ]
    )


def _escape_review_value(value: str) -> str:
    named = {
        "\0": r"\0",
        "\b": r"\b",
        "\t": r"\t",
        "\r": r"\r",
        "\v": r"\v",
        "\f": r"\f",
    }
    escaped: list[str] = []
    for character in value:
        if character == "\n":
            escaped.append(character)
        elif character == "\\":
            escaped.append(r"\\")
        elif character in named:
            escaped.append(named[character])
        elif character.isprintable() and unicodedata.category(character) not in {
            "Cf",
            "Cs",
            "Co",
            "Cn",
            "Zl",
            "Zp",
        }:
            escaped.append(character)
        else:
            codepoint = ord(character)
            if codepoint <= 0xFF:
                escaped.append(f"\\x{codepoint:02x}")
            elif codepoint <= 0xFFFF:
                escaped.append(f"\\u{codepoint:04x}")
            else:
                escaped.append(f"\\U{codepoint:08x}")
    return "".join(escaped)


__all__ = ["render_approval_review", "render_run_report"]
