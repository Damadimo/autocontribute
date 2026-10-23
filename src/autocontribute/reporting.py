"""Human-reviewable summaries generated from machine-readable run evidence."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Final

from autocontribute.approval import ApprovalManifest, ApprovalReview
from autocontribute.domain import CommandResult, RunManifest
from autocontribute.exceptions import PolicyError, ReviewTooLargeError

# GitHub refuses issue bodies and comments over 65,536 characters; the rest is margin.
GITHUB_TEXT_LIMIT: Final = 60_000
MAX_PATCH_PARTS: Final = 5
# Discovery records the repository's AI policy as JSON under this eligibility evidence key.
AI_POLICY_EVIDENCE_KEY: Final = "ai_policy"
_HIDDEN_CATEGORIES: Final = frozenset({"Cf", "Cs", "Co", "Cn", "Zl", "Zp"})
_NAMED_ESCAPES: Final = {
    "\0": r"\0",
    "\b": r"\b",
    "\t": r"\t",
    "\r": r"\r",
    "\v": r"\v",
    "\f": r"\f",
}
_BACKTICKS: Final = re.compile(r"`+")
# Budgets for the validation, critic and AI-policy sections, tried in order until the review
# fits; a zero budget leaves only a note that names where the full evidence is.
_EVIDENCE_BUDGETS: Final = ((8_000, 6_000, 6_000), (3_000, 2_000, 2_000), (0, 0, 0))
_OUTPUT_TAILS: Final = (2_000, 1_000, 400, 0)


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
            ]
        )
        _append_exact_text(lines, "Commit message", manifest.proposal.commit_message)
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
        f"- Head repository: {_head_repository_line(approval)}",
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


@dataclass(frozen=True, slots=True)
class GitHubReview:
    """An approval issue body and the patch parts that continue it as issue comments."""

    body: str
    parts: tuple[str, ...]
    shortened: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _PatchLine:
    number: int
    text: str


def render_github_review(review: ApprovalReview, *, approval_expires_hours: int) -> GitHubReview:
    """Render the review as a GitHub issue body of at most 60,000 characters.

    Everything the fingerprint binds is shown in full: the pull request text and commit go in
    the body, and a patch too long for the body continues in at most five comment parts.
    Validation, critic and AI-policy evidence is shortened first, always with a note. Every
    untrusted text is fenced or in a code span, where GitHub neither renders HTML nor turns
    ``@handles`` and issue references into notifications and links.
    """

    run = review.run
    if run.candidate is None:
        raise PolicyError("Approval review is missing its issue candidate")
    try:
        patch = review.patch.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PolicyError(
            "Contribution patch is not valid UTF-8 and cannot be reviewed safely"
        ) from exc
    lines = [
        _PatchLine(number, _github_visible(text))
        for number, text in enumerate(re.findall(r"[^\n]*\n|[^\n]+$", patch), start=1)
    ]
    validation_sha256 = hashlib.sha256(review.validation_artifact).hexdigest()
    before = "\n".join(
        [
            *_github_header(
                review,
                approval_expires_hours,
                patch_lines=len(lines),
                validation_sha256=validation_sha256,
            ),
            *_github_publication_text(review.manifest),
            "",
        ]
    )
    for validation, critic, policy in _EVIDENCE_BUDGETS:
        sections = (
            _github_validation(run, validation_sha256, budget=validation),
            _github_critic(run, budget=critic),
            _github_ai_policy(run, budget=policy),
        )
        after = "".join(text for text, _ in sections)
        fitted = _fit_patch(run.run_id, before, after, lines)
        if fitted is not None:
            body, parts = fitted
            shortened = tuple(name for (_, name) in sections if name is not None)
            return GitHubReview(body=body, parts=parts, shortened=shortened)
    raise ReviewTooLargeError(
        f"The review needs more than an issue body and {MAX_PATCH_PARTS} comments of "
        f"{GITHUB_TEXT_LIMIT:,} characters; review run {run.run_id} with `runs show` instead"
    )


def _github_header(
    review: ApprovalReview,
    approval_expires_hours: int,
    *,
    patch_lines: int,
    validation_sha256: str,
) -> list[str]:
    run = review.run
    approval = review.manifest
    assert run.candidate is not None
    if not approval.draft:
        opens_as = "ready for review"
    elif approval.ready_for_review:
        opens_as = "draft, then marked ready for review"
    else:
        opens_as = "draft"
    issue = f"{approval.repository}#{approval.issue_number}"
    return [
        f"<!-- autocontribute:run={run.run_id} -->",
        "## Approve this pull request",
        "",
        "To publish the pull request below, comment exactly:",
        "",
        "```text",
        f"/approve {review.fingerprint[:12]}",
        "```",
        "",
        f"The approval binds fingerprint {_code(review.fingerprint)}: the patch, the pull "
        "request text, the commit, and where it is published. Anything that changes them "
        f"changes the fingerprint. An approval lasts {approval_expires_hours} hours.",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Run | {_code(run.run_id, table=True)} |",
        f"| Upstream issue | {_code(issue, table=True)} |",
        f"| Issue link | {_code(run.candidate.html_url, table=True)} |",
        f"| Base | {_code(approval.base_branch, table=True)} at "
        f"{_code(approval.base_sha, table=True)} |",
        f"| Head repository | {_code(_head_repository_line(approval), table=True)} |",
        f"| Opens as | {opens_as} |",
        f"| Publishing account | {_code(approval.publishing_login, table=True)} |",
        f"| Patch | {len(review.patch):,} bytes, {patch_lines:,} lines, SHA-256 "
        f"{_code(approval.diff_sha256, table=True)} |",
        f"| validation.json SHA-256 | {_code(validation_sha256, table=True)} |",
        "",
        "Upstream issue title:",
        "",
        _fenced(run.candidate.title, "text"),
        "",
    ]


def _github_publication_text(approval: ApprovalManifest) -> list[str]:
    author = f"{approval.commit_author_name} <{approval.commit_author_email}>"
    committer = f"{approval.commit_committer_name} <{approval.commit_committer_email}>"
    identity = (
        f"Author and committer: {_code(author)}"
        if author == committer
        else f"Author: {_code(author)}; committer: {_code(committer)}"
    )
    return [
        "### Pull request title",
        "",
        _fenced(approval.pull_request_title, "text"),
        "",
        "### Pull request body",
        "",
        "The Markdown source of the body, exactly as it will be posted:",
        "",
        _fenced(approval.pull_request_body, "markdown"),
        "",
        "### Commit",
        "",
        identity,
        "",
        _fenced(approval.commit_message, "text"),
        "",
    ]


def _fit_patch(
    run_id: str,
    before: str,
    after: str,
    lines: list[_PatchLine],
) -> tuple[str, tuple[str, ...]] | None:
    """Keep as much of the patch in the body as fits, continuing it in at most five parts."""

    fence = _fence("".join(line.text for line in lines), minimum=3)
    whole = before + _patch_section(lines, lines, part_count=0, fence=fence) + after
    if len(whole) <= GITHUB_TEXT_LIMIT:
        return whole, ()
    part_capacity = GITHUB_TEXT_LIMIT - 2 * len(fence) - 500
    units = [
        _PatchLine(line.number, line.text[start : start + part_capacity])
        for line in lines
        for start in range(0, max(len(line.text), 1), part_capacity)
    ]
    # Start with an estimate of the room the body leaves, then shrink it by any overshoot.
    capacity = max(0, GITHUB_TEXT_LIMIT - len(before) - len(after) - 2 * len(fence) - 500)
    while capacity >= 0:
        kept = _take(units, capacity)
        chunks: list[list[_PatchLine]] = []
        rest = units[len(kept) :]
        while rest:
            chunk = _take(rest, part_capacity)
            chunks.append(chunk)
            rest = rest[len(chunk) :]
        if len(chunks) > MAX_PATCH_PARTS:
            return None
        body = before + _patch_section(kept, lines, part_count=len(chunks), fence=fence) + after
        if len(body) <= GITHUB_TEXT_LIMIT:
            parts = tuple(
                _patch_part(run_id, chunk, lines, index, len(chunks), fence)
                for index, chunk in enumerate(chunks, start=1)
            )
            return body, parts
        capacity -= len(body) - GITHUB_TEXT_LIMIT
    return None


def _take(units: list[_PatchLine], capacity: int) -> list[_PatchLine]:
    taken: list[_PatchLine] = []
    used = 0
    for unit in units:
        if used + len(unit.text) > capacity:
            break
        taken.append(unit)
        used += len(unit.text)
    return taken


def _patch_section(
    shown: list[_PatchLine],
    lines: list[_PatchLine],
    *,
    part_count: int,
    fence: str,
) -> str:
    total = len(lines)
    if part_count == 0:
        intro = f"All {total:,} lines of the patch:"
    elif shown:
        intro = (
            f"Lines 1-{shown[-1].number:,} of {total:,}. The rest continues in parts 1-"
            f"{part_count} below, posted as comments; no line is left out."
        )
    else:
        intro = (
            f"The {total:,} lines of the patch are in parts 1-{part_count} below, posted as "
            "comments; no line is left out."
        )
    block = [_fenced_lines(shown, "diff", fence)] if shown else []
    return "\n".join(["### Patch", "", intro, "", *block, "", ""])


def _patch_part(
    run_id: str,
    chunk: list[_PatchLine],
    lines: list[_PatchLine],
    index: int,
    count: int,
    fence: str,
) -> str:
    return "\n".join(
        [
            f"<!-- autocontribute:run={run_id} part={index}/{count} -->",
            f"### Patch, part {index}/{count}",
            "",
            f"Lines {chunk[0].number:,}-{chunk[-1].number:,} of {len(lines):,}.",
            "",
            _fenced_lines(chunk, "diff", fence),
            "",
        ]
    )


def _github_validation(
    run: RunManifest,
    artifact_sha256: str,
    *,
    budget: int,
) -> tuple[str, str | None]:
    results: list[tuple[str, CommandResult]] = []
    if run.baseline_validation is not None:
        results.append(("Baseline on the unpatched code", run.baseline_validation))
    results.extend(
        (f"Patched command {index}", result)
        for index, result in enumerate(run.patched_validation, start=1)
    )
    reference = (
        f"validation.json (SHA-256 {_code(artifact_sha256)}) in the run evidence has every "
        "command's full output."
    )
    for tail in _OUTPUT_TAILS if budget else ():
        lines = ["### Validation", ""]
        cut = False
        for heading, result in results:
            lines.extend(
                [
                    f"#### {heading}",
                    "",
                    f"Command {_code(result.command)}: exit code {result.exit_code}, "
                    f"{result.duration_seconds:.2f} seconds, timed out: "
                    f"{'yes' if result.timed_out else 'no'}.",
                    "",
                ]
            )
            for stream, output in (("stdout", result.stdout), ("stderr", result.stderr)):
                if not output:
                    lines.extend([f"{stream} is empty.", ""])
                elif tail == 0:
                    cut = True
                    lines.extend([f"{stream}: {len(output):,} characters, not shown.", ""])
                else:
                    shown = output[-tail:]
                    cut = cut or len(shown) < len(output)
                    label = (
                        f"Last {len(shown):,} of {len(output):,} characters of {stream}:"
                        if len(shown) < len(output)
                        else f"{stream}:"
                    )
                    lines.extend([label, "", _fenced(shown, "text"), ""])
        if not results:
            lines.extend(["No validation command was recorded.", ""])
        if cut:
            lines.extend([f"Output is shortened to fit; {reference}", ""])
        text = "\n".join(lines) + "\n"
        if len(text) <= budget:
            return text, "validation output" if cut else None
    note = f"### Validation\n\nValidation evidence is left out to fit; {reference}\n\n"
    return note, "validation output"


def _github_critic(run: RunManifest, *, budget: int) -> tuple[str, str | None]:
    quality = run.quality
    if quality is None:
        return "", None
    critic = quality.review
    evidence = [
        "Critic summary:",
        critic.summary,
        "",
        "Blocking findings:",
        *([f"- {finding}" for finding in critic.blocking_findings] or ["(none)"]),
        "",
        "Gates:",
        *[
            f"{'PASS' if gate.passed else 'FAIL'} {gate.gate}: {gate.evidence}"
            for gate in quality.gates
        ],
    ]
    heading = (
        f"### Checks and critic\n\nReadiness {quality.readiness_score}/100; critic verdict: "
        f"{critic.verdict}.\n\n"
    )
    full = "\n".join(evidence)
    text = heading + _fenced(full, "text") + "\n\n"
    if len(text) <= budget:
        return text, None
    room = budget - len(heading) - 300
    if room <= 0:
        note = "Critic and gate evidence is left out to fit; manifest.json has it in full.\n\n"
        return heading + note, "critic"
    shortened = (
        heading
        + _fenced(full[:room], "text")
        + f"\n\nShortened to fit: the first {room:,} of {len(full):,} characters; "
        "manifest.json has the rest.\n\n"
    )
    return shortened, "critic"


def _github_ai_policy(run: RunManifest, *, budget: int) -> tuple[str, str | None]:
    raw = run.eligibility.evidence.get(AI_POLICY_EVIDENCE_KEY) if run.eligibility else None
    if raw is None:
        return "", None
    heading = "### Repository AI policy\n\n"
    try:
        policy = json.loads(raw)
        stance = policy["stance"]
        quotes = [
            (f"{quote['repository']}/{quote['path']}", quote["text"])
            for quote in policy.get("quotes", [])
        ]
        if not isinstance(stance, str) or not all(
            isinstance(source, str) and isinstance(text, str) for source, text in quotes
        ):
            raise TypeError("AI policy evidence has unexpected types")
    except (ValueError, KeyError, TypeError, AttributeError):
        return heading + "The recorded AI-policy evidence could not be read.\n\n", None
    text = heading + f"Stance: {_code(stance)}.\n\n"
    shown = 0
    for source, quote in quotes:
        entry = f"From {_code(source)}:\n\n{_fenced(quote, 'text')}\n\n"
        if len(text) + len(entry) > budget - 200:
            break
        text += entry
        shown += 1
    if shown == len(quotes):
        return text, None
    omitted = len(quotes) - shown
    text += f"{omitted} more quote(s) are left out to fit; manifest.json has every quote.\n\n"
    return text, "AI policy"


def _github_visible(value: str) -> str:
    """Show invisible and control characters as escapes; keep backslashes, tabs, newlines."""

    return "".join(
        character if character in "\n\t" else _visible_character(character) for character in value
    )


def _fence(value: str, *, minimum: int) -> str:
    longest = max((len(run) for run in _BACKTICKS.findall(value)), default=0)
    return "`" * max(minimum, longest + 1)


def _fenced(value: str, info: str) -> str:
    shown = _github_visible(value)
    fence = _fence(shown, minimum=3)
    return f"{fence}{info}\n{shown.removesuffix(chr(10))}\n{fence}"


def _fenced_lines(lines: list[_PatchLine], info: str, fence: str) -> str:
    content = "".join(line.text for line in lines)
    return f"{fence}{info}\n{content.removesuffix(chr(10))}\n{fence}"


def _code(value: str, *, table: bool = False) -> str:
    """An inline code span that no backtick, newline or table pipe in ``value`` can end."""

    shown = _github_visible(value).replace("\n", " ")
    if table:
        shown = shown.replace("|", "\\|")
    delimiter = _fence(shown, minimum=1)
    if shown.startswith("`") or shown.endswith("`"):
        shown = f" {shown} "
    return f"{delimiter}{shown}{delimiter}"


def _head_repository_line(approval: ApprovalManifest) -> str:
    head = approval.head_repository
    if head is None:
        raise PolicyError("Approval review is missing its head repository")
    mode = "same repository" if head.casefold() == approval.repository.casefold() else "fork"
    return f"{head} ({mode})"


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
    escaped: list[str] = []
    for character in value:
        if character == "\n":
            escaped.append(character)
        elif character == "\\":
            escaped.append(r"\\")
        else:
            escaped.append(_visible_character(character))
    return "".join(escaped)


def _visible_character(character: str) -> str:
    if character in _NAMED_ESCAPES:
        return _NAMED_ESCAPES[character]
    if character.isprintable() and unicodedata.category(character) not in _HIDDEN_CATEGORIES:
        return character
    codepoint = ord(character)
    if codepoint <= 0xFF:
        return f"\\x{codepoint:02x}"
    if codepoint <= 0xFFFF:
        return f"\\u{codepoint:04x}"
    return f"\\U{codepoint:08x}"


__all__ = [
    "AI_POLICY_EVIDENCE_KEY",
    "GITHUB_TEXT_LIMIT",
    "MAX_PATCH_PARTS",
    "GitHubReview",
    "render_approval_review",
    "render_github_review",
    "render_run_report",
]
