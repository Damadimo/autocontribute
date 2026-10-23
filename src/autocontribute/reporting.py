"""Human-reviewable summaries generated from machine-readable run evidence."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass
from typing import Final

from autocontribute.ai_policy import RepositoryAiPolicy
from autocontribute.approval import ApprovalManifest, ApprovalReview
from autocontribute.domain import RunManifest
from autocontribute.evidence import ValidationEvidence, read_validation_evidence
from autocontribute.exceptions import PolicyError, ReviewTooLargeError
from autocontribute.fix_checks import SuiteRunEvidence
from autocontribute.submissions import ReviewBlocker
from autocontribute.task_messages import baseline_summary

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
# Budgets for the testing, review and AI-policy sections, tried in order until the review
# fits; a zero budget leaves only a note that names where the full evidence is.
_EVIDENCE_BUDGETS: Final = ((8_000, 6_000, 6_000), (3_000, 2_000, 2_000), (0, 0, 0))
_OUTPUT_TAILS: Final = (2_000, 1_000, 400, 0)


def render_run_report(manifest: RunManifest) -> str:
    lines = [
        f"# Autocontribute run `{manifest.run_id}`",
        "",
        f"- Status: `{manifest.status.value}`",
        f"- Created: {manifest.created_at.isoformat()}",
        f"- Updated: {manifest.updated_at.isoformat()}",
        f"- Model usage: {manifest.model_calls} call(s), {manifest.model_input_tokens} input, "
        f"{manifest.model_output_tokens} output tokens",
        f"- Model time: {manifest.model_seconds:.2f}s",
        f"- Recorded model cost: ${manifest.model_cost_usd}",
    ]
    if manifest.model_reservation:
        reservation = manifest.model_reservation
        lines.append(
            "- Unresolved model reservation: "
            f"call {reservation.call} ({reservation.role}), {reservation.input_tokens} input, "
            f"{reservation.output_tokens} output tokens, ${reservation.cost_usd}, "
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
    if manifest.models:
        models = manifest.models
        lines.append(
            f"- Models: agent `{models.agent}`, critic `{models.critic}`, setup "
            f"`{models.setup}`, triage `{models.triage}`"
        )
    if manifest.environment:
        environment = manifest.environment
        lines.append(
            f"- Environment: {environment.recipe_source} recipe on `{environment.base_image}` "
            f"(`{environment.base_digest}`), image `{environment.image_id}`"
        )

    if manifest.skip_reason:
        lines.extend(["", "## Skip reason", "", manifest.skip_reason])
    if manifest.reject_reason:
        lines.extend(["", "## Rejection reason", "", manifest.reject_reason])
    if manifest.error:
        lines.extend(["", "## Error", "", manifest.error])
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
        lines.extend(
            [
                "",
                "## The agent's summary",
                "",
                "These are the agent's claims, not evidence.",
                "",
                manifest.proposal.summary,
            ]
        )
    if manifest.quality:
        quality = manifest.quality
        lines.extend(["", "## Gates", ""])
        for gate in quality.gates:
            marker = "PASS" if gate.passed else "FAIL"
            lines.append(f"- **{marker} {gate.gate}** — {gate.evidence}")
        lines.extend(
            ["", f"## Review after {quality.review_rounds} round(s)", "", quality.review_summary]
        )
        if quality.review_notes:
            lines.extend(["", *(f"- {note}" for note in quality.review_notes)])
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

    evidence = read_validation_evidence(review.validation_artifact)
    lines.extend(
        [
            "",
            "## Testing",
            "",
            *_escape_review_value("\n".join(_testing_facts(run, evidence))).split("\n"),
        ]
    )
    for index, test_run in enumerate(_test_runs(evidence), start=1):
        lines.extend(
            [
                "",
                f"### Test run {index}: {test_run.kind}",
                "",
                f"- Command: {_escape_review_value(test_run.command)}",
                f"- Result: {_run_result(test_run)}",
            ]
        )
        if test_run.failure:
            lines.append(f"- Not usable: {_escape_review_value(test_run.failure)}")
        _append_exact_text(lines, f"Test run {index} output tail", test_run.output_tail, level=4)

    lines.extend(["", "## The agent's summary", "", "These are the agent's claims, not evidence."])
    _append_exact_text(lines, "Agent summary", proposal.summary)
    _append_exact_text(lines, "Agent's test files", "\n".join(proposal.test_files))
    _append_exact_text(lines, "Agent's test command", proposal.test_command or "")

    lines.extend(["", "## Review"])
    for review_round in evidence.critic_rounds:
        lines.extend(["", f"### Round {review_round.number}: {review_round.decision}"])
        _append_exact_text(
            lines, f"Round {review_round.number} summary", review_round.review.summary, level=4
        )
        _append_exact_text(
            lines,
            f"Round {review_round.number} notes",
            "\n".join(review_round.review.notes),
            level=4,
        )
        _append_exact_text(
            lines,
            f"Round {review_round.number} blockers sent back",
            "\n".join(_blocker_line(blocker) for blocker in review_round.confirmed),
            level=4,
        )
        _append_exact_text(
            lines,
            f"Round {review_round.number} blockers dropped",
            "\n".join(
                f"{_blocker_line(dropped.blocker)} ({dropped.reason})"
                for dropped in review_round.dropped
            ),
            level=4,
        )

    policy = _ai_policy(run)
    if policy is not None:
        stance, quotes = policy
        lines.extend(["", "## Repository AI policy", "", f"Stance: {_escape_review_value(stance)}"])
        for index, (source, quote) in enumerate(quotes, start=1):
            _append_exact_text(lines, f"Quote {index} from {_escape_review_value(source)}", quote)

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
    evidence = read_validation_evidence(review.validation_artifact)
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
            _github_testing(run, evidence, validation_sha256, budget=validation),
            _github_review(run, evidence, budget=critic),
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
        f"The approval binds fingerprint {code_span(review.fingerprint)}: the patch, the pull "
        "request text, the commit, and where it is published. Anything that changes them "
        f"changes the fingerprint. An approval lasts {approval_expires_hours} hours.",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Run | {code_span(run.run_id, table=True)} |",
        f"| Upstream issue | {code_span(issue, table=True)} |",
        f"| Issue link | {code_span(run.candidate.html_url, table=True)} |",
        f"| Base | {code_span(approval.base_branch, table=True)} at "
        f"{code_span(approval.base_sha, table=True)} |",
        f"| Head repository | {code_span(_head_repository_line(approval), table=True)} |",
        f"| Opens as | {opens_as} |",
        f"| Publishing account | {code_span(approval.publishing_login, table=True)} |",
        f"| Patch | {len(review.patch):,} bytes, {patch_lines:,} lines, SHA-256 "
        f"{code_span(approval.diff_sha256, table=True)} |",
        f"| validation.json SHA-256 | {code_span(validation_sha256, table=True)} |",
        "",
        "Upstream issue title:",
        "",
        fenced_block(run.candidate.title, "text"),
        "",
    ]


def _github_publication_text(approval: ApprovalManifest) -> list[str]:
    author = f"{approval.commit_author_name} <{approval.commit_author_email}>"
    committer = f"{approval.commit_committer_name} <{approval.commit_committer_email}>"
    identity = (
        f"Author and committer: {code_span(author)}"
        if author == committer
        else f"Author: {code_span(author)}; committer: {code_span(committer)}"
    )
    return [
        "### Pull request title",
        "",
        fenced_block(approval.pull_request_title, "text"),
        "",
        "### Pull request body",
        "",
        "The Markdown source of the body, exactly as it will be posted:",
        "",
        fenced_block(approval.pull_request_body, "markdown"),
        "",
        "### Commit",
        "",
        identity,
        "",
        fenced_block(approval.commit_message, "text"),
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


def _github_testing(
    run: RunManifest,
    evidence: ValidationEvidence,
    artifact_sha256: str,
    *,
    budget: int,
) -> tuple[str, str | None]:
    reference = (
        f"validation.json (SHA-256 {code_span(artifact_sha256)}) in the run evidence has every "
        "test run and the baseline's test lists."
    )
    facts = fenced_block("\n".join(_testing_facts(run, evidence)), "text")
    runs = _test_runs(evidence)
    for tail in _OUTPUT_TAILS if budget else ():
        lines = ["### Testing", "", "What autocontribute ran and saw:", "", facts, ""]
        cut = False
        for index, test_run in enumerate(runs, start=1):
            lines.extend(
                [
                    f"Test run {index}, {test_run.kind}: {code_span(test_run.command)}: "
                    f"{_run_result(test_run)}"
                    + (
                        f"; not usable: {code_span(test_run.failure)}." if test_run.failure else "."
                    ),
                    "",
                ]
            )
            output = test_run.output_tail
            if not output:
                continue
            if tail == 0:
                cut = True
                continue
            shown = output[-tail:]
            cut = cut or len(shown) < len(output)
            label = (
                f"Last {len(shown):,} of {len(output):,} characters of its output:"
                if len(shown) < len(output)
                else "Its output:"
            )
            lines.extend([label, "", fenced_block(shown, "text"), ""])
        if cut:
            lines.extend([f"Output is shortened to fit; {reference}", ""])
        text = "\n".join(lines) + "\n"
        if len(text) <= budget:
            return text, "test output" if cut else None
    note = f"### Testing\n\nTest evidence is left out to fit; {reference}\n\n"
    return note, "test output"


def _github_review(
    run: RunManifest, evidence: ValidationEvidence, *, budget: int
) -> tuple[str, str | None]:
    proposal = run.proposal
    if proposal is None:
        return "", None
    claims = [
        "The agent's summary:",
        proposal.summary,
        "",
        "Tests it added or changed: " + (", ".join(proposal.test_files) or "none"),
        f"Its test command: {proposal.test_command or 'none'}",
    ]
    review = []
    for review_round in evidence.critic_rounds:
        review += [
            "",
            f"Round {review_round.number}: {review_round.decision}",
            review_round.review.summary,
            *(f"- note: {note}" for note in review_round.review.notes),
            *(f"- sent back: {_blocker_line(blocker)}" for blocker in review_round.confirmed),
            *(
                f"- dropped: {_blocker_line(dropped.blocker)} ({dropped.reason})"
                for dropped in review_round.dropped
            ),
        ]
    heading = (
        "### The agent's account and the review\n\nThe agent's summary is its own claim, not "
        "evidence. A fresh reviewer checked the change in each round.\n\n"
    )
    full = "\n".join([*claims, *review])
    text = heading + fenced_block(full, "text") + "\n\n"
    if len(text) <= budget:
        return text, None
    room = budget - len(heading) - 300
    if room <= 0:
        note = (
            "The agent's account and the review are left out to fit; validation.json has them.\n\n"
        )
        return heading + note, "review"
    shortened = (
        heading
        + fenced_block(full[:room], "text")
        + f"\n\nShortened to fit: the first {room:,} of {len(full):,} characters; "
        "validation.json and manifest.json have the rest.\n\n"
    )
    return shortened, "review"


def _github_ai_policy(run: RunManifest, *, budget: int) -> tuple[str, str | None]:
    raw = run.eligibility.evidence.get(AI_POLICY_EVIDENCE_KEY) if run.eligibility else None
    if raw is None:
        return "", None
    heading = "### Repository AI policy\n\n"
    policy = _ai_policy(run)
    if policy is None:
        return heading + "The recorded AI-policy evidence could not be read.\n\n", None
    stance, quotes = policy
    text = heading + f"Stance: {code_span(stance)}.\n\n"
    shown = 0
    for source, quote in quotes:
        entry = f"From {code_span(source)}:\n\n{fenced_block(quote, 'text')}\n\n"
        if len(text) + len(entry) > budget - 200:
            break
        text += entry
        shown += 1
    if shown == len(quotes):
        return text, None
    omitted = len(quotes) - shown
    text += f"{omitted} more quote(s) are left out to fit; manifest.json has every quote.\n\n"
    return text, "AI policy"


def _testing_facts(run: RunManifest, evidence: ValidationEvidence) -> list[str]:
    """The environment, the baseline, and how the fix's checks came out, one fact a line."""

    recipe = evidence.recipe
    facts = [f"Test command: {recipe.test_command} ({recipe.test_framework})"]
    environment = run.environment
    if environment is not None:
        facts.append(
            f"Environment: {environment.recipe_source} recipe on {environment.base_image} "
            f"({environment.base_digest}), image {environment.image_id}"
        )
    facts.append(f"Before the change: {baseline_summary(evidence.baseline)}")
    check = evidence.check
    if check is None:
        facts.append("No fix was checked.")
        return facts
    failed = [gate.gate for gate in check.gates if not gate.passed]
    facts.append("Gates: " + (f"failed: {', '.join(failed)}" if failed else "all passed"))
    if check.red_green is not None:
        red_green = check.red_green
        facts.append(f"Fails before, passes after: {red_green.status}: {red_green.detail}")
    if check.regression is not None:
        regression = check.regression
        facts.append(
            f"Patched tests against the baseline: {regression.status}: {regression.detail}"
        )
    facts.extend(f"Note: {note}" for note in check.notes)
    return facts


def _test_runs(evidence: ValidationEvidence) -> list[SuiteRunEvidence]:
    check = evidence.check
    if check is None:
        return []
    red_green = check.red_green.runs if check.red_green is not None else []
    regression = check.regression.runs if check.regression is not None else []
    return [*red_green, *regression]


def _run_result(run: SuiteRunEvidence) -> str:
    result = (
        f"{run.passed} passed, {run.failed} failed, {run.skipped} skipped, exit {run.exit_code}, "
        f"{run.duration_seconds:.1f} s"
    )
    return result + ", timed out" if run.timed_out else result


def _blocker_line(blocker: ReviewBlocker) -> str:
    where = (
        f" at {blocker.path}" + (f":{blocker.line}" if blocker.line else "") if blocker.path else ""
    )
    return f"{blocker.category}{where}: {blocker.evidence}"


def _ai_policy(run: RunManifest) -> tuple[str, list[tuple[str, str]]] | None:
    """The recorded AI policy's stance and quotes, or None when none was recorded or readable."""

    raw = run.eligibility.evidence.get(AI_POLICY_EVIDENCE_KEY) if run.eligibility else None
    if raw is None:
        return None
    try:
        policy = RepositoryAiPolicy.model_validate_json(raw)
    except ValueError:
        return None
    return policy.stance, [
        (f"{quote.repository}/{quote.path}", quote.text) for quote in policy.quotes
    ]


def _github_visible(value: str) -> str:
    """Show invisible and control characters as escapes; keep backslashes, tabs, newlines."""

    return "".join(
        character if character in "\n\t" else _visible_character(character) for character in value
    )


def _fence(value: str, *, minimum: int) -> str:
    longest = max((len(run) for run in _BACKTICKS.findall(value)), default=0)
    return "`" * max(minimum, longest + 1)


def fenced_block(value: str, info: str) -> str:
    """A fenced block that no backtick run in ``value`` can close; GitHub renders nothing in it."""

    shown = _github_visible(value)
    fence = _fence(shown, minimum=3)
    return f"{fence}{info}\n{shown.removesuffix(chr(10))}\n{fence}"


def _fenced_lines(lines: list[_PatchLine], info: str, fence: str) -> str:
    content = "".join(line.text for line in lines)
    return f"{fence}{info}\n{content.removesuffix(chr(10))}\n{fence}"


def code_span(value: str, *, table: bool = False) -> str:
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
    "code_span",
    "fenced_block",
    "render_approval_review",
    "render_github_review",
    "render_run_report",
]
