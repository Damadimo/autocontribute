"""The pull request text a prepared run proposes (DESIGN §7.3, §7.4).

After the critic approves, the controller builds the final text from the agent's reviewed
title, body and commit message without a model: it links the issue when the body does not,
appends a testing note that states only what the controller ran, and appends the filled AI
disclosure, which the approval binds. Template checkboxes are left as the agent wrote them.
When the repository's AI policy names a commit trailer, the commit message gets it; an AI
``Co-authored-by`` never goes in, and ``Signed-off-by`` comes only from
``discovery.apply_legal_commit_message``, with the human's DCO attestation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from autocontribute.ai_policy import RepositoryAiPolicy
from autocontribute.exceptions import PullRequestTextError
from autocontribute.fix_checks import FixCheckResult
from autocontribute.pr_template import visible_markdown
from autocontribute.redaction import contains_high_confidence_token
from autocontribute.submissions import AgentSubmission

# GitHub's limits on what publication sends.
_TITLE_CHARACTERS: Final = 200
_BODY_CHARACTERS: Final = 50_000
_LISTED_TESTS: Final = 3
_TRAILER: Final = re.compile(r"\b(Assisted-by|Generated-by)\s*:", re.IGNORECASE)
_AI_COAUTHOR: Final = re.compile(r"^\s*co-authored-by\s*:", re.IGNORECASE | re.MULTILINE)
_FENCE: Final = re.compile(r"^[ \t]{0,3}(?P<fence>`{3,}|~{3,})(?P<tail>.*)$")


@dataclass(frozen=True, slots=True)
class PullRequestText:
    """The text a run proposes; the approval binds all four fields."""

    title: str
    body: str
    commit_message: str
    # The filled disclosure, which ``body`` shows outside comments and code blocks.
    disclosure: str


def fill_disclosure(template: str, *, version: str, model: str) -> str:
    """Fill ``{version}`` and ``{model}`` in the disclosure; other braces stay as written."""

    disclosure = template.replace("{version}", version).replace("{model}", model).strip()
    if not disclosure:
        raise PullRequestTextError("policy.ai_disclosure cannot be blank")
    return disclosure


def render_testing_note(check: FixCheckResult) -> str:
    """Three lines on what the controller ran and saw, for the pull request body."""

    return "\n".join(
        ["Testing (run by autocontribute):", f"- {_tests_line(check)}", f"- {_suite_line(check)}"]
    )


def assemble_pull_request(
    submission: AgentSubmission,
    *,
    issue_number: int,
    check: FixCheckResult,
    disclosure: str,
    commit_message: str,
    ai_policy: RepositoryAiPolicy | None,
    assistant: str,
) -> PullRequestText:
    """Build the final title, body and commit message of a fix the critic approved.

    ``disclosure`` is filled (:func:`fill_disclosure`). ``commit_message`` is the agent's
    subject after ``discovery.apply_legal_commit_message``. ``assistant`` names the tool and
    model in a trailer the policy asks for, as ``autocontribute 0.4.0, gpt-5.6-sol``. Raises
    :class:`PullRequestTextError` when the text cannot be published, for one when the
    disclosure would not be visible.
    """

    title = (submission.pr_title or "").strip()
    if not title or "\n" in title or len(title) > _TITLE_CHARACTERS:
        raise PullRequestTextError(
            f"The pull request title must be one line of 1 to {_TITLE_CHARACTERS} characters"
        )
    body = _closed((submission.pr_body or "").strip())
    if not _links_issue(body, issue_number):
        body = f"Fixes #{issue_number}\n\n{body}"
    body = f"{body.rstrip()}\n\n{render_testing_note(check)}\n\n---\n\n{disclosure}"
    if disclosure not in visible_markdown(body):
        raise PullRequestTextError(
            "The AI disclosure would be hidden in the pull request body, inside a comment or a "
            "code block that cannot be closed"
        )
    if len(body) > _BODY_CHARACTERS:
        raise PullRequestTextError(f"The pull request body exceeds {_BODY_CHARACTERS:,} characters")
    message = _with_trailer(commit_message, ai_policy, assistant)
    for name, text in (("title", title), ("body", body), ("commit message", message)):
        if contains_high_confidence_token(text):
            raise PullRequestTextError(f"The pull request {name} appears to contain a credential")
        if "@everyone" in text.casefold() or "@here" in text.casefold():
            raise PullRequestTextError(f"The pull request {name} mentions @everyone or @here")
    return PullRequestText(title, body, message, disclosure)


def _tests_line(check: FixCheckResult) -> str:
    red_green = check.red_green
    if red_green is None or red_green.status == "not_applicable":
        return "Tests: no test was added or changed."
    runs = sum(1 for run in red_green.runs if run.kind == "green")
    if not check.per_test:
        # The suite is the one test, so the command is what failed and passed.
        command = f"`{red_green.runs[0].command}`" if red_green.runs else "The test command"
        if not red_green.reproduced:
            return f"Tests: {command} passes with the changed tests ({runs} runs)."
        return f"Tests: {command} fails before this change and passes after it ({runs} runs)."
    if not red_green.reproduced:
        return f"Tests: the tests changed in {', '.join(check.test_paths)} pass ({runs} runs)."
    one = len(red_green.reproduced) == 1
    fail, passes = ("fails", "passes") if one else ("fail", "pass")
    return (
        f"Tests: {_listed(red_green.reproduced)} {fail} before this change and {passes} after "
        f"it ({runs} runs)."
    )


def _suite_line(check: FixCheckResult) -> str:
    regression = check.regression
    if regression is None or regression.status == "not_run":
        return "Full suite: not run."
    full = next((run for run in regression.runs if run.kind == "full_suite"), None)
    related = next((run for run in regression.runs if run.kind == "related"), None)
    if full is not None and not check.per_test:
        return f"Full suite: `{full.command}` passes, as it did before this change."
    if full is not None:
        before = f", {full.failed:,} failed as before this change" if full.failed else ""
        return f"Full suite: no new failures ({full.passed:,} passed{before})."
    if related is not None and not check.per_test:
        return (
            f"Tests related to the change: `{related.command}` passes; the full suite was not "
            "run in the time available."
        )
    passed = f" ({related.passed:,} passed)" if related is not None else ""
    return (
        f"Tests related to the change: no new failures{passed}; the full suite was not run in "
        "the time available."
    )


def _listed(tests: list[str]) -> str:
    shown = ", ".join(tests[:_LISTED_TESTS])
    more = len(tests) - _LISTED_TESTS
    return shown if more <= 0 else f"{shown} and {more} more"


def _links_issue(body: str, number: int) -> bool:
    keyword = r"\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?):?\s+(?:[\w.-]+/[\w.-]+)?#"
    return re.search(rf"(?i){keyword}{number}\b", visible_markdown(body)) is not None


def _closed(body: str) -> str:
    """Close a comment or code block the body leaves open, so text after it shows."""

    opened = body.rfind("<!--")
    if opened != -1 and "-->" not in body[opened + 4 :]:
        body += "\n-->"
    fence: str | None = None
    for line in re.sub(r"<!--.*?-->", "", body, flags=re.DOTALL).splitlines():
        marker = _FENCE.match(line)
        if marker is None:
            continue
        found = marker.group("fence")
        if fence is None:
            fence = found
        elif found[0] == fence[0] and len(found) >= len(fence) and not marker.group("tail").strip():
            fence = None
    return body if fence is None else f"{body}\n{fence}"


def _with_trailer(commit_message: str, policy: RepositoryAiPolicy | None, assistant: str) -> str:
    if _AI_COAUTHOR.search(commit_message):
        raise PullRequestTextError("The commit message names a co-author, which is not allowed")
    if policy is None:
        return commit_message
    texts = [*policy.disclosure_requirements, *(quote.text for quote in policy.quotes)]
    named = next((match for text in texts if (match := _TRAILER.search(text))), None)
    if named is None:
        return commit_message
    trailer = f"{named.group(1)}: {assistant}"
    subject, separator, trailers = commit_message.partition("\n\n")
    return f"{subject}\n\n{trailer}" + (f"\n{trailers}" if separator else "")


__all__ = [
    "PullRequestText",
    "assemble_pull_request",
    "fill_disclosure",
    "render_testing_note",
]
