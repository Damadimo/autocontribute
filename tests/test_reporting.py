from __future__ import annotations

import json
import re
from datetime import UTC, datetime

import pytest
from test_evidence import ENVIRONMENT, MODELS, ready_quality, validation_evidence

from autocontribute.approval import (
    ApprovalManifest,
    ApprovalReview,
    hash_diff,
    manifest_fingerprint,
)
from autocontribute.domain import (
    EligibilityResult,
    IssueCandidate,
    PatchProposal,
    RunManifest,
    RunStatus,
)
from autocontribute.evidence import render_validation_evidence
from autocontribute.exceptions import ReviewTooLargeError
from autocontribute.reporting import (
    AI_POLICY_EVIDENCE_KEY,
    GITHUB_TEXT_LIMIT,
    MAX_PATCH_PARTS,
    render_approval_review,
    render_github_review,
)
from autocontribute.submissions import ReviewBlocker

NOW = datetime(2026, 10, 22, 12, tzinfo=UTC)
RUN_ID = "0123456789abcdef"
SMALL_PATCH = (
    "diff --git a/src/widget.py b/src/widget.py\n"
    "--- a/src/widget.py\n"
    "+++ b/src/widget.py\n"
    "@@ -1 +1 @@\n"
    "-old = 1\n"
    "+new = 2\n"
)


def _review(
    *,
    patch: str = SMALL_PATCH,
    pull_request_body: str = "Fixes the widget.\n\n---\n\nAI assistance: disclosed.",
    output_tail: str = "RUN_OUTPUT_MARKER",
    critic_summary: str = "CRITIC_SUMMARY_MARKER",
    ai_policy: str | None = None,
) -> ApprovalReview:
    candidate = IssueCandidate(
        repository="example/project",
        number=42,
        title="ISSUE_TITLE_MARKER",
        body="Issue body",
        html_url="https://github.com/example/project/issues/42",
        state="open",
        author="reporter",
        labels=["bug"],
        assignees=[],
        comments=0,
        created_at=NOW,
        updated_at=NOW,
    )
    evidence = validation_evidence()
    assert evidence.check is not None and evidence.check.red_green is not None
    evidence.check.red_green.runs[0].output_tail = output_tail
    evidence.critic_rounds[0].review.summary = critic_summary
    run = RunManifest(
        run_id=RUN_ID,
        status=RunStatus.READY_FOR_APPROVAL,
        created_at=NOW,
        updated_at=NOW,
        candidate=candidate,
        eligibility=EligibilityResult(
            eligible=True,
            score=90,
            evidence={} if ai_policy is None else {AI_POLICY_EVIDENCE_KEY: ai_policy},
            blockers=[],
        ),
        models=MODELS,
        environment=ENVIRONMENT,
        proposal=PatchProposal(
            summary="AGENT_SUMMARY_MARKER",
            commit_message="COMMIT_MESSAGE_MARKER",
            pull_request_title="PR_TITLE_MARKER",
            pull_request_body=pull_request_body,
            test_files=["tests/test_widget.py"],
            test_command="python -m pytest tests/test_widget.py",
            disclosure="AI assistance: disclosed.",
        ),
        quality=ready_quality(),
    )
    manifest = ApprovalManifest(
        schema_version=5,
        repository="example/project",
        head_repository="octocat/project",
        issue_number=42,
        base_sha="a" * 40,
        preparation_fingerprint="b" * 64,
        publishing_login="octocat",
        publishing_api_origin="https://api.github.com",
        commit_author_name="Octo Cat",
        commit_author_email="583231+octocat@users.noreply.github.com",
        commit_committer_name="Octo Cat",
        commit_committer_email="583231+octocat@users.noreply.github.com",
        base_branch="main",
        draft=False,
        ready_for_review=False,
        diff_sha256=hash_diff(patch),
        commit_message="COMMIT_MESSAGE_MARKER",
        pull_request_title="PR_TITLE_MARKER",
        pull_request_body=pull_request_body,
        disclosure="AI assistance: disclosed.",
    )
    return ApprovalReview(
        run=run,
        patch=patch.encode(),
        validation_artifact=render_validation_evidence(evidence).encode(),
        manifest=manifest,
        fingerprint=manifest_fingerprint(manifest),
    )


def _prose(markdown: str) -> str:
    """The Markdown outside fenced blocks and code spans, where GitHub links and mentions."""

    kept: list[str] = []
    fence: str | None = None
    for line in markdown.split("\n"):
        opener = re.match(r"^(`{3,})", line)
        if fence is None and opener:
            fence = opener.group(1)
        elif fence is not None and line.startswith(fence) and line.strip("`") == "":
            fence = None
        elif fence is None:
            kept.append(re.sub(r"(`+)(?:(?!\1).)+?\1", "", line))
    assert fence is None, "a fenced block was left open"
    return "\n".join(kept)


def _diff_blocks(markdown: str) -> list[str]:
    return re.findall(r"^```diff\n(.*?)\n```$", markdown, flags=re.S | re.M)


def test_github_review_shows_every_bound_field_in_one_body() -> None:
    review = _review()

    rendered = render_github_review(review, approval_expires_hours=72)

    body = rendered.body
    assert rendered.parts == ()
    assert rendered.shortened == ()
    assert body.split("\n", 1)[0] == f"<!-- autocontribute:run={RUN_ID} -->"
    assert f"```text\n/approve {review.fingerprint[:12]}\n```" in body
    assert f"`{review.fingerprint}`" in body
    assert "An approval lasts 72 hours." in body
    assert "| Head repository | `octocat/project (fork)` |" in body
    assert "| Upstream issue | `example/project#42` |" in body
    assert f"| Base | `main` at `{'a' * 40}` |" in body
    assert "| Opens as | ready for review |" in body
    for marker in (
        "ISSUE_TITLE_MARKER",
        "PR_TITLE_MARKER",
        "Fixes the widget.",
        "COMMIT_MESSAGE_MARKER",
        "`Octo Cat <583231+octocat@users.noreply.github.com>`",
        "RUN_OUTPUT_MARKER",
        "CRITIC_SUMMARY_MARKER",
        "AGENT_SUMMARY_MARKER",
        "The agent's summary is its own claim, not evidence.",
        "Round 1: approve",
        "Fails before, passes after: passed:",
        "Patched tests against the baseline: passed: the full suite shows no new failure",
        "Before the change: 4 tests: 2 passed in every run",
    ):
        assert marker in body
    assert _diff_blocks(body) == [SMALL_PATCH.removesuffix("\n")]
    assert "### Repository AI policy" not in body
    assert len(body) <= GITHUB_TEXT_LIMIT


def test_github_review_fences_untrusted_text_and_keeps_mentions_out_of_prose() -> None:
    hostile = (
        "Thanks @maintainer, see #99 and other/repo#7 <img src=x onerror=alert(1)>\n"
        "````\n# Not a heading\n```\n"
        "hidden‮flip and escape \x1b[2J here\n"
        "\n---\n\nAI assistance: disclosed."
    )
    review = _review(
        pull_request_body=hostile,
        critic_summary="Ask @maintainer about ``` fences",
        patch=SMALL_PATCH + "+# ping @someone in #12\n",
    )

    body = render_github_review(review, approval_expires_hours=72).body

    prose = _prose(body)
    for reference in ("@maintainer", "@someone", "#99", "#7", "#12", "<img"):
        assert reference not in prose
    assert "‮" not in body and "\x1b" not in body
    assert "hidden\\u202eflip and escape \\x1b[2J here" in body
    assert "`````markdown\n" in body


def test_github_review_continues_a_long_patch_in_parts_without_cutting_it() -> None:
    lines = [f"+line {number:05d} " + "x" * 40 + "\n" for number in range(3_000)]
    patch = SMALL_PATCH + "".join(lines)
    review = _review(patch=patch)

    rendered = render_github_review(review, approval_expires_hours=72)

    assert 2 <= len(rendered.parts) <= MAX_PATCH_PARTS
    assert len(rendered.body) <= GITHUB_TEXT_LIMIT
    assert all(len(part) <= GITHUB_TEXT_LIMIT for part in rendered.parts)
    count = len(rendered.parts)
    for index, part in enumerate(rendered.parts, start=1):
        assert part.startswith(f"<!-- autocontribute:run={RUN_ID} part={index}/{count} -->\n")
        assert f"### Patch, part {index}/{count}" in part
    assert f"The rest continues in parts 1-{count} below" in rendered.body
    blocks = _diff_blocks(rendered.body) + [
        block for part in rendered.parts for block in _diff_blocks(part)
    ]
    assert "\n".join(blocks) + "\n" == patch


def test_github_review_splits_a_line_longer_than_a_part() -> None:
    patch = SMALL_PATCH + "+" + "y" * 130_000 + "\n"
    review = _review(patch=patch)

    rendered = render_github_review(review, approval_expires_hours=72)

    assert len(rendered.parts) == 3
    assert all(len(part) <= GITHUB_TEXT_LIMIT for part in rendered.parts)
    blocks = _diff_blocks(rendered.body) + [
        block for part in rendered.parts for block in _diff_blocks(part)
    ]
    assert "".join(blocks).replace("\n", "") == patch.replace("\n", "")
    assert "Lines 7-7 of 7." in rendered.parts[1]


def test_github_review_shortens_evidence_with_a_note_and_never_the_bound_text() -> None:
    output = "".join(f"test {number} passed\n" for number in range(10_000))
    long_body = "B" * 49_000 + "\n\n---\n\nAI assistance: disclosed."
    review = _review(output_tail=output, pull_request_body=long_body, critic_summary="C" * 20_000)

    rendered = render_github_review(review, approval_expires_hours=72)

    assert rendered.shortened == ("test output", "review")
    assert long_body in rendered.body
    assert "Output is shortened to fit; validation.json (SHA-256 `" in rendered.body
    assert "Shortened to fit: the first" in rendered.body
    assert len(rendered.body) <= GITHUB_TEXT_LIMIT
    blocks = _diff_blocks(rendered.body) + [
        block for part in rendered.parts for block in _diff_blocks(part)
    ]
    assert "\n".join(blocks) + "\n" == SMALL_PATCH


@pytest.mark.parametrize(
    ("patch", "body"),
    [
        (SMALL_PATCH + "+" + "z" * 400_000 + "\n", "Short.\n\n---\n\nAI assistance: disclosed."),
        (SMALL_PATCH, "B" * 61_000 + "\n\n---\n\nAI assistance: disclosed."),
    ],
)
def test_github_review_refuses_what_cannot_fit_in_a_body_and_five_parts(
    patch: str,
    body: str,
) -> None:
    with pytest.raises(ReviewTooLargeError, match="more than an issue body and 5 comments"):
        render_github_review(
            _review(patch=patch, pull_request_body=body),
            approval_expires_hours=72,
        )


def test_github_review_shows_recorded_ai_policy_quotes() -> None:
    policy = json.dumps(
        {
            "stance": "conditional",
            "requires_disclosure": True,
            "quotes": [
                {
                    "repository": "example/project",
                    "path": "CONTRIBUTING.md",
                    "text": "Disclose AI use, @bot-handle.",
                }
            ],
        }
    )

    shown = render_github_review(_review(ai_policy=policy), approval_expires_hours=72).body
    unreadable = render_github_review(_review(ai_policy="{"), approval_expires_hours=72).body

    assert "### Repository AI policy\n\nStance: `conditional`." in shown
    assert (
        "From `example/project/CONTRIBUTING.md`:\n\n```text\nDisclose AI use, @bot-handle.\n```"
        in (shown)
    )
    assert "@bot-handle" not in _prose(shown)
    assert "The recorded AI-policy evidence could not be read." in unreadable


def test_terminal_review_shows_claims_tests_review_and_policy_as_evidence() -> None:
    policy = json.dumps(
        {
            "stance": "conditional",
            "quotes": [{"repository": "example/project", "path": "AI.md", "text": "Disclose."}],
        }
    )
    review = _review(ai_policy=policy, output_tail="1 passed\x1b[2J")
    blocker = ReviewBlocker(
        category="weak_test",
        path="tests/test_widget.py",
        line=3,
        evidence="The test passes without the fix.",
        check_command=None,
        fix_hint="Assert the new value.",
    )
    evidence = validation_evidence()
    first = evidence.critic_rounds[0].model_copy(
        update={"decision": "request_changes", "confirmed": [blocker]}
    )
    second = evidence.critic_rounds[0].model_copy(update={"number": 2})
    evidence.critic_rounds = [first, second]
    review = ApprovalReview(
        run=review.run,
        patch=review.patch,
        validation_artifact=render_validation_evidence(evidence).encode(),
        manifest=review.manifest,
        fingerprint=review.fingerprint,
    )

    text = render_approval_review(review)

    assert "## The agent's summary\n\nThese are the agent's claims, not evidence." in text
    assert "| AGENT_SUMMARY_MARKER" in text
    assert "Test command: python -m pytest (pytest)" in text
    assert "### Test run 1: red" in text
    assert "### Round 1: request_changes" in text and "### Round 2: approve" in text
    assert "| weak_test at tests/test_widget.py:3: The test passes without the fix." in text
    assert "## Repository AI policy\n\nStance: conditional" in text
    assert "| Disclose." in text
    assert "\x1b" not in text
