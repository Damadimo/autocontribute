from __future__ import annotations

from typing import Any

import pytest
from test_task_messages import _check

from autocontribute.ai_policy import AiPolicyQuote, RepositoryAiPolicy
from autocontribute.exceptions import PullRequestTextError
from autocontribute.fix_checks import RedGreenEvidence, RegressionEvidence, SuiteRunEvidence
from autocontribute.pr_template import visible_markdown
from autocontribute.pr_text import (
    PullRequestText,
    assemble_pull_request,
    fill_disclosure,
    render_testing_note,
)
from autocontribute.submissions import AgentSubmission

_TEMPLATE = (
    "AI assistance: an AI coding agent (autocontribute {version}, {model}) drafted this change "
    "and its test and ran the tests listed above in a sandbox. I reviewed the diff and the test "
    "results before opening this PR and will handle the review."
)
_DISCLOSURE = fill_disclosure(_TEMPLATE, version="0.4.0", model="gpt-5.6-sol")
_ASSISTANT = "autocontribute 0.4.0, gpt-5.6-sol"


def _submission(**changes: Any) -> AgentSubmission:
    fields: dict[str, Any] = {
        "outcome": "fixed",
        "skip_reason": None,
        "summary": "add subtracted; it adds now.",
        "pr_title": "Fix add returning the difference",
        "pr_body": "add returned a - b; it now returns a + b.\n\nFixes #7",
        "commit_message": "Fix add returning the difference",
        "test_files": ["tests/test_calc.py"],
        "test_command": None,
    }
    return AgentSubmission.model_validate({**fields, **changes})


def _assemble(
    submission: AgentSubmission | None = None,
    *,
    disclosure: str = _DISCLOSURE,
    commit_message: str = "Fix add returning the difference",
    ai_policy: RepositoryAiPolicy | None = None,
    **check: Any,
) -> PullRequestText:
    return assemble_pull_request(
        submission or _submission(),
        issue_number=7,
        check=_check(**check),
        disclosure=disclosure,
        commit_message=commit_message,
        ai_policy=ai_policy,
        assistant=_ASSISTANT,
    )


def _run(kind: str, passed: int, failed: int = 0) -> SuiteRunEvidence:
    return SuiteRunEvidence(
        kind=kind,
        command="python -m pytest",
        exit_code=int(failed > 0),
        timed_out=False,
        duration_seconds=10.0,
        failure=None,
        passed=passed,
        failed=failed,
        skipped=0,
        output_tail="",
    )


def test_the_disclosure_is_filled_and_blank_ones_are_refused() -> None:
    assert _DISCLOSURE.startswith(
        "AI assistance: an AI coding agent (autocontribute 0.4.0, gpt-5.6-sol) drafted"
    )
    assert fill_disclosure("Made with {tool} {model}", version="1", model="m") == (
        "Made with {tool} m"
    )
    with pytest.raises(PullRequestTextError, match="cannot be blank"):
        fill_disclosure("  ", version="1", model="m")


def test_the_body_gets_the_testing_note_and_a_visible_disclosure() -> None:
    regression = RegressionEvidence(
        status="passed",
        detail="the full suite shows no new failure",
        full_suite=True,
        new_failures=[],
        runs=[_run("related", 3), _run("full_suite", 1234, 2)],
    )
    red_green = _check().red_green
    assert red_green is not None
    runs = [_run("red", 1, 1), *(_run("green", 2) for _ in range(3))]

    text = _assemble(regression=regression, red_green=red_green.model_copy(update={"runs": runs}))

    assert text.title == "Fix add returning the difference"
    assert text.body == (
        "add returned a - b; it now returns a + b.\n\nFixes #7\n\n"
        "Testing (run by autocontribute):\n"
        "- Tests: t::adds fails before this change and passes after it (3 runs).\n"
        "- Full suite: no new failures (1,234 passed, 2 failed as before this change).\n\n"
        f"---\n\n{_DISCLOSURE}"
    )
    assert text.disclosure == _DISCLOSURE
    assert text.commit_message == "Fix add returning the difference"


@pytest.mark.parametrize(
    ("body", "linked"),
    [
        ("Closes #7.", True),
        ("This resolved acme/calc#7", True),
        ("Fixes #70", False),
        ("See #7", False),
        ("<!-- Fixes #7 -->", False),
    ],
)
def test_the_issue_is_linked_when_the_body_does_not(body: str, linked: bool) -> None:
    text = _assemble(_submission(pr_body=body))

    assert text.body.startswith("Fixes #7\n\n") is not linked


def test_an_unclosed_comment_or_code_block_is_closed_first() -> None:
    comment = _assemble(_submission(pr_body="Fixes #7\n\n<!-- left open"))
    fence = _assemble(_submission(pr_body="Fixes #7\n\n````python\nadd(1, 2)\n```"))

    assert _DISCLOSURE in visible_markdown(comment.body)
    assert "<!-- left open\n-->\n\nTesting" in comment.body
    assert _DISCLOSURE in visible_markdown(fence.body)
    assert "add(1, 2)\n```\n````\n\nTesting" in fence.body


def test_a_disclosure_that_stays_hidden_rejects_the_run() -> None:
    with pytest.raises(PullRequestTextError, match="disclosure would be hidden"):
        _assemble(disclosure="<!-- AI assistance -->")


def test_template_checkboxes_are_left_as_the_agent_wrote_them() -> None:
    body = "Fixes #7\n\n## Checklist\n\n- [ ] I have added tests\n- [x] Docs\n- [ ] Bug fix"

    text = _assemble(_submission(pr_body=body))

    assert text.body.startswith(body + "\n\nTesting")


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"pr_title": "x" * 201}, "title must be one line"),
        ({"pr_body": "Fixes #7\n\n" + "y" * 50_000}, "exceeds 50,000 characters"),
        ({"pr_body": "Fixes #7. cc @here"}, "mentions @everyone or @here"),
        ({"pr_body": "Fixes #7 with ghp_" + "K1" * 18}, "appears to contain a credential"),
    ],
)
def test_text_that_cannot_be_published_rejects_the_run(
    changes: dict[str, str], message: str
) -> None:
    with pytest.raises(PullRequestTextError, match=message):
        _assemble(_submission(**changes))


def _policy(requirement: str) -> RepositoryAiPolicy:
    return RepositoryAiPolicy(
        stance="conditional",
        requires_disclosure=True,
        disclosure_requirements=[requirement],
        quotes=[AiPolicyQuote(repository="acme/calc", path="AI.md", text=requirement)],
    )


def test_a_trailer_the_policy_names_goes_into_the_commit_message() -> None:
    plain = _assemble(ai_policy=_policy("Add an `Assisted-by:` trailer to each commit."))
    signed = _assemble(
        commit_message="Fix add\n\nSigned-off-by: Ada Lovelace <ada@example.org>",
        ai_policy=_policy("Commits made with AI need a generated-by: line."),
    )
    without = _assemble(ai_policy=_policy("Disclose AI use in the pull request."))

    assert plain.commit_message == (
        "Fix add returning the difference\n\nAssisted-by: autocontribute 0.4.0, gpt-5.6-sol"
    )
    assert signed.commit_message == (
        "Fix add\n\ngenerated-by: autocontribute 0.4.0, gpt-5.6-sol\n"
        "Signed-off-by: Ada Lovelace <ada@example.org>"
    )
    assert without.commit_message == "Fix add returning the difference"


def test_an_ai_co_author_never_goes_in() -> None:
    with pytest.raises(PullRequestTextError, match="co-author"):
        _assemble(commit_message="Co-authored-by: Claude <noreply@anthropic.com>")


def test_the_testing_note_says_what_ran_and_what_did_not() -> None:
    no_test = _check(
        red_green=RedGreenEvidence(
            status="not_applicable",
            detail="the patch changes no test",
            targets=[],
            reproduced=[],
            uncollected=[],
            runs=[],
        ),
        regression=RegressionEvidence(
            status="passed",
            detail="related tests show no new failure; ...",
            full_suite=False,
            new_failures=[],
            runs=[_run("related", 12)],
        ),
    )
    not_run = _check(
        regression=RegressionEvidence(
            status="not_run", detail="not run", full_suite=False, new_failures=[], runs=[]
        )
    )

    assert render_testing_note(no_test).splitlines() == [
        "Testing (run by autocontribute):",
        "- Tests: no test was added or changed.",
        "- Tests related to the change: no new failures (12 passed); the full suite was not run "
        "in the time available.",
    ]
    assert render_testing_note(not_run).splitlines()[-1] == "- Full suite: not run."
