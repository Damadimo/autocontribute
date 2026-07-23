from datetime import UTC, datetime, timedelta

import pytest

from autocontribute.domain import IssueCandidate, IssueComment
from autocontribute.issue_revision import compute_issue_revision


def _issue() -> IssueCandidate:
    created_at = datetime(2026, 7, 1, 12, tzinfo=UTC)
    comment_at = created_at + timedelta(days=1)
    return IssueCandidate(
        repository="Example/Project",
        number=42,
        title="Fix the parser boundary",
        body="Actual output differs from the documented expected output.",
        html_url="https://github.com/Example/Project/issues/42",
        state="OPEN",
        author="Maintainer",
        labels=["Bug", "Help Wanted"],
        assignees=["Alice", "Bob"],
        comments=1,
        discussion=[
            IssueComment(
                author="Contributor",
                author_association="NONE",
                body="I can reproduce this on the current release.",
                html_url="https://github.com/Example/Project/issues/42#issuecomment-1",
                created_at=comment_at,
                updated_at=comment_at,
            )
        ],
        created_at=created_at,
        updated_at=comment_at,
        score=91,
        score_evidence={"signal": "strong"},
    )


def test_issue_revision_ignores_ranking_and_set_order() -> None:
    issue = _issue()
    equivalent = issue.model_copy(
        update={
            "repository": "example/project",
            "state": "open",
            "author": "maintainer",
            "labels": ["help wanted", "BUG"],
            "assignees": ["bob", "ALICE"],
            "score": 12,
            "score_evidence": {"different": "derived evidence"},
        }
    )

    assert compute_issue_revision(equivalent) == compute_issue_revision(issue)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("title", "Fix both parser boundaries"),
        ("body", "New reproduction evidence."),
        ("state", "closed"),
        ("labels", ["bug", "help wanted", "needs tests"]),
        ("assignees", ["alice"]),
        ("comments", 2),
        ("updated_at", datetime(2026, 7, 3, 12, tzinfo=UTC)),
    ],
)
def test_issue_revision_changes_with_issue_evidence(field: str, value: object) -> None:
    issue = _issue()

    assert compute_issue_revision(
        issue.model_copy(update={field: value})
    ) != compute_issue_revision(issue)


def test_issue_revision_changes_when_a_comment_is_edited_added_or_removed() -> None:
    issue = _issue()
    comment = issue.discussion[0]
    edited = issue.model_copy(
        update={
            "discussion": [
                comment.model_copy(
                    update={
                        "body": "The maintainer confirmed the expected result.",
                        "updated_at": comment.updated_at + timedelta(hours=1),
                    }
                )
            ]
        }
    )
    added = issue.model_copy(
        update={
            "comments": 2,
            "discussion": [
                *issue.discussion,
                comment.model_copy(
                    update={
                        "body": "A second independent reproduction.",
                        "html_url": ("https://github.com/Example/Project/issues/42#issuecomment-2"),
                    }
                ),
            ],
        }
    )
    removed = issue.model_copy(update={"comments": 0, "discussion": []})
    revision = compute_issue_revision(issue)

    assert compute_issue_revision(edited) != revision
    assert compute_issue_revision(added) != revision
    assert compute_issue_revision(removed) != revision


def test_issue_revision_rejects_naive_timestamps() -> None:
    issue = _issue().model_copy(update={"updated_at": datetime(2026, 7, 2, 12)})

    with pytest.raises(ValueError, match="timezone-aware"):
        compute_issue_revision(issue)
