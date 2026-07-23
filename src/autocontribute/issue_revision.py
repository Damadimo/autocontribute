"""Stable revisions for the complete issue evidence supplied to contribution planning."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Final

from autocontribute.domain import IssueCandidate

_ISSUE_REVISION_DOMAIN: Final = b"autocontribute.issue-revision.v1\x00"


def compute_issue_revision(issue: IssueCandidate) -> str:
    """Hash semantic issue evidence while excluding derived ranking fields."""

    if not isinstance(issue, IssueCandidate):
        raise TypeError("issue revision requires an IssueCandidate")

    payload = {
        "assignees": sorted({assignee.casefold() for assignee in issue.assignees}),
        "author": issue.author.casefold(),
        "body": issue.body,
        "comments": issue.comments,
        "created_at": _canonical_timestamp(issue.created_at),
        "discussion": [
            {
                "author": comment.author.casefold(),
                "author_association": comment.author_association.casefold(),
                "body": comment.body,
                "created_at": _canonical_timestamp(comment.created_at),
                "html_url": comment.html_url,
                "updated_at": _canonical_timestamp(comment.updated_at),
            }
            for comment in issue.discussion
        ],
        "html_url": issue.html_url,
        "labels": sorted({label.casefold() for label in issue.labels}),
        "number": issue.number,
        "repository": issue.repository.casefold(),
        "state": issue.state.casefold(),
        "title": issue.title,
        "updated_at": _canonical_timestamp(issue.updated_at),
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(_ISSUE_REVISION_DOMAIN + encoded).hexdigest()


def _canonical_timestamp(value: datetime) -> str:
    if value.utcoffset() is None:
        raise ValueError("issue revision timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


__all__ = ["compute_issue_revision"]
