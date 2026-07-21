from datetime import UTC, datetime, timedelta

from autocontribute.config import AutocontributeConfig
from autocontribute.discovery import DiscoveryService, parse_issue_reference
from autocontribute.domain import IssueCandidate, IssueComment, RepositoryInfo
from autocontribute.store import RunStore


class FakeGitHub:
    def search_competing_pull_requests(self, repository: str, issue_number: int) -> list[str]:
        return []

    def get_file(self, repository: str, path: str, *, ref: str | None = None) -> str | None:
        return "Contribution guidelines" if path == "CONTRIBUTING.md" else None


def _repository() -> RepositoryInfo:
    return RepositoryInfo(
        full_name="example/project",
        html_url="https://github.com/example/project",
        clone_url="https://github.com/example/project.git",
        default_branch="main",
        stars=10_000,
        archived=False,
        disabled=False,
        private=False,
        pushed_at=datetime.now(UTC),
        license_spdx="MIT",
    )


def _issue(**updates: object) -> IssueCandidate:
    values: dict[str, object] = {
        "repository": "example/project",
        "number": 42,
        "title": "Fix incorrect parser output",
        "body": (
            "Steps to reproduce: parse the attached minimal input. Actual behavior returns the "
            "wrong node; expected behavior is the documented node. Please add a regression test. "
            * 3
        ),
        "html_url": "https://github.com/example/project/issues/42",
        "state": "open",
        "author": "maintainer",
        "labels": ["help wanted", "bug", "good first issue"],
        "assignees": [],
        "comments": 2,
        "created_at": datetime.now(UTC) - timedelta(days=10),
        "updated_at": datetime.now(UTC) - timedelta(days=1),
    }
    values.update(updates)
    return IssueCandidate.model_validate(values)


def test_clear_maintainer_signaled_issue_passes(tmp_path) -> None:
    config = AutocontributeConfig()
    service = DiscoveryService(config, FakeGitHub(), RunStore(tmp_path))  # type: ignore[arg-type]

    result = service.evaluate(_issue(), _repository())

    assert result.eligible
    assert result.score >= config.quality.min_candidate_score


def test_assigned_issue_fails_closed(tmp_path) -> None:
    config = AutocontributeConfig()
    service = DiscoveryService(config, FakeGitHub(), RunStore(tmp_path))  # type: ignore[arg-type]

    result = service.evaluate(_issue(assignees=["someone"]), _repository())

    assert not result.eligible
    assert "already assigned" in " ".join(result.blockers)


def test_possible_security_issue_is_never_publicly_selected(tmp_path) -> None:
    config = AutocontributeConfig()
    service = DiscoveryService(config, FakeGitHub(), RunStore(tmp_path))  # type: ignore[arg-type]

    result = service.evaluate(_issue(title="CVE-2026-1234 remote code execution"), _repository())

    assert not result.eligible
    assert "private handling" in " ".join(result.blockers)


def test_inactive_repository_fails_before_model_selection(tmp_path) -> None:
    config = AutocontributeConfig.model_validate({"github": {"max_repository_inactivity_days": 30}})
    service = DiscoveryService(config, FakeGitHub(), RunStore(tmp_path))  # type: ignore[arg-type]
    repository = _repository().model_copy(
        update={"pushed_at": datetime.now(UTC) - timedelta(days=31)}
    )

    result = service.evaluate(_issue(), repository)

    assert not result.eligible
    assert "inactive" in " ".join(result.blockers)


def test_issue_reference_parser_is_unambiguous() -> None:
    assert parse_issue_reference("owner/repo#123") == ("owner/repo", 123)


def _comment(*, body: str, author: str = "contributor", association: str = "NONE") -> IssueComment:
    now = datetime.now(UTC)
    return IssueComment(
        author=author,
        author_association=association,
        body=body,
        html_url=f"https://github.com/example/project/issues/42#{author}",
        created_at=now,
        updated_at=now,
    )


def test_claimed_work_in_discussion_fails_closed(tmp_path) -> None:
    config = AutocontributeConfig()
    service = DiscoveryService(config, FakeGitHub(), RunStore(tmp_path))  # type: ignore[arg-type]
    issue = _issue(
        comments=1,
        discussion=[_comment(body="I'm working on this and will open a PR shortly.")],
    )

    result = service.evaluate(issue, _repository())

    assert not result.eligible
    assert "claimed work" in " ".join(result.blockers)


def test_maintainer_stop_request_in_discussion_fails_closed(tmp_path) -> None:
    config = AutocontributeConfig()
    service = DiscoveryService(config, FakeGitHub(), RunStore(tmp_path))  # type: ignore[arg-type]
    issue = _issue(
        comments=1,
        discussion=[
            _comment(
                body="Please hold off; no PR is needed until the design is settled.",
                author="maintainer",
                association="MEMBER",
            )
        ],
    )

    result = service.evaluate(issue, _repository())

    assert not result.eligible
    assert "hold off" in " ".join(result.blockers)
