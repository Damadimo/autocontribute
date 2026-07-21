from datetime import UTC, datetime, timedelta

from autocontribute.config import AutocontributeConfig
from autocontribute.discovery import DiscoveryService, parse_issue_reference
from autocontribute.domain import IssueCandidate, RepositoryInfo
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


def test_issue_reference_parser_is_unambiguous() -> None:
    assert parse_issue_reference("owner/repo#123") == ("owner/repo", 123)
