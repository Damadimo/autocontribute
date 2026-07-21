from __future__ import annotations

import httpx
import pytest

from autocontribute.config import GitHubConfig
from autocontribute.exceptions import GitHubError
from autocontribute.github import GitHubClient


def _client(handler) -> GitHubClient:  # type: ignore[no-untyped-def]
    github = GitHubClient(GitHubConfig(), token="fixture-token")
    github._client.close()
    github._client = httpx.Client(
        base_url="https://api.github.com",
        transport=httpx.MockTransport(handler),
        headers={"Authorization": "Bearer fixture-token"},
        follow_redirects=False,
    )
    return github


def _repository_payload(full_name: str) -> dict[str, object]:
    return {
        "full_name": full_name,
        "html_url": f"https://github.com/{full_name}",
        "clone_url": f"https://github.com/{full_name}.git",
        "default_branch": "main",
        "stargazers_count": 1234,
        "archived": False,
        "disabled": False,
        "private": False,
        "pushed_at": "2026-07-21T12:00:00Z",
        "license": {"spdx_id": "MIT"},
    }


def test_same_origin_repository_rename_redirect_is_followed_once() -> None:
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path == "/repos/old/project":
            return httpx.Response(
                301,
                headers={"Location": "https://api.github.com/repositories/123"},
            )
        return httpx.Response(200, json=_repository_payload("new/project"))

    with _client(handler) as github:
        repository = github.get_repository("old/project")

    assert repository.full_name == "new/project"
    assert paths == ["/repos/old/project", "/repositories/123"]


def test_cross_origin_redirect_never_receives_authorization() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(301, headers={"Location": "https://attacker.invalid/steal"})

    with _client(handler) as github, pytest.raises(GitHubError, match="unsafe redirect"):
        github.get_repository("old/project")
    assert calls == 1


def test_rate_limit_is_a_circuit_breaker() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            429,
            headers={"Retry-After": "60", "X-RateLimit-Remaining": "0"},
            json={"message": "slow down"},
        )

    with _client(handler) as github, pytest.raises(GitHubError, match="run was stopped"):
        github.authenticated_login()


def test_existing_unrelated_repository_cannot_be_reused_as_fork() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"fork": False, "full_name": "octocat/project"})

    with _client(handler) as github, pytest.raises(GitHubError, match="not a fork"):
        github.ensure_fork("upstream/project", "octocat")


def test_competing_pull_request_search_paginates_issue_timeline() -> None:
    pages: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params["page"])
        pages.append(page)
        if page == 1:
            return httpx.Response(200, json=[{"event": "commented"}] * 100)
        return httpx.Response(
            200,
            json=[
                {
                    "event": "cross-referenced",
                    "source": {
                        "issue": {
                            "state": "open",
                            "html_url": "https://github.com/example/project/pull/99",
                            "pull_request": {"url": "https://api.github.com/pulls/99"},
                        }
                    },
                }
            ],
        )

    with _client(handler) as github:
        matches = github.search_competing_pull_requests("example/project", 42)

    assert matches == ["https://github.com/example/project/pull/99"]
    assert pages == [1, 2]


def test_oversized_issue_timeline_fails_closed() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=[{"event": "commented"}] * 100)

    with _client(handler) as github, pytest.raises(GitHubError, match="ambiguous"):
        github.search_competing_pull_requests("example/project", 42)

    assert calls == 10
