from __future__ import annotations

import base64
import subprocess

import httpx
import pytest

from autocontribute.config import GitHubConfig
from autocontribute.exceptions import GitHubError, GitHubSafetyError
from autocontribute.github import GitHubClient, resolve_github_token
from autocontribute.store import RunStore


def _client(
    handler,  # type: ignore[no-untyped-def]
    *,
    api_url: str = "https://api.github.com",
    safety_trigger_handler=None,  # type: ignore[no-untyped-def]
) -> GitHubClient:
    github = GitHubClient(
        GitHubConfig(api_url=api_url),
        token="fixture-token",
        safety_trigger_handler=safety_trigger_handler,
    )
    github._client.close()
    github._client = httpx.Client(
        base_url=api_url,
        transport=httpx.MockTransport(handler),
        headers={"Authorization": "Bearer fixture-token"},
        follow_redirects=False,
    )
    return github


def _repository_payload(full_name: str) -> dict[str, object]:
    return {
        "id": 1001,
        "node_id": "R_fixture_1001",
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


def _pull_request_payload(*, merged: bool = False, draft: bool = False) -> dict[str, object]:
    return {
        "number": 7,
        "node_id": "PR_fixture_node_7",
        "title": "Fix parser boundary",
        "body": "Fixes #42.",
        "html_url": "https://github.com/example/project/pull/7",
        "state": "closed" if merged else "open",
        "draft": draft,
        "merged": merged,
        "updated_at": "2026-07-21T13:00:00Z",
        "merged_at": "2026-07-21T12:30:00Z" if merged else None,
        "closed_at": "2026-07-21T12:30:00Z" if merged else None,
        "merge_commit_sha": "b" * 40 if merged else None,
        "head": {
            "sha": "a" * 40,
            "ref": "fix",
            "label": "octocat:fix",
            "repo": {
                "id": 2001,
                "node_id": "R_fixture_2001",
                "full_name": "octocat/project",
            },
        },
        "base": {
            "sha": "c" * 40,
            "ref": "main",
            "repo": {
                "id": 1001,
                "node_id": "R_fixture_1001",
                "full_name": "example/project",
            },
        },
        "comments": 1,
        "review_comments": 1,
        "commits": 1,
    }


def _linear_pull_request_commits(count: int) -> list[dict[str, object]]:
    commits: list[dict[str, object]] = []
    parent_sha = "f" * 40
    for index in range(1, count + 1):
        sha = f"{index:040x}"
        commits.append(
            {
                "sha": sha,
                "node_id": f"C_fixture_{index}",
                "parents": [{"sha": parent_sha}],
            }
        )
        parent_sha = sha
    return commits


@pytest.mark.parametrize(
    ("api_url", "expected_hostname"),
    [
        ("https://api.github.com", "github.com"),
        ("https://git.example.com/api/v3", "git.example.com"),
        ("https://git.example.com:8443/api/v3", "git.example.com:8443"),
    ],
)
def test_cli_token_lookup_is_bound_to_configured_github_host(
    monkeypatch: pytest.MonkeyPatch,
    api_url: str,
    expected_hostname: str,
) -> None:
    config = GitHubConfig(api_url=api_url)
    monkeypatch.delenv(config.token_env, raising=False)
    monkeypatch.setenv("GH_HOST", "wrong-host.example")
    observed: dict[str, object] = {}

    def run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        observed["args"] = args
        observed["kwargs"] = kwargs
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="host-bound-token\n")

    monkeypatch.setattr(subprocess, "run", run)

    assert resolve_github_token(config) == "host-bound-token"
    assert observed["args"] == (["gh", "auth", "token", "--hostname", expected_hostname],)
    environment = observed["kwargs"]
    assert isinstance(environment, dict)
    assert "GH_HOST" not in environment["env"]


def test_get_file_distinguishes_absence_from_readable_content() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/missing.md"):
            return httpx.Response(404, json={"message": "Not Found"})
        return httpx.Response(
            200,
            json={
                "type": "file",
                "encoding": "base64",
                "size": len(b"Policy text.\n"),
                "content": base64.b64encode(b"Policy text.\n").decode("ascii"),
            },
        )

    with _client(handler) as github:
        assert github.get_file("example/project", "POLICY.md", ref="a" * 40) == "Policy text.\n"
        assert github.get_file("example/project", "missing.md", ref="a" * 40) is None


@pytest.mark.parametrize(
    "payload",
    [
        {"type": "dir", "encoding": "base64", "size": 0, "content": ""},
        {"type": "file", "encoding": "none", "size": 6, "content": "Policy"},
        {
            "type": "file",
            "encoding": "base64",
            "size": 6,
            "content": "not valid base64!",
        },
    ],
)
def test_get_file_fails_closed_when_present_content_is_unreadable(
    payload: dict[str, object],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    with _client(handler) as github, pytest.raises(GitHubError, match="policy"):
        github.get_file("example/project", "POLICY.md", ref="a" * 40)


@pytest.mark.parametrize(
    "payload",
    [
        {
            "type": "file",
            "encoding": "base64",
            "size": 5,
            "content": base64.b64encode(b"too large").decode("ascii"),
        },
        {
            "type": "file",
            "encoding": "base64",
            "size": 9,
            "content": base64.b64encode(b"too large").decode("ascii"),
        },
    ],
)
def test_get_file_enforces_declared_and_decoded_byte_limits(
    payload: dict[str, object],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    with _client(handler) as github, pytest.raises(GitHubError, match=r"size|exceeds"):
        github.get_file("example/project", "POLICY.md", ref="a" * 40, max_bytes=8)


def test_policy_tree_and_content_requests_are_bound_to_an_immutable_ref() -> None:
    seen: list[tuple[str, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.path, request.url.params.get("ref")))
        if "/git/trees/" in request.url.path:
            return httpx.Response(
                200,
                json={
                    "truncated": False,
                    "tree": [{"type": "blob", "path": "CONTRIBUTING.md"}],
                },
            )
        content = b"Policy text.\n"
        return httpx.Response(
            200,
            json={
                "type": "file",
                "encoding": "base64",
                "size": len(content),
                "content": base64.b64encode(content).decode("ascii"),
            },
        )

    ref = "b" * 40
    with _client(handler) as github:
        assert github.list_repository_files("example/project", ref=ref) == ["CONTRIBUTING.md"]
        assert github.get_file("example/project", "CONTRIBUTING.md", ref=ref) == "Policy text.\n"

    assert seen == [
        (f"/repos/example/project/git/trees/{ref}", None),
        ("/repos/example/project/contents/CONTRIBUTING.md", ref),
    ]


def test_optional_policy_repository_resolves_one_full_default_branch_sha() -> None:
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path == "/repos/example/.github":
            return httpx.Response(200, json=_repository_payload("example/.github"))
        return httpx.Response(200, json={"object": {"sha": "c" * 40}})

    with _client(handler) as github:
        assert github.default_branch_sha_if_exists("example/.github") == "c" * 40

    assert paths == [
        "/repos/example/.github",
        "/repos/example/.github/git/ref/heads/main",
    ]


def _comment_payload(identifier: int = 11) -> dict[str, object]:
    return {
        "id": identifier,
        "user": {"login": "maintainer"},
        "author_association": "MEMBER",
        "body": "Please update the regression test.",
        "html_url": f"https://github.com/example/project/pull/7#comment-{identifier}",
        "created_at": "2026-07-21T12:00:00Z",
        "updated_at": "2026-07-21T12:00:00Z",
    }


def _candidate_issue_payload(
    *,
    repository: str = "example/project",
    number: int = 42,
    comments: int = 1,
    api_url: str = "https://api.github.com",
    web_origin: str = "https://github.com",
) -> dict[str, object]:
    api_url = api_url.rstrip("/")
    web_origin = web_origin.rstrip("/")
    return {
        "number": number,
        "url": f"{api_url}/repos/{repository}/issues/{number}",
        "repository_url": f"{api_url}/repos/{repository}",
        "title": "Fix parser",
        "body": "Reproduction steps and expected behavior",
        "html_url": f"{web_origin}/{repository}/issues/{number}",
        "state": "open",
        "user": {"login": "reporter"},
        "labels": [{"name": "help wanted"}],
        "assignees": [],
        "comments": comments,
        "created_at": "2026-07-19T12:00:00Z",
        "updated_at": "2026-07-20T12:00:00Z",
    }


def _issue_discussion_comment_payload(
    *,
    identifier: int = 1,
    repository: str = "example/project",
    number: int = 42,
    api_url: str = "https://api.github.com",
    web_origin: str = "https://github.com",
) -> dict[str, object]:
    api_url = api_url.rstrip("/")
    web_origin = web_origin.rstrip("/")
    return {
        "id": identifier,
        "url": f"{api_url}/repos/{repository}/issues/comments/{identifier}",
        "issue_url": f"{api_url}/repos/{repository}/issues/{number}",
        "user": {"login": "maintainer"},
        "author_association": "MEMBER",
        "body": "Please include the parser regression test.",
        "html_url": (f"{web_origin}/{repository}/issues/{number}#issuecomment-{identifier}"),
        "created_at": "2026-07-20T12:00:00Z",
        "updated_at": "2026-07-20T12:00:00Z",
    }


def _pull_request_search_item(
    number: int,
    *,
    title: str,
    body: str | None = None,
) -> dict[str, object]:
    return {
        "title": title,
        "body": body,
        "state": "open",
        "html_url": f"https://github.com/example/project/pull/{number}",
        "pull_request": {"url": f"https://api.github.com/pulls/{number}"},
    }


def _authored_pull_request_search_item(
    number: int = 7,
    *,
    repository: str = "example/project",
    state: str = "open",
) -> dict[str, object]:
    return {
        "number": number,
        "state": state,
        "html_url": f"https://github.com/{repository}/pull/{number}",
        "url": f"https://api.github.com/repos/{repository}/issues/{number}",
        "repository_url": f"https://api.github.com/repos/{repository}",
        "pull_request": {
            "url": f"https://api.github.com/repos/{repository}/pulls/{number}",
        },
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


def test_get_repository_accepts_exact_configured_ghes_web_urls() -> None:
    api_url = "https://git.example.com:8443/api/v3"
    payload = _repository_payload("example/project")
    payload["html_url"] = "https://git.example.com:8443/example/project"
    payload["clone_url"] = "https://git.example.com:8443/example/project.git"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    with _client(handler, api_url=api_url) as github:
        repository = github.get_repository("example/project")

    assert repository.html_url == "https://git.example.com:8443/example/project"
    assert repository.clone_url == "https://git.example.com:8443/example/project.git"


def test_repository_identity_reads_database_and_graphql_ids() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/repos/example/project"
        return httpx.Response(200, json=_repository_payload("example/project"))

    with _client(handler) as github:
        identity = github.get_repository_identity("example/project")

    assert identity.full_name == "example/project"
    assert identity.database_id == 1001
    assert identity.node_id == "R_fixture_1001"


def test_fork_identity_binds_immutable_parent() -> None:
    payload = _repository_payload("octocat/project")
    payload.update(
        {
            "id": 2001,
            "node_id": "R_fixture_2001",
            "fork": True,
            "parent": _repository_payload("example/project"),
        }
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/repos/octocat/project"
        return httpx.Response(200, json=payload)

    with _client(handler) as github:
        identity = github.get_fork_identity("octocat/project")

    assert identity.repository.database_id == 2001
    assert identity.repository.node_id == "R_fixture_2001"
    assert identity.parent.database_id == 1001
    assert identity.parent.node_id == "R_fixture_1001"


def test_repository_identity_assertion_uses_immutable_route_and_rejects_name_reuse() -> None:
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        return httpx.Response(200, json=_repository_payload("attacker/project"))

    with _client(handler) as github, pytest.raises(GitHubError, match="durable immutable"):
        github.assert_repository_identity(
            "example/project",
            expected_database_id=1001,
            expected_node_id="R_fixture_1001",
        )

    assert paths == ["/repositories/1001"]


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("full_name", "example/../project", "repository full name"),
        (
            "html_url",
            "https://attacker.invalid/example/project",
            "repository HTML URL",
        ),
        (
            "html_url",
            "https://github.com/example/project/",
            "repository HTML URL",
        ),
        (
            "clone_url",
            "https://attacker.invalid/example/project.git",
            "repository clone URL",
        ),
        (
            "clone_url",
            "https://github.com/example/project.git?redirect=attacker.invalid",
            "repository clone URL",
        ),
    ],
)
def test_get_repository_rejects_noncanonical_or_cross_host_identity_metadata(
    field: str,
    value: object,
    message: str,
) -> None:
    payload = _repository_payload("example/project")
    payload[field] = value

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    with _client(handler) as github, pytest.raises(GitHubError, match=message):
        github.get_repository("example/project")


def test_cross_origin_redirect_never_receives_authorization() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(301, headers={"Location": "https://attacker.invalid/steal"})

    with _client(handler) as github, pytest.raises(GitHubError, match="unsafe redirect"):
        github.get_repository("old/project")
    assert calls == 1


@pytest.mark.parametrize(
    ("status_code", "message"),
    [
        (403, "API rate limit exceeded for user"),
        (429, "slow down"),
    ],
)
def test_exhausted_rate_limit_retries_then_fails_without_tripping_breaker(
    tmp_path, monkeypatch, status_code: int, message: str
) -> None:  # type: ignore[no-untyped-def]
    store = RunStore(tmp_path / "state")
    waits: list[float] = []
    monkeypatch.setattr("autocontribute.github._sleep", waits.append)
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(
            status_code,
            headers={
                "Retry-After": "60",
                "X-GitHub-Request-Id": "fixture-request",
                "X-RateLimit-Remaining": "0",
            },
            json={"message": message},
        )

    with (
        _client(handler, safety_trigger_handler=store.trip_circuit_breaker_trigger) as github,
        pytest.raises(GitHubError, match="rate limited") as raised,
    ):
        github.authenticated_login()

    assert not isinstance(raised.value, GitHubSafetyError)
    assert requests == 4
    assert waits == [60.0, 60.0, 60.0]
    assert not store.circuit_breaker_status().is_tripped


def test_rate_limit_retry_honors_wait_and_recovers(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    store = RunStore(tmp_path / "state")
    waits: list[float] = []
    monkeypatch.setattr("autocontribute.github._sleep", waits.append)
    responses = iter(
        [
            httpx.Response(
                429,
                headers={"Retry-After": "3"},
                json={"message": "slow down"},
            ),
            httpx.Response(200, json={"login": "octocat"}),
        ]
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return next(responses)

    with _client(handler, safety_trigger_handler=store.trip_circuit_breaker_trigger) as github:
        assert github.authenticated_login() == "octocat"

    assert waits == [3.0]
    assert not store.circuit_breaker_status().is_tripped


def test_excessive_rate_limit_wait_fails_fast_without_sleeping(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    store = RunStore(tmp_path / "state")
    waits: list[float] = []
    monkeypatch.setattr("autocontribute.github._sleep", waits.append)
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(
            429,
            headers={"Retry-After": "3600"},
            json={"message": "slow down"},
        )

    with (
        _client(handler, safety_trigger_handler=store.trip_circuit_breaker_trigger) as github,
        pytest.raises(GitHubError, match="rate limited"),
    ):
        github.authenticated_login()

    assert requests == 1
    assert waits == []
    assert not store.circuit_breaker_status().is_tripped


def test_permission_403_fails_without_retry_or_breaker(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    store = RunStore(tmp_path / "state")
    monkeypatch.setattr(
        "autocontribute.github._sleep",
        lambda _: pytest.fail("permission failures must not sleep"),
    )
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(403, json={"message": "Resource not accessible by this token"})

    with (
        _client(handler, safety_trigger_handler=store.trip_circuit_breaker_trigger) as github,
        pytest.raises(GitHubError, match="returned 403") as raised,
    ):
        github.authenticated_login()

    assert not isinstance(raised.value, GitHubSafetyError)
    assert requests == 1
    assert not store.circuit_breaker_status().is_tripped


def test_persistent_abuse_signal_is_persisted_after_honored_wait(
    tmp_path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    store = RunStore(tmp_path / "state")
    waits: list[float] = []
    monkeypatch.setattr("autocontribute.github._sleep", waits.append)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            422,
            headers={
                "Retry-After": "60",
                "X-GitHub-Request-Id": "fixture-request",
            },
            json={"message": "You have triggered an abuse detection mechanism"},
        )

    with _client(
        handler,
        safety_trigger_handler=store.trip_circuit_breaker_trigger,
    ) as github:
        with pytest.raises(GitHubSafetyError, match="global safety stop") as raised:
            github.authenticated_login()
        first_hash = raised.value.trigger.trigger_hash
        with pytest.raises(GitHubSafetyError):
            github.authenticated_login()

    assert waits == [60.0, 60.0]
    status = store.circuit_breaker_status()
    assert status.is_tripped
    assert status.source == "github_api:persistent_abuse_limit"
    assert status.trigger_hash == first_hash


def test_transient_abuse_signal_recovers_without_tripping_breaker(
    tmp_path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    store = RunStore(tmp_path / "state")
    waits: list[float] = []
    monkeypatch.setattr("autocontribute.github._sleep", waits.append)
    responses = iter(
        [
            httpx.Response(
                403,
                headers={"Retry-After": "30"},
                json={"message": "You have exceeded a secondary rate limit"},
            ),
            httpx.Response(200, json={"login": "octocat"}),
        ]
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return next(responses)

    with _client(handler, safety_trigger_handler=store.trip_circuit_breaker_trigger) as github:
        assert github.authenticated_login() == "octocat"

    assert waits == [30.0]
    assert not store.circuit_breaker_status().is_tripped


def test_account_suspension_trips_breaker_immediately(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    store = RunStore(tmp_path / "state")
    monkeypatch.setattr(
        "autocontribute.github._sleep",
        lambda _: pytest.fail("account suspension must not be retried"),
    )
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(
            403,
            headers={"X-GitHub-Request-Id": "fixture-request"},
            json={"message": "Sorry. Your account was suspended."},
        )

    with (
        _client(handler, safety_trigger_handler=store.trip_circuit_breaker_trigger) as github,
        pytest.raises(GitHubSafetyError, match="suspended"),
    ):
        github.authenticated_login()

    assert requests == 1
    status = store.circuit_breaker_status()
    assert status.is_tripped
    assert status.source == "github_api:account_suspended"


def test_get_retries_transient_5xx_and_recovers(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    waits: list[float] = []
    monkeypatch.setattr("autocontribute.github._sleep", waits.append)
    responses = iter(
        [
            httpx.Response(502, json={"message": "bad gateway"}),
            httpx.Response(200, json={"login": "octocat"}),
        ]
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return next(responses)

    with _client(handler) as github:
        assert github.authenticated_login() == "octocat"

    assert waits == [2.0]


def test_mutation_is_never_retried_on_transient_5xx(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(
        "autocontribute.github._sleep",
        lambda _: pytest.fail("mutations must not be retried on ambiguous failures"),
    )
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        if request.method == "GET":
            return httpx.Response(404, json={"message": "Not Found"})
        return httpx.Response(502, json={"message": "bad gateway"})

    with _client(handler) as github, pytest.raises(GitHubError, match="returned 502"):
        github.ensure_fork("upstream/project", "octocat")

    assert requests == 2


def test_get_retries_transport_errors_and_recovers(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    waits: list[float] = []
    monkeypatch.setattr("autocontribute.github._sleep", waits.append)
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise httpx.ConnectError("connection reset")
        return httpx.Response(200, json={"login": "octocat"})

    with _client(handler) as github:
        assert github.authenticated_login() == "octocat"

    assert waits == [2.0]


def test_existing_unrelated_repository_cannot_be_reused_as_fork() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"fork": False, "full_name": "octocat/project"})

    with _client(handler) as github, pytest.raises(GitHubError, match="not a fork"):
        github.ensure_fork("upstream/project", "octocat")


def test_ensure_fork_callback_can_block_creation_before_post() -> None:
    requests: list[tuple[str, str]] = []
    callbacks: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append((request.method, request.url.path))
        assert request.method == "GET"
        return httpx.Response(404, json={"message": "Not Found"})

    def block_creation() -> None:
        callbacks.append("called")
        raise RuntimeError("stop before fork creation")

    with (
        _client(handler) as github,
        pytest.raises(RuntimeError, match="stop before fork creation"),
    ):
        github.ensure_fork(
            "upstream/project",
            "octocat",
            before_mutation=block_creation,
        )

    assert callbacks == ["called"]
    assert requests == [("GET", "/repos/octocat/project")]


def test_ensure_fork_does_not_invoke_mutation_callback_for_existing_fork() -> None:
    requests: list[tuple[str, str]] = []
    callbacks: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append((request.method, request.url.path))
        return httpx.Response(
            200,
            json={
                "fork": True,
                "full_name": "octocat/project",
                "parent": {"full_name": "upstream/project"},
            },
        )

    with _client(handler) as github:
        fork = github.ensure_fork(
            "upstream/project",
            "octocat",
            before_mutation=lambda: callbacks.append("called"),
        )

    assert fork == "octocat/project"
    assert callbacks == []
    assert requests == [("GET", "/repos/octocat/project")]


def test_competing_pull_request_search_paginates_issue_timeline() -> None:
    pages: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/search/issues":
            return httpx.Response(
                200,
                json={
                    "total_count": 1,
                    "incomplete_results": False,
                    "items": [
                        {
                            "title": "Fixes #42",
                            "body": None,
                            "state": "open",
                            "html_url": "https://github.com/example/project/pull/99",
                            "pull_request": {"url": "https://api.github.com/pulls/99"},
                        }
                    ],
                },
            )
        page = int(request.url.params["page"])
        pages.append(page)
        if page == 1:
            return httpx.Response(
                200,
                json=[
                    {
                        "event": "cross-referenced",
                        "source": {
                            "issue": {
                                "state": "open",
                                "html_url": "https://github.com/example/project/pull/98",
                                "pull_request": {"url": "https://api.github.com/pulls/98"},
                            }
                        },
                    },
                    *[{"event": "commented"}] * 99,
                ],
            )
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

    assert matches == [
        "https://github.com/example/project/pull/98",
        "https://github.com/example/project/pull/99",
    ]
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


def test_competing_pull_request_search_accepts_only_exact_issue_references() -> None:
    search_query = ""

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal search_query
        if request.url.path.endswith("/timeline"):
            return httpx.Response(200, json=[])
        search_query = request.url.params["q"]
        items = [
            _pull_request_search_item(1, title="Fix parser regression (#42)"),
            _pull_request_search_item(
                2,
                title="Fix parser regression",
                body="Resolves example/project#42.",
            ),
            _pull_request_search_item(
                3,
                title="Fix parser regression",
                body="See https://github.com/example/project/issues/42?source=pr.",
            ),
            _pull_request_search_item(4, title="Unrelated follow-up for #420"),
            _pull_request_search_item(
                5,
                title="Different project",
                body="Resolves other/example/project#42.",
            ),
            _pull_request_search_item(
                6,
                title="Different URL",
                body="See https://github.com/example/project/issues/420.",
            ),
        ]
        return httpx.Response(
            200,
            json={
                "total_count": len(items),
                "incomplete_results": False,
                "items": items,
            },
        )

    with _client(handler) as github:
        matches = github.search_competing_pull_requests("example/project", 42)

    assert matches == [
        "https://github.com/example/project/pull/1",
        "https://github.com/example/project/pull/2",
        "https://github.com/example/project/pull/3",
    ]
    assert "42" in search_query
    assert "in:title,body" in search_query


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (
            {"total_count": 0, "incomplete_results": True, "items": []},
            "incomplete competing",
        ),
        (
            {"total_count": 101, "incomplete_results": False, "items": []},
            "above the safe limit",
        ),
        (
            {
                "total_count": 2,
                "incomplete_results": False,
                "items": [_pull_request_search_item(1, title="Fixes #42")],
            },
            "truncated competing",
        ),
    ],
)
def test_competing_pull_request_search_fails_closed_on_incomplete_evidence(
    payload: dict[str, object], message: str
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/timeline"):
            return httpx.Response(200, json=[])
        return httpx.Response(200, json=payload)

    with _client(handler) as github, pytest.raises(GitHubError, match=message):
        github.search_competing_pull_requests("example/project", 42)


def test_authored_pull_request_search_requires_complete_canonical_results() -> None:
    query: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        query.update(dict(request.url.params))
        return httpx.Response(
            200,
            json={
                "total_count": 1,
                "incomplete_results": False,
                "items": [_authored_pull_request_search_item()],
            },
        )

    with _client(handler) as github:
        urls = github.authored_pull_requests(
            "octocat",
            state="open",
            repository="example/project",
            updated_after="2026-07-01",
            created_after="2026-07-20",
        )

    assert urls == ["https://github.com/example/project/pull/7"]
    assert query == {
        "q": (
            "is:pr is:open author:octocat repo:example/project "
            "updated:>=2026-07-01 created:>=2026-07-20"
        ),
        "sort": "updated",
        "per_page": "100",
        "page": "1",
    }


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (
            {"total_count": 0, "incomplete_results": True, "items": []},
            "incomplete authored",
        ),
        (
            {"total_count": 0, "items": []},
            "malformed authored",
        ),
        (
            {"total_count": 101, "incomplete_results": False, "items": []},
            "one-page safe limit",
        ),
        (
            {
                "total_count": 2,
                "incomplete_results": False,
                "items": [_authored_pull_request_search_item()],
            },
            "truncated authored",
        ),
        (
            {"total_count": 0, "incomplete_results": False},
            "malformed authored pull request search results",
        ),
    ],
)
def test_authored_pull_request_search_fails_closed_on_ambiguous_metadata(
    payload: dict[str, object], message: str
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    with _client(handler) as github, pytest.raises(GitHubError, match=message):
        github.authored_pull_requests("octocat")


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"state": "closed"}, "different state"),
        ({"number": 8}, "different number"),
        ({"html_url": "https://attacker.invalid/example/project/pull/7"}, "noncanonical"),
        ({"html_url": " https://github.com/example/project/pull/7"}, "noncanonical"),
        ({"html_url": "https://github.com/other/project/pull/7"}, "different repository"),
        ({"url": ""}, "invalid searched pull request issue API URL"),
        ({"repository_url": "https://api.github.com/repos/other/project"}, "noncanonical"),
        ({"pull_request": {}}, "searched pull request API URL"),
    ],
)
def test_authored_pull_request_search_rejects_malformed_item_identity(
    overrides: dict[str, object], message: str
) -> None:
    item = _authored_pull_request_search_item()
    item.update(overrides)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"total_count": 1, "incomplete_results": False, "items": [item]},
        )

    with _client(handler) as github, pytest.raises(GitHubError, match=message):
        github.authored_pull_requests("octocat", repository="example/project")


@pytest.mark.parametrize(
    "arguments",
    [
        {"login": "octocat repo:other/project"},
        {"login": "octocat", "state": "all"},
        {"login": "octocat", "repository": "not-a-repository"},
        {"login": "octocat", "updated_after": "2026-02-30"},
        {"login": "octocat", "created_after": "2026-7-1"},
    ],
)
def test_authored_pull_request_search_rejects_unsafe_inputs(
    arguments: dict[str, object],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("invalid search inputs must not reach GitHub")

    with _client(handler) as github, pytest.raises(ValueError):
        github.authored_pull_requests(**arguments)  # type: ignore[arg-type]


def test_get_issue_fetches_complete_discussion() -> None:
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path.endswith("/comments"):
            return httpx.Response(
                200,
                json=[
                    {
                        "id": 1,
                        "url": ("https://api.github.com/repos/example/project/issues/comments/1"),
                        "user": {"login": "maintainer"},
                        "author_association": "MEMBER",
                        "body": "Please include the parser regression test.",
                        "html_url": "https://github.com/example/project/issues/42#issuecomment-1",
                        "issue_url": "https://api.github.com/repos/example/project/issues/42",
                        "created_at": "2026-07-20T12:00:00Z",
                        "updated_at": "2026-07-20T12:00:00Z",
                    }
                ],
            )
        return httpx.Response(
            200,
            json={
                "number": 42,
                "url": "https://api.github.com/repos/example/project/issues/42",
                "repository_url": "https://api.github.com/repos/example/project",
                "title": "Fix parser",
                "body": "Reproduction steps and expected behavior",
                "html_url": "https://github.com/example/project/issues/42",
                "state": "open",
                "user": {"login": "reporter"},
                "labels": [{"name": "help wanted"}],
                "assignees": [],
                "comments": 1,
                "created_at": "2026-07-19T12:00:00Z",
                "updated_at": "2026-07-20T12:00:00Z",
            },
        )

    with _client(handler) as github:
        issue = github.get_issue("example/project", 42)

    assert paths == [
        "/repos/example/project/issues/42",
        "/repos/example/project/issues/42/comments",
        "/repos/example/project/issues/42",
        "/repos/example/project/issues/42/comments",
        "/repos/example/project/issues/42",
    ]
    assert issue.discussion[0].author == "maintainer"
    assert issue.discussion[0].author_association == "MEMBER"


def test_get_issue_rejects_metadata_change_during_discussion_fetch() -> None:
    issue_reads = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal issue_reads
        if request.url.path.endswith("/comments"):
            return httpx.Response(
                200,
                json=[
                    {
                        "id": 1,
                        "url": ("https://api.github.com/repos/example/project/issues/comments/1"),
                        "user": {"login": "maintainer"},
                        "author_association": "MEMBER",
                        "body": "Please include the parser regression test.",
                        "html_url": "https://github.com/example/project/issues/42#issuecomment-1",
                        "issue_url": "https://api.github.com/repos/example/project/issues/42",
                        "created_at": "2026-07-20T12:00:00Z",
                        "updated_at": "2026-07-20T12:00:00Z",
                    }
                ],
            )
        issue_reads += 1
        return httpx.Response(
            200,
            json={
                "number": 42,
                "url": "https://api.github.com/repos/example/project/issues/42",
                "repository_url": "https://api.github.com/repos/example/project",
                "title": "Fix parser",
                "body": "Reproduction steps and expected behavior",
                "html_url": "https://github.com/example/project/issues/42",
                "state": "open" if issue_reads == 1 else "closed",
                "user": {"login": "reporter"},
                "labels": [{"name": "help wanted"}],
                "assignees": [],
                "comments": 1,
                "created_at": "2026-07-19T12:00:00Z",
                "updated_at": "2026-07-20T12:00:00Z",
            },
        )

    with (
        _client(handler) as github,
        pytest.raises(
            GitHubError,
            match="Issue changed while its complete discussion was fetched",
        ),
    ):
        github.get_issue("example/project", 42)

    assert issue_reads == 2


def test_get_issue_rejects_comment_content_change_with_stable_metadata() -> None:
    paths: list[str] = []
    comment_reads = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal comment_reads
        paths.append(request.url.path)
        if request.url.path.endswith("/comments"):
            comment_reads += 1
            return httpx.Response(
                200,
                json=[
                    {
                        "id": 1,
                        "url": ("https://api.github.com/repos/example/project/issues/comments/1"),
                        "user": {"login": "maintainer"},
                        "author_association": "MEMBER",
                        "body": (
                            "Please include the parser regression test."
                            if comment_reads == 1
                            else "Please include parser and serializer regression tests."
                        ),
                        "html_url": "https://github.com/example/project/issues/42#issuecomment-1",
                        "issue_url": "https://api.github.com/repos/example/project/issues/42",
                        "created_at": "2026-07-20T12:00:00Z",
                        "updated_at": "2026-07-20T12:00:00Z",
                    }
                ],
            )
        return httpx.Response(
            200,
            json={
                "number": 42,
                "url": "https://api.github.com/repos/example/project/issues/42",
                "repository_url": "https://api.github.com/repos/example/project",
                "title": "Fix parser",
                "body": "Reproduction steps and expected behavior",
                "html_url": "https://github.com/example/project/issues/42",
                "state": "open",
                "user": {"login": "reporter"},
                "labels": [{"name": "help wanted"}],
                "assignees": [],
                "comments": 1,
                "created_at": "2026-07-19T12:00:00Z",
                "updated_at": "2026-07-20T12:00:00Z",
            },
        )

    with (
        _client(handler) as github,
        pytest.raises(GitHubError, match="Issue discussion changed while it was fetched"),
    ):
        github.get_issue("example/project", 42)

    assert paths == [
        "/repos/example/project/issues/42",
        "/repos/example/project/issues/42/comments",
        "/repos/example/project/issues/42",
        "/repos/example/project/issues/42/comments",
        "/repos/example/project/issues/42",
    ]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("repository_url", None),
        ("repository_url", "https://api.github.com/repos/other/project"),
        ("url", None),
        ("url", "https://api.github.com/repos/other/project/issues/42"),
    ],
)
def test_get_issue_rejects_unbound_metadata_identity(
    field: str,
    value: str | None,
) -> None:
    payload: dict[str, object] = {
        "number": 42,
        "url": "https://api.github.com/repos/example/project/issues/42",
        "repository_url": "https://api.github.com/repos/example/project",
        "title": "Fix parser",
        "body": "Reproduction steps and expected behavior",
        "html_url": "https://github.com/example/project/issues/42",
        "state": "open",
        "user": {"login": "reporter"},
        "labels": [{"name": "help wanted"}],
        "assignees": [],
        "comments": 0,
        "created_at": "2026-07-19T12:00:00Z",
        "updated_at": "2026-07-20T12:00:00Z",
    }
    if value is None:
        payload.pop(field)
    else:
        payload[field] = value

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    with (
        _client(handler) as github,
        pytest.raises(GitHubError, match=r"noncanonical issue .*API URL"),
    ):
        github.get_issue("example/project", 42)


@pytest.mark.parametrize(
    "value",
    [
        None,
        "https://attacker.example/example/project/issues/42",
        "https://github.com/other/project/issues/42",
        "https://github.com/example/project/issues/99",
        "https://github.com/example/project/issues/42?view=full",
        "https://github.com/example/project/issues/42#fragment",
        "https://github.com/example/project/issues/42/",
    ],
)
def test_get_issue_rejects_unbound_html_identity(value: str | None) -> None:
    payload = _candidate_issue_payload(comments=0)
    if value is None:
        payload.pop("html_url")
    else:
        payload["html_url"] = value

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    with (
        _client(handler) as github,
        pytest.raises(GitHubError, match="noncanonical issue HTML URL"),
    ):
        github.get_issue("example/project", 42)


def test_get_issue_rejects_comment_bound_to_another_issue() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/comments"):
            return httpx.Response(
                200,
                json=[
                    {
                        "id": 1,
                        "url": ("https://api.github.com/repos/example/project/issues/comments/1"),
                        "user": {"login": "maintainer"},
                        "author_association": "MEMBER",
                        "body": "Comment from a different issue.",
                        "html_url": "https://github.com/other/project/issues/99#issuecomment-1",
                        "issue_url": "https://api.github.com/repos/other/project/issues/99",
                        "created_at": "2026-07-20T12:00:00Z",
                        "updated_at": "2026-07-20T12:00:00Z",
                    }
                ],
            )
        return httpx.Response(
            200,
            json={
                "number": 42,
                "url": "https://api.github.com/repos/example/project/issues/42",
                "repository_url": "https://api.github.com/repos/example/project",
                "title": "Fix parser",
                "body": "Reproduction steps and expected behavior",
                "html_url": "https://github.com/example/project/issues/42",
                "state": "open",
                "user": {"login": "reporter"},
                "labels": [{"name": "help wanted"}],
                "assignees": [],
                "comments": 1,
                "created_at": "2026-07-19T12:00:00Z",
                "updated_at": "2026-07-20T12:00:00Z",
            },
        )

    with (
        _client(handler) as github,
        pytest.raises(GitHubError, match="noncanonical issue comment parent API URL"),
    ):
        github.get_issue("example/project", 42)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("id", None, "invalid issue comment identifier"),
        ("id", 0, "invalid issue comment identifier"),
        ("id", -1, "invalid issue comment identifier"),
        ("id", True, "invalid issue comment identifier"),
        ("id", "1", "invalid issue comment identifier"),
        ("url", None, "noncanonical issue comment API URL"),
        (
            "url",
            "https://api.github.com/repos/other/project/issues/comments/1",
            "noncanonical issue comment API URL",
        ),
        (
            "url",
            "https://api.github.com/repos/example/project/issues/comments/2",
            "noncanonical issue comment API URL",
        ),
        (
            "url",
            "https://api.github.com/repos/example/project/issues/comments/1?view=full",
            "noncanonical issue comment API URL",
        ),
        (
            "url",
            "https://api.github.com/repos/example/project/issues/comments/1#fragment",
            "noncanonical issue comment API URL",
        ),
        (
            "url",
            "https://api.github.com/repos/example/project/issues/comments/1/",
            "noncanonical issue comment API URL",
        ),
        ("issue_url", None, "noncanonical issue comment parent API URL"),
        (
            "issue_url",
            "https://api.github.com/repos/other/project/issues/42",
            "noncanonical issue comment parent API URL",
        ),
        (
            "issue_url",
            "https://api.github.com/repos/example/project/issues/99",
            "noncanonical issue comment parent API URL",
        ),
        (
            "issue_url",
            "https://api.github.com/repos/example/project/issues/42?view=full",
            "noncanonical issue comment parent API URL",
        ),
        (
            "issue_url",
            "https://api.github.com/repos/example/project/issues/42#fragment",
            "noncanonical issue comment parent API URL",
        ),
        (
            "issue_url",
            "https://api.github.com/repos/example/project/issues/42/",
            "noncanonical issue comment parent API URL",
        ),
        ("html_url", None, "noncanonical issue comment HTML URL"),
        (
            "html_url",
            "https://github.com/other/project/issues/42#issuecomment-1",
            "noncanonical issue comment HTML URL",
        ),
        (
            "html_url",
            "https://github.com/example/project/issues/99#issuecomment-1",
            "noncanonical issue comment HTML URL",
        ),
        (
            "html_url",
            "https://github.com/example/project/issues/42#issuecomment-2",
            "noncanonical issue comment HTML URL",
        ),
        (
            "html_url",
            "https://github.com/example/project/issues/42?view=full#issuecomment-1",
            "noncanonical issue comment HTML URL",
        ),
        (
            "html_url",
            "https://github.com/example/project/issues/42/#issuecomment-1",
            "noncanonical issue comment HTML URL",
        ),
    ],
)
def test_get_issue_comments_rejects_unbound_comment_identity(
    field: str,
    value: object,
    message: str,
) -> None:
    comment = _issue_discussion_comment_payload()
    if value is None:
        comment.pop(field)
    else:
        comment[field] = value

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[comment])

    with _client(handler) as github, pytest.raises(GitHubError, match=message):
        github.get_issue_comments("example/project", 42, expected_count=1)


def test_get_issue_comments_rejects_duplicate_comment_identities() -> None:
    comment = _issue_discussion_comment_payload()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[comment, comment])

    with (
        _client(handler) as github,
        pytest.raises(GitHubError, match="duplicate issue comment identities"),
    ):
        github.get_issue_comments("example/project", 42, expected_count=2)


def test_get_issue_accepts_canonical_ghes_comment_identity() -> None:
    api_url = "https://git.example.com/api/v3"
    web_origin = "https://git.example.com"
    issue_payload = _candidate_issue_payload(api_url=api_url, web_origin=web_origin)
    comment_payload = _issue_discussion_comment_payload(
        api_url=api_url,
        web_origin=web_origin,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/comments"):
            return httpx.Response(200, json=[comment_payload])
        return httpx.Response(200, json=issue_payload)

    with _client(handler, api_url=api_url) as github:
        issue = github.get_issue("example/project", 42)

    assert issue.discussion[0].html_url == (
        "https://git.example.com/example/project/issues/42#issuecomment-1"
    )
    assert issue.html_url == "https://git.example.com/example/project/issues/42"


def test_get_issue_proves_a_stable_empty_discussion() -> None:
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path.endswith("/comments"):
            return httpx.Response(200, json=[])
        return httpx.Response(
            200,
            json={
                "number": 42,
                "url": "https://api.github.com/repos/example/project/issues/42",
                "repository_url": "https://api.github.com/repos/example/project",
                "title": "Fix parser",
                "body": "Reproduction steps and expected behavior",
                "html_url": "https://github.com/example/project/issues/42",
                "state": "open",
                "user": {"login": "reporter"},
                "labels": [{"name": "help wanted"}],
                "assignees": [],
                "comments": 0,
                "created_at": "2026-07-19T12:00:00Z",
                "updated_at": "2026-07-20T12:00:00Z",
            },
        )

    with _client(handler) as github:
        issue = github.get_issue("example/project", 42)

    assert issue.discussion == []
    assert paths == [
        "/repos/example/project/issues/42",
        "/repos/example/project/issues/42/comments",
        "/repos/example/project/issues/42",
        "/repos/example/project/issues/42/comments",
        "/repos/example/project/issues/42",
    ]


def test_get_issue_rejects_third_metadata_read_drift() -> None:
    issue_reads = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal issue_reads
        if request.url.path.endswith("/comments"):
            return httpx.Response(200, json=[])
        issue_reads += 1
        return httpx.Response(
            200,
            json={
                "number": 42,
                "url": "https://api.github.com/repos/example/project/issues/42",
                "repository_url": "https://api.github.com/repos/example/project",
                "title": "Fix parser",
                "body": "Reproduction steps and expected behavior",
                "html_url": "https://github.com/example/project/issues/42",
                "state": "open" if issue_reads < 3 else "closed",
                "user": {"login": "reporter"},
                "labels": [{"name": "help wanted"}],
                "assignees": [],
                "comments": 0,
                "created_at": "2026-07-19T12:00:00Z",
                "updated_at": "2026-07-20T12:00:00Z",
            },
        )

    with (
        _client(handler) as github,
        pytest.raises(GitHubError, match="Issue changed while its complete discussion was fetched"),
    ):
        github.get_issue("example/project", 42)

    assert issue_reads == 3


def test_issue_discussion_above_bound_fails_closed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "number": 42,
                "url": "https://api.github.com/repos/example/project/issues/42",
                "repository_url": "https://api.github.com/repos/example/project",
                "title": "Busy issue",
                "body": "body",
                "html_url": "https://github.com/example/project/issues/42",
                "state": "open",
                "user": {"login": "reporter"},
                "labels": [],
                "assignees": [],
                "comments": 501,
                "created_at": "2026-07-19T12:00:00Z",
                "updated_at": "2026-07-20T12:00:00Z",
            },
        )

    with _client(handler) as github, pytest.raises(GitHubError, match="discussion limit"):
        github.get_issue("example/project", 42)


def test_exact_hundred_issue_comment_count_detects_new_overflow_comment() -> None:
    pages: list[int] = []

    def comment(identifier: int) -> dict[str, object]:
        return {
            "id": identifier,
            "url": (f"https://api.github.com/repos/example/project/issues/comments/{identifier}"),
            "user": {"login": "maintainer"},
            "author_association": "MEMBER",
            "body": f"Comment {identifier}",
            "html_url": (f"https://github.com/example/project/issues/42#issuecomment-{identifier}"),
            "issue_url": "https://api.github.com/repos/example/project/issues/42",
            "created_at": "2026-07-20T12:00:00Z",
            "updated_at": "2026-07-20T12:00:00Z",
        }

    def handler(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params["page"])
        pages.append(page)
        if page == 1:
            return httpx.Response(200, json=[comment(index) for index in range(1, 101)])
        return httpx.Response(200, json=[comment(101)])

    with _client(handler) as github, pytest.raises(GitHubError, match="count changed"):
        github.get_issue_comments("example/project", 42, expected_count=100)

    assert pages == [1, 2]


def test_lifecycle_read_api_parses_complete_bounded_evidence() -> None:
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        paths.append(path)
        if path == "/repos/example/project/pulls/7":
            return httpx.Response(200, json=_pull_request_payload(merged=True))
        if path == "/repos/example/project/pulls/7/commits":
            return httpx.Response(
                200,
                json=[
                    {
                        "sha": "a" * 40,
                        "node_id": "C_fixture_a",
                        "parents": [{"sha": "c" * 40}],
                    }
                ],
            )
        if path.endswith("/reviews"):
            return httpx.Response(
                200,
                json=[
                    {
                        "id": 21,
                        "user": {"login": "reviewer"},
                        "author_association": "COLLABORATOR",
                        "state": "APPROVED",
                        "body": "Looks good.",
                        "html_url": "https://github.com/example/project/pull/7#review-21",
                        "submitted_at": "2026-07-21T12:10:00Z",
                    }
                ],
            )
        if path == "/repos/example/project/issues/7/comments":
            return httpx.Response(200, json=[_comment_payload(11)])
        if path == "/repos/example/project/pulls/7/comments":
            return httpx.Response(200, json=[_comment_payload(12)])
        if path.endswith("/check-runs"):
            return httpx.Response(
                200,
                json={
                    "total_count": 1,
                    "check_runs": [
                        {
                            "id": 31,
                            "name": "unit",
                            "status": "completed",
                            "conclusion": "success",
                            "details_url": "https://github.com/example/project/actions/runs/31",
                            "app": {"slug": "github-actions"},
                            "started_at": "2026-07-21T12:15:00Z",
                            "completed_at": "2026-07-21T12:20:00Z",
                        }
                    ],
                },
            )
        if path.endswith("/statuses"):
            return httpx.Response(
                200,
                json=[
                    {
                        "id": 41,
                        "context": "buildkite/test",
                        "state": "success",
                        "description": "passed",
                        "target_url": "https://ci.example.invalid/41",
                        "creator": {"login": "ci-bot"},
                        "created_at": "2026-07-21T12:15:00Z",
                        "updated_at": "2026-07-21T12:20:00Z",
                    }
                ],
            )
        if path.endswith("/timeline"):
            return httpx.Response(
                200,
                json=[
                    {
                        "id": 51,
                        "node_id": "CRE_fixture_51",
                        "event": "cross-referenced",
                        "created_at": "2026-07-21T14:00:00Z",
                        "source": {
                            "issue": {
                                "title": "Revert parser fix",
                                "body": "Reverts example/project#7",
                                "state": "closed",
                                "html_url": "https://github.com/example/project/pull/8",
                                "pull_request": {"merged_at": "2026-07-21T14:30:00Z"},
                            }
                        },
                    }
                ],
            )
        raise AssertionError(f"unexpected path: {path}")

    with _client(handler) as github:
        pull_request = github.get_pull_request("example/project", 7)
        commits = github.list_pull_request_commits(
            "example/project",
            7,
            expected_count=pull_request.commit_count,
            expected_head_sha=pull_request.head_sha,
        )
        reviews = github.list_pull_request_reviews("example/project", 7)
        issue_comments = github.list_issue_comments(
            "example/project", 7, expected_count=pull_request.issue_comment_count
        )
        review_comments = github.list_review_comments(
            "example/project", 7, expected_count=pull_request.review_comment_count
        )
        checks = github.list_check_runs("example/project", pull_request.head_sha)
        statuses = github.list_commit_statuses("example/project", pull_request.head_sha)
        timeline = github.get_pull_request_timeline("example/project", 7)

    assert pull_request.merged
    assert pull_request.merge_commit_sha == "b" * 40
    assert commits[0].sha == pull_request.head_sha
    assert reviews[0].state == "APPROVED"
    assert issue_comments[0].identifier == 11
    assert review_comments[0].identifier == 12
    assert checks[0].app_name == "github-actions"
    assert statuses[0].context == "buildkite/test"
    assert timeline.references[0].source_merged_at is not None
    assert timeline.item_count == 1
    assert len(paths) == 8


def test_pull_request_commits_collect_more_than_one_page_in_order() -> None:
    payloads = _linear_pull_request_commits(101)
    pages: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params["page"])
        pages.append(page)
        start = (page - 1) * 100
        return httpx.Response(200, json=payloads[start : start + 100])

    with _client(handler) as github:
        commits = github.list_pull_request_commits(
            "example/project",
            7,
            expected_count=101,
            expected_head_sha=str(payloads[-1]["sha"]),
        )

    assert pages == [1, 2]
    assert [commit.position for commit in commits] == list(range(1, 102))
    assert commits[-1].sha == payloads[-1]["sha"]


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        ("count", "count changed"),
        ("head", "advertised head"),
        ("sha", "duplicate pull request commits"),
        ("node", "duplicate pull request commits node identities"),
    ],
)
def test_pull_request_commit_evidence_fails_closed_on_identity_drift(
    failure: str,
    message: str,
) -> None:
    payloads = _linear_pull_request_commits(2)
    expected_count = 2
    expected_head = str(payloads[-1]["sha"])
    if failure == "count":
        expected_count = 3
    elif failure == "head":
        expected_head = "e" * 40
    elif failure == "sha":
        payloads[-1]["sha"] = payloads[0]["sha"]
        payloads[-1]["parents"] = [{"sha": "e" * 40}]
        expected_head = str(payloads[0]["sha"])
    elif failure == "node":
        payloads[-1]["node_id"] = payloads[0]["node_id"]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payloads)

    with _client(handler) as github, pytest.raises(GitHubError, match=message):
        github.list_pull_request_commits(
            "example/project",
            7,
            expected_count=expected_count,
            expected_head_sha=expected_head,
        )


def test_pull_request_timeline_captures_force_push_and_orders_close_reopen_history() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=[
                {
                    "id": 3,
                    "node_id": "RE_fixture_3",
                    "event": "reopened",
                    "actor": {"login": "maintainer"},
                    "commit_id": None,
                    "created_at": "2026-07-21T13:00:00Z",
                },
                {
                    "id": 2,
                    "node_id": "HRFPE_fixture_2",
                    "event": "head_ref_force_pushed",
                    "actor": {"login": "contributor"},
                    "commit_id": "a" * 40,
                    "created_at": "2026-07-21T12:30:00Z",
                },
                {
                    "id": 1,
                    "node_id": "CE_fixture_1",
                    "event": "closed",
                    "actor": {"login": "maintainer"},
                    "commit_id": None,
                    "created_at": "2026-07-21T12:00:00Z",
                },
            ],
        )

    with _client(handler) as github:
        timeline = github.get_pull_request_timeline("example/project", 7)

    assert timeline.item_count == 3
    assert [event.event for event in timeline.events] == [
        "closed",
        "head_ref_force_pushed",
        "reopened",
    ]
    assert timeline.events[1].actor == "contributor"
    assert timeline.events[1].commit_sha == "a" * 40


def test_pull_request_timeline_overflow_fails_closed() -> None:
    pages: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params["page"])
        pages.append(page)
        start = (page - 1) * 100
        return httpx.Response(
            200,
            json=[
                {
                    "id": index,
                    "node_id": f"LE_fixture_{index}",
                    "event": "labeled",
                }
                for index in range(start + 1, start + 101)
            ],
        )

    with _client(handler) as github, pytest.raises(GitHubError, match="safe limit of 100"):
        github.get_pull_request_timeline("example/project", 7, max_events=100)

    assert pages == [1, 2]


@pytest.mark.parametrize(
    ("payloads", "message"),
    [
        (
            [
                {"id": 1, "node_id": "LE_duplicate", "event": "labeled"},
                {"id": 2, "node_id": "LE_duplicate", "event": "unlabeled"},
            ],
            "duplicate pull request timeline node identities",
        ),
        (
            [
                {
                    "id": 1,
                    "node_id": "CE_fixture_1",
                    "event": "closed",
                    "actor": {"login": "maintainer"},
                    "commit_id": None,
                    "created_at": "2026-07-21T12:00:00Z",
                },
                {
                    "id": 1,
                    "node_id": "RE_fixture_1",
                    "event": "reopened",
                    "actor": {"login": "maintainer"},
                    "commit_id": None,
                    "created_at": "2026-07-21T13:00:00Z",
                },
            ],
            "duplicate pull request history events",
        ),
        (
            [
                {
                    "id": 1,
                    "node_id": "CE_fixture_1",
                    "event": "closed",
                    "actor": {"login": "maintainer"},
                    "commit_id": None,
                    "created_at": "2026-07-21T12:00:00Z",
                },
                {
                    "id": 1,
                    "node_id": "CRE_fixture_1",
                    "event": "cross-referenced",
                    "created_at": "2026-07-21T13:00:00Z",
                    "source": {
                        "issue": {
                            "title": "Related pull request",
                            "body": "Tracks example/project#7",
                            "state": "open",
                            "html_url": "https://github.com/example/project/pull/8",
                            "pull_request": {"merged_at": None},
                        }
                    },
                },
            ],
            "duplicate retained pull request timeline identifiers",
        ),
    ],
)
def test_pull_request_timeline_rejects_duplicate_identities(
    payloads: list[dict[str, object]],
    message: str,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payloads)

    with _client(handler) as github, pytest.raises(GitHubError, match=message):
        github.get_pull_request_timeline("example/project", 7)


def test_lifecycle_collection_over_limit_fails_closed_with_overflow_page() -> None:
    pages: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        pages.append(int(request.url.params["page"]))
        review = {
            "id": 1,
            "user": {"login": "reviewer"},
            "author_association": "MEMBER",
            "state": "COMMENTED",
            "body": "note",
            "html_url": "https://github.com/example/project/pull/7#review-1",
            "submitted_at": "2026-07-21T12:00:00Z",
        }
        return httpx.Response(200, json=[review] * 100)

    with _client(handler) as github, pytest.raises(GitHubError, match="safe limit of 100"):
        github.list_pull_request_reviews("example/project", 7, max_reviews=100)

    assert pages == [1, 2]


def test_lifecycle_comment_count_race_fails_closed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[_comment_payload()])

    with _client(handler) as github, pytest.raises(GitHubError, match="count changed"):
        github.list_issue_comments("example/project", 7, expected_count=2)


def test_check_run_total_mismatch_fails_closed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"total_count": 2, "check_runs": []})

    with _client(handler) as github, pytest.raises(GitHubError, match="fewer check runs"):
        github.list_check_runs("example/project", "a" * 40)


def test_lifecycle_timestamp_without_timezone_fails_closed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        payload = _pull_request_payload()
        payload["updated_at"] = "2026-07-21T13:00:00"
        return httpx.Response(200, json=payload)

    with _client(handler) as github, pytest.raises(GitHubError, match="without a timezone"):
        github.get_pull_request("example/project", 7)


def test_publication_branch_lookup_rejects_multiple_pull_requests() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=[
                {"html_url": "https://github.com/example/project/pull/7"},
                {"html_url": "https://github.com/example/project/pull/8"},
            ],
        )

    with _client(handler) as github, pytest.raises(GitHubError, match="multiple pull requests"):
        github.find_pull_request("example/project", head="octocat:autocontribute/issue-42")


def _create_pull_request(github: GitHubClient):  # type: ignore[no-untyped-def]
    return github.create_pull_request(
        "example/project",
        title="Fix parser boundary",
        body="Fixes #42.",
        head="octocat:fix",
        expected_head_sha="a" * 40,
        expected_head_repository="octocat/project",
        base="main",
        expected_base_sha="c" * 40,
        draft=False,
    )


def test_create_pull_request_returns_canonical_success_details() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/repos/example/project/pulls"
        return httpx.Response(200, json=_pull_request_payload())

    with _client(handler) as github:
        details = _create_pull_request(github)

    assert details.html_url == "https://github.com/example/project/pull/7"
    assert details.repository == "example/project"
    assert details.number == 7
    assert details.head_sha == "a" * 40
    assert details.base_sha == "c" * 40


def test_create_pull_request_callback_can_block_before_post() -> None:
    requests: list[tuple[str, str]] = []
    callbacks: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append((request.method, request.url.path))
        return httpx.Response(200, json=_pull_request_payload())

    def block_creation() -> None:
        callbacks.append("called")
        raise RuntimeError("stop before pull-request creation")

    with (
        _client(handler) as github,
        pytest.raises(RuntimeError, match="stop before pull-request creation"),
    ):
        github.create_pull_request(
            "example/project",
            title="Fix parser boundary",
            body="Fixes #42.",
            head="octocat:fix",
            expected_head_sha="a" * 40,
            expected_head_repository="octocat/project",
            base="main",
            expected_base_sha="c" * 40,
            draft=False,
            before_mutation=block_creation,
        )

    assert callbacks == ["called"]
    assert requests == []


def test_create_pull_request_accepts_exact_ghes_url_with_custom_port() -> None:
    api_url = "https://git.example.com:8443/api/v3"
    expected_url = "https://git.example.com:8443/example/project/pull/7"

    def handler(request: httpx.Request) -> httpx.Response:
        payload = _pull_request_payload()
        payload["html_url"] = expected_url
        return httpx.Response(200, json=payload)

    with _client(handler, api_url=api_url) as github:
        details = _create_pull_request(github)

    assert details.html_url == expected_url


def test_create_pull_request_rejects_ghes_url_without_configured_port() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        payload = _pull_request_payload()
        payload["html_url"] = "https://git.example.com/example/project/pull/7"
        return httpx.Response(200, json=payload)

    with (
        _client(
            handler,
            api_url="https://git.example.com:8443/api/v3",
        ) as github,
        pytest.raises(GitHubError, match="noncanonical"),
    ):
        _create_pull_request(github)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("draft", True),
        ("title", "Different title"),
        ("body", "Different body"),
    ],
)
def test_create_pull_request_returns_semantically_mismatched_response_for_durable_validation(
    field: str, value: object
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        payload = _pull_request_payload()
        payload[field] = value
        return httpx.Response(200, json=payload)

    with _client(handler) as github:
        details = _create_pull_request(github)

    assert details.html_url == "https://github.com/example/project/pull/7"
    assert getattr(details, field) == value


@pytest.mark.parametrize(
    ("url", "message"),
    [
        ("https://github.com/example/project/pull/8", "different number"),
        ("https://attacker.invalid/example/project/pull/7", "noncanonical"),
    ],
)
def test_create_pull_request_rejects_noncanonical_identity_url(url: str, message: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        payload = _pull_request_payload()
        payload["html_url"] = url
        return httpx.Response(200, json=payload)

    with _client(handler) as github, pytest.raises(GitHubError, match=message):
        _create_pull_request(github)


@pytest.mark.parametrize(
    ("nested", "field", "value", "attribute"),
    [
        ("base", "ref", "develop", "base_ref"),
        ("head", "ref", "other", "head_ref"),
        ("head", "label", "octocat:other", "head_label"),
        ("head", "sha", "b" * 40, "head_sha"),
        ("head.repo", "full_name", "other/project", "head_repository"),
        ("base", "sha", "d" * 40, "base_sha"),
    ],
)
def test_create_pull_request_returns_nested_drift_for_durable_validation(
    nested: str, field: str, value: object, attribute: str
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        payload = _pull_request_payload()
        if nested in {"base.repo", "head.repo"}:
            parent = payload[nested.split(".", 1)[0]]
            assert isinstance(parent, dict)
            target = parent["repo"]
        else:
            target = payload[nested]
        assert isinstance(target, dict)
        target[field] = value
        return httpx.Response(200, json=payload)

    with _client(handler) as github:
        details = _create_pull_request(github)

    assert details.html_url == "https://github.com/example/project/pull/7"
    assert getattr(details, attribute) == value


def test_create_pull_request_rejects_different_base_repository() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        payload = _pull_request_payload()
        base = payload["base"]
        assert isinstance(base, dict)
        repository = base["repo"]
        assert isinstance(repository, dict)
        repository["full_name"] = "other/project"
        return httpx.Response(200, json=payload)

    with _client(handler) as github, pytest.raises(GitHubError, match="different repository"):
        _create_pull_request(github)


def test_create_pull_request_rejects_malformed_success_mapping() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[])

    with _client(handler) as github, pytest.raises(GitHubError, match="malformed created"):
        _create_pull_request(github)


def test_create_pull_request_returns_closed_success_response_for_reconciliation() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_pull_request_payload(merged=True))

    with _client(handler) as github:
        details = _create_pull_request(github)

    assert details.state == "closed"
    assert details.merged


def test_mark_pull_request_ready_for_review_uses_exact_graphql_identity() -> None:
    requests: list[tuple[str, str]] = []
    get_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal get_count
        requests.append((request.method, request.url.path))
        if request.method == "GET":
            get_count += 1
            return httpx.Response(
                200,
                json=_pull_request_payload(draft=get_count <= 2),
            )
        assert request.url.path == "/graphql"
        body = request.read().decode("utf-8")
        assert "PR_fixture_node_7" in body
        return httpx.Response(
            200,
            json={
                "data": {
                    "markPullRequestReadyForReview": {
                        "pullRequest": {
                            "id": "PR_fixture_node_7",
                            "number": 7,
                            "url": "https://github.com/example/project/pull/7",
                            "isDraft": False,
                            "headRefOid": "a" * 40,
                        }
                    }
                }
            },
        )

    with _client(handler) as github:
        details = github.mark_pull_request_ready_for_review(
            "example/project",
            7,
            expected_url="https://github.com/example/project/pull/7",
            expected_node_id="PR_fixture_node_7",
            expected_head_repository="octocat/project",
            expected_head_ref="fix",
            expected_head_sha="a" * 40,
        )

    assert not details.draft
    assert requests == [
        ("GET", "/repos/example/project/pulls/7"),
        ("GET", "/repos/example/project/pulls/7"),
        ("POST", "/graphql"),
        ("GET", "/repos/example/project/pulls/7"),
    ]


def test_ready_for_review_local_callback_runs_after_final_get_and_before_graphql() -> None:
    requests: list[tuple[str, str]] = []
    callbacks: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append((request.method, request.url.path))
        assert request.method == "GET"
        return httpx.Response(200, json=_pull_request_payload(draft=True))

    def block_mutation() -> None:
        callbacks.append("called")
        raise RuntimeError("stop before ready-for-review mutation")

    with (
        _client(handler) as github,
        pytest.raises(RuntimeError, match="stop before ready-for-review mutation"),
    ):
        github.mark_pull_request_ready_for_review(
            "example/project",
            7,
            expected_url="https://github.com/example/project/pull/7",
            expected_node_id="PR_fixture_node_7",
            expected_head_repository="octocat/project",
            expected_head_ref="fix",
            expected_head_sha="a" * 40,
            before_mutation=block_mutation,
        )

    assert callbacks == ["called"]
    assert requests == [
        ("GET", "/repos/example/project/pulls/7"),
        ("GET", "/repos/example/project/pulls/7"),
    ]


def test_ready_for_review_returns_when_exact_pull_request_became_ready_after_callback() -> None:
    requests: list[tuple[str, str]] = []
    callback_ran = False

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append((request.method, request.url.path))
        assert request.method == "GET"
        return httpx.Response(200, json=_pull_request_payload(draft=not callback_ran))

    def concurrent_ready_transition() -> None:
        nonlocal callback_ran
        callback_ran = True

    with _client(handler) as github:
        details = github.mark_pull_request_ready_for_review(
            "example/project",
            7,
            expected_url="https://github.com/example/project/pull/7",
            expected_node_id="PR_fixture_node_7",
            expected_head_repository="octocat/project",
            expected_head_ref="fix",
            expected_head_sha="a" * 40,
            before_observation=concurrent_ready_transition,
        )

    assert callback_ran
    assert not details.draft
    assert requests == [
        ("GET", "/repos/example/project/pulls/7"),
        ("GET", "/repos/example/project/pulls/7"),
    ]


@pytest.mark.parametrize(
    ("drift", "message"),
    [
        ("node", "different pull-request node"),
        ("head", "different head commit"),
    ],
)
def test_ready_for_review_rechecks_exact_identity_after_callback(
    drift: str,
    message: str,
) -> None:
    requests: list[tuple[str, str]] = []
    callback_ran = False

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append((request.method, request.url.path))
        assert request.method == "GET"
        payload = _pull_request_payload(draft=True)
        if callback_ran and drift == "node":
            payload["node_id"] = "PR_replaced_after_callback"
        elif callback_ran:
            head = payload["head"]
            assert isinstance(head, dict)
            head["sha"] = "d" * 40
        return httpx.Response(200, json=payload)

    def repository_identity_check() -> None:
        nonlocal callback_ran
        callback_ran = True

    with _client(handler) as github, pytest.raises(GitHubError, match=message):
        github.mark_pull_request_ready_for_review(
            "example/project",
            7,
            expected_url="https://github.com/example/project/pull/7",
            expected_node_id="PR_fixture_node_7",
            expected_head_repository="octocat/project",
            expected_head_ref="fix",
            expected_head_sha="a" * 40,
            before_observation=repository_identity_check,
        )

    assert requests == [
        ("GET", "/repos/example/project/pulls/7"),
        ("GET", "/repos/example/project/pulls/7"),
    ]


def test_ready_for_review_rechecks_authority_at_final_dispatch_boundary() -> None:
    requests: list[tuple[str, str]] = []
    final_identity_read_completed = False
    callbacks: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal final_identity_read_completed
        requests.append((request.method, request.url.path))
        assert request.method == "GET"
        if len(requests) == 2:
            final_identity_read_completed = True
        return httpx.Response(200, json=_pull_request_payload(draft=True))

    def remote_preflight() -> None:
        callbacks.append("remote preflight")

    def local_authority_check() -> None:
        callbacks.append("local authority")
        if final_identity_read_completed:
            raise RuntimeError("authority changed during final pull-request read")

    with (
        _client(handler) as github,
        pytest.raises(RuntimeError, match="authority changed during final"),
    ):
        github.mark_pull_request_ready_for_review(
            "example/project",
            7,
            expected_url="https://github.com/example/project/pull/7",
            expected_node_id="PR_fixture_node_7",
            expected_head_repository="octocat/project",
            expected_head_ref="fix",
            expected_head_sha="a" * 40,
            before_observation=remote_preflight,
            before_mutation=local_authority_check,
        )

    assert callbacks == ["remote preflight", "local authority"]
    assert requests == [
        ("GET", "/repos/example/project/pulls/7"),
        ("GET", "/repos/example/project/pulls/7"),
    ]


@pytest.mark.parametrize("concurrent_state", ["closed", "merged"])
def test_ready_for_review_rejects_terminal_state_after_callback(
    concurrent_state: str,
) -> None:
    requests: list[tuple[str, str]] = []
    callback_ran = False

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append((request.method, request.url.path))
        assert request.method == "GET"
        payload = _pull_request_payload(
            draft=True,
            merged=callback_ran and concurrent_state == "merged",
        )
        if callback_ran and concurrent_state == "closed":
            payload["state"] = "closed"
            payload["closed_at"] = "2026-07-21T13:01:00Z"
        return httpx.Response(200, json=payload)

    def terminal_transition() -> None:
        nonlocal callback_ran
        callback_ran = True

    with _client(handler) as github, pytest.raises(GitHubError, match="state changed"):
        github.mark_pull_request_ready_for_review(
            "example/project",
            7,
            expected_url="https://github.com/example/project/pull/7",
            expected_node_id="PR_fixture_node_7",
            expected_head_repository="octocat/project",
            expected_head_ref="fix",
            expected_head_sha="a" * 40,
            before_observation=terminal_transition,
        )

    assert requests == [
        ("GET", "/repos/example/project/pulls/7"),
        ("GET", "/repos/example/project/pulls/7"),
    ]


def test_mark_pull_request_ready_for_review_is_idempotent_when_already_ready() -> None:
    methods: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        methods.append(request.method)
        return httpx.Response(200, json=_pull_request_payload())

    with _client(handler) as github:
        details = github.mark_pull_request_ready_for_review(
            "example/project",
            7,
            expected_url="https://github.com/example/project/pull/7",
            expected_node_id="PR_fixture_node_7",
            expected_head_repository="octocat/project",
            expected_head_ref="fix",
            expected_head_sha="a" * 40,
        )

    assert not details.draft
    assert methods == ["GET"]


def test_mark_pull_request_ready_for_review_uses_ghes_graphql_path() -> None:
    paths: list[str] = []
    get_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal get_count
        paths.append(request.url.path)
        if request.method == "GET":
            get_count += 1
            payload = _pull_request_payload(draft=get_count <= 2)
            payload["html_url"] = "https://git.example.com/example/project/pull/7"
            return httpx.Response(200, json=payload)
        return httpx.Response(
            200,
            json={
                "data": {
                    "markPullRequestReadyForReview": {
                        "pullRequest": {
                            "id": "PR_fixture_node_7",
                            "number": 7,
                            "url": "https://git.example.com/example/project/pull/7",
                            "isDraft": False,
                            "headRefOid": "a" * 40,
                        }
                    }
                }
            },
        )

    with _client(handler, api_url="https://git.example.com/api/v3") as github:
        github.mark_pull_request_ready_for_review(
            "example/project",
            7,
            expected_url="https://git.example.com/example/project/pull/7",
            expected_node_id="PR_fixture_node_7",
            expected_head_repository="octocat/project",
            expected_head_ref="fix",
            expected_head_sha="a" * 40,
        )

    assert paths == [
        "/api/v3/repos/example/project/pulls/7",
        "/api/v3/repos/example/project/pulls/7",
        "/api/graphql",
        "/api/v3/repos/example/project/pulls/7",
    ]


def test_close_pull_request_uses_immutable_node_and_confirms_identity() -> None:
    requests: list[tuple[str, str]] = []
    get_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal get_count
        requests.append((request.method, request.url.path))
        if request.method == "GET":
            get_count += 1
            payload = _pull_request_payload()
            if get_count == 3:
                payload["state"] = "closed"
                payload["closed_at"] = "2026-07-21T13:01:00Z"
            return httpx.Response(200, json=payload)
        assert request.url.path == "/graphql"
        body = request.read().decode("utf-8")
        assert "closePullRequest" in body
        assert "PR_fixture_node_7" in body
        return httpx.Response(
            200,
            json={
                "data": {
                    "closePullRequest": {
                        "pullRequest": {
                            "id": "PR_fixture_node_7",
                            "number": 7,
                            "url": "https://github.com/example/project/pull/7",
                            "state": "CLOSED",
                            "merged": False,
                            "headRefOid": "a" * 40,
                        }
                    }
                }
            },
        )

    with _client(handler) as github:
        closed = github.close_pull_request(
            "example/project",
            7,
            expected_node_id="PR_fixture_node_7",
            expected_head_repository="octocat/project",
            expected_head_ref="fix",
            expected_head_sha="a" * 40,
        )

    assert requests == [
        ("GET", "/repos/example/project/pulls/7"),
        ("GET", "/repos/example/project/pulls/7"),
        ("POST", "/graphql"),
        ("GET", "/repos/example/project/pulls/7"),
    ]
    assert closed.state == "closed"
    assert not closed.merged


def test_close_pull_request_refuses_head_drift_without_mutation() -> None:
    methods: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        methods.append(request.method)
        payload = _pull_request_payload()
        head = payload["head"]
        assert isinstance(head, dict)
        head["sha"] = "d" * 40
        return httpx.Response(200, json=payload)

    with _client(handler) as github, pytest.raises(GitHubError, match="different head commit"):
        github.close_pull_request(
            "example/project",
            7,
            expected_node_id="PR_fixture_node_7",
            expected_head_repository="octocat/project",
            expected_head_ref="fix",
            expected_head_sha="a" * 40,
        )

    assert methods == ["GET"]


def test_close_pull_request_refuses_node_drift_without_mutation() -> None:
    methods: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        methods.append(request.method)
        payload = _pull_request_payload()
        payload["node_id"] = "PR_different_node"
        return httpx.Response(200, json=payload)

    with _client(handler) as github, pytest.raises(GitHubError, match="different pull-request"):
        github.close_pull_request(
            "example/project",
            7,
            expected_node_id="PR_fixture_node_7",
            expected_head_repository="octocat/project",
            expected_head_ref="fix",
            expected_head_sha="a" * 40,
        )

    assert methods == ["GET"]


def test_close_pull_request_rechecks_node_after_repository_identity_callback() -> None:
    methods: list[str] = []
    callback_ran = False

    def handler(request: httpx.Request) -> httpx.Response:
        methods.append(request.method)
        payload = _pull_request_payload()
        if callback_ran:
            payload["node_id"] = "PR_replaced_after_callback"
        return httpx.Response(200, json=payload)

    def repository_identity_check() -> None:
        nonlocal callback_ran
        callback_ran = True

    with _client(handler) as github, pytest.raises(GitHubError, match="different pull-request"):
        github.close_pull_request(
            "example/project",
            7,
            expected_node_id="PR_fixture_node_7",
            expected_head_repository="octocat/project",
            expected_head_ref="fix",
            expected_head_sha="a" * 40,
            before_observation=repository_identity_check,
        )

    assert methods == ["GET", "GET"]


def test_close_pull_request_rechecks_authority_at_final_dispatch_boundary() -> None:
    requests: list[tuple[str, str]] = []
    final_identity_read_completed = False
    callbacks: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal final_identity_read_completed
        requests.append((request.method, request.url.path))
        assert request.method == "GET"
        if len(requests) == 2:
            final_identity_read_completed = True
        return httpx.Response(200, json=_pull_request_payload())

    def remote_preflight() -> None:
        callbacks.append("remote preflight")

    def local_authority_check() -> None:
        callbacks.append("local authority")
        if final_identity_read_completed:
            raise RuntimeError("authority changed during final pull-request read")

    with (
        _client(handler) as github,
        pytest.raises(RuntimeError, match="authority changed during final"),
    ):
        github.close_pull_request(
            "example/project",
            7,
            expected_node_id="PR_fixture_node_7",
            expected_head_repository="octocat/project",
            expected_head_ref="fix",
            expected_head_sha="a" * 40,
            before_observation=remote_preflight,
            before_mutation=local_authority_check,
        )

    assert callbacks == ["remote preflight", "local authority"]
    assert requests == [
        ("GET", "/repos/example/project/pulls/7"),
        ("GET", "/repos/example/project/pulls/7"),
    ]
