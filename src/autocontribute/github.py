"""Narrow GitHub API client with read operations separated from publication."""

from __future__ import annotations

import base64
import os
import subprocess
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any, cast
from urllib.parse import quote, urljoin, urlparse

import httpx

from autocontribute.config import GitHubConfig
from autocontribute.domain import IssueCandidate, IssueComment, RepositoryInfo
from autocontribute.exceptions import ConfigurationError, GitHubError


def resolve_github_token(config: GitHubConfig) -> str:
    """Resolve a token at the last possible moment without logging it."""

    token = os.environ.get(config.token_env)
    if token:
        return token
    if config.auth == "token" and not token:
        raise ConfigurationError(
            f"GitHub credential is missing; set environment variable {config.token_env}"
        )
    try:
        environment = {"PATH": os.environ.get("PATH", "")}
        for name in ("HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "GH_HOST", "GH_CONFIG_DIR"):
            value = os.environ.get(name)
            if value:
                environment[name] = value
        result = subprocess.run(
            ["gh", "auth", "token"],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ConfigurationError("Could not invoke `gh auth token`; run `gh auth login`") from exc
    token = result.stdout.strip()
    if result.returncode != 0 or not token:
        raise ConfigurationError("GitHub CLI is not authenticated; run `gh auth login`")
    return token


class GitHubClient:
    """A small REST client; mutation methods are called only by Publisher."""

    def __init__(self, config: GitHubConfig, *, token: str | None = None) -> None:
        self.config = config
        self._token = token or resolve_github_token(config)
        self._client = httpx.Client(
            base_url=str(config.api_url).rstrip("/"),
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "autocontribute/0.1",
            },
            timeout=30,
            follow_redirects=False,
        )

    @property
    def token(self) -> str:
        """Credential broker access for an approved git push only."""

        return self._token

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> GitHubClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str | int] | None = None,
        json_body: dict[str, object] | None = None,
        allow_not_found: bool = False,
    ) -> Any:
        try:
            response = self._client.request(method, path, params=params, json=json_body)
        except httpx.HTTPError as exc:
            raise GitHubError(f"GitHub request failed: {method} {path}: {exc}") from exc
        if response.status_code in {301, 302, 307, 308}:
            location = response.headers.get("Location")
            target = urljoin(str(response.request.url), location or "")
            configured = urlparse(str(self.config.api_url))
            redirected = urlparse(target)
            if (
                method != "GET"
                or not location
                or redirected.scheme != "https"
                or redirected.netloc != configured.netloc
            ):
                raise GitHubError("GitHub returned an unsafe redirect; request was stopped")
            try:
                response = self._client.request("GET", target, params=params)
            except httpx.HTTPError as exc:
                raise GitHubError(f"GitHub redirected request failed: GET {path}: {exc}") from exc
        if response.status_code == 404 and allow_not_found:
            return None
        if response.status_code in {403, 429}:
            retry_after = response.headers.get("Retry-After")
            remaining = response.headers.get("X-RateLimit-Remaining")
            raise GitHubError(
                "GitHub paused this account or exhausted its rate limit; "
                f"retry_after={retry_after!r}, remaining={remaining!r}. The run was stopped."
            )
        if not 200 <= response.status_code < 300:
            request_id = response.headers.get("X-GitHub-Request-Id", "unknown")
            message = ""
            try:
                payload = response.json()
                message = str(payload.get("message", "")) if isinstance(payload, dict) else ""
            except ValueError:
                pass
            raise GitHubError(
                f"GitHub returned {response.status_code} for {method} {path} "
                f"(request {request_id}): {message}"
            )
        if response.status_code == 204:
            return None
        try:
            return response.json()
        except ValueError as exc:
            raise GitHubError(f"GitHub returned invalid JSON for {method} {path}") from exc

    def authenticated_login(self) -> str:
        data = cast("dict[str, Any]", self._request("GET", "/user"))
        return str(data["login"])

    def get_repository(self, full_name: str) -> RepositoryInfo:
        data = cast("dict[str, Any]", self._request("GET", f"/repos/{quote(full_name, safe='/')}"))
        license_data = data.get("license") or {}
        return RepositoryInfo(
            full_name=str(data["full_name"]),
            html_url=str(data["html_url"]),
            clone_url=str(data["clone_url"]),
            default_branch=str(data["default_branch"]),
            stars=int(data.get("stargazers_count", 0)),
            archived=bool(data.get("archived", False)),
            disabled=bool(data.get("disabled", False)),
            private=bool(data.get("private", False)),
            pushed_at=_parse_datetime(data.get("pushed_at")),
            license_spdx=(
                str(license_data["spdx_id"])
                if license_data.get("spdx_id") not in {None, "NOASSERTION"}
                else None
            ),
        )

    def list_owner_repositories(self, owner: str, *, limit: int) -> list[RepositoryInfo]:
        params: dict[str, str | int] = {
            "sort": "pushed",
            "direction": "desc",
            "type": "public",
            "per_page": min(limit, 100),
        }
        data = self._request(
            "GET", f"/orgs/{quote(owner)}/repos", params=params, allow_not_found=True
        )
        if data is None:
            data = self._request("GET", f"/users/{quote(owner)}/repos", params=params)
        repositories = []
        for item in cast("list[dict[str, Any]]", data)[:limit]:
            repositories.append(self.get_repository(str(item["full_name"])))
        return repositories

    def get_issue(self, repository: str, number: int) -> IssueCandidate:
        data = cast(
            "dict[str, Any]",
            self._request("GET", f"/repos/{quote(repository, safe='/')}/issues/{number}"),
        )
        if "pull_request" in data:
            raise GitHubError(f"{repository}#{number} is a pull request, not an issue")
        issue = _parse_issue(data, repository)
        if issue.comments:
            issue.discussion = self.get_issue_comments(
                issue.repository,
                issue.number,
                expected_count=issue.comments,
            )
        return issue

    def get_issue_comments(
        self,
        repository: str,
        number: int,
        *,
        expected_count: int | None = None,
        max_comments: int = 500,
    ) -> list[IssueComment]:
        """Fetch the complete bounded issue discussion or fail closed when it is too large."""

        if max_comments < 1 or max_comments > 1_000:
            raise ValueError("max_comments must be between 1 and 1,000")
        if expected_count is not None and expected_count > max_comments:
            raise GitHubError(
                f"Issue has {expected_count} comments, above the safe discussion limit "
                f"of {max_comments}; candidate review is incomplete"
            )

        comments: list[IssueComment] = []
        pages = (max_comments + 99) // 100
        for page in range(1, pages + 1):
            data = cast(
                "list[dict[str, Any]]",
                self._request(
                    "GET",
                    f"/repos/{quote(repository, safe='/')}/issues/{number}/comments",
                    params={"per_page": 100, "page": page},
                ),
            )
            comments.extend(_parse_issue_comment(item) for item in data)
            if len(comments) > max_comments:
                raise GitHubError("Issue discussion exceeded the safe comment limit")
            if len(data) < 100:
                break
            if expected_count is not None and len(comments) >= expected_count:
                break
        else:
            if expected_count is None or len(comments) < expected_count:
                raise GitHubError(
                    "Issue discussion reached the pagination limit; candidate review is incomplete"
                )

        if expected_count is not None and len(comments) != expected_count:
            raise GitHubError(
                "Issue comment count changed while it was fetched; retry before selecting it"
            )
        return comments

    def search_issues(
        self, repository: str, *, labels: Iterable[str], limit: int
    ) -> list[IssueCandidate]:
        results: dict[int, IssueCandidate] = {}
        for label in labels:
            query = f'repo:{repository} is:issue is:open label:"{label}"'
            data = cast(
                "dict[str, Any]",
                self._request(
                    "GET",
                    "/search/issues",
                    params={
                        "q": query,
                        "sort": "updated",
                        "order": "desc",
                        "per_page": min(limit, 100),
                    },
                ),
            )
            for item in cast("list[dict[str, Any]]", data.get("items", [])):
                issue = _parse_issue(item, repository)
                results[issue.number] = issue
                if len(results) >= limit:
                    break
            if len(results) >= limit:
                break
        return list(results.values())

    def search_competing_pull_requests(self, repository: str, issue_number: int) -> list[str]:
        pull_requests: set[str] = set()
        for page in range(1, 11):
            data = cast(
                "list[dict[str, Any]]",
                self._request(
                    "GET",
                    f"/repos/{quote(repository, safe='/')}/issues/{issue_number}/timeline",
                    params={"per_page": 100, "page": page},
                ),
            )
            for event in data:
                source_issue = (event.get("source") or {}).get("issue") or {}
                if source_issue.get("pull_request") and source_issue.get("state") == "open":
                    url = source_issue.get("html_url")
                    if url:
                        pull_requests.add(str(url))
            if pull_requests or len(data) < 100:
                return sorted(pull_requests)
        raise GitHubError(
            "Issue timeline exceeded 1,000 events; duplicate pull-request status is ambiguous"
        )

    def authored_pull_requests(
        self,
        login: str,
        *,
        state: str = "open",
        repository: str | None = None,
        updated_after: str | None = None,
        created_after: str | None = None,
    ) -> list[str]:
        qualifiers = ["is:pr", f"is:{state}", f"author:{login}"]
        if repository:
            qualifiers.append(f"repo:{repository}")
        if updated_after:
            qualifiers.append(f"updated:>={updated_after}")
        if created_after:
            qualifiers.append(f"created:>={created_after}")
        data = cast(
            "dict[str, Any]",
            self._request(
                "GET",
                "/search/issues",
                params={"q": " ".join(qualifiers), "sort": "updated", "per_page": 100},
            ),
        )
        return [str(item["html_url"]) for item in data.get("items", [])]

    def get_file(self, repository: str, path: str, *, ref: str | None = None) -> str | None:
        encoded_path = quote(path.strip("/"), safe="/")
        params: dict[str, str | int] | None = {"ref": ref} if ref else None
        data = self._request(
            "GET",
            f"/repos/{quote(repository, safe='/')}/contents/{encoded_path}",
            params=params,
            allow_not_found=True,
        )
        if data is None:
            return None
        if not isinstance(data, dict) or data.get("type") != "file":
            return None
        if data.get("encoding") != "base64":
            return None
        try:
            return base64.b64decode(str(data["content"]), validate=False).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None

    def default_branch_sha(self, repository: str, branch: str) -> str:
        data = cast(
            "dict[str, Any]",
            self._request(
                "GET",
                f"/repos/{quote(repository, safe='/')}/git/ref/heads/{quote(branch, safe='')}",
            ),
        )
        return str(data["object"]["sha"])

    def ref_sha(self, repository: str, ref: str) -> str | None:
        data = self._request(
            "GET",
            f"/repos/{quote(repository, safe='/')}/git/ref/{quote(ref, safe='/')}",
            allow_not_found=True,
        )
        if data is None:
            return None
        return str(cast("dict[str, Any]", data)["object"]["sha"])

    def find_pull_request(self, repository: str, *, head: str) -> str | None:
        data = cast(
            "list[dict[str, Any]]",
            self._request(
                "GET",
                f"/repos/{quote(repository, safe='/')}/pulls",
                params={"state": "all", "head": head, "per_page": 10},
            ),
        )
        return str(data[0]["html_url"]) if data else None

    def ensure_fork(self, repository: str, login: str) -> str:
        name = repository.split("/", 1)[1]
        fork_name = f"{login}/{name}"
        existing = self._request(
            "GET", f"/repos/{quote(fork_name, safe='/')}", allow_not_found=True
        )
        if existing is None:
            self._request("POST", f"/repos/{quote(repository, safe='/')}/forks", json_body={})
        else:
            existing_data = cast("dict[str, Any]", existing)
            parent = existing_data.get("parent") or {}
            if not existing_data.get("fork") or str(parent.get("full_name")) != repository:
                raise GitHubError(f"{fork_name} already exists but is not a fork of {repository}")
        return fork_name

    def create_pull_request(
        self,
        repository: str,
        *,
        title: str,
        body: str,
        head: str,
        base: str,
        draft: bool,
    ) -> str:
        data = cast(
            "dict[str, Any]",
            self._request(
                "POST",
                f"/repos/{quote(repository, safe='/')}/pulls",
                json_body={
                    "title": title,
                    "body": body,
                    "head": head,
                    "base": base,
                    "draft": draft,
                    "maintainer_can_modify": True,
                },
            ),
        )
        return str(data["html_url"])


def _parse_datetime(value: object) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _parse_issue(data: dict[str, Any], repository: str) -> IssueCandidate:
    repository_url = str(data.get("repository_url") or "")
    marker = "/repos/"
    if marker in repository_url:
        canonical = repository_url.split(marker, 1)[1]
        if canonical.count("/") == 1:
            repository = canonical
    return IssueCandidate(
        repository=repository,
        number=int(data["number"]),
        title=str(data.get("title") or ""),
        body=str(data.get("body") or ""),
        html_url=str(data["html_url"]),
        state=str(data["state"]),
        author=str((data.get("user") or {}).get("login") or "unknown"),
        labels=[str(label.get("name") or "") for label in data.get("labels", [])],
        assignees=[str(user.get("login") or "") for user in data.get("assignees", [])],
        comments=int(data.get("comments", 0)),
        created_at=_parse_datetime(data.get("created_at")) or datetime.min.replace(tzinfo=UTC),
        updated_at=_parse_datetime(data.get("updated_at")) or datetime.min.replace(tzinfo=UTC),
    )


def _parse_issue_comment(data: dict[str, Any]) -> IssueComment:
    return IssueComment(
        author=str((data.get("user") or {}).get("login") or "unknown"),
        author_association=str(data.get("author_association") or "NONE").upper(),
        body=str(data.get("body") or ""),
        html_url=str(data.get("html_url") or ""),
        created_at=_parse_datetime(data.get("created_at")) or datetime.min.replace(tzinfo=UTC),
        updated_at=_parse_datetime(data.get("updated_at")) or datetime.min.replace(tzinfo=UTC),
    )


__all__ = ["GitHubClient", "resolve_github_token"]
