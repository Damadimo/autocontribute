"""Narrow GitHub API client with read operations separated from publication."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime
from typing import Any, Protocol, TypeVar, cast
from urllib.parse import quote, urljoin, urlparse

import httpx

from autocontribute.config import GitHubConfig
from autocontribute.domain import IssueCandidate, IssueComment, RepositoryInfo
from autocontribute.exceptions import (
    CircuitBreakerTrigger,
    ConfigurationError,
    GitHubError,
    GitHubSafetyError,
)
from autocontribute.github_origin import canonical_api_origin, web_origin_for_api


class _Identified(Protocol):
    @property
    def identifier(self) -> int: ...


IdentifiedT = TypeVar("IdentifiedT", bound=_Identified)

_AUTHOR_ASSOCIATIONS = frozenset(
    {
        "COLLABORATOR",
        "CONTRIBUTOR",
        "FIRST_TIMER",
        "FIRST_TIME_CONTRIBUTOR",
        "MANNEQUIN",
        "MEMBER",
        "NONE",
        "OWNER",
    }
)
_CHECK_CONCLUSIONS = frozenset(
    {
        "action_required",
        "cancelled",
        "failure",
        "neutral",
        "skipped",
        "stale",
        "startup_failure",
        "success",
        "timed_out",
    }
)
_AUTHORED_PULL_REQUEST_LIMIT = 100
_GITHUB_LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_GIT_SHA = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_REPOSITORY_NAME = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_ABUSE_WARNING = re.compile(r"(?:abuse detection|secondary rate limit|temporarily blocked)", re.I)

SafetyTriggerHandler = Callable[[CircuitBreakerTrigger], object]


@dataclass(frozen=True, slots=True)
class PullRequestDetails:
    repository: str
    number: int
    html_url: str
    state: str
    draft: bool
    merged: bool
    updated_at: datetime
    merged_at: datetime | None
    closed_at: datetime | None
    merge_commit_sha: str | None
    head_sha: str
    base_sha: str
    head_repository: str
    issue_comment_count: int
    review_comment_count: int
    title: str = ""
    body: str = ""
    base_ref: str = ""
    head_ref: str = ""
    head_label: str = ""


@dataclass(frozen=True, slots=True)
class PullRequestReview:
    identifier: int
    author: str
    author_association: str
    state: str
    body: str
    html_url: str
    submitted_at: datetime | None


@dataclass(frozen=True, slots=True)
class GitHubComment:
    identifier: int
    author: str
    author_association: str
    body: str
    html_url: str
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class CheckRunDetails:
    identifier: int
    name: str
    status: str
    conclusion: str | None
    details_url: str
    app_name: str
    started_at: datetime | None
    completed_at: datetime | None


@dataclass(frozen=True, slots=True)
class CommitStatusDetails:
    identifier: int
    context: str
    state: str
    description: str
    target_url: str
    creator: str
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class PullRequestReference:
    """One PR-to-PR timeline reference used only as explicit revert evidence."""

    identifier: int
    source_url: str
    source_title: str
    source_body: str
    source_state: str
    source_merged_at: datetime | None
    created_at: datetime


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
        cli_hostname = urlparse(web_origin_for_api(config.api_url)).netloc
        environment = {"PATH": os.environ.get("PATH", "")}
        for name in ("HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "GH_CONFIG_DIR"):
            value = os.environ.get(name)
            if value:
                environment[name] = value
        result = subprocess.run(
            ["gh", "auth", "token", "--hostname", cli_hostname],
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

    def __init__(
        self,
        config: GitHubConfig,
        *,
        token: str | None = None,
        safety_trigger_handler: SafetyTriggerHandler | None = None,
    ) -> None:
        self.config = config
        self._token = token or resolve_github_token(config)
        self._safety_trigger_handler = safety_trigger_handler
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

    @property
    def api_origin(self) -> str:
        """Canonical credential-free origin used to bind GitHub identities."""

        return canonical_api_origin(self.config.api_url)

    def close(self) -> None:
        self._client.close()

    def bind_safety_trigger_handler(self, handler: SafetyTriggerHandler) -> None:
        """Bind global-stop persistence when a higher-level service supplies durable state."""

        self._safety_trigger_handler = handler

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
        response_message = _response_message(response)
        is_abuse_warning = bool(_ABUSE_WARNING.search(response_message))
        if response.status_code == 404 and allow_not_found and not is_abuse_warning:
            return None
        if response.status_code in {403, 429} or (response.status_code >= 400 and is_abuse_warning):
            retry_after = response.headers.get("Retry-After")
            remaining = response.headers.get("X-RateLimit-Remaining")
            request_id = response.headers.get("X-GitHub-Request-Id")
            evidence = {
                "api_origin": self.api_origin,
                "method": method,
                "path": path,
                "request_id": request_id,
                "response_message": response_message[:1_000],
                "retry_after": retry_after,
                "status_code": response.status_code,
                "x_ratelimit_remaining": remaining,
            }
            trigger = CircuitBreakerTrigger(
                source="github_api:rate_or_abuse_limit",
                reason=(
                    "GitHub returned a rate-limit, abuse, or account-pause safety response "
                    f"({response.status_code} for {method} {path}; request "
                    f"{request_id or 'unknown'})."
                ),
                trigger_hash=hashlib.sha256(
                    json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest(),
            )
            if self._safety_trigger_handler is not None:
                self._safety_trigger_handler(trigger)
            raise GitHubSafetyError(
                "GitHub paused this account or exhausted its rate limit; "
                f"retry_after={retry_after!r}, remaining={remaining!r}. "
                "The global safety stop was activated.",
                trigger=trigger,
            )
        if not 200 <= response.status_code < 300:
            request_id = response.headers.get("X-GitHub-Request-Id", "unknown")
            raise GitHubError(
                f"GitHub returned {response.status_code} for {method} {path} "
                f"(request {request_id}): {response_message}"
            )
        if response.status_code == 204:
            return None
        try:
            return response.json()
        except ValueError as exc:
            raise GitHubError(f"GitHub returned invalid JSON for {method} {path}") from exc

    def _bounded_list(
        self,
        path: str,
        *,
        resource: str,
        max_items: int,
        params: dict[str, str | int] | None = None,
    ) -> list[dict[str, Any]]:
        """Read a complete REST collection or reject ambiguous/truncated evidence."""

        if not 1 <= max_items <= 1_000:
            raise ValueError(f"{resource} limit must be between 1 and 1,000")
        items: list[dict[str, Any]] = []
        base_params = dict(params or {})
        # One overflow page distinguishes an exact multiple of 100 from a truncated collection.
        maximum_pages = max_items // 100 + 1
        for page in range(1, maximum_pages + 1):
            request_params = {**base_params, "per_page": 100, "page": page}
            data = self._request("GET", path, params=request_params)
            page_items = _mapping_list(data, resource=resource)
            if len(page_items) > 100:
                raise GitHubError(f"GitHub returned an oversized {resource} page")
            if len(items) + len(page_items) > max_items:
                raise GitHubError(
                    f"{resource.capitalize()} exceeded the safe limit of {max_items}; "
                    "lifecycle evidence is incomplete"
                )
            items.extend(page_items)
            if len(page_items) < 100:
                return items
        raise GitHubError(
            f"{resource.capitalize()} reached the pagination limit; "
            "lifecycle evidence is incomplete"
        )

    def authenticated_login(self) -> str:
        data = cast("dict[str, Any]", self._request("GET", "/user"))
        return str(data["login"])

    def get_repository(self, full_name: str) -> RepositoryInfo:
        data = _mapping(
            self._request("GET", f"/repos/{quote(full_name, safe='/')}"),
            resource="repository",
        )
        canonical_name = _canonical_repository_name(data.get("full_name"))
        web_origin = web_origin_for_api(self.config.api_url)
        html_url = _exact_repository_url(
            data.get("html_url"),
            expected=f"{web_origin}/{canonical_name}",
            field="repository HTML URL",
        )
        clone_url = _exact_repository_url(
            data.get("clone_url"),
            expected=f"{web_origin}/{canonical_name}.git",
            field="repository clone URL",
        )
        license_data = data.get("license") or {}
        return RepositoryInfo(
            full_name=canonical_name,
            html_url=html_url,
            clone_url=clone_url,
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
        if expected_count is not None:
            _nonnegative_count(expected_count, field="expected issue comment count")
            if expected_count > max_comments:
                raise GitHubError(
                    f"Issue has {expected_count} comments, above the safe discussion limit "
                    f"of {max_comments}; candidate review is incomplete"
                )

        comments: list[IssueComment] = []
        # Always request an overflow page after a full page. Otherwise an advertised count of
        # exactly 100 can race with comment 101 and silently accept incomplete evidence.
        pages = max_comments // 100 + 1
        for page in range(1, pages + 1):
            data = _mapping_list(
                self._request(
                    "GET",
                    f"/repos/{quote(repository, safe='/')}/issues/{number}/comments",
                    params={"per_page": 100, "page": page},
                ),
                resource="issue comments",
            )
            if len(data) > 100:
                raise GitHubError("GitHub returned an oversized issue comments page")
            comments.extend(_parse_issue_comment(item) for item in data)
            if len(comments) > max_comments:
                raise GitHubError("Issue discussion exceeded the safe comment limit")
            if len(data) < 100:
                break
        else:
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

    def search_competing_pull_requests(
        self,
        repository: str,
        issue_number: int,
        *,
        max_search_results: int = 100,
    ) -> list[str]:
        """Find open linked PRs using complete timeline evidence plus bounded search."""

        normalized_number = _positive_issue_number(issue_number)
        if not 1 <= max_search_results <= 100:
            raise ValueError("competing pull-request search limit must be between 1 and 100")
        pull_requests: set[str] = set()
        for page in range(1, 11):
            data = _mapping_list(
                self._request(
                    "GET",
                    (f"/repos/{quote(repository, safe='/')}/issues/{normalized_number}/timeline"),
                    params={"per_page": 100, "page": page},
                ),
                resource="issue timeline events",
            )
            if len(data) > 100:
                raise GitHubError("GitHub returned an oversized issue timeline page")
            for event in data:
                if str(event.get("event") or "").casefold() != "cross-referenced":
                    continue
                source = event.get("source")
                if not isinstance(source, dict):
                    raise GitHubError("GitHub returned malformed issue cross-reference evidence")
                source_issue = source.get("issue")
                if not isinstance(source_issue, dict):
                    raise GitHubError("GitHub returned malformed issue cross-reference evidence")
                pull_request = source_issue.get("pull_request")
                if pull_request is None:
                    continue
                if not isinstance(pull_request, dict):
                    raise GitHubError("GitHub returned malformed pull-request cross-reference data")
                state = _nonempty(
                    source_issue.get("state"), field="cross-referenced pull request state"
                ).casefold()
                if state not in {"open", "closed"}:
                    raise GitHubError(
                        "GitHub returned an unsupported cross-referenced pull request state"
                    )
                if state == "open":
                    pull_requests.add(
                        _nonempty(
                            source_issue.get("html_url"),
                            field="cross-referenced pull request URL",
                        )
                    )
            if len(data) < 100:
                break
        else:
            raise GitHubError(
                "Issue timeline exceeded 1,000 events; duplicate pull-request status is ambiguous"
            )

        pull_requests.update(
            self._search_open_pull_requests_referencing_issue(
                repository,
                normalized_number,
                max_results=max_search_results,
            )
        )
        return sorted(pull_requests)

    def _search_open_pull_requests_referencing_issue(
        self,
        repository: str,
        issue_number: int,
        *,
        max_results: int,
    ) -> set[str]:
        if not 1 <= max_results <= 100:
            raise ValueError("competing pull-request search limit must be between 1 and 100")
        query = f"repo:{repository} is:pr is:open {issue_number} in:title,body"
        payload = _mapping(
            self._request(
                "GET",
                "/search/issues",
                params={
                    "q": query,
                    "sort": "updated",
                    "order": "desc",
                    "per_page": max_results,
                    "page": 1,
                },
            ),
            resource="competing pull request search",
        )
        incomplete = payload.get("incomplete_results")
        if not isinstance(incomplete, bool):
            raise GitHubError("GitHub returned malformed competing pull-request search metadata")
        if incomplete:
            raise GitHubError(
                "GitHub returned incomplete competing pull-request search results; "
                "duplicate status is ambiguous"
            )
        total = _nonnegative_count(
            payload.get("total_count"), field="competing pull request search total_count"
        )
        if total > max_results:
            raise GitHubError(
                f"Competing pull-request search found {total} candidates above the safe limit "
                f"of {max_results}; duplicate status is ambiguous"
            )
        items = _mapping_list(
            payload.get("items"), resource="competing pull request search results"
        )
        if len(items) != total:
            raise GitHubError(
                "GitHub returned a truncated competing pull-request search page; "
                "duplicate status is ambiguous"
            )

        matches: set[str] = set()
        for item in items:
            if not isinstance(item.get("pull_request"), dict):
                raise GitHubError("GitHub search returned a non-pull-request result")
            state = _nonempty(item.get("state"), field="searched pull request state").casefold()
            if state != "open":
                raise GitHubError("GitHub search returned a non-open pull request")
            title = _nonempty(item.get("title"), field="searched pull request title")
            body = _optional_string(item.get("body"), field="searched pull request body")
            if _explicit_issue_reference(f"{title}\n{body}", repository, issue_number):
                matches.add(_nonempty(item.get("html_url"), field="searched pull request URL"))
        return matches

    def authored_pull_requests(
        self,
        login: str,
        *,
        state: str = "open",
        repository: str | None = None,
        updated_after: str | None = None,
        created_after: str | None = None,
    ) -> list[str]:
        if not isinstance(state, str) or state not in {"open", "closed"}:
            raise ValueError("authored pull-request state must be 'open' or 'closed'")
        if not isinstance(login, str) or not _GITHUB_LOGIN.fullmatch(login):
            raise ValueError("GitHub login is not safe for an authored pull-request search")
        if repository is not None and (
            not isinstance(repository, str) or not _REPOSITORY_NAME.fullmatch(repository)
        ):
            raise ValueError("repository must use owner/name syntax")
        for value, field in (
            (updated_after, "updated_after"),
            (created_after, "created_after"),
        ):
            if value is not None:
                _canonical_date(value, field=field)

        qualifiers = ["is:pr", f"is:{state}", f"author:{login}"]
        if repository:
            qualifiers.append(f"repo:{repository}")
        if updated_after:
            qualifiers.append(f"updated:>={updated_after}")
        if created_after:
            qualifiers.append(f"created:>={created_after}")
        payload = _mapping(
            self._request(
                "GET",
                "/search/issues",
                params={
                    "q": " ".join(qualifiers),
                    "sort": "updated",
                    "per_page": _AUTHORED_PULL_REQUEST_LIMIT,
                    "page": 1,
                },
            ),
            resource="authored pull request search",
        )
        incomplete = payload.get("incomplete_results")
        if not isinstance(incomplete, bool):
            raise GitHubError("GitHub returned malformed authored pull-request search metadata")
        if incomplete:
            raise GitHubError(
                "GitHub returned incomplete authored pull-request search results; "
                "account publication limits are ambiguous"
            )
        total = _nonnegative_count(
            payload.get("total_count"), field="authored pull request search total_count"
        )
        if total > _AUTHORED_PULL_REQUEST_LIMIT:
            raise GitHubError(
                f"Authored pull-request search found {total} results above the one-page safe "
                f"limit of {_AUTHORED_PULL_REQUEST_LIMIT}; account publication limits are "
                "ambiguous"
            )
        items = _mapping_list(payload.get("items"), resource="authored pull request search results")
        if len(items) != total:
            raise GitHubError(
                "GitHub returned a truncated authored pull-request search page; "
                "account publication limits are ambiguous"
            )

        urls: list[str] = []
        identities: set[tuple[str, int]] = set()
        for item in items:
            number = _identifier(item.get("number"), resource="searched pull request")
            item_state = _nonempty(
                item.get("state"), field="searched pull request state"
            ).casefold()
            if item_state != state:
                raise GitHubError(
                    "GitHub authored search returned a pull request in a different state"
                )
            pull_request = _mapping(
                item.get("pull_request"), resource="authored search pull request identity"
            )
            html_url, item_repository = self._canonical_pull_request_url(
                item.get("html_url"),
                expected_repository=repository,
                expected_number=number,
            )
            self._require_canonical_api_url(
                item.get("repository_url"),
                path=f"/repos/{item_repository}",
                field="searched pull request repository URL",
            )
            self._require_canonical_api_url(
                item.get("url"),
                path=f"/repos/{item_repository}/issues/{number}",
                field="searched pull request issue API URL",
            )
            self._require_canonical_api_url(
                pull_request.get("url"),
                path=f"/repos/{item_repository}/pulls/{number}",
                field="searched pull request API URL",
            )
            identity = (item_repository.casefold(), number)
            if identity in identities:
                raise GitHubError("GitHub authored search returned a duplicate pull request")
            identities.add(identity)
            urls.append(html_url)
        return urls

    def get_file(
        self,
        repository: str,
        path: str,
        *,
        ref: str,
        max_bytes: int = 1_000_000,
    ) -> str | None:
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
            raise ValueError("max_bytes must be a positive integer")
        immutable_ref = _input_nonempty(ref, field="repository file ref").casefold()
        if not _GIT_SHA.fullmatch(immutable_ref):
            raise ValueError("repository file ref must be a full immutable git SHA")
        encoded_path = quote(path.strip("/"), safe="/")
        data = self._request(
            "GET",
            f"/repos/{quote(repository, safe='/')}/contents/{encoded_path}",
            params={"ref": immutable_ref},
            allow_not_found=True,
        )
        if data is None:
            return None
        if not isinstance(data, dict) or data.get("type") != "file":
            raise GitHubError(
                f"GitHub policy path is present but is not a readable file: {repository}/{path}"
            )
        if data.get("encoding") != "base64":
            raise GitHubError(
                f"GitHub policy file uses an unsupported encoding: {repository}/{path}"
            )
        try:
            declared_size = data["size"]
            if (
                isinstance(declared_size, bool)
                or not isinstance(declared_size, int)
                or declared_size < 0
            ):
                raise ValueError("size is not a nonnegative integer")
            if declared_size > max_bytes:
                raise GitHubError(
                    f"GitHub policy file exceeds the {max_bytes}-byte safety limit: "
                    f"{repository}/{path}"
                )
            encoded = data["content"]
            if not isinstance(encoded, str):
                raise ValueError("content is not text")
            maximum_encoded = 4 * ((max_bytes + 2) // 3)
            maximum_wire_characters = maximum_encoded + maximum_encoded // 16 + 128
            if len(encoded) > maximum_wire_characters:
                raise GitHubError(
                    f"GitHub policy file exceeds the {max_bytes}-byte safety limit: "
                    f"{repository}/{path}"
                )
            compact = "".join(encoded.split())
            if len(compact) > maximum_encoded:
                raise GitHubError(
                    f"GitHub policy file exceeds the {max_bytes}-byte safety limit: "
                    f"{repository}/{path}"
                )
            decoded = base64.b64decode(compact, validate=True)
            if len(decoded) != declared_size or len(decoded) > max_bytes:
                raise GitHubError(
                    f"GitHub policy file size is invalid or exceeds the safety limit: "
                    f"{repository}/{path}"
                )
            return decoded.decode("utf-8")
        except (KeyError, ValueError, UnicodeDecodeError) as exc:
            raise GitHubError(
                f"GitHub policy file could not be decoded safely: {repository}/{path}"
            ) from exc

    def list_repository_files(
        self,
        repository: str,
        *,
        ref: str,
        max_files: int = 20_000,
    ) -> list[str]:
        """List every blob path, rejecting GitHub's silently truncated recursive trees."""

        if max_files < 1:
            raise ValueError("max_files must be positive")
        immutable_ref = _input_nonempty(ref, field="repository tree ref").casefold()
        if not _GIT_SHA.fullmatch(immutable_ref):
            raise ValueError("repository tree ref must be a full immutable git SHA")
        data = self._request(
            "GET",
            f"/repos/{quote(repository, safe='/')}/git/trees/{immutable_ref}",
            params={"recursive": 1},
            allow_not_found=True,
        )
        if data is None:
            return []
        payload = _mapping(data, resource="repository tree")
        if payload.get("truncated") is not False:
            raise GitHubError(
                "GitHub repository tree is truncated; policy discovery would be incomplete"
            )
        paths: list[str] = []
        seen: set[str] = set()
        for entry in _mapping_list(payload.get("tree"), resource="repository tree entries"):
            entry_type = _nonempty(entry.get("type"), field="repository tree entry type")
            if entry_type not in {"blob", "tree", "commit"}:
                raise GitHubError("GitHub returned an unsupported repository tree entry type")
            if entry_type != "blob":
                continue
            path = _nonempty(entry.get("path"), field="repository tree path")
            if (
                path.startswith("/")
                or "\\" in path
                or any(ord(character) < 32 for character in path)
                or any(part in {"", ".", ".."} for part in path.split("/"))
            ):
                raise GitHubError("GitHub returned an unsafe repository tree path")
            if path in seen:
                raise GitHubError("GitHub returned a duplicate repository tree path")
            seen.add(path)
            paths.append(path)
            if len(paths) > max_files:
                raise GitHubError(
                    f"Repository has more than {max_files} files; policy discovery is incomplete"
                )
        return sorted(paths, key=str.casefold)

    def default_branch_sha(self, repository: str, branch: str) -> str:
        data = _mapping(
            self._request(
                "GET",
                f"/repos/{quote(repository, safe='/')}/git/ref/heads/{quote(branch, safe='')}",
            ),
            resource="default branch ref",
        )
        target = _mapping(data.get("object"), resource="default branch ref target")
        return _full_git_sha(target.get("sha"), field="default branch SHA")

    def default_branch_sha_if_exists(self, repository: str) -> str | None:
        """Resolve an optional repository's default branch to one immutable commit."""

        if not isinstance(repository, str) or not _REPOSITORY_NAME.fullmatch(repository):
            raise ValueError("repository must use owner/name syntax")
        data = self._request(
            "GET",
            f"/repos/{quote(repository, safe='/')}",
            allow_not_found=True,
        )
        if data is None:
            return None
        payload = _mapping(data, resource="optional policy repository")
        full_name = _nonempty(
            payload.get("full_name"), field="optional policy repository full name"
        )
        if full_name.casefold() != repository.casefold():
            raise GitHubError("GitHub returned a different optional policy repository")
        branch = _nonempty(
            payload.get("default_branch"), field="optional policy repository default branch"
        )
        return self.default_branch_sha(full_name, branch)

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
        data = _mapping_list(
            self._request(
                "GET",
                f"/repos/{quote(repository, safe='/')}/pulls",
                params={"state": "all", "head": head, "per_page": 10},
            ),
            resource="pull requests for publication branch",
        )
        if len(data) > 1:
            raise GitHubError(
                "Publication branch matches multiple pull requests; state is ambiguous"
            )
        if not data:
            return None
        return _nonempty(data[0].get("html_url"), field="matching pull request URL")

    def get_pull_request(self, repository: str, number: int) -> PullRequestDetails:
        """Read the identity and current top-level state of one pull request."""

        data = self._request(
            "GET", f"/repos/{quote(repository, safe='/')}/pulls/{_positive_number(number)}"
        )
        return _parse_pull_request(
            _mapping(data, resource="pull request"),
            expected_repository=repository,
            expected_number=number,
        )

    def list_pull_request_reviews(
        self,
        repository: str,
        number: int,
        *,
        max_reviews: int = 500,
    ) -> list[PullRequestReview]:
        data = self._bounded_list(
            f"/repos/{quote(repository, safe='/')}/pulls/{_positive_number(number)}/reviews",
            resource="pull request reviews",
            max_items=max_reviews,
        )
        return _unique_records(
            [_parse_pull_request_review(item) for item in data],
            resource="pull request reviews",
        )

    def list_issue_comments(
        self,
        repository: str,
        number: int,
        *,
        expected_count: int | None = None,
        max_comments: int = 500,
    ) -> list[GitHubComment]:
        """Read all issue-style PR comments and verify the PR's advertised count."""

        if expected_count is not None:
            _nonnegative_count(expected_count, field="expected issue comment count")
            if expected_count > max_comments:
                raise GitHubError(
                    f"Pull request has {expected_count} issue comments, above the safe limit "
                    f"of {max_comments}; lifecycle evidence is incomplete"
                )
        data = self._bounded_list(
            f"/repos/{quote(repository, safe='/')}/issues/{_positive_number(number)}/comments",
            resource="pull request issue comments",
            max_items=max_comments,
        )
        comments = _unique_records(
            [_parse_github_comment(item) for item in data],
            resource="pull request issue comments",
        )
        if expected_count is not None and len(comments) != expected_count:
            raise GitHubError(
                "Pull-request issue comment count changed while it was fetched; retry observation"
            )
        return comments

    def list_review_comments(
        self,
        repository: str,
        number: int,
        *,
        expected_count: int | None = None,
        max_comments: int = 500,
    ) -> list[GitHubComment]:
        """Read all inline review comments and verify the PR's advertised count."""

        if expected_count is not None:
            _nonnegative_count(expected_count, field="expected review comment count")
            if expected_count > max_comments:
                raise GitHubError(
                    f"Pull request has {expected_count} review comments, above the safe limit "
                    f"of {max_comments}; lifecycle evidence is incomplete"
                )
        data = self._bounded_list(
            f"/repos/{quote(repository, safe='/')}/pulls/{_positive_number(number)}/comments",
            resource="pull request review comments",
            max_items=max_comments,
        )
        comments = _unique_records(
            [_parse_github_comment(item) for item in data],
            resource="pull request review comments",
        )
        if expected_count is not None and len(comments) != expected_count:
            raise GitHubError(
                "Pull-request review comment count changed while it was fetched; retry observation"
            )
        return comments

    def list_check_runs(
        self,
        repository: str,
        ref: str,
        *,
        max_check_runs: int = 500,
    ) -> list[CheckRunDetails]:
        """Read the latest check run for each check name, with total-count verification."""

        if not 1 <= max_check_runs <= 1_000:
            raise ValueError("check run limit must be between 1 and 1,000")
        path = (
            f"/repos/{quote(repository, safe='/')}/commits/"
            f"{quote(_nonempty(ref, field='commit ref'), safe='')}/check-runs"
        )
        results: list[CheckRunDetails] = []
        expected_total: int | None = None
        maximum_pages = max_check_runs // 100 + 1
        for page in range(1, maximum_pages + 1):
            payload = _mapping(
                self._request(
                    "GET",
                    path,
                    params={"filter": "latest", "per_page": 100, "page": page},
                ),
                resource="check runs",
            )
            total = _nonnegative_count(payload.get("total_count"), field="check run total_count")
            if total > max_check_runs:
                raise GitHubError(
                    f"Check runs exceeded the safe limit of {max_check_runs}; "
                    "lifecycle evidence is incomplete"
                )
            if expected_total is None:
                expected_total = total
            elif total != expected_total:
                raise GitHubError("Check-run count changed while it was fetched; retry observation")
            page_items = _mapping_list(payload.get("check_runs"), resource="check runs")
            if len(page_items) > 100:
                raise GitHubError("GitHub returned an oversized check runs page")
            results.extend(_parse_check_run(item) for item in page_items)
            _require_unique_identifiers(results, resource="check runs")
            if len(results) > total:
                raise GitHubError("GitHub returned more check runs than its advertised total")
            if len(results) == total:
                return results
            if not page_items or len(page_items) < 100:
                raise GitHubError(
                    "GitHub returned fewer check runs than its advertised total; retry observation"
                )
        raise GitHubError(
            "Check runs reached the pagination limit; lifecycle evidence is incomplete"
        )

    def list_commit_statuses(
        self,
        repository: str,
        ref: str,
        *,
        max_statuses: int = 500,
    ) -> list[CommitStatusDetails]:
        """Read all reverse-chronological legacy commit statuses for a head commit."""

        data = self._bounded_list(
            (
                f"/repos/{quote(repository, safe='/')}/commits/"
                f"{quote(_nonempty(ref, field='commit ref'), safe='')}/statuses"
            ),
            resource="commit statuses",
            max_items=max_statuses,
        )
        return _unique_records(
            [_parse_commit_status(item) for item in data],
            resource="commit statuses",
        )

    def list_pull_request_references(
        self,
        repository: str,
        number: int,
        *,
        max_events: int = 1_000,
    ) -> list[PullRequestReference]:
        """Read bounded PR cross-references that may provide explicit revert evidence."""

        data = self._bounded_list(
            f"/repos/{quote(repository, safe='/')}/issues/{_positive_number(number)}/timeline",
            resource="pull request timeline events",
            max_items=max_events,
        )
        references: list[PullRequestReference] = []
        for event in data:
            if str(event.get("event") or "").casefold() != "cross-referenced":
                continue
            source = event.get("source")
            if not isinstance(source, dict):
                continue
            source_issue = source.get("issue")
            if not isinstance(source_issue, dict) or not isinstance(
                source_issue.get("pull_request"), dict
            ):
                continue
            references.append(_parse_pull_request_reference(event, source_issue))
        return _unique_records(references, resource="pull request references")

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
        expected_head_sha: str,
        expected_head_repository: str,
        base: str,
        expected_base_sha: str,
        draft: bool,
    ) -> PullRequestDetails:
        """Create a PR and return its canonical response before policy validation.

        The caller is responsible for durably recording ``html_url`` before comparing the
        returned head/base identity with its publication intent.  This separation is deliberate:
        a successful POST must never be converted into an exception that discards the identity
        of the remote object that was just created.
        """

        if not isinstance(repository, str) or not _REPOSITORY_NAME.fullmatch(repository):
            raise ValueError("repository must use owner/name syntax")
        expected_title = _input_nonempty(title, field="pull request title")
        expected_body = _input_string(body, field="pull request body")
        expected_head = _input_nonempty(head, field="pull request head")
        expected_sha = _input_nonempty(
            expected_head_sha,
            field="pull request expected head SHA",
        ).casefold()
        if not _GIT_SHA.fullmatch(expected_sha):
            raise ValueError(
                "pull request expected head SHA must be a full 40- or 64-character git SHA"
            )
        expected_head_repo = _input_nonempty(
            expected_head_repository,
            field="pull request expected head repository",
        )
        if not _REPOSITORY_NAME.fullmatch(expected_head_repo):
            raise ValueError("pull request expected head repository must use owner/name syntax")
        expected_base = _input_nonempty(base, field="pull request base")
        expected_base_commit = _input_nonempty(
            expected_base_sha,
            field="pull request expected base SHA",
        ).casefold()
        if not _GIT_SHA.fullmatch(expected_base_commit):
            raise ValueError(
                "pull request expected base SHA must be a full 40- or 64-character git SHA"
            )
        if expected_head.count(":") != 1:
            raise ValueError("pull request head must use owner:branch syntax")
        expected_head_owner, expected_head_ref = expected_head.split(":", 1)
        if not _GITHUB_LOGIN.fullmatch(expected_head_owner):
            raise ValueError("pull request head owner is invalid")
        if not expected_head_ref:
            raise ValueError("pull request head branch cannot be blank")
        if expected_head_repo.split("/", 1)[0].casefold() != expected_head_owner.casefold():
            raise ValueError("pull request head owner differs from expected head repository")
        if not isinstance(draft, bool):
            raise ValueError("pull request draft must be a boolean")

        data = _mapping(
            self._request(
                "POST",
                f"/repos/{quote(repository, safe='/')}/pulls",
                json_body={
                    "title": expected_title,
                    "body": expected_body,
                    "head": expected_head,
                    "base": expected_base,
                    "draft": draft,
                    "maintainer_can_modify": True,
                },
            ),
            resource="created pull request",
        )
        number = _identifier(data.get("number"), resource="created pull request")
        html_url, _ = self._canonical_pull_request_url(
            data.get("html_url"),
            expected_repository=repository,
            expected_number=number,
        )
        details = _parse_pull_request(
            data,
            expected_repository=repository,
            expected_number=number,
        )
        return replace(details, html_url=html_url)

    def close_pull_request(
        self,
        repository: str,
        number: int,
        *,
        expected_head_repository: str,
        expected_head_ref: str,
        expected_head_sha: str,
    ) -> PullRequestDetails:
        """Close only an exact, unmerged PR and verify the resulting remote state.

        This is a narrow compensation primitive.  It deliberately re-reads the PR immediately
        before PATCH and validates the response again so a caller cannot close an object merely
        because it has the expected PR number.
        """

        expected_repository = _input_nonempty(
            expected_head_repository,
            field="compensation head repository",
        )
        if not _REPOSITORY_NAME.fullmatch(expected_repository):
            raise ValueError("compensation head repository must use owner/name syntax")
        expected_ref = _input_nonempty(expected_head_ref, field="compensation head ref")
        expected_sha = _input_nonempty(
            expected_head_sha,
            field="compensation head SHA",
        ).casefold()
        if not _GIT_SHA.fullmatch(expected_sha):
            raise ValueError("compensation head SHA must be a full 40- or 64-character git SHA")

        current = self.get_pull_request(repository, number)
        self._validate_compensation_pull_request(
            current,
            expected_head_repository=expected_repository,
            expected_head_ref=expected_ref,
            expected_head_sha=expected_sha,
        )
        if current.merged:
            raise GitHubError("Refusing to close a pull request that has already been merged")
        if current.state == "closed":
            return current

        data = _mapping(
            self._request(
                "PATCH",
                f"/repos/{quote(repository, safe='/')}/pulls/{_positive_number(number)}",
                json_body={"state": "closed"},
            ),
            resource="closed pull request",
        )
        closed = _parse_pull_request(
            data,
            expected_repository=repository,
            expected_number=number,
        )
        self._validate_compensation_pull_request(
            closed,
            expected_head_repository=expected_repository,
            expected_head_ref=expected_ref,
            expected_head_sha=expected_sha,
        )
        if closed.state != "closed" or closed.merged:
            raise GitHubError("GitHub did not confirm the exact pull request was closed unmerged")
        canonical_url, _ = self._canonical_pull_request_url(
            closed.html_url,
            expected_repository=repository,
            expected_number=number,
        )
        return replace(closed, html_url=canonical_url)

    def _validate_compensation_pull_request(
        self,
        details: PullRequestDetails,
        *,
        expected_head_repository: str,
        expected_head_ref: str,
        expected_head_sha: str,
    ) -> None:
        if details.head_repository.casefold() != expected_head_repository.casefold():
            raise GitHubError("Refusing to close a pull request from a different head repository")
        if details.head_ref != expected_head_ref:
            raise GitHubError("Refusing to close a pull request from a different head branch")
        if details.head_sha.casefold() != expected_head_sha.casefold():
            raise GitHubError("Refusing to close a pull request at a different head commit")

    def _canonical_pull_request_url(
        self,
        value: object,
        *,
        expected_repository: str | None,
        expected_number: int,
    ) -> tuple[str, str]:
        if not isinstance(value, str) or value != value.strip():
            raise GitHubError("GitHub returned a noncanonical pull request URL")
        url = _nonempty(value, field="pull request URL")
        try:
            parsed = urlparse(url)
            parsed_port = parsed.port
        except ValueError as exc:
            raise GitHubError("GitHub returned a noncanonical pull request URL") from exc
        expected_origin = urlparse(web_origin_for_api(self.config.api_url))
        if (
            parsed.scheme != expected_origin.scheme
            or parsed.hostname != expected_origin.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed_port != expected_origin.port
            or parsed.query
            or parsed.fragment
            or parsed.params
        ):
            raise GitHubError("GitHub returned a noncanonical pull request URL")
        match = re.fullmatch(
            r"/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/pull/([1-9][0-9]*)",
            parsed.path,
        )
        if match is None:
            raise GitHubError("GitHub returned a noncanonical pull request URL")
        repository = f"{match.group(1)}/{match.group(2)}"
        number = int(match.group(3))
        if number != expected_number:
            raise GitHubError("GitHub returned a pull request URL with a different number")
        if (
            expected_repository is not None
            and repository.casefold() != expected_repository.casefold()
        ):
            raise GitHubError("GitHub returned a pull request URL from a different repository")
        return url, repository

    def _require_canonical_api_url(self, value: object, *, path: str, field: str) -> None:
        if not isinstance(value, str) or value != value.strip():
            raise GitHubError(f"GitHub returned a noncanonical {field}")
        url = _nonempty(value, field=field)
        try:
            parsed = urlparse(url)
        except ValueError as exc:
            raise GitHubError(f"GitHub returned a noncanonical {field}") from exc
        api = urlparse(str(self.config.api_url))
        expected_path = f"{api.path.rstrip('/')}{path}"
        if (
            parsed.scheme != api.scheme
            or parsed.netloc != api.netloc
            or parsed.path.casefold() != expected_path.casefold()
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.params
        ):
            raise GitHubError(f"GitHub returned a noncanonical {field}")


def _mapping(value: object, *, resource: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GitHubError(f"GitHub returned malformed {resource} data")
    return value


def _canonical_repository_name(value: object) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or not _REPOSITORY_NAME.fullmatch(value)
        or any(part in {".", ".."} for part in value.split("/"))
    ):
        raise GitHubError("GitHub returned a noncanonical repository full name")
    return value


def _exact_repository_url(value: object, *, expected: str, field: str) -> str:
    if not isinstance(value, str) or value != expected:
        raise GitHubError(f"GitHub returned a noncanonical {field}")
    return value


def _mapping_list(value: object, *, resource: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise GitHubError(f"GitHub returned malformed {resource} data")
    return cast("list[dict[str, Any]]", value)


def _require_unique_identifiers(records: Sequence[_Identified], *, resource: str) -> None:
    identifiers = [record.identifier for record in records]
    if len(identifiers) != len(set(identifiers)):
        raise GitHubError(
            f"GitHub returned duplicate {resource}; lifecycle evidence may have changed"
        )


def _unique_records(records: list[IdentifiedT], *, resource: str) -> list[IdentifiedT]:
    _require_unique_identifiers(records, resource=resource)
    return records


def _nonempty(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\0" in value:
        raise GitHubError(f"GitHub returned an invalid {field}")
    return value.strip()


def _optional_string(value: object, *, field: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str) or "\0" in value:
        raise GitHubError(f"GitHub returned an invalid {field}")
    return value


def _full_git_sha(value: object, *, field: str) -> str:
    sha = _nonempty(value, field=field).casefold()
    if not _GIT_SHA.fullmatch(sha):
        raise GitHubError(f"GitHub returned an invalid {field}")
    return sha


def _input_nonempty(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip() or "\0" in value:
        raise ValueError(f"{field} must be a nonempty canonical string")
    return value


def _input_string(value: object, *, field: str) -> str:
    if not isinstance(value, str) or "\0" in value:
        raise ValueError(f"{field} must be a string without null bytes")
    return value


def _canonical_date(value: object, *, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an ISO calendar date")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO calendar date") from exc
    if parsed.isoformat() != value:
        raise ValueError(f"{field} must be a canonical ISO calendar date")
    return value


def _positive_number(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError("pull request number must be a positive integer")
    return value


def _positive_issue_number(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError("issue number must be a positive integer")
    return value


def _explicit_issue_reference(text: str, repository: str, issue_number: int) -> bool:
    """Match GitHub issue references without treating #42 as a prefix of #420."""

    reference_end = r"(?![A-Za-z0-9])"
    local = rf"(?<![A-Za-z0-9_./#-])\#{issue_number}{reference_end}"
    qualified = rf"(?<![A-Za-z0-9_./-]){re.escape(repository)}\#{issue_number}{reference_end}"
    canonical_url = (
        rf"https://github\.com/{re.escape(repository)}/issues/{issue_number}{reference_end}"
    )
    return (
        re.search(
            rf"(?:{canonical_url}|{qualified}|{local})",
            text,
            re.IGNORECASE,
        )
        is not None
    )


def _nonnegative_count(value: object, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise GitHubError(f"GitHub returned an invalid {field}")
    return value


def _identifier(value: object, *, resource: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise GitHubError(f"GitHub returned an invalid {resource} identifier")
    return value


def _parse_datetime(value: object) -> datetime | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise GitHubError("GitHub returned a non-string timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GitHubError("GitHub returned an invalid timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise GitHubError("GitHub returned a timestamp without a timezone")
    return parsed.astimezone(UTC)


def _required_datetime(value: object, *, field: str) -> datetime:
    parsed = _parse_datetime(value)
    if parsed is None:
        raise GitHubError(f"GitHub omitted required {field}")
    return parsed


def _user_login(value: object, *, resource: str) -> str:
    user = _mapping(value, resource=f"{resource} user")
    return _nonempty(user.get("login"), field=f"{resource} user login")


def _author_association(value: object, *, resource: str) -> str:
    association = _nonempty(value, field=f"{resource} author association").upper()
    if association not in _AUTHOR_ASSOCIATIONS:
        raise GitHubError(f"GitHub returned an unsupported {resource} author association")
    return association


def _parse_pull_request(
    data: dict[str, Any],
    *,
    expected_repository: str,
    expected_number: int,
) -> PullRequestDetails:
    number = _identifier(data.get("number"), resource="pull request")
    if number != expected_number:
        raise GitHubError("GitHub returned a different pull request number than requested")
    base = _mapping(data.get("base"), resource="pull request base")
    base_repository = _mapping(base.get("repo"), resource="pull request base repository")
    repository = _nonempty(
        base_repository.get("full_name"), field="pull request base repository name"
    )
    if repository.casefold() != expected_repository.casefold():
        raise GitHubError("GitHub returned a pull request from a different repository")
    head = _mapping(data.get("head"), resource="pull request head")
    head_repository_data = _mapping(head.get("repo"), resource="pull request head repository")
    head_repository = _nonempty(
        head_repository_data.get("full_name"), field="pull request head repository name"
    )
    if not _REPOSITORY_NAME.fullmatch(head_repository):
        raise GitHubError("GitHub returned an invalid pull request head repository name")
    state = _nonempty(data.get("state"), field="pull request state").casefold()
    if state not in {"open", "closed"}:
        raise GitHubError("GitHub returned an unsupported pull request state")
    draft = data.get("draft")
    merged = data.get("merged")
    if not isinstance(draft, bool) or not isinstance(merged, bool):
        raise GitHubError("GitHub returned invalid pull request draft or merged state")
    merge_commit_value = data.get("merge_commit_sha")
    merge_commit_sha = (
        None
        if merge_commit_value is None
        else _nonempty(merge_commit_value, field="pull request merge commit SHA")
    )
    merged_at = _parse_datetime(data.get("merged_at"))
    closed_at = _parse_datetime(data.get("closed_at"))
    if merged and (state != "closed" or merged_at is None or closed_at is None):
        raise GitHubError("GitHub returned inconsistent merged pull request state")
    if not merged and merged_at is not None:
        raise GitHubError("GitHub returned merged_at for an unmerged pull request")
    if state == "closed" and closed_at is None:
        raise GitHubError("GitHub omitted closed_at for a closed pull request")
    if state == "open" and closed_at is not None:
        raise GitHubError("GitHub returned closed_at for an open pull request")
    return PullRequestDetails(
        repository=repository,
        number=number,
        html_url=_nonempty(data.get("html_url"), field="pull request URL"),
        state=state,
        draft=draft,
        merged=merged,
        updated_at=_required_datetime(data.get("updated_at"), field="pull request updated_at"),
        merged_at=merged_at,
        closed_at=closed_at,
        merge_commit_sha=merge_commit_sha,
        head_sha=_full_git_sha(head.get("sha"), field="pull request head SHA"),
        base_sha=_full_git_sha(base.get("sha"), field="pull request base SHA"),
        head_repository=head_repository,
        issue_comment_count=_nonnegative_count(
            data.get("comments"), field="pull request issue comment count"
        ),
        review_comment_count=_nonnegative_count(
            data.get("review_comments"), field="pull request review comment count"
        ),
        title=_nonempty(data.get("title"), field="pull request title"),
        body=_optional_string(data.get("body"), field="pull request body"),
        base_ref=_nonempty(base.get("ref"), field="pull request base ref"),
        head_ref=_nonempty(head.get("ref"), field="pull request head ref"),
        head_label=_nonempty(head.get("label"), field="pull request head label"),
    )


def _parse_pull_request_review(data: dict[str, Any]) -> PullRequestReview:
    state = _nonempty(data.get("state"), field="pull request review state").upper()
    if state not in {"APPROVED", "CHANGES_REQUESTED", "COMMENTED", "DISMISSED", "PENDING"}:
        raise GitHubError("GitHub returned an unsupported pull request review state")
    return PullRequestReview(
        identifier=_identifier(data.get("id"), resource="pull request review"),
        author=_user_login(data.get("user"), resource="pull request review"),
        author_association=_author_association(
            data.get("author_association"), resource="pull request review"
        ),
        state=state,
        body=_optional_string(data.get("body"), field="pull request review body"),
        html_url=_nonempty(data.get("html_url"), field="pull request review URL"),
        submitted_at=_parse_datetime(data.get("submitted_at")),
    )


def _parse_github_comment(data: dict[str, Any]) -> GitHubComment:
    return GitHubComment(
        identifier=_identifier(data.get("id"), resource="comment"),
        author=_user_login(data.get("user"), resource="comment"),
        author_association=_author_association(data.get("author_association"), resource="comment"),
        body=_optional_string(data.get("body"), field="comment body"),
        html_url=_nonempty(data.get("html_url"), field="comment URL"),
        created_at=_required_datetime(data.get("created_at"), field="comment created_at"),
        updated_at=_required_datetime(data.get("updated_at"), field="comment updated_at"),
    )


def _parse_check_run(data: dict[str, Any]) -> CheckRunDetails:
    status = _nonempty(data.get("status"), field="check run status").casefold()
    if status not in {"completed", "in_progress", "pending", "queued", "requested", "waiting"}:
        raise GitHubError("GitHub returned an unsupported check run status")
    conclusion_value = data.get("conclusion")
    conclusion = (
        None
        if conclusion_value is None
        else _nonempty(conclusion_value, field="check run conclusion").casefold()
    )
    if status == "completed" and conclusion is None:
        raise GitHubError("GitHub returned a completed check run without a conclusion")
    if conclusion is not None and conclusion not in _CHECK_CONCLUSIONS:
        raise GitHubError("GitHub returned an unsupported check run conclusion")
    if status != "completed" and conclusion is not None:
        raise GitHubError("GitHub returned a conclusion for an incomplete check run")
    completed_at = _parse_datetime(data.get("completed_at"))
    if status == "completed" and completed_at is None:
        raise GitHubError("GitHub returned a completed check run without completed_at")
    if status != "completed" and completed_at is not None:
        raise GitHubError("GitHub returned completed_at for an incomplete check run")
    app = _mapping(data.get("app"), resource="check run app")
    app_name = app.get("slug") or app.get("name")
    return CheckRunDetails(
        identifier=_identifier(data.get("id"), resource="check run"),
        name=_nonempty(data.get("name"), field="check run name"),
        status=status,
        conclusion=conclusion,
        details_url=_optional_string(data.get("details_url"), field="check run details URL"),
        app_name=_nonempty(app_name, field="check run app name"),
        started_at=_parse_datetime(data.get("started_at")),
        completed_at=completed_at,
    )


def _parse_commit_status(data: dict[str, Any]) -> CommitStatusDetails:
    state = _nonempty(data.get("state"), field="commit status state").casefold()
    if state not in {"error", "failure", "pending", "success"}:
        raise GitHubError("GitHub returned an unsupported commit status state")
    return CommitStatusDetails(
        identifier=_identifier(data.get("id"), resource="commit status"),
        context=_nonempty(data.get("context"), field="commit status context"),
        state=state,
        description=_optional_string(data.get("description"), field="commit status description"),
        target_url=_optional_string(data.get("target_url"), field="commit status target URL"),
        creator=_user_login(data.get("creator"), resource="commit status"),
        created_at=_required_datetime(data.get("created_at"), field="commit status created_at"),
        updated_at=_required_datetime(data.get("updated_at"), field="commit status updated_at"),
    )


def _parse_pull_request_reference(
    event: dict[str, Any], source_issue: dict[str, Any]
) -> PullRequestReference:
    source_pull_request = _mapping(
        source_issue.get("pull_request"), resource="timeline source pull request"
    )
    source_state = _nonempty(source_issue.get("state"), field="timeline source state").casefold()
    if source_state not in {"open", "closed"}:
        raise GitHubError("GitHub returned an unsupported timeline source state")
    return PullRequestReference(
        identifier=_identifier(event.get("id"), resource="timeline event"),
        source_url=_nonempty(source_issue.get("html_url"), field="timeline source URL"),
        source_title=_optional_string(source_issue.get("title"), field="timeline source title"),
        source_body=_optional_string(source_issue.get("body"), field="timeline source body"),
        source_state=source_state,
        source_merged_at=_parse_datetime(source_pull_request.get("merged_at")),
        created_at=_required_datetime(event.get("created_at"), field="timeline event created_at"),
    )


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


def _response_message(response: httpx.Response) -> str:
    """Extract a bounded diagnostic without reflecting arbitrary response bodies."""

    try:
        payload = response.json()
    except ValueError:
        return ""
    if not isinstance(payload, dict):
        return ""
    message = payload.get("message")
    return str(message)[:1_000] if message is not None else ""


__all__ = [
    "CheckRunDetails",
    "CommitStatusDetails",
    "GitHubClient",
    "GitHubComment",
    "PullRequestDetails",
    "PullRequestReference",
    "PullRequestReview",
    "resolve_github_token",
]
