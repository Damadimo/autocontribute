"""Narrow GitHub API client with read operations separated from publication."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import time
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime
from typing import Any, Literal, Protocol, TypeVar, cast
from urllib.parse import quote, urljoin, urlparse

import httpx

from autocontribute.config import GitHubConfig
from autocontribute.domain import IssueCandidate, IssueComment, RepositoryInfo
from autocontribute.exceptions import (
    CircuitBreakerTrigger,
    ConfigurationError,
    GitHubError,
    GitHubHTTPError,
    GitHubRateLimitError,
    GitHubRequestNotSentError,
    GitHubSafetyError,
    StopScope,
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
# GitHub search never returns more than 1,000 results for one query.
_SEARCH_RESULT_LIMIT = 1_000
_AUTHORED_PULL_REQUESTS_QUERY = (
    "query AuthoredPullRequests($query: String!, $cursor: String) { "
    "search(query: $query, type: ISSUE, first: 100, after: $cursor) { "
    "pageInfo { hasNextPage endCursor } "
    "nodes { ... on PullRequest { number url headRefName createdAt updatedAt } } } }"
)
_COMPARE_FILE_LIMIT = 300
_GITHUB_LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_GIT_SHA = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_REPOSITORY_NAME = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SECONDARY_RATE_LIMIT = re.compile(
    r"(?:abuse detection|secondary rate limit|temporarily blocked)", re.I
)
# GitHub words its content-creation block as a secondary limit too; on a mutation it pauses
# every publication, not one request.
_CONTENT_CREATION_BLOCK = re.compile(r"temporarily blocked", re.I)
_ACCOUNT_SUSPENSION = re.compile(r"account (?:was |has been |is )?suspended", re.I)
# Bounded, self-limiting retry policy for transient GitHub responses. Waits are capped so a
# scheduled run can never stall on GitHub's word alone, and every exhausted budget fails closed.
_MAX_REQUEST_ATTEMPTS = 4
_MAX_SINGLE_WAIT_SECONDS = 60.0
_MAX_TOTAL_WAIT_SECONDS = 180.0
_TRANSIENT_BACKOFF_SECONDS = (2.0, 4.0, 8.0)
_TRANSIENT_STATUS_CODES = frozenset({500, 502, 503, 504})
# GitHub asks for at least a minute after a secondary limit, then exponential backoff. These are
# the shortest waits before each retry; one client (one run) waits at most the budget in total.
_SECONDARY_BACKOFF_SECONDS = (60.0, 120.0, 240.0)
_SECONDARY_WAIT_BUDGET_SECONDS = 600.0
# GitHub allows 30 searches a minute; staying under it avoids secondary limits.
_SEARCH_PATH = "/search/issues"
_SEARCHES_PER_MINUTE = 25
# Path segments after these name a file, ref, or commit range rather than a resource.
_FREE_FORM_PATH_RESOURCES = frozenset({"compare", "contents", "ref", "refs"})
_MAX_REPOSITORY_LABELS = 1_000
# The contents API returns at most this many entries of one directory, without saying so.
_MAX_DIRECTORY_ENTRIES = 1_000
# Issues with this many comments are usually contested or need a design decision.
_SEARCH_MAX_COMMENTS = 40

# Test seams: retries sleep and the search limit reads time through these module attributes, so
# tests never wait on the wall clock.
_sleep = time.sleep
_monotonic = time.monotonic

SafetyTriggerHandler = Callable[[CircuitBreakerTrigger], object]


class _TransportFailure(GitHubError):
    """A network-level failure with no response; retriable only for reads."""


class _RequestNotSent(_TransportFailure, GitHubRequestNotSentError):
    """A transport failure raised before the request left this client."""


# Connection-establishment failures happen before any request bytes reach GitHub, so even
# a mutation that fails this way provably did not happen on the remote side.
_NOT_SENT_TRANSPORT_ERRORS = (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout)


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
    node_id: str = ""


@dataclass(frozen=True, slots=True)
class RepositoryIdentity:
    """GitHub's immutable identity for a repository currently reachable by ``full_name``."""

    full_name: str
    database_id: int
    node_id: str


@dataclass(frozen=True, slots=True)
class RepositoryAccess:
    """Ownership, this token's push permission, and who may open pull requests."""

    identity: RepositoryIdentity
    owner: str
    fork_parent: RepositoryIdentity | None
    # None when GitHub reported no permissions for this token, as for an unrelated app token.
    can_push: bool | None
    has_pull_requests: bool
    pull_requests_from_collaborators_only: bool


@dataclass(frozen=True, slots=True)
class AuthoredPullRequest:
    """One pull request the publishing account opened, as GitHub search reports it."""

    url: str
    repository: str
    head_ref: str
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class CommitComparison:
    """How a later commit relates to an earlier one, and which paths changed between them."""

    status: str
    changed_paths: frozenset[str]
    # GitHub lists at most 300 files, so a full list cannot prove the remaining paths unchanged.
    complete: bool


@dataclass(frozen=True, slots=True)
class GitHubAccount:
    """A user account by its current login and immutable database ID."""

    login: str
    database_id: int


@dataclass(frozen=True, slots=True)
class ForkIdentity:
    """Immutable identities for a fork and the upstream repository GitHub reports as parent."""

    repository: RepositoryIdentity
    parent: RepositoryIdentity


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


@dataclass(frozen=True, slots=True)
class CommitStatusDetails:
    identifier: int
    context: str
    state: str
    target_url: str
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class DirectoryEntry:
    """One entry of a repository directory listing; kind is file, dir, symlink, or submodule."""

    path: str
    kind: str


@dataclass(frozen=True, slots=True)
class LinkedPullRequest:
    """An open pull request in the issue's own repository that references the issue."""

    html_url: str
    updated_at: datetime
    closes_issue: bool


@dataclass(frozen=True, slots=True)
class BranchPush:
    """One update of a branch, with the account whose credential made it.

    A commit's author comes from its author email, which anyone can set; the pusher cannot be
    chosen that way.
    """

    ref: str
    activity_type: str
    before: str
    after: str
    actor_login: str | None


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
        self._secondary_wait_seconds = 0.0
        self._secondary_limit_exhausted = False
        self._recent_searches: deque[float] = deque()
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
    def secondary_limit_exhausted(self) -> bool:
        """Whether GitHub kept a secondary rate limit past every wait this client allows."""

        return self._secondary_limit_exhausted

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
        total_wait = 0.0
        secondary_limits = 0
        for attempt in range(1, _MAX_REQUEST_ATTEMPTS + 1):
            attempts_remain = attempt < _MAX_REQUEST_ATTEMPTS
            if path == _SEARCH_PATH:
                self._throttle_search()
            try:
                response = self._send(method, path, params=params, json_body=json_body)
            except _TransportFailure:
                # Transport failures are only retried for reads: a lost response to a mutation
                # is ambiguous and must surface to the caller's reconciliation logic instead.
                if method == "GET" and attempts_remain:
                    backoff = _TRANSIENT_BACKOFF_SECONDS[
                        min(attempt, len(_TRANSIENT_BACKOFF_SECONDS)) - 1
                    ]
                    if total_wait + backoff <= _MAX_TOTAL_WAIT_SECONDS:
                        _sleep(backoff)
                        total_wait += backoff
                        continue
                raise
            response_message = _response_message(response)
            is_secondary_limit = bool(_SECONDARY_RATE_LIMIT.search(response_message))
            if response.status_code == 404 and allow_not_found and not is_secondary_limit:
                return None
            if response.status_code == 403 and _ACCOUNT_SUSPENSION.search(response_message):
                self._raise_safety_stop(
                    response,
                    method=method,
                    path=path,
                    source="github_api:account_suspended",
                    summary="GitHub reports this account is suspended",
                    scope=StopScope.GLOBAL,
                )
            if (
                is_secondary_limit
                and method != "GET"
                and _CONTENT_CREATION_BLOCK.search(response_message)
            ):
                self._raise_safety_stop(
                    response,
                    method=method,
                    path=path,
                    source="github_api:content_creation_blocked",
                    summary="GitHub temporarily blocked this account from creating content",
                    scope=StopScope.PUBLICATION,
                )
            if is_secondary_limit:
                secondary_limits += 1
                wait = max(
                    _retry_after_seconds(response) or 0.0,
                    _SECONDARY_BACKOFF_SECONDS[
                        min(secondary_limits, len(_SECONDARY_BACKOFF_SECONDS)) - 1
                    ],
                )
                if (
                    attempts_remain
                    and secondary_limits <= len(_SECONDARY_BACKOFF_SECONDS)
                    and self._secondary_wait_seconds + wait <= _SECONDARY_WAIT_BUDGET_SECONDS
                ):
                    _sleep(wait)
                    self._secondary_wait_seconds += wait
                    continue
                self._secondary_limit_exhausted = True
                request_id = response.headers.get("X-GitHub-Request-Id", "unknown")
                raise GitHubRateLimitError(
                    f"GitHub kept applying a secondary rate limit to {method} {path} "
                    f"({response.status_code}, request {request_id}) after this run waited "
                    f"{self._secondary_wait_seconds:.0f}s. The run ends; a later run can retry."
                )
            is_rate_limited = response.status_code == 429 or (
                response.status_code == 403
                and (
                    response.headers.get("Retry-After") is not None
                    or response.headers.get("X-RateLimit-Remaining") == "0"
                )
            )
            if is_rate_limited:
                wait = _rate_limit_wait_seconds(response, attempt)
                if (
                    attempts_remain
                    and wait <= _MAX_SINGLE_WAIT_SECONDS
                    and total_wait + wait <= _MAX_TOTAL_WAIT_SECONDS
                ):
                    _sleep(wait)
                    total_wait += wait
                    continue
                request_id = response.headers.get("X-GitHub-Request-Id", "unknown")
                raise GitHubRateLimitError(
                    f"GitHub rate limited {method} {path} "
                    f"({response.status_code}, request {request_id}) beyond the bounded retry "
                    f"budget (waited {total_wait:.0f}s, next wait {wait:.0f}s). "
                    "This is transient; a later run can retry safely."
                )
            if (
                response.status_code in _TRANSIENT_STATUS_CODES
                and method == "GET"
                and attempts_remain
            ):
                backoff = _TRANSIENT_BACKOFF_SECONDS[
                    min(attempt, len(_TRANSIENT_BACKOFF_SECONDS)) - 1
                ]
                if total_wait + backoff <= _MAX_TOTAL_WAIT_SECONDS:
                    _sleep(backoff)
                    total_wait += backoff
                    continue
            if not 200 <= response.status_code < 300:
                request_id = response.headers.get("X-GitHub-Request-Id", "unknown")
                github_message = _error_message(response)
                raise GitHubHTTPError(
                    f"GitHub returned {response.status_code} for {method} {path} "
                    f"(request {request_id}): {github_message}",
                    status_code=response.status_code,
                    request_id=request_id,
                    github_message=github_message,
                )
            if response.status_code == 204:
                return None
            try:
                return response.json()
            except ValueError as exc:
                raise GitHubError(f"GitHub returned invalid JSON for {method} {path}") from exc
        raise GitHubError(f"GitHub request failed after retries: {method} {path}")

    def _throttle_search(self) -> None:
        """Wait until fewer than the allowed number of searches fall in the last minute."""

        now = _monotonic()
        if len(self._recent_searches) >= _SEARCHES_PER_MINUTE:
            wait = self._recent_searches[0] + 60.0 - now
            if wait > 0:
                _sleep(wait)
                now += wait
        while self._recent_searches and self._recent_searches[0] <= now - 60.0:
            self._recent_searches.popleft()
        self._recent_searches.append(now)

    def _send(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str | int] | None,
        json_body: dict[str, object] | None,
    ) -> httpx.Response:
        try:
            response = self._client.request(method, path, params=params, json=json_body)
        except _NOT_SENT_TRANSPORT_ERRORS as exc:
            raise _RequestNotSent(
                f"GitHub request could not be sent: {method} {path}: {exc}"
            ) from exc
        except httpx.HTTPError as exc:
            raise _TransportFailure(f"GitHub request failed: {method} {path}: {exc}") from exc
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
                raise _TransportFailure(
                    f"GitHub redirected request failed: GET {path}: {exc}"
                ) from exc
        return response

    def _raise_safety_stop(
        self,
        response: httpx.Response,
        *,
        method: str,
        path: str,
        source: str,
        summary: str,
        scope: StopScope,
    ) -> None:
        retry_after = response.headers.get("Retry-After")
        remaining = response.headers.get("X-RateLimit-Remaining")
        request_id = response.headers.get("X-GitHub-Request-Id")
        template = _path_template(path)
        # Repeats within one incident share this hash, whatever their request IDs, and are
        # recorded once. The UTC day separates incidents, so a block that returns after an
        # operator released the last one stops work again.
        evidence = {
            "method": method,
            "path": template,
            "source": source,
            "incident_day": datetime.now(UTC).date().isoformat(),
        }
        trigger = CircuitBreakerTrigger(
            source=source,
            reason=f"{summary} ({method} {template}).",
            trigger_hash=hashlib.sha256(
                json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            scope=scope,
            scope_key="" if scope is StopScope.GLOBAL else self.api_origin,
        )
        if self._safety_trigger_handler is not None:
            self._safety_trigger_handler(trigger)
        stopped = (
            "The global safety stop was activated."
            if scope is StopScope.GLOBAL
            else "Publication is held until an operator releases it."
        )
        raise GitHubSafetyError(
            f"{summary} ({response.status_code} for {method} {path}; request "
            f"{request_id or 'unknown'}); retry_after={retry_after!r}, "
            f"remaining={remaining!r}. {stopped}",
            trigger=trigger,
        )

    def _bounded_list(
        self,
        path: str,
        *,
        resource: str,
        max_items: int,
    ) -> list[dict[str, Any]]:
        """Read a complete REST collection or reject ambiguous/truncated evidence."""

        if not 1 <= max_items <= 1_000:
            raise ValueError(f"{resource} limit must be between 1 and 1,000")
        items: list[dict[str, Any]] = []
        # One overflow page distinguishes an exact multiple of 100 from a truncated collection.
        maximum_pages = max_items // 100 + 1
        for page in range(1, maximum_pages + 1):
            data = self._request("GET", path, params={"per_page": 100, "page": page})
            page_items = _mapping_list(data, resource=resource)
            if len(page_items) > 100:
                raise GitHubError(f"GitHub returned an oversized {resource} page")
            if len(items) + len(page_items) > max_items:
                raise GitHubError(
                    f"{resource.capitalize()} exceeded the safe limit of {max_items}; "
                    "the evidence is incomplete"
                )
            items.extend(page_items)
            if len(page_items) < 100:
                return items
        raise GitHubError(
            f"{resource.capitalize()} reached the pagination limit; the evidence is incomplete"
        )

    def authenticated_login(self) -> str:
        data = cast("dict[str, Any]", self._request("GET", "/user"))
        return str(data["login"])

    def authenticated_user(self) -> GitHubAccount:
        """Resolve the token's owner; tokens that act for no user cannot do this."""

        return _parse_account(_mapping(self._request("GET", "/user"), resource="token owner"))

    def get_user(self, login: str) -> GitHubAccount:
        """Resolve any public account, so no token of that account is needed."""

        if not isinstance(login, str) or not _GITHUB_LOGIN.fullmatch(login):
            raise ValueError("GitHub login is not a valid account name")
        account = _parse_account(
            _mapping(self._request("GET", f"/users/{quote(login)}"), resource="account")
        )
        if account.login.casefold() != login.casefold():
            raise GitHubError("GitHub resolved the login to a different account")
        return account

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
        creation_policy = data.get("pull_request_creation_policy")
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
            has_pull_requests=bool(data.get("has_pull_requests", True)),
            pull_request_creation_policy=None if creation_policy is None else str(creation_policy),
        )

    def get_repository_identity(self, full_name: str) -> RepositoryIdentity:
        """Resolve an owner/name once to GitHub's immutable database and GraphQL identities."""

        data = _mapping(
            self._request("GET", f"/repos/{quote(full_name, safe='/')}"),
            resource="repository identity",
        )
        return _parse_repository_identity(data, resource="repository identity")

    def get_repository_access(self, full_name: str) -> RepositoryAccess | None:
        """Read one repository's access facts, or None when it does not exist."""

        data = self._request(
            "GET",
            f"/repos/{quote(full_name, safe='/')}",
            allow_not_found=True,
        )
        if data is None:
            return None
        payload = _mapping(data, resource="repository access")
        fork = payload.get("fork")
        if not isinstance(fork, bool):
            raise GitHubError("GitHub returned malformed repository fork state")
        permissions = payload.get("permissions")
        can_push: bool | None = None
        if permissions is not None:
            push = _mapping(permissions, resource="repository permissions").get("push")
            if not isinstance(push, bool):
                raise GitHubError("GitHub returned malformed repository push permission")
            can_push = push
        # Servers that predate these 2026 settings omit them; PRs are then open to everyone.
        has_pull_requests = payload.get("has_pull_requests", True)
        policy = payload.get("pull_request_creation_policy", "all")
        if not isinstance(has_pull_requests, bool) or policy not in {"all", "collaborators_only"}:
            raise GitHubError("GitHub returned an unsupported pull-request creation setting")
        return RepositoryAccess(
            identity=_parse_repository_identity(payload, resource="repository access"),
            owner=_user_login(payload.get("owner"), resource="repository owner"),
            fork_parent=(
                _parse_repository_identity(
                    _mapping(payload.get("parent"), resource="fork parent"),
                    resource="fork parent",
                )
                if fork
                else None
            ),
            can_push=can_push,
            has_pull_requests=has_pull_requests,
            pull_requests_from_collaborators_only=policy == "collaborators_only",
        )

    def get_fork_identity(self, full_name: str) -> ForkIdentity:
        """Resolve a fork and its parent to immutable identities in one API observation."""

        data = _mapping(
            self._request("GET", f"/repos/{quote(full_name, safe='/')}"),
            resource="fork identity",
        )
        if data.get("fork") is not True:
            raise GitHubError("GitHub repository is not a fork")
        parent = _mapping(data.get("parent"), resource="fork parent identity")
        return ForkIdentity(
            repository=_parse_repository_identity(data, resource="fork identity"),
            parent=_parse_repository_identity(parent, resource="fork parent identity"),
        )

    def assert_repository_identity(
        self,
        full_name: str,
        *,
        expected_database_id: int,
        expected_node_id: str,
    ) -> RepositoryIdentity:
        """Re-read a repository through its immutable database-ID route and match all identity."""

        database_id = _positive_number(expected_database_id)
        node_id = _graphql_node_id(expected_node_id)
        expected_name = _canonical_repository_name(full_name)
        data = _mapping(
            self._request("GET", f"/repositories/{database_id}"),
            resource="immutable repository identity",
        )
        identity = _parse_repository_identity(data, resource="immutable repository identity")
        if (
            identity.database_id != database_id
            or identity.node_id != node_id
            or identity.full_name.casefold() != expected_name.casefold()
        ):
            raise GitHubError("GitHub repository differs from its durable immutable identity")
        return identity

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
        issue_path = f"/repos/{quote(repository, safe='/')}/issues/{number}"

        def read_metadata() -> IssueCandidate:
            data = cast("dict[str, Any]", self._request("GET", issue_path))
            if "pull_request" in data:
                raise GitHubError(f"{repository}#{number} is a pull request, not an issue")
            self._require_canonical_api_url(
                data.get("repository_url"),
                path=f"/repos/{repository}",
                field="issue repository API URL",
            )
            self._require_canonical_api_url(
                data.get("url"),
                path=issue_path,
                field="issue API URL",
            )
            _exact_repository_url(
                data.get("html_url"),
                expected=f"{web_origin_for_api(self.config.api_url)}/{repository}/issues/{number}",
                field="issue HTML URL",
            )
            issue = _parse_issue(data, repository)
            if issue.repository.casefold() != repository.casefold() or issue.number != number:
                raise GitHubError("GitHub returned a different issue identity")
            return issue

        initial_issue = read_metadata()
        initial_discussion = self.get_issue_comments(
            repository,
            number,
            expected_count=initial_issue.comments,
        )
        middle_issue = read_metadata()
        if middle_issue != initial_issue:
            raise GitHubError(
                "Issue changed while its complete discussion was fetched; retry with fresh evidence"
            )
        confirmed_discussion = self.get_issue_comments(
            repository,
            number,
            expected_count=middle_issue.comments,
        )
        confirmed_issue = read_metadata()
        if confirmed_issue != middle_issue:
            raise GitHubError(
                "Issue changed while its complete discussion was fetched; retry with fresh evidence"
            )
        if confirmed_discussion != initial_discussion:
            raise GitHubError(
                "Issue discussion changed while it was fetched; retry with fresh evidence"
            )
        return confirmed_issue.model_copy(update={"discussion": confirmed_discussion})

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
        comment_ids: set[int] = set()
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
            for item in data:
                identifier = _identifier(item.get("id"), resource="issue comment")
                if identifier in comment_ids:
                    raise GitHubError(
                        "GitHub returned duplicate issue comment identities; "
                        "discussion evidence may be incomplete"
                    )
                comment_ids.add(identifier)
                self._require_canonical_api_url(
                    item.get("url"),
                    path=f"/repos/{repository}/issues/comments/{identifier}",
                    field="issue comment API URL",
                )
                self._require_canonical_api_url(
                    item.get("issue_url"),
                    path=f"/repos/{repository}/issues/{number}",
                    field="issue comment parent API URL",
                )
                _exact_repository_url(
                    item.get("html_url"),
                    expected=(
                        f"{web_origin_for_api(self.config.api_url)}/{repository}/issues/{number}"
                        f"#issuecomment-{identifier}"
                    ),
                    field="issue comment HTML URL",
                )
                comments.append(_parse_issue_comment(item))
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

    def list_labels(self, repository: str) -> list[str]:
        """Return the names of every label defined in the repository."""

        labels = self._bounded_list(
            f"/repos/{quote(repository, safe='/')}/labels",
            resource="repository labels",
            max_items=_MAX_REPOSITORY_LABELS,
        )
        return [_nonempty(label.get("name"), field="repository label name") for label in labels]

    def search_issues(
        self,
        repository: str,
        *,
        include_labels: Sequence[str],
        exclude_labels: Sequence[str],
        unassigned: bool,
        page: int,
        per_page: int,
    ) -> list[IssueCandidate]:
        """Return one page of open issues that carry any include label, newest first.

        One query covers every label. It leaves out issues with a linked pull request, an
        exclude label, or a long discussion, and assigned issues when ``unassigned`` is set.
        """

        if not include_labels:
            raise ValueError("issue search needs at least one include label")
        if page < 1 or not 1 <= per_page <= 100:
            raise ValueError("issue search pages start at 1 and hold 1 to 100 results")
        qualifiers = [
            f"repo:{repository}",
            "is:issue",
            "is:open",
            "-linked:pr",
            f"comments:<{_SEARCH_MAX_COMMENTS}",
            "label:" + ",".join(_search_label(label) for label in include_labels),
            *(f"-label:{_search_label(label)}" for label in exclude_labels),
        ]
        if unassigned:
            qualifiers.append("no:assignee")
        payload = _mapping(
            self._request(
                "GET",
                "/search/issues",
                params={
                    "q": " ".join(qualifiers),
                    "sort": "created",
                    "order": "desc",
                    "per_page": per_page,
                    "page": page,
                },
            ),
            resource="issue search",
        )
        return [
            _parse_issue(item, repository)
            for item in _mapping_list(payload.get("items"), resource="issue search results")
        ]

    def search_competing_pull_requests(
        self,
        repository: str,
        issue_number: int,
        *,
        max_search_results: int = 100,
    ) -> list[LinkedPullRequest]:
        """Find open PRs that reference the issue, from complete timeline evidence and search.

        Only pull requests in the issue's own repository are returned: a PR elsewhere that
        mentions the issue does not compete with a fix for it.
        """

        normalized_number = _positive_issue_number(issue_number)
        if not 1 <= max_search_results <= 100:
            raise ValueError("competing pull-request search limit must be between 1 and 100")
        pull_requests: dict[str, LinkedPullRequest] = {}
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
                html_url = _nonempty(
                    source_issue.get("html_url"),
                    field="cross-referenced pull request URL",
                )
                if state == "open" and self._in_repository(html_url, repository):
                    pull_requests[html_url] = _linked_pull_request(
                        source_issue,
                        html_url=html_url,
                        repository=repository,
                        issue_number=normalized_number,
                    )
            if len(data) < 100:
                break
        else:
            raise GitHubError(
                "Issue timeline exceeded 1,000 events; duplicate pull-request status is ambiguous"
            )

        for pull_request in self._search_open_pull_requests_referencing_issue(
            repository,
            normalized_number,
            max_results=max_search_results,
        ):
            pull_requests.setdefault(pull_request.html_url, pull_request)
        return [pull_requests[url] for url in sorted(pull_requests)]

    def _in_repository(self, pull_request_url: str, repository: str) -> bool:
        parsed = urlparse(pull_request_url)
        origin = urlparse(web_origin_for_api(self.config.api_url))
        match = re.fullmatch(r"/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/pull/[1-9][0-9]*", parsed.path)
        return (
            (parsed.scheme, parsed.netloc) == (origin.scheme, origin.netloc)
            and match is not None
            and match.group(1).casefold() == repository.casefold()
        )

    def _search_open_pull_requests_referencing_issue(
        self,
        repository: str,
        issue_number: int,
        *,
        max_results: int,
    ) -> list[LinkedPullRequest]:
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

        matches: list[LinkedPullRequest] = []
        for item in items:
            if not isinstance(item.get("pull_request"), dict):
                raise GitHubError("GitHub search returned a non-pull-request result")
            state = _nonempty(item.get("state"), field="searched pull request state").casefold()
            if state != "open":
                raise GitHubError("GitHub search returned a non-open pull request")
            title = _nonempty(item.get("title"), field="searched pull request title")
            body = _optional_string(item.get("body"), field="searched pull request body")
            html_url = _nonempty(item.get("html_url"), field="searched pull request URL")
            if _explicit_issue_reference(
                f"{title}\n{body}", repository, issue_number
            ) and self._in_repository(html_url, repository):
                matches.append(
                    _linked_pull_request(
                        item,
                        html_url=html_url,
                        repository=repository,
                        issue_number=issue_number,
                    )
                )
        return matches

    def authored_pull_requests(
        self,
        login: str,
        *,
        head_ref_prefix: str,
        state: Literal["open"] | None = None,
        updated_after: str | None = None,
    ) -> list[AuthoredPullRequest]:
        """List the login's pull requests whose head branch starts with ``head_ref_prefix``.

        Search results carry no head branch over REST, so this uses GraphQL search and pages
        through every result instead of refusing past one page.
        """

        if not isinstance(login, str) or not _GITHUB_LOGIN.fullmatch(login):
            raise ValueError("GitHub login is not safe for an authored pull-request search")
        if not head_ref_prefix:
            raise ValueError("authored pull-request search needs a head branch prefix")
        qualifiers = ["is:pr", f"author:{login}"]
        if state is not None:
            qualifiers.append(f"is:{state}")
        if updated_after is not None:
            qualifiers.append(f"updated:>={_canonical_date(updated_after, field='updated_after')}")
        pull_requests: dict[str, AuthoredPullRequest] = {}
        cursor: str | None = None
        for _ in range(_SEARCH_RESULT_LIMIT // 100):
            payload = _mapping(
                self._request(
                    "POST",
                    _graphql_api_path(self.config.api_url),
                    json_body={
                        "query": _AUTHORED_PULL_REQUESTS_QUERY,
                        "variables": {"query": " ".join(qualifiers), "cursor": cursor},
                    },
                ),
                resource="authored pull request search",
            )
            if payload.get("errors") is not None:
                raise GitHubError("GitHub rejected the authored pull-request search")
            search = _mapping(
                _mapping(payload.get("data"), resource="authored search data").get("search"),
                resource="authored search",
            )
            for node in _mapping_list(search.get("nodes"), resource="authored search results"):
                number = _identifier(node.get("number"), resource="searched pull request")
                url, repository = self._canonical_pull_request_url(
                    node.get("url"),
                    expected_repository=None,
                    expected_number=number,
                )
                head_ref = _nonempty(node.get("headRefName"), field="searched head branch")
                if url in pull_requests:
                    raise GitHubError("GitHub authored search returned a duplicate pull request")
                if head_ref.startswith(head_ref_prefix):
                    pull_requests[url] = AuthoredPullRequest(
                        url=url,
                        repository=repository,
                        head_ref=head_ref,
                        created_at=_required_datetime(
                            node.get("createdAt"), field="searched pull request creation time"
                        ),
                        updated_at=_required_datetime(
                            node.get("updatedAt"), field="searched pull request update time"
                        ),
                    )
            page_info = _mapping(search.get("pageInfo"), resource="authored search page")
            has_next_page = page_info.get("hasNextPage")
            if has_next_page is False:
                return list(pull_requests.values())
            if has_next_page is not True:
                raise GitHubError("GitHub returned malformed authored search pagination")
            cursor = _nonempty(page_info.get("endCursor"), field="authored search cursor")
        raise GitHubError(
            f"Authored pull-request search exceeded GitHub's {_SEARCH_RESULT_LIMIT}-result "
            "limit; account publication limits are ambiguous"
        )

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

    def list_directory(
        self,
        repository: str,
        path: str,
        *,
        ref: str,
    ) -> list[DirectoryEntry] | None:
        """List one directory at an immutable ref without descending into subdirectories.

        Returns None when the path is absent or is not a directory.
        """

        immutable_ref = _input_nonempty(ref, field="repository directory ref").casefold()
        if not _GIT_SHA.fullmatch(immutable_ref):
            raise ValueError("repository directory ref must be a full immutable git SHA")
        directory = path.strip("/")
        suffix = f"/{quote(directory, safe='/')}" if directory else ""
        data = self._request(
            "GET",
            f"/repos/{quote(repository, safe='/')}/contents{suffix}",
            params={"ref": immutable_ref},
            allow_not_found=True,
        )
        if not isinstance(data, list):
            return None
        if len(data) >= _MAX_DIRECTORY_ENTRIES:
            raise GitHubError(
                f"GitHub lists at most {_MAX_DIRECTORY_ENTRIES} entries of a directory; the "
                f"listing of {repository}/{directory} may be incomplete"
            )
        entries: list[DirectoryEntry] = []
        seen: set[str] = set()
        for item in _mapping_list(data, resource="repository directory entries"):
            kind = _nonempty(item.get("type"), field="repository directory entry type")
            if kind not in {"file", "dir", "symlink", "submodule"}:
                raise GitHubError("GitHub returned an unsupported repository directory entry type")
            entry_path = _nonempty(item.get("path"), field="repository directory entry path")
            parent, _, name = entry_path.rpartition("/")
            if (
                parent != directory
                or name in {"", ".", ".."}
                or "\\" in entry_path
                or any(ord(character) < 32 for character in entry_path)
            ):
                raise GitHubError("GitHub returned an unsafe repository directory entry path")
            if entry_path in seen:
                raise GitHubError("GitHub returned a duplicate repository directory entry")
            seen.add(entry_path)
            entries.append(DirectoryEntry(path=entry_path, kind=kind))
        return sorted(entries, key=lambda entry: entry.path.casefold())

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

    def compare_commits(self, repository: str, base: str, head: str) -> CommitComparison:
        """Compare two commits by SHA; renames report both their old and new paths."""

        base_sha = _full_git_sha(base, field="comparison base SHA")
        head_sha = _full_git_sha(head, field="comparison head SHA")
        data = _mapping(
            self._request(
                "GET",
                f"/repos/{quote(repository, safe='/')}/compare/{base_sha}...{head_sha}",
            ),
            resource="commit comparison",
        )
        status = data.get("status")
        if status not in {"ahead", "behind", "diverged", "identical"}:
            raise GitHubError("GitHub returned an unsupported commit comparison status")
        listed = data.get("files")
        files = _mapping_list([] if listed is None else listed, resource="compared files")
        paths: set[str] = set()
        for item in files:
            paths.add(_nonempty(item.get("filename"), field="compared file name"))
            previous = item.get("previous_filename")
            if previous is not None:
                paths.add(_nonempty(previous, field="compared previous file name"))
        # GitHub may leave the file list out, and lists no file only for equal trees; without a
        # list that covers the commits, no path is proven unchanged.
        return CommitComparison(
            status=status,
            changed_paths=frozenset(paths),
            complete=(
                listed is not None
                and len(files) < _COMPARE_FILE_LIMIT
                and (bool(files) or data.get("ahead_by") == 0)
            ),
        )

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

    def list_branch_pushes(self, repository: str, branch: str) -> list[BranchPush]:
        """Return the latest updates of one branch, newest first; empty when GitHub has none."""

        ref = f"refs/heads/{_input_nonempty(branch, field='branch')}"
        data = self._request(
            "GET",
            f"/repos/{quote(repository, safe='/')}/activity",
            params={"ref": ref, "per_page": 100},
            allow_not_found=True,
        )
        if data is None:
            return []
        pushes = [
            _parse_branch_push(item) for item in _mapping_list(data, resource="repository activity")
        ]
        if any(push.ref != ref for push in pushes):
            raise GitHubError("GitHub returned activity for a different ref than requested")
        return pushes

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

    def ensure_fork(
        self,
        repository: str,
        fork: str,
        *,
        upstream_repository_id: int,
        before_mutation: Callable[[], None] | None = None,
    ) -> str:
        """Reuse or create ``fork`` and return the name GitHub reports for it.

        GitHub answers a fork request with the account's existing fork of the upstream even
        when it has another name, so callers must compare the returned name.
        """

        existing = self.get_repository_access(fork)
        if existing is not None:
            if (
                existing.fork_parent is None
                or existing.fork_parent.database_id != upstream_repository_id
            ):
                raise GitHubError(f"{fork} already exists but is not a fork of {repository}")
            return existing.identity.full_name
        if before_mutation is not None:
            before_mutation()
        created = _mapping(
            self._request(
                "POST",
                f"/repos/{quote(repository, safe='/')}/forks",
                json_body={"name": fork.split("/", 1)[1], "default_branch_only": True},
            ),
            resource="created fork",
        )
        return _canonical_repository_name(created.get("full_name"))

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
        before_mutation: Callable[[], None] | None = None,
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

        if before_mutation is not None:
            before_mutation()
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
                    # GitHub defines this only for heads in a fork; maintainers already
                    # control a branch in their own repository.
                    **(
                        {"maintainer_can_modify": True}
                        if expected_head_repo.casefold() != repository.casefold()
                        else {}
                    ),
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

    def mark_pull_request_ready_for_review(
        self,
        repository: str,
        number: int,
        *,
        expected_url: str,
        expected_node_id: str,
        expected_head_repository: str,
        expected_head_ref: str,
        expected_head_sha: str,
        before_observation: Callable[[], None] | None = None,
        before_mutation: Callable[[], None] | None = None,
    ) -> PullRequestDetails:
        """Move one exact open draft PR to ready-for-review and verify the result.

        ``before_observation`` may perform remote preflight checks. ``before_mutation`` must be a
        local-only authority check because it runs after the final exact PR observation.
        """

        current = self.get_pull_request(repository, number)
        self._validate_ready_for_review_identity(
            current,
            expected_url=expected_url,
            expected_node_id=expected_node_id,
            expected_head_repository=expected_head_repository,
            expected_head_ref=expected_head_ref,
            expected_head_sha=expected_head_sha,
        )
        if current.state != "open" or current.merged:
            raise GitHubError("Refusing to mark a non-open pull request ready for review")
        if not current.draft:
            return current

        node_id = _graphql_node_id(expected_node_id)
        if before_observation is not None:
            before_observation()
        # The preflight can perform remote repository-ID checks. Re-read the immutable PR node
        # after those checks so only a local authority check remains before the GraphQL mutation.
        current = self.get_pull_request(repository, number)
        self._validate_ready_for_review_identity(
            current,
            expected_url=expected_url,
            expected_node_id=node_id,
            expected_head_repository=expected_head_repository,
            expected_head_ref=expected_head_ref,
            expected_head_sha=expected_head_sha,
        )
        if current.state != "open" or current.merged:
            raise GitHubError("Refusing to mark a pull request whose state changed")
        if not current.draft:
            return current
        # Keep the dispatch-boundary callback local-only: another network request here would
        # reopen a window for head drift after the final exact PR observation.
        if before_mutation is not None:
            before_mutation()
        payload = _mapping(
            self._request(
                "POST",
                _graphql_api_path(self.config.api_url),
                json_body={
                    "query": (
                        "mutation MarkPullRequestReadyForReview($pullRequestId: ID!) { "
                        "markPullRequestReadyForReview(input: {pullRequestId: $pullRequestId}) { "
                        "pullRequest { id number url isDraft headRefOid } } }"
                    ),
                    "variables": {"pullRequestId": node_id},
                },
            ),
            resource="ready-for-review mutation",
        )
        if payload.get("errors") is not None:
            raise GitHubError("GitHub rejected the ready-for-review mutation")
        data = _mapping(payload.get("data"), resource="ready-for-review mutation data")
        result = _mapping(
            data.get("markPullRequestReadyForReview"),
            resource="ready-for-review mutation result",
        )
        returned = _mapping(
            result.get("pullRequest"),
            resource="ready-for-review pull request",
        )
        returned_number = _identifier(
            returned.get("number"), resource="ready-for-review pull request"
        )
        returned_sha = _full_git_sha(
            returned.get("headRefOid"),
            field="ready-for-review pull request head SHA",
        )
        if (
            _graphql_node_id(returned.get("id")) != node_id
            or returned_number != number
            or _nonempty(returned.get("url"), field="ready-for-review pull request URL")
            != expected_url
            or returned.get("isDraft") is not False
            or returned_sha.casefold() != expected_head_sha.casefold()
        ):
            raise GitHubError("GitHub returned a different ready-for-review pull request")

        confirmed = self.get_pull_request(repository, number)
        self._validate_ready_for_review_identity(
            confirmed,
            expected_url=expected_url,
            expected_node_id=node_id,
            expected_head_repository=expected_head_repository,
            expected_head_ref=expected_head_ref,
            expected_head_sha=expected_head_sha,
        )
        if confirmed.state != "open" or confirmed.merged or confirmed.draft:
            raise GitHubError("GitHub did not confirm the pull request is ready for review")
        return confirmed

    def _validate_ready_for_review_identity(
        self,
        details: PullRequestDetails,
        *,
        expected_url: str,
        expected_node_id: str,
        expected_head_repository: str,
        expected_head_ref: str,
        expected_head_sha: str,
    ) -> None:
        if details.html_url != expected_url:
            raise GitHubError("Refusing to update a pull request with a different canonical URL")
        if details.node_id != _graphql_node_id(expected_node_id):
            raise GitHubError("Refusing to update a different pull-request node")
        self._validate_compensation_pull_request(
            details,
            expected_head_repository=expected_head_repository,
            expected_head_ref=expected_head_ref,
            expected_head_sha=expected_head_sha,
        )

    def close_pull_request(
        self,
        repository: str,
        number: int,
        *,
        expected_node_id: str,
        expected_head_repository: str,
        expected_head_ref: str,
        expected_head_sha: str,
        before_observation: Callable[[], None] | None = None,
        before_mutation: Callable[[], None] | None = None,
    ) -> PullRequestDetails:
        """Close only an exact, unmerged PR and verify the resulting remote state.

        This is a narrow compensation primitive.  It deliberately re-reads the PR immediately
        before the immutable-node GraphQL mutation and validates the response again so a caller
        cannot close an object merely because it has the expected PR number.

        ``before_observation`` may perform remote preflight checks. ``before_mutation`` must be a
        local-only authority check because it runs after the final exact PR observation.
        """

        expected_repository = _input_nonempty(
            expected_head_repository,
            field="compensation head repository",
        )
        if not _REPOSITORY_NAME.fullmatch(expected_repository):
            raise ValueError("compensation head repository must use owner/name syntax")
        expected_pull_request_node_id = _graphql_node_id(expected_node_id)
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
            expected_node_id=expected_pull_request_node_id,
            expected_head_repository=expected_repository,
            expected_head_ref=expected_ref,
            expected_head_sha=expected_sha,
        )
        if current.merged:
            raise GitHubError("Refusing to close a pull request that has already been merged")
        if current.state == "closed":
            return current
        expected_url, _ = self._canonical_pull_request_url(
            current.html_url,
            expected_repository=repository,
            expected_number=number,
        )

        if before_observation is not None:
            before_observation()
        # The preflight may perform remote repository-ID checks. Re-read the immutable PR node
        # after those checks so only a local authority check remains before the mutation.
        current = self.get_pull_request(repository, number)
        self._validate_compensation_pull_request(
            current,
            expected_node_id=expected_pull_request_node_id,
            expected_head_repository=expected_repository,
            expected_head_ref=expected_ref,
            expected_head_sha=expected_sha,
        )
        if current.merged or current.state != "open":
            raise GitHubError("Refusing to close a pull request whose state changed")
        if current.html_url != expected_url:
            raise GitHubError("Refusing to close a pull request whose canonical URL changed")
        # As with ready-for-review, keep this dispatch-boundary callback local-only.
        if before_mutation is not None:
            before_mutation()
        payload = _mapping(
            self._request(
                "POST",
                _graphql_api_path(self.config.api_url),
                json_body={
                    "query": (
                        "mutation ClosePullRequest($pullRequestId: ID!) { "
                        "closePullRequest(input: {pullRequestId: $pullRequestId}) { "
                        "pullRequest { id number url state merged headRefOid } } }"
                    ),
                    "variables": {"pullRequestId": expected_pull_request_node_id},
                },
            ),
            resource="close pull-request mutation",
        )
        if payload.get("errors") is not None:
            raise GitHubError("GitHub rejected the close pull-request mutation")
        mutation_data = _mapping(
            payload.get("data"),
            resource="close pull-request mutation data",
        )
        result = _mapping(
            mutation_data.get("closePullRequest"),
            resource="close pull-request mutation result",
        )
        returned = _mapping(
            result.get("pullRequest"),
            resource="closed pull request",
        )
        returned_number = _identifier(returned.get("number"), resource="closed pull request")
        returned_sha = _full_git_sha(
            returned.get("headRefOid"),
            field="closed pull request head SHA",
        )
        if (
            _graphql_node_id(returned.get("id")) != expected_pull_request_node_id
            or returned_number != number
            or _nonempty(returned.get("url"), field="closed pull request URL") != expected_url
            or returned.get("state") != "CLOSED"
            or returned.get("merged") is not False
            or returned_sha.casefold() != expected_sha
        ):
            raise GitHubError("GitHub returned a different closed pull request")

        closed = self.get_pull_request(repository, number)
        self._validate_compensation_pull_request(
            closed,
            expected_node_id=expected_pull_request_node_id,
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
        if canonical_url != expected_url:
            raise GitHubError("GitHub confirmed a different canonical pull-request URL")
        return replace(closed, html_url=canonical_url)

    def _validate_compensation_pull_request(
        self,
        details: PullRequestDetails,
        *,
        expected_node_id: str | None = None,
        expected_head_repository: str,
        expected_head_ref: str,
        expected_head_sha: str,
    ) -> None:
        if expected_node_id is not None and details.node_id != expected_node_id:
            raise GitHubError("Refusing to close a different pull-request node")
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


def _search_label(label: str) -> str:
    if '"' in label or not label.isprintable():
        raise ValueError(f"label cannot be quoted in a GitHub search: {label!r}")
    return f'"{label}"'


def _issue_reference_pattern(repository: str, issue_number: int) -> str:
    reference_end = r"(?![A-Za-z0-9])"
    local = rf"(?<![A-Za-z0-9_./#-])\#{issue_number}{reference_end}"
    qualified = rf"(?<![A-Za-z0-9_./-]){re.escape(repository)}\#{issue_number}{reference_end}"
    canonical_url = (
        rf"https://github\.com/{re.escape(repository)}/issues/{issue_number}{reference_end}"
    )
    return rf"(?:{canonical_url}|{qualified}|{local})"


def _explicit_issue_reference(text: str, repository: str, issue_number: int) -> bool:
    """Match GitHub issue references without treating #42 as a prefix of #420."""

    pattern = _issue_reference_pattern(repository, issue_number)
    return re.search(pattern, text, re.IGNORECASE) is not None


def _closes_issue(text: str, repository: str, issue_number: int) -> bool:
    """Whether the text links the issue with a GitHub closing keyword, as in "Fixes #42"."""

    keyword = r"\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?):?\s+"
    pattern = keyword + _issue_reference_pattern(repository, issue_number)
    return re.search(pattern, text, re.IGNORECASE) is not None


def _linked_pull_request(
    item: dict[str, Any],
    *,
    html_url: str,
    repository: str,
    issue_number: int,
) -> LinkedPullRequest:
    title = _optional_string(item.get("title"), field="linked pull request title")
    body = _optional_string(item.get("body"), field="linked pull request body")
    return LinkedPullRequest(
        html_url=html_url,
        updated_at=_required_datetime(
            item.get("updated_at"), field="linked pull request updated_at"
        ),
        closes_issue=_closes_issue(f"{title}\n{body}", repository, issue_number),
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


def _parse_branch_push(data: dict[str, Any]) -> BranchPush:
    actor = data.get("actor")
    login = actor.get("login") if isinstance(actor, dict) else None
    return BranchPush(
        ref=_nonempty(data.get("ref"), field="activity ref"),
        activity_type=_nonempty(data.get("activity_type"), field="activity type"),
        before=_full_git_sha(data.get("before"), field="activity before SHA"),
        after=_full_git_sha(data.get("after"), field="activity after SHA"),
        actor_login=(
            login
            if isinstance(login, str) and _GITHUB_LOGIN.fullmatch(login.removesuffix("[bot]"))
            else None
        ),
    )


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
        node_id=_graphql_node_id(data.get("node_id")),
    )


def _parse_repository_identity(
    data: dict[str, Any],
    *,
    resource: str,
) -> RepositoryIdentity:
    return RepositoryIdentity(
        full_name=_canonical_repository_name(data.get("full_name")),
        database_id=_identifier(data.get("id"), resource=resource),
        node_id=_graphql_node_id(data.get("node_id")),
    )


def _parse_account(data: dict[str, Any]) -> GitHubAccount:
    login = data.get("login")
    if not isinstance(login, str) or not _GITHUB_LOGIN.fullmatch(login):
        raise GitHubError("GitHub returned an invalid account login")
    return GitHubAccount(login=login, database_id=_identifier(data.get("id"), resource="account"))


def _graphql_node_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 256
        or any(not character.isprintable() for character in value)
    ):
        raise GitHubError("GitHub returned an invalid GraphQL node identifier")
    return value


def _graphql_api_path(value: object) -> str:
    parsed = urlparse(str(value))
    path = parsed.path.rstrip("/")
    if parsed.hostname == "api.github.com" and not path:
        return canonical_api_origin(value) + "/graphql"
    if path.casefold().endswith("/api/v3"):
        return canonical_api_origin(value) + path[: -len("/v3")] + "/graphql"
    raise ConfigurationError(
        "GitHub API URL does not expose a recognized GraphQL endpoint for ready-for-review"
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
    )


def _parse_commit_status(data: dict[str, Any]) -> CommitStatusDetails:
    state = _nonempty(data.get("state"), field="commit status state").casefold()
    if state not in {"error", "failure", "pending", "success"}:
        raise GitHubError("GitHub returned an unsupported commit status state")
    return CommitStatusDetails(
        identifier=_identifier(data.get("id"), resource="commit status"),
        context=_nonempty(data.get("context"), field="commit status context"),
        state=state,
        target_url=_optional_string(data.get("target_url"), field="commit status target URL"),
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
        locked=data.get("locked") is True,
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


def _path_template(path: str) -> str:
    """The API path with owner, repository, number, SHA, file and ref names replaced."""

    parts = path.split("?", 1)[0].strip("/").split("/")
    first_resource = 1
    if parts[0] == "repos" and len(parts) >= 3:
        parts[1:3] = ["{owner}", "{repo}"]
        first_resource = 3
    elif parts[0] in {"orgs", "users"} and len(parts) >= 2:
        parts[1] = "{owner}"
        first_resource = 2
    for index in range(first_resource, len(parts)):
        if parts[index - 1] in _FREE_FORM_PATH_RESOURCES:
            parts[index:] = ["{name}"]
            break
        if parts[index].isdigit():
            parts[index] = "{number}"
        elif _GIT_SHA.fullmatch(parts[index]):
            parts[index] = "{sha}"
    return "/" + "/".join(parts)


def _retry_after_seconds(response: httpx.Response) -> float | None:
    retry_after = response.headers.get("Retry-After")
    if retry_after is None:
        return None
    try:
        return max(1.0, float(int(retry_after.strip())))
    except ValueError:
        return None


def _error_message(response: httpx.Response) -> str:
    """Join GitHub's message with its per-field validation errors, bounded."""

    message = _response_message(response)
    try:
        payload = response.json()
    except ValueError:
        return message
    errors = payload.get("errors") if isinstance(payload, dict) else None
    if not isinstance(errors, list):
        return message
    details = [
        str(error["message"])
        for error in errors
        if isinstance(error, dict) and error.get("message") is not None
    ]
    return "; ".join(part for part in (message, *details) if part)[:1_000]


def _rate_limit_wait_seconds(response: httpx.Response, attempt: int) -> float:
    """Compute how long GitHub asked us to wait, from its most specific signal."""

    retry_after = _retry_after_seconds(response)
    if retry_after is not None:
        return retry_after
    reset = response.headers.get("X-RateLimit-Reset")
    if reset is not None and response.headers.get("X-RateLimit-Remaining") == "0":
        try:
            return max(1.0, float(int(reset.strip())) - datetime.now(UTC).timestamp())
        except ValueError:
            pass
    return _TRANSIENT_BACKOFF_SECONDS[min(attempt, len(_TRANSIENT_BACKOFF_SECONDS)) - 1]


__all__ = [
    "AuthoredPullRequest",
    "BranchPush",
    "CheckRunDetails",
    "CommitComparison",
    "CommitStatusDetails",
    "DirectoryEntry",
    "ForkIdentity",
    "GitHubAccount",
    "GitHubClient",
    "GitHubComment",
    "LinkedPullRequest",
    "PullRequestDetails",
    "PullRequestReference",
    "PullRequestReview",
    "RepositoryAccess",
    "RepositoryIdentity",
    "resolve_github_token",
]
