"""The GitHub Actions runner: its repository, its state branch, and its approval comments.

Every write here goes to the runner repository with the workflow's GITHUB_TOKEN. Upstream
repositories are written only by the publisher, with the publishing token.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import quote

import httpx
from pydantic import ConfigDict, Field

from autocontribute.config import AutocontributeConfig, load_config, starter_placeholders
from autocontribute.doctor import DoctorCheck
from autocontribute.domain import DomainModel, RunManifest, RunStatus
from autocontribute.exceptions import (
    AutocontributeError,
    ConfigurationError,
    GitHubError,
    GitHubHTTPError,
    PolicyError,
    StateError,
)
from autocontribute.lifecycle import LifecycleSyncResult, parse_pull_request_url
from autocontribute.redaction import redact_text
from autocontribute.reporting import GitHubReview, code_span, fenced_block
from autocontribute.store import RunStore

AWAITING_LABEL = "autocontribute:awaiting-approval"
PUBLISHED_LABEL = "autocontribute:published"
STATE_BRANCH = "autocontribute-state"
STATE_ARCHIVE = "state.tar.gz"
PREPARED_FILE = "prepared.json"
PREPARE_WORKFLOW = "prepare.yml"
PUBLISHING_TOKEN_ENV = "AUTOCONTRIBUTE_GITHUB_TOKEN"
MODEL_KEY_ENVS = ("OPENAI_API_KEY", "ANTHROPIC_API_KEY")
TOKEN_URL = "https://github.com/settings/tokens/new?scopes=public_repo&description=autocontribute"
APPROVAL_SYNTAX_REPLY = (
    "Not approved. An approval is a comment that holds only `/approve` and the first 12 "
    "characters of the fingerprint, exactly as the issue shows it. Write a new comment; edited "
    "comments are ignored."
)

_BOT_LOGIN = "github-actions[bot]"
_BOT_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"
_LABELS = (
    (AWAITING_LABEL, "fbca04", "Prepared; the owner approves it with /approve <fingerprint>"),
    (PUBLISHED_LABEL, "0e8a16", "The pull request is open"),
)
_SETUP_MARKER = "<!-- autocontribute:setup -->"
_RUN_MARKER = re.compile(r"<!-- autocontribute:run=([0-9a-f]{16}) -->")
_APPROVE_COMMENT = re.compile(r"/approve ([0-9a-f]{12})\s*")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_ACCOUNT_ID = re.compile(r"^[1-9][0-9]{0,18}$")
_EXPIRY_FORMATS = ("%Y-%m-%d %H:%M:%S %Z", "%Y-%m-%d %H:%M:%S %z")
_EXPIRY_WARNING = timedelta(days=14)
_MAX_LISTED_PAGES = 10
_MAX_READY_RUNS = 200
_PUSH_ATTEMPTS = 3
_MAX_PREPARED_BYTES = 1 << 20
# GitHub refuses files over 100 MiB, and the state branch keeps the archive as one file.
_MAX_ARCHIVE_BYTES = 90 << 20
# Runs whose approval issue stays open: they wait for an approval or for its publication.
_ACTIVE_STATUSES = frozenset(
    {RunStatus.READY_FOR_APPROVAL, RunStatus.APPROVED, RunStatus.SUBMITTING}
)
_APPROVAL_FAILURES = {
    "fingerprint_mismatch": (
        "the fingerprint does not match this run's review, so nothing was approved."
    ),
    "limit": (
        "a publishing limit stopped it. The approval stays; comment the same approval again "
        "later to try once more."
    ),
    "stale": "the run cannot publish as it was approved.",
    "resume_required": (
        "publishing stopped part way. Comment the same approval again to finish it."
    ),
    "safety_stop": "a safety stop is active, so nothing was published.",
    "error": "publishing failed.",
}

_Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
_RunId = Annotated[str, Field(pattern=r"^[0-9a-f]{16}$")]
_HttpsUrl = Annotated[str, Field(pattern=r"^https://[\x21-\x7e]{1,500}$")]


@dataclass(frozen=True, slots=True)
class RunnerContext:
    """The runner repository as the Actions environment describes it."""

    repository: str
    owner: str
    owner_id: int
    api_url: str
    step_summary: Path | None

    @classmethod
    def from_environment(cls, environ: Mapping[str, str]) -> RunnerContext:
        repository = environ.get("GITHUB_REPOSITORY", "")
        owner = environ.get("GITHUB_REPOSITORY_OWNER", "")
        owner_id = environ.get("GITHUB_REPOSITORY_OWNER_ID", "")
        api_url = environ.get("GITHUB_API_URL") or "https://api.github.com"
        if (
            not _REPOSITORY.fullmatch(repository)
            or repository.split("/", 1)[0].casefold() != owner.casefold()
            or not _ACCOUNT_ID.fullmatch(owner_id)
        ):
            raise ConfigurationError(
                "GITHUB_REPOSITORY, GITHUB_REPOSITORY_OWNER and GITHUB_REPOSITORY_OWNER_ID must "
                "describe the runner repository; run this command in a GitHub Actions job"
            )
        if not api_url.startswith("https://"):
            raise ConfigurationError("GITHUB_API_URL must use HTTPS")
        summary = environ.get("GITHUB_STEP_SUMMARY")
        return cls(
            repository=repository,
            owner=owner,
            owner_id=int(owner_id),
            api_url=api_url.rstrip("/"),
            step_summary=Path(summary) if summary else None,
        )

    def summarize(self, markdown: str) -> None:
        """Add Markdown to the job summary that the Actions run page shows."""

        if self.step_summary is not None:
            with self.step_summary.open("a", encoding="utf-8") as summary:
                summary.write(markdown.rstrip("\n") + "\n\n")


def runner_token(environ: Mapping[str, str]) -> str:
    """The workflow's GITHUB_TOKEN, which every runner-repository write uses."""

    token = environ.get("GH_TOKEN", "")
    if not token:
        raise ConfigurationError("GH_TOKEN must hold the workflow's GITHUB_TOKEN")
    return token


def load_runner_config(path: Path, *, owner: str) -> AutocontributeConfig:
    """Load the runner's configuration and bind publishing to the runner repository's owner.

    Jobs without the publishing token prepare and render reviews for this login, and approve
    and publish require the token to belong to it.
    """

    settings = load_config(path)
    if settings.github.auth != "token":
        raise ConfigurationError(
            "github.auth must be token in a runner, because the workflows pass the tokens"
        )
    login = settings.publishing.login
    if login and login.casefold() != owner.casefold():
        raise ConfigurationError(
            f"publishing.login is {login}, but {owner} owns the runner repository; leave it empty"
        )
    settings.publishing.login = owner
    return settings


@dataclass(frozen=True, slots=True)
class RunnerIssue:
    number: int
    is_open: bool
    labels: frozenset[str]
    first_line: str

    @property
    def run_id(self) -> str | None:
        match = _RUN_MARKER.fullmatch(self.first_line)
        return match.group(1) if match else None


@dataclass(frozen=True, slots=True)
class RunnerComment:
    author_id: int | None
    body: str
    created_at: str
    updated_at: str


class RunnerRepository:
    """Issues, labels, workflows and branches of the runner repository, through GITHUB_TOKEN."""

    def __init__(
        self,
        context: RunnerContext,
        token: str,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._prefix = f"/repos/{context.repository}"
        self._client = httpx.Client(
            base_url=context.api_url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "autocontribute-runner",
            },
            timeout=30,
            follow_redirects=False,
            transport=transport,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> RunnerRepository:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str | int] | None = None,
        body: dict[str, object] | None = None,
        allow_not_found: bool = False,
    ) -> Any:
        try:
            response = self._client.request(
                method, f"{self._prefix}{path}", params=params, json=body
            )
        except httpx.HTTPError as exc:
            raise GitHubError(f"GitHub request failed: {method} {path}: {exc}") from exc
        if response.status_code == 404 and allow_not_found:
            return None
        if not 200 <= response.status_code < 300:
            request_id = response.headers.get("X-GitHub-Request-Id", "unknown")
            message = _response_message(response)
            raise GitHubHTTPError(
                f"GitHub returned {response.status_code} for {method} {path} "
                f"(request {request_id}): {message}",
                status_code=response.status_code,
                request_id=request_id,
                github_message=message,
            )
        if not response.content:
            return None
        try:
            return response.json()
        except ValueError as exc:
            raise GitHubError(f"GitHub returned invalid JSON for {method} {path}") from exc

    def _pages(self, path: str, params: dict[str, str | int]) -> Iterator[dict[str, Any]]:
        for page in range(1, _MAX_LISTED_PAGES + 1):
            items = self._request("GET", path, params={**params, "per_page": 100, "page": page})
            if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
                raise GitHubError(f"GitHub returned an unexpected list for {path}")
            yield from items
            if len(items) < 100:
                return
        raise GitHubError(f"{path} has more than {_MAX_LISTED_PAGES * 100} entries")

    def ensure_label(self, name: str, color: str, description: str) -> None:
        path = f"/labels/{quote(name, safe='')}"
        fields: dict[str, object] = {"color": color, "description": description}
        if self._request("GET", path, allow_not_found=True) is None:
            self._request("POST", "/labels", body={"name": name, **fields})
        else:
            self._request("PATCH", path, body=fields)

    def issues(self) -> list[RunnerIssue]:
        """Every issue the runner's workflows opened, open or closed, oldest first."""

        found: list[RunnerIssue] = []
        for item in self._pages(
            "/issues",
            {"creator": _BOT_LOGIN, "state": "all", "sort": "created", "direction": "asc"},
        ):
            if item.get("pull_request") is not None:
                continue
            number = _integer(item.get("number"))
            labels = item.get("labels")
            body = item.get("body") or ""
            if number is None or not isinstance(labels, list) or not isinstance(body, str):
                raise GitHubError("GitHub returned an issue without a number, labels or body")
            found.append(
                RunnerIssue(
                    number=number,
                    is_open=item.get("state") == "open",
                    labels=frozenset(
                        str(label.get("name")) for label in labels if isinstance(label, dict)
                    ),
                    first_line=body.split("\n", 1)[0].strip(),
                )
            )
        return found

    def create_issue(self, title: str, body: str) -> int:
        created = self._request("POST", "/issues", body={"title": title, "body": body})
        number = _integer(created.get("number")) if isinstance(created, dict) else None
        if number is None:
            raise GitHubError("GitHub created an issue but returned no number")
        return number

    def edit_issue_body(self, number: int, body: str) -> None:
        self._request("PATCH", f"/issues/{number}", body={"body": body})

    def close_issue(self, number: int, *, completed: bool) -> None:
        reason = "completed" if completed else "not_planned"
        self._request(
            "PATCH", f"/issues/{number}", body={"state": "closed", "state_reason": reason}
        )

    def lock_issue(self, number: int) -> None:
        self._request("PUT", f"/issues/{number}/lock", body={})

    def add_label(self, number: int, label: str) -> None:
        self._request("POST", f"/issues/{number}/labels", body={"labels": [label]})

    def remove_label(self, number: int, label: str) -> None:
        self._request(
            "DELETE", f"/issues/{number}/labels/{quote(label, safe='')}", allow_not_found=True
        )

    def comment(self, number: int, body: str) -> None:
        self._request("POST", f"/issues/{number}/comments", body={"body": body})

    def comment_bodies(self, number: int) -> list[str]:
        return [
            str(item.get("body") or "") for item in self._pages(f"/issues/{number}/comments", {})
        ]

    def get_comment(self, comment_id: int) -> RunnerComment | None:
        data = self._request("GET", f"/issues/comments/{comment_id}", allow_not_found=True)
        if data is None:
            return None
        if not isinstance(data, dict):
            raise GitHubError("GitHub returned an unexpected comment")
        user = data.get("user")
        return RunnerComment(
            author_id=_integer(user.get("id")) if isinstance(user, dict) else None,
            body=str(data.get("body") or ""),
            created_at=str(data.get("created_at")),
            updated_at=str(data.get("updated_at")),
        )

    def set_workflow_enabled(self, workflow: str, *, enabled: bool) -> None:
        action = "enable" if enabled else "disable"
        self._request("PUT", f"/actions/workflows/{quote(workflow, safe='')}/{action}")

    def has_branch(self, branch: str) -> bool:
        ref = f"/git/ref/heads/{quote(branch, safe='')}"
        return self._request("GET", ref, allow_not_found=True) is not None

    def create_orphan_branch(self, branch: str, files: Mapping[str, str], message: str) -> None:
        """Create ``branch`` as one commit without parents that holds only ``files``."""

        tree = self._request(
            "POST",
            "/git/trees",
            body={
                "tree": [
                    {"path": path, "mode": "100644", "type": "blob", "content": content}
                    for path, content in sorted(files.items())
                ]
            },
        )
        commit = self._request(
            "POST",
            "/git/commits",
            body={"message": message, "tree": _sha(tree), "parents": []},
        )
        self._request(
            "POST", "/git/refs", body={"ref": f"refs/heads/{branch}", "sha": _sha(commit)}
        )


class StateBranch:
    """A checkout of the state branch, made without credentials, that this job may push to."""

    def __init__(self, checkout: Path, *, token: str | None) -> None:
        self.checkout = checkout
        self._token = token

    @property
    def archive(self) -> Path:
        return self.checkout / STATE_ARCHIVE

    def archive_sha256(self) -> str | None:
        """The SHA-256 of the saved state, or None before any state was saved."""

        try:
            mode = self.archive.lstat().st_mode
        except FileNotFoundError:
            return None
        if not stat.S_ISREG(mode):
            raise StateError(f"{self.archive} is not a regular file")
        return file_sha256(self.archive)

    def save(self, archive: Path, *, message: str) -> bool:
        """Commit ``archive`` as the state when it differs, then push it without force.

        A rejected push is rebased onto the branch and tried again. A rebase that conflicts
        means another job saved state after this one read it, and that state must not be lost.
        """

        if self.archive_sha256() == file_sha256(archive):
            return False
        shutil.copyfile(archive, self.archive)
        self._git("add", "--", STATE_ARCHIVE)
        self._git("commit", "--quiet", "--message", message)
        for _ in range(_PUSH_ATTEMPTS):
            try:
                self._git("push", "--quiet", "origin", f"HEAD:refs/heads/{STATE_BRANCH}")
            except _PushRejected:
                self._git("fetch", "--quiet", "origin", STATE_BRANCH)
                try:
                    self._git("rebase", "--quiet", "FETCH_HEAD")
                except StateError as exc:
                    self._git("rebase", "--abort")
                    raise StateError(
                        "Another job saved the state while this one ran, so this job's state "
                        "was not saved; run this job again"
                    ) from exc
            else:
                return True
        raise StateError(f"The {STATE_BRANCH} branch kept changing; the state was not saved")

    def _git(self, *arguments: str) -> None:
        with _askpass(self._token) as credentials:
            environment = {
                **_git_environment(),
                **credentials,
                "GIT_AUTHOR_NAME": _BOT_LOGIN,
                "GIT_AUTHOR_EMAIL": _BOT_EMAIL,
                "GIT_COMMITTER_NAME": _BOT_LOGIN,
                "GIT_COMMITTER_EMAIL": _BOT_EMAIL,
            }
            try:
                result = subprocess.run(
                    [
                        "git",
                        "-c",
                        "core.hooksPath=/dev/null",
                        "-c",
                        "commit.gpgsign=false",
                        *arguments,
                    ],
                    cwd=self.checkout,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=300,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise StateError(f"git {arguments[0]} failed to run: {type(exc).__name__}") from exc
        if result.returncode == 0:
            return
        detail = redact_text((result.stderr or result.stdout).strip())[:1_000]
        if arguments[0] == "push" and re.search(
            r"\[rejected\].*\((?:fetch first|non-fast-forward)\)", detail
        ):
            raise _PushRejected(detail)
        raise StateError(f"git {arguments[0]} failed: {detail}")


class _PushRejected(StateError):
    """The remote branch moved since this checkout was made."""


class _PreparedData(DomainModel):
    # The prepare job runs repository code, so its output is read as untrusted data.
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class AttentionItem(_PreparedData):
    """A signal on a published pull request that the owner should look at."""

    run_id: _RunId
    pull_request_url: _HttpsUrl
    kind: Annotated[str, Field(pattern=r"^[a-z_]{1,40}$")]
    reason: Annotated[str, Field(min_length=1, max_length=1_000)]
    source_url: _HttpsUrl
    key: _Sha256


class PreparedState(_PreparedData):
    """What the prepare job hands the record job, next to the state archive."""

    format: Literal["autocontribute.prepared.v1"] = "autocontribute.prepared.v1"
    # The state this preparation started from; None when no state had been saved yet.
    base_state_sha256: _Sha256 | None
    state_sha256: _Sha256
    run_id: _RunId | None
    attention: tuple[AttentionItem, ...] = Field(default=(), max_length=200)


def write_prepared(output: Path, prepared: PreparedState) -> None:
    (output / PREPARED_FILE).write_text(prepared.model_dump_json(indent=2) + "\n", encoding="utf-8")


def read_prepared(directory: Path) -> tuple[PreparedState, Path]:
    """Check the prepare job's output: exactly two bounded regular files that agree."""

    if directory.is_symlink() or not directory.is_dir():
        raise StateError(f"{directory} is not a directory")
    names = sorted(entry.name for entry in directory.iterdir())
    if names != sorted([PREPARED_FILE, STATE_ARCHIVE]):
        raise StateError(
            f"The prepared output must hold only {PREPARED_FILE} and {STATE_ARCHIVE}, not {names!r}"
        )
    for name, limit in ((PREPARED_FILE, _MAX_PREPARED_BYTES), (STATE_ARCHIVE, _MAX_ARCHIVE_BYTES)):
        info = (directory / name).lstat()
        if not stat.S_ISREG(info.st_mode):
            raise StateError(f"The prepared {name} is not a regular file")
        if info.st_size > limit:
            raise StateError(f"The prepared {name} is larger than {limit:,} bytes")
    try:
        prepared = PreparedState.model_validate_json((directory / PREPARED_FILE).read_bytes())
    except ValueError as exc:
        raise StateError(f"The prepared {PREPARED_FILE} is not valid: {exc}") from exc
    archive = directory / STATE_ARCHIVE
    if file_sha256(archive) != prepared.state_sha256:
        raise StateError(f"The prepared {STATE_ARCHIVE} does not match {PREPARED_FILE}")
    return prepared, archive


def attention_items(
    result: LifecycleSyncResult, published: Sequence[RunManifest]
) -> tuple[AttentionItem, ...]:
    """Pair each lifecycle signal with the published run whose pull request it concerns."""

    runs: dict[tuple[str, int], RunManifest] = {}
    for run in published:
        if run.pull_request_url and run.publishing_api_origin:
            repository, number = parse_pull_request_url(
                run.pull_request_url, api_origin=run.publishing_api_origin
            )
            runs[(repository.casefold(), number)] = run
    items: list[AttentionItem] = []
    for observation in result.observations:
        for signal in observation.signals:
            manifest = runs.get((signal.repository.casefold(), signal.pull_request_number))
            if manifest is None or manifest.pull_request_url is None:
                continue
            items.append(
                AttentionItem(
                    run_id=manifest.run_id,
                    pull_request_url=manifest.pull_request_url,
                    kind=signal.kind.value,
                    reason=signal.reason,
                    source_url=signal.source_url,
                    key=signal.trigger_hash(),
                )
            )
    return tuple(items)


@dataclass(frozen=True, slots=True)
class ApprovalComment:
    """An owner's comment on an approval issue, checked against the event that delivered it."""

    comment_id: int
    run_id: str
    # None when the comment is not exactly ``/approve`` and a 12-character fingerprint prefix.
    fingerprint_prefix: str | None
    url: str
    body: str
    created_at: str


def read_approval_event(
    path: Path,
    context: RunnerContext,
    *,
    issue_number: int,
    comment_id: int,
) -> ApprovalComment:
    """Check every condition of the approve workflow again, from the event file itself."""

    try:
        event = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PolicyError(f"The event file cannot be read: {exc}") from exc
    if not isinstance(event, dict):
        raise PolicyError("The event file is not a JSON object")
    repository = _mapping(event.get("repository"))
    issue = _mapping(event.get("issue"))
    issue_author = _mapping(issue.get("user"))
    comment = _mapping(event.get("comment"))
    commenter = _mapping(comment.get("user"))
    labels = issue.get("labels")
    created_at = comment.get("created_at")
    conditions = (
        (event.get("action") == "created", "the comment was not just created"),
        (
            str(repository.get("full_name")).casefold() == context.repository.casefold()
            and _integer(_mapping(repository.get("owner")).get("id")) == context.owner_id,
            "the event belongs to another repository",
        ),
        (_integer(issue.get("number")) == issue_number, "--issue differs from the event"),
        (_integer(comment.get("id")) == comment_id, "--comment-id differs from the event"),
        (issue.get("pull_request") is None, "the comment is on a pull request"),
        (issue.get("state") == "open", "the issue is closed"),
        (
            issue_author.get("login") == _BOT_LOGIN and issue_author.get("type") == "Bot",
            "the runner's workflows did not open the issue",
        ),
        (
            isinstance(labels, list)
            and any(
                isinstance(label, dict) and label.get("name") == AWAITING_LABEL for label in labels
            ),
            "the issue is not awaiting approval",
        ),
        (
            _integer(commenter.get("id")) == context.owner_id
            and comment.get("author_association") == "OWNER",
            "the repository owner did not write the comment",
        ),
        (
            isinstance(created_at, str) and comment.get("updated_at") == created_at,
            "the comment was edited",
        ),
    )
    for passed, reason in conditions:
        if not passed:
            raise PolicyError(f"Not an approval: {reason}")
    issue_body = issue.get("body")
    marker = _RUN_MARKER.fullmatch(
        issue_body.split("\n", 1)[0].strip() if isinstance(issue_body, str) else ""
    )
    if marker is None:
        raise PolicyError("Not an approval: the issue does not name a run")
    body = comment.get("body")
    url = comment.get("html_url")
    if not isinstance(body, str) or not isinstance(url, str) or not url.startswith("https://"):
        raise PolicyError("Not an approval: the comment has no body or URL")
    command = _APPROVE_COMMENT.fullmatch(body)
    assert isinstance(created_at, str)
    return ApprovalComment(
        comment_id=comment_id,
        run_id=marker.group(1),
        fingerprint_prefix=command.group(1) if command else None,
        url=url,
        body=body,
        created_at=created_at,
    )


def confirm_comment_unchanged(
    repository: RunnerRepository, approval: ApprovalComment, *, owner_id: int
) -> None:
    """The comment must still read as it did when the event fired, and never have been edited."""

    current = repository.get_comment(approval.comment_id)
    if current is None:
        raise PolicyError("Not an approval: the comment was deleted")
    if (
        current.body != approval.body
        or current.author_id != owner_id
        or current.created_at != approval.created_at
        or current.updated_at != current.created_at
    ):
        raise PolicyError("Not an approval: the comment changed after it was posted")


def report_approval(
    repository: RunnerRepository,
    number: int,
    store: RunStore,
    run_id: str,
    *,
    outcome: str,
    message: str,
    save_error: str | None,
) -> None:
    """Answer an approval on its issue: announce the pull request, or say why there is none."""

    manifest = _saved_run(store, run_id)
    if manifest is not None and manifest.status == RunStatus.PR_OPEN and manifest.pull_request_url:
        _mark_published(repository, number, manifest.pull_request_url)
    else:
        explanation = _APPROVAL_FAILURES.get(outcome, _APPROVAL_FAILURES["error"])
        repository.comment(
            number, f"Not published: {explanation}\n\n{fenced_block(message, 'text')}"
        )
        if manifest is None or manifest.status not in _ACTIVE_STATUSES:
            repository.remove_label(number, AWAITING_LABEL)
            repository.close_issue(number, completed=False)
    if save_error is not None:
        repository.comment(
            number,
            "The runner's state was not saved, so re-run this approve job from the Actions tab:"
            f"\n\n{fenced_block(save_error, 'text')}",
        )


def check_runner(
    config: Path,
    context: RunnerContext,
    environ: Mapping[str, str],
    *,
    now: datetime,
    transport: httpx.BaseTransport | None = None,
) -> list[DoctorCheck]:
    """Check what a runner needs before it may prepare anything."""

    present = [name for name in MODEL_KEY_ENVS if environ.get(name)]
    model_key = (
        DoctorCheck("model API key", True, f"{' and '.join(present)} is set")
        if present
        else DoctorCheck(
            "model API key",
            False,
            "add the repository secret OPENAI_API_KEY or ANTHROPIC_API_KEY",
        )
    )
    return [
        model_key,
        publishing_token_check(
            environ.get(PUBLISHING_TOKEN_ENV, ""), context, now=now, transport=transport
        ),
        _config_check(config, context),
        _docker_check(),
        _disk_check(),
    ]


def publishing_token_check(
    token: str,
    context: RunnerContext,
    *,
    now: datetime,
    transport: httpx.BaseTransport | None = None,
) -> DoctorCheck:
    """The publishing token must be a classic token of the owner with only public_repo."""

    name = "publishing token"
    if not token:
        return DoctorCheck(
            name,
            False,
            f"add the repository secret {PUBLISHING_TOKEN_ENV}: a classic token with only the "
            f"public_repo scope, from {TOKEN_URL}",
        )
    with httpx.Client(
        base_url=context.api_url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "autocontribute-runner",
        },
        timeout=30,
        follow_redirects=False,
        transport=transport,
    ) as client:
        try:
            response = client.get("/user")
        except httpx.HTTPError as exc:
            return DoctorCheck(name, False, f"GitHub could not be reached: {type(exc).__name__}")
    if response.status_code != 200:
        return DoctorCheck(
            name,
            False,
            f"GitHub refused {PUBLISHING_TOKEN_ENV} ({response.status_code}); create a new token "
            f"at {TOKEN_URL}",
        )
    try:
        login = response.json().get("login")
    except (ValueError, AttributeError):
        login = None
    if not isinstance(login, str) or login.casefold() != context.owner.casefold():
        return DoctorCheck(
            name,
            False,
            f"the token belongs to {login}, not to {context.owner}, who owns this repository",
        )
    scopes = response.headers.get("X-OAuth-Scopes")
    if scopes is None:
        return DoctorCheck(
            name,
            False,
            "the token is not a classic token; only classic tokens can open pull requests on "
            f"repositories you do not own. Create one at {TOKEN_URL}",
        )
    granted = sorted({scope.strip() for scope in scopes.split(",") if scope.strip()})
    if granted != ["public_repo"]:
        return DoctorCheck(
            name,
            False,
            f"the token has the scopes {', '.join(granted) or 'none'}; it must have only "
            "public_repo",
        )
    header = response.headers.get("GitHub-Authentication-Token-Expiration")
    if header is None:
        return DoctorCheck(
            name, True, f"a classic public_repo token of {login} with no expiry date"
        )
    expiry = _token_expiry(header)
    if expiry is None:
        return DoctorCheck(
            name, True, f"the token's expiry date {header!r} cannot be read", warning=True
        )
    if expiry - now <= _EXPIRY_WARNING:
        return DoctorCheck(
            name,
            True,
            f"the token expires on {expiry:%Y-%m-%d}; create a new one at {TOKEN_URL} before then",
            warning=True,
        )
    return DoctorCheck(
        name, True, f"a classic public_repo token of {login}, valid until {expiry:%Y-%m-%d}"
    )


def apply_setup(
    repository: RunnerRepository,
    context: RunnerContext,
    checks: Sequence[DoctorCheck],
) -> bool:
    """Create the labels and state branch, then turn preparation on only when nothing is missing."""

    for name, color, description in _LABELS:
        repository.ensure_label(name, color, description)
    if not repository.has_branch(STATE_BRANCH):
        # Binary: a line-ending conversion would change the archive the fingerprints rely on.
        repository.create_orphan_branch(
            STATE_BRANCH, {".gitattributes": "* binary\n"}, "Start the autocontribute state"
        )
    complete = all(check.passed for check in checks)
    repository.set_workflow_enabled(PREPARE_WORKFLOW, enabled=complete)
    checklist = _setup_checklist(checks, complete=complete)
    context.summarize(checklist)
    issue = next(
        (
            issue
            for issue in repository.issues()
            if issue.is_open and issue.first_line == _SETUP_MARKER
        ),
        None,
    )
    if complete and issue is not None:
        repository.comment(issue.number, "Setup is complete, and preparation is on.")
        repository.close_issue(issue.number, completed=True)
    elif not complete and issue is not None:
        repository.edit_issue_body(issue.number, checklist)
    elif not complete:
        repository.create_issue("Finish setup", checklist)
    return complete


def sync_issues(
    repository: RunnerRepository,
    store: RunStore,
    *,
    review: Callable[[str], GitHubReview],
    attention: Sequence[AttentionItem],
) -> list[str]:
    """Open an issue per ready run, close the issues of finished runs, and relay attention.

    Returns Markdown lines for the job summary.
    """

    issues = repository.issues()
    by_run: dict[str, list[RunnerIssue]] = {}
    for issue in issues:
        if issue.run_id is not None:
            by_run.setdefault(issue.run_id, []).append(issue)
    lines: list[str] = []
    for manifest in store.list_with_statuses(
        {RunStatus.READY_FOR_APPROVAL}, limit=_MAX_READY_RUNS, resource="ready"
    ):
        existing = [issue for issue in by_run.get(manifest.run_id, []) if issue.is_open]
        if any(AWAITING_LABEL in issue.labels for issue in existing):
            continue
        try:
            rendered = review(manifest.run_id)
        except AutocontributeError as exc:
            lines.append(
                f"- Run {code_span(manifest.run_id)} has no issue yet: {code_span(str(exc))}"
            )
            continue
        # An earlier job stopped before labelling these, so nobody could approve them.
        for incomplete in existing:
            repository.close_issue(incomplete.number, completed=False)
        number = _open_approval_issue(repository, manifest, rendered)
        lines.append(f"- Opened issue #{number} for run {code_span(manifest.run_id)}")
    for issue in issues:
        if not issue.is_open or issue.run_id is None:
            continue
        run = _saved_run(store, issue.run_id)
        if run is not None and run.status in _ACTIVE_STATUSES:
            continue
        if run is not None and run.status == RunStatus.PR_OPEN and run.pull_request_url:
            _mark_published(repository, issue.number, run.pull_request_url)
        else:
            repository.comment(issue.number, _closing_note(issue.run_id, run))
            repository.remove_label(issue.number, AWAITING_LABEL)
            repository.close_issue(issue.number, completed=False)
        lines.append(f"- Closed issue #{issue.number}")
    for item in attention:
        lines.extend(_relay_attention(repository, store, by_run, item))
    return lines


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _mark_published(repository: RunnerRepository, number: int, pull_request_url: str) -> None:
    repository.comment(number, f"Opened {code_span(pull_request_url)}.")
    repository.remove_label(number, AWAITING_LABEL)
    repository.add_label(number, PUBLISHED_LABEL)
    repository.close_issue(number, completed=True)


def _open_approval_issue(
    repository: RunnerRepository, manifest: RunManifest, review: GitHubReview
) -> int:
    candidate = manifest.candidate
    title = f"Approve run {manifest.run_id}"
    if candidate is not None:
        # Plain words, so the title links to nothing upstream.
        title += f": {candidate.repository} issue {candidate.number}"
    number = repository.create_issue(title, review.body)
    for part in review.parts:
        repository.comment(number, part)
    repository.lock_issue(number)
    # The approve workflow acts only on labelled issues, so the label goes on once the issue is
    # complete.
    repository.add_label(number, AWAITING_LABEL)
    return number


def _closing_note(run_id: str, manifest: RunManifest | None) -> str:
    if manifest is None:
        return f"Run {code_span(run_id)} is not in the saved state, so it will not be published."
    note = f"Run {code_span(run_id)} is {manifest.status.value}, so it will not be published."
    reason = manifest.error or manifest.skip_reason
    if reason:
        note += "\n\n" + fenced_block(reason, "text")
    return note


def _relay_attention(
    repository: RunnerRepository,
    store: RunStore,
    by_run: Mapping[str, Sequence[RunnerIssue]],
    item: AttentionItem,
) -> list[str]:
    manifest = _saved_run(store, item.run_id)
    if (
        manifest is None
        or manifest.status != RunStatus.PR_OPEN
        or manifest.pull_request_url != item.pull_request_url
    ):
        return [f"- Ignored attention for run {code_span(item.run_id)}: no such open pull request"]
    issues = by_run.get(item.run_id)
    if not issues:
        return []
    number = max(issue.number for issue in issues)
    marker = f"<!-- autocontribute:attention={item.key} -->"
    if any(body.startswith(marker) for body in repository.comment_bodies(number)):
        return []
    repository.comment(
        number,
        f"{marker}\nThe pull request {code_span(item.pull_request_url)} needs your attention: "
        f"{code_span(item.reason)}\n\nSee {code_span(item.source_url)}. Autocontribute does not "
        "reply to maintainers or push follow-up commits; answer them yourself.",
    )
    return [f"- Posted attention ({item.kind}) on issue #{number}"]


def _saved_run(store: RunStore, run_id: str) -> RunManifest | None:
    try:
        return store.get(run_id)
    except StateError:
        return None


def _setup_checklist(checks: Sequence[DoctorCheck], *, complete: bool) -> str:
    lines = [_SETUP_MARKER, "## Finish setup" if not complete else "## Setup is complete", ""]
    if not complete:
        lines += [
            "Preparation stays off until every item is checked. Fix the open items, then push "
            "to main or run the setup workflow again.",
            "",
        ]
    for check in checks:
        box = "x" if check.passed else " "
        note = " (warning)" if check.warning else ""
        lines.append(f"- [{box}] **{check.name}**{note}: {check.detail}")
    return "\n".join(lines)


def _config_check(path: Path, context: RunnerContext) -> DoctorCheck:
    try:
        settings = load_runner_config(path, owner=context.owner)
    except ConfigurationError as exc:
        return DoctorCheck("configuration", False, str(exc))
    problems = starter_placeholders(settings)
    if not (settings.github.repositories or settings.github.owners):
        problems.append(
            "github.repositories is empty: list the public repositories to contribute to"
        )
    if problems:
        return DoctorCheck("configuration", False, "; ".join(problems))
    return DoctorCheck(
        "configuration",
        True,
        f"{len(settings.github.repositories)} repositories and {len(settings.github.owners)} "
        "owners to search",
    )


def _docker_check() -> DoctorCheck:
    version = _docker_cgroup_version()
    if version is None:
        return DoctorCheck(
            "Docker", False, "`docker info` failed; use a GitHub-hosted ubuntu-24.04 runner"
        )
    if version != "2":
        return DoctorCheck(
            "Docker", False, f"Docker uses cgroup v{version}; sandbox limits need cgroup v2"
        )
    return DoctorCheck("Docker", True, "Docker uses cgroup v2")


def _docker_cgroup_version() -> str | None:
    try:
        result = subprocess.run(
            ["docker", "info", "--format", "{{.CgroupVersion}}"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def _disk_check() -> DoctorCheck:
    usage = shutil.disk_usage("/")
    return DoctorCheck(
        "disk", True, f"{usage.free / 2**30:.0f} GiB free of {usage.total / 2**30:.0f} GiB on /"
    )


def _token_expiry(value: str) -> datetime | None:
    for pattern in _EXPIRY_FORMATS:
        try:
            parsed = datetime.strptime(value.strip(), pattern)
        except ValueError:
            continue
        return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
    return None


@contextmanager
def _askpass(token: str | None) -> Iterator[dict[str, str]]:
    """Hand ``token`` to git through a helper script, so it never appears in arguments."""

    if token is None:
        yield {}
        return
    with tempfile.TemporaryDirectory(prefix="autocontribute-askpass-") as directory:
        script = Path(directory) / "askpass.sh"
        script.write_text(
            "#!/bin/sh\n"
            'case "$1" in\n'
            "  *Username*) printf '%s\\n' x-access-token ;;\n"
            "  *) printf '%s\\n' \"$AUTOCONTRIBUTE_GIT_TOKEN\" ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        script.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        yield {"GIT_ASKPASS": str(script), "AUTOCONTRIBUTE_GIT_TOKEN": token}


def _git_environment() -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", "/nonexistent"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
    }


def _response_message(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return response.text[:200]
    message = payload.get("message") if isinstance(payload, dict) else None
    return str(message)[:500] if message else response.text[:200]


def _sha(value: object) -> str:
    sha = value.get("sha") if isinstance(value, dict) else None
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", sha):
        raise GitHubError("GitHub returned a git object without a SHA")
    return sha


def _mapping(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _integer(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


__all__ = [
    "APPROVAL_SYNTAX_REPLY",
    "AWAITING_LABEL",
    "MODEL_KEY_ENVS",
    "PREPARED_FILE",
    "PUBLISHED_LABEL",
    "PUBLISHING_TOKEN_ENV",
    "STATE_ARCHIVE",
    "STATE_BRANCH",
    "TOKEN_URL",
    "ApprovalComment",
    "AttentionItem",
    "PreparedState",
    "RunnerContext",
    "RunnerRepository",
    "StateBranch",
    "apply_setup",
    "attention_items",
    "check_runner",
    "confirm_comment_unchanged",
    "file_sha256",
    "load_runner_config",
    "publishing_token_check",
    "read_approval_event",
    "read_prepared",
    "report_approval",
    "runner_token",
    "sync_issues",
    "write_prepared",
]
