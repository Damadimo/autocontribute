import json
import os
import re
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from test_cli import _ready_review_run, _ReviewGitHub
from typer.testing import CliRunner

import autocontribute.cli as cli
import autocontribute.runner as runner_module
from autocontribute.cli import app
from autocontribute.doctor import DoctorCheck
from autocontribute.domain import RunManifest, RunStatus
from autocontribute.exceptions import (
    ConfigurationError,
    GitHubHTTPError,
    PolicyError,
    PublicationLimitError,
    StateError,
)
from autocontribute.github import RepositoryAccess, RepositoryIdentity
from autocontribute.lifecycle import (
    LifecycleObservation,
    LifecycleSignal,
    LifecycleSignalKind,
    LifecycleSyncResult,
)
from autocontribute.orchestrator import RunInvocationMode
from autocontribute.reporting import GitHubReview
from autocontribute.runner import (
    AWAITING_LABEL,
    PUBLISHED_LABEL,
    STATE_ARCHIVE,
    AttentionItem,
    PreparedState,
    RunnerContext,
    RunnerRepository,
    StateBranch,
    apply_setup,
    attention_items,
    check_runner,
    confirm_comment_unchanged,
    create_runner_repository,
    file_sha256,
    load_runner_config,
    publishing_token_check,
    read_approval_event,
    read_prepared,
    report_approval,
    sync_issues,
    template_files,
    write_prepared,
)
from autocontribute.state_archive import export_state, import_state
from autocontribute.store import RunStore

cli_runner = CliRunner()
OWNER = "octocat"
OWNER_ID = 583231
RUNNER = f"{OWNER}/runner"
FINGERPRINT_COMMENT = re.compile(r"/approve ([0-9a-f]{12})")
_NOW = datetime(2026, 10, 22, 12, tzinfo=UTC)


class FakeRunnerGitHub:
    """The runner repository's REST API, in memory, for one httpx MockTransport."""

    def __init__(self) -> None:
        self.prefix = f"/repos/{RUNNER}"
        self.labels: dict[str, dict[str, Any]] = {}
        self.issues: dict[int, dict[str, Any]] = {}
        self.comments: dict[int, dict[str, Any]] = {}
        self.workflows: dict[str, bool] = {}
        self.branches: dict[str, list[str]] = {}
        self.requests: list[tuple[str, str]] = []
        self._next_id = 1

    def repository(self, context: RunnerContext, token: str) -> RunnerRepository:
        assert token == "runner-token"
        return RunnerRepository(context, token, transport=httpx.MockTransport(self.handle))

    def add_issue(self, body: str, *, labels: tuple[str, ...] = (), author: str = "") -> int:
        number = self._take_id()
        self.issues[number] = {
            "number": number,
            "title": "seeded",
            "body": body,
            "state": "open",
            "state_reason": None,
            "labels": list(labels),
            "locked": False,
            "user": {"login": author or "github-actions[bot]", "type": "Bot"},
        }
        return number

    def add_comment(self, issue: int, body: str, *, user_id: int = OWNER_ID) -> int:
        identifier = self._take_id()
        self.comments[identifier] = {
            "id": identifier,
            "issue": issue,
            "body": body,
            "user": {"id": user_id, "login": OWNER},
            "created_at": "2026-10-22T10:00:00Z",
            "updated_at": "2026-10-22T10:00:00Z",
            "html_url": f"https://github.com/{RUNNER}/issues/{issue}#issuecomment-{identifier}",
        }
        return identifier

    def issue_comments(self, issue: int) -> list[str]:
        return [comment["body"] for comment in self.comments.values() if comment["issue"] == issue]

    def _take_id(self) -> int:
        identifier = self._next_id
        self._next_id += 1
        return identifier

    def handle(self, request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer runner-token"
        path = request.url.path
        assert path.startswith(self.prefix), path
        route = path.removeprefix(self.prefix)
        method = request.method
        body = json.loads(request.content) if request.content else {}
        self.requests.append((method, route))
        page = int(request.url.params.get("page", "1"))
        if match := re.fullmatch(r"/labels/(.+)", route):
            name = httpx.URL(f"/{match.group(1)}").path[1:]
            if method == "GET":
                return self._found(self.labels.get(name))
            self.labels[name].update(body)
            return httpx.Response(200, json=self.labels[name])
        if route == "/labels":
            self.labels[body["name"]] = body
            return httpx.Response(201, json=body)
        if route == "/issues" and method == "GET":
            assert request.url.params["creator"] == "github-actions[bot]"
            listed = [
                {**issue, "labels": [{"name": name} for name in issue["labels"]]}
                for issue in self.issues.values()
                if issue["user"]["login"] == "github-actions[bot]"
            ]
            return httpx.Response(200, json=listed[(page - 1) * 100 : page * 100])
        if route == "/issues":
            number = self.add_issue(body["body"])
            self.issues[number]["title"] = body["title"]
            return httpx.Response(201, json={"number": number})
        if match := re.fullmatch(r"/issues/(\d+)", route):
            self.issues[int(match.group(1))].update(body)
            return httpx.Response(200, json={})
        if match := re.fullmatch(r"/issues/(\d+)/lock", route):
            self.issues[int(match.group(1))]["locked"] = True
            return httpx.Response(204)
        if match := re.fullmatch(r"/issues/(\d+)/labels", route):
            self.issues[int(match.group(1))]["labels"].extend(body["labels"])
            return httpx.Response(200, json=[])
        if match := re.fullmatch(r"/issues/(\d+)/labels/(.+)", route):
            labels = self.issues[int(match.group(1))]["labels"]
            name = httpx.URL(f"/{match.group(2)}").path[1:]
            if name not in labels:
                return httpx.Response(404, json={"message": "Label does not exist"})
            labels.remove(name)
            return httpx.Response(200, json=[])
        if match := re.fullmatch(r"/issues/(\d+)/comments", route):
            number = int(match.group(1))
            if method == "POST":
                self.add_comment(number, body["body"], user_id=41898282)
                return httpx.Response(201, json={})
            listed = [comment for comment in self.comments.values() if comment["issue"] == number]
            return httpx.Response(200, json=listed[(page - 1) * 100 : page * 100])
        if match := re.fullmatch(r"/issues/comments/(\d+)", route):
            return self._found(self.comments.get(int(match.group(1))))
        if match := re.fullmatch(r"/actions/workflows/([^/]+)/(enable|disable)", route):
            self.workflows[match.group(1)] = match.group(2) == "enable"
            return httpx.Response(204)
        if match := re.fullmatch(r"/git/ref/heads/(.+)", route):
            files = self.branches.get(match.group(1))
            return self._found(None if files is None else {"ref": match.group(1)})
        if route == "/git/trees":
            self.pending_tree = [entry["path"] for entry in body["tree"]]
            return httpx.Response(201, json={"sha": "1" * 40})
        if route == "/git/commits":
            assert body["parents"] == [] and body["tree"] == "1" * 40
            return httpx.Response(201, json={"sha": "2" * 40})
        if route == "/git/refs":
            assert body["sha"] == "2" * 40
            self.branches[body["ref"].removeprefix("refs/heads/")] = self.pending_tree
            return httpx.Response(201, json={})
        raise AssertionError(f"unexpected request {method} {route}")

    @staticmethod
    def _found(value: dict[str, Any] | None) -> httpx.Response:
        if value is None:
            return httpx.Response(404, json={"message": "Not Found"})
        return httpx.Response(200, json=value)


def _environment(tmp_path: Path) -> dict[str, str]:
    return {
        "GITHUB_REPOSITORY": RUNNER,
        "GITHUB_REPOSITORY_OWNER": OWNER,
        "GITHUB_REPOSITORY_OWNER_ID": str(OWNER_ID),
        "GITHUB_API_URL": "https://api.github.com",
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary.md"),
        "GH_TOKEN": "runner-token",
    }


def _context(tmp_path: Path) -> RunnerContext:
    return RunnerContext.from_environment(_environment(tmp_path))


def _git(directory: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-c", "commit.gpgsign=false", *arguments],
        cwd=directory,
        env={
            **os.environ,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "Test",
            "GIT_AUTHOR_EMAIL": "test@example.invalid",
            "GIT_COMMITTER_NAME": "Test",
            "GIT_COMMITTER_EMAIL": "test@example.invalid",
        },
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _state_remote(tmp_path: Path) -> Path:
    """A bare repository whose state branch holds only .gitattributes, as setup creates it."""

    origin = tmp_path / "origin.git"
    _git(tmp_path, "init", "--quiet", "--bare", str(origin))
    seed = tmp_path / "seed"
    seed.mkdir()
    _git(seed, "init", "--quiet", "--initial-branch=autocontribute-state")
    (seed / ".gitattributes").write_text("* binary\n", encoding="utf-8")
    _git(seed, "add", "--all")
    _git(seed, "commit", "--quiet", "-m", "Start the autocontribute state")
    _git(seed, "push", "--quiet", str(origin), "HEAD:refs/heads/autocontribute-state")
    return origin


def _checkout(origin: Path, target: Path) -> Path:
    """A shallow state-branch checkout, as actions/checkout makes one."""

    _git(
        origin.parent,
        "clone",
        "--quiet",
        "--depth=1",
        "--branch=autocontribute-state",
        f"file://{origin}",
        str(target),
    )
    return target


def _remote_file(origin: Path, name: str) -> bytes:
    return subprocess.run(
        ["git", f"--git-dir={origin}", "show", f"autocontribute-state:{name}"],
        check=True,
        capture_output=True,
    ).stdout


def _approval_event(
    issue: int,
    comment: int,
    *,
    body: str,
    run_id: str = "0123456789abcdef",
) -> dict[str, Any]:
    return {
        "action": "created",
        "repository": {"full_name": RUNNER, "owner": {"id": OWNER_ID, "login": OWNER}},
        "issue": {
            "number": issue,
            "state": "open",
            "user": {"login": "github-actions[bot]", "type": "Bot"},
            "labels": [{"name": AWAITING_LABEL}],
            "body": f"<!-- autocontribute:run={run_id} -->\n## Approve this pull request",
        },
        "comment": {
            "id": comment,
            "body": body,
            "user": {"id": OWNER_ID, "login": OWNER},
            "author_association": "OWNER",
            "created_at": "2026-10-22T10:00:00Z",
            "updated_at": "2026-10-22T10:00:00Z",
            "html_url": f"https://github.com/{RUNNER}/issues/{issue}#issuecomment-{comment}",
        },
    }


def _manifest(run_id: str, status: RunStatus, **fields: Any) -> RunManifest:
    return RunManifest(run_id=run_id, status=status, created_at=_NOW, updated_at=_NOW, **fields)


class _ManifestStore:
    def __init__(self, *manifests: RunManifest) -> None:
        self.manifests = {manifest.run_id: manifest for manifest in manifests}

    def get(self, run_id: str) -> RunManifest:
        if run_id not in self.manifests:
            raise StateError(f"Unknown run: {run_id}")
        return self.manifests[run_id]

    def list_with_statuses(
        self, statuses: set[RunStatus], *, limit: int, resource: str
    ) -> list[RunManifest]:
        del limit, resource
        return [manifest for manifest in self.manifests.values() if manifest.status in statuses]


def _runner_config(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "autocontribute.yml"
    path.write_text(text, encoding="utf-8")
    return path


def test_context_requires_the_actions_description_of_the_runner(tmp_path: Path) -> None:
    context = _context(tmp_path)

    assert (context.repository, context.owner, context.owner_id) == (RUNNER, OWNER, OWNER_ID)
    for name, value in (
        ("GITHUB_REPOSITORY", "someone-else/runner"),
        ("GITHUB_REPOSITORY_OWNER_ID", "01"),
        ("GITHUB_API_URL", "http://api.github.com"),
    ):
        with pytest.raises(ConfigurationError):
            RunnerContext.from_environment({**_environment(tmp_path), name: value})
    context.summarize("first")
    context.summarize("second\n")
    assert (tmp_path / "summary.md").read_text(encoding="utf-8") == "first\n\nsecond\n\n"


def test_runner_config_binds_publishing_to_the_repository_owner(tmp_path: Path) -> None:
    token_config = _runner_config(tmp_path, "github:\n  auth: token\n")
    assert load_runner_config(token_config, owner=OWNER).publishing.login == OWNER

    gh_config = _runner_config(tmp_path, "github:\n  auth: gh\n")
    with pytest.raises(ConfigurationError, match="auth must be token"):
        load_runner_config(gh_config, owner=OWNER)

    other = _runner_config(tmp_path, "github:\n  auth: token\npublishing:\n  login: hubot\n")
    with pytest.raises(ConfigurationError, match="hubot"):
        load_runner_config(other, owner=OWNER)


def test_state_branch_commits_only_changes_and_pushes_without_force(tmp_path: Path) -> None:
    origin = _state_remote(tmp_path)
    branch = StateBranch(_checkout(origin, tmp_path / "checkout"), token=None)
    archive = tmp_path / "state.tar.gz"
    archive.write_bytes(b"first state")

    assert branch.archive_sha256() is None
    assert branch.save(archive, message="Save the state") is True
    assert _remote_file(origin, STATE_ARCHIVE) == b"first state"
    assert branch.archive_sha256() == file_sha256(archive)
    assert branch.save(archive, message="Save the state") is False

    other = _checkout(origin, tmp_path / "other")
    (other / "README.md").write_text("notes\n", encoding="utf-8")
    _git(other, "add", "--all")
    _git(other, "commit", "--quiet", "-m", "Add notes")
    _git(other, "push", "--quiet", "origin", "HEAD:refs/heads/autocontribute-state")

    archive.write_bytes(b"second state")
    assert branch.save(archive, message="Save the state again") is True
    assert _remote_file(origin, STATE_ARCHIVE) == b"second state"
    assert _remote_file(origin, "README.md") == b"notes\n"


@pytest.mark.parametrize("failed_pushes", [2, 3])
def test_state_branch_tries_a_failed_push_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failed_pushes: int
) -> None:
    origin = _state_remote(tmp_path)
    branch = StateBranch(_checkout(origin, tmp_path / "checkout"), token=None)
    archive = tmp_path / "state.tar.gz"
    archive.write_bytes(b"state with an open pull request")
    original_git = StateBranch._git
    pushes: list[str] = []
    pauses: list[float] = []

    def flaky_git(self: StateBranch, *arguments: str) -> None:
        if arguments[0] == "push":
            pushes.append(arguments[0])
            if len(pushes) <= failed_pushes:
                raise StateError("git push failed: Could not resolve host: github.com")
        original_git(self, *arguments)

    monkeypatch.setattr(StateBranch, "_git", flaky_git)
    monkeypatch.setattr(runner_module.time, "sleep", pauses.append)

    if failed_pushes < 3:
        assert branch.save(archive, message="Save the state") is True
        assert _remote_file(origin, STATE_ARCHIVE) == b"state with an open pull request"
    else:
        with pytest.raises(StateError, match="Could not resolve host"):
            branch.save(archive, message="Save the state")
    assert len(pushes) == 3
    assert pauses == [5, 5]


def test_state_branch_refuses_to_overwrite_state_saved_by_another_job(tmp_path: Path) -> None:
    origin = _state_remote(tmp_path)
    branch = StateBranch(_checkout(origin, tmp_path / "checkout"), token=None)
    other = _checkout(origin, tmp_path / "other")
    (other / STATE_ARCHIVE).write_bytes(b"approval state")
    _git(other, "add", "--all")
    _git(other, "commit", "--quiet", "-m", "Save the state after an approval")
    _git(other, "push", "--quiet", "origin", "HEAD:refs/heads/autocontribute-state")
    archive = tmp_path / "state.tar.gz"
    archive.write_bytes(b"preparation state")

    with pytest.raises(StateError, match="Another job saved the state"):
        branch.save(archive, message="Save the state")

    assert _remote_file(origin, STATE_ARCHIVE) == b"approval state"


def _prepared_dir(tmp_path: Path, archive_bytes: bytes = b"archive") -> Path:
    directory = tmp_path / "prepared"
    directory.mkdir()
    (directory / STATE_ARCHIVE).write_bytes(archive_bytes)
    write_prepared(
        directory,
        PreparedState(
            base_state_sha256=None,
            state_sha256=file_sha256(directory / STATE_ARCHIVE),
            run_id="0123456789abcdef",
        ),
    )
    return directory


def test_prepared_output_is_read_as_bounded_untrusted_data(tmp_path: Path) -> None:
    directory = _prepared_dir(tmp_path)
    prepared, archive = read_prepared(directory)
    assert prepared.run_id == "0123456789abcdef"
    assert archive == directory / STATE_ARCHIVE

    (directory / "extra.sh").write_text("echo run me\n", encoding="utf-8")
    with pytest.raises(StateError, match="must hold only"):
        read_prepared(directory)
    (directory / "extra.sh").unlink()

    (directory / STATE_ARCHIVE).write_bytes(b"tampered")
    with pytest.raises(StateError, match="does not match"):
        read_prepared(directory)

    document = json.loads((directory / "prepared.json").read_text(encoding="utf-8"))
    for tampered in (
        {**document, "state_sha256": "A" * 64},
        {**document, "unexpected": True},
        {**document, "run_id": 7},
    ):
        (directory / "prepared.json").write_text(json.dumps(tampered), encoding="utf-8")
        with pytest.raises(StateError, match="not valid"):
            read_prepared(directory)

    (directory / "prepared.json").unlink()
    (directory / "prepared.json").symlink_to(tmp_path / "elsewhere.json")
    with pytest.raises(StateError, match="not a regular file"):
        read_prepared(directory)


def test_attention_items_pair_signals_with_published_runs() -> None:
    published = _manifest(
        "0123456789abcdef",
        RunStatus.PR_OPEN,
        pull_request_url="https://github.com/example/project/pull/9",
        publishing_api_origin="https://api.github.com",
    )
    signal = LifecycleSignal(
        kind=LifecycleSignalKind.CHANGES_REQUESTED,
        repository="Example/Project",
        pull_request_number=9,
        evidence_key="review:1",
        reason="A maintainer submitted a changes-requested review",
        source_url="https://github.com/example/project/pull/9#pullrequestreview-1",
    )
    unrelated = LifecycleSignal(
        kind=LifecycleSignalKind.CI_FAILED,
        repository="example/other",
        pull_request_number=9,
        evidence_key="check:1",
        reason="CI failed",
        source_url="https://github.com/example/other/pull/9",
    )
    result = LifecycleSyncResult(
        observations=(
            LifecycleObservation(snapshot=None, signals=(signal, unrelated), newly_tripped=()),  # type: ignore[arg-type]
        )
    )

    (item,) = attention_items(result, [published])

    assert item.run_id == "0123456789abcdef"
    assert item.kind == "changes_requested"
    assert item.key == signal.trigger_hash()


def test_approval_event_is_checked_again_in_python(tmp_path: Path) -> None:
    event_path = tmp_path / "event.json"
    context = _context(tmp_path)

    def read(event: dict[str, Any], *, issue: int = 5, comment: int = 9) -> Any:
        event_path.write_text(json.dumps(event), encoding="utf-8")
        return read_approval_event(event_path, context, issue_number=issue, comment_id=comment)

    approval = read(_approval_event(5, 9, body="/approve 0123456789ab \n"))
    assert approval.fingerprint_prefix == "0123456789ab"
    assert approval.run_id == "0123456789abcdef"
    assert approval.url.endswith("#issuecomment-9")

    assert (
        read(_approval_event(5, 9, body="/approve 0123456789ab please")).fingerprint_prefix is None
    )
    assert read(_approval_event(5, 9, body="/approve 0123456789AB")).fingerprint_prefix is None

    def mutated(path: str, value: object) -> dict[str, Any]:
        event = _approval_event(5, 9, body="/approve 0123456789ab")
        target = event
        *parents, key = path.split(".")
        for parent in parents:
            target = target[parent]
        target[key] = value
        return event

    refusals = (
        ("action", "edited"),
        ("repository.full_name", "someone-else/runner"),
        ("repository.owner", {"id": 1, "login": OWNER}),
        ("issue.pull_request", {"url": "https://api.github.com/x"}),
        ("issue.state", "closed"),
        ("issue.user", {"login": OWNER, "type": "User"}),
        ("issue.labels", [{"name": PUBLISHED_LABEL}]),
        ("issue.body", "<!-- autocontribute:run=zz -->"),
        ("comment.user", {"id": str(OWNER_ID)}),
        ("comment.user", {"id": 1}),
        ("comment.author_association", "COLLABORATOR"),
        ("comment.updated_at", "2026-10-22T10:05:00Z"),
    )
    for path, value in refusals:
        with pytest.raises(PolicyError, match="Not an approval"):
            read(mutated(path, value))
    with pytest.raises(PolicyError, match="--issue"):
        read(_approval_event(5, 9, body="/approve 0123456789ab"), issue=6)
    with pytest.raises(PolicyError, match="--comment-id"):
        read(_approval_event(5, 9, body="/approve 0123456789ab"), comment=10)


def test_approval_comment_must_still_read_as_posted(tmp_path: Path) -> None:
    github = FakeRunnerGitHub()
    issue = github.add_issue("<!-- autocontribute:run=0123456789abcdef -->")
    comment = github.add_comment(issue, "/approve 0123456789ab")
    event_path = tmp_path / "event.json"
    event_path.write_text(
        json.dumps(_approval_event(issue, comment, body="/approve 0123456789ab")),
        encoding="utf-8",
    )
    context = _context(tmp_path)
    approval = read_approval_event(event_path, context, issue_number=issue, comment_id=comment)

    with github.repository(context, "runner-token") as repository:
        confirm_comment_unchanged(repository, approval, owner_id=OWNER_ID)
        github.comments[comment]["updated_at"] = "2026-10-22T10:01:00Z"
        with pytest.raises(PolicyError, match="changed after it was posted"):
            confirm_comment_unchanged(repository, approval, owner_id=OWNER_ID)
        del github.comments[comment]
        with pytest.raises(PolicyError, match="deleted"):
            confirm_comment_unchanged(repository, approval, owner_id=OWNER_ID)


def _token_response(
    *, login: str = OWNER, scopes: str | None = "public_repo", expiry: str | None = None
) -> httpx.MockTransport:
    def handle(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/user"
        assert request.headers["Authorization"] == "Bearer publishing-token"
        headers = {}
        if scopes is not None:
            headers["X-OAuth-Scopes"] = scopes
        if expiry is not None:
            headers["GitHub-Authentication-Token-Expiration"] = expiry
        return httpx.Response(200, json={"login": login, "id": OWNER_ID}, headers=headers)

    return httpx.MockTransport(handle)


@pytest.mark.parametrize(
    ("response", "passed", "warning", "detail"),
    [
        (_token_response(), True, False, "no expiry date"),
        (_token_response(expiry="2027-01-01 00:00:00 UTC"), True, False, "valid until 2027-01-01"),
        (_token_response(expiry="2026-10-30 00:00:00 UTC"), True, True, "expires on 2026-10-30"),
        (_token_response(expiry="soon"), True, True, "cannot be read"),
        (_token_response(login="hubot"), False, False, "belongs to hubot"),
        (_token_response(scopes=None), False, False, "not a classic token"),
        (_token_response(scopes="public_repo, workflow"), False, False, "public_repo, workflow"),
        (_token_response(scopes=""), False, False, "scopes none"),
    ],
)
def test_publishing_token_must_be_the_owners_public_repo_classic_token(
    tmp_path: Path,
    response: httpx.MockTransport,
    passed: bool,
    warning: bool,
    detail: str,
) -> None:
    check = publishing_token_check(
        "publishing-token", _context(tmp_path), now=_NOW, transport=response
    )

    assert (check.passed, check.warning) == (passed, warning)
    assert detail in check.detail


def test_runner_checks_report_each_missing_piece(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(runner_module, "_docker_cgroup_version", lambda: "1")
    config = _runner_config(tmp_path, "github:\n  auth: token\n  repositories: []\n")

    checks = {check.name: check for check in check_runner(config, _context(tmp_path), {}, now=_NOW)}

    assert not checks["model API key"].passed
    assert not checks["publishing token"].passed
    assert "github.repositories is empty" in checks["configuration"].detail
    assert "cgroup v1" in checks["Docker"].detail
    assert checks["disk"].passed

    monkeypatch.setattr(runner_module, "_docker_cgroup_version", lambda: "2")
    checks = {
        check.name: check
        for check in check_runner(
            config,
            _context(tmp_path),
            {"ANTHROPIC_API_KEY": "model-key", "AUTOCONTRIBUTE_GITHUB_TOKEN": "publishing-token"},
            now=_NOW,
            transport=_token_response(),
        )
    }
    assert checks["model API key"].passed and checks["publishing token"].passed
    assert checks["Docker"].passed


def test_setup_turns_preparation_on_only_when_every_check_passes(tmp_path: Path) -> None:
    github = FakeRunnerGitHub()
    context = _context(tmp_path)
    missing = [
        DoctorCheck("model API key", True, "OPENAI_API_KEY is set"),
        DoctorCheck("publishing token", False, "add the repository secret"),
    ]

    with github.repository(context, "runner-token") as repository:
        assert apply_setup(repository, context, missing) is False
        assert apply_setup(repository, context, missing) is False

    assert set(github.labels) == {AWAITING_LABEL, PUBLISHED_LABEL}
    assert github.branches == {"autocontribute-state": [".gitattributes"]}
    assert github.workflows == {"prepare.yml": False}
    (issue,) = github.issues.values()
    assert issue["title"] == "Finish setup"
    assert issue["state"] == "open"
    assert "- [ ] **publishing token**: add the repository secret" in issue["body"]
    assert "Finish setup" in (tmp_path / "summary.md").read_text(encoding="utf-8")

    with github.repository(context, "runner-token") as repository:
        assert apply_setup(repository, context, missing[:1]) is True

    assert github.workflows == {"prepare.yml": True}
    assert issue["state"] == "closed"
    assert ("POST", "/git/trees") in github.requests
    assert github.requests.count(("POST", "/git/trees")) == 1


def _review(body: str) -> GitHubReview:
    return GitHubReview(body=body, parts=("Part 2 of 2",), shortened=())


def test_issue_sync_opens_locked_issues_labelled_last_and_closes_finished_runs(
    tmp_path: Path,
) -> None:
    github = FakeRunnerGitHub()
    context = _context(tmp_path)
    ready = _manifest("aaaaaaaaaaaaaaaa", RunStatus.READY_FOR_APPROVAL)
    cancelled = _manifest("bbbbbbbbbbbbbbbb", RunStatus.CANCELLED, error="the approval expired")
    published = _manifest(
        "cccccccccccccccc",
        RunStatus.PR_OPEN,
        pull_request_url="https://github.com/example/project/pull/9",
    )
    stale_issue = github.add_issue(
        "<!-- autocontribute:run=bbbbbbbbbbbbbbbb -->", labels=(AWAITING_LABEL,)
    )
    published_issue = github.add_issue(
        "<!-- autocontribute:run=cccccccccccccccc -->", labels=(AWAITING_LABEL,)
    )
    store = _ManifestStore(ready, cancelled, published)

    with github.repository(context, "runner-token") as repository:
        lines = sync_issues(
            repository,
            store,  # type: ignore[arg-type]
            review=lambda run_id: _review(f"<!-- autocontribute:run={run_id} -->\nbody"),
            attention=(),
        )
        again = sync_issues(
            repository,
            store,  # type: ignore[arg-type]
            review=lambda run_id: _review("unused"),
            attention=(),
        )

    opened = max(github.issues)
    assert github.issues[opened]["title"] == "Approve run aaaaaaaaaaaaaaaa"
    assert github.issues[opened]["locked"] is True
    assert github.issues[opened]["labels"] == [AWAITING_LABEL]
    assert github.issue_comments(opened) == ["Part 2 of 2"]
    locked = github.requests.index(("PUT", f"/issues/{opened}/lock"))
    assert locked < github.requests.index(("POST", f"/issues/{opened}/comments"))
    assert locked < github.requests.index(("POST", f"/issues/{opened}/labels"))
    assert github.issues[stale_issue]["state_reason"] == "not_planned"
    assert github.issues[stale_issue]["labels"] == []
    assert "cancelled" in github.issue_comments(stale_issue)[0]
    assert github.issues[published_issue]["state_reason"] == "completed"
    assert github.issues[published_issue]["labels"] == [PUBLISHED_LABEL]
    assert (
        "`https://github.com/example/project/pull/9`" in github.issue_comments(published_issue)[0]
    )
    assert len(lines) == 3
    assert again == []


def test_issue_sync_replaces_an_issue_an_earlier_job_left_unlabelled(tmp_path: Path) -> None:
    github = FakeRunnerGitHub()
    context = _context(tmp_path)
    incomplete = github.add_issue("<!-- autocontribute:run=aaaaaaaaaaaaaaaa -->")
    store = _ManifestStore(_manifest("aaaaaaaaaaaaaaaa", RunStatus.READY_FOR_APPROVAL))

    with github.repository(context, "runner-token") as repository:
        sync_issues(
            repository,
            store,  # type: ignore[arg-type]
            review=lambda run_id: _review(f"<!-- autocontribute:run={run_id} -->"),
            attention=(),
        )

    assert github.issues[incomplete]["state"] == "closed"
    assert github.issues[max(github.issues)]["labels"] == [AWAITING_LABEL]


def test_issue_sync_relays_attention_once_and_only_for_open_pull_requests(
    tmp_path: Path,
) -> None:
    github = FakeRunnerGitHub()
    context = _context(tmp_path)
    url = "https://github.com/example/project/pull/9"
    published = _manifest("cccccccccccccccc", RunStatus.PR_OPEN, pull_request_url=url)
    issue = github.add_issue("<!-- autocontribute:run=cccccccccccccccc -->")
    github.issues[issue]["state"] = "closed"
    item = AttentionItem(
        run_id="cccccccccccccccc",
        pull_request_url=url,
        kind="changes_requested",
        reason="A maintainer submitted a changes-requested review",
        source_url=f"{url}#pullrequestreview-1",
        key="d" * 64,
    )
    forged = item.model_copy(update={"pull_request_url": "https://github.com/evil/x/pull/1"})
    store = _ManifestStore(published)

    with github.repository(context, "runner-token") as repository:
        for _ in range(2):
            lines = sync_issues(
                repository,
                store,  # type: ignore[arg-type]
                review=lambda run_id: _review("unused"),
                attention=(item, forged),
            )

    (comment,) = github.issue_comments(issue)
    assert comment.startswith(f"<!-- autocontribute:attention={'d' * 64} -->")
    assert f"`{url}`" in comment
    assert lines == ["- Ignored attention for run `cccccccccccccccc`: no such open pull request"]


def test_approval_report_announces_the_pull_request_or_explains_the_refusal(
    tmp_path: Path,
) -> None:
    github = FakeRunnerGitHub()
    context = _context(tmp_path)
    published_issue = github.add_issue("x", labels=(AWAITING_LABEL,))
    waiting_issue = github.add_issue("x", labels=(AWAITING_LABEL,))
    failed_issue = github.add_issue("x", labels=(AWAITING_LABEL,))
    missing_issue = github.add_issue("x", labels=(AWAITING_LABEL,))
    interrupted_issue = github.add_issue("x", labels=(AWAITING_LABEL,))
    unanswered_issue = github.add_issue("x", labels=(AWAITING_LABEL,))
    url = "https://github.com/example/project/pull/9"
    store = _ManifestStore(
        _manifest("cccccccccccccccc", RunStatus.PR_OPEN, pull_request_url=url),
        _manifest("aaaaaaaaaaaaaaaa", RunStatus.APPROVED),
        _manifest("bbbbbbbbbbbbbbbb", RunStatus.FAILED),
        _manifest("eeeeeeeeeeeeeeee", RunStatus.SUBMITTING),
        _manifest("ffffffffffffffff", RunStatus.SUBMITTING, pull_request_creation_started=True),
    )

    with github.repository(context, "runner-token") as repository:
        for number, run_id, outcome, message, save_error in (
            (published_issue, "cccccccccccccccc", "pr_open", "", "connection reset"),
            (waiting_issue, "aaaaaaaaaaaaaaaa", "limit", "At most 1 per day", "push rejected"),
            (failed_issue, "bbbbbbbbbbbbbbbb", "error", "GitHub refused the pull request", None),
            (missing_issue, "dddddddddddddddd", "error", "Unknown run", None),
            (interrupted_issue, "eeeeeeeeeeeeeeee", "error", "Fork was not ready", None),
            (unanswered_issue, "ffffffffffffffff", "resume_required", "No answer", None),
        ):
            report_approval(
                repository,
                number,
                store,  # type: ignore[arg-type]
                run_id,
                outcome=outcome,
                message=message,
                save_error=save_error,
            )

    assert github.issues[published_issue]["labels"] == [PUBLISHED_LABEL]
    assert github.issues[published_issue]["state"] == "closed"
    opened, untracked = github.issue_comments(published_issue)
    assert f"`{url}`" in opened
    assert "will not watch the pull request" in untracked
    assert "re-run" not in untracked
    assert github.issues[waiting_issue]["state"] == "open"
    assert github.issues[waiting_issue]["labels"] == [AWAITING_LABEL]
    limit_reply, unsaved = github.issue_comments(waiting_issue)
    assert "comment the same approval again later" in limit_reply
    assert "re-run this approve job" in unsaved
    for closed in (failed_issue, missing_issue):
        assert github.issues[closed]["state_reason"] == "not_planned"
        assert github.issues[closed]["labels"] == []
    (interrupted,) = github.issue_comments(interrupted_issue)
    assert "Comment the same approval again to finish it" in interrupted
    (unanswered,) = github.issue_comments(unanswered_issue)
    assert "GitHub never answered" in unanswered
    assert "docs/actions.md#fix-a-run-by-hand" in unanswered
    for waiting in (interrupted_issue, unanswered_issue):
        assert github.issues[waiting]["state"] == "open"
        assert github.issues[waiting]["labels"] == [AWAITING_LABEL]


def test_template_files_hold_the_runner(tmp_path: Path) -> None:
    files = template_files()

    assert set(files) == {
        ".github/actions/install-autocontribute/action.yml",
        ".github/workflows/approve.yml",
        ".github/workflows/prepare.yml",
        ".github/workflows/setup.yml",
        ".gitignore",
        "README.md",
        "autocontribute.yml",
    }
    config = tmp_path / "autocontribute.yml"
    config.write_bytes(files["autocontribute.yml"])
    assert load_runner_config(config, owner=OWNER).github.repositories == []


def test_init_actions_creates_a_private_repository_from_the_template(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []
    pushed: dict[str, bytes] = {}

    def run_command(
        arguments: list[str], *, cwd: Path | None = None, extra_env: object = None
    ) -> str:
        calls.append(arguments)
        if arguments[:3] == ["gh", "api", "user"]:
            return json.dumps({"login": OWNER, "id": OWNER_ID})
        if arguments[:3] == ["gh", "repo", "create"]:
            source = Path(arguments[arguments.index("--source") + 1])
            pushed.update(
                {
                    path.relative_to(source).as_posix(): path.read_bytes()
                    for path in source.rglob("*")
                    if path.is_file()
                }
            )
        if "commit" in arguments:
            assert extra_env == {
                "GIT_AUTHOR_NAME": OWNER,
                "GIT_AUTHOR_EMAIL": f"{OWNER_ID}+{OWNER}@users.noreply.github.com",
                "GIT_COMMITTER_NAME": OWNER,
                "GIT_COMMITTER_EMAIL": f"{OWNER_ID}+{OWNER}@users.noreply.github.com",
            }
        return ""

    monkeypatch.setattr(runner_module, "_run_command", run_command)

    result = cli_runner.invoke(app, ["init", "--actions", "--repo", "my-runner"])

    assert result.exit_code == 0, result.output
    create = next(call for call in calls if call[:3] == ["gh", "repo", "create"])
    assert create[3:5] == ["my-runner", "--private"]
    assert "--push" in create
    assert pushed == template_files()
    assert "gh secret set AUTOCONTRIBUTE_GITHUB_TOKEN --repo octocat/my-runner" in result.output
    assert "gh secret set OPENAI_API_KEY --repo octocat/my-runner" in result.output
    assert runner_module.TOKEN_URL in result.output

    with pytest.raises(ConfigurationError, match="--repo"):
        create_runner_repository("../escape", public=True)
    refused = cli_runner.invoke(app, ["init", "--public", "--path", "x.yml"])
    assert refused.exit_code == 1
    assert "only with --actions" in refused.output


# The commands, with GitHub, Docker and the orchestrator faked.


def _actions_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, github: FakeRunnerGitHub
) -> None:
    for name, value in _environment(tmp_path).items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(cli, "RunnerRepository", github.repository)


def test_actions_setup_exits_zero_with_a_checklist_when_secrets_are_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    github = FakeRunnerGitHub()
    _actions_environment(tmp_path, monkeypatch, github)
    monkeypatch.setattr(
        cli,
        "check_runner",
        lambda *_, **__: [DoctorCheck("model API key", False, "add the repository secret")],
    )

    result = cli_runner.invoke(app, ["actions", "setup"])

    assert result.exit_code == 0, result.output
    assert github.workflows == {"prepare.yml": False}
    assert [issue["title"] for issue in github.issues.values()] == ["Finish setup"]
    assert "stays off" in result.output


def _runner_ready_run(tmp_path: Path) -> tuple[Path, RunStore, str, Path]:
    """A ready run prepared elsewhere, and a runner config whose state directory is empty."""

    prepared_config, store, run_id = _ready_review_run(tmp_path / "prepared", runner_owner=OWNER)
    runner_dir = tmp_path / "runner"
    runner_dir.mkdir()
    config = runner_dir / "autocontribute.yml"
    config.write_text(
        prepared_config.read_text(encoding="utf-8").replace(
            str(tmp_path / "prepared" / "state"), str(runner_dir / "state")
        ),
        encoding="utf-8",
    )
    return config, store, run_id, runner_dir


def test_actions_prepare_restores_runs_and_exports_the_state_for_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "prepared").mkdir()
    config, prepared_store, ready_run, runner_dir = _runner_ready_run(tmp_path)
    origin = _state_remote(tmp_path)
    checkout = _checkout(origin, tmp_path / "branch")
    export_state(prepared_store, tmp_path / "base.tar.gz")
    StateBranch(checkout, token=None).save(tmp_path / "base.tar.gz", message="seed")
    for name, value in _environment(tmp_path).items():
        monkeypatch.setenv(name, value)
    calls: list[str] = []

    class FakeOrchestrator:
        def __init__(self, _: object, *, store: RunStore, github: object) -> None:
            self.store = store

        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *_: object) -> None:
            pass

        def run(self, *, issue_reference, invocation_mode, retry_authorization):  # type: ignore[no-untyped-def]
            assert issue_reference is None and retry_authorization is None
            assert invocation_mode == RunInvocationMode.SCHEDULED
            calls.append("run")
            manifest = self.store.create_run()
            manifest.status = RunStatus.SKIPPED
            manifest.skip_reason = "no candidate passed the rules"
            self.store.save(manifest, event="test.skipped", details={})
            self.store.write_artifact(manifest.run_id, "report.md", "# report\n")
            return manifest

    def sync(*_: object, reconcile_submitting: bool = True) -> LifecycleSyncResult:
        assert not reconcile_submitting
        calls.append("sync")
        return LifecycleSyncResult(observations=())

    monkeypatch.setattr(cli, "_github_client", lambda *_: _ReviewGitHub())
    monkeypatch.setattr(cli, "_sync_lifecycle", sync)
    monkeypatch.setattr(cli, "Orchestrator", FakeOrchestrator)
    output = tmp_path / "out"

    result = cli_runner.invoke(
        app,
        [
            "actions",
            "prepare",
            "--state",
            str(checkout),
            "--output",
            str(output),
            "--config",
            str(config),
        ],
    )

    assert result.exit_code == 0, result.output
    assert calls == ["sync", "run"]
    prepared, _ = read_prepared(_without_evidence(output))
    assert prepared.base_state_sha256 == file_sha256(checkout / STATE_ARCHIVE)
    assert prepared.run_id is not None
    assert (output / "evidence" / prepared.run_id / "report.md").is_file()
    restored = RunStore(runner_dir / "state")
    assert restored.get(ready_run).status == RunStatus.READY_FOR_APPROVAL
    assert restored.get(prepared.run_id).status == RunStatus.SKIPPED
    assert "**skipped**" in (tmp_path / "summary.md").read_text(encoding="utf-8")


def test_actions_prepare_runs_beside_a_submitting_run_without_the_publishing_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "prepared").mkdir()
    config, prepared_store, _, runner_dir = _runner_ready_run(tmp_path)
    submitting = prepared_store.create_run()
    submitting.status = RunStatus.SUBMITTING
    prepared_store.save(submitting, event="test.unanswered_post", details={})
    origin = _state_remote(tmp_path)
    checkout = _checkout(origin, tmp_path / "branch")
    export_state(prepared_store, tmp_path / "base.tar.gz")
    StateBranch(checkout, token=None).save(tmp_path / "base.tar.gz", message="seed")
    for name, value in _environment(tmp_path).items():
        monkeypatch.setenv(name, value)
    calls: list[str] = []

    class WorkflowToken(_ReviewGitHub):
        def authenticated_login(self) -> str:
            calls.append("GET /user")
            raise GitHubHTTPError(
                "GitHub returned 403 for GET /user",
                status_code=403,
                request_id="ABCD:1",
                github_message="Resource not accessible by integration",
            )

    class Preparation:
        def __init__(self, _: object, *, store: RunStore, github: object) -> None:
            self.store = store

        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *_: object) -> None:
            pass

        def run(self, **_: object) -> RunManifest:
            calls.append("run")
            manifest = self.store.create_run()
            manifest.status = RunStatus.SKIPPED
            self.store.save(manifest, event="test.skipped", details={})
            return manifest

    monkeypatch.setattr(cli, "_github_client", lambda *_: WorkflowToken())
    monkeypatch.setattr(cli, "Orchestrator", Preparation)

    result = cli_runner.invoke(
        app,
        [
            "actions",
            "prepare",
            "--state",
            str(checkout),
            "--output",
            str(tmp_path / "out"),
            "--config",
            str(config),
        ],
    )

    assert result.exit_code == 0, result.output
    assert calls == ["run"]
    restored = RunStore(runner_dir / "state")
    assert restored.get(submitting.run_id).status == RunStatus.SUBMITTING


def _without_evidence(output: Path) -> Path:
    """The files the prepare job uploads for the record job."""

    uploaded = output.parent / f"{output.name}-uploaded"
    uploaded.mkdir()
    for name in ("prepared.json", STATE_ARCHIVE):
        (uploaded / name).write_bytes((output / name).read_bytes())
    return uploaded


def test_actions_prepare_cancels_runs_that_can_never_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "prepared").mkdir()
    config, prepared_store, ready_run, runner_dir = _runner_ready_run(tmp_path)
    origin = _state_remote(tmp_path)
    checkout = _checkout(origin, tmp_path / "branch")
    export_state(prepared_store, tmp_path / "base.tar.gz")
    StateBranch(checkout, token=None).save(tmp_path / "base.tar.gz", message="seed")
    for name, value in _environment(tmp_path).items():
        monkeypatch.setenv(name, value)

    class PullRequestsOff(_ReviewGitHub):
        def get_repository_access(self, full_name: str) -> RepositoryAccess:
            return RepositoryAccess(
                identity=RepositoryIdentity(full_name=full_name, database_id=1, node_id="R_1"),
                owner="example",
                fork_parent=None,
                can_push=False,
                has_pull_requests=False,
                pull_requests_from_collaborators_only=False,
            )

    class NoCandidate:
        def __init__(self, _: object, *, store: RunStore, github: object) -> None:
            self.store = store

        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *_: object) -> None:
            pass

        def run(self, **_: object) -> RunManifest:
            manifest = self.store.create_run()
            manifest.status = RunStatus.SKIPPED
            self.store.save(manifest, event="test.skipped", details={})
            return manifest

    monkeypatch.setattr(cli, "_github_client", lambda *_: PullRequestsOff())
    monkeypatch.setattr(
        cli, "_sync_lifecycle", lambda *_, **__: LifecycleSyncResult(observations=())
    )
    monkeypatch.setattr(cli, "Orchestrator", NoCandidate)

    result = cli_runner.invoke(
        app,
        [
            "actions",
            "prepare",
            "--state",
            str(checkout),
            "--output",
            str(tmp_path / "out"),
            "--config",
            str(config),
        ],
    )

    assert result.exit_code == 0, result.output
    cancelled = RunStore(runner_dir / "state").get(ready_run)
    assert cancelled.status == RunStatus.CANCELLED


def _record_setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Path, Path, FakeRunnerGitHub, str]:
    (tmp_path / "prepared").mkdir()
    config, prepared_store, run_id, _ = _runner_ready_run(tmp_path)
    origin = _state_remote(tmp_path)
    checkout = _checkout(origin, tmp_path / "branch")
    output = tmp_path / "artifact"
    output.mkdir()
    exported = export_state(prepared_store, output / STATE_ARCHIVE)
    write_prepared(
        output,
        PreparedState(base_state_sha256=None, state_sha256=exported.sha256, run_id=run_id),
    )
    github = FakeRunnerGitHub()
    _actions_environment(tmp_path, monkeypatch, github)
    monkeypatch.setattr(cli, "_github_client", lambda *_: _ReviewGitHub())
    return config, origin, checkout, github, run_id


def test_actions_record_saves_the_state_and_opens_the_rendered_issue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, origin, checkout, github, run_id = _record_setup(tmp_path, monkeypatch)
    arguments = [
        "actions",
        "record",
        "--input",
        str(tmp_path / "artifact"),
        "--state",
        str(checkout),
        "--config",
        str(config),
    ]

    result = cli_runner.invoke(app, arguments)

    assert result.exit_code == 0, result.output
    assert (
        _remote_file(origin, STATE_ARCHIVE) == (tmp_path / "artifact" / STATE_ARCHIVE).read_bytes()
    )
    (issue,) = github.issues.values()
    assert issue["body"].startswith(f"<!-- autocontribute:run={run_id} -->")
    assert FINGERPRINT_COMMENT.search(issue["body"])
    assert "PR_TITLE_EXACT_MARKER" in issue["body"]
    assert issue["labels"] == [AWAITING_LABEL]
    assert issue["locked"] is True

    # A re-run gets a fresh machine, so the restored state is gone.
    shutil.rmtree(config.parent / "state")
    rerun = cli_runner.invoke(app, arguments)

    assert rerun.exit_code == 0, rerun.output
    assert "already saved" in rerun.output
    assert len(github.issues) == 1


def test_actions_record_drops_a_preparation_when_the_state_moved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, origin, checkout, github, _ = _record_setup(tmp_path, monkeypatch)
    (checkout / STATE_ARCHIVE).write_bytes(b"saved by an approval")
    _git(checkout, "add", "--all")
    _git(checkout, "commit", "--quiet", "-m", "Save the state after an approval")
    _git(checkout, "push", "--quiet", "origin", "HEAD:refs/heads/autocontribute-state")

    result = cli_runner.invoke(
        app,
        [
            "actions",
            "record",
            "--input",
            str(tmp_path / "artifact"),
            "--state",
            str(checkout),
            "--config",
            str(config),
        ],
    )

    assert result.exit_code == 1
    assert "saved the state while this preparation ran" in result.output
    assert _remote_file(origin, STATE_ARCHIVE) == b"saved by an approval"
    assert github.issues == {}


def test_actions_record_refuses_a_prepared_state_that_drops_saved_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "prepared").mkdir()
    config, trusted, _, _ = _runner_ready_run(tmp_path)
    trusted.trip_circuit_breaker(source="maintainer", reason="stop", trigger_hash="c" * 64)
    origin = _state_remote(tmp_path)
    checkout = _checkout(origin, tmp_path / "branch")
    export_state(trusted, tmp_path / "trusted.tar.gz")
    StateBranch(checkout, token=None).save(tmp_path / "trusted.tar.gz", message="seed")
    saved = _remote_file(origin, STATE_ARCHIVE)
    forged = tmp_path / "artifact"
    forged.mkdir()
    exported = export_state(RunStore(tmp_path / "fresh"), forged / STATE_ARCHIVE)
    write_prepared(
        forged,
        PreparedState(
            base_state_sha256=file_sha256(checkout / STATE_ARCHIVE),
            state_sha256=exported.sha256,
            run_id=None,
        ),
    )
    github = FakeRunnerGitHub()
    _actions_environment(tmp_path, monkeypatch, github)
    monkeypatch.setattr(cli, "_github_client", lambda *_: _ReviewGitHub())

    result = cli_runner.invoke(
        app,
        [
            "actions",
            "record",
            "--input",
            str(forged),
            "--state",
            str(checkout),
            "--config",
            str(config),
        ],
    )

    assert result.exit_code == 1
    assert "drops or rewrites" in result.output
    assert _remote_file(origin, STATE_ARCHIVE) == saved
    assert github.issues == {}


def _approve_setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, body: str | None = None
) -> tuple[list[str], FakeRunnerGitHub, Path, str, int, Path]:
    config, origin, checkout, github, run_id = _record_setup(tmp_path, monkeypatch)
    recorded = cli_runner.invoke(
        app,
        [
            "actions",
            "record",
            "--input",
            str(tmp_path / "artifact"),
            "--state",
            str(checkout),
            "--config",
            str(config),
        ],
    )
    assert recorded.exit_code == 0, recorded.output
    (issue,) = github.issues
    match = FINGERPRINT_COMMENT.search(github.issues[issue]["body"])
    assert match is not None
    comment_body = body if body is not None else f"/approve {match.group(1)}"
    comment = github.add_comment(issue, comment_body)
    event = _approval_event(issue, comment, body=comment_body, run_id=run_id)
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps(event), encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
    approve_dir = tmp_path / "approve"
    approve_dir.mkdir()
    approve_config = approve_dir / "autocontribute.yml"
    approve_config.write_text(
        config.read_text(encoding="utf-8").replace(
            str(config.parent / "state"), str(approve_dir / "state")
        ),
        encoding="utf-8",
    )
    arguments = [
        "actions",
        "approve",
        "--issue",
        str(issue),
        "--comment-id",
        str(comment),
        "--state",
        str(_checkout(origin, tmp_path / "approve-branch")),
        "--config",
        str(approve_config),
    ]
    return arguments, github, origin, run_id, issue, approve_dir


def test_actions_approve_records_the_approval_and_reports_a_refused_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    arguments, github, origin, run_id, issue, _ = _approve_setup(tmp_path, monkeypatch)

    def limited(*_: object) -> RunManifest:
        raise PublicationLimitError("At most 1 new pull request per UTC day")

    monkeypatch.setattr(cli, "_publish_approved", limited)

    result = cli_runner.invoke(app, arguments)

    assert result.exit_code == 3, result.output
    reply = github.issue_comments(issue)[-1]
    assert reply.startswith("Not published: a publishing limit stopped it")
    assert github.issues[issue]["labels"] == [AWAITING_LABEL]
    saved = tmp_path / "saved"
    saved.mkdir()
    (saved / STATE_ARCHIVE).write_bytes(_remote_file(origin, STATE_ARCHIVE))
    restored_root = tmp_path / "restored"
    import_state(saved / STATE_ARCHIVE, restored_root)
    approved = RunStore(restored_root).get(run_id)
    assert approved.status == RunStatus.APPROVED
    assert approved.approval is not None
    assert "#issuecomment-" in approved.approval.attestation


def test_actions_approve_answers_a_malformed_comment_without_touching_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    arguments, github, origin, _, issue, _ = _approve_setup(
        tmp_path, monkeypatch, body="/approve please"
    )
    before = _remote_file(origin, STATE_ARCHIVE)

    result = cli_runner.invoke(app, arguments)

    assert result.exit_code == 1
    assert github.issue_comments(issue)[-1].startswith("Not approved.")
    assert _remote_file(origin, STATE_ARCHIVE) == before


def test_actions_approve_refuses_a_fingerprint_of_another_review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    arguments, github, _, _, issue, _ = _approve_setup(
        tmp_path, monkeypatch, body="/approve 000000000000"
    )
    monkeypatch.setattr(cli, "_publish_approved", lambda *_: pytest.fail("must not publish"))

    result = cli_runner.invoke(app, arguments)

    assert result.exit_code == 3, result.output
    assert "fingerprint does not match" in github.issue_comments(issue)[-1]
