"""Opt-in test of a whole run against a real Docker daemon, from the issue to the approval.

A scripted provider plays the models and a fake GitHub serves one issue of a local fixture
repository. Everything else is the real ``Orchestrator.run``: the claim and the clone, the
environment build through the egress proxy and its offline baseline, the agent's session and
host-side edits, the fix checks' red/green and regression runs, a critic round, the pull
request text, the evidence and both fingerprints. The run must end ready for approval, and
the approval review must accept it. Enabled by the security-integration workflow.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import JsonValue
from test_agent_loop import Raw, Shell, Submit, turn

from autocontribute.config import AutocontributeConfig
from autocontribute.domain import IssueCandidate, RepositoryInfo, RunStatus
from autocontribute.evidence import read_validation_evidence
from autocontribute.github import (
    DirectoryEntry,
    GitHubAccount,
    RepositoryAccess,
    RepositoryIdentity,
)
from autocontribute.orchestrator import Orchestrator, RunInvocationMode
from autocontribute.preparation import validate_preparation_fingerprint
from autocontribute.pricing import ModelSpec
from autocontribute.publication import build_approval_review
from autocontribute.reporting import render_github_review
from autocontribute.repository import RepositoryWorkspace
from autocontribute.sandbox import docker_client_environment
from autocontribute.store import RunStore
from autocontribute.suite_runs import SUITE_TEST_ID
from autocontribute.transcript import Transcript, TranscriptKind, Turn

pytestmark = pytest.mark.skipif(
    os.environ.get("AUTOCONTRIBUTE_RUN_DOCKER_TESTS") != "1",
    reason="set AUTOCONTRIBUTE_RUN_DOCKER_TESTS=1 to run live Docker tests",
)

# The smallest official Python image, as in test_sandbox_live.py, and the egress proxy's image.
_PYTHON = "python@sha256:e32be0e55814a08977501ca863271d9bd02443710db8f2afaf8372e2c4508530"
_PROXY = (
    "python:3.12-alpine@sha256:b658b05ce9c4eb97ec6fc19424818a1f31993659c2b505a532f470e83807815d"
)
_TEST_COMMAND = "python -m unittest -v"
_FIX: dict[str, JsonValue] = {
    "outcome": "fixed",
    "skip_reason": None,
    "summary": "add subtracted its arguments; it now adds them.",
    "pr_title": "Fix add returning the difference",
    "pr_body": "add returned a - b for every input. It now returns their sum.",
    "commit_message": "Fix add returning the difference",
    "test_files": ["test_calc.py"],
    "test_command": _TEST_COMMAND,
}
_REVIEW: dict[str, JsonValue] = {
    "verdict": "approve",
    "blockers": [],
    "notes": ["The new test covers one pair of positive numbers."],
    "no_test_needed": False,
    "summary": "add now returns the sum, and the new test fails without the fix.",
}


def _docker(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *arguments],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=900,
        env=docker_client_environment(),
    )


def _present_or_pulled(image: str) -> Iterator[str]:
    if shutil.which("docker") is None:
        pytest.fail("live Docker tests were requested but Docker is not installed")
    present = _docker("image", "inspect", image).returncode == 0
    if not present:
        pulled = _docker("pull", "--quiet", image)
        assert pulled.returncode == 0, pulled.stderr
    try:
        yield image
    finally:
        if not present:
            _docker("image", "rm", image)


@pytest.fixture(scope="module")
def python_image() -> Iterator[str]:
    yield from _present_or_pulled(_PYTHON)


@pytest.fixture(scope="module")
def proxy_image() -> Iterator[str]:
    yield from _present_or_pulled(_PROXY)


@pytest.fixture
def live_root() -> Iterator[Path]:
    # Colima shares only $HOME with its VM, and pytest's tmp_path is outside it on macOS.
    with tempfile.TemporaryDirectory(
        prefix=".autocontribute-live-", dir=Path(__file__).resolve().parents[1]
    ) as temporary:
        yield Path(temporary)


def _git(directory: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-c", "user.name=F", "-c", "user.email=f@example.invalid", *arguments],
        cwd=directory,
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"},
    )
    return completed.stdout.strip()


def _fixture_repository(root: Path) -> tuple[Path, str]:
    source = root / "source"
    source.mkdir()
    files = {
        ".gitignore": "__pycache__/\n",
        "CONTRIBUTING.md": "Run python -m unittest -v before opening a pull request.\n",
        "calc.py": "def add(a, b):\n    return a - b\n",
        "test_calc.py": (
            "import unittest\n\nfrom calc import add\n\n\n"
            "class AddTest(unittest.TestCase):\n"
            "    def test_zero(self):\n"
            "        self.assertEqual(add(0, 0), 0)\n"
        ),
    }
    for relative, content in files.items():
        (source / relative).write_text(content, encoding="utf-8")
    _git(source, "init", "--quiet")
    _git(source, "add", ".")
    _git(source, "commit", "-qm", "base")
    return source, _git(source, "rev-parse", "HEAD")


def _issue() -> IssueCandidate:
    now = datetime.now(UTC)
    return IssueCandidate(
        repository="acme/calc",
        number=7,
        title="add returns the difference of its arguments",
        body=(
            "Steps to reproduce: call add(1, 2) from calc.py. The actual behavior is that it "
            "returns -1. The expected behavior is 3. A focused regression test would help. " * 3
        ),
        html_url="https://github.com/acme/calc/issues/7",
        state="open",
        author="maintainer",
        labels=["help wanted", "bug"],
        assignees=[],
        comments=0,
        created_at=now - timedelta(days=3),
        updated_at=now - timedelta(days=1),
    )


class FixtureGitHub:
    """Public reads of the fixture repository, and the publishing account's view of it."""

    # Assembled at runtime so the repository secret scan does not report this file.
    token = "-".join(("fixture", "github", "token", "value"))

    def __init__(self, sha: str) -> None:
        self.sha = sha

    def get_repository(self, full_name: str) -> RepositoryInfo:
        return RepositoryInfo(
            full_name="acme/calc",
            html_url="https://github.com/acme/calc",
            clone_url="https://github.com/acme/calc.git",
            default_branch="main",
            stars=1_200,
            archived=False,
            disabled=False,
            private=False,
            pushed_at=datetime.now(UTC),
            license_spdx="MIT",
        )

    def get_issue(self, repository: str, number: int) -> IssueCandidate:
        return _issue()

    def default_branch_sha(self, repository: str, branch: str) -> str:
        return self.sha

    def default_branch_sha_if_exists(self, repository: str) -> str | None:
        return None

    def list_directory(
        self, repository: str, path: str, *, ref: str
    ) -> list[DirectoryEntry] | None:
        return None if path else [DirectoryEntry(path="CONTRIBUTING.md", kind="file")]

    def get_file(
        self, repository: str, path: str, *, ref: str, max_bytes: int = 1_000_000
    ) -> str | None:
        return "Run python -m unittest -v." if path == "CONTRIBUTING.md" else None

    def search_competing_pull_requests(self, repository: str, issue_number: int) -> list[str]:
        return []

    def recent_commit_titles(self, repository: str, sha: str) -> list[str]:
        return ["base"]

    def get_user(self, login: str) -> GitHubAccount:
        return GitHubAccount(login=login, database_id=583231)

    def authenticated_user(self) -> GitHubAccount:
        return GitHubAccount(login="octocat", database_id=583231)

    def get_repository_access(self, full_name: str) -> RepositoryAccess:
        return RepositoryAccess(
            identity=RepositoryIdentity(full_name=full_name, database_id=1001, node_id="R_1"),
            owner="acme",
            fork_parent=None,
            can_push=False,
            has_pull_requests=True,
            pull_requests_from_collaborators_only=False,
        )


class ScriptedModels:
    """Answers each transcript kind from its own script, as the models would."""

    def __init__(self, scripts: dict[TranscriptKind, list[Turn]]) -> None:
        self.scripts = scripts
        self.requests: list[TranscriptKind] = []

    def provider(self, spec: ModelSpec, host_values: frozenset[str]) -> ScriptedModels:
        return self

    def step(
        self, *, transcript: Transcript, max_output_tokens: int, timeout_seconds: float
    ) -> Turn:
        self.requests.append(transcript.kind)
        return self.scripts[transcript.kind].pop(0)


def test_live_run_prepares_a_fix_ready_for_approval(
    live_root: Path, python_image: str, proxy_image: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, sha = _fixture_repository(live_root)
    original_clone = RepositoryWorkspace.clone

    def local_clone(
        cls: type[RepositoryWorkspace],
        clone_url: str,
        base_sha: str,
        destination: Path,
        **_: object,
    ) -> RepositoryWorkspace:
        return original_clone(str(source), base_sha, destination, allow_local_source=True)

    monkeypatch.setattr(RepositoryWorkspace, "clone", classmethod(local_clone))
    monkeypatch.setenv("OPENAI_API_KEY", "live-test-key-placeholder")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["acme/calc"]},
            "environments": {
                "acme/calc": {"image": python_image, "setup": [], "test": _TEST_COMMAND}
            },
            "sandbox": {
                "command_timeout_seconds": 300,
                "memory": "1g",
                "cpus": 1.0,
                "pids_limit": 256,
            },
            "publishing": {"login": "octocat"},
            "storage": {"path": live_root / "state"},
        }
    )
    new_test = (
        "@@\n         self.assertEqual(add(0, 0), 0)\n"
        "+\n+    def test_adds(self):\n+        self.assertEqual(add(1, 2), 3)\n"
    )
    fix = "@@\n def add(a, b):\n-    return a - b\n+    return sum((a, b))\n"
    models = ScriptedModels(
        {
            "agent": [
                turn("openai", Shell(_TEST_COMMAND)),
                turn(
                    "openai",
                    Raw(
                        "apply_patch",
                        {"type": "update_file", "path": "test_calc.py", "diff": new_test},
                    ),
                    Raw("apply_patch", {"type": "update_file", "path": "calc.py", "diff": fix}),
                ),
                turn("openai", Submit(_FIX)),
                turn("openai", Submit(_FIX)),
            ],
            "critic": [
                turn("openai", Shell(_TEST_COMMAND)),
                turn("openai", Submit(_REVIEW, name="submit_review")),
            ],
        }
    )
    github = FixtureGitHub(sha)
    store = RunStore(config.storage.path)
    image_id: str | None = None
    try:
        with Orchestrator(
            config,
            store=store,
            github=github,  # type: ignore[arg-type]
            provider_factory=models.provider,
        ) as orchestrator:
            manifest = orchestrator.run(
                issue_reference="acme/calc#7", invocation_mode=RunInvocationMode.MANUAL
            )
        if manifest.environment is not None:
            image_id = manifest.environment.image_id

        assert manifest.status == RunStatus.READY_FOR_APPROVAL, (
            manifest.error or manifest.reject_reason or manifest.skip_reason
        )
        assert models.requests == ["agent"] * 4 + ["critic"] * 2
        assert models.scripts == {"agent": [], "critic": []}
        assert manifest.environment is not None
        assert manifest.environment.recipe_source == "config"
        artifacts = store.artifact_dir(manifest.run_id)
        patch = (artifacts / "contribution.patch").read_bytes()
        assert b"+    return sum((a, b))" in patch
        assert b"+    def test_adds(self):" in patch
        validate_preparation_fingerprint(store.get(manifest.run_id), diff=patch)
        evidence = read_validation_evidence((artifacts / "validation.json").read_bytes())
        # unittest writes no report, so the suite counts as one test.
        assert evidence.baseline.pass_stable == [SUITE_TEST_ID]
        assert evidence.check is not None and evidence.check.passed
        assert evidence.check.red_green is not None
        assert evidence.check.red_green.status == "passed"
        assert evidence.check.regression is not None
        assert evidence.check.regression.status == "passed"
        assert [round_.decision for round_ in evidence.critic_rounds] == ["approve"]
        assert manifest.proposal is not None
        assert manifest.proposal.pull_request_body.startswith("Fixes #7\n\n")
        assert (artifacts / "agent-1.jsonl").is_file()
        assert (artifacts / "critic-1.jsonl").is_file()
        assert not (store.workspaces_dir / manifest.run_id).exists()

        review = build_approval_review(config, store, manifest.run_id, github=github)  # type: ignore[arg-type]

        assert len(review.fingerprint) == 64
        assert review.manifest.disclosure == manifest.proposal.disclosure
        assert review.manifest.head_repository == "octocat/calc"
        body = render_github_review(review, approval_expires_hours=72).body
        assert f"/approve {review.fingerprint[:12]}" in body
        label = f"label=org.autocontribute.run={manifest.run_id}"
        leftovers = _docker("ps", "--all", "--quiet", "--filter", label)
        assert leftovers.returncode == 0 and leftovers.stdout.strip() == ""
    finally:
        if image_id is not None:
            _docker("image", "rm", "--force", image_id)
