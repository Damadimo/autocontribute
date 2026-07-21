"""Human approval and the only code path authorized to mutate GitHub."""

from __future__ import annotations

import os
import re
import stat
import subprocess
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from autocontribute.approval import (
    build_approval_manifest,
    create_approval,
    validate_approval,
)
from autocontribute.config import AutocontributeConfig
from autocontribute.domain import RunManifest, RunStatus
from autocontribute.exceptions import GitHubError, PolicyError, RepositoryError, StateError
from autocontribute.github import GitHubClient
from autocontribute.redaction import redact_text
from autocontribute.repository import RepositoryWorkspace
from autocontribute.store import RunStore

_SAFE_SLUG = re.compile(r"[^a-z0-9-]+")
_SECRET = re.compile(
    r"(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)


def validate_publication_text(manifest: RunManifest) -> None:
    proposal = manifest.proposal
    if proposal is None:
        raise PolicyError("Run has no publication proposal")
    values = {
        "commit message": proposal.commit_message,
        "pull request title": proposal.pull_request_title,
        "pull request body": proposal.pull_request_body,
    }
    limits = {"commit message": 200, "pull request title": 200, "pull request body": 50_000}
    for name, value in values.items():
        if not value.strip():
            raise PolicyError(f"{name} cannot be blank")
        if len(value) > limits[name]:
            raise PolicyError(f"{name} exceeds the {limits[name]}-character limit")
        if _SECRET.search(value):
            raise PolicyError(f"{name} appears to contain a credential")
        if "@everyone" in value.casefold() or "@here" in value.casefold():
            raise PolicyError(f"{name} contains a broadcast mention")
    if "\n" in proposal.commit_message or "\r" in proposal.commit_message:
        raise PolicyError("commit message must be one line")


def approve_run(
    config: AutocontributeConfig,
    store: RunStore,
    run_id: str,
    *,
    actor: str,
    attestation: str,
) -> RunManifest:
    manifest = store.get(run_id)
    if manifest.status != RunStatus.READY_FOR_APPROVAL:
        raise StateError(f"Run {run_id} is {manifest.status.value}, not ready_for_approval")
    if manifest.quality is None or not manifest.quality.ready:
        raise PolicyError("Run has not passed every quality gate")
    validate_publication_text(manifest)
    patch_path = store.artifact_dir(run_id) / "contribution.patch"
    if not patch_path.is_file() or patch_path.is_symlink():
        raise PolicyError("Contribution patch artifact is missing or unsafe")
    approval_manifest = build_approval_manifest(
        manifest,
        diff=patch_path.read_bytes(),
        disclosure=config.policy.ai_disclosure,
        publishing_login=actor,
        draft=config.publishing.draft,
    )
    manifest.approval = create_approval(
        approval_manifest,
        actor=actor,
        attestation=attestation,
        config=config.publishing,
    )
    store.save(
        manifest,
        event="approval.created",
        details={
            "actor": actor,
            "expires_at": manifest.approval.expires_at.isoformat(),
            "manifest_hash": manifest.approval.manifest_hash,
        },
    )
    store.transition(manifest, RunStatus.APPROVED, reason=f"approved by {actor}")
    return manifest


class Publisher:
    """Credential broker that performs one idempotent fork/branch/PR sequence."""

    def __init__(
        self,
        config: AutocontributeConfig,
        store: RunStore,
        github: GitHubClient,
    ) -> None:
        self.config = config
        self.store = store
        self.github = github

    def publish(self, run_id: str) -> RunManifest:
        manifest = self.store.get(run_id)
        if manifest.status == RunStatus.PR_OPEN and manifest.pull_request_url:
            return manifest
        if manifest.status not in {
            RunStatus.READY_FOR_APPROVAL,
            RunStatus.APPROVED,
            RunStatus.SUBMITTING,
        }:
            raise StateError(f"Run {run_id} cannot be published from {manifest.status.value}")
        if not manifest.quality or not manifest.quality.ready:
            raise PolicyError("Run has not passed every quality gate")
        if not manifest.candidate or not manifest.repository or not manifest.base_sha:
            raise PolicyError("Run is missing repository freshness evidence")
        validate_publication_text(manifest)

        patch_path = self.store.artifact_dir(run_id) / "contribution.patch"
        if not patch_path.is_file() or patch_path.is_symlink():
            raise PolicyError("Contribution patch artifact is missing or unsafe")
        patch = patch_path.read_bytes()
        if self.config.publishing.mode == "review_required":
            if manifest.approval is None:
                raise PolicyError("A human approval is required before publication")
        elif os.environ.get(self.config.publishing.auto_publish_env, "").casefold() not in {
            "1",
            "true",
            "yes",
        }:
            raise PolicyError(
                f"Automatic publication is disabled; set "
                f"{self.config.publishing.auto_publish_env}=1 deliberately"
            )

        login = self.github.authenticated_login()
        approval_manifest = build_approval_manifest(
            manifest,
            diff=patch,
            disclosure=self.config.policy.ai_disclosure,
            publishing_login=login,
            draft=self.config.publishing.draft,
        )
        if self.config.publishing.mode == "review_required":
            assert manifest.approval is not None
            if manifest.approval.actor.strip().casefold() != login.strip().casefold():
                raise PolicyError(
                    "The authenticated GitHub account differs from the account that approved "
                    "publication"
                )
            validate_approval(manifest.approval, approval_manifest)
        branch = manifest.branch_name or self._branch_name(manifest)
        manifest.branch_name = branch
        head = f"{login}:{branch}"

        existing_pr = self.github.find_pull_request(
            manifest.candidate.repository,
            head=head,
        )
        if existing_pr:
            if not manifest.commit_sha:
                raise PolicyError(
                    "Cannot reconcile an existing pull request without a stored commit SHA"
                )
            fork = f"{login}/{manifest.candidate.repository.split('/', 1)[1]}"
            remote_sha = self.github.ref_sha(fork, f"heads/{branch}")
            if remote_sha != manifest.commit_sha:
                raise PolicyError(
                    "Existing pull-request branch does not match the stored contribution commit"
                )
            manifest.pull_request_url = existing_pr
            if manifest.status != RunStatus.SUBMITTING:
                self.store.transition(
                    manifest, RunStatus.SUBMITTING, reason="reconciling existing PR"
                )
            self.store.transition(manifest, RunStatus.PR_OPEN, reason="existing PR reconciled")
            return manifest

        self._check_account_limits(login, manifest)
        self._check_freshness(manifest)
        workspace_path = self.store.workspace_dir(run_id) / "repository"
        workspace = self._prepare_workspace(manifest, workspace_path, patch)

        if manifest.status != RunStatus.SUBMITTING:
            self.store.transition(
                manifest,
                RunStatus.SUBMITTING,
                reason="authorized publication intent persisted",
            )
        self.store.save(
            manifest,
            event="github.mutation.intent",
            details={"repository": manifest.candidate.repository, "branch": branch},
        )

        fork = self.github.ensure_fork(manifest.candidate.repository, login)
        self._wait_for_fork(fork, manifest.repository.default_branch)
        if manifest.commit_sha:
            commit_sha = manifest.commit_sha
        else:
            if workspace is None:
                raise PolicyError("Publication workspace is missing its approved working tree")
            commit_sha = self._commit(workspace, manifest, login)
        manifest.commit_sha = commit_sha
        self.store.save(
            manifest,
            event="commit.created",
            details={"commit_sha": commit_sha, "branch": branch},
        )

        remote_sha = self.github.ref_sha(fork, f"heads/{branch}")
        if remote_sha is None:
            self._push(workspace_path, fork, branch)
            self.store.save(
                manifest,
                event="branch.pushed",
                details={"fork": fork, "branch": branch, "commit_sha": commit_sha},
            )
        elif remote_sha != commit_sha:
            raise PolicyError(
                "Publication branch already exists with different content; refusing to force-push"
            )

        proposal = manifest.proposal
        assert proposal is not None
        pull_request_url = self.github.create_pull_request(
            manifest.candidate.repository,
            title=proposal.pull_request_title,
            body=proposal.pull_request_body,
            head=head,
            base=manifest.repository.default_branch,
            draft=self.config.publishing.draft,
        )
        manifest.pull_request_url = pull_request_url
        self.store.save(
            manifest,
            event="pull_request.created",
            details={"url": pull_request_url},
        )
        self.store.transition(manifest, RunStatus.PR_OPEN, reason="pull request opened")
        return manifest

    def _check_freshness(self, manifest: RunManifest) -> None:
        assert manifest.candidate and manifest.repository and manifest.base_sha
        issue = self.github.get_issue(manifest.candidate.repository, manifest.candidate.number)
        if issue.state.casefold() != "open":
            raise PolicyError("Issue is no longer open; approval is stale")
        if issue.assignees and not self.config.policy.allow_assigned_issues:
            raise PolicyError("Issue was assigned after preparation; approval is stale")
        competing = self.github.search_competing_pull_requests(
            manifest.candidate.repository, manifest.candidate.number
        )
        if competing:
            raise PolicyError(f"A competing pull request now exists: {competing[0]}")
        current_sha = self.github.default_branch_sha(
            manifest.repository.full_name, manifest.repository.default_branch
        )
        if current_sha != manifest.base_sha:
            raise PolicyError("The upstream base branch moved; rerun validation and approval")

    def _check_account_limits(self, login: str, manifest: RunManifest) -> None:
        assert manifest.candidate
        open_prs = self.github.authored_pull_requests(login, state="open")
        if len(open_prs) >= self.config.publishing.max_open_pull_requests:
            raise PolicyError("Maximum number of open Autocontribute-era PRs reached")

        today = datetime.now(UTC).date().isoformat()
        recent = self.github.authored_pull_requests(
            login,
            state="open",
            created_after=today,
        ) + self.github.authored_pull_requests(
            login,
            state="closed",
            created_after=today,
        )
        if len(recent) >= self.config.publishing.max_new_pull_requests_per_day:
            raise PolicyError("Daily new pull-request limit reached")

        cooldown_start = (
            (datetime.now(UTC) - timedelta(days=self.config.publishing.repository_cooldown_days))
            .date()
            .isoformat()
        )
        same_repo = self.github.authored_pull_requests(
            login,
            state="open",
            repository=manifest.candidate.repository,
        ) + self.github.authored_pull_requests(
            login,
            state="closed",
            repository=manifest.candidate.repository,
            updated_after=cooldown_start,
        )
        if same_repo:
            raise PolicyError("Repository cooldown is active for this account")

    def _prepare_workspace(
        self,
        manifest: RunManifest,
        path: Path,
        patch: bytes,
    ) -> RepositoryWorkspace | None:
        assert manifest.repository and manifest.base_sha
        if manifest.commit_sha:
            if not path.is_dir():
                raise PolicyError(
                    "Publication workspace containing the stored commit is missing; refusing "
                    "to reconstruct or push a different HEAD"
                )
            head = _git(path, ["rev-parse", "HEAD"]).strip()
            if head != manifest.commit_sha:
                raise PolicyError(
                    "Publication workspace HEAD does not match the stored contribution commit"
                )
            # A prior attempt committed before an uncertain push. The caller can reconcile or
            # push this exact commit without regenerating it.
            return None
        if path.is_dir():
            head = _git(path, ["rev-parse", "HEAD"]).strip()
            if head == manifest.base_sha:
                workspace = RepositoryWorkspace(path, manifest.base_sha)
                if workspace.diff_bytes() != patch:
                    raise PolicyError("Workspace diff no longer matches the approved artifact")
                return workspace
            raise PolicyError("Publication workspace HEAD no longer matches the approved base")
        workspace = RepositoryWorkspace.clone(
            manifest.repository.clone_url,
            manifest.base_sha,
            path,
        )
        _git_apply(workspace.path, patch)
        if workspace.diff_bytes() != patch:
            raise PolicyError("Reconstructed diff does not match the approved artifact")
        return workspace

    def _commit(self, workspace: RepositoryWorkspace, manifest: RunManifest, login: str) -> str:
        proposal = manifest.proposal
        assert proposal is not None
        name = self.config.identity.name.strip() or login
        email = self.config.identity.email.strip() or f"{login}@users.noreply.github.com"
        _git(workspace.path, ["add", "--all"])
        _git(workspace.path, ["diff", "--cached", "--check"])
        _git(
            workspace.path,
            [
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "commit.gpgsign=false",
                "-c",
                f"user.name={name}",
                "-c",
                f"user.email={email}",
                "commit",
                "--no-verify",
                "--message",
                proposal.commit_message,
            ],
        )
        return _git(workspace.path, ["rev-parse", "HEAD"]).strip()

    def _push(self, workspace: Path, fork: str, branch: str) -> None:
        with tempfile.TemporaryDirectory(prefix="autocontribute-askpass-") as temporary:
            askpass = Path(temporary) / "askpass.sh"
            askpass.write_text(
                "#!/bin/sh\n"
                'case "$1" in\n'
                "  *Username*) printf '%s\\n' x-access-token ;;\n"
                "  *) printf '%s\\n' \"$AUTOCONTRIBUTE_GIT_TOKEN\" ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            askpass.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            _git(
                workspace,
                [
                    "-c",
                    "core.hooksPath=/dev/null",
                    "push",
                    f"https://github.com/{fork}.git",
                    f"HEAD:refs/heads/{branch}",
                ],
                extra_env={
                    "GIT_ASKPASS": str(askpass),
                    "GIT_TERMINAL_PROMPT": "0",
                    "AUTOCONTRIBUTE_GIT_TOKEN": self.github.token,
                },
            )

    def _wait_for_fork(self, fork: str, default_branch: str) -> None:
        for _ in range(10):
            if self.github.ref_sha(fork, f"heads/{default_branch}"):
                return
            time.sleep(1)
        raise GitHubError("Fork was not ready after 10 seconds; rerun publish to reconcile")

    def _branch_name(self, manifest: RunManifest) -> str:
        assert manifest.candidate
        prefix = _SAFE_SLUG.sub("-", self.config.publishing.branch_prefix.casefold()).strip("-")
        if not prefix:
            prefix = "autocontribute"
        return f"{prefix}/issue-{manifest.candidate.number}-{manifest.run_id[:8]}"


def _git_apply(workspace: Path, patch: bytes) -> None:
    environment = _git_environment()
    command = [
        "git",
        "-c",
        "core.hooksPath=/dev/null",
        "apply",
        "--index",
        "--whitespace=error-all",
        "--recount",
        "-",
    ]
    result = subprocess.run(
        command,
        cwd=workspace,
        env=environment,
        input=patch,
        capture_output=True,
        check=False,
        timeout=60,
    )
    if result.returncode != 0:
        raise RepositoryError("Approved patch could not be reconstructed with git apply")
    # Return the workspace to an unstaged patch, matching RepositoryWorkspace's invariant.
    _git(workspace, ["reset", "--mixed", "HEAD"])


def _git(
    workspace: Path,
    arguments: list[str],
    *,
    extra_env: dict[str, str] | None = None,
) -> str:
    environment = _git_environment()
    if extra_env:
        environment.update(extra_env)
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=workspace,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RepositoryError(f"Git operation failed to start: {type(exc).__name__}") from exc
    if result.returncode != 0:
        detail = redact_text((result.stderr or result.stdout).strip())[:1_000]
        raise RepositoryError(f"Git operation failed: {detail}")
    return result.stdout


def _git_environment() -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", "/tmp"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_LFS_SKIP_SMUDGE": "1",
    }


__all__ = ["Publisher", "approve_run", "validate_publication_text"]
