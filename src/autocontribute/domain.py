"""Domain models shared by the orchestrator, providers, and audit store."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from autocontribute.exceptions import StateError


def utc_now() -> datetime:
    return datetime.now(UTC)


class DomainModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RunStatus(StrEnum):
    QUEUED = "queued"
    DISCOVERING = "discovering"
    CANDIDATE_SELECTED = "candidate_selected"
    ELIGIBILITY_CHECKED = "eligibility_checked"
    SETTING_UP = "setting_up"
    IMPLEMENTING = "implementing"
    VALIDATING = "validating"
    CRITIQUING = "critiquing"
    READY_FOR_APPROVAL = "ready_for_approval"
    APPROVED = "approved"
    SUBMITTING = "submitting"
    PR_OPEN = "pr_open"
    SKIPPED = "skipped"
    REJECTED = "rejected"
    FAILED = "failed"
    CANCELLED = "cancelled"


TERMINAL_STATUSES = {
    RunStatus.PR_OPEN,
    RunStatus.SKIPPED,
    RunStatus.REJECTED,
    RunStatus.FAILED,
    RunStatus.CANCELLED,
}

ALLOWED_TRANSITIONS: dict[RunStatus, set[RunStatus]] = {
    RunStatus.QUEUED: {RunStatus.DISCOVERING, RunStatus.CANCELLED, RunStatus.FAILED},
    RunStatus.DISCOVERING: {
        RunStatus.CANDIDATE_SELECTED,
        RunStatus.SKIPPED,
        RunStatus.FAILED,
    },
    RunStatus.CANDIDATE_SELECTED: {
        RunStatus.ELIGIBILITY_CHECKED,
        RunStatus.SKIPPED,
        RunStatus.FAILED,
    },
    RunStatus.ELIGIBILITY_CHECKED: {
        RunStatus.SETTING_UP,
        RunStatus.SKIPPED,
        RunStatus.FAILED,
    },
    RunStatus.SETTING_UP: {
        RunStatus.IMPLEMENTING,
        RunStatus.SKIPPED,
        RunStatus.FAILED,
    },
    RunStatus.IMPLEMENTING: {
        RunStatus.VALIDATING,
        # The agent declines the issue.
        RunStatus.SKIPPED,
        RunStatus.REJECTED,
        RunStatus.FAILED,
    },
    RunStatus.VALIDATING: {
        RunStatus.CRITIQUING,
        RunStatus.IMPLEMENTING,
        RunStatus.REJECTED,
        RunStatus.FAILED,
    },
    RunStatus.CRITIQUING: {
        RunStatus.IMPLEMENTING,
        RunStatus.READY_FOR_APPROVAL,
        RunStatus.REJECTED,
        RunStatus.FAILED,
    },
    RunStatus.READY_FOR_APPROVAL: {RunStatus.APPROVED, RunStatus.CANCELLED},
    RunStatus.APPROVED: {RunStatus.SUBMITTING, RunStatus.CANCELLED},
    RunStatus.SUBMITTING: {
        RunStatus.PR_OPEN,
        RunStatus.READY_FOR_APPROVAL,
        RunStatus.FAILED,
    },
}


class RepositoryInfo(DomainModel):
    full_name: str
    html_url: str
    clone_url: str
    default_branch: str
    stars: int
    archived: bool
    disabled: bool
    private: bool
    pushed_at: datetime | None
    license_spdx: str | None
    # Maintainers can turn pull requests off or limit them to collaborators.
    has_pull_requests: bool = True
    pull_request_creation_policy: str | None = None


class IssueComment(DomainModel):
    """One bounded issue-discussion entry used as untrusted planning evidence."""

    author: str
    author_association: str
    body: str
    html_url: str
    created_at: datetime
    updated_at: datetime


class IssueCandidate(DomainModel):
    repository: str
    number: int
    title: str
    body: str
    html_url: str
    state: str
    locked: bool = False
    author: str
    labels: list[str]
    assignees: list[str]
    comments: int
    discussion: list[IssueComment] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime
    score: int = 0
    score_evidence: dict[str, str] = Field(default_factory=dict)

    @property
    def reference(self) -> str:
        return f"{self.repository}#{self.number}"


class EligibilityResult(DomainModel):
    eligible: bool
    score: int = Field(ge=0, le=100)
    evidence: dict[str, str]
    blockers: list[str]


class PatchProposal(DomainModel):
    """The pull request a prepared run proposes, as ``pr_text`` assembled it."""

    # The agent's account of what was wrong and what changed: its claims, for the reviewer.
    summary: str
    commit_message: str
    pull_request_title: str
    pull_request_body: str
    # The tests the agent added or changed, and the command it ran them with.
    test_files: list[str]
    test_command: str | None
    # policy.ai_disclosure with {version} and {model} filled; the body shows it, and the
    # approval binds it.
    disclosure: str


class CommandResult(DomainModel):
    command: str
    exit_code: int
    duration_seconds: float
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def passed(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


class GateResult(DomainModel):
    gate: str
    passed: bool
    evidence: str


class QualityReport(DomainModel):
    """The checks and the review of a run's fix; ``ready`` when both passed (DESIGN §7.2).

    ``validation.json`` holds every review round in full.
    """

    ready: bool
    # The gates of the fix's last check.
    gates: list[GateResult]
    review_rounds: int = Field(ge=1)
    # The last round's summary and its notes that do not block the change.
    review_summary: str
    review_notes: list[str]

    @property
    def failed_gates(self) -> list[GateResult]:
        return [gate for gate in self.gates if not gate.passed]


PullRequestAttentionKind = Literal[
    "changes_requested", "ci_failed", "maintainer_push", "observation_failed"
]


class PullRequestAttention(DomainModel):
    """A routine pull-request event for the approving human to handle; it stops no work."""

    kind: PullRequestAttentionKind
    reason: str
    source_url: str
    evidence_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    observed_at: datetime


class Approval(DomainModel):
    actor: str
    approved_at: datetime
    expires_at: datetime
    manifest_hash: str
    attestation: str


class ModelBudgetReservation(DomainModel):
    """A durable, conservative charge recorded before one external model request."""

    call: int = Field(ge=1)
    # The budget scope of the request (``budget.py``).
    role: Literal["agent", "critic", "setup", "triage"]
    input_tokens: int = Field(ge=1)
    output_tokens: int = Field(ge=1)
    cost_usd: Decimal = Field(default=Decimal("0"), ge=0)
    timeout_seconds: float = Field(gt=0)
    started_at: datetime


class RunModels(DomainModel):
    """The model of each role in a run, after ``auto`` was resolved (DESIGN §2)."""

    agent: str
    critic: str
    setup: str
    triage: str


class RunEnvironment(DomainModel):
    """The accepted test environment of a run; ``validation.json`` has its full recipe."""

    recipe_source: Literal["config", "cached", "detected", "agent"]
    image_id: str
    base_image: str
    # What the base image's tag resolved to when the environment was built.
    base_digest: str
    test_command: str


class RunManifest(DomainModel):
    schema_version: int = 1
    run_id: str
    status: RunStatus
    created_at: datetime
    updated_at: datetime
    candidate: IssueCandidate | None = None
    eligibility: EligibilityResult | None = None
    repository: RepositoryInfo | None = None
    base_sha: str | None = None
    models: RunModels | None = None
    environment: RunEnvironment | None = None
    proposal: PatchProposal | None = None
    quality: QualityReport | None = None
    # The SHA-256 of runs/<id>/validation.json, which the approval binds; set when the run
    # becomes ready.
    validation_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    preparation_config_fingerprint: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    preparation_fingerprint: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    approval: Approval | None = None
    publishing_login: str | None = None
    publishing_api_origin: str | None = None
    commit_author_name: str | None = None
    commit_author_email: str | None = None
    commit_committer_name: str | None = None
    commit_committer_email: str | None = None
    publication_draft: bool | None = None
    publication_ready_for_review: bool | None = None
    # GitHub owner/name pairs are mutable.  These immutable remote identifiers are bound before
    # publication mutates a branch and are required by automatic compensation.  ``None`` remains
    # accepted so historical manifests can be inspected, but old in-flight publication evidence
    # is deliberately not eligible for destructive recovery.
    upstream_repository_id: int | None = Field(default=None, gt=0)
    upstream_repository_node_id: str | None = Field(default=None, min_length=1, max_length=256)
    # The fork_* identity names whichever repository holds the branch: the publishing
    # account's fork, or the upstream itself in same-repository mode.
    fork_repository_id: int | None = Field(default=None, gt=0)
    fork_repository_node_id: str | None = Field(default=None, min_length=1, max_length=256)
    # Bound by the reviewed approval. None only for runs approved before it existed, which
    # always published from ``<publishing_login>/<name>``.
    head_repository: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
    branch_name: str | None = None
    commit_sha: str | None = None
    pull_request_creation_started: bool = False
    pull_request_ready_started: bool = False
    pull_request_ready_completed: bool = False
    publication_compensation_reason: (
        Literal[
            "pre_pr_base_moved",
            "pre_pr_policy_stale",
            "pre_pr_creation_refused",
            "created_pr_base_moved",
        ]
        | None
    ) = None
    pull_request_url: str | None = None
    pull_request_node_id: str | None = Field(default=None, min_length=1, max_length=256)
    # Set by lifecycle sync. Sync stops observing a closed pull request, and watches a merged one
    # only for a revert, for 30 days after it merged.
    pull_request_state: Literal["open", "merged", "closed"] | None = None
    pull_request_merged_at: datetime | None = None
    pull_request_attention: list[PullRequestAttention] = Field(default_factory=list)
    skip_reason: str | None = None
    # Why a prepared change was not good enough: the agent did not finish, the critic rejected
    # it, or its pull request text cannot be published.
    reject_reason: str | None = None
    error: str | None = None
    model_calls: int = 0
    model_input_tokens: int = Field(default=0, ge=0)
    model_output_tokens: int = Field(default=0, ge=0)
    model_cost_usd: Decimal = Field(default=Decimal("0"), ge=0)
    model_seconds: float = Field(default=0, ge=0)
    model_reservation: ModelBudgetReservation | None = None

    @field_validator(
        "upstream_repository_node_id",
        "fork_repository_node_id",
        "pull_request_node_id",
    )
    @classmethod
    def immutable_github_node_id(cls, value: str | None) -> str | None:
        if value is not None and (
            value != value.strip() or any(not character.isprintable() for character in value)
        ):
            raise ValueError("GitHub node identifiers must be bounded printable strings")
        return value

    @model_validator(mode="after")
    def immutable_remote_identity_is_complete(self) -> RunManifest:
        upstream = (self.upstream_repository_id, self.upstream_repository_node_id)
        fork = (self.fork_repository_id, self.fork_repository_node_id)
        if (upstream[0] is None) != (upstream[1] is None):
            raise ValueError("upstream repository immutable identity must be complete")
        if (fork[0] is None) != (fork[1] is None):
            raise ValueError("fork repository immutable identity must be complete")
        if fork[0] is not None and upstream[0] is None:
            raise ValueError("fork immutable identity requires upstream immutable identity")
        if self.pull_request_node_id is not None and self.pull_request_url is None:
            raise ValueError("pull-request node identity requires its canonical URL")
        return self


@dataclass(frozen=True, slots=True)
class PublicationHead:
    """Where a run's pull-request branch lives and how GitHub's ``head`` filter names it."""

    repository: str
    label: str
    same_repository: bool


def publication_head(manifest: RunManifest) -> PublicationHead:
    if manifest.candidate is None or manifest.branch_name is None:
        raise StateError("Publication head needs the run's repository and branch")
    repository = manifest.head_repository
    if repository is None:
        if manifest.publishing_login is None:
            raise StateError("Publication head needs the run's publishing login")
        repository = f"{manifest.publishing_login}/{manifest.candidate.repository.split('/', 1)[1]}"
    return PublicationHead(
        repository=repository,
        label=f"{repository.split('/', 1)[0]}:{manifest.branch_name}",
        same_repository=repository.casefold() == manifest.candidate.repository.casefold(),
    )


__all__ = [
    "ALLOWED_TRANSITIONS",
    "TERMINAL_STATUSES",
    "Approval",
    "CommandResult",
    "EligibilityResult",
    "GateResult",
    "IssueCandidate",
    "IssueComment",
    "ModelBudgetReservation",
    "PatchProposal",
    "PublicationHead",
    "PullRequestAttention",
    "PullRequestAttentionKind",
    "QualityReport",
    "RepositoryInfo",
    "RunEnvironment",
    "RunManifest",
    "RunModels",
    "RunStatus",
    "publication_head",
    "utc_now",
]
