"""Domain models shared by the orchestrator, providers, and audit store."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def utc_now() -> datetime:
    return datetime.now(UTC)


class DomainModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RunStatus(StrEnum):
    QUEUED = "queued"
    DISCOVERING = "discovering"
    CANDIDATE_SELECTED = "candidate_selected"
    ELIGIBILITY_CHECKED = "eligibility_checked"
    PLANNING = "planning"
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
        RunStatus.PLANNING,
        RunStatus.SKIPPED,
        RunStatus.FAILED,
    },
    RunStatus.PLANNING: {
        RunStatus.IMPLEMENTING,
        RunStatus.SKIPPED,
        RunStatus.FAILED,
    },
    RunStatus.IMPLEMENTING: {
        RunStatus.VALIDATING,
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
    RunStatus.READY_FOR_APPROVAL: {
        RunStatus.APPROVED,
        RunStatus.SUBMITTING,
        RunStatus.CANCELLED,
    },
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


class ContributionPlan(DomainModel):
    decision: Literal["proceed", "skip"]
    decision_reason: str
    contribution_kind: Literal["bugfix", "documentation", "test"]
    issue_understanding: str
    acceptance_criteria: list[str]
    implementation_steps: list[str]
    files_to_read: list[str]
    reproduction_command: str | None
    validation_commands: list[str]
    risks: list[str]
    maintainer_fit: str

    @field_validator("files_to_read")
    @classmethod
    def unique_files(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(values))


class FileEdit(DomainModel):
    operation: Literal["replace", "create", "delete"]
    path: str
    find: str | None
    replace: str | None
    content: str | None
    rationale: str

    @model_validator(mode="after")
    def operation_fields_match(self) -> FileEdit:
        if self.operation == "replace" and (self.find is None or self.replace is None):
            raise ValueError("replace edits require find and replace")
        if self.operation == "create" and self.content is None:
            raise ValueError("create edits require content")
        if self.operation == "delete" and any(
            value is not None for value in (self.find, self.replace, self.content)
        ):
            raise ValueError("delete edits cannot include find, replace, or content")
        return self


class PatchProposal(DomainModel):
    summary: str
    edits: list[FileEdit]
    validation_commands: list[str]
    commit_message: str
    pull_request_title: str
    pull_request_body: str
    limitations: list[str]

    @field_validator("edits")
    @classmethod
    def requires_an_edit(cls, values: list[FileEdit]) -> list[FileEdit]:
        if not values:
            raise ValueError("a patch proposal must contain at least one edit")
        return values


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


class ReviewScores(DomainModel):
    correctness: int = Field(ge=0, le=100)
    issue_alignment: int = Field(ge=0, le=100)
    tests: int = Field(ge=0, le=100)
    repository_conventions: int = Field(ge=0, le=100)
    diff_hygiene: int = Field(ge=0, le=100)
    maintainer_clarity: int = Field(ge=0, le=100)

    def weighted_score(self) -> int:
        value = (
            self.correctness * 0.25
            + self.issue_alignment * 0.25
            + self.tests * 0.15
            + self.repository_conventions * 0.15
            + self.diff_hygiene * 0.10
            + self.maintainer_clarity * 0.10
        )
        return round(value)

    def minimum(self) -> int:
        return min(
            self.correctness,
            self.issue_alignment,
            self.tests,
            self.repository_conventions,
            self.diff_hygiene,
            self.maintainer_clarity,
        )


class CriticReview(DomainModel):
    verdict: Literal["approve", "reject"]
    summary: str
    scores: ReviewScores
    blocking_findings: list[str]
    non_blocking_findings: list[str]
    issue_requirements_met: list[str]
    issue_requirements_missing: list[str]
    test_evidence_assessment: str
    maintainer_perspective: str


class GateResult(DomainModel):
    gate: str
    passed: bool
    evidence: str


class QualityReport(DomainModel):
    ready: bool
    readiness_score: int = Field(ge=0, le=100)
    gates: list[GateResult]
    review: CriticReview
    changed_files: int
    changed_lines: int

    @property
    def failed_gates(self) -> list[GateResult]:
        return [gate for gate in self.gates if not gate.passed]


class Approval(DomainModel):
    actor: str
    approved_at: datetime
    expires_at: datetime
    manifest_hash: str
    attestation: str


class ModelBudgetReservation(DomainModel):
    """A durable, conservative charge recorded before one external model request."""

    call: int = Field(ge=1)
    role: Literal["scout", "builder", "critic"]
    input_tokens: int = Field(ge=1)
    output_tokens: int = Field(ge=1)
    cost_usd: Decimal = Field(default=Decimal("0"), ge=0)
    timeout_seconds: float = Field(gt=0)
    started_at: datetime


class RunManifest(DomainModel):
    schema_version: int = 1
    run_id: str
    status: RunStatus
    created_at: datetime
    updated_at: datetime
    deployment_fingerprint: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    candidate: IssueCandidate | None = None
    eligibility: EligibilityResult | None = None
    repository: RepositoryInfo | None = None
    base_sha: str | None = None
    plan: ContributionPlan | None = None
    proposal: PatchProposal | None = None
    baseline_validation: CommandResult | None = None
    patched_validation: list[CommandResult] = Field(default_factory=list)
    quality: QualityReport | None = None
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
    branch_name: str | None = None
    commit_sha: str | None = None
    pull_request_creation_started: bool = False
    pull_request_ready_started: bool = False
    pull_request_ready_completed: bool = False
    publication_compensation_reason: (
        Literal[
            "pre_pr_base_moved",
            "created_pr_base_moved",
        ]
        | None
    ) = None
    pull_request_url: str | None = None
    skip_reason: str | None = None
    error: str | None = None
    model_calls: int = 0
    model_input_tokens: int = Field(default=0, ge=0)
    model_output_tokens: int = Field(default=0, ge=0)
    model_cost_usd: Decimal = Field(default=Decimal("0"), ge=0)
    model_seconds: float = Field(default=0, ge=0)
    model_reservation: ModelBudgetReservation | None = None


__all__ = [
    "ALLOWED_TRANSITIONS",
    "TERMINAL_STATUSES",
    "Approval",
    "CommandResult",
    "ContributionPlan",
    "CriticReview",
    "EligibilityResult",
    "FileEdit",
    "GateResult",
    "IssueCandidate",
    "IssueComment",
    "ModelBudgetReservation",
    "PatchProposal",
    "QualityReport",
    "RepositoryInfo",
    "RunManifest",
    "RunStatus",
    "utc_now",
]
