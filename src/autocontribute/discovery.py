"""Issue-first discovery and deterministic eligibility scoring."""

from __future__ import annotations

import re
from datetime import UTC, datetime

from autocontribute.config import AutocontributeConfig
from autocontribute.domain import EligibilityResult, IssueCandidate, RepositoryInfo
from autocontribute.github import GitHubClient
from autocontribute.store import RunStore

_CLARITY_TERMS = re.compile(
    r"\b(expected|actual|acceptance|should|reproduce|steps|behavior|documentation)\b", re.I
)
_REPRODUCTION_TERMS = re.compile(
    r"\b(repro(?:duce|duction)?|traceback|error|fails?|incorrect|bug|typo|broken)\b", re.I
)
_DANGEROUS_TERMS = re.compile(
    r"\b(CVE-\d{4}-\d+|vulnerabilit(?:y|ies)|remote code execution|credential leak)\b", re.I
)
_AI_PROHIBITION = re.compile(
    r"\b(no|do not|don't|must not|prohibit(?:ed)?)\b.{0,40}\b"
    r"(AI|LLM|artificial intelligence|generated code)\b",
    re.I | re.S,
)

_GUIDANCE_PATHS = (
    "CONTRIBUTING.md",
    ".github/CONTRIBUTING.md",
    "docs/CONTRIBUTING.md",
)
_AI_POLICY_PATHS = (
    ".github/AI_POLICY.md",
    "AI_POLICY.md",
    "CONTRIBUTING.md",
    ".github/CONTRIBUTING.md",
)


class DiscoveryService:
    def __init__(
        self,
        config: AutocontributeConfig,
        github: GitHubClient,
        store: RunStore,
    ) -> None:
        self.config = config
        self.github = github
        self.store = store

    def repositories(self) -> list[RepositoryInfo]:
        by_name: dict[str, RepositoryInfo] = {}
        for full_name in self.config.github.repositories:
            repository = self.github.get_repository(full_name)
            by_name[repository.full_name] = repository
        for owner in self.config.github.owners:
            for repository in self.github.list_owner_repositories(
                owner, limit=self.config.github.repository_limit_per_owner
            ):
                by_name[repository.full_name] = repository
        return sorted(by_name.values(), key=lambda repo: repo.stars, reverse=True)

    def discover(self) -> tuple[IssueCandidate, RepositoryInfo, EligibilityResult] | None:
        ranked: list[tuple[IssueCandidate, RepositoryInfo, EligibilityResult]] = []
        for repository in self.repositories():
            if not self._repository_baseline(repository):
                continue
            issues = self.github.search_issues(
                repository.full_name,
                labels=self.config.github.include_labels,
                limit=self.config.github.issue_limit_per_repository,
            )
            for issue in issues:
                if self.store.has_active_candidate(issue.repository, issue.number):
                    continue
                eligibility = self.evaluate(issue, repository)
                issue.score = eligibility.score
                issue.score_evidence = eligibility.evidence
                if eligibility.eligible:
                    ranked.append((issue, repository, eligibility))
                if len(ranked) >= self.config.budget.max_candidates_per_run:
                    break
            if len(ranked) >= self.config.budget.max_candidates_per_run:
                break
        if not ranked:
            return None
        ranked.sort(key=lambda item: (item[2].score, item[0].updated_at), reverse=True)
        return ranked[0]

    def evaluate(
        self,
        issue: IssueCandidate,
        repository: RepositoryInfo,
        *,
        check_remote_policy: bool = True,
    ) -> EligibilityResult:
        blockers: list[str] = []
        labels = {label.casefold() for label in issue.labels}
        include = {label.casefold() for label in self.config.github.include_labels}
        exclude = {label.casefold() for label in self.config.github.exclude_labels}

        if not self._repository_baseline(repository):
            blockers.append(
                "repository is private, archived, disabled, inactive, or below the star floor"
            )
        if issue.state.casefold() != "open":
            blockers.append("issue is not open")
        if self.config.policy.require_maintainer_signal and not labels.intersection(include):
            blockers.append("issue has no configured maintainer-signal label")
        excluded = labels.intersection(exclude)
        if excluded:
            blockers.append(f"issue has excluded labels: {', '.join(sorted(excluded))}")
        if issue.assignees and not (
            self.config.policy.allow_assigned_issues or not self.config.github.require_unassigned
        ):
            blockers.append("issue is already assigned")
        age = (datetime.now(UTC) - issue.updated_at).days
        if age > self.config.github.max_issue_age_days:
            blockers.append(f"issue has not been updated for {age} days")
        if _DANGEROUS_TERMS.search(f"{issue.title}\n{issue.body}") and not (
            self.config.policy.allow_security_issues
        ):
            blockers.append("issue may concern a vulnerability and requires private handling")

        evidence: dict[str, str] = {}
        signal = 25 if labels.intersection(include) else 0
        evidence["maintainer_signal"] = (
            f"{signal}/25: labels={sorted(labels.intersection(include))}"
        )

        body_length = len(issue.body.strip())
        clarity = 10 if body_length >= 100 else 0
        if body_length >= 300 and _CLARITY_TERMS.search(issue.body):
            clarity = 20
        elif _CLARITY_TERMS.search(issue.body):
            clarity = max(clarity, 15)
        evidence["clarity"] = f"{clarity}/20: body_length={body_length}"

        issue_text = f"{issue.title}\n{issue.body}"
        reproducibility = 20 if _REPRODUCTION_TERMS.search(issue_text) else 5
        evidence["reproducibility"] = f"{reproducibility}/20"

        scope_labels = {"good first issue", "small", "size/s", "documentation", "bug"}
        scope = 15 if labels.intersection(scope_labels) else 7
        evidence["scope"] = f"{scope}/15"

        activity = 10 if age <= 30 else 7 if age <= 90 else 3
        evidence["activity"] = f"{activity}/10: updated_days_ago={age}"

        policy_fit = 10 if not excluded else 0
        evidence["policy_fit"] = f"{policy_fit}/10"

        if check_remote_policy:
            contribution_policy = self._first_existing_file(repository.full_name, _GUIDANCE_PATHS)
            if self.config.policy.require_contribution_guidelines and contribution_policy is None:
                blockers.append("no contribution guidelines were found")
                policy_fit = 0
                evidence["policy_fit"] = "0/10: contribution guidelines missing"
            ai_policy = self._combined_existing_files(repository.full_name, _AI_POLICY_PATHS)
            if ai_policy and _AI_PROHIBITION.search(ai_policy):
                blockers.append("repository policy appears to prohibit AI-assisted contributions")
                policy_fit = 0
                evidence["policy_fit"] = "0/10: AI-assistance prohibition detected"

        competing = self.github.search_competing_pull_requests(repository.full_name, issue.number)
        if competing:
            blockers.append(f"possible competing pull request already exists: {competing[0]}")
            evidence["no_duplicate"] = f"0/required: {len(competing)} possible duplicate(s)"
        else:
            evidence["no_duplicate"] = "passed: no open PR references the issue"

        score = signal + clarity + reproducibility + scope + activity + policy_fit
        threshold = self.config.quality.min_candidate_score
        if score < threshold:
            blockers.append(f"candidate score {score} is below required {threshold}")
        return EligibilityResult(
            eligible=not blockers,
            score=score,
            evidence=evidence,
            blockers=blockers,
        )

    def _repository_baseline(self, repository: RepositoryInfo) -> bool:
        return (
            not repository.private
            and not repository.archived
            and not repository.disabled
            and repository.stars >= self.config.github.min_stars
        )

    def _first_existing_file(self, repository: str, paths: tuple[str, ...]) -> str | None:
        for path in paths:
            content = self.github.get_file(repository, path)
            if content:
                return content
        return None

    def _combined_existing_files(self, repository: str, paths: tuple[str, ...]) -> str:
        contents = [self.github.get_file(repository, path) for path in paths]
        return "\n".join(content for content in contents if content)


def parse_issue_reference(value: str) -> tuple[str, int]:
    """Parse `owner/repository#123` without accepting URLs or ambiguous shorthand."""

    match = re.fullmatch(r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)#([1-9][0-9]*)", value.strip())
    if not match:
        raise ValueError("issue must use owner/repository#number syntax")
    return match.group(1), int(match.group(2))


__all__ = ["DiscoveryService", "parse_issue_reference"]
