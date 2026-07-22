"""Issue-first discovery and deterministic eligibility scoring."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import PurePosixPath

from autocontribute.config import AutocontributeConfig
from autocontribute.domain import EligibilityResult, IssueCandidate, RepositoryInfo
from autocontribute.exceptions import CircuitBreakerTrigger, GitHubError, StateError
from autocontribute.github import GitHubClient
from autocontribute.store import RunStore

_CLARITY_TERMS = re.compile(
    r"\b(expected|actual|acceptance|should|reproduce|steps|behavior|documentation)\b", re.I
)
_REPRODUCTION_TERMS = re.compile(
    r"\b(repro(?:duce|duction)?|traceback|error|fails?|incorrect|bug|typo|broken)\b", re.I
)
_DANGEROUS_TERMS = re.compile(
    r"\b(CVE-\d{4}-\d+|vulnerabilit(?:y|ies)|remote code execution|credential leak|"
    r"SQL injection|cross[ -]site scripting|XSS)\b",
    re.I,
)
_AI_PROHIBITION = re.compile(
    r"(?:\b(?:no|do not|don't|must not|prohibit(?:ed)?|forbid(?:den)?|"
    r"reject(?:ed|ing)?|decline(?:d|ing)?|not accept(?:ed|ing)?|not allowed)\b"
    r".{0,120}\b(?:AI(?:[- ](?:generated|assisted))?|LLM(?:[- ]generated)?|"
    r"artificial intelligence|generated code|AI assistance)\b|"
    r"\b(?:AI(?:[- ](?:generated|assisted))?|LLM(?:[- ]generated)?|"
    r"artificial intelligence|generated code|AI assistance)\b.{0,120}"
    r"\b(?:prohibit(?:ed)?|forbid(?:den)?|reject(?:ed|ing)?|decline(?:d|ing)?|"
    r"not accept(?:ed|ing)?|not allowed|will be closed)\b)",
    re.I | re.S,
)
_AUTOMATION_PROHIBITION = re.compile(
    r"(?:\b(?:no|do not|don't|must not|prohibit(?:ed)?|forbid(?:den)?|"
    r"reject(?:ed|ing)?|decline(?:d|ing)?|not accept(?:ed|ing)?|not allowed)\b"
    r".{0,120}\b(?:bots?|bot[- ]authored|automated|automation)\b|"
    r"\b(?:bots?|bot[- ]authored|automated|automation)\b.{0,120}"
    r"\b(?:prohibit(?:ed)?|forbid(?:den)?|reject(?:ed|ing)?|decline(?:d|ing)?|"
    r"not accept(?:ed|ing)?|not allowed|will be closed)\b)",
    re.I | re.S,
)
_LEGAL_ATTESTATION = re.compile(
    r"(?:\b(?:must|required|requires?|need(?:ed)? to)\b.{0,100}"
    r"\b(?:signed-off-by|developer certificate of origin|\bDCO\b|"
    r"contributor license agreement|\bCLA\b)\b|"
    r"\b(?:signed-off-by|developer certificate of origin|\bDCO\b|"
    r"contributor license agreement|\bCLA\b)\b.{0,100}"
    r"\b(?:must|required|requires?|need(?:ed)? to|sign|agree)\b|"
    r"\bby submitting\b.{0,120}\b(?:developer certificate of origin|\bDCO\b|"
    r"contributor license agreement|\bCLA\b)\b)",
    re.I | re.S,
)
_WORK_CLAIM = re.compile(
    r"\b(?:i(?:'m| am|\u2019m) working on (?:this|it)|"
    r"i(?:'ll| will) (?:take|work on) (?:this|it)|"
    r"working on (?:a |the )?(?:fix|pull request|pr)|"
    r"please assign (?:this|it) to me)\b",
    re.I,
)
_MAINTAINER_STOP = re.compile(
    r"\b(?:do not|don't|please (?:do not|don't)|stop|hold off|not accepting|"
    r"already (?:being )?worked on|no (?:pull request|pr)s? needed)\b",
    re.I,
)
_NEGATED_STOP_DIRECTIVE = re.compile(
    r"\b(?:do\s+not|don't|never)\s+(?:stop|cease|pause|hold\s+off)\b",
    re.I,
)
_BOT_LOGIN = re.compile(r"\[bot\]$", re.I)
_GIT_SHA = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_MAINTAINER_ASSOCIATIONS = {"OWNER", "MEMBER", "COLLABORATOR"}

MAX_POLICY_FILES_PER_REPOSITORY = 128
MAX_POLICY_FILE_BYTES = 256_000
MAX_POLICY_TOTAL_BYTES = 4_000_000
MAX_POLICY_INVENTORY_FILES = 20_000

_GUIDANCE_PATHS = (
    "CONTRIBUTING.md",
    "CONTRIBUTING.rst",
    "CONTRIBUTING.txt",
    ".github/CONTRIBUTING.md",
    ".github/CONTRIBUTING.rst",
    "docs/CONTRIBUTING.md",
    "docs/CONTRIBUTING.rst",
    "CONTRIBUTION_GUIDELINES.md",
    "docs/CONTRIBUTION_GUIDELINES.md",
)
_AI_POLICY_PATHS = (
    ".github/AI_POLICY.md",
    ".github/AI-CONTRIBUTIONS.md",
    ".github/AI_CONTRIBUTIONS.md",
    ".github/AUTOMATION_POLICY.md",
    ".github/BOT_POLICY.md",
    "AI_POLICY.md",
    "AI-CONTRIBUTIONS.md",
    "AI_CONTRIBUTIONS.md",
    "AUTOMATION_POLICY.md",
    "BOT_POLICY.md",
    "LLM_POLICY.md",
    "docs/AI_POLICY.md",
    "docs/AI-CONTRIBUTIONS.md",
    "docs/AUTOMATION_POLICY.md",
    "CONTRIBUTING.md",
    ".github/CONTRIBUTING.md",
)
_LEGAL_POLICY_PATHS = (
    "CONTRIBUTING.md",
    ".github/CONTRIBUTING.md",
    "DCO.md",
    ".github/DCO.md",
    "docs/DCO.md",
    "CLA.md",
    ".github/CLA.md",
    "docs/CLA.md",
    "CONTRIBUTOR_LICENSE_AGREEMENT.md",
    "DEVELOPER_CERTIFICATE_OF_ORIGIN.md",
)
_SECURITY_POLICY_PATHS = (
    "SECURITY.md",
    ".github/SECURITY.md",
    "docs/SECURITY.md",
    "CODE_OF_CONDUCT.md",
    ".github/CODE_OF_CONDUCT.md",
    "SUPPORT.md",
    ".github/SUPPORT.md",
    "CONTRIBUTION_POLICY.md",
    ".github/CONTRIBUTION_POLICY.md",
    "docs/CONTRIBUTION_POLICY.md",
    "README.md",
    ".github/README.md",
)
_PULL_REQUEST_TEMPLATE_PATHS = (
    "PULL_REQUEST_TEMPLATE.md",
    ".github/PULL_REQUEST_TEMPLATE.md",
    "docs/PULL_REQUEST_TEMPLATE.md",
)
_ALL_POLICY_PATHS = tuple(
    sorted(
        {
            *_GUIDANCE_PATHS,
            *_AI_POLICY_PATHS,
            *_LEGAL_POLICY_PATHS,
            *_SECURITY_POLICY_PATHS,
            *_PULL_REQUEST_TEMPLATE_PATHS,
        },
        key=str.casefold,
    )
)
POLICY_SOURCES_EVIDENCE_KEY = "policy_sources_sha256"


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
        bind_safety = getattr(github, "bind_safety_trigger_handler", None)
        if callable(bind_safety):
            bind_safety(store.trip_circuit_breaker_trigger)
        self._remote_file_cache: dict[tuple[str, str, str], str | None] = {}
        self._policy_path_cache: dict[tuple[str, str], tuple[str, ...]] = {}
        self._repository_policy_refs: dict[str, str] = {}
        self._organization_policy_refs: dict[str, str | None] = {}

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
            repository_ref = self._pin_repository_ref(repository)
            issues = self.github.search_issues(
                repository.full_name,
                labels=self.config.github.include_labels,
                limit=self.config.github.issue_limit_per_repository,
            )
            for issue in issues:
                # Search results omit the discussion and may contain a shortened body. Fetch the
                # canonical issue before spending model budget or deciding that work is unclaimed.
                issue = self.github.get_issue(repository.full_name, issue.number)
                if self.store.has_active_candidate(issue.repository, issue.number):
                    continue
                eligibility = self.evaluate(
                    issue,
                    repository,
                    repository_ref=repository_ref,
                )
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
        repository_ref: str | None = None,
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

        claimed_by = sorted(
            {comment.author for comment in issue.discussion if _WORK_CLAIM.search(comment.body)}
        )
        if claimed_by:
            blockers.append(f"issue discussion indicates claimed work by {', '.join(claimed_by)}")

        maintainer_stops = [
            comment
            for comment in issue.discussion
            if comment.author_association in _MAINTAINER_ASSOCIATIONS
            and not _BOT_LOGIN.search(comment.author)
            and _is_maintainer_stop(comment.body)
        ]
        if maintainer_stops:
            for comment in maintainer_stops:
                trigger_evidence = {
                    "author": comment.author,
                    "author_association": comment.author_association,
                    "body_sha256": hashlib.sha256(comment.body.encode()).hexdigest(),
                    "html_url": comment.html_url,
                    "issue": issue.reference.casefold(),
                    "updated_at": comment.updated_at.isoformat(),
                }
                self.store.trip_circuit_breaker_trigger(
                    CircuitBreakerTrigger(
                        source=f"github_issue_discussion:{issue.reference}",
                        reason=(
                            "A trusted maintainer discussion comment asks contributors to stop, "
                            f"hold off, or avoid a pull request for {issue.reference}; review "
                            f"{comment.html_url[:1_000]}"
                        ),
                        trigger_hash=hashlib.sha256(
                            json.dumps(
                                trigger_evidence,
                                sort_keys=True,
                                separators=(",", ":"),
                            ).encode()
                        ).hexdigest(),
                    )
                )
            raise StateError(
                "A trusted maintainer stop request activated the global circuit breaker"
            )

        evidence: dict[str, str] = {}
        maintainer_comments = sum(
            comment.author_association in _MAINTAINER_ASSOCIATIONS for comment in issue.discussion
        )
        evidence["discussion"] = (
            f"loaded={len(issue.discussion)}/{issue.comments}, "
            f"maintainer_comments={maintainer_comments}, claims={len(claimed_by)}"
        )
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
            pinned_repository_ref = self._pin_repository_ref(
                repository,
                repository_ref=repository_ref,
            )
            owner_policy_repository = f"{repository.full_name.split('/', 1)[0]}/.github"
            organization_ref = self._organization_policy_ref(owner_policy_repository)
            repository_policy_paths = self._policy_paths(
                repository.full_name,
                pinned_repository_ref,
            )
            organization_policy_paths = self._policy_paths(
                owner_policy_repository,
                organization_ref,
            )
            evidence[POLICY_SOURCES_EVIDENCE_KEY] = self._policy_sources_fingerprint(
                repository.full_name,
                pinned_repository_ref,
                owner_policy_repository,
                organization_ref,
                repository_policy_paths,
                organization_policy_paths,
            )
            contribution_policy = self._first_existing_file(
                repository.full_name,
                pinned_repository_ref,
                tuple(path for path in repository_policy_paths if _is_contribution_guidance(path)),
            )
            organization_contribution_policy = self._first_existing_file(
                owner_policy_repository,
                organization_ref,
                tuple(
                    path for path in organization_policy_paths if _is_contribution_guidance(path)
                ),
            )
            if (
                self.config.policy.require_contribution_guidelines
                and contribution_policy is None
                and organization_contribution_policy is None
            ):
                blockers.append("no repository or organization contribution guidelines were found")
                policy_fit = 0
                evidence["policy_fit"] = "0/10: contribution guidelines missing"
            ai_policy = self._combined_existing_files(
                repository.full_name,
                pinned_repository_ref,
                repository_policy_paths,
            )
            organization_ai_policy = self._combined_existing_files(
                owner_policy_repository,
                organization_ref,
                organization_policy_paths,
            )
            combined_ai_policy = f"{ai_policy}\n{organization_ai_policy}"
            if combined_ai_policy and _AI_PROHIBITION.search(combined_ai_policy):
                blockers.append("repository policy appears to prohibit AI-assisted contributions")
                policy_fit = 0
                evidence["policy_fit"] = "0/10: AI-assistance prohibition detected"
            elif combined_ai_policy and _AUTOMATION_PROHIBITION.search(combined_ai_policy):
                blockers.append("repository policy appears to prohibit automated contributions")
                policy_fit = 0
                evidence["policy_fit"] = "0/10: contribution automation prohibition detected"

            legal_policy = self._combined_existing_files(
                repository.full_name,
                pinned_repository_ref,
                repository_policy_paths,
            )
            organization_legal_policy = self._combined_existing_files(
                owner_policy_repository,
                organization_ref,
                organization_policy_paths,
            )
            legal_policy = f"{legal_policy}\n{organization_legal_policy}"
            if legal_policy and _LEGAL_ATTESTATION.search(legal_policy):
                blockers.append(
                    "repository appears to require a CLA/DCO or signed-off legal attestation; "
                    "autonomous completion is not configured"
                )
                policy_fit = 0
                evidence["policy_fit"] = "0/10: unresolved CLA/DCO attestation requirement"

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
        pushed_at = repository.pushed_at
        active = (
            pushed_at is not None
            and (datetime.now(UTC) - pushed_at).days
            <= self.config.github.max_repository_inactivity_days
        )
        return (
            not repository.private
            and not repository.archived
            and not repository.disabled
            and active
            and repository.stars >= self.config.github.min_stars
        )

    def pinned_repository_ref(self, repository: str) -> str:
        """Return the immutable policy/base ref already selected for this service."""

        try:
            return self._repository_policy_refs[repository.casefold()]
        except KeyError as exc:
            raise StateError(
                f"Repository policy ref was not pinned before use: {repository}"
            ) from exc

    def _pin_repository_ref(
        self,
        repository: RepositoryInfo,
        *,
        repository_ref: str | None = None,
    ) -> str:
        resolved = repository_ref
        if resolved is None:
            resolved = self.github.default_branch_sha(
                repository.full_name,
                repository.default_branch,
            )
        immutable_ref = _immutable_ref(resolved, field="repository policy ref")
        key = repository.full_name.casefold()
        existing = self._repository_policy_refs.get(key)
        if existing is not None and existing != immutable_ref:
            raise GitHubError(
                "Repository policy ref changed within one discovery snapshot; retry the run"
            )
        self._repository_policy_refs[key] = immutable_ref
        return immutable_ref

    def _organization_policy_ref(self, repository: str) -> str | None:
        key = repository.casefold()
        if key in self._organization_policy_refs:
            return self._organization_policy_refs[key]
        resolve = getattr(self.github, "default_branch_sha_if_exists", None)
        if not callable(resolve):
            raise GitHubError("GitHub client cannot resolve an immutable organization-policy ref")
        resolved = resolve(repository)
        immutable_ref = (
            None if resolved is None else _immutable_ref(resolved, field="organization policy ref")
        )
        self._organization_policy_refs[key] = immutable_ref
        return immutable_ref

    def _first_existing_file(
        self,
        repository: str,
        ref: str | None,
        paths: tuple[str, ...],
    ) -> str | None:
        for path in paths:
            content = self._remote_file(repository, path, ref)
            if content:
                return content
        return None

    def _combined_existing_files(
        self,
        repository: str,
        ref: str | None,
        paths: tuple[str, ...],
    ) -> str:
        contents = [self._remote_file(repository, path, ref) for path in paths]
        return "\n".join(content for content in contents if content)

    def _remote_file(self, repository: str, path: str, ref: str | None) -> str | None:
        if ref is None:
            return None
        key = (repository.casefold(), ref, path.casefold())
        if key not in self._remote_file_cache:
            content = self.github.get_file(
                repository,
                path,
                ref=ref,
                max_bytes=MAX_POLICY_FILE_BYTES,
            )
            if content is not None and len(content.encode("utf-8")) > MAX_POLICY_FILE_BYTES:
                raise GitHubError(
                    f"Repository policy file exceeds the {MAX_POLICY_FILE_BYTES}-byte limit: "
                    f"{repository}/{path}"
                )
            self._remote_file_cache[key] = content
        return self._remote_file_cache[key]

    def organization_pull_request_templates(self, repository: str) -> dict[str, str]:
        """Return bounded organization-default templates using normal GitHub precedence paths."""

        owner_policy_repository = f"{repository.split('/', 1)[0]}/.github"
        organization_ref = self._organization_policy_ref(owner_policy_repository)
        result: dict[str, str] = {}
        total_bytes = 0
        for path in self._policy_paths(owner_policy_repository, organization_ref):
            if not _is_pull_request_template(path):
                continue
            content = self._remote_file(owner_policy_repository, path, organization_ref)
            if content is not None:
                total_bytes += len(path.encode("utf-8")) + len(content.encode("utf-8"))
                if total_bytes > MAX_POLICY_TOTAL_BYTES:
                    raise GitHubError(
                        "Organization pull-request templates exceed the aggregate policy byte limit"
                    )
                result[path] = content
        return result

    def _policy_paths(self, repository: str, ref: str | None) -> tuple[str, ...]:
        if ref is None:
            return ()
        key = (repository.casefold(), ref)
        if key in self._policy_path_cache:
            return self._policy_path_cache[key]
        list_files = getattr(self.github, "list_repository_files", None)
        if not callable(list_files):
            paths = _ALL_POLICY_PATHS
        else:
            listed = list_files(
                repository,
                ref=ref,
                max_files=MAX_POLICY_INVENTORY_FILES,
            )
            if not isinstance(listed, list) or any(not isinstance(path, str) for path in listed):
                raise GitHubError("GitHub returned an invalid repository policy-file inventory")
            if len(listed) > MAX_POLICY_INVENTORY_FILES:
                raise GitHubError(
                    "Repository policy-file inventory exceeds the safe repository file limit"
                )
            paths = tuple(
                sorted(
                    (path for path in listed if _is_policy_path(path)),
                    key=str.casefold,
                )
            )
            folded = [path.casefold() for path in paths]
            if len(folded) != len(set(folded)):
                raise GitHubError(
                    "Repository policy paths differ only by case; policy precedence is ambiguous"
                )
        if len(paths) > MAX_POLICY_FILES_PER_REPOSITORY:
            raise GitHubError(
                f"Repository has more than {MAX_POLICY_FILES_PER_REPOSITORY} policy files; "
                "bounded policy review is incomplete"
            )
        self._policy_path_cache[key] = paths
        return paths

    def _policy_sources_fingerprint(
        self,
        repository: str,
        repository_ref: str,
        organization_repository: str,
        organization_ref: str | None,
        repository_paths: tuple[str, ...],
        organization_paths: tuple[str, ...],
    ) -> str:
        """Hash every bounded repository/organization policy input, including absences."""

        sources: dict[str, str | None] = {}
        total_bytes = 0
        for source_repository, ref, paths in (
            (repository, repository_ref, repository_paths),
            (organization_repository, organization_ref, organization_paths),
        ):
            source_key = source_repository.casefold()
            entries: tuple[tuple[str, str | None], ...] = (
                (f"{source_key}:__policy_ref__", ref),
                (
                    f"{source_key}:__policy_path_inventory__",
                    json.dumps(paths, ensure_ascii=False, separators=(",", ":")),
                ),
            )
            for key, value in entries:
                total_bytes = _bounded_policy_source_size(total_bytes, key, value)
                sources[key] = value
            for path in paths:
                key = f"{source_key}:{path.casefold()}"
                value = self._remote_file(source_repository, path, ref)
                total_bytes = _bounded_policy_source_size(total_bytes, key, value)
                sources[key] = value
        payload = json.dumps(
            sources,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(payload) > MAX_POLICY_TOTAL_BYTES:
            raise GitHubError(
                f"Repository policy evidence exceeds the {MAX_POLICY_TOTAL_BYTES}-byte limit"
            )
        return hashlib.sha256(payload).hexdigest()


def _is_contribution_guidance(path: str) -> bool:
    name = PurePosixPath(path.casefold()).name
    return name.startswith(("contributing", "contribution_guideline"))


def _immutable_ref(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not _GIT_SHA.fullmatch(value):
        raise GitHubError(f"{field} must be a full immutable git SHA")
    return value.casefold()


def _bounded_policy_source_size(
    current: int,
    key: str,
    value: str | None,
) -> int:
    size = current + len(key.encode("utf-8"))
    size += len(value.encode("utf-8")) if value is not None else 4
    if size > MAX_POLICY_TOTAL_BYTES:
        raise GitHubError(
            f"Repository policy evidence exceeds the {MAX_POLICY_TOTAL_BYTES}-byte limit"
        )
    return size


def _is_maintainer_stop(body: str) -> bool:
    without_negated_directives = _NEGATED_STOP_DIRECTIVE.sub("", body)
    return _MAINTAINER_STOP.search(without_negated_directives) is not None


def _is_pull_request_template(path: str) -> bool:
    lowered = path.casefold().strip("/")
    name = PurePosixPath(lowered).name
    return name.endswith((".md", ".markdown", ".rst", ".txt")) and (
        name.startswith("pull_request_template") or "/pull_request_template/" in f"/{lowered}"
    )


def _is_policy_path(path: str) -> bool:
    lowered = path.casefold().strip("/")
    name = PurePosixPath(lowered).name
    if not name.endswith((".md", ".markdown", ".rst", ".txt")):
        return False
    if _is_pull_request_template(path):
        return True
    if name.startswith(("ai.", "ai-", "ai_", "policy.", "readme.", "support.")):
        return True
    markers = (
        "ai-policy",
        "ai_policy",
        "ai-contribution",
        "ai_contribution",
        "automation",
        "bot-policy",
        "bot_policy",
        "cla",
        "code_of_conduct",
        "code-of-conduct",
        "contribut",
        "developer_certificate",
        "dco",
        "generative-ai",
        "license_agreement",
        "llm-policy",
        "llm_policy",
        "responsible-ai",
        "security",
    )
    return any(marker in name for marker in markers)


def parse_issue_reference(value: str) -> tuple[str, int]:
    """Parse `owner/repository#123` without accepting URLs or ambiguous shorthand."""

    match = re.fullmatch(r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)#([1-9][0-9]*)", value.strip())
    if not match:
        raise ValueError("issue must use owner/repository#number syntax")
    return match.group(1), int(match.group(2))


__all__ = [
    "MAX_POLICY_FILES_PER_REPOSITORY",
    "MAX_POLICY_FILE_BYTES",
    "MAX_POLICY_INVENTORY_FILES",
    "MAX_POLICY_TOTAL_BYTES",
    "POLICY_SOURCES_EVIDENCE_KEY",
    "DiscoveryService",
    "parse_issue_reference",
]
