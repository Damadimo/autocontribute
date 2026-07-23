"""Issue-first discovery and deterministic eligibility scoring."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import PurePosixPath

from autocontribute.config import AutocontributeConfig, LegalAttestation
from autocontribute.domain import EligibilityResult, IssueCandidate, RepositoryInfo
from autocontribute.exceptions import CircuitBreakerTrigger, GitHubError, PolicyError, StateError
from autocontribute.github import GitHubClient
from autocontribute.store import CandidateAttemptState, RunStore

_CLARITY_TERMS = re.compile(
    r"\b(expected|actual|acceptance|should|reproduce|steps|behavior|documentation)\b", re.I
)
_REPRODUCTION_TERMS = re.compile(
    r"\b(repro(?:duce|duction)?|traceback|error|fails?|incorrect|bug|typo|broken)\b", re.I
)
_DANGEROUS_TERMS = re.compile(
    r"\b(?:CVE-\d{4}-\d+|CWE-\d+|vulnerabilit(?:y|ies)|"
    r"(?:potential\s+)?security (?:issue|bug|impact)|timing attack|"
    r"remote (?:code|command) exec(?:ution)?|arbitrary (?:code|command) execution|RCE|"
    r"(?:authentication|auth) bypass|authorization bypass|privilege escalation|"
    r"bypass(?:es|ed|ing)? (?:an? |the )?"
    r"(?:permission|authorization|authentication|access[ -]control)(?: check)?|"
    r"(?:permission|access[ -]control)(?: check)? bypass|"
    r"server[ -]side request forgery|SSRF|"
    r"server[ -]side template injection|SSTI|"
    r"insecure direct object reference|IDOR|"
    r"(?:local|remote) file inclusion|LFI|RFI|LPE|"
    r"(?:path|directory) traversal|use[ -]after[ -]free|"
    r"arbitrary file (?:read|write)|credentials? (?:exposure|leak(?:age)?)|"
    r"secrets? (?:exposure|leak(?:age)?)|hard[ -]coded credentials?|"
    r"SQL injection|command injection|code injection|"
    r"cross[ -]site scripting|XSS|cross[ -]site request forgery|CSRF|XSRF|"
    r"XML external entity|XXE|buffer overflow|memory corruption|"
    r"CRLF injection|HTTP response splitting|cache poisoning|host header injection|"
    r"double free|integer overflow|data exfiltration|"
    r"denial[ -]of[ -]service|(?-i:DDoS|DDOS|DoS|DOS|ReDoS|ReDOS|REDOS)|"
    r"information (?:disclosure|leak(?:age)?)|"
    r"account takeover|SQLi|"
    r"out[ -]of[ -]bounds (?:memory )?(?:read|write|access)|"
    r"OOB (?:memory )?(?:read|write|access)|"
    r"sensitive (?:data|information) (?:exposure|leak)|open redirect|"
    r"security advisory|zero[ -]day|sandbox escape|request smuggling|"
    r"prototype pollution|insecure deserialization)\b",
    re.I,
)
_SECURITY_WORD_SEPARATOR = re.compile(r"(?<=\w)[_/\-\u2010-\u2015]+(?=\w)")
_SECURITY_MARKUP_SEPARATOR = re.compile(r"[*_`~]+")
_DANGEROUS_LABEL = re.compile(
    r"(?:^|[\s/:_-])(?:security|sec|vuln(?:erabilit(?:y|ies))?|CVE|CWE(?:-\d+)?)"
    r"(?:$|[\s/:_-])",
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
_CLA_TERM = r"(?:contributor(?:['\u2019]s)? license agreement|\bCLA\b)"
_DCO_TERM = r"(?:signed[- ]off[- ]by|developer(?:['\u2019]s)? certificate of origin|\bDCO\b)"
_CLA_REFERENCE = re.compile(rf"\b{_CLA_TERM}\b", re.I)
_DCO_REFERENCE = re.compile(rf"\b{_DCO_TERM}\b", re.I)
_LEGAL_SEGMENT_SPLIT = re.compile(r"(?:\r?\n)+|(?<=[.!?])\s+")
_LEGAL_NEGATION_CONTRAST = re.compile(r"\b(?:although|but|except|however|unless|yet)\b", re.I)
_LEGAL_NEGATED_PREFIX = re.compile(
    r"(?:\b(?:(?:do|does|did|will)\s+not|don't|doesn't|didn't|won't|never)\s+"
    r"(?:add|enforce|include|need|request|require|use)[^.!?]{0,80}|"
    r"\bno\s+(?:(?:legal\s+)?(?:need|requirement)\b[^.!?]{0,80}|(?:an?\s+)?))$",
    re.I,
)
_LEGAL_NEGATED_SUFFIX = re.compile(
    r"^\s*(?:(?:requirements?|signoffs?|trailers?|lines?)\s+)?"
    r"(?:(?:is|are|was|were|should|must)\s+)?(?:not|never|no\s+longer)\s+"
    r"(?:added|applicable|enforced|included|needed|required|requested|used)\b|"
    r"^\s*(?:requirements?\s+)?do(?:es)?\s+not\s+apply\b|"
    r"^\s*(?:is|are)\s+optional\b",
    re.I,
)
_WORK_CLAIM = re.compile(
    r"\b(?:(?:i(?:'m| am|\u2019m)|we(?:'re| are|\u2019re))\s+"
    r"(?:(?:already|currently)\s+)?working on (?:this|it)|"
    r"i(?:'ll| will) (?:take|work on) (?:this|it)|"
    r"i(?:'d|\u2019d| would) (?:like|loke) to "
    r"(?:take (?:on )?|(?:work|worn) on )(?:this|it)|"
    r"i (?:want|plan) to (?:take (?:on )?|work on )(?:this|it)|"
    r"working on (?:a |the )?(?:fix|pull request|pr)|"
    r"please assign (?:this|it) to me)\b",
    re.I,
)
_STOP_TARGET = (
    r"(?:(?:(?:ai|llm)[ -]generated|ai[ -]assisted|automated|bot[ -]authored|"
    r"community|external|outside|unsolicited)\s+)?"
    r"(?:pull\s+requests?|prs?|contributions?|submissions?|patch(?:es)?)"
)
_STOP_TEMPORAL = r"(?:currently|temporarily)"
_STOP_SCOPE_TAIL = (
    r"(?:for|on)\s+(?:(?:this|the)\s+)?(?:issue|fix|change)"
    r"(?:\s+(?:right\s+now|currently|at\s+this\s+time|for\s+now|anymore|here)"
    r"|\s+(?:until|pending)\b[^\n.!?;]*)?"
)
_STOP_CURRENT_TAIL = (
    rf"(?:\s*$"
    rf"|\s+(?:right\s+now|currently|at\s+this\s+time|for\s+now|anymore|here|yet)\s*$"
    rf"|\s+(?:until|pending)\b[^\n.!?;]*$"
    rf"|\s+{_STOP_SCOPE_TAIL}\s*$)"
)
_STOP_POLICY_TAIL = (
    r"(?:\s*$"
    r"|\s+(?:right\s+now|currently|at\s+this\s+time|for\s+now|anymore|here)\s*$"
    r"|\s+(?:until|pending|because|since|as)\b[^\n.!?;]*$"
    r"|\s*[\u2013\u2014]\s*[^\n.!?;]+$)"
)
_MAINTAINER_STOP = re.compile(
    rf"(?:"
    rf"\b(?:do\s+not|don't|never)\s+"
    rf"(?:open|submit|send|create|prepare)\s+(?:an?\s+|any\s+)?{_STOP_TARGET}\b"
    rf"{_STOP_CURRENT_TAIL}"
    rf"|\b(?:do\s+not|don't|never)\s+"
    rf"(?:work\s+on|implement)\s+(?:this|it|the\s+issue|this\s+issue|this\s+fix)\b"
    rf"{_STOP_CURRENT_TAIL}"
    rf"|\b(?:you\s+should|let's)\s+not\s+"
    rf"(?:open|submit|send|create|prepare)\s+(?:an?\s+|any\s+)?{_STOP_TARGET}\b"
    rf"{_STOP_CURRENT_TAIL}"
    rf"|\b(?:avoid|refrain\s+from)\s+"
    rf"(?:opening|submitting|sending|creating|preparing)\s+(?:an?\s+|any\s+)?"
    rf"{_STOP_TARGET}\b{_STOP_CURRENT_TAIL}"
    rf"|\bno\s+need\s+to\s+(?:open|submit|send|create|prepare)\s+"
    rf"(?:an?\s+|any\s+)?{_STOP_TARGET}\b{_STOP_CURRENT_TAIL}"
    rf"|\b(?:please\s+)?(?:hold\s+off|pause|wait)\s+"
    rf"(?:"
    rf"(?:(?:on|before|to)\s+)?"
    rf"(?:open(?:ing)?|submit(?:ting)?|send(?:ing)?|creat(?:e|ing)|prepar(?:e|ing))"
    rf"\s+(?:an?\s+|any\s+)?{_STOP_TARGET}\b{_STOP_CURRENT_TAIL}"
    rf"|(?:on\s+)?(?:working|implementing)\s+(?:on\s+)?(?:this|it|the\s+issue)\b"
    rf"{_STOP_CURRENT_TAIL}"
    rf"|(?:on\s+)?(?:work\s+on|implementation\s+of)\s+(?:this|it|the\s+issue)\b"
    rf"{_STOP_CURRENT_TAIL}"
    rf"|on\s+(?:an?\s+|any\s+)?{_STOP_TARGET}\b{_STOP_CURRENT_TAIL}"
    rf"|(?:on\s+)?(?:this\s+issue|the\s+issue|this|it)\b{_STOP_CURRENT_TAIL}"
    rf"|(?:for\s+now|right\s+now|until\s+further\s+notice)\s*$"
    rf"|until\s+(?:next\s+\w+|tomorrow|later)\b[^\n.!?;]*$"
    rf"|until\s+(?:the\s+)?(?:design|approach|plan|direction|decision)\b"
    rf"[^\n.!?;]*$"
    rf"|(?:for|until)\s+(?:the\s+)?maintainers?\s+"
    rf"(?:direction|guidance|approval|decision)\s+before\s+"
    rf"(?:starting|working|implementing|opening|submitting)\b[^\n.!?;]*$"
    rf")"
    rf"|\b(?:please\s+)?(?:stop|cease)\s+(?:working\s+on|work\s+on|"
    rf"implementing)\s+(?:this|it|the\s+issue)\b"
    rf"|\b(?:we(?:'re)?|maintainers?|(?:this|the)\s+(?:project|repository|repo))\s+"
    rf"(?:"
    rf"(?:(?:are|is)\s+)?(?:{_STOP_TEMPORAL}\s+)?(?:not|no\s+longer)\s+"
    rf"(?:{_STOP_TEMPORAL}\s+)?accepting"
    rf"|(?:aren't|isn't)\s+(?:{_STOP_TEMPORAL}\s+)?accepting"
    rf"|(?:{_STOP_TEMPORAL}\s+)?"
    rf"(?:(?:will|do(?:es)?|can)\s+not|cannot|won't|don't|doesn't|can't)\s+"
    rf"(?:{_STOP_TEMPORAL}\s+)?accept"
    rf"|no\s+longer\s+accepts"
    rf"|(?:have|has)\s+(?:stopped|paused)\s+accepting"
    rf")\s+(?:any\s+)?{_STOP_TARGET}\b{_STOP_POLICY_TAIL}"
    rf"|\b{_STOP_TARGET}\s+"
    rf"(?:"
    rf"(?:are|is)\s+(?:{_STOP_TEMPORAL}\s+)?(?:not|no\s+longer)\s+"
    rf"(?:{_STOP_TEMPORAL}\s+)?(?:accepted|allowed|welcome)"
    rf"|(?:are|is)\s+not\s+being\s+(?:accepted|allowed)"
    rf"|(?:aren't|isn't)\s+(?:{_STOP_TEMPORAL}\s+)?(?:accepted|allowed|welcome)"
    rf"|(?:are|is)\s+(?:{_STOP_TEMPORAL}\s+)?(?:closed|on\s+hold|paused)"
    rf"){_STOP_POLICY_TAIL}"
    rf"|\b{_STOP_TARGET}\s+will\s+be\s+closed\b"
    rf"(?:\s+without\s+(?:human\s+)?review)?{_STOP_POLICY_TAIL}"
    rf"|\bno\s+(?:(?:more|new)\s+)?{_STOP_TARGET}\s*"
    rf"(?:(?:are|is)\s+(?:needed|required))?(?:,\s*)?(?:please)?{_STOP_CURRENT_TAIL}"
    rf"|\b(?:an?\s+)?(?:pull\s+request|pr|contribution)\s+is\s+not\s+"
    rf"(?:needed|required)\b{_STOP_CURRENT_TAIL}"
    rf"|\b(?:please\s+)?(?:close|withdraw)\s+(?:this\s+)?{_STOP_TARGET}\b"
    rf"{_STOP_CURRENT_TAIL}"
    rf"|\b(?:i(?:'m|\s+am)|we(?:'re|\s+are)|maintainers?\s+(?:is|are))\s+"
    rf"(?:(?:already|currently)\s+)?(?:working\s+on|implementing)\s+"
    rf"(?:this|it|(?:this|the)\s+(?:issue|fix|change))\b{_STOP_CURRENT_TAIL}"
    rf"|\balready\s+being\s+worked\s+on\b"
    rf")",
    re.I,
)
_NON_STOP_DIRECTIVE = re.compile(
    r"\b(?:do\s+not|don't|never)\s+(?:(?:hesitate|wait|forget)\s+to|"
    r"(?:stop|cease|pause|hold\s+off|close|withdraw)\b)",
    re.I,
)
_NON_ACTIVE_WORK = re.compile(
    r"\b(?:not|never|was|were)\s+already\s+being\s+worked\s+on\b",
    re.I,
)
_ALREADY_WORKED_ON = re.compile(r"\balready\s+being\s+worked\s+on\b", re.I)
_CONDITIONAL_CLAIM = re.compile(r"\b(?:if|unless|whether)\b", re.I)
_RETIRED_STOP_PREFIX = re.compile(
    r"(?:"
    r"\b(?:(?:the|our|this)\s+)?(?:old|former|previous|prior|retired|removed|"
    r"obsolete|outdated|superseded)\s+"
    r"(?:policy|guidance|rule|wording|documentation|docs?|message|notice)\s+"
    r"(?:said|stated|read|required|was|used\s+to\s+say)"
    r"|\b(?:(?:the|our|this)\s+)?"
    r"(?:policy|guidance|rule|wording|documentation|docs?|message|notice)\s+"
    r"(?:(?:no\s+longer\s+(?:says?|states?|reads?|requires?)|"
    r"does(?:n't|\s+not)\s+(?:say|state|read|require))|"
    r"(?:was|has\s+been)\s+(?:removed|retired|superseded))"
    r"|\bwe\s+(?:removed|retired|superseded)\s+(?:(?:the|our)\s+)?"
    r"(?:(?:old|previous|prior)\s+)?"
    r"(?:policy|guidance|rule|wording|documentation|docs?|message|notice)"
    r")\s*(?:[:,\-\u2013\u2014]\s*)?[\"'\u201c\u201d]?\s*$",
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
    "DCO",
    "DCO.md",
    ".github/DCO.md",
    ".github/dco.yml",
    ".github/dco.yaml",
    "docs/DCO.md",
    "CLA",
    "CLA.md",
    ".github/CLA.md",
    ".github/cla.yml",
    ".github/cla.yaml",
    ".github/cla-assistant.yml",
    ".clabot",
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
POLICY_REPOSITORY_REF_EVIDENCE_KEY = "policy_repository_ref"
POLICY_ORGANIZATION_REF_EVIDENCE_KEY = "policy_organization_ref"
LEGAL_REQUIREMENTS_EVIDENCE_KEY = "legal_requirements"
LEGAL_ATTESTATION_EVIDENCE_KEY = "legal_attestation_sha256"
LEGAL_POLICY_EVIDENCE_KEY = "legal_policy_sha256"
_LEGAL_ATTESTATION_FINGERPRINT_DOMAIN = b"autocontribute.legal-attestation.v1\x00"
_LEGAL_POLICY_FINGERPRINT_DOMAIN = b"autocontribute.legal-policy-surface.v1\x00"


@dataclass(frozen=True, slots=True)
class PolicySnapshot:
    """One bounded repository and organization policy view at immutable refs."""

    repository: str
    repository_ref: str
    organization_repository: str
    organization_ref: str | None
    repository_paths: tuple[str, ...]
    organization_paths: tuple[str, ...]
    policy_sources_sha256: str
    legal_policy_sha256: str
    legal_requirements: tuple[str, ...]

    @property
    def organization_ref_evidence(self) -> str:
        return self.organization_ref or "absent"


DiscoverySelection = tuple[IssueCandidate, RepositoryInfo, EligibilityResult]


@dataclass(frozen=True, slots=True)
class DiscoveryOutcome:
    """A selection or a bounded explanation of why discovery exhausted its search."""

    selection: DiscoverySelection | None
    active_candidates: int = 0
    suppressed_candidates: int = 0
    ineligible_candidates: int = 0

    @property
    def no_candidate_reason(self) -> str:
        if self.selection is not None:
            raise ValueError("A successful discovery outcome has no exhaustion reason")
        if not any(
            (self.active_candidates, self.suppressed_candidates, self.ineligible_candidates)
        ):
            return "No candidate passed deterministic discovery gates."

        explanations: list[str] = []
        if self.suppressed_candidates:
            explanations.append(
                _counted_reason(
                    self.suppressed_candidates,
                    singular=(
                        "unchanged issue revision was deferred after a prior skipped, "
                        "rejected, or cancelled run"
                    ),
                    plural=(
                        "unchanged issue revisions were deferred after prior skipped, "
                        "rejected, or cancelled runs"
                    ),
                )
            )
        if self.active_candidates:
            explanations.append(
                _counted_reason(
                    self.active_candidates,
                    singular="candidate already has an active run",
                    plural="candidates already have active runs",
                )
            )
        if self.ineligible_candidates:
            explanations.append(
                _counted_reason(
                    self.ineligible_candidates,
                    singular="candidate failed deterministic discovery gates",
                    plural="candidates failed deterministic discovery gates",
                )
            )
        return "No candidate is currently available: " + "; ".join(explanations) + "."


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

    def discover(self) -> DiscoveryOutcome:
        ranked: list[DiscoverySelection] = []
        active_candidates = 0
        suppressed_candidates = 0
        ineligible_candidates = 0
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
                disposition = self.store.candidate_attempt_disposition(issue)
                if disposition.state == CandidateAttemptState.ACTIVE:
                    active_candidates += 1
                    continue
                if disposition.state == CandidateAttemptState.SUPPRESSED:
                    suppressed_candidates += 1
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
                else:
                    ineligible_candidates += 1
                if len(ranked) >= self.config.budget.max_candidates_per_run:
                    break
            if len(ranked) >= self.config.budget.max_candidates_per_run:
                break
        if not ranked:
            return DiscoveryOutcome(
                selection=None,
                active_candidates=active_candidates,
                suppressed_candidates=suppressed_candidates,
                ineligible_candidates=ineligible_candidates,
            )
        ranked.sort(key=lambda item: (item[2].score, item[0].updated_at), reverse=True)
        return DiscoveryOutcome(
            selection=ranked[0],
            active_candidates=active_candidates,
            suppressed_candidates=suppressed_candidates,
            ineligible_candidates=ineligible_candidates,
        )

    def evaluate(
        self,
        issue: IssueCandidate,
        repository: RepositoryInfo,
        *,
        check_remote_policy: bool = True,
        check_competing_pull_requests: bool = True,
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
        issue_discussion_text = (
            issue.title,
            issue.body,
            *(comment.body for comment in issue.discussion),
        )
        security_sensitive = any(
            _is_security_sensitive(text) for text in issue_discussion_text
        ) or any(_DANGEROUS_LABEL.search(label) for label in issue.labels)
        if not self.config.policy.allow_security_issues and security_sensitive:
            blockers.append("issue may concern a vulnerability and requires private handling")
        if _is_maintainer_stop(f"{issue.title}\n{issue.body}"):
            blockers.append("issue description asks contributors not to open a pull request")

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
            snapshot = self.policy_snapshot(
                repository,
                repository_ref=repository_ref,
            )
            evidence[POLICY_SOURCES_EVIDENCE_KEY] = snapshot.policy_sources_sha256
            evidence[POLICY_REPOSITORY_REF_EVIDENCE_KEY] = snapshot.repository_ref
            evidence[POLICY_ORGANIZATION_REF_EVIDENCE_KEY] = snapshot.organization_ref_evidence
            evidence[LEGAL_POLICY_EVIDENCE_KEY] = snapshot.legal_policy_sha256
            contribution_policy = self._first_existing_file(
                repository.full_name,
                snapshot.repository_ref,
                tuple(
                    path for path in snapshot.repository_paths if _is_contribution_guidance(path)
                ),
            )
            organization_contribution_policy = self._first_existing_file(
                snapshot.organization_repository,
                snapshot.organization_ref,
                tuple(
                    path for path in snapshot.organization_paths if _is_contribution_guidance(path)
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
                snapshot.repository_ref,
                snapshot.repository_paths,
            )
            organization_ai_policy = self._combined_existing_files(
                snapshot.organization_repository,
                snapshot.organization_ref,
                snapshot.organization_paths,
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

            if snapshot.legal_requirements:
                evidence[LEGAL_REQUIREMENTS_EVIDENCE_KEY] = ",".join(snapshot.legal_requirements)
                attestation = self.config.policy.legal_attestation_for(repository.full_name)
                mismatch = _legal_attestation_mismatch(snapshot, attestation)
                if mismatch is None:
                    assert attestation is not None
                    evidence[LEGAL_ATTESTATION_EVIDENCE_KEY] = legal_attestation_fingerprint(
                        repository.full_name, attestation
                    )
                else:
                    blockers.append(
                        "CLA/DCO requirements lack an exact current repository attestation: "
                        + mismatch
                    )
                    policy_fit = 0
                    evidence["policy_fit"] = "0/10: unresolved repository-bound legal attestation"
            else:
                evidence[LEGAL_REQUIREMENTS_EVIDENCE_KEY] = "none"

        if check_competing_pull_requests:
            competing = self.github.search_competing_pull_requests(
                repository.full_name,
                issue.number,
            )
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

    def policy_snapshot(
        self,
        repository: RepositoryInfo,
        *,
        repository_ref: str | None = None,
    ) -> PolicySnapshot:
        """Read and hash the complete bounded policy surface at immutable refs."""

        pinned_repository_ref = self._pin_repository_ref(
            repository,
            repository_ref=repository_ref,
        )
        owner_policy_repository = f"{repository.full_name.split('/', 1)[0]}/.github"
        organization_ref = self._organization_policy_ref(owner_policy_repository)
        repository_paths = self._policy_paths(
            repository.full_name,
            pinned_repository_ref,
        )
        organization_paths = self._policy_paths(
            owner_policy_repository,
            organization_ref,
        )
        policy_sources_sha256 = self._policy_sources_fingerprint(
            repository.full_name,
            pinned_repository_ref,
            owner_policy_repository,
            organization_ref,
            repository_paths,
            organization_paths,
        )
        legal_policy_sha256 = self._legal_policy_fingerprint(
            repository.full_name,
            pinned_repository_ref,
            owner_policy_repository,
            organization_ref,
            repository_paths,
            organization_paths,
        )
        legal_policy = "\n".join(
            (
                self._combined_existing_files(
                    repository.full_name,
                    pinned_repository_ref,
                    repository_paths,
                ),
                self._combined_existing_files(
                    owner_policy_repository,
                    organization_ref,
                    organization_paths,
                ),
            )
        )
        legal_requirements: list[str] = []
        policy_sources = (
            (repository.full_name, pinned_repository_ref, repository_paths),
            (owner_policy_repository, organization_ref, organization_paths),
        )

        def explicit_policy_requires_review(
            path_matches: Callable[[str], bool],
            reference: re.Pattern[str],
        ) -> bool:
            for source_repository, ref, paths in policy_sources:
                for path in paths:
                    if not path_matches(path):
                        continue
                    content = self._remote_file(source_repository, path, ref)
                    if content is not None and (
                        reference.search(content) is None
                        or _legal_reference_requires_review(content, reference)
                    ):
                        return True
            return False

        explicit_cla_policy = explicit_policy_requires_review(
            _is_explicit_cla_policy_path,
            _CLA_REFERENCE,
        )
        explicit_dco_policy = explicit_policy_requires_review(
            _is_explicit_dco_policy_path,
            _DCO_REFERENCE,
        )
        if _legal_reference_requires_review(legal_policy, _CLA_REFERENCE) or explicit_cla_policy:
            legal_requirements.append("cla")
        if _legal_reference_requires_review(legal_policy, _DCO_REFERENCE) or explicit_dco_policy:
            legal_requirements.append("dco")
        return PolicySnapshot(
            repository=repository.full_name,
            repository_ref=pinned_repository_ref,
            organization_repository=owner_policy_repository,
            organization_ref=organization_ref,
            repository_paths=repository_paths,
            organization_paths=organization_paths,
            policy_sources_sha256=policy_sources_sha256,
            legal_policy_sha256=legal_policy_sha256,
            legal_requirements=tuple(legal_requirements),
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

    def _legal_policy_fingerprint(
        self,
        repository: str,
        repository_ref: str,
        organization_repository: str,
        organization_ref: str | None,
        repository_paths: tuple[str, ...],
        organization_paths: tuple[str, ...],
    ) -> str:
        """Hash policy presence, inventories, and contents without moving commit refs."""

        sources: dict[str, str | None] = {}
        total_bytes = 0
        for source_repository, ref, paths in (
            (repository, repository_ref, repository_paths),
            (organization_repository, organization_ref, organization_paths),
        ):
            source_key = source_repository.casefold()
            entries: tuple[tuple[str, str | None], ...] = (
                (
                    f"{source_key}:__policy_repository_presence__",
                    "present" if ref is not None else "absent",
                ),
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
                f"Repository legal-policy evidence exceeds the {MAX_POLICY_TOTAL_BYTES}-byte limit"
            )
        return hashlib.sha256(_LEGAL_POLICY_FINGERPRINT_DOMAIN + payload).hexdigest()


def _is_contribution_guidance(path: str) -> bool:
    name = PurePosixPath(path.casefold()).name
    return name.startswith(("contributing", "contribution_guideline"))


def _is_explicit_cla_policy_path(path: str) -> bool:
    parsed = PurePosixPath(path.casefold())
    if parsed.suffix not in {"", ".json", ".markdown", ".md", ".rst", ".txt", ".yaml", ".yml"}:
        return False
    stem = parsed.stem.lstrip(".")
    return (
        stem == "cla"
        or stem.startswith(("cla-", "cla_"))
        or stem
        in {
            "cla-assistant",
            "cla_assistant",
            "clabot",
            "contributor-license-agreement",
            "contributor_license_agreement",
        }
    )


def _is_explicit_dco_policy_path(path: str) -> bool:
    parsed = PurePosixPath(path.casefold())
    if parsed.suffix not in {"", ".json", ".markdown", ".md", ".rst", ".txt", ".yaml", ".yml"}:
        return False
    stem = parsed.stem.lstrip(".")
    return (
        stem == "dco"
        or stem.startswith(("dco-", "dco_"))
        or stem
        in {
            "developer-certificate-of-origin",
            "developer_certificate_of_origin",
        }
    )


def _legal_reference_requires_review(policy: str, reference: re.Pattern[str]) -> bool:
    """Treat every non-negated or ambiguous legal reference as requiring review."""

    for segment in _LEGAL_SEGMENT_SPLIT.split(policy):
        matches = list(reference.finditer(segment))
        if not matches:
            continue
        if len(matches) != 1 or _LEGAL_NEGATION_CONTRAST.search(segment):
            return True
        match = matches[0]
        if not (
            _LEGAL_NEGATED_PREFIX.search(segment[: match.start()])
            or _LEGAL_NEGATED_SUFFIX.search(segment[match.end() :])
        ):
            return True
    return False


def legal_attestation_fingerprint(
    repository: str,
    attestation: LegalAttestation,
) -> str:
    """Hash the exact repository-scoped assertion copied into durable run evidence."""

    payload = json.dumps(
        {
            "schema_version": 1,
            "repository": repository.casefold(),
            "attestation": attestation.model_dump(mode="json"),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(_LEGAL_ATTESTATION_FINGERPRINT_DOMAIN + payload).hexdigest()


def _legal_attestation_mismatch(
    snapshot: PolicySnapshot,
    attestation: LegalAttestation | None,
) -> str | None:
    if attestation is None:
        return "no attestation is configured for this repository"
    if attestation.legal_policy_sha256 != snapshot.legal_policy_sha256:
        return "bounded policy inventories or contents changed"
    if tuple(attestation.legal_requirements) != snapshot.legal_requirements:
        return "detected legal requirement set changed"
    missing: list[str] = []
    if "cla" in snapshot.legal_requirements and attestation.cla is None:
        missing.append("completed account-level CLA authorization")
    if "dco" in snapshot.legal_requirements and attestation.dco is None:
        missing.append("named DCO signoff authorization")
    if missing:
        return "missing " + " and ".join(missing)
    return None


def _legal_requirements_from_evidence(eligibility: EligibilityResult) -> tuple[str, ...]:
    raw = eligibility.evidence.get(LEGAL_REQUIREMENTS_EVIDENCE_KEY)
    if raw == "none":
        return ()
    if raw is None:
        raise PolicyError("Run is missing durable legal-requirement evidence")
    requirements = tuple(raw.split(","))
    if not requirements or any(value not in {"cla", "dco"} for value in requirements):
        raise PolicyError("Run contains invalid legal-requirement evidence")
    if requirements != tuple(value for value in ("cla", "dco") if value in requirements):
        raise PolicyError("Run contains non-canonical legal-requirement evidence")
    return requirements


def _attestation_from_evidence(
    config: AutocontributeConfig,
    eligibility: EligibilityResult,
    repository: str,
) -> LegalAttestation:
    attestation = config.policy.legal_attestation_for(repository)
    recorded = eligibility.evidence.get(LEGAL_ATTESTATION_EVIDENCE_KEY)
    if attestation is None or recorded is None:
        raise PolicyError("Run lacks its exact repository-bound legal attestation")
    current = legal_attestation_fingerprint(repository, attestation)
    if not hmac.compare_digest(recorded, current):
        raise PolicyError("Repository legal attestation changed after candidate discovery")
    return attestation


def apply_legal_commit_message(
    config: AutocontributeConfig,
    eligibility: EligibilityResult,
    repository: str,
    commit_message: str,
) -> str:
    """Append an authorized DCO trailer before preparation evidence is sealed."""

    if (
        not commit_message
        or commit_message != commit_message.strip()
        or "\r" in commit_message
        or "\n" in commit_message
        or re.search(r"signed-off-by\s*:", commit_message, re.I)
    ):
        raise PolicyError(
            "Model commit subject must be one canonical line and cannot safely supply a legal "
            "signoff"
        )
    requirements = _legal_requirements_from_evidence(eligibility)
    if not requirements:
        return commit_message
    attestation = _attestation_from_evidence(config, eligibility, repository)
    if "dco" not in requirements:
        return commit_message
    if attestation.dco is None:
        raise PolicyError("Run lacks its named DCO signoff authorization")
    return f"{commit_message}\n\n{attestation.dco.trailer}"


def validate_legal_publication(
    config: AutocontributeConfig,
    eligibility: EligibilityResult,
    *,
    repository: str,
    publishing_login: str,
    commit_message: str,
) -> None:
    """Revalidate attesting account, authorization, and exact signoff before mutation."""

    requirements = _legal_requirements_from_evidence(eligibility)
    if not requirements:
        if re.search(r"signed-off-by\s*:", commit_message, re.I):
            raise PolicyError("Commit contains an unauthorized legal signoff trailer")
        return
    attestation = _attestation_from_evidence(config, eligibility, repository)
    if attestation.attested_by != publishing_login.strip().casefold():
        raise PolicyError(
            "Authenticated publishing account differs from the legal attesting identity"
        )
    if "cla" in requirements and attestation.cla is None:
        raise PolicyError("Run lacks its completed account-level CLA authorization")
    if "dco" in requirements:
        if attestation.dco is None:
            raise PolicyError("Run lacks its named DCO signoff authorization")
        parts = commit_message.split("\n\n")
        if (
            len(parts) != 2
            or not parts[0]
            or "\r" in commit_message
            or "\n" in parts[0]
            or parts[1] != attestation.dco.trailer
        ):
            raise PolicyError("Commit does not contain the exact authorized DCO signoff trailer")
    elif re.search(r"signed-off-by\s*:", commit_message, re.I):
        raise PolicyError("Commit contains a DCO signoff without a detected DCO requirement")


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


def _is_security_sensitive(text: str) -> bool:
    normalized = _SECURITY_MARKUP_SEPARATOR.sub(" ", text)
    normalized = _SECURITY_WORD_SEPARATOR.sub(" ", normalized)
    normalized = " ".join(normalized.split())
    return (
        _DANGEROUS_TERMS.search(text) is not None or _DANGEROUS_TERMS.search(normalized) is not None
    )


def _is_maintainer_stop(body: str) -> bool:
    normalized = body.replace("\u2018", "'").replace("\u2019", "'")
    without_invitations = _NON_STOP_DIRECTIVE.sub("", normalized)
    without_invitations = _NON_ACTIVE_WORK.sub("", without_invitations)
    for raw_segment in re.split(r"(?<=[.!?])|[;\n]", without_invitations):
        is_question = "?" in raw_segment
        segment = raw_segment.strip(" \t\r\n.!?\"'\u201c\u201d")
        if not segment:
            continue
        if _ALREADY_WORKED_ON.search(segment) and (
            is_question or _CONDITIONAL_CLAIM.search(segment)
        ):
            segment = _ALREADY_WORKED_ON.sub("", segment)
        for match in _MAINTAINER_STOP.finditer(segment):
            if _RETIRED_STOP_PREFIX.search(segment[: match.start()]):
                continue
            return True
    return False


def _is_pull_request_template(path: str) -> bool:
    lowered = path.casefold().strip("/")
    name = PurePosixPath(lowered).name
    return name.endswith((".md", ".markdown", ".rst", ".txt")) and (
        name.startswith("pull_request_template") or "/pull_request_template/" in f"/{lowered}"
    )


def _is_policy_path(path: str) -> bool:
    lowered = path.casefold().strip("/")
    name = PurePosixPath(lowered).name
    if _is_explicit_cla_policy_path(path) or _is_explicit_dco_policy_path(path):
        return True
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


def _counted_reason(count: int, *, singular: str, plural: str) -> str:
    return f"{count} {singular if count == 1 else plural}"


__all__ = [
    "LEGAL_ATTESTATION_EVIDENCE_KEY",
    "LEGAL_POLICY_EVIDENCE_KEY",
    "LEGAL_REQUIREMENTS_EVIDENCE_KEY",
    "MAX_POLICY_FILES_PER_REPOSITORY",
    "MAX_POLICY_FILE_BYTES",
    "MAX_POLICY_INVENTORY_FILES",
    "MAX_POLICY_TOTAL_BYTES",
    "POLICY_ORGANIZATION_REF_EVIDENCE_KEY",
    "POLICY_REPOSITORY_REF_EVIDENCE_KEY",
    "POLICY_SOURCES_EVIDENCE_KEY",
    "DiscoveryOutcome",
    "DiscoverySelection",
    "DiscoveryService",
    "PolicySnapshot",
    "apply_legal_commit_message",
    "legal_attestation_fingerprint",
    "parse_issue_reference",
    "validate_legal_publication",
]
