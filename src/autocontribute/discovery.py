"""Issue-first discovery and deterministic eligibility scoring."""

from __future__ import annotations

import hashlib
import hmac
import json
import posixpath
import re
from collections import Counter
from collections.abc import Collection, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import PurePosixPath
from typing import Literal, Protocol
from urllib.parse import unquote, urlparse

from autocontribute.ai_policy import (
    AGENT_INSTRUCTION_FILES,
    AiPolicyQuote,
    PolicyFile,
    RepositoryAiPolicy,
    ai_policy_digest,
    ai_policy_files,
    checked_ai_policy,
    deterministic_ai_policy,
)
from autocontribute.config import AutocontributeConfig, LegalAttestation
from autocontribute.domain import (
    DomainModel,
    EligibilityResult,
    IssueCandidate,
    IssueComment,
    RepositoryInfo,
)
from autocontribute.exceptions import (
    AutocontributeError,
    CircuitBreakerTrigger,
    GitHubError,
    GitHubRateLimitError,
    GitHubSafetyError,
    PolicyError,
    StateError,
    StopScope,
)
from autocontribute.github import GitHubClient, LinkedPullRequest
from autocontribute.github_origin import web_origin_for_api
from autocontribute.stop_text import AUTOMATION_STOP
from autocontribute.store import CandidateAttemptState, RunStore

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
_CLA_REFERENCE = re.compile(
    r"\bcontributor(?:['\u2019]s)?\s+license\s+agreement\b|\bCLA\b",
    re.I,
)
# Reviewers "sign off" on pull requests too; only the trailer and its tooling name the DCO.
_DCO_REFERENCE = re.compile(
    r"\bsigned-off-by\b|(?<![\w-])--signoff\b|\bgit\s+commit\s+(?:-\w+\s+)*-s\b"
    r"|\bdeveloper(?:['\u2019]s)?\s+certificate\s+of\s+origin\b|\bDCO\b",
    re.I,
)
# Wrapped lines stay in one segment; paragraphs, list items and headings start a new one.
_LEGAL_SEGMENT_SPLIT = re.compile(
    r"\r?\n[ \t]*\r?\n|\r?\n(?=[ \t]*(?:[-+*]|\d+[.)])[ \t]|[ \t]*#)|(?<=[.!?])\s+"
)
_MARKDOWN_HEADING = re.compile(r"^[ \t]{0,3}#{1,6}[ \t]", re.M)
_HEADING_UNDERLINE = re.compile(r"\n[ \t]*([=\-~^\"'`#*+])\1{2,}[ \t]*$", re.M)
_LEGAL_NEGATION_CONTRAST = re.compile(r"\b(?:although|but|except|however|unless|yet)\b", re.I)
_LEGAL_NEGATED_PREFIX = re.compile(
    r"(?:\b(?:(?:do|does|did|will)\s+not|don't|doesn't|didn't|won't|never)\s+"
    r"(?:add|enforce|have|include|need|request|require|use)[^.!?]{0,80}|"
    r"\b(?:not|never)\s+(?:be\s+)?(?:required|needed|asked)\s+to\s+sign[^.!?]{0,40}|"
    r"\bno\s+(?:(?:legal\s+)?(?:need|requirement)\b[^.!?]{0,80}"
    r"|(?:formal\s+|separate\s+)?(?:an?\s+)?))$",
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
    r"\b(?:(?:i(?:'m| am)|we(?:'re| are))\s+"
    r"(?:(?:already|currently)\s+)?working on (?:this|it)|"
    r"i(?:'ll| will) (?:take|work on) (?:this|it)|"
    r"working on (?:a |the )?(?:fix|pull request|pr))\b",
    re.I,
)
# Asking to be assigned claims the work even when it is phrased as a question.
_ASSIGNMENT_REQUEST = re.compile(r"\bassign (?:this|it) to me\b", re.I)
_WORK_INVITATION = re.compile(
    r"\b(?:"
    r"(?:prs?|pull\s+requests?|patch(?:es)?|contributions?|fix(?:es)?|help)\s+"
    r"(?:(?:are|is|would\s+be)\s+)?(?:(?:very|always|more\s+than)\s+)?(?:welcome|appreciated)"
    r"|help\s+wanted"
    r"|feel\s+free\s+to\s+(?:open|submit|send|make|create|take|pick|work\s+on|tackle|grab)"
    r"|happy\s+to\s+(?:review|accept|merge)"
    r"|(?:would|will)\s+(?:gladly\s+|happily\s+)?(?:accept|review|merge)\s+(?:a|an|any)\s+"
    r"(?:pr|pull\s+request|patch|fix|contribution)"
    r"|up\s+for\s+grabs"
    r"|open\s+(?:to|for)\s+(?:contributions|prs|pull\s+requests)"
    r")\b",
    re.I,
)
_SENTENCE_BREAK = re.compile(r"(?<=[.!?])\s+|[;\n]")
_CLAUSE_BREAK = re.compile(r"[,:()\u2013\u2014]")
_NEGATED_OR_CONDITIONAL = re.compile(
    r"\b(?:not|no|never|nobody|none|no\s+one|if|unless|whether)\b|n't\b", re.I
)
_CLAIM_WINDOW = timedelta(days=30)
# Repositories name the same invitation in many ways; these are searched whenever a repository
# defines them, unless github.labels sets the repository's include list.
_INVITATION_SYNONYMS = (
    "status: help wanted",
    "sprintable",
    "E-easy",
    "contributions welcome",
    "PR welcome",
    "accepted",
    "confirmed",
)
_SEARCH_PAGE_SIZE = 100
_MAX_SEARCH_PAGES = 3
# A search result has no discussion, and a maintainer comment there can still invite the work
# or raise the score; every other gate already holds for the full issue.
_DISCUSSION_DEPENDENT_BLOCKERS = frozenset({"no invitation", "low score"})
_LINKED_PULL_REQUEST_ACTIVITY = timedelta(days=90)
_MIN_CANDIDATE_SCORE = 60
_TRIAGE_CANDIDATES = 5
_RECENT_ACTIVITY = timedelta(days=90)
_RECENT_CREATION = timedelta(days=730)
_CODE_FENCE = re.compile(r"^[ \t]*(?:```|~~~)", re.M)
_CODE_REFERENCE = re.compile(r"`[^`\n]+`|\b\w+\(\)")
_SOURCE_FILE = re.compile(
    r"(?<![\w/.-])(?:[\w.-]+/)*[\w-]+\."
    r"(?:c|cc|cpp|cs|go|h|hpp|java|js|jsx|kt|php|py|pyi|rb|rs|scala|sh|swift|ts|tsx)\b"
)
_ERROR_OUTPUT = re.compile(
    r"Traceback \(most recent call last\)|\b[A-Z]\w*(?:Error|Exception)\b|\bpanicked at\b"
    r"|(?i:\berror(?:\[\w+\])?:)"
)
_EXPECTED_BEHAVIOR = re.compile(r"\b(?:expected|expect|should|desired)\b", re.I)
_OBSERVED_BEHAVIOR = re.compile(
    r"\b(?:actual(?:ly)?|instead|currently|got"
    r"|but (?:it|the|this|returns?|raises?|fails?|gives?|is|was))\b",
    re.I,
)
_REPRODUCTION = re.compile(
    r"\b(?:steps? to reproduce|to reproduce|reproduc(?:e|es|ed|ible|ing|tion)|repro"
    r"|minimal (?:example|reproducer|reproduction)|mcve)\b",
    re.I,
)
_TEST_MENTION = re.compile(r"\b(?:tests?|testing|test_\w+|pytest|unittest|jest|vitest)\b", re.I)
# Documentation and test issues have no faulty behavior to reproduce, so the bug-report signals
# count as met for them.
_DOCS_OR_TESTS_LABEL = re.compile(r"\b(?:docs?|documentation|typo|tests?|testing)\b")
_DOCS_TITLE = re.compile(r"\b(?:typos?|docs?|documentation|docstrings?|readme|spelling)\b", re.I)
_SMALL_LABEL = re.compile(
    r"(?:(?:size|difficulty|effort|complexity)\s*[:/]?\s*)?(?:xs|s|small|easy|low|trivial|tiny)"
    r"|e easy|typo"
)
_TYPO_TITLE = re.compile(r"\b(?:typos?|spelling)\b", re.I)
# Agents fix these kinds of work most reliably, and maintainers merge them most often.
_ROUTINE_WORK = re.compile(
    r"\b(?:docs?|documentation|typos?|ci|continuous integration|build|packaging|tests?|testing"
    r"|typing|type (?:hints?|annotations?|stubs?)|mypy|pyright)\b",
    re.I,
)
# These need judgement or hardware that a sandboxed agent lacks, unless a maintainer has said
# what the result should be.
_JUDGEMENT_WORK = re.compile(
    r"\b(?:perf(?:ormance)?|slow(?:ness)?|speed\s?up|memory (?:usage|leak)|optimi[sz]\w*"
    r"|features?(?: requests?)?|enhancements?|ui|ux|gui|visual|css"
    r"|windows|macos|osx|ios|android|gpu|cuda|rocm|arm64|aarch64|platform(?:[- ]specific)?"
    r"|concurren\w*|thread(?:s|ing|[- ]safe\w*)?|race(?: conditions?)?|deadlocks?"
    r"|flak(?:y|iness))\b",
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
_REPOSITORY_BASELINE_REASON = (
    "repository is private, archived, disabled, inactive, or below the star floor"
)
_SUMMARY_BLOCKER_KINDS = 3
# Safety stops, rate limits (more requests would only extend them) and local state failures (the
# breaker, leases, store integrity) end discovery. Every other failure belongs to one repository
# or one issue and must not hide the rest.
_FATAL_ERRORS = (GitHubSafetyError, GitHubRateLimitError, StateError)
_ISOLATED_ERRORS = (AutocontributeError, ValueError)

MAX_POLICY_FILES_PER_REPOSITORY = 128
MAX_POLICY_FILE_BYTES = 256_000
MAX_POLICY_TOTAL_BYTES = 4_000_000

# Community files live in these directories; listing them without recursion keeps the cost of a
# policy review independent of repository size.
_POLICY_DIRECTORIES = frozenset({".github", "docs"})
_TEXT_SUFFIXES = frozenset({"", ".adoc", ".markdown", ".md", ".rst", ".txt"})
_CONTRIBUTION_GUIDES = frozenset(
    {
        "contribute",
        "contributing",
        "contributing-guide",
        "contribution",
        "contribution-guide",
        "contribution-guidelines",
        "contributions",
        "contributor-guide",
        "contributors-guide",
        "how-to-contribute",
    }
)
_POLICY_NAME = re.compile(
    r"(?:code[-_]of[-_]conduct|security|support|governance"
    r"|[^.]*ai[^.]*polic[^.]*|[^.]*llm[^.]*polic[^.]*"
    r"|ai[-_](?:contributions?|usage|use|assistance|tools?)"
    r"|(?:generative|responsible)[-_]ai|(?:automation|bot)[-_]polic[^.]*"
    r"|contribut(?!ors\b)[^.]*)(?:\..*)?"
)
# A repository with this file closes pull requests from contributors its maintainers have not
# vouched for.
_VOUCH_FILE = ".github/vouched.td"
_MARKDOWN_LINK = re.compile(r"\]\(\s*<?([^()\s<>]+)>?(?:\s+[\"'][^\"'\n]*[\"'])?\s*\)")
_REFERENCE_LINK = re.compile(r"^[ \t]{0,3}\[[^\]\n]+\]:[ \t]*<?([^\s<>]+)>?", re.M)
_RST_LINK = re.compile(r"`[^`<]*<([^`<>]+)>`_{1,2}")
_RST_TARGET = re.compile(r"^[ \t]*\.\.[ \t]+_[^:\n]+:[ \t]*(\S+)", re.M)
_HTML_LINK = re.compile(r"\bhref\s*=\s*[\"']([^\"']+)[\"']", re.I)
# Contribution guides link to release notes and license texts, which hold no policy and can be
# large enough to exceed the byte caps.
_UNLINKED_DOCUMENT = re.compile(
    r"(?:change[-_]?log|changes|history|news|release[-_]?notes?|releases|authors|contributors"
    r"|licen[cs]e|copying|notice)(?:\..*)?"
)

POLICY_SOURCES_EVIDENCE_KEY = "policy_sources_sha256"
AI_POLICY_EVIDENCE_KEY = "ai_policy"
POLICY_REPOSITORY_REF_EVIDENCE_KEY = "policy_repository_ref"
POLICY_ORGANIZATION_REF_EVIDENCE_KEY = "policy_organization_ref"
LEGAL_REQUIREMENTS_EVIDENCE_KEY = "legal_requirements"
LEGAL_ATTESTATION_EVIDENCE_KEY = "legal_attestation_sha256"
LEGAL_POLICY_EVIDENCE_KEY = "legal_policy_sha256"
_LEGAL_ATTESTATION_FINGERPRINT_DOMAIN = b"autocontribute.legal-attestation.v1\x00"
_LEGAL_POLICY_FINGERPRINT_DOMAIN = b"autocontribute.legal-policy-surface.v2\x00"


@dataclass(frozen=True, slots=True)
class _PolicySource:
    """The policy files of one repository, and why reading them was incomplete if it was."""

    files: tuple[PolicyFile, ...] = ()
    vouched: bool = False
    problems: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PolicySnapshot:
    """One bounded repository and organization policy view at immutable refs.

    Problems name files that could not be read or caps that were exceeded; a repository with
    problems is skipped, because its policy is not fully known.
    """

    repository: str
    repository_ref: str
    organization_repository: str
    organization_ref: str | None
    files: tuple[PolicyFile, ...]
    vouched: bool
    problems: tuple[str, ...]
    policy_sources_sha256: str
    legal_policy_sha256: str
    legal_requirements: tuple[str, ...]

    @property
    def organization_ref_evidence(self) -> str:
        return self.organization_ref or "absent"

    @property
    def repository_paths(self) -> tuple[str, ...]:
        return tuple(file.path for file in self.files if file.repository == self.repository)

    @property
    def organization_paths(self) -> tuple[str, ...]:
        return tuple(
            file.path for file in self.files if file.repository == self.organization_repository
        )


@dataclass(frozen=True, slots=True)
class _RepositoryReview:
    """What the policy files of one repository mean for every issue in it."""

    blockers: tuple[tuple[str, str], ...]
    evidence: tuple[tuple[str, str], ...]


DiscoverySelection = tuple[IssueCandidate, RepositoryInfo, EligibilityResult]


class TriageVerdict(DomainModel):
    """A triage model's judgement of one eligible issue, as its submit_triage call states it."""

    suitable: bool
    reasons: list[str]
    already_fixed: bool
    needs_design: bool
    difficulty: Literal["small", "medium", "large"]

    @property
    def problems(self) -> list[str]:
        """Why an agent should not take the issue; empty when it should."""

        return [
            problem
            for problem, present in (
                ("judged unsuitable", not self.suitable),
                ("already fixed", self.already_fixed),
                ("needs a design decision", self.needs_design),
                ("too large", self.difficulty == "large"),
            )
            if present
        ]


class IssueTriage(Protocol):
    """Judges whether an agent can fix an issue that passed every deterministic gate."""

    def triage(self, issue: IssueCandidate, repository: RepositoryInfo) -> TriageVerdict: ...


class PolicyClassifier(Protocol):
    """Reads a repository's AI-contribution policy from its policy files that concern AI.

    Every quote in the result must appear verbatim in the file it names, or the result is
    replaced (see ``checked_ai_policy``).
    """

    def classify(
        self, repository: RepositoryInfo, files: Sequence[PolicyFile]
    ) -> RepositoryAiPolicy: ...


@dataclass(frozen=True, slots=True)
class IssueEvaluation:
    """One assessed issue; each blocker has a short kind that discovery summaries count.

    ``repository_hold`` is the hold this assessment newly recorded on the whole repository.
    """

    issue: IssueCandidate
    repository: RepositoryInfo
    eligibility: EligibilityResult
    blocker_kinds: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    repository_hold: CircuitBreakerTrigger | None = None


@dataclass(frozen=True, slots=True)
class DiscoveryOutcome:
    """A selection plus every evaluation, skipped repository, and failure behind it."""

    selection: DiscoverySelection | None
    active_candidates: int = 0
    suppressed_candidates: int = 0
    evaluations: tuple[IssueEvaluation, ...] = ()
    skipped_repositories: tuple[tuple[str, str], ...] = ()
    repository_errors: tuple[tuple[str, str], ...] = ()
    issue_errors: tuple[tuple[str, str], ...] = ()

    @property
    def ineligible_candidates(self) -> int:
        return sum(not evaluation.eligibility.eligible for evaluation in self.evaluations)

    @property
    def blocker_counts(self) -> list[tuple[str, int]]:
        """Blocker kinds with the number of issues each one blocked, most common first."""

        return Counter(
            kind for evaluation in self.evaluations for kind in evaluation.blocker_kinds
        ).most_common()

    @property
    def summary(self) -> str:
        eligible = len(self.evaluations) - self.ineligible_candidates
        explanations = [
            _counted_reason(len(self.evaluations), singular="issue", plural="issues")
            + f" evaluated, {eligible} eligible",
            *self._explanations(),
        ]
        return "; ".join(explanations) + "."

    @property
    def no_candidate_reason(self) -> str:
        if self.selection is not None:
            raise ValueError("A successful discovery outcome has no exhaustion reason")
        explanations = self._explanations()
        if not explanations:
            return "No candidate passed deterministic discovery gates."
        return "No candidate is currently available: " + "; ".join(explanations) + "."

    def _explanations(self) -> list[str]:
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
            top_blockers = ", ".join(
                f"{kind} {count}" for kind, count in self.blocker_counts[:_SUMMARY_BLOCKER_KINDS]
            )
            explanations.append(
                _counted_reason(
                    self.ineligible_candidates,
                    singular="candidate failed discovery gates",
                    plural="candidates failed discovery gates",
                )
                + f" ({top_blockers})"
            )
        for failures, singular, plural in (
            (self.skipped_repositories, "repository was skipped", "repositories were skipped"),
            (
                self.repository_errors,
                "repository could not be searched",
                "repositories could not be searched",
            ),
            (self.issue_errors, "issue could not be evaluated", "issues could not be evaluated"),
        ):
            if failures:
                explanations.append(
                    _counted_reason(len(failures), singular=singular, plural=plural)
                )
        return explanations


class DiscoveryService:
    def __init__(
        self,
        config: AutocontributeConfig,
        github: GitHubClient,
        store: RunStore,
        *,
        triage: IssueTriage | None = None,
        policy_classifier: PolicyClassifier | None = None,
    ) -> None:
        self.config = config
        self.github = github
        self.store = store
        self.triage = triage
        self.policy_classifier = policy_classifier
        self._policy_sources: dict[tuple[str, str], _PolicySource] = {}
        self._policy_snapshots: dict[tuple[str, str], PolicySnapshot] = {}
        self._repository_reviews: dict[tuple[str, str], _RepositoryReview] = {}
        self._repository_policy_refs: dict[str, str] = {}
        self._organization_policy_refs: dict[str, str | None] = {}

    def repositories(self) -> tuple[list[RepositoryInfo], list[tuple[str, str]]]:
        """Resolve configured repositories and owners; one failure never hides the others."""

        by_name: dict[str, RepositoryInfo] = {}
        errors: list[tuple[str, str]] = []
        for full_name in self.config.github.repositories:
            try:
                repository = self.github.get_repository(full_name)
            except _FATAL_ERRORS:
                raise
            except _ISOLATED_ERRORS as exc:
                errors.append((full_name, str(exc)))
                continue
            by_name[repository.full_name] = repository
        for owner in self.config.github.owners:
            try:
                listed = self.github.list_owner_repositories(
                    owner, limit=self.config.github.repository_limit_per_owner
                )
            except _FATAL_ERRORS:
                raise
            except _ISOLATED_ERRORS as exc:
                errors.append((owner, str(exc)))
                continue
            for repository in listed:
                by_name[repository.full_name] = repository
        return sorted(by_name.values(), key=lambda repo: repo.stars, reverse=True), errors

    def discover(self) -> DiscoveryOutcome:
        repositories, repository_errors = self.repositories()
        # At most one open autocontribute pull request per repository.
        open_pull_requests = {
            manifest.candidate.repository.casefold(): (
                manifest.pull_request_url or f"run {manifest.run_id}"
            )
            for manifest in self.store.list_open_pull_request_runs()
            if manifest.candidate is not None
        }
        held_repositories = {
            hold.scope_key.casefold(): hold
            for hold in self.store.active_holds()
            if hold.scope is StopScope.REPOSITORY
        }
        evaluations: list[IssueEvaluation] = []
        eligible: list[IssueEvaluation] = []
        skipped_repositories: list[tuple[str, str]] = []
        issue_errors: list[tuple[str, str]] = []
        active_candidates = 0
        suppressed_candidates = 0
        candidate_limit = self.config.budget.max_candidates_per_run
        for repository in repositories:
            if len(eligible) >= candidate_limit:
                break
            hold = held_repositories.get(repository.full_name.casefold())
            if hold is not None:
                skipped_repositories.append(
                    (
                        repository.full_name,
                        f"held since {hold.created_at.date().isoformat()} "
                        f"(hold {hold.hold_id}): {hold.reason}",
                    )
                )
                continue
            if not self._repository_baseline(repository):
                skipped_repositories.append((repository.full_name, _REPOSITORY_BASELINE_REASON))
                continue
            restriction = _pull_request_restriction(repository)
            if restriction is not None:
                skipped_repositories.append((repository.full_name, restriction))
                continue
            open_pull_request = open_pull_requests.get(repository.full_name.casefold())
            if open_pull_request is not None:
                skipped_repositories.append(
                    (
                        repository.full_name,
                        f"an autocontribute pull request is already open: {open_pull_request}",
                    )
                )
                continue
            try:
                include_labels, exclude_labels = self._search_labels(repository.full_name)
                if not include_labels:
                    skipped_repositories.append(
                        (repository.full_name, "repository has none of the invitation labels")
                    )
                    continue
                repository_ref = self._pin_repository_ref(repository)
                found, rejected = self._search(repository, include_labels, exclude_labels)
                # Policy blockers hold for every issue, so they skip the repository before any
                # issue is fetched.
                review = (
                    self._repository_review(repository, repository_ref=repository_ref)
                    if found
                    else None
                )
            except _FATAL_ERRORS:
                raise
            except _ISOLATED_ERRORS as exc:
                repository_errors.append((repository.full_name, str(exc)))
                continue
            if review is not None and review.blockers:
                skipped_repositories.append(
                    (repository.full_name, "; ".join(reason for _, reason in review.blockers))
                )
                continue
            evaluations.extend(rejected)
            for snapshot in found:
                if len(eligible) >= candidate_limit:
                    break
                try:
                    # Search results omit the discussion and may contain a shortened body. Fetch
                    # the canonical issue before spending model budget or deciding that work is
                    # unclaimed.
                    issue = self.github.get_issue(repository.full_name, snapshot.number)
                    disposition = self.store.candidate_attempt_disposition(issue)
                    if disposition.state == CandidateAttemptState.ACTIVE:
                        active_candidates += 1
                        continue
                    if disposition.state == CandidateAttemptState.SUPPRESSED:
                        suppressed_candidates += 1
                        continue
                    evaluation = self._assess(issue, repository, repository_ref=repository_ref)
                except _FATAL_ERRORS:
                    raise
                except _ISOLATED_ERRORS as exc:
                    issue_errors.append((snapshot.reference, str(exc)))
                    continue
                evaluations.append(evaluation)
                if evaluation.repository_hold is not None:
                    skipped_repositories.append(
                        (repository.full_name, evaluation.repository_hold.reason)
                    )
                    eligible = [
                        candidate
                        for candidate in eligible
                        if candidate.repository.full_name != repository.full_name
                    ]
                    break
                if evaluation.eligibility.eligible:
                    eligible.append(evaluation)
        eligible.sort(
            key=lambda evaluation: (evaluation.eligibility.score, evaluation.issue.updated_at),
            reverse=True,
        )
        winner = self._select(eligible, evaluations, issue_errors)
        return DiscoveryOutcome(
            selection=(
                None if winner is None else (winner.issue, winner.repository, winner.eligibility)
            ),
            active_candidates=active_candidates,
            suppressed_candidates=suppressed_candidates,
            evaluations=tuple(evaluations),
            skipped_repositories=tuple(skipped_repositories),
            repository_errors=tuple(repository_errors),
            issue_errors=tuple(issue_errors),
        )

    def _select(
        self,
        ranked: list[IssueEvaluation],
        evaluations: list[IssueEvaluation],
        issue_errors: list[tuple[str, str]],
    ) -> IssueEvaluation | None:
        """Pick the best-ranked issue, or with triage the best-ranked one triage accepts.

        Triage sees at most the top five issues. Its verdicts replace their evaluations, so that
        a rejection shows up as a blocker.
        """

        if self.triage is None:
            return ranked[0] if ranked else None
        for candidate in ranked[:_TRIAGE_CANDIDATES]:
            try:
                verdict = self.triage.triage(candidate.issue, candidate.repository)
            except _FATAL_ERRORS:
                raise
            except _ISOLATED_ERRORS as exc:
                issue_errors.append((candidate.issue.reference, f"triage failed: {exc}"))
                continue
            triaged = _with_triage(candidate, verdict)
            position = next(
                index for index, evaluation in enumerate(evaluations) if evaluation is candidate
            )
            evaluations[position] = triaged
            if triaged.eligibility.eligible:
                return triaged
        return None

    def _search_labels(self, repository: str) -> tuple[list[str], list[str]]:
        """Name the repository's own labels that discovery searches for and leaves out."""

        include, exclude = self._label_rules(repository)
        names = self.github.list_labels(repository)
        return (
            [name for name in names if include.fullmatch(_label_key(name))],
            [name for name in names if exclude.fullmatch(_label_key(name))],
        )

    def _label_rules(self, repository: str) -> tuple[re.Pattern[str], re.Pattern[str]]:
        """Match label keys to the include and exclude lists that apply to the repository."""

        override = self.config.github.labels.get(repository.casefold())
        include: Sequence[str] = (*self.config.github.include_labels, *_INVITATION_SYNONYMS)
        exclude: Sequence[str] = self.config.github.exclude_labels
        if override is not None and override.include is not None:
            include = override.include
        if override is not None and override.exclude is not None:
            exclude = override.exclude
        return _label_matcher(include), _label_matcher(exclude)

    def _search(
        self,
        repository: RepositoryInfo,
        include_labels: list[str],
        exclude_labels: list[str],
    ) -> tuple[list[IssueCandidate], list[IssueEvaluation]]:
        """Page through open issues, newest first, until enough pass the issue-only gates.

        Returns the search results worth fetching in full and the evaluations of the rest.
        """

        limit = self.config.github.issue_limit_per_repository
        found: list[IssueCandidate] = []
        rejected: list[IssueEvaluation] = []
        seen: set[int] = set()
        for page in range(1, _MAX_SEARCH_PAGES + 1):
            results = self.github.search_issues(
                repository.full_name,
                include_labels=include_labels,
                exclude_labels=exclude_labels,
                unassigned=self._unassigned_only,
                page=page,
                per_page=_SEARCH_PAGE_SIZE,
            )
            for snapshot in results:
                if snapshot.number in seen:
                    continue
                seen.add(snapshot.number)
                evaluation = self._assess(
                    snapshot,
                    repository,
                    check_remote_policy=False,
                    check_competing_pull_requests=False,
                )
                if set(evaluation.blocker_kinds) - _DISCUSSION_DEPENDENT_BLOCKERS:
                    rejected.append(
                        replace(
                            evaluation,
                            notes=(
                                *evaluation.notes,
                                "rejected from the search result; the discussion was not read",
                            ),
                        )
                    )
                    continue
                found.append(snapshot)
                if len(found) >= limit:
                    return found, rejected
            if len(results) < _SEARCH_PAGE_SIZE:
                break
        return found, rejected

    @property
    def _unassigned_only(self) -> bool:
        return (
            self.config.github.require_unassigned and not self.config.policy.allow_assigned_issues
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
        """Assess one issue outside a search, as `run --issue` and publication do.

        Discovery skips held repositories before searching them; these callers learn of a hold,
        including one this assessment just recorded, as a blocker.
        """

        eligibility = self._assess(
            issue,
            repository,
            check_remote_policy=check_remote_policy,
            check_competing_pull_requests=check_competing_pull_requests,
            repository_ref=repository_ref,
        ).eligibility
        held = [
            f"the repository is held (hold {hold.hold_id}): {hold.reason}"
            for hold in self.store.active_holds()
            if hold.scope is StopScope.REPOSITORY
            and hold.scope_key.casefold() == repository.full_name.casefold()
        ]
        if not held:
            return eligibility
        return eligibility.model_copy(
            update={"eligible": False, "blockers": [*eligibility.blockers, *held]}
        )

    def _assess(
        self,
        issue: IssueCandidate,
        repository: RepositoryInfo,
        *,
        check_remote_policy: bool = True,
        check_competing_pull_requests: bool = True,
        repository_ref: str | None = None,
    ) -> IssueEvaluation:
        blockers: list[tuple[str, str]] = []
        include, exclude = self._label_rules(repository.full_name)
        labels = {_label_key(label): label for label in issue.labels}
        invitation_labels = sorted(label for key, label in labels.items() if include.fullmatch(key))
        excluded = sorted(label for key, label in labels.items() if exclude.fullmatch(key))
        maintainer_comments = [
            comment for comment in issue.discussion if _is_trusted_maintainer(comment)
        ]
        invited_in_discussion = any(
            _stated(_WORK_INVITATION, comment.body) for comment in maintainer_comments
        )

        if not self._repository_baseline(repository):
            blockers.append(("repository", _REPOSITORY_BASELINE_REASON))
        restriction = _pull_request_restriction(repository)
        if restriction is not None:
            blockers.append(("pull requests restricted", restriction))
        if issue.state.casefold() != "open":
            blockers.append(("closed", "issue is not open"))
        if (
            self.config.policy.require_maintainer_signal
            and not invitation_labels
            and not invited_in_discussion
        ):
            blockers.append(
                (
                    "no invitation",
                    "issue has no invitation label and no maintainer comment inviting a pull "
                    "request",
                )
            )
        if excluded:
            blockers.append(("excluded label", f"issue has excluded labels: {', '.join(excluded)}"))
        if issue.assignees and self._unassigned_only:
            blockers.append(("assigned", "issue is already assigned"))
        now = datetime.now(UTC)
        age = (now - issue.updated_at).days
        if age > self.config.github.max_issue_age_days:
            blockers.append(("stale", f"issue has not been updated for {age} days"))
        issue_discussion_text = (
            issue.title,
            issue.body,
            *(comment.body for comment in issue.discussion),
        )
        security_sensitive = any(
            _is_security_sensitive(text) for text in issue_discussion_text
        ) or any(_DANGEROUS_LABEL.search(label) for label in issue.labels)
        if not self.config.policy.allow_security_issues and security_sensitive:
            blockers.append(
                ("security", "issue may concern a vulnerability and requires private handling")
            )
        if _is_maintainer_stop(f"{issue.title}\n{issue.body}"):
            blockers.append(
                (
                    "stop request",
                    "issue description asks contributors not to open a pull request",
                )
            )

        claimed_by = _active_claimants(issue.discussion, maintainer_comments, now=now)
        if claimed_by:
            blockers.append(
                ("claimed", f"issue discussion indicates claimed work by {', '.join(claimed_by)}")
            )

        # A stop in the discussion blocks this issue only. It also holds the whole repository
        # when it turns away automated or AI contributions in general.
        stops = [comment for comment in maintainer_comments if _is_maintainer_stop(comment.body)]
        repository_hold: CircuitBreakerTrigger | None = None
        if stops:
            blockers.append(
                (
                    "stop request",
                    "a maintainer comment asks contributors to stop, hold off, or avoid a pull "
                    f"request: {stops[-1].html_url}",
                )
            )
            hold = next((comment for comment in stops if _targets_automation(comment.body)), None)
            if hold is not None:
                trigger = _automation_stop_hold(issue, repository, hold)
                # Evidence that an operator released does not hold the repository again.
                if self.store.record_stop(trigger):
                    repository_hold = trigger

        evidence: dict[str, str] = {}
        evidence["discussion"] = (
            f"loaded={len(issue.discussion)}/{issue.comments}, "
            f"maintainer_comments={len(maintainer_comments)}, claims={len(claimed_by)}"
        )
        score, score_evidence = _suitability(
            issue,
            label_keys=labels.keys(),
            invitation_labels=invitation_labels,
            invited_in_discussion=invited_in_discussion,
            maintainer_comments=maintainer_comments,
            now=now,
        )
        evidence.update(score_evidence)
        if score < _MIN_CANDIDATE_SCORE:
            blockers.append(
                (
                    "low score",
                    f"candidate score {score} is below the floor of {_MIN_CANDIDATE_SCORE}",
                )
            )

        if check_remote_policy:
            review = self._repository_review(repository, repository_ref=repository_ref)
            blockers.extend(review.blockers)
            evidence.update(review.evidence)

        notes: list[str] = []
        # The linked-PR search costs several GitHub calls; skip it once the issue is blocked.
        if check_competing_pull_requests and not blockers:
            try:
                linked = self.github.search_competing_pull_requests(
                    repository.full_name,
                    issue.number,
                )
            except _FATAL_ERRORS:
                raise
            except GitHubError as exc:
                blockers.append(
                    (
                        "linked pull request",
                        f"linked pull requests could not be checked completely: {exc}",
                    )
                )
                evidence["linked_pull_requests"] = "unknown"
            else:
                competing = competing_pull_requests(linked, now=now)
                stale = [pull_request for pull_request in linked if pull_request not in competing]
                if competing:
                    blockers.append(
                        (
                            "linked pull request",
                            "possible competing pull request already exists: "
                            f"{competing[0].html_url}",
                        )
                    )
                notes.extend(
                    f"stale linked PR, not blocking: {pull_request.html_url} "
                    f"(updated {pull_request.updated_at.date().isoformat()})"
                    for pull_request in stale
                )
                evidence["linked_pull_requests"] = f"{len(competing)} competing, {len(stale)} stale"

        return IssueEvaluation(
            issue=issue,
            repository=repository,
            eligibility=EligibilityResult(
                eligible=not blockers,
                score=score,
                evidence=evidence,
                blockers=[reason for _, reason in blockers],
            ),
            blocker_kinds=tuple(kind for kind, _ in blockers),
            notes=tuple(notes),
            repository_hold=repository_hold,
        )

    def _repository_review(
        self,
        repository: RepositoryInfo,
        *,
        repository_ref: str | None = None,
    ) -> _RepositoryReview:
        """Turn the repository's policy files into the blockers that hold for all its issues."""

        snapshot = self.policy_snapshot(repository, repository_ref=repository_ref)
        key = (repository.full_name.casefold(), snapshot.repository_ref)
        cached = self._repository_reviews.get(key)
        if cached is not None:
            return cached
        blockers = [("policy files", problem) for problem in snapshot.problems]
        evidence = {
            POLICY_SOURCES_EVIDENCE_KEY: snapshot.policy_sources_sha256,
            POLICY_REPOSITORY_REF_EVIDENCE_KEY: snapshot.repository_ref,
            POLICY_ORGANIZATION_REF_EVIDENCE_KEY: snapshot.organization_ref_evidence,
            LEGAL_POLICY_EVIDENCE_KEY: snapshot.legal_policy_sha256,
        }
        if snapshot.vouched:
            blockers.append(
                (
                    "vouch",
                    "the repository closes pull requests from contributors its maintainers have "
                    "not vouched for (.github/VOUCHED.td)",
                )
            )
        # Guidelines can only be missing once every policy file has been read.
        if (
            self.config.policy.require_contribution_guidelines
            and not snapshot.problems
            and not any(
                file.text and _is_contribution_guidance(file.path) for file in snapshot.files
            )
        ):
            blockers.append(
                (
                    "no contribution guidelines",
                    "no repository or organization contribution guidelines were found",
                )
            )
        ai_policy = self._ai_policy(repository, snapshot)
        # The approval review shows the policy, conditions and quotes included.
        evidence[AI_POLICY_EVIDENCE_KEY] = ai_policy.model_dump_json()
        ai_policy_reason = self._ai_policy_blocker(repository.full_name, ai_policy)
        if ai_policy_reason is not None:
            blockers.append(("AI policy", ai_policy_reason))
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
                    (
                        "CLA/DCO",
                        "CLA/DCO requirements lack an exact current repository attestation: "
                        + mismatch,
                    )
                )
        else:
            evidence[LEGAL_REQUIREMENTS_EVIDENCE_KEY] = "none"
        result = _RepositoryReview(blockers=tuple(blockers), evidence=tuple(evidence.items()))
        self._repository_reviews[key] = result
        return result

    def _ai_policy(
        self, repository: RepositoryInfo, snapshot: PolicySnapshot
    ) -> RepositoryAiPolicy:
        """Read the AI policy, preferring a verified classifier reading cached by file digest."""

        deterministic = deterministic_ai_policy(snapshot.files)
        files = ai_policy_files(snapshot.files)
        # A repository with unread policy files is skipped anyway; its partial text is not
        # worth a classifier call or a cache entry.
        if not files or snapshot.problems:
            return deterministic
        digest = ai_policy_digest(files)
        cached = self.store.repository_ai_policy(repository.full_name, digest)
        if cached is not None:
            return cached
        if self.policy_classifier is None:
            return deterministic
        policy = checked_ai_policy(
            self.policy_classifier.classify(repository, files),
            files,
            fallback=deterministic,
        )
        self.store.record_repository_ai_policy(repository.full_name, digest, policy)
        return policy

    def _ai_policy_blocker(self, repository: str, policy: RepositoryAiPolicy) -> str | None:
        quotes = _quoted(policy.quotes)
        if policy.stance == "ban":
            return f"the repository's AI policy bans agent-made contributions: {quotes}"
        if policy.stance == "unclear":
            return "the repository's AI policy could not be verified: " + (
                quotes or "no quoted passage appears in its policy files"
            )
        if (
            policy.stance == "conditional"
            and policy.requires_human_written_text
            and repository.casefold() not in self.config.policy.allow_conditional_ai_policy
        ):
            return (
                "the repository's AI policy asks for human-written pull request text; list it in "
                f"policy.allow_conditional_ai_policy to contribute there: {quotes}"
            )
        return None

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
        """Read and hash the bounded repository and organization policy files at immutable refs.

        A file that cannot be read, or a cap that is exceeded, does not raise; the snapshot
        names it as a problem instead.
        """

        pinned_repository_ref = self._pin_repository_ref(
            repository,
            repository_ref=repository_ref,
        )
        key = (repository.full_name.casefold(), pinned_repository_ref)
        cached = self._policy_snapshots.get(key)
        if cached is not None:
            return cached
        owner_policy_repository = f"{repository.full_name.split('/', 1)[0]}/.github"
        organization_ref = self._organization_policy_ref(owner_policy_repository)
        repository_source = self._policy_source(repository.full_name, pinned_repository_ref)
        organization_source = self._policy_source(owner_policy_repository, organization_ref)
        sources: tuple[_SourceAtRef, ...] = (
            (repository.full_name, pinned_repository_ref, repository_source),
            (owner_policy_repository, organization_ref, organization_source),
        )
        files = (*repository_source.files, *organization_source.files)
        snapshot = PolicySnapshot(
            repository=repository.full_name,
            repository_ref=pinned_repository_ref,
            organization_repository=owner_policy_repository,
            organization_ref=organization_ref,
            files=files,
            vouched=repository_source.vouched,
            problems=(*repository_source.problems, *organization_source.problems),
            policy_sources_sha256=_policy_sources_fingerprint(sources),
            legal_policy_sha256=_legal_policy_fingerprint(files),
            legal_requirements=_legal_requirements(files),
        )
        self._policy_snapshots[key] = snapshot
        return snapshot

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
        resolved = self.github.default_branch_sha_if_exists(repository)
        immutable_ref = (
            None if resolved is None else _immutable_ref(resolved, field="organization policy ref")
        )
        self._organization_policy_refs[key] = immutable_ref
        return immutable_ref

    def organization_pull_request_templates(self, repository: str) -> dict[str, str]:
        """Return the owner's default pull-request templates from its .github repository."""

        owner_policy_repository = f"{repository.split('/', 1)[0]}/.github"
        source = self._policy_source(
            owner_policy_repository,
            self._organization_policy_ref(owner_policy_repository),
        )
        if source.problems:
            raise GitHubError("; ".join(source.problems))
        return {
            file.path: file.text for file in source.files if _is_pull_request_template(file.path)
        }

    def _policy_source(self, repository: str, ref: str | None) -> _PolicySource:
        if ref is None:
            return _PolicySource()
        key = (repository.casefold(), ref)
        if key not in self._policy_sources:
            self._policy_sources[key] = self._read_policy_source(repository, ref)
        return self._policy_sources[key]

    def _read_policy_source(self, repository: str, ref: str) -> _PolicySource:
        """Read the policy files in the root, .github/ and docs/, and the pages guides link to.

        Projects often keep their AI or provenance rules on a developer-guide page that the
        contribution guide links to, so relative links from guides are followed one hop.
        """

        try:
            listed, vouched = self._list_policy_paths(repository, ref)
        except _FATAL_ERRORS:
            raise
        except GitHubError as exc:
            return _PolicySource(
                problems=(f"the policy files of {repository} could not be listed: {exc}",)
            )
        files, problems = self._read_policy_files(repository, ref, listed, read=())
        web_origin = web_origin_for_api(self.config.github.api_url)
        known = {path.casefold() for path in listed}
        linked: list[str] = []
        for guide in files:
            if not _is_contribution_guidance(guide.path):
                continue
            for path in _linked_paths(guide, web_origin=web_origin):
                if path.casefold() not in known:
                    known.add(path.casefold())
                    linked.append(path)
        linked_files, linked_problems = self._read_policy_files(repository, ref, linked, read=files)
        folded = [path.casefold() for path in listed]
        ambiguous = (
            (f"policy paths of {repository} differ only by case; their precedence is ambiguous",)
            if len(folded) != len(set(folded))
            else ()
        )
        return _PolicySource(
            files=(*files, *linked_files),
            vouched=vouched,
            problems=(*problems, *linked_problems, *ambiguous),
        )

    def _list_policy_paths(self, repository: str, ref: str) -> tuple[list[str], bool]:
        """List the policy files in the root, .github/ and docs/, and see if a vouch file exists."""

        paths: list[str] = []
        vouched = False
        pending = [""]
        while pending:
            directory = pending.pop(0)
            for entry in self.github.list_directory(repository, directory, ref=ref) or []:
                name = PurePosixPath(entry.path).name
                if entry.kind == "dir":
                    if (
                        not directory and name in _POLICY_DIRECTORIES
                    ) or name.casefold() == "pull_request_template":
                        pending.append(entry.path)
                elif entry.path.casefold() == _VOUCH_FILE:
                    vouched = True
                elif entry.kind != "submodule" and _is_policy_path(entry.path):
                    paths.append(entry.path)
        return paths, vouched

    def _read_policy_files(
        self,
        repository: str,
        ref: str,
        paths: Sequence[str],
        *,
        read: Sequence[PolicyFile],
    ) -> tuple[tuple[PolicyFile, ...], tuple[str, ...]]:
        """Read paths within the file-count and byte caps that already-read files count toward."""

        if len(read) + len(paths) > MAX_POLICY_FILES_PER_REPOSITORY:
            return (), (
                f"{repository} has more than {MAX_POLICY_FILES_PER_REPOSITORY} policy files",
            )
        total_bytes = sum(len(file.text.encode("utf-8")) for file in read)
        files: list[PolicyFile] = []
        problems: list[str] = []
        for path in paths:
            try:
                text = self.github.get_file(
                    repository,
                    path,
                    ref=ref,
                    max_bytes=MAX_POLICY_FILE_BYTES,
                )
            except _FATAL_ERRORS:
                raise
            except GitHubError as exc:
                problems.append(f"policy file {repository}/{path} could not be read: {exc}")
                continue
            if text is None:
                continue
            size = len(text.encode("utf-8"))
            if size > MAX_POLICY_FILE_BYTES:
                problems.append(
                    f"policy file {repository}/{path} exceeds the "
                    f"{MAX_POLICY_FILE_BYTES}-byte limit"
                )
                continue
            total_bytes += size
            if total_bytes > MAX_POLICY_TOTAL_BYTES:
                problems.append(
                    f"policy files of {repository} exceed the {MAX_POLICY_TOTAL_BYTES}-byte limit"
                )
                break
            files.append(PolicyFile(repository=repository, path=path, text=text))
        return tuple(files), tuple(problems)


_SourceAtRef = tuple[str, str | None, _PolicySource]


def _policy_sources_fingerprint(sources: Sequence[_SourceAtRef]) -> str:
    """Hash every policy file read, the refs they were read at, and the vouch file's presence."""

    payload = {
        repository.casefold(): {
            "ref": ref,
            "vouched": source.vouched,
            "files": {file.path: file.text for file in source.files},
        }
        for repository, ref, source in sources
    }
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _legal_policy_fingerprint(files: Sequence[PolicyFile]) -> str:
    """Hash only what bears on a CLA or DCO, so other policy edits keep attestations valid.

    CLA and DCO files count whole; every other file counts by the sections that name a CLA or
    DCO.
    """

    payload: dict[str, list[str]] = {}
    for file in files:
        key = f"{file.repository.casefold()}:{file.path}"
        if _is_explicit_cla_policy_path(file.path) or _is_explicit_dco_policy_path(file.path):
            payload[key] = [file.text]
            continue
        sections = [
            section
            for section in _sections(file.text)
            if _CLA_REFERENCE.search(section) or _DCO_REFERENCE.search(section)
        ]
        if sections:
            payload[key] = sections
    return hashlib.sha256(_LEGAL_POLICY_FINGERPRINT_DOMAIN + _canonical_json(payload)).hexdigest()


def _sections(text: str) -> list[str]:
    """Split a document at its Markdown or reStructuredText headings."""

    starts = {0, *(match.start() for match in _MARKDOWN_HEADING.finditer(text))}
    for underline in _HEADING_UNDERLINE.finditer(text):
        # An underline makes the line above it a heading, unless that line is blank.
        title_start = text.rfind("\n", 0, underline.start()) + 1
        if text[title_start : underline.start()].strip():
            starts.add(title_start)
    ordered = sorted(starts)
    return [text[start:end] for start, end in zip(ordered, [*ordered[1:], len(text)], strict=True)]


def _legal_requirements(files: Sequence[PolicyFile]) -> tuple[str, ...]:
    """Name each legal requirement that a file states or that a CLA or DCO file implies."""

    requirements: list[str] = []
    for requirement, reference, explicit in (
        ("cla", _CLA_REFERENCE, _is_explicit_cla_policy_path),
        ("dco", _DCO_REFERENCE, _is_explicit_dco_policy_path),
    ):
        if any(
            _legal_reference_requires_review(file.text, reference)
            or (explicit(file.path) and reference.search(file.text) is None)
            for file in files
        ):
            requirements.append(requirement)
    return tuple(requirements)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _linked_paths(guide: PolicyFile, *, web_origin: str) -> list[str]:
    """Resolve the guide's links to text files in its own repository, in document order."""

    blob_prefix = f"{web_origin}/{guide.repository}/blob/".casefold()
    targets = sorted(
        (match.start(), match.group(1))
        for pattern in (_MARKDOWN_LINK, _REFERENCE_LINK, _RST_LINK, _RST_TARGET, _HTML_LINK)
        for match in pattern.finditer(guide.text)
    )
    paths: list[str] = []
    for _, raw_target in targets:
        target = raw_target.strip()
        if target.casefold().startswith(blob_prefix):
            # A blob URL names a branch; the page is read at the pinned ref like every other.
            target = "/" + target[len(blob_prefix) :].partition("/")[2]
        elif urlparse(target).scheme or target.startswith(("#", "//")):
            continue
        target = unquote(target.partition("#")[0].partition("?")[0])
        if not target or "\\" in target or not target.isprintable():
            continue
        base = "" if target.startswith("/") else posixpath.dirname(guide.path)
        path = posixpath.normpath(posixpath.join(base, target.lstrip("/")))
        name = PurePosixPath(path).name.casefold()
        if (
            path in {".", ".."}
            or path.startswith("../")
            or PurePosixPath(name).suffix not in _TEXT_SUFFIXES - {""}
            or _UNLINKED_DOCUMENT.fullmatch(name)
        ):
            continue
        paths.append(path)
    return list(dict.fromkeys(paths))


def _is_contribution_guidance(path: str) -> bool:
    name = PurePosixPath(path.casefold()).name
    stem = name.split(".", 1)[0].replace("_", "-")
    return PurePosixPath(name).suffix in _TEXT_SUFFIXES and (
        stem in _CONTRIBUTION_GUIDES or stem.startswith("contributing")
    )


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
        return "the CLA or DCO text of the policy files changed"
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


def _quoted(quotes: Sequence[AiPolicyQuote]) -> str:
    return "; ".join(
        f'"{" ".join(quote.text.split())}" ({quote.repository}/{quote.path})'
        for quote in quotes[:3]
    )


def _pull_request_restriction(repository: RepositoryInfo) -> str | None:
    if not repository.has_pull_requests:
        return "the repository has pull requests turned off"
    if repository.pull_request_creation_policy == "collaborators_only":
        return "the repository takes pull requests only from collaborators"
    return None


def _is_security_sensitive(text: str) -> bool:
    normalized = _SECURITY_MARKUP_SEPARATOR.sub(" ", text)
    normalized = _SECURITY_WORD_SEPARATOR.sub(" ", normalized)
    normalized = " ".join(normalized.split())
    return (
        _DANGEROUS_TERMS.search(text) is not None or _DANGEROUS_TERMS.search(normalized) is not None
    )


def _is_maintainer_stop(body: str) -> bool:
    return bool(_maintainer_stop_sentences(body))


def _automation_stop_hold(
    issue: IssueCandidate,
    repository: RepositoryInfo,
    comment: IssueComment,
) -> CircuitBreakerTrigger:
    """A repository hold for a maintainer comment that turns automated contributions away."""

    evidence = {
        "author": comment.author,
        "body": comment.body,
        "comment": comment.html_url,
        "updated_at": comment.updated_at.isoformat(),
    }
    return CircuitBreakerTrigger(
        source=f"github_issue_discussion:{issue.reference}",
        reason=(
            f"a maintainer comment turns away automated or AI contributions: {comment.html_url}"
        ),
        # An edited comment is new evidence, so a hold released after review can return.
        trigger_hash=hashlib.sha256(_canonical_json(evidence)).hexdigest(),
        scope=StopScope.REPOSITORY,
        # Addressed to every contributor rather than to this tool, so it does not escalate.
        scope_key=repository.full_name,
    )


def _targets_automation(body: str) -> bool:
    return any(AUTOMATION_STOP.search(sentence) for sentence in _maintainer_stop_sentences(body))


def _maintainer_stop_sentences(body: str) -> list[str]:
    """Return the sentences that ask contributors to stop, hold off, or avoid a pull request."""

    normalized = body.replace("\u2018", "'").replace("\u2019", "'")
    without_invitations = _NON_STOP_DIRECTIVE.sub("", normalized)
    without_invitations = _NON_ACTIVE_WORK.sub("", without_invitations)
    sentences: list[str] = []
    for raw_segment in re.split(r"(?<=[.!?])|[;\n]", without_invitations):
        is_question = "?" in raw_segment
        segment = raw_segment.strip(" \t\r\n.!?\"'\u201c\u201d")
        if not segment:
            continue
        if _ALREADY_WORKED_ON.search(segment) and (
            is_question or _CONDITIONAL_CLAIM.search(segment)
        ):
            segment = _ALREADY_WORKED_ON.sub("", segment)
        if any(
            not _RETIRED_STOP_PREFIX.search(segment[: match.start()])
            for pattern in (_MAINTAINER_STOP, AUTOMATION_STOP)
            for match in pattern.finditer(segment)
        ):
            sentences.append(segment)
    return sentences


def _suitability(
    issue: IssueCandidate,
    *,
    label_keys: Collection[str],
    invitation_labels: list[str],
    invited_in_discussion: bool,
    maintainer_comments: list[IssueComment],
    now: datetime,
) -> tuple[int, dict[str, str]]:
    """Score, out of 100, how well an agent can fix the issue, with evidence for each part.

    Parts: invitation 25, specificity 25, smallness 20, freshness 15, testability 15. The kind
    of work then moves the score: up for routine work and pinpointed bugs, down for work that
    needs judgement nobody has supplied.
    """

    text = f"{issue.title}\n{issue.body}"
    docs_or_tests = any(_DOCS_OR_TESTS_LABEL.search(key) for key in label_keys) or bool(
        _DOCS_TITLE.search(issue.title)
    )

    if invited_in_discussion or any(_label_key(label) != "bug" for label in invitation_labels):
        invitation = 25
    elif invitation_labels:
        invitation = 15
    else:
        invitation = 0

    expected = docs_or_tests or bool(
        _EXPECTED_BEHAVIOR.search(text) and _OBSERVED_BEHAVIOR.search(text)
    )
    code_block = bool(_CODE_FENCE.search(issue.body))
    reference = bool(_CODE_REFERENCE.search(text) or _SOURCE_FILE.search(text))
    reproduction = bool(_REPRODUCTION.search(text))
    error_output = bool(_ERROR_OUTPUT.search(issue.body))
    specific = {
        "expected vs actual": (10, expected),
        "code block": (5, code_block),
        "code reference": (5, reference),
        "reproduction or error": (5, docs_or_tests or reproduction or error_output),
    }

    files = {match.group(0) for match in _SOURCE_FILE.finditer(text)}
    small_label = any(_SMALL_LABEL.fullmatch(key) for key in label_keys)
    small = {
        "small or typo label": (10, small_label or bool(_TYPO_TITLE.search(issue.title))),
        "under 15 comments": (5, issue.comments < 15),
        "one file or none named": (5, len(files) <= 1),
    }

    fresh = {
        "created within 2 years": (5, now - issue.created_at <= _RECENT_CREATION),
        "updated within 90 days": (5, now - issue.updated_at <= _RECENT_ACTIVITY),
        "maintainer comment within 90 days": (
            5,
            any(now - comment.created_at <= _RECENT_ACTIVITY for comment in maintainer_comments),
        ),
    }

    testable = {
        "reproduction": (10, docs_or_tests or code_block or reproduction),
        "tests named": (5, bool(_TEST_MENTION.search(text))),
    }

    kinds = (issue.title, *label_keys)
    stated = any(_EXPECTED_BEHAVIOR.search(comment.body) for comment in maintainer_comments)
    adjustments = {
        "docs, CI, build, test or typing work": (
            10,
            any(_ROUTINE_WORK.search(kind) for kind in kinds),
        ),
        "reproduction and a named file or function": (
            5,
            (code_block or reproduction or error_output) and reference,
        ),
        "performance, feature, UI, platform or concurrency work without a maintainer-stated "
        "expected behaviour": (
            -15,
            not stated and any(_JUDGEMENT_WORK.search(kind) for kind in kinds),
        ),
    }

    evidence = {
        "invitation": (
            f"{invitation}/25: labels={invitation_labels}, "
            f"maintainer invitation={'yes' if invited_in_discussion else 'no'}"
        )
    }
    if docs_or_tests:
        evidence["issue_kind"] = (
            "documentation or tests: expected vs actual and reproduction count as met"
        )
    score = invitation
    for name, maximum, signals in (
        ("specificity", 25, specific),
        ("smallness", 20, small),
        ("freshness", 15, fresh),
        ("testability", 15, testable),
    ):
        points = sum(weight for weight, present in signals.values() if present)
        met = [signal for signal, (_, present) in signals.items() if present]
        evidence[name] = f"{points}/{maximum}: {', '.join(met) or 'none'}"
        score += points
    applied = [(points, name) for name, (points, present) in adjustments.items() if present]
    evidence["adjustments"] = ", ".join(f"{points:+d} {name}" for points, name in applied) or "none"
    return max(0, min(100, score + sum(points for points, _ in applied))), evidence


def _with_triage(evaluation: IssueEvaluation, verdict: TriageVerdict) -> IssueEvaluation:
    """Record the verdict as evidence, and as a blocker when triage turns the issue down."""

    reasons = "; ".join(verdict.reasons)
    summary = f"{verdict.difficulty}, {', '.join(verdict.problems) or 'suitable'}"
    if reasons:
        summary += f": {reasons}"
    eligibility = evaluation.eligibility
    evidence = {**eligibility.evidence, "triage": summary}
    if not verdict.problems:
        return replace(
            evaluation, eligibility=eligibility.model_copy(update={"evidence": evidence})
        )
    return replace(
        evaluation,
        eligibility=eligibility.model_copy(
            update={
                "eligible": False,
                "evidence": evidence,
                "blockers": [*eligibility.blockers, f"triage turned the issue down: {summary}"],
            }
        ),
        blocker_kinds=(*evaluation.blocker_kinds, "triage"),
    )


def _label_key(name: str) -> str:
    """Compare labels as people spell them, ignoring case, hyphens, and underscores."""

    return " ".join(re.split(r"[\s_-]+", name.casefold())).strip()


def _label_matcher(names: Sequence[str]) -> re.Pattern[str]:
    """Match label keys to label names, where * in a name stands for any text."""

    alternatives = [
        "".join(".*" if part == "*" else re.escape(part) for part in re.split(r"(\*)", key))
        for key in map(_label_key, names)
    ]
    return re.compile("|".join(alternatives) or "(?!)")


def _is_trusted_maintainer(comment: IssueComment) -> bool:
    return comment.author_association in _MAINTAINER_ASSOCIATIONS and not _BOT_LOGIN.search(
        comment.author
    )


def _active_claimants(
    discussion: list[IssueComment],
    maintainer_comments: list[IssueComment],
    *,
    now: datetime,
) -> list[str]:
    """Name everyone with a recent, unanswered claim on the issue.

    A claim lapses after 30 days, and a later maintainer invitation that does not address the
    claimant reopens the work to everyone.
    """

    invitations = [
        comment for comment in maintainer_comments if _stated(_WORK_INVITATION, comment.body)
    ]
    claimants: set[str] = set()
    for comment in discussion:
        if now - comment.created_at > _CLAIM_WINDOW or not (
            _stated(_WORK_CLAIM, comment.body)
            or _stated(_ASSIGNMENT_REQUEST, comment.body, questions_count=True)
        ):
            continue
        mention = re.compile(rf"@{re.escape(comment.author)}(?![\w-])", re.I)
        if any(
            invitation.created_at > comment.created_at and not mention.search(invitation.body)
            for invitation in invitations
        ):
            continue
        claimants.add(comment.author)
    return sorted(claimants)


def _stated(pattern: re.Pattern[str], text: str, *, questions_count: bool = False) -> bool:
    """Whether some sentence says the pattern outright, not negated or as a condition.

    A match inside a question counts only when ``questions_count`` is set.
    """

    for sentence in _SENTENCE_BREAK.split(text.replace("\u2019", "'")):
        for match in pattern.finditer(sentence):
            clause_start = _CLAUSE_BREAK.split(sentence[: match.start()])[-1]
            clause_end = _CLAUSE_BREAK.split(sentence[match.end() :])[0]
            if _NEGATED_OR_CONDITIONAL.search(clause_start):
                continue
            if "?" in clause_end and not questions_count:
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
    """Whether a file in the root, .github/ or docs/ can hold contribution or AI policy."""

    lowered = path.casefold()
    name = PurePosixPath(lowered).name
    if _is_explicit_cla_policy_path(path) or _is_explicit_dco_policy_path(path):
        return True
    if PurePosixPath(name).suffix not in _TEXT_SUFFIXES:
        return False
    if name == "readme" or name.startswith("readme."):
        # Only the top-level README speaks for the whole repository.
        return "/" not in lowered
    return (
        name in AGENT_INSTRUCTION_FILES
        or _is_contribution_guidance(path)
        or _is_pull_request_template(path)
        or _POLICY_NAME.fullmatch(name) is not None
    )


def competing_pull_requests(
    linked: Sequence[LinkedPullRequest],
    *,
    now: datetime,
) -> list[LinkedPullRequest]:
    """Keep the linked pull requests that still compete: recently active or closing the issue."""

    return [
        pull_request
        for pull_request in linked
        if pull_request.closes_issue
        or now - pull_request.updated_at <= _LINKED_PULL_REQUEST_ACTIVITY
    ]


def parse_issue_reference(value: str) -> tuple[str, int]:
    """Parse `owner/repository#123` without accepting URLs or ambiguous shorthand."""

    match = re.fullmatch(r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)#([1-9][0-9]*)", value.strip())
    if not match:
        raise ValueError("issue must use owner/repository#number syntax")
    return match.group(1), int(match.group(2))


def _counted_reason(count: int, *, singular: str, plural: str) -> str:
    return f"{count} {singular if count == 1 else plural}"


__all__ = [
    "AI_POLICY_EVIDENCE_KEY",
    "LEGAL_ATTESTATION_EVIDENCE_KEY",
    "LEGAL_POLICY_EVIDENCE_KEY",
    "LEGAL_REQUIREMENTS_EVIDENCE_KEY",
    "MAX_POLICY_FILES_PER_REPOSITORY",
    "MAX_POLICY_FILE_BYTES",
    "MAX_POLICY_TOTAL_BYTES",
    "POLICY_ORGANIZATION_REF_EVIDENCE_KEY",
    "POLICY_REPOSITORY_REF_EVIDENCE_KEY",
    "POLICY_SOURCES_EVIDENCE_KEY",
    "DiscoveryOutcome",
    "DiscoverySelection",
    "DiscoveryService",
    "IssueEvaluation",
    "IssueTriage",
    "PolicyClassifier",
    "PolicySnapshot",
    "TriageVerdict",
    "apply_legal_commit_message",
    "competing_pull_requests",
    "legal_attestation_fingerprint",
    "parse_issue_reference",
    "validate_legal_publication",
]
