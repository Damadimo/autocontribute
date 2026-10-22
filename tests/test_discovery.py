from datetime import UTC, datetime, timedelta

import pytest

from autocontribute.config import (
    CLA_ATTESTATION_STATEMENT,
    DCO_ATTESTATION_STATEMENT,
    AutocontributeConfig,
)
from autocontribute.discovery import (
    LEGAL_ATTESTATION_EVIDENCE_KEY,
    LEGAL_POLICY_EVIDENCE_KEY,
    MAX_POLICY_FILE_BYTES,
    MAX_POLICY_FILES_PER_REPOSITORY,
    MAX_POLICY_TOTAL_BYTES,
    POLICY_SOURCES_EVIDENCE_KEY,
    DiscoveryOutcome,
    DiscoveryService,
    PolicySnapshot,
    TriageVerdict,
    apply_legal_commit_message,
    competing_pull_requests,
    parse_issue_reference,
    validate_legal_publication,
)
from autocontribute.domain import (
    IssueCandidate,
    IssueComment,
    RepositoryInfo,
    RunManifest,
    RunStatus,
)
from autocontribute.exceptions import (
    CircuitBreakerTrigger,
    GitHubError,
    GitHubSafetyError,
    PolicyError,
    StateError,
)
from autocontribute.github import LinkedPullRequest
from autocontribute.store import (
    CandidateAttemptDisposition,
    CandidateAttemptState,
    RunStore,
)

REPOSITORY_REF = "a" * 40
ORGANIZATION_REF = "b" * 40


class FakeGitHub:
    def search_competing_pull_requests(
        self, repository: str, issue_number: int
    ) -> list[LinkedPullRequest]:
        return []

    def get_file(
        self,
        repository: str,
        path: str,
        *,
        ref: str,
        max_bytes: int = 1_000_000,
    ) -> str | None:
        del repository, ref, max_bytes
        return "Contribution guidelines" if path == "CONTRIBUTING.md" else None

    def default_branch_sha(self, repository: str, branch: str) -> str:
        del repository, branch
        return REPOSITORY_REF

    def default_branch_sha_if_exists(self, repository: str) -> str | None:
        del repository
        return ORGANIZATION_REF

    def list_repository_files(self, repository: str, *, ref: str, max_files: int) -> list[str]:
        del repository, ref, max_files
        return ["CONTRIBUTING.md"]


class PolicyGitHub(FakeGitHub):
    def __init__(self, files: dict[tuple[str, str], str]) -> None:
        self.files = files

    def get_file(
        self,
        repository: str,
        path: str,
        *,
        ref: str,
        max_bytes: int = 1_000_000,
    ) -> str | None:
        del ref, max_bytes
        return self.files.get((repository, path))

    def list_repository_files(self, repository: str, *, ref: str, max_files: int) -> list[str]:
        del ref, max_files
        return [path for owner_repository, path in self.files if owner_repository == repository]


REPOSITORY_LABELS = ["help wanted", "bug", "Good First Issue", "security", "wontfix"]


def _search_page(issues: list[IssueCandidate], *, page: int, per_page: int) -> list[IssueCandidate]:
    """Serve one page of search results; like GitHub's, they carry no discussion."""

    start = (page - 1) * per_page
    return [
        issue.model_copy(update={"discussion": []}) for issue in issues[start : start + per_page]
    ]


class CandidateDiscoveryGitHub(FakeGitHub):
    def __init__(self, issues: list[IssueCandidate]) -> None:
        self.issues = {issue.number: issue for issue in issues}
        self.fetched: list[int] = []

    def get_repository(self, full_name: str) -> RepositoryInfo:
        del full_name
        return _repository()

    def list_labels(self, repository: str) -> list[str]:
        del repository
        return REPOSITORY_LABELS

    def search_issues(
        self,
        repository: str,
        *,
        include_labels: list[str],
        exclude_labels: list[str],
        unassigned: bool,
        page: int,
        per_page: int,
    ) -> list[IssueCandidate]:
        del repository, include_labels, exclude_labels, unassigned
        return _search_page(list(self.issues.values()), page=page, per_page=per_page)

    def get_issue(self, repository: str, number: int) -> IssueCandidate:
        del repository
        self.fetched.append(number)
        return self.issues[number]


class DispositionStore:
    def __init__(
        self,
        states: dict[int, CandidateAttemptState],
        open_pull_request_runs: list[RunManifest] | None = None,
    ) -> None:
        self.states = states
        self.open_pull_request_runs = open_pull_request_runs or []

    def list_open_pull_request_runs(self) -> list[RunManifest]:
        return self.open_pull_request_runs

    def candidate_attempt_disposition(
        self,
        issue: IssueCandidate,
    ) -> CandidateAttemptDisposition:
        state = self.states.get(issue.number, CandidateAttemptState.AVAILABLE)
        prior = state != CandidateAttemptState.AVAILABLE
        return CandidateAttemptDisposition(
            state=state,
            issue_revision="a" * 64,
            prior_run_id="prior-run" if prior else None,
            prior_status=(
                RunStatus.REJECTED
                if state == CandidateAttemptState.SUPPRESSED
                else RunStatus.READY_FOR_APPROVAL
                if state == CandidateAttemptState.ACTIVE
                else None
            ),
        )


def _repository() -> RepositoryInfo:
    return RepositoryInfo(
        full_name="example/project",
        html_url="https://github.com/example/project",
        clone_url="https://github.com/example/project.git",
        default_branch="main",
        stars=10_000,
        archived=False,
        disabled=False,
        private=False,
        pushed_at=datetime.now(UTC),
        license_spdx="MIT",
    )


def _issue(**updates: object) -> IssueCandidate:
    values: dict[str, object] = {
        "repository": "example/project",
        "number": 42,
        "title": "Fix incorrect parser output",
        "body": (
            "Steps to reproduce: parse the attached minimal input. Actual behavior returns the "
            "wrong node; expected behavior is the documented node. Please add a regression test. "
            * 3
        ),
        "html_url": "https://github.com/example/project/issues/42",
        "state": "open",
        "author": "maintainer",
        "labels": ["help wanted", "bug"],
        "assignees": [],
        "comments": 2,
        "created_at": datetime.now(UTC) - timedelta(days=10),
        "updated_at": datetime.now(UTC) - timedelta(days=1),
    }
    values.update(updates)
    return IssueCandidate.model_validate(values)


def _legal_config(
    snapshot: PolicySnapshot,
    *,
    repository: str = "example/project",
) -> AutocontributeConfig:
    requirements = set(snapshot.legal_requirements)
    attestation: dict[str, object] = {
        "repository": repository,
        "reviewed_repository_ref": snapshot.repository_ref,
        "reviewed_organization_policy_ref": snapshot.organization_ref_evidence,
        "legal_policy_sha256": snapshot.legal_policy_sha256,
        "legal_requirements": list(snapshot.legal_requirements),
        "attested_by": "octocat",
        "attested_at": "2026-07-22T12:00:00Z",
    }
    if "cla" in requirements:
        attestation["cla"] = {"statement": CLA_ATTESTATION_STATEMENT}
    if "dco" in requirements:
        attestation["dco"] = {
            "statement": DCO_ATTESTATION_STATEMENT,
            "signoff_name": "Example Signer",
            "signoff_email": "signer@example.invalid",
        }
    return AutocontributeConfig.model_validate(
        {
            "identity": {
                "name": "Example Signer" if "dco" in requirements else "",
                "email": "signer@example.invalid" if "dco" in requirements else "",
            },
            "policy": {"legal_attestations": {repository: attestation}},
        }
    )


def test_clear_maintainer_signaled_issue_passes(tmp_path) -> None:
    config = AutocontributeConfig()
    service = DiscoveryService(config, FakeGitHub(), RunStore(tmp_path))  # type: ignore[arg-type]

    result = service.evaluate(_issue(), _repository())

    assert result.eligible
    assert result.score == 75
    assert {key: result.evidence[key] for key in SCORE_PARTS} == {
        "invitation": "25/25: labels=['bug', 'help wanted'], maintainer invitation=no",
        "specificity": "15/25: expected vs actual, reproduction or error",
        "smallness": "10/20: under 15 comments, one file or none named",
        "freshness": "10/15: created within 2 years, updated within 90 days",
        "testability": "15/15: reproduction, tests named",
    }


SCORE_PARTS = ("invitation", "specificity", "smallness", "freshness", "testability")


@pytest.mark.parametrize(
    ("updates", "score"),
    [
        ({"labels": ["bug"]}, 65),
        (
            {
                "title": "Parser crashes on empty input",
                "labels": ["bug"],
                "body": (
                    "Steps to reproduce:\n```python\nimport lib\nlib.parse('')\n```\n"
                    "Traceback (most recent call last):\n  ValueError: empty\n"
                    "Expected an empty node, but it raises. See src/lib/parser.py. A regression "
                    "test would help."
                ),
            },
            75,
        ),
        (
            {
                "title": "Fix typo in README",
                "labels": ["help wanted", "documentation"],
                "body": "The README says 'teh' where it means 'the'.",
            },
            80,
        ),
        (
            {
                "title": "Add a timeout to `fetch()`",
                "labels": ["help wanted"],
                "body": "Currently `fetch()` waits forever; it should accept a timeout.",
            },
            60,
        ),
        (
            {
                "created_at": datetime.now(UTC) - timedelta(days=900),
                "updated_at": datetime.now(UTC) - timedelta(days=200),
            },
            65,
        ),
    ],
)
def test_score_rewards_agent_suitable_issues(
    tmp_path,
    updates: dict[str, object],
    score: int,
) -> None:  # type: ignore[no-untyped-def]
    service = DiscoveryService(AutocontributeConfig(), FakeGitHub(), RunStore(tmp_path))  # type: ignore[arg-type]

    result = service.evaluate(_issue(**updates), _repository())

    assert result.score == score
    assert result.eligible, result.blockers


def test_vague_issue_falls_below_the_score_floor(tmp_path) -> None:  # type: ignore[no-untyped-def]
    service = DiscoveryService(AutocontributeConfig(), FakeGitHub(), RunStore(tmp_path))  # type: ignore[arg-type]

    evaluation = service._assess(
        _issue(title="Improve things", body="It would be nice to improve this."), _repository()
    )

    assert evaluation.eligibility.score == 45
    assert evaluation.blocker_kinds == ("low score",)
    assert evaluation.eligibility.blockers == ["candidate score 45 is below the floor of 60"]


def test_recent_maintainer_comment_adds_freshness(tmp_path) -> None:  # type: ignore[no-untyped-def]
    service = DiscoveryService(AutocontributeConfig(), FakeGitHub(), RunStore(tmp_path))  # type: ignore[arg-type]
    engaged = _issue(
        comments=1,
        discussion=[
            _comment(body="Confirmed on main.", author="maintainer", association="COLLABORATOR")
        ],
    )

    assert service.evaluate(engaged, _repository()).score == 80


def test_blockers_do_not_lower_the_score(tmp_path) -> None:  # type: ignore[no-untyped-def]
    github = PolicyGitHub(
        {
            ("example/project", "CONTRIBUTING.md"): "Ordinary contribution guidance.",
            ("example/.github", "AI_POLICY.md"): "AI-generated contributions will be closed.",
        }
    )
    service = DiscoveryService(AutocontributeConfig(), github, RunStore(tmp_path))  # type: ignore[arg-type]

    blocked = service.evaluate(_issue(assignees=["someone"]), _repository())

    assert not blocked.eligible
    assert blocked.score == 75


def test_assigned_issue_fails_closed(tmp_path) -> None:
    config = AutocontributeConfig()
    service = DiscoveryService(config, FakeGitHub(), RunStore(tmp_path))  # type: ignore[arg-type]

    result = service.evaluate(_issue(assignees=["someone"]), _repository())

    assert not result.eligible
    assert "already assigned" in " ".join(result.blockers)


def test_possible_security_issue_is_never_publicly_selected(tmp_path) -> None:
    config = AutocontributeConfig()
    service = DiscoveryService(config, FakeGitHub(), RunStore(tmp_path))  # type: ignore[arg-type]

    result = service.evaluate(_issue(title="CVE-2026-1234 remote code execution"), _repository())

    assert not result.eligible
    assert "private handling" in " ".join(result.blockers)


@pytest.mark.parametrize(
    "title",
    [
        "Fix SQL injection in search",
        "Prevent XSS in rendered names",
        "Authentication bypass in SSO middleware",
        "Authorization bypass permits cross-tenant reads",
        "Local privilege escalation through helper binary",
        "Prevent SSRF in webhook previews",
        "Server-side request forgery through redirects",
        "Path traversal when unpacking an archive",
        "Directory traversal in static file handler",
        "Use-after-free in the stream parser",
        "Arbitrary file write via crafted output path",
        "Arbitrary file read in template loader",
        "Denial of service in the parser",
        "Information disclosure in diagnostic logs",
        "Remote account takeover through password reset",
        "RCE via a crafted request",
        "Remote command execution through the helper",
        "ReDoS in the route matcher",
        "Out-of-bounds write in the decoder",
        "Sensitive data leak in debug output",
        "Open redirect in the login callback",
        "Remote-code-execution through the helper",
        "Open-redirect in the login callback",
        "Sandbox-escape from the worker",
        "HTTP request-smuggling in the proxy",
        "Prototype-pollution in object merging",
        "Insecure-deserialization in session loading",
        "Account-takeover through password reset",
        "Out-of-bounds memory read in the decoder",
        "OOB-read in the native parser",
        "Information leak from diagnostic logs",
        "SQLi in the query builder",
        "Auth bypass in the login handler",
        "IDOR in the account endpoint",
        "LFI through the template name",
        "SSTI in notification rendering",
        "LPE through the helper binary",
        "Remote code exec through the worker",
        "Arbitrary command execution in the task runner",
        "Remote file inclusion in template loading",
        "RFI through the locale parameter",
        "CRLF injection in response headers",
        "HTTP response splitting in the proxy",
        "Cache poisoning through an unkeyed header",
        "Host header injection in password-reset links",
        "Double free in the native decoder",
        "Integer overflow in length calculation",
        "Data exfiltration through diagnostic output",
        "Security issue in token validation",
        "Security bug in token validation",
        "Potential security impact in token validation",
        "A timing attack can reveal the secret",
        "A race condition bypasses the permission check",
        "Fix DOS in the request parser",
        "Prevent DDoS through expensive requests",
        "Secret leak in debug logs",
        "Hard-coded credentials in the sample app",
        "CWE-798 in the default config",
        "XSRF in the callback flow",
    ],
)
def test_security_issue_synonyms_fail_closed(tmp_path, title: str) -> None:  # type: ignore[no-untyped-def]
    service = DiscoveryService(AutocontributeConfig(), FakeGitHub(), RunStore(tmp_path))  # type: ignore[arg-type]

    result = service.evaluate(_issue(title=title), _repository())

    assert not result.eligible
    assert "private handling" in " ".join(result.blockers)


def test_security_issue_term_in_body_fails_closed(tmp_path) -> None:
    service = DiscoveryService(AutocontributeConfig(), FakeGitHub(), RunStore(tmp_path))  # type: ignore[arg-type]

    result = service.evaluate(
        _issue(body="A crafted request triggers memory corruption in the native parser."),
        _repository(),
    )

    assert not result.eligible
    assert "private handling" in " ".join(result.blockers)


@pytest.mark.parametrize(
    "body",
    [
        "A crafted request permits remote\ncode execution in the worker.",
        "A crafted request permits remote  code execution in the worker.",
        "A crafted request permits remote **code** execution in the worker.",
    ],
)
def test_security_issue_markup_and_whitespace_normalization_fails_closed(
    tmp_path,
    body: str,
) -> None:  # type: ignore[no-untyped-def]
    service = DiscoveryService(AutocontributeConfig(), FakeGitHub(), RunStore(tmp_path))  # type: ignore[arg-type]

    result = service.evaluate(_issue(body=body), _repository())

    assert not result.eligible
    assert "private handling" in " ".join(result.blockers)


def test_lowercase_non_security_word_dos_is_not_treated_as_denial_of_service(
    tmp_path,
) -> None:  # type: ignore[no-untyped-def]
    service = DiscoveryService(AutocontributeConfig(), FakeGitHub(), RunStore(tmp_path))  # type: ignore[arg-type]

    result = service.evaluate(
        _issue(title="Hay dos errores en el analizador"),
        _repository(),
    )

    assert result.eligible
    assert "private handling" not in " ".join(result.blockers)


def test_security_issue_term_in_later_discussion_comment_fails_closed(tmp_path) -> None:
    service = DiscoveryService(AutocontributeConfig(), FakeGitHub(), RunStore(tmp_path))  # type: ignore[arg-type]
    issue = _issue(
        comments=2,
        discussion=[
            _comment(body="The public symptoms look like an ordinary parsing bug."),
            _comment(body="A private reproducer confirms an authentication bypass."),
        ],
    )

    result = service.evaluate(issue, _repository())

    assert not result.eligible
    assert "private handling" in " ".join(result.blockers)


@pytest.mark.parametrize(
    "label",
    [
        "vulnerability",
        "CVE",
        "type: security advisory",
        "CWE-79",
        "sec:high",
        "kind/vuln",
    ],
)
def test_security_issue_labels_fail_closed(tmp_path, label: str) -> None:
    service = DiscoveryService(AutocontributeConfig(), FakeGitHub(), RunStore(tmp_path))  # type: ignore[arg-type]
    issue = _issue(labels=["help wanted", "bug", label])

    result = service.evaluate(issue, _repository())

    assert not result.eligible
    assert "private handling" in " ".join(result.blockers)


def test_explicit_security_issue_override_applies_to_text_and_labels(tmp_path) -> None:
    config = AutocontributeConfig.model_validate({"policy": {"allow_security_issues": True}})
    service = DiscoveryService(config, FakeGitHub(), RunStore(tmp_path))  # type: ignore[arg-type]
    issue = _issue(
        title="Denial of service in the parser",
        labels=["help wanted", "bug", "vulnerability"],
        comments=1,
        discussion=[_comment(body="A private report confirms an authentication bypass.")],
    )

    result = service.evaluate(issue, _repository())

    assert result.eligible
    assert "private handling" not in " ".join(result.blockers)


def test_inactive_repository_fails_before_model_selection(tmp_path) -> None:
    config = AutocontributeConfig.model_validate({"github": {"max_repository_inactivity_days": 30}})
    service = DiscoveryService(config, FakeGitHub(), RunStore(tmp_path))  # type: ignore[arg-type]
    repository = _repository().model_copy(
        update={"pushed_at": datetime.now(UTC) - timedelta(days=31)}
    )

    result = service.evaluate(_issue(), repository)

    assert not result.eligible
    assert "inactive" in " ".join(result.blockers)


def test_issue_reference_parser_is_unambiguous() -> None:
    assert parse_issue_reference("owner/repo#123") == ("owner/repo", 123)


def _discovery_config(*repositories: str, **budget: int) -> AutocontributeConfig:
    return AutocontributeConfig.model_validate(
        {
            "github": {"repositories": list(repositories)},
            "budget": budget,
            "validation": {
                "required_commands": {
                    repository: ["python -m pytest"] for repository in repositories
                }
            },
        }
    )


def test_discovery_continues_past_suppressed_revision_without_spending_candidate_budget() -> None:
    first = _issue(number=41, title="Previously rejected candidate")
    second = _issue(number=42, title="Fresh candidate")
    third = _issue(number=43, title="Candidate beyond the configured evaluation budget")
    github = CandidateDiscoveryGitHub([first, second, third])
    store = DispositionStore({41: CandidateAttemptState.SUPPRESSED})
    config = _discovery_config("example/project", max_candidates_per_run=1)
    service = DiscoveryService(config, github, store)  # type: ignore[arg-type]

    outcome = service.discover()

    assert outcome.selection is not None
    assert outcome.selection[0].number == 42
    assert outcome.suppressed_candidates == 1
    assert [evaluation.issue.number for evaluation in outcome.evaluations] == [42]
    assert github.fetched == [41, 42]


def test_discovery_exhaustion_distinguishes_suppressed_active_and_ineligible_candidates() -> None:
    issues = [
        _issue(number=41),
        _issue(number=42),
        _issue(number=43, assignees=["someone"]),
    ]
    github = CandidateDiscoveryGitHub(issues)
    store = DispositionStore(
        {
            41: CandidateAttemptState.SUPPRESSED,
            42: CandidateAttemptState.ACTIVE,
        }
    )
    service = DiscoveryService(_discovery_config("example/project"), github, store)  # type: ignore[arg-type]

    outcome = service.discover()

    assert outcome.selection is None
    assert outcome.active_candidates == 1
    assert outcome.suppressed_candidates == 1
    assert outcome.ineligible_candidates == 1
    assert outcome.blocker_counts == [("assigned", 1)]
    assert outcome.no_candidate_reason == (
        "No candidate is currently available: 1 unchanged issue revision was deferred after a "
        "prior skipped, rejected, or cancelled run; 1 candidate already has an active run; "
        "1 candidate failed discovery gates (assigned 1)."
    )


def _open_pull_request_run(repository: str) -> RunManifest:
    now = datetime.now(UTC)
    return RunManifest(
        run_id="open-pull-request",
        status=RunStatus.PR_OPEN,
        created_at=now,
        updated_at=now,
        candidate=_repository_issue(repository, 5),
        pull_request_url=f"https://github.com/{repository}/pull/77",
    )


def test_repository_with_an_open_autocontribute_pull_request_is_skipped() -> None:
    github = IsolationGitHub(
        {
            "example/project": [_repository_issue("example/project", 42)],
            "other/project": [_repository_issue("other/project", 7)],
        }
    )
    store = DispositionStore({}, [_open_pull_request_run("Example/Project")])
    service = DiscoveryService(  # type: ignore[arg-type]
        _discovery_config("example/project", "other/project"), github, store
    )

    outcome = service.discover()

    assert outcome.selection is not None
    assert outcome.selection[0].reference == "other/project#7"
    assert outcome.skipped_repositories == (
        (
            "example/project",
            "an autocontribute pull request is already open: "
            "https://github.com/Example/Project/pull/77",
        ),
    )
    assert [evaluation.issue.repository for evaluation in outcome.evaluations] == ["other/project"]


def test_empty_discovery_preserves_generic_no_candidate_reason() -> None:
    outcome = DiscoveryOutcome(selection=None)

    assert outcome.no_candidate_reason == "No candidate passed deterministic discovery gates."


class IsolationGitHub(FakeGitHub):
    """Serves several repositories and fails the reads named in ``failures``."""

    def __init__(
        self,
        issues: dict[str, list[IssueCandidate]],
        failures: dict[str, Exception] | None = None,
    ) -> None:
        self.issues = issues
        self.failures = failures or {}

    def _fail(self, key: str) -> None:
        if key in self.failures:
            raise self.failures[key]

    def get_repository(self, full_name: str) -> RepositoryInfo:
        self._fail(f"repository:{full_name}")
        return _repository().model_copy(
            update={
                "full_name": full_name,
                "html_url": f"https://github.com/{full_name}",
                "clone_url": f"https://github.com/{full_name}.git",
            }
        )

    def list_owner_repositories(self, owner: str, *, limit: int) -> list[RepositoryInfo]:
        self._fail(f"owner:{owner}")
        del limit
        return [self.get_repository(name) for name in self.issues if name.startswith(f"{owner}/")]

    def list_labels(self, repository: str) -> list[str]:
        self._fail(f"labels:{repository}")
        return REPOSITORY_LABELS

    def search_issues(
        self,
        repository: str,
        *,
        include_labels: list[str],
        exclude_labels: list[str],
        unassigned: bool,
        page: int,
        per_page: int,
    ) -> list[IssueCandidate]:
        del include_labels, exclude_labels, unassigned
        self._fail(f"search:{repository}")
        return _search_page(self.issues[repository], page=page, per_page=per_page)

    def get_issue(self, repository: str, number: int) -> IssueCandidate:
        self._fail(f"issue:{repository}#{number}")
        return next(issue for issue in self.issues[repository] if issue.number == number)

    def get_file(
        self,
        repository: str,
        path: str,
        *,
        ref: str,
        max_bytes: int = 1_000_000,
    ) -> str | None:
        self._fail(f"file:{repository}/{path}")
        return super().get_file(repository, path, ref=ref, max_bytes=max_bytes)


def _repository_issue(repository: str, number: int, **updates: object) -> IssueCandidate:
    return _issue(
        repository=repository,
        number=number,
        html_url=f"https://github.com/{repository}/issues/{number}",
        **updates,
    )


def test_one_failing_repository_or_issue_cannot_abort_discovery(tmp_path) -> None:  # type: ignore[no-untyped-def]
    github = IsolationGitHub(
        {
            "broken/search": [_repository_issue("broken/search", 1)],
            "broken/policy": [
                _repository_issue("broken/policy", 2),
                _repository_issue("broken/policy", 3),
            ],
            "example/project": [
                _repository_issue("example/project", 7),
                _repository_issue("example/project", 8, assignees=["someone"]),
                _repository_issue("example/project", 9),
            ],
        },
        failures={
            "repository:missing/repository": GitHubError("GitHub returned 404"),
            "search:broken/search": GitHubError("Search timed out"),
            "file:broken/policy/CONTRIBUTING.md": GitHubError(
                "GitHub policy file could not be decoded safely"
            ),
            "issue:example/project#7": GitHubError(
                "Issue changed while its complete discussion was fetched"
            ),
        },
    )
    config = _discovery_config(
        "missing/repository", "broken/search", "broken/policy", "example/project"
    )
    service = DiscoveryService(config, github, RunStore(tmp_path))  # type: ignore[arg-type]

    outcome = service.discover()

    assert outcome.selection is not None
    assert outcome.selection[0].reference == "example/project#9"
    assert outcome.repository_errors == (
        ("missing/repository", "GitHub returned 404"),
        ("broken/search", "Search timed out"),
        ("broken/policy", "GitHub policy file could not be decoded safely"),
    )
    assert outcome.issue_errors == (
        ("example/project#7", "Issue changed while its complete discussion was fetched"),
    )
    assert [evaluation.issue.number for evaluation in outcome.evaluations] == [8, 9]
    assert outcome.blocker_counts == [("assigned", 1)]
    assert outcome.summary == (
        "2 issues evaluated, 1 eligible; 1 candidate failed discovery gates (assigned 1); "
        "3 repositories could not be searched; 1 issue could not be evaluated."
    )


def test_failing_owner_listing_keeps_explicit_repositories(tmp_path) -> None:  # type: ignore[no-untyped-def]
    github = IsolationGitHub(
        {"example/project": [_repository_issue("example/project", 42)]},
        failures={"owner:gone": GitHubError("GitHub returned 404")},
    )
    config = _discovery_config("example/project")
    config.github.owners = ["gone"]
    service = DiscoveryService(config, github, RunStore(tmp_path))  # type: ignore[arg-type]

    outcome = service.discover()

    assert outcome.selection is not None
    assert outcome.repository_errors == (("gone", "GitHub returned 404"),)


def test_repositories_below_the_baseline_are_reported_as_skipped(tmp_path) -> None:  # type: ignore[no-untyped-def]
    github = IsolationGitHub({"example/project": [_repository_issue("example/project", 42)]})
    config = _discovery_config("example/project")
    config.github.min_stars = 1_000_000
    service = DiscoveryService(config, github, RunStore(tmp_path))  # type: ignore[arg-type]

    outcome = service.discover()

    assert outcome.selection is None
    assert outcome.skipped_repositories == (
        (
            "example/project",
            "repository is private, archived, disabled, inactive, or below the star floor",
        ),
    )
    assert outcome.no_candidate_reason == (
        "No candidate is currently available: 1 repository was skipped."
    )


@pytest.mark.parametrize(
    "failure",
    [
        GitHubSafetyError(
            "GitHub reports this account is suspended",
            trigger=CircuitBreakerTrigger(
                source="github_api", reason="suspended", trigger_hash="a"
            ),
        ),
        StateError("Circuit breaker is tripped by operator:me: maintenance"),
        StateError("Lease autocontribute.run is no longer owned by this worker"),
    ],
)
def test_safety_stops_and_state_errors_still_end_discovery(
    tmp_path,
    failure: Exception,
) -> None:  # type: ignore[no-untyped-def]
    github = IsolationGitHub(
        {"example/project": [_repository_issue("example/project", 42)]},
        failures={"issue:example/project#42": failure},
    )
    service = DiscoveryService(  # type: ignore[arg-type]
        _discovery_config("example/project"), github, RunStore(tmp_path)
    )

    with pytest.raises(type(failure)):
        service.discover()


class SearchGitHub(FakeGitHub):
    def __init__(self, issues: list[IssueCandidate], labels: list[str]) -> None:
        self.issues = issues
        self.labels = labels
        self.searches: list[dict[str, object]] = []
        self.fetched: list[int] = []

    def get_repository(self, full_name: str) -> RepositoryInfo:
        del full_name
        return _repository()

    def list_labels(self, repository: str) -> list[str]:
        del repository
        return self.labels

    def search_issues(
        self,
        repository: str,
        *,
        include_labels: list[str],
        exclude_labels: list[str],
        unassigned: bool,
        page: int,
        per_page: int,
    ) -> list[IssueCandidate]:
        del repository
        self.searches.append(
            {
                "include": include_labels,
                "exclude": exclude_labels,
                "unassigned": unassigned,
                "page": page,
            }
        )
        return _search_page(self.issues, page=page, per_page=per_page)

    def get_issue(self, repository: str, number: int) -> IssueCandidate:
        del repository
        self.fetched.append(number)
        return next(issue for issue in self.issues if issue.number == number)


def test_search_uses_the_repository_spelling_of_invitation_labels_and_synonyms(tmp_path) -> None:  # type: ignore[no-untyped-def]
    github = SearchGitHub(
        [_issue(labels=["Help-Wanted"])],
        labels=[
            "Help-Wanted",
            "Status: Help Wanted",
            "sprintable",
            "E-easy",
            "enhancement",
            "good-first-issue",
            "Security",
        ],
    )
    service = DiscoveryService(  # type: ignore[arg-type]
        _discovery_config("example/project"), github, RunStore(tmp_path)
    )

    outcome = service.discover()

    assert outcome.selection is not None
    assert github.searches == [
        {
            "include": ["Help-Wanted", "Status: Help Wanted", "sprintable", "E-easy"],
            "exclude": ["good-first-issue", "Security"],
            "unassigned": True,
            "page": 1,
        }
    ]


def test_repository_label_override_replaces_the_global_lists_and_synonyms(tmp_path) -> None:  # type: ignore[no-untyped-def]
    config = _discovery_config("example/project")
    config.github.labels = {  # type: ignore[assignment]
        "Example/Project": {"include": ["enhancement"], "exclude": []}
    }
    github = SearchGitHub(
        [_issue(labels=["Enhancement", "Good First Issue"])],
        labels=["help wanted", "sprintable", "enhancement", "Good First Issue"],
    )
    service = DiscoveryService(config, github, RunStore(tmp_path))  # type: ignore[arg-type]

    outcome = service.discover()

    assert github.searches[0]["include"] == ["enhancement"]
    assert github.searches[0]["exclude"] == []
    assert outcome.selection is not None


def test_repository_without_invitation_labels_is_skipped_before_searching(tmp_path) -> None:  # type: ignore[no-untyped-def]
    github = SearchGitHub([_issue()], labels=["enhancement", "question"])
    service = DiscoveryService(  # type: ignore[arg-type]
        _discovery_config("example/project"), github, RunStore(tmp_path)
    )

    outcome = service.discover()

    assert outcome.selection is None
    assert outcome.skipped_repositories == (
        ("example/project", "repository has none of the invitation labels"),
    )
    assert github.searches == []


def test_search_pages_past_issues_rejected_from_the_search_result(tmp_path) -> None:  # type: ignore[no-untyped-def]
    assigned = [_issue(number=number, assignees=["someone"]) for number in range(1, 101)]
    github = SearchGitHub([*assigned, _issue(number=101), _issue(number=102)], REPOSITORY_LABELS)
    config = _discovery_config("example/project")
    config.github.issue_limit_per_repository = 2
    service = DiscoveryService(config, github, RunStore(tmp_path))  # type: ignore[arg-type]

    outcome = service.discover()

    assert [search["page"] for search in github.searches] == [1, 2]
    assert github.fetched == [101, 102]
    assert outcome.blocker_counts == [("assigned", 100)]
    assert outcome.evaluations[0].notes == (
        "rejected from the search result; the discussion was not read",
    )
    assert outcome.selection is not None


def test_search_reads_a_bounded_number_of_pages(tmp_path) -> None:  # type: ignore[no-untyped-def]
    assigned = [_issue(number=number, assignees=["someone"]) for number in range(1, 401)]
    github = SearchGitHub(assigned, REPOSITORY_LABELS)
    service = DiscoveryService(  # type: ignore[arg-type]
        _discovery_config("example/project"), github, RunStore(tmp_path)
    )

    outcome = service.discover()

    assert [search["page"] for search in github.searches] == [1, 2, 3]
    assert github.fetched == []
    assert outcome.ineligible_candidates == 300


@pytest.mark.parametrize(
    ("labels", "blocker"),
    [
        (["Status: Help Wanted"], None),
        (["HELP WANTED"], None),
        (["sprintable"], None),
        (["help wanted", "Good-First-Issue"], "issue has excluded labels: Good-First-Issue"),
        (
            ["enhancement"],
            "issue has no invitation label and no maintainer comment inviting a pull request",
        ),
    ],
)
def test_labels_match_without_case_hyphens_or_underscores(
    tmp_path,
    labels: list[str],
    blocker: str | None,
) -> None:  # type: ignore[no-untyped-def]
    service = DiscoveryService(AutocontributeConfig(), FakeGitHub(), RunStore(tmp_path))  # type: ignore[arg-type]

    result = service.evaluate(_issue(labels=labels), _repository())

    if blocker is None:
        assert result.eligible, result.blockers
    else:
        assert blocker in result.blockers


def test_maintainer_comment_inviting_a_pull_request_is_an_invitation(tmp_path) -> None:  # type: ignore[no-untyped-def]
    service = DiscoveryService(AutocontributeConfig(), FakeGitHub(), RunStore(tmp_path))  # type: ignore[arg-type]
    invited = _issue(
        labels=["enhancement"],
        comments=1,
        discussion=[
            _comment(body="Good idea, PRs welcome!", author="maintainer", association="MEMBER")
        ],
    )
    from_contributor = invited.model_copy(
        update={"discussion": [_comment(body="Good idea, PRs welcome!")]}
    )

    assert service.evaluate(invited, _repository()).eligible
    assert not service.evaluate(from_contributor, _repository()).eligible


class RecordingTriage:
    def __init__(self, verdicts: dict[int, TriageVerdict | Exception]) -> None:
        self.verdicts = verdicts
        self.triaged: list[int] = []

    def triage(self, issue: IssueCandidate, repository: RepositoryInfo) -> TriageVerdict:
        del repository
        self.triaged.append(issue.number)
        verdict = self.verdicts.get(issue.number, _verdict())
        if isinstance(verdict, Exception):
            raise verdict
        return verdict


def _verdict(**updates: object) -> TriageVerdict:
    values: dict[str, object] = {
        "suitable": True,
        "reasons": ["Small, well-specified parser fix."],
        "already_fixed": False,
        "needs_design": False,
        "difficulty": "small",
    }
    values.update(updates)
    return TriageVerdict.model_validate(values)


def _ranked_issues() -> list[IssueCandidate]:
    """Seven equally scored eligible issues; a lower number was updated later and ranks first."""

    issues = []
    for number in range(1, 8):
        issues.append(
            _issue(
                number=number,
                updated_at=datetime.now(UTC) - timedelta(hours=number),
            )
        )
    return issues


def test_without_triage_the_top_score_wins(tmp_path) -> None:  # type: ignore[no-untyped-def]
    github = SearchGitHub(_ranked_issues(), REPOSITORY_LABELS)
    service = DiscoveryService(  # type: ignore[arg-type]
        _discovery_config("example/project"), github, RunStore(tmp_path)
    )

    outcome = service.discover()

    assert outcome.selection is not None
    assert outcome.selection[0].number == 1
    assert "triage" not in outcome.selection[2].evidence


def test_triage_picks_the_best_ranked_issue_it_accepts(tmp_path) -> None:  # type: ignore[no-untyped-def]
    triage = RecordingTriage(
        {
            1: _verdict(suitable=False, reasons=["Needs a maintainer decision on the API."]),
            2: _verdict(difficulty="large"),
            3: GitHubError("triage request failed"),
            4: _verdict(already_fixed=True, reasons=["Fixed on main by #77."]),
            5: _verdict(difficulty="medium", reasons=["Two files, clear tests."]),
        }
    )
    github = SearchGitHub(_ranked_issues(), REPOSITORY_LABELS)
    service = DiscoveryService(  # type: ignore[arg-type]
        _discovery_config("example/project"), github, RunStore(tmp_path), triage=triage
    )

    outcome = service.discover()

    assert triage.triaged == [1, 2, 3, 4, 5]
    assert outcome.selection is not None
    issue, _, eligibility = outcome.selection
    assert issue.number == 5
    assert eligibility.evidence["triage"] == "medium, suitable: Two files, clear tests."
    assert outcome.issue_errors == (("example/project#3", "triage failed: triage request failed"),)
    blocked = {evaluation.issue.number: evaluation for evaluation in outcome.evaluations}
    assert blocked[1].eligibility.blockers == [
        "triage turned the issue down: small, judged unsuitable: Needs a maintainer decision on "
        "the API."
    ]
    assert blocked[2].blocker_kinds == ("triage",)
    assert blocked[4].eligibility.blockers == [
        "triage turned the issue down: small, already fixed: Fixed on main by #77."
    ]
    assert outcome.blocker_counts == [("triage", 3)]


def test_triage_sees_only_the_top_five_issues(tmp_path) -> None:  # type: ignore[no-untyped-def]
    triage = RecordingTriage({number: _verdict(needs_design=True) for number in range(1, 8)})
    github = SearchGitHub(_ranked_issues(), REPOSITORY_LABELS)
    service = DiscoveryService(  # type: ignore[arg-type]
        _discovery_config("example/project"), github, RunStore(tmp_path), triage=triage
    )

    outcome = service.discover()

    assert triage.triaged == [1, 2, 3, 4, 5]
    assert outcome.selection is None
    assert outcome.no_candidate_reason == (
        "No candidate is currently available: 5 candidates failed discovery gates (triage 5)."
    )


class LinkedPullRequestGitHub(FakeGitHub):
    def __init__(self, linked: list[LinkedPullRequest] | Exception) -> None:
        self.linked = linked
        self.searches = 0

    def search_competing_pull_requests(
        self, repository: str, issue_number: int
    ) -> list[LinkedPullRequest]:
        del repository, issue_number
        self.searches += 1
        if isinstance(self.linked, Exception):
            raise self.linked
        return self.linked


def _linked(number: int, *, days_ago: int, closes_issue: bool = False) -> LinkedPullRequest:
    return LinkedPullRequest(
        html_url=f"https://github.com/example/project/pull/{number}",
        updated_at=datetime.now(UTC) - timedelta(days=days_ago),
        closes_issue=closes_issue,
    )


def test_recent_or_closing_linked_pull_requests_compete_and_stale_ones_do_not() -> None:
    recent = _linked(1, days_ago=89)
    stale = _linked(2, days_ago=91)
    stale_closing = _linked(3, days_ago=400, closes_issue=True)

    assert competing_pull_requests([recent, stale, stale_closing], now=datetime.now(UTC)) == [
        recent,
        stale_closing,
    ]


def test_stale_linked_pull_request_is_reported_without_blocking(tmp_path) -> None:  # type: ignore[no-untyped-def]
    stale = _linked(7, days_ago=120)
    service = DiscoveryService(  # type: ignore[arg-type]
        AutocontributeConfig(), LinkedPullRequestGitHub([stale]), RunStore(tmp_path)
    )

    evaluation = service._assess(_issue(), _repository())

    assert evaluation.eligibility.eligible, evaluation.eligibility.blockers
    assert evaluation.notes == (
        "stale linked PR, not blocking: https://github.com/example/project/pull/7 "
        f"(updated {stale.updated_at.date().isoformat()})",
    )
    assert evaluation.eligibility.evidence["linked_pull_requests"] == "0 competing, 1 stale"


def test_active_linked_pull_request_blocks_the_issue(tmp_path) -> None:  # type: ignore[no-untyped-def]
    service = DiscoveryService(  # type: ignore[arg-type]
        AutocontributeConfig(),
        LinkedPullRequestGitHub([_linked(8, days_ago=3), _linked(9, days_ago=200)]),
        RunStore(tmp_path),
    )

    evaluation = service._assess(_issue(), _repository())

    assert evaluation.blocker_kinds == ("linked pull request",)
    assert evaluation.eligibility.blockers == [
        "possible competing pull request already exists: https://github.com/example/project/pull/8"
    ]
    assert len(evaluation.notes) == 1


def test_incomplete_linked_pull_request_evidence_blocks_only_that_issue(tmp_path) -> None:  # type: ignore[no-untyped-def]
    github = LinkedPullRequestGitHub(
        GitHubError(
            "Issue timeline exceeded 1,000 events; duplicate pull-request status is ambiguous"
        )
    )
    service = DiscoveryService(AutocontributeConfig(), github, RunStore(tmp_path))  # type: ignore[arg-type]

    evaluation = service._assess(_issue(), _repository())

    assert evaluation.blocker_kinds == ("linked pull request",)
    assert evaluation.eligibility.blockers == [
        "linked pull requests could not be checked completely: Issue timeline exceeded 1,000 "
        "events; duplicate pull-request status is ambiguous"
    ]


def test_linked_pull_requests_are_not_searched_for_an_already_blocked_issue(tmp_path) -> None:  # type: ignore[no-untyped-def]
    github = LinkedPullRequestGitHub([])
    service = DiscoveryService(AutocontributeConfig(), github, RunStore(tmp_path))  # type: ignore[arg-type]

    result = service.evaluate(_issue(assignees=["someone"]), _repository())

    assert not result.eligible
    assert github.searches == 0
    assert "linked_pull_requests" not in result.evidence


def _comment(
    *,
    body: str,
    author: str = "contributor",
    association: str = "NONE",
    days_ago: int = 0,
) -> IssueComment:
    created = datetime.now(UTC) - timedelta(days=days_ago)
    return IssueComment(
        author=author,
        author_association=association,
        body=body,
        html_url=f"https://github.com/example/project/issues/42#{author}-{days_ago}",
        created_at=created,
        updated_at=created,
    )


@pytest.mark.parametrize(
    "body",
    [
        "I'm working on this and will open a PR shortly.",
        "I\u2019ll take this.",
        "I'm working on this, OK?",
        "Is anyone working on this? If not, I'll take it.",
        "I started working on a fix last week.",
        "Could you please assign this to me?",
    ],
)
def test_claimed_work_in_discussion_fails_closed(tmp_path, body: str) -> None:  # type: ignore[no-untyped-def]
    config = AutocontributeConfig()
    service = DiscoveryService(config, FakeGitHub(), RunStore(tmp_path))  # type: ignore[arg-type]
    issue = _issue(comments=1, discussion=[_comment(body=body, author="claimant")])

    result = service.evaluate(issue, _repository())

    assert not result.eligible
    assert result.blockers == ["issue discussion indicates claimed work by claimant"]


@pytest.mark.parametrize(
    "body",
    [
        "Is anyone working on a fix?",
        "Nobody is working on a fix yet.",
        "Not sure anyone is working on a fix.",
        "I don't think anyone is working on a fix.",
        "If you're working on a fix, please link the PR here.",
        "Please don't assign this to me; I only reported it.",
    ],
)
def test_questions_negations_and_conditions_are_not_claims(tmp_path, body: str) -> None:  # type: ignore[no-untyped-def]
    service = DiscoveryService(AutocontributeConfig(), FakeGitHub(), RunStore(tmp_path))  # type: ignore[arg-type]
    issue = _issue(comments=1, discussion=[_comment(body=body)])

    result = service.evaluate(issue, _repository())

    assert result.eligible, result.blockers


def test_claims_lapse_after_thirty_days(tmp_path) -> None:  # type: ignore[no-untyped-def]
    service = DiscoveryService(AutocontributeConfig(), FakeGitHub(), RunStore(tmp_path))  # type: ignore[arg-type]
    claim = "I'm working on this now."

    recent = service.evaluate(
        _issue(comments=1, discussion=[_comment(body=claim, days_ago=29)]), _repository()
    )
    lapsed = service.evaluate(
        _issue(comments=1, discussion=[_comment(body=claim, days_ago=31)]), _repository()
    )

    assert not recent.eligible
    assert lapsed.eligible, lapsed.blockers


@pytest.mark.parametrize(
    ("invitation", "invitation_days_ago", "reopened"),
    [
        ("This is still open for anyone: feel free to open a PR.", 2, True),
        ("PRs welcome!", 2, True),
        ("@claimant thanks, feel free to open a PR.", 2, False),
        ("Feel free to open a PR.", 20, False),
        ("I don't think PRs are welcome here yet.", 2, False),
    ],
)
def test_later_maintainer_invitation_reopens_claimed_work(
    tmp_path,
    invitation: str,
    invitation_days_ago: int,
    reopened: bool,
) -> None:  # type: ignore[no-untyped-def]
    service = DiscoveryService(AutocontributeConfig(), FakeGitHub(), RunStore(tmp_path))  # type: ignore[arg-type]
    issue = _issue(
        comments=2,
        discussion=[
            _comment(body="I'll take this.", author="claimant", days_ago=10),
            _comment(
                body=invitation,
                author="maintainer",
                association="MEMBER",
                days_ago=invitation_days_ago,
            ),
        ],
    )

    result = service.evaluate(issue, _repository())

    assert ("claimed work" in " ".join(result.blockers)) is not reopened


@pytest.mark.parametrize(
    "body",
    [
        "Please hold off; no PR is needed until the design is settled.",
        "Please wait before opening a PR.",
        "Please pause work on this until the design is approved.",
        "We will not accept automated submissions.",
        "AI-generated PRs will be closed.",
        "No PR please.",
        "Contributions are on hold.",
        "Please avoid opening a PR.",
        "Please refrain from opening a PR.",
        "Hold off on implementing this.",
        "We aren't accepting PRs right now.",
        "We won't accept PRs right now.",
        "No need to open a PR.",
        "A PR is not needed.",
        "No PRs at this time.",
        "Contributions are no longer accepted.",
        "LLM-generated PRs will be closed.",
        "PRs will be closed.",
        "Please don\u2019t open a PR.",
        "We're not accepting PRs right now.",
        "Contributions are no longer accepted because the project is archived.",
        "We won\u2019t accept PRs.",
        "This project is not accepting contributions.",
        "We cannot accept PRs.",
        "Please hold off for now.",
        "Please wait until the design is approved.",
        "Please wait to open a PR.",
        "No more PRs.",
        "No PRs, please.",
        "PRs will be closed without review.",
        "Please do not work on this issue.",
        "You should not open a PR.",
        "Please hold off until next week.",
        "PRs will be closed \u2014 please use Discussions.",
        "Don't implement this.",
        "Let's not open a PR.",
        "No new PRs.",
        "PRs are not being accepted.",
        "The project is not accepting PRs.",
        "We have stopped accepting contributions.",
        "We are currently not accepting PRs.",
        "We are not currently accepting PRs.",
        "We do not currently accept pull requests.",
        "We are not accepting community contributions.",
        "Please hold off on this issue for now.",
        "Please hold off on a PR.",
        "Hold off on PRs.",
        "Do not open a PR yet.",
        "PRs are temporarily on hold.",
        "Do not open a PR for this issue.",
        "No PR is needed for this issue.",
        "Please do not submit patches for this issue.",
        "We are already working on this.",
        "External PRs are paused.",
        "Please wait for maintainer direction before starting work.",
        "The current policy says: \u201cDo not open a PR.\u201d",
        (
            "The old policy said: \u201cDo not open a PR.\u201d That was retired. "
            "The current policy says: \u201cDo not submit patches for this issue.\u201d"
        ),
    ],
)
def test_maintainer_stop_request_in_discussion_blocks_only_that_issue(tmp_path, body: str) -> None:  # type: ignore[no-untyped-def]
    config = AutocontributeConfig()
    service = DiscoveryService(config, FakeGitHub(), RunStore(tmp_path))  # type: ignore[arg-type]
    issue = _issue(
        comments=1,
        discussion=[
            _comment(
                body=body,
                author="maintainer",
                association="MEMBER",
            )
        ],
    )

    evaluation = service._assess(issue, _repository())

    assert not evaluation.eligibility.eligible
    assert "stop request" in evaluation.blocker_kinds
    assert (
        "a maintainer comment asks contributors to stop, hold off, or avoid a pull request: "
        "https://github.com/example/project/issues/42#maintainer-0"
    ) in evaluation.eligibility.blockers
    assert (evaluation.repository_hold is not None) is (
        body
        in {
            "We will not accept automated submissions.",
            "AI-generated PRs will be closed.",
            "LLM-generated PRs will be closed.",
        }
    )
    assert not service.store.circuit_breaker_status().is_tripped


def test_discussion_stop_is_reported_again_without_raising_on_every_discovery(
    tmp_path,
) -> None:  # type: ignore[no-untyped-def]
    stopped = _repository_issue(
        "example/project",
        41,
        comments=1,
        discussion=[
            _comment(
                body="Please hold off; no PR is needed until the design is settled.",
                author="maintainer",
                association="MEMBER",
            )
        ],
    )
    github = IsolationGitHub(
        {"example/project": [stopped, _repository_issue("example/project", 42)]}
    )
    service = DiscoveryService(  # type: ignore[arg-type]
        _discovery_config("example/project"), github, RunStore(tmp_path)
    )

    outcomes = [service.discover(), service.discover()]

    for outcome in outcomes:
        assert outcome.selection is not None
        assert outcome.selection[0].number == 42
        assert outcome.blocker_counts == [("stop request", 1)]
        assert outcome.skipped_repositories == ()
    assert not service.store.circuit_breaker_status().is_tripped


def test_stop_aimed_at_automation_holds_the_repository_for_the_run(tmp_path) -> None:  # type: ignore[no-untyped-def]
    held = [
        _repository_issue("example/project", 40),
        _repository_issue(
            "example/project",
            41,
            comments=1,
            discussion=[
                _comment(
                    body="AI-generated PRs will be closed.",
                    author="maintainer",
                    association="OWNER",
                )
            ],
        ),
        _repository_issue("example/project", 42),
    ]
    github = IsolationGitHub(
        {
            "example/project": held,
            "other/project": [_repository_issue("other/project", 7)],
        }
    )
    service = DiscoveryService(  # type: ignore[arg-type]
        _discovery_config("example/project", "other/project"), github, RunStore(tmp_path)
    )

    outcome = service.discover()

    assert outcome.selection is not None
    assert outcome.selection[0].reference == "other/project#7"
    assert outcome.skipped_repositories == (
        (
            "example/project",
            "a maintainer comment turns away automated or AI contributions: "
            "https://github.com/example/project/issues/42#maintainer-0",
        ),
    )
    assert [evaluation.issue.reference for evaluation in outcome.evaluations] == [
        "example/project#40",
        "example/project#41",
        "other/project#7",
    ]
    assert not service.store.circuit_breaker_status().is_tripped


def test_issue_description_stop_request_fails_closed_without_tripping_global_breaker(
    tmp_path,
) -> None:  # type: ignore[no-untyped-def]
    service = DiscoveryService(AutocontributeConfig(), FakeGitHub(), RunStore(tmp_path))  # type: ignore[arg-type]
    issue = _issue(
        body=(
            "This is a tracking issue with reproduction details and expected behavior. "
            "Do not open a pull request until the design is approved."
        )
    )

    result = service.evaluate(issue, _repository())

    assert not result.eligible
    assert "description asks contributors" in " ".join(result.blockers)
    assert not service.store.circuit_breaker_status().is_tripped


@pytest.mark.parametrize(
    "body",
    [
        (
            "The old policy said: \u201cDo not open a PR.\u201d That policy has been removed "
            "and pull requests are welcome."
        ),
        (
            "Our documentation no longer says: \u201cNo PR is needed for this issue.\u201d "
            "Contributions are welcome."
        ),
    ],
)
def test_retired_quoted_stop_policy_is_not_a_stop_request(
    tmp_path,
    body: str,
) -> None:  # type: ignore[no-untyped-def]
    service = DiscoveryService(AutocontributeConfig(), FakeGitHub(), RunStore(tmp_path))  # type: ignore[arg-type]
    issue = _issue(
        comments=1,
        discussion=[_comment(body=body, author="maintainer", association="MEMBER")],
    )

    result = service.evaluate(issue, _repository())

    assert result.eligible


@pytest.mark.parametrize(
    ("body", "author", "association"),
    [
        ("Please do not stop working on this fix.", "maintainer", "MEMBER"),
        ("This change should stop the parser from crashing.", "maintainer", "MEMBER"),
        ("Is this already being worked on?", "maintainer", "MEMBER"),
        (
            "Unless this is already being worked on, feel free to open a PR.",
            "maintainer",
            "MEMBER",
        ),
        (
            "This should stop automated retries from exhausting the rate limit.",
            "maintainer",
            "MEMBER",
        ),
        (
            "Automated inputs are not allowed to exceed 10 KiB.",
            "maintainer",
            "MEMBER",
        ),
        ("PRs are not accepted by this test helper.", "maintainer", "MEMBER"),
        ("Do not hesitate to open a PR.", "maintainer", "MEMBER"),
        ("Do not wait to open a PR.", "maintainer", "MEMBER"),
        ("Don't forget to submit a PR.", "maintainer", "MEMBER"),
        ("Do not close this PR.", "maintainer", "MEMBER"),
        ("Do not block pull requests from forks.", "maintainer", "MEMBER"),
        (
            "Wait for pull requests to finish CI before merging.",
            "maintainer",
            "MEMBER",
        ),
        ("Pull requests without tests are not accepted.", "maintainer", "MEMBER"),
        (
            "Contributions are not allowed to modify generated files.",
            "maintainer",
            "MEMBER",
        ),
        ("Wait before opening the output file.", "maintainer", "MEMBER"),
        ("Do not open a PR without tests.", "maintainer", "MEMBER"),
        (
            "Hold off on submitting the form until validation finishes.",
            "maintainer",
            "MEMBER",
        ),
        ("Please hold off on PRs without tests.", "maintainer", "MEMBER"),
        ("Do not submit PRs that lack a regression test.", "maintainer", "MEMBER"),
        ("Never open a PR against main; use develop.", "maintainer", "MEMBER"),
        (
            "Do not send automated PRs more than once a day.",
            "maintainer",
            "MEMBER",
        ),
        (
            "We are not currently accepting PRs that lack tests.",
            "maintainer",
            "MEMBER",
        ),
        (
            "PRs are temporarily on hold while this test fixture runs.",
            "maintainer",
            "MEMBER",
        ),
        ("This is not already being worked on.", "maintainer", "MEMBER"),
        (
            "This was already worked on in v1, but the regression is back and a new PR is welcome.",
            "maintainer",
            "MEMBER",
        ),
        ("Do not open a PR before running the tests.", "maintainer", "MEMBER"),
        ("Never submit a PR before filing an issue.", "maintainer", "MEMBER"),
        (
            "Do not create a PR because the test fixture already does so.",
            "maintainer",
            "MEMBER",
        ),
        ("Please hold off; no PR is needed.", "helper[bot]", "MEMBER"),
        ("Please hold off; no PR is needed.", "drive-by", "CONTRIBUTOR"),
    ],
)
def test_untrusted_or_negated_stop_text_is_not_a_stop_request(
    tmp_path, body: str, author: str, association: str
) -> None:  # type: ignore[no-untyped-def]
    service = DiscoveryService(AutocontributeConfig(), FakeGitHub(), RunStore(tmp_path))  # type: ignore[arg-type]
    issue = _issue(
        comments=1,
        discussion=[_comment(body=body, author=author, association=association)],
    )

    evaluation = service._assess(issue, _repository())

    assert "stop request" not in evaluation.blocker_kinds
    assert evaluation.repository_hold is None


def test_organization_ai_prohibition_fails_closed(tmp_path) -> None:
    github = PolicyGitHub(
        {
            ("example/project", "CONTRIBUTING.md"): "Ordinary contribution guidance.",
            ("example/.github", "AI_POLICY.md"): (
                "AI-assisted or generated code is not accepted and will be closed."
            ),
        }
    )
    service = DiscoveryService(AutocontributeConfig(), github, RunStore(tmp_path))  # type: ignore[arg-type]

    result = service.evaluate(_issue(), _repository())

    assert not result.eligible
    assert "prohibit AI-assisted" in " ".join(result.blockers)


def test_unresolved_dco_attestation_fails_closed(tmp_path) -> None:
    github = PolicyGitHub(
        {
            ("example/project", "CONTRIBUTING.md"): (
                "All commits must include a Signed-off-by line under the Developer Certificate "
                "of Origin."
            )
        }
    )
    service = DiscoveryService(AutocontributeConfig(), github, RunStore(tmp_path))  # type: ignore[arg-type]

    result = service.evaluate(_issue(), _repository())

    assert not result.eligible
    assert "CLA/DCO" in " ".join(result.blockers)


@pytest.mark.parametrize(
    ("path", "policy", "requirement"),
    [
        (
            "PULL_REQUEST_TEMPLATE.md",
            "- [ ] I have signed the Contributor License Agreement.",
            "cla",
        ),
        (
            "CONTRIBUTING.md",
            "Add a Signed-off-by: Name <email> line to every commit.",
            "dco",
        ),
        (
            "docs/DCO.md",
            "Developer's Certificate of Origin, Version 1.1",
            "dco",
        ),
    ],
)
def test_common_legal_policy_forms_fail_closed(
    tmp_path,
    path: str,
    policy: str,
    requirement: str,
) -> None:  # type: ignore[no-untyped-def]
    github = PolicyGitHub({("example/project", path): policy})

    result = DiscoveryService(  # type: ignore[arg-type]
        AutocontributeConfig(), github, RunStore(tmp_path)
    ).evaluate(_issue(), _repository())

    assert not result.eligible
    assert result.evidence["legal_requirements"] == requirement
    assert "CLA/DCO" in " ".join(result.blockers)


@pytest.mark.parametrize(
    "policy",
    [
        "This repository does not require a Contributor License Agreement.",
        "Signed-off-by trailers are not required for contributions.",
    ],
)
def test_unambiguously_negated_legal_reference_does_not_create_requirement(
    tmp_path,
    policy: str,
) -> None:  # type: ignore[no-untyped-def]
    github = PolicyGitHub({("example/project", "CONTRIBUTING.md"): policy})

    result = DiscoveryService(  # type: ignore[arg-type]
        AutocontributeConfig(), github, RunStore(tmp_path)
    ).evaluate(_issue(), _repository())

    assert result.eligible
    assert result.evidence["legal_requirements"] == "none"


def test_unambiguously_negated_named_legal_policy_does_not_create_requirement(
    tmp_path,
) -> None:  # type: ignore[no-untyped-def]
    github = PolicyGitHub(
        {
            ("example/project", "CONTRIBUTING.md"): "Contribution guidelines.",
            ("example/project", "CLA.md"): "The CLA is no longer required.",
        }
    )

    result = DiscoveryService(  # type: ignore[arg-type]
        AutocontributeConfig(), github, RunStore(tmp_path)
    ).evaluate(_issue(), _repository())

    assert result.eligible
    assert result.evidence["legal_requirements"] == "none"


def test_ambiguous_legal_reference_fails_closed_for_personal_review(tmp_path) -> None:
    github = PolicyGitHub(
        {
            ("example/project", "CONTRIBUTING.md"): (
                "Before participating, consult the Contributor License Agreement policy."
            )
        }
    )

    result = DiscoveryService(  # type: ignore[arg-type]
        AutocontributeConfig(), github, RunStore(tmp_path)
    ).evaluate(_issue(), _repository())

    assert not result.eligible
    assert result.evidence["legal_requirements"] == "cla"
    assert "CLA/DCO" in " ".join(result.blockers)


def test_negation_for_one_legal_term_does_not_suppress_another(tmp_path) -> None:
    github = PolicyGitHub(
        {
            ("example/project", "CONTRIBUTING.md"): (
                "No CLA; consult the DCO requirements before contributing."
            )
        }
    )

    result = DiscoveryService(  # type: ignore[arg-type]
        AutocontributeConfig(), github, RunStore(tmp_path)
    ).evaluate(_issue(), _repository())

    assert not result.eligible
    assert result.evidence["legal_requirements"] == "dco"


@pytest.mark.parametrize(
    ("path", "contents", "requirement"),
    [
        (".github/dco.yml", "enabled: true", "dco"),
        (".github/cla.yaml", "enabled: true", "cla"),
        ("DCO", "Version 1.1", "dco"),
        (".clabot", '{"contributors": []}', "cla"),
    ],
)
def test_legal_configuration_and_extensionless_policy_paths_are_inventoried(
    tmp_path,
    path: str,
    contents: str,
    requirement: str,
) -> None:  # type: ignore[no-untyped-def]
    class InventoryLegalGitHub(PolicyGitHub):
        def list_repository_files(
            self,
            repository: str,
            *,
            ref: str,
            max_files: int,
        ) -> list[str]:
            del ref, max_files
            return ["CONTRIBUTING.md", path] if repository == "example/project" else []

    github = InventoryLegalGitHub(
        {
            ("example/project", "CONTRIBUTING.md"): "Contribution guidelines.",
            ("example/project", path): contents,
        }
    )

    result = DiscoveryService(  # type: ignore[arg-type]
        AutocontributeConfig(), github, RunStore(tmp_path)
    ).evaluate(_issue(), _repository())

    assert not result.eligible
    assert result.evidence["legal_requirements"] == requirement
    assert "CLA/DCO" in " ".join(result.blockers)


def test_exact_repository_bound_cla_attestation_unblocks_snapshot(tmp_path) -> None:
    github = PolicyGitHub(
        {
            ("example/project", "CONTRIBUTING.md"): (
                "Contributors must complete our Contributor License Agreement before opening a PR."
            )
        }
    )
    snapshot = DiscoveryService(  # type: ignore[arg-type]
        AutocontributeConfig(), github, RunStore(tmp_path / "preview")
    ).policy_snapshot(_repository(), repository_ref=REPOSITORY_REF)
    config = _legal_config(snapshot)

    result = DiscoveryService(config, github, RunStore(tmp_path / "run")).evaluate(  # type: ignore[arg-type]
        _issue(), _repository(), repository_ref=REPOSITORY_REF
    )

    assert result.eligible
    assert result.evidence[LEGAL_POLICY_EVIDENCE_KEY] == snapshot.legal_policy_sha256
    assert len(result.evidence[LEGAL_ATTESTATION_EVIDENCE_KEY]) == 64


def test_attestation_does_not_cross_repository_boundary(tmp_path) -> None:
    github = PolicyGitHub(
        {
            ("example/project", "CONTRIBUTING.md"): (
                "Contributors must complete our Contributor License Agreement before opening a PR."
            )
        }
    )
    snapshot = DiscoveryService(  # type: ignore[arg-type]
        AutocontributeConfig(), github, RunStore(tmp_path / "preview")
    ).policy_snapshot(_repository(), repository_ref=REPOSITORY_REF)
    config = _legal_config(snapshot, repository="other/project")

    result = DiscoveryService(config, github, RunStore(tmp_path / "run")).evaluate(  # type: ignore[arg-type]
        _issue(), _repository(), repository_ref=REPOSITORY_REF
    )

    assert not result.eligible
    assert "no attestation is configured" in " ".join(result.blockers)


def test_legal_attestation_survives_unrelated_repository_commit(tmp_path) -> None:
    github = PolicyGitHub(
        {
            ("example/project", "CONTRIBUTING.md"): (
                "Contributors must complete our Contributor License Agreement before opening a PR."
            )
        }
    )
    original = DiscoveryService(  # type: ignore[arg-type]
        AutocontributeConfig(), github, RunStore(tmp_path / "preview")
    ).policy_snapshot(_repository(), repository_ref=REPOSITORY_REF)
    config = _legal_config(original)
    new_ref = "c" * 40

    result = DiscoveryService(config, github, RunStore(tmp_path / "run")).evaluate(  # type: ignore[arg-type]
        _issue(), _repository(), repository_ref=new_ref
    )

    assert result.eligible
    assert result.evidence[LEGAL_POLICY_EVIDENCE_KEY] == original.legal_policy_sha256
    assert result.evidence[POLICY_SOURCES_EVIDENCE_KEY] != original.policy_sources_sha256


def test_legal_policy_content_change_invalidates_attestation(tmp_path) -> None:
    files = {
        ("example/project", "CONTRIBUTING.md"): (
            "Contributors must complete our Contributor License Agreement before opening a PR."
        )
    }
    github = PolicyGitHub(files)
    snapshot = DiscoveryService(  # type: ignore[arg-type]
        AutocontributeConfig(), github, RunStore(tmp_path / "preview")
    ).policy_snapshot(_repository(), repository_ref=REPOSITORY_REF)
    config = _legal_config(snapshot)
    files[("example/project", "CONTRIBUTING.md")] += " Organization approval is also required."

    result = DiscoveryService(config, github, RunStore(tmp_path / "run")).evaluate(  # type: ignore[arg-type]
        _issue(), _repository(), repository_ref="c" * 40
    )

    assert not result.eligible
    assert "inventories or contents changed" in " ".join(result.blockers)


def test_benign_legal_policy_inventory_change_invalidates_attestation(tmp_path) -> None:
    class InventoryLegalGitHub(PolicyGitHub):
        def __init__(self, files: dict[tuple[str, str], str]) -> None:
            super().__init__(files)
            self.repository_paths = ["CONTRIBUTING.md"]

        def list_repository_files(
            self,
            repository: str,
            *,
            ref: str,
            max_files: int,
        ) -> list[str]:
            del ref, max_files
            return list(self.repository_paths) if repository == "example/project" else []

    github = InventoryLegalGitHub(
        {
            ("example/project", "CONTRIBUTING.md"): (
                "Contributors must complete our Contributor License Agreement before opening a PR."
            ),
            ("example/project", "docs/AI_POLICY.md"): "AI contributions receive normal review.",
        }
    )
    snapshot = DiscoveryService(  # type: ignore[arg-type]
        AutocontributeConfig(), github, RunStore(tmp_path / "preview")
    ).policy_snapshot(_repository(), repository_ref=REPOSITORY_REF)
    config = _legal_config(snapshot)
    github.repository_paths.append("docs/AI_POLICY.md")

    result = DiscoveryService(config, github, RunStore(tmp_path / "run")).evaluate(  # type: ignore[arg-type]
        _issue(), _repository(), repository_ref="c" * 40
    )

    assert not result.eligible
    assert "inventories or contents changed" in " ".join(result.blockers)


def test_organization_policy_repository_appearance_invalidates_absence_attestation(
    tmp_path,
) -> None:  # type: ignore[no-untyped-def]
    class MutableOrganizationGitHub(PolicyGitHub):
        organization_ref: str | None = None

        def default_branch_sha_if_exists(self, repository: str) -> str | None:
            del repository
            return self.organization_ref

    github = MutableOrganizationGitHub(
        {
            ("example/project", "CONTRIBUTING.md"): (
                "Contributors must complete our Contributor License Agreement before opening a PR."
            )
        }
    )
    snapshot = DiscoveryService(  # type: ignore[arg-type]
        AutocontributeConfig(), github, RunStore(tmp_path / "preview")
    ).policy_snapshot(_repository(), repository_ref=REPOSITORY_REF)
    assert snapshot.organization_ref_evidence == "absent"
    config = _legal_config(snapshot)
    github.organization_ref = ORGANIZATION_REF

    result = DiscoveryService(config, github, RunStore(tmp_path / "run")).evaluate(  # type: ignore[arg-type]
        _issue(), _repository(), repository_ref="c" * 40
    )

    assert not result.eligible
    assert "inventories or contents changed" in " ".join(result.blockers)


def test_dco_authorization_produces_and_revalidates_exact_signoff(tmp_path) -> None:
    github = PolicyGitHub(
        {
            ("example/project", "CONTRIBUTING.md"): (
                "All commits must include a Signed-off-by line under the Developer Certificate "
                "of Origin."
            )
        }
    )
    snapshot = DiscoveryService(  # type: ignore[arg-type]
        AutocontributeConfig(), github, RunStore(tmp_path / "preview")
    ).policy_snapshot(_repository(), repository_ref=REPOSITORY_REF)
    config = _legal_config(snapshot)
    result = DiscoveryService(config, github, RunStore(tmp_path / "run")).evaluate(  # type: ignore[arg-type]
        _issue(), _repository(), repository_ref=REPOSITORY_REF
    )

    message = apply_legal_commit_message(
        config,
        result,
        "example/project",
        "Fix documented parser boundary",
    )
    validate_legal_publication(
        config,
        result,
        repository="example/project",
        publishing_login="octocat",
        commit_message=message,
    )

    assert result.eligible
    assert message == (
        "Fix documented parser boundary\n\nSigned-off-by: Example Signer <signer@example.invalid>"
    )
    with pytest.raises(PolicyError, match="publishing account"):
        validate_legal_publication(
            config,
            result,
            repository="example/project",
            publishing_login="different-user",
            commit_message=message,
        )


def test_dco_authorization_rejects_model_supplied_legal_trailer(tmp_path) -> None:
    github = PolicyGitHub(
        {
            ("example/project", "CONTRIBUTING.md"): (
                "All commits must include a Signed-off-by line under the DCO."
            )
        }
    )
    snapshot = DiscoveryService(  # type: ignore[arg-type]
        AutocontributeConfig(), github, RunStore(tmp_path / "preview")
    ).policy_snapshot(_repository(), repository_ref=REPOSITORY_REF)
    config = _legal_config(snapshot)
    result = DiscoveryService(config, github, RunStore(tmp_path / "run")).evaluate(  # type: ignore[arg-type]
        _issue(), _repository(), repository_ref=REPOSITORY_REF
    )

    with pytest.raises(PolicyError, match="cannot safely supply"):
        apply_legal_commit_message(
            config,
            result,
            "example/project",
            "Fix parser\n\nSigned-off-by: Invented Person <invented@example.invalid>",
        )


@pytest.mark.parametrize(
    "commit_message",
    [
        "Fix parser\n\nSigned-off-by: Invented Person <invented@example.invalid>",
        "Fix parser Signed-off-by : Invented Person <invented@example.invalid>",
        "Fix parser\nwith an unauthorized body",
    ],
)
def test_preparation_rejects_model_supplied_multiline_or_signoff_without_dco(
    tmp_path,
    commit_message: str,
) -> None:  # type: ignore[no-untyped-def]
    github = PolicyGitHub({("example/project", "CONTRIBUTING.md"): "Contribution guidelines"})
    config = AutocontributeConfig()
    result = DiscoveryService(config, github, RunStore(tmp_path)).evaluate(  # type: ignore[arg-type]
        _issue(), _repository(), repository_ref=REPOSITORY_REF
    )

    with pytest.raises(PolicyError, match="cannot safely supply"):
        apply_legal_commit_message(
            config,
            result,
            "example/project",
            commit_message,
        )


def test_organization_automation_prohibition_fails_closed(tmp_path) -> None:
    github = PolicyGitHub(
        {
            ("example/project", "CONTRIBUTING.md"): "Ordinary contribution guidance.",
            ("example/.github", "AI-CONTRIBUTIONS.md"): (
                "Automated contributions are not allowed and will be closed."
            ),
        }
    )
    service = DiscoveryService(AutocontributeConfig(), github, RunStore(tmp_path))  # type: ignore[arg-type]

    result = service.evaluate(_issue(), _repository())

    assert not result.eligible
    assert "automated" in " ".join(result.blockers)


def test_organization_dco_attestation_fails_closed(tmp_path) -> None:
    github = PolicyGitHub(
        {
            ("example/project", "CONTRIBUTING.md"): "Ordinary contribution guidance.",
            ("example/.github", "DCO.md"): (
                "By submitting a contribution, you agree to the Developer Certificate of Origin."
            ),
        }
    )
    service = DiscoveryService(AutocontributeConfig(), github, RunStore(tmp_path))  # type: ignore[arg-type]

    result = service.evaluate(_issue(), _repository())

    assert not result.eligible
    assert "CLA/DCO" in " ".join(result.blockers)


def test_policy_source_fingerprint_detects_benign_organization_policy_change(
    tmp_path,
) -> None:  # type: ignore[no-untyped-def]
    files = {
        ("example/project", "CONTRIBUTING.md"): "Ordinary contribution guidance.",
        ("example/.github", "AI_POLICY.md"): "AI contributions receive careful review.",
    }
    github = PolicyGitHub(files)

    original = DiscoveryService(AutocontributeConfig(), github, RunStore(tmp_path)).evaluate(  # type: ignore[arg-type]
        _issue(), _repository()
    )
    files[("example/.github", "AI_POLICY.md")] = (
        "AI contributions receive careful review and must include tests."
    )
    current = DiscoveryService(AutocontributeConfig(), github, RunStore(tmp_path)).evaluate(  # type: ignore[arg-type]
        _issue(), _repository()
    )

    assert original.eligible
    assert current.eligible
    assert len(original.evidence[POLICY_SOURCES_EVIDENCE_KEY]) == 64
    assert (
        original.evidence[POLICY_SOURCES_EVIDENCE_KEY]
        != current.evidence[POLICY_SOURCES_EVIDENCE_KEY]
    )


@pytest.mark.parametrize(
    ("files", "blocker"),
    [
        (
            {
                ("example/project", "CONTRIBUTING.md"): "Ordinary guidance.",
                ("example/project", "docs/CONTRIBUTION_POLICY.md"): (
                    "We reject AI-generated contributions."
                ),
            },
            "AI-assisted",
        ),
        (
            {
                ("example/project", "CONTRIBUTING.md"): "Ordinary guidance.",
                ("example/.github", "PULL_REQUEST_TEMPLATE.md"): (
                    "Bot-authored pull requests are forbidden."
                ),
            },
            "automated",
        ),
    ],
)
def test_expanded_policy_paths_and_prohibition_phrases_fail_closed(
    tmp_path, files: dict[tuple[str, str], str], blocker: str
) -> None:  # type: ignore[no-untyped-def]
    service = DiscoveryService(  # type: ignore[arg-type]
        AutocontributeConfig(), PolicyGitHub(files), RunStore(tmp_path)
    )

    result = service.evaluate(_issue(), _repository())

    assert not result.eligible
    assert blocker in " ".join(result.blockers)


def test_organization_default_contribution_guidance_and_template_are_evidence(tmp_path) -> None:
    github = PolicyGitHub(
        {
            ("example/.github", "CONTRIBUTING.md"): "Organization contribution guidance.",
            ("example/.github", "PULL_REQUEST_TEMPLATE.md"): "## Summary\n",
        }
    )
    service = DiscoveryService(AutocontributeConfig(), github, RunStore(tmp_path))  # type: ignore[arg-type]

    result = service.evaluate(_issue(), _repository())

    assert result.eligible
    assert service.organization_pull_request_templates("example/project") == {
        "PULL_REQUEST_TEMPLATE.md": "## Summary\n"
    }


def test_present_but_unreadable_policy_file_stops_discovery(tmp_path) -> None:
    class UnreadablePolicyGitHub(FakeGitHub):
        def get_file(
            self,
            repository: str,
            path: str,
            *,
            ref: str,
            max_bytes: int = 1_000_000,
        ) -> str | None:
            if path == "SECURITY.md":
                raise GitHubError("policy file could not be decoded safely")
            return super().get_file(
                repository,
                path,
                ref=ref,
                max_bytes=max_bytes,
            )

        def list_repository_files(self, repository: str, *, ref: str, max_files: int) -> list[str]:
            del repository, ref, max_files
            return ["CONTRIBUTING.md", "SECURITY.md"]

    service = DiscoveryService(  # type: ignore[arg-type]
        AutocontributeConfig(), UnreadablePolicyGitHub(), RunStore(tmp_path)
    )

    with pytest.raises(GitHubError, match="could not be decoded"):
        service.evaluate(_issue(), _repository())


def test_repository_inventory_discovers_named_organization_templates_and_alt_policies(
    tmp_path,
) -> None:  # type: ignore[no-untyped-def]
    class InventoryPolicyGitHub(PolicyGitHub):
        def list_repository_files(
            self,
            repository: str,
            *,
            ref: str,
            max_files: int,
        ) -> list[str]:
            del ref, max_files
            if repository == "example/project":
                return ["CONTRIBUTING.md", "governance/ai-generated-code.md"]
            if repository == "example/.github":
                return [".github/PULL_REQUEST_TEMPLATE/verification.md"]
            return []

    github = InventoryPolicyGitHub(
        {
            ("example/project", "CONTRIBUTING.md"): "Ordinary guidance.",
            ("example/project", "governance/ai-generated-code.md"): (
                "We reject AI-generated contributions."
            ),
            ("example/.github", ".github/PULL_REQUEST_TEMPLATE/verification.md"): (
                "## Verification\n"
            ),
        }
    )
    service = DiscoveryService(AutocontributeConfig(), github, RunStore(tmp_path))  # type: ignore[arg-type]

    result = service.evaluate(_issue(), _repository())

    assert not result.eligible
    assert "AI-assisted" in " ".join(result.blockers)
    assert service.organization_pull_request_templates("example/project") == {
        ".github/PULL_REQUEST_TEMPLATE/verification.md": "## Verification\n"
    }


def test_repository_inventory_rejects_too_many_matching_policy_files(tmp_path) -> None:
    class ExcessivePolicyInventoryGitHub(PolicyGitHub):
        def list_repository_files(
            self,
            repository: str,
            *,
            ref: str,
            max_files: int,
        ) -> list[str]:
            del repository, ref, max_files
            return [
                f"docs/contributing-{index}.md"
                for index in range(MAX_POLICY_FILES_PER_REPOSITORY + 1)
            ]

    service = DiscoveryService(  # type: ignore[arg-type]
        AutocontributeConfig(),
        ExcessivePolicyInventoryGitHub({}),
        RunStore(tmp_path),
    )

    with pytest.raises(GitHubError, match="more than 128 policy files"):
        service.evaluate(_issue(), _repository())


def test_policy_reader_rechecks_size_when_github_adapter_ignores_limit(tmp_path) -> None:
    class OversizedPolicyGitHub(PolicyGitHub):
        def get_file(
            self,
            repository: str,
            path: str,
            *,
            ref: str,
            max_bytes: int = 1_000_000,
        ) -> str | None:
            del repository, path, ref, max_bytes
            return "x" * (MAX_POLICY_FILE_BYTES + 1)

        def list_repository_files(self, repository: str, *, ref: str, max_files: int) -> list[str]:
            del repository, ref, max_files
            return ["CONTRIBUTING.md"]

    service = DiscoveryService(  # type: ignore[arg-type]
        AutocontributeConfig(), OversizedPolicyGitHub({}), RunStore(tmp_path)
    )

    with pytest.raises(GitHubError, match="policy file exceeds the 256000-byte limit"):
        service.evaluate(_issue(), _repository())


def test_policy_fingerprint_rejects_aggregate_byte_overflow(tmp_path) -> None:
    policy_paths = ["CONTRIBUTING.md", *[f"docs/ai-policy-{index}.md" for index in range(15)]]

    class AggregatePolicyGitHub(PolicyGitHub):
        def list_repository_files(
            self,
            repository: str,
            *,
            ref: str,
            max_files: int,
        ) -> list[str]:
            del ref, max_files
            return policy_paths if repository == "example/project" else []

        def get_file(
            self,
            repository: str,
            path: str,
            *,
            ref: str,
            max_bytes: int = 1_000_000,
        ) -> str | None:
            del ref, max_bytes
            if repository == "example/project" and path in policy_paths:
                return "x" * MAX_POLICY_FILE_BYTES
            return None

    service = DiscoveryService(  # type: ignore[arg-type]
        AutocontributeConfig(), AggregatePolicyGitHub({}), RunStore(tmp_path)
    )

    with pytest.raises(
        GitHubError,
        match=rf"policy evidence exceeds the {MAX_POLICY_TOTAL_BYTES}-byte limit",
    ):
        service.evaluate(_issue(), _repository())


def test_repository_and_organization_policy_reads_use_their_pinned_shas(tmp_path) -> None:
    class RecordingPolicyGitHub(PolicyGitHub):
        def __init__(self) -> None:
            super().__init__(
                {
                    ("example/project", "CONTRIBUTING.md"): "Ordinary guidance.",
                    ("example/.github", "AI_POLICY.md"): "AI contributions are reviewed.",
                }
            )
            self.tree_reads: list[tuple[str, str]] = []
            self.content_reads: list[tuple[str, str, str]] = []

        def list_repository_files(
            self,
            repository: str,
            *,
            ref: str,
            max_files: int,
        ) -> list[str]:
            del max_files
            self.tree_reads.append((repository, ref))
            if repository == "example/project":
                return ["CONTRIBUTING.md"]
            return ["AI_POLICY.md"]

        def get_file(
            self,
            repository: str,
            path: str,
            *,
            ref: str,
            max_bytes: int = 1_000_000,
        ) -> str | None:
            del max_bytes
            self.content_reads.append((repository, path, ref))
            return self.files.get((repository, path))

    github = RecordingPolicyGitHub()
    result = DiscoveryService(  # type: ignore[arg-type]
        AutocontributeConfig(), github, RunStore(tmp_path)
    ).evaluate(_issue(), _repository())

    assert result.eligible
    assert github.tree_reads == [
        ("example/project", REPOSITORY_REF),
        ("example/.github", ORGANIZATION_REF),
    ]
    assert github.content_reads == [
        ("example/project", "CONTRIBUTING.md", REPOSITORY_REF),
        ("example/.github", "AI_POLICY.md", ORGANIZATION_REF),
    ]


def test_policy_fingerprint_changes_when_immutable_organization_ref_changes(tmp_path) -> None:
    class RefPolicyGitHub(PolicyGitHub):
        def __init__(self, organization_ref: str) -> None:
            super().__init__(
                {
                    ("example/project", "CONTRIBUTING.md"): "Ordinary guidance.",
                    ("example/.github", "AI_POLICY.md"): "AI contributions are reviewed.",
                }
            )
            self.organization_ref = organization_ref

        def default_branch_sha_if_exists(self, repository: str) -> str | None:
            del repository
            return self.organization_ref

    first = DiscoveryService(  # type: ignore[arg-type]
        AutocontributeConfig(), RefPolicyGitHub("b" * 40), RunStore(tmp_path / "first")
    ).evaluate(_issue(), _repository())
    second = DiscoveryService(  # type: ignore[arg-type]
        AutocontributeConfig(), RefPolicyGitHub("c" * 40), RunStore(tmp_path / "second")
    ).evaluate(_issue(), _repository())

    assert first.eligible
    assert second.eligible
    assert (
        first.evidence[POLICY_SOURCES_EVIDENCE_KEY] != second.evidence[POLICY_SOURCES_EVIDENCE_KEY]
    )
