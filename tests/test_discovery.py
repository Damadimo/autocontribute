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
    apply_legal_commit_message,
    parse_issue_reference,
    validate_legal_publication,
)
from autocontribute.domain import (
    EligibilityResult,
    IssueCandidate,
    IssueComment,
    RepositoryInfo,
    RunStatus,
)
from autocontribute.exceptions import GitHubError, PolicyError, StateError
from autocontribute.store import (
    CandidateAttemptDisposition,
    CandidateAttemptState,
    RunStore,
)

REPOSITORY_REF = "a" * 40
ORGANIZATION_REF = "b" * 40


class FakeGitHub:
    def search_competing_pull_requests(self, repository: str, issue_number: int) -> list[str]:
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


class CandidateDiscoveryGitHub(FakeGitHub):
    def __init__(self, issues: list[IssueCandidate]) -> None:
        self.issues = {issue.number: issue for issue in issues}
        self.fetched: list[int] = []

    def get_repository(self, full_name: str) -> RepositoryInfo:
        del full_name
        return _repository()

    def search_issues(
        self,
        repository: str,
        *,
        labels: list[str],
        limit: int,
    ) -> list[IssueCandidate]:
        del repository, labels
        return list(self.issues.values())[:limit]

    def get_issue(self, repository: str, number: int) -> IssueCandidate:
        del repository
        self.fetched.append(number)
        return self.issues[number]


class DispositionStore:
    def __init__(self, states: dict[int, CandidateAttemptState]) -> None:
        self.states = states

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
        "labels": ["help wanted", "bug", "good first issue"],
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
    assert result.score >= config.quality.min_candidate_score


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
    issue = _issue(labels=["help wanted", "bug", "good first issue", label])

    result = service.evaluate(issue, _repository())

    assert not result.eligible
    assert "private handling" in " ".join(result.blockers)


def test_explicit_security_issue_override_applies_to_text_and_labels(tmp_path) -> None:
    config = AutocontributeConfig.model_validate({"policy": {"allow_security_issues": True}})
    service = DiscoveryService(config, FakeGitHub(), RunStore(tmp_path))  # type: ignore[arg-type]
    issue = _issue(
        title="Denial of service in the parser",
        labels=["help wanted", "bug", "good first issue", "vulnerability"],
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


def test_discovery_continues_past_suppressed_revision_without_spending_candidate_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _issue(number=41, title="Previously rejected candidate")
    second = _issue(number=42, title="Fresh candidate")
    third = _issue(number=43, title="Candidate beyond the configured evaluation budget")
    github = CandidateDiscoveryGitHub([first, second, third])
    store = DispositionStore({41: CandidateAttemptState.SUPPRESSED})
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "budget": {"max_candidates_per_run": 1},
            "validation": {"required_commands": {"example/project": ["python -m pytest"]}},
        }
    )
    service = DiscoveryService(config, github, store)  # type: ignore[arg-type]
    evaluated: list[int] = []

    def eligible(
        issue: IssueCandidate,
        repository: RepositoryInfo,
        **_: object,
    ) -> EligibilityResult:
        del repository
        evaluated.append(issue.number)
        return EligibilityResult(eligible=True, score=90, evidence={}, blockers=[])

    monkeypatch.setattr(service, "evaluate", eligible)

    outcome = service.discover()

    assert outcome.selection is not None
    assert outcome.selection[0].number == 42
    assert outcome.suppressed_candidates == 1
    assert evaluated == [42]
    assert github.fetched == [41, 42]


def test_discovery_exhaustion_distinguishes_suppressed_active_and_ineligible_candidates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    issues = [_issue(number=number) for number in (41, 42, 43)]
    github = CandidateDiscoveryGitHub(issues)
    store = DispositionStore(
        {
            41: CandidateAttemptState.SUPPRESSED,
            42: CandidateAttemptState.ACTIVE,
        }
    )
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "validation": {"required_commands": {"example/project": ["python -m pytest"]}},
        }
    )
    service = DiscoveryService(config, github, store)  # type: ignore[arg-type]
    monkeypatch.setattr(
        service,
        "evaluate",
        lambda *_args, **_kwargs: EligibilityResult(
            eligible=False,
            score=20,
            evidence={},
            blockers=["fixture"],
        ),
    )

    outcome = service.discover()

    assert outcome.selection is None
    assert outcome.active_candidates == 1
    assert outcome.suppressed_candidates == 1
    assert outcome.ineligible_candidates == 1
    assert outcome.no_candidate_reason == (
        "No candidate is currently available: 1 unchanged issue revision was deferred after a "
        "prior skipped, rejected, or cancelled run; 1 candidate already has an active run; "
        "1 candidate failed deterministic discovery gates."
    )


def test_empty_discovery_preserves_generic_no_candidate_reason() -> None:
    outcome = DiscoveryOutcome(selection=None)

    assert outcome.no_candidate_reason == "No candidate passed deterministic discovery gates."


def _comment(*, body: str, author: str = "contributor", association: str = "NONE") -> IssueComment:
    now = datetime.now(UTC)
    return IssueComment(
        author=author,
        author_association=association,
        body=body,
        html_url=f"https://github.com/example/project/issues/42#{author}",
        created_at=now,
        updated_at=now,
    )


@pytest.mark.parametrize(
    "claim",
    [
        "I'm working on this and will open a PR shortly.",
        "I would like to work on this.",
        "I'd like to work on this as a follow up.",
        "I'd loke to worn on this as a follow up.",
        "I want to take this.",
    ],
)
def test_claimed_work_in_discussion_fails_closed(tmp_path, claim: str) -> None:
    config = AutocontributeConfig()
    service = DiscoveryService(config, FakeGitHub(), RunStore(tmp_path))  # type: ignore[arg-type]
    issue = _issue(
        comments=1,
        discussion=[_comment(body=claim)],
    )

    result = service.evaluate(issue, _repository())

    assert not result.eligible
    assert "claimed work" in " ".join(result.blockers)


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
def test_maintainer_stop_request_in_discussion_fails_closed(tmp_path, body: str) -> None:
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

    with pytest.raises(StateError, match="global circuit breaker"):
        service.evaluate(issue, _repository())

    status = service.store.circuit_breaker_status()
    assert status.is_tripped
    assert status.source == "github_issue_discussion:example/project#42"
    assert status.trigger_hash is not None


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
def test_retired_quoted_stop_policy_does_not_trip_global_breaker(
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
    assert not service.store.circuit_breaker_status().is_tripped


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
def test_untrusted_or_negated_stop_text_does_not_trip_global_breaker(
    tmp_path, body: str, author: str, association: str
) -> None:  # type: ignore[no-untyped-def]
    service = DiscoveryService(AutocontributeConfig(), FakeGitHub(), RunStore(tmp_path))  # type: ignore[arg-type]
    issue = _issue(
        comments=1,
        discussion=[_comment(body=body, author=author, association=association)],
    )

    service.evaluate(issue, _repository())

    assert not service.store.circuit_breaker_status().is_tripped


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
