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
    DiscoveryService,
    PolicySnapshot,
    apply_legal_commit_message,
    parse_issue_reference,
    validate_legal_publication,
)
from autocontribute.domain import IssueCandidate, IssueComment, RepositoryInfo
from autocontribute.exceptions import GitHubError, PolicyError, StateError
from autocontribute.store import RunStore

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


def test_claimed_work_in_discussion_fails_closed(tmp_path) -> None:
    config = AutocontributeConfig()
    service = DiscoveryService(config, FakeGitHub(), RunStore(tmp_path))  # type: ignore[arg-type]
    issue = _issue(
        comments=1,
        discussion=[_comment(body="I'm working on this and will open a PR shortly.")],
    )

    result = service.evaluate(issue, _repository())

    assert not result.eligible
    assert "claimed work" in " ".join(result.blockers)


def test_maintainer_stop_request_in_discussion_fails_closed(tmp_path) -> None:
    config = AutocontributeConfig()
    service = DiscoveryService(config, FakeGitHub(), RunStore(tmp_path))  # type: ignore[arg-type]
    issue = _issue(
        comments=1,
        discussion=[
            _comment(
                body="Please hold off; no PR is needed until the design is settled.",
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


@pytest.mark.parametrize(
    ("body", "author", "association"),
    [
        ("Please do not stop working on this fix.", "maintainer", "MEMBER"),
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
