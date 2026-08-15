"""Human approval and the only code path authorized to mutate GitHub."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import subprocess
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from autocontribute.approval import (
    ApprovalReview,
    build_approval_manifest,
    create_approval,
    manifest_fingerprint,
    validate_approval,
)
from autocontribute.config import AutocontributeConfig, auto_publish_opt_in_enabled
from autocontribute.coordination import (
    PUBLICATION_HEARTBEAT_INTERVAL,
    PUBLICATION_LEASE_NAME,
    PUBLICATION_LEASE_TTL,
    LeaseHeartbeatGuard,
)
from autocontribute.deployment import validate_deployment_fingerprint
from autocontribute.discovery import (
    LEGAL_ATTESTATION_EVIDENCE_KEY,
    LEGAL_POLICY_EVIDENCE_KEY,
    LEGAL_REQUIREMENTS_EVIDENCE_KEY,
    POLICY_ORGANIZATION_REF_EVIDENCE_KEY,
    POLICY_SOURCES_EVIDENCE_KEY,
    DiscoveryService,
    validate_legal_publication,
)
from autocontribute.domain import EligibilityResult, IssueCandidate, RunManifest, RunStatus
from autocontribute.exceptions import (
    AutomaticRolloutBlocked,
    GitHubError,
    GitHubRequestNotSentError,
    GitHubSafetyError,
    PolicyError,
    PublicationResumeRequired,
    RepositoryError,
    StateError,
)
from autocontribute.github import GitHubClient, PullRequestDetails, RepositoryIdentity
from autocontribute.github_origin import canonical_api_origin, git_push_url
from autocontribute.lifecycle import LifecycleObserver, parse_pull_request_url
from autocontribute.pr_template import visible_markdown
from autocontribute.preparation import (
    validate_preparation_config_fingerprint,
    validate_preparation_fingerprint,
    validate_validation_artifact,
)
from autocontribute.redaction import contains_credential_material, redact_text
from autocontribute.repository import RepositoryWorkspace
from autocontribute.rollout import RolloutGate, RolloutSummary
from autocontribute.store import PublicationGateHold, RunStore
from autocontribute.upstream_outcomes import (
    ExactHumanApproval,
    UpstreamPublicationScope,
    classify_exact_human_approval,
)

_SAFE_SLUG = re.compile(r"[^a-z0-9-]+")
_GIT_SHA = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_SECRET = re.compile(
    r"(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)
_GITHUB_LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")


@dataclass(frozen=True, slots=True)
class _PublicationContext:
    login: str
    api_origin: str
    author_name: str
    author_email: str
    committer_name: str
    committer_email: str
    draft: bool
    ready_for_review: bool


def has_visible_disclosure(body: str, disclosure: str) -> bool:
    """Return whether the exact disclosure appears in rendered prose."""

    return disclosure in visible_markdown(body)


def validate_publication_text(
    manifest: RunManifest,
    *,
    required_disclosure: str | None = None,
) -> None:
    proposal = manifest.proposal
    if proposal is None:
        raise PolicyError("Run has no publication proposal")
    values = {
        "commit message": proposal.commit_message,
        "pull request title": proposal.pull_request_title,
        "pull request body": proposal.pull_request_body,
    }
    limits = {"commit message": 750, "pull request title": 200, "pull request body": 50_000}
    for name, value in values.items():
        if not value.strip():
            raise PolicyError(f"{name} cannot be blank")
        if len(value) > limits[name]:
            raise PolicyError(f"{name} exceeds the {limits[name]}-character limit")
        if _SECRET.search(value):
            raise PolicyError(f"{name} appears to contain a credential")
        if "@everyone" in value.casefold() or "@here" in value.casefold():
            raise PolicyError(f"{name} contains a broadcast mention")
    if "\r" in proposal.commit_message:
        raise PolicyError("commit message contains a carriage return")
    if "\n" in proposal.commit_message:
        if not re.fullmatch(
            r"[^\n]{1,200}\n\nSigned-off-by: [^<>\n]{1,200} <[^<>\n]{3,320}>",
            proposal.commit_message,
        ):
            raise PolicyError(
                "multiline commit message must be one subject and one exact DCO signoff trailer"
            )
    elif len(proposal.commit_message) > 200:
        raise PolicyError("commit message subject exceeds the 200-character limit")
    if required_disclosure is not None:
        if not required_disclosure.strip():
            raise PolicyError("policy.ai_disclosure cannot be blank")
        if not has_visible_disclosure(proposal.pull_request_body, required_disclosure):
            raise PolicyError(
                "Pull request body does not visibly contain the exact current configured AI "
                "disclosure"
            )


def _validate_command_evidence(store: RunStore, manifest: RunManifest) -> None:
    path = store.artifact_dir(manifest.run_id) / "validation.json"
    if path.is_symlink() or not path.is_file():
        raise PolicyError("Validation artifact is missing or unsafe")
    try:
        artifact = path.read_bytes()
    except OSError as exc:
        raise PolicyError("Validation artifact could not be read") from exc
    validate_validation_artifact(manifest, artifact=artifact)


def _read_approval_artifact(
    store: RunStore,
    run_id: str,
    filename: str,
    *,
    description: str,
) -> bytes:
    """Read one immutable-review input through a regular, non-symlink descriptor."""

    path = store.artifact_dir(run_id) / filename
    try:
        before = path.lstat()
    except OSError as exc:
        raise PolicyError(f"{description} artifact is missing or unsafe") from exc
    if not stat.S_ISREG(before.st_mode):
        raise PolicyError(f"{description} artifact is missing or unsafe")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
        ):
            raise PolicyError(f"{description} artifact changed while it was being opened")
        with os.fdopen(descriptor, "rb") as artifact:
            descriptor = -1
            return artifact.read()
    except PolicyError:
        raise
    except OSError as exc:
        raise PolicyError(f"{description} artifact could not be read safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _validate_current_config(config: AutocontributeConfig) -> None:
    """Re-run parent validators after any programmatic nested-model assignments."""

    try:
        AutocontributeConfig.model_validate(config.model_dump(mode="python"))
    except ValueError as exc:
        raise PolicyError(
            "Current configuration no longer satisfies publication safety invariants"
        ) from exc


def _validate_git_identity_credentials(
    config: AutocontributeConfig,
    *values: str,
) -> None:
    secret_env_names = {
        config.github.token_env,
        config.models.scout.api_key_env,
        config.models.builder.api_key_env,
        config.models.critic.api_key_env,
    }
    if any(
        contains_credential_material(value, secret_env_names=secret_env_names) for value in values
    ):
        raise PolicyError("Git author or committer identity appears to contain a credential")


def _publication_context(
    config: AutocontributeConfig,
    *,
    login: str,
    api_origin: str,
) -> _PublicationContext:
    canonical_login = login.strip().casefold()
    if not _GITHUB_LOGIN.fullmatch(canonical_login):
        raise PolicyError("Authenticated GitHub login is not canonical")
    expected_origin = canonical_api_origin(config.github.api_url)
    if api_origin != expected_origin:
        raise PolicyError("GitHub client API origin differs from the configured API origin")
    name = config.identity.name.strip() or canonical_login
    email = config.identity.email.strip() or f"{canonical_login}@users.noreply.github.com"
    if len(name) > 200 or not name or any(character in name for character in ("\0", "\r", "\n")):
        raise PolicyError("Configured Git author name must be a canonical single-line value")
    if (
        len(email) > 320
        or "@" not in email
        or any(character in email for character in ("\0", "\r", "\n", "<", ">"))
    ):
        raise PolicyError("Configured Git author email must be a canonical email address")
    _validate_git_identity_credentials(config, name, email)
    return _PublicationContext(
        login=canonical_login,
        api_origin=api_origin,
        author_name=name,
        author_email=email,
        committer_name=name,
        committer_email=email,
        draft=config.publishing.draft,
        ready_for_review=config.publishing.ready_for_review,
    )


def _bind_publication_context(
    manifest: RunManifest,
    context: _PublicationContext,
    *,
    allow_new: bool,
) -> bool:
    fields = {
        "publishing_login": context.login,
        "publishing_api_origin": context.api_origin,
        "commit_author_name": context.author_name,
        "commit_author_email": context.author_email,
        "commit_committer_name": context.committer_name,
        "commit_committer_email": context.committer_email,
        "publication_draft": context.draft,
        "publication_ready_for_review": context.ready_for_review,
    }
    present = {name: getattr(manifest, name) for name in fields}
    if all(value is None for value in present.values()):
        if not allow_new:
            raise PolicyError("Submitting run is missing its durable publication context")
        for name, value in fields.items():
            setattr(manifest, name, value)
        return True
    missing = [name for name, value in present.items() if value is None]
    if missing:
        raise PolicyError("Run has incomplete durable publication context: " + ", ".join(missing))
    mismatches = [name for name, expected in fields.items() if getattr(manifest, name) != expected]
    if mismatches:
        raise PolicyError(
            "Current publishing account, API origin, or Git identity differs from durable "
            "publication intent: " + ", ".join(mismatches)
        )
    return False


def _durable_publication_context(
    config: AutocontributeConfig,
    manifest: RunManifest,
    *,
    login: str,
    api_origin: str,
) -> _PublicationContext:
    """Resolve retry authority from durable intent, never mutable authoring settings."""

    canonical_login = login.strip().casefold()
    if not _GITHUB_LOGIN.fullmatch(canonical_login):
        raise PolicyError("Authenticated GitHub login is not canonical")
    canonical_origin = canonical_api_origin(api_origin)
    if api_origin != canonical_origin:
        raise PolicyError("GitHub client API origin is not canonical")
    required = {
        "publishing login": manifest.publishing_login,
        "publishing API origin": manifest.publishing_api_origin,
        "commit author name": manifest.commit_author_name,
        "commit author email": manifest.commit_author_email,
        "commit committer name": manifest.commit_committer_name,
        "commit committer email": manifest.commit_committer_email,
    }
    missing = [name for name, value in required.items() if not value]
    if (
        missing
        or manifest.publication_draft is None
        or manifest.publication_ready_for_review is None
    ):
        if manifest.publication_draft is None:
            missing.append("pull-request draft state")
        if manifest.publication_ready_for_review is None:
            missing.append("pull-request ready-for-review state")
        raise PolicyError(
            "Submitting run is missing durable publication context: " + ", ".join(missing)
        )
    if (
        manifest.publishing_login != canonical_login
        or manifest.publishing_api_origin != canonical_origin
    ):
        raise PolicyError(
            "Current publishing account or API origin differs from durable publication intent"
        )
    assert manifest.commit_author_name is not None
    assert manifest.commit_author_email is not None
    assert manifest.commit_committer_name is not None
    assert manifest.commit_committer_email is not None
    name = manifest.commit_author_name
    email = manifest.commit_author_email
    if len(name) > 200 or not name or any(character in name for character in ("\0", "\r", "\n")):
        raise PolicyError("Durable Git author name is not a canonical single-line value")
    if (
        len(email) > 320
        or "@" not in email
        or any(character in email for character in ("\0", "\r", "\n", "<", ">"))
    ):
        raise PolicyError("Durable Git author email is not a canonical email address")
    _validate_git_identity_credentials(
        config,
        name,
        email,
        manifest.commit_committer_name,
        manifest.commit_committer_email,
    )
    if manifest.commit_committer_name != name or manifest.commit_committer_email != email:
        raise PolicyError("Durable Git author and committer identities differ")
    return _PublicationContext(
        login=canonical_login,
        api_origin=canonical_origin,
        author_name=name,
        author_email=email,
        committer_name=manifest.commit_committer_name,
        committer_email=manifest.commit_committer_email,
        draft=manifest.publication_draft,
        ready_for_review=manifest.publication_ready_for_review,
    )


def _required_publication_draft(manifest: RunManifest) -> bool:
    if manifest.publication_draft is None:
        raise PolicyError("Run is missing its durable pull-request draft intent")
    return manifest.publication_draft


def _required_publication_ready_for_review(manifest: RunManifest) -> bool:
    if manifest.publication_ready_for_review is None:
        raise PolicyError("Run is missing its durable pull-request ready-for-review intent")
    return manifest.publication_ready_for_review


def build_approval_review(
    config: AutocontributeConfig,
    store: RunStore,
    run_id: str,
    *,
    actor: str,
) -> ApprovalReview:
    """Rebuild the exact human review from authoritative state and safe artifacts."""

    manifest = store.get(run_id)
    if manifest.status != RunStatus.READY_FOR_APPROVAL:
        raise StateError(f"Run {run_id} is {manifest.status.value}, not ready_for_approval")
    _validate_current_config(config)
    if manifest.quality is None or not manifest.quality.ready:
        raise PolicyError("Run has not passed every quality gate")
    validate_publication_text(
        manifest,
        required_disclosure=config.policy.ai_disclosure,
    )
    patch = _read_approval_artifact(
        store,
        run_id,
        "contribution.patch",
        description="Contribution patch",
    )
    validation_artifact = _read_approval_artifact(
        store,
        run_id,
        "validation.json",
        description="Validation",
    )
    validate_preparation_config_fingerprint(manifest, config)
    validate_preparation_fingerprint(manifest, diff=patch)
    validate_validation_artifact(manifest, artifact=validation_artifact)
    context = _publication_context(
        config,
        login=actor,
        api_origin=canonical_api_origin(config.github.api_url),
    )
    _bind_publication_context(manifest, context, allow_new=True)
    if manifest.eligibility is None or manifest.proposal is None or manifest.candidate is None:
        raise PolicyError("Run is missing durable legal-publication evidence")
    validate_legal_publication(
        config,
        manifest.eligibility,
        repository=manifest.candidate.repository,
        publishing_login=context.login,
        commit_message=manifest.proposal.commit_message,
    )
    approval_manifest = build_approval_manifest(
        manifest,
        diff=patch,
        disclosure=config.policy.ai_disclosure,
        draft=context.draft,
        ready_for_review=context.ready_for_review,
    )
    return ApprovalReview(
        run=manifest,
        patch=patch,
        validation_artifact=validation_artifact,
        manifest=approval_manifest,
        fingerprint=manifest_fingerprint(approval_manifest),
    )


def approve_run(
    config: AutocontributeConfig,
    store: RunStore,
    run_id: str,
    *,
    actor: str,
    attestation: str,
    reviewed_fingerprint: str,
) -> RunManifest:
    review = build_approval_review(config, store, run_id, actor=actor)
    if not hmac.compare_digest(reviewed_fingerprint, review.fingerprint):
        raise PolicyError(
            "Approval evidence changed after review; inspect the run again before approving"
        )
    manifest = review.run
    manifest.approval = create_approval(
        review.manifest,
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
        bind_safety = getattr(github, "bind_safety_trigger_handler", None)
        if callable(bind_safety):
            bind_safety(store.trip_circuit_breaker_trigger)

    def _require_automatic_rollout(
        self,
        *,
        run_id: str,
        deployment_fingerprint: str,
        context: _PublicationContext,
        lease_guard: LeaseHeartbeatGuard,
    ) -> RolloutSummary:
        """Return exact dual-gate authority or an expected no-publication decision."""

        if not auto_publish_opt_in_enabled(self.config.publishing):
            raise AutomaticRolloutBlocked(
                "Automatic publication is disabled; set "
                f"{self.config.publishing.auto_publish_env}=1 deliberately"
            )
        scope = UpstreamPublicationScope(
            deployment_fingerprint=deployment_fingerprint,
            publishing_login=context.login,
            publishing_api_origin=context.api_origin,
        )
        self.store.assert_circuit_breaker_clear()
        lease_guard.assert_owned()
        summary = RolloutGate.for_store(self.store).summary(
            scope,
            exclude_run_id=run_id,
        )
        if not summary.overall_gate_passed:
            blockers: list[str] = []
            if not summary.evaluation_gate_passed:
                blockers.append("expert-evaluation shadow cohort")
            if not summary.manual_cohort_passed:
                blockers.append("fixed manual upstream-outcome cohort")
            if not summary.prior_automatic_passed:
                blockers.append("prior automatic upstream outcomes")
            if not summary.upstream_outcome_gate_passed and not blockers:
                blockers.append("complete upstream-outcome evidence")
            raise AutomaticRolloutBlocked(
                "Automatic publication requires every measured rollout gate to pass; blocked: "
                + ", ".join(blockers)
            )
        return summary

    @staticmethod
    def _validate_recovery_hold(
        hold: PublicationGateHold,
        summary: RolloutSummary,
    ) -> None:
        """Require recovery to retain the hold's immutable deployment identity.

        The hold's anchored cursors may lag the live corpus after a crash (for example when
        lifecycle outcomes were observed for other runs while this publication awaited
        recovery). Recovery re-proves current authority instead: every measured rollout gate
        must pass on the fresh summary, whose verified-current cursors re-anchor the durable
        hold, and each constructive mutation revalidates that hold immediately before acting.
        """

        if hold.deployment_fingerprint is None or hold.outcome_corpus_cursor is None:
            raise StateError(
                "Publication gate hold predates schema-v6 upstream-outcome authority; "
                "automatic recovery is forbidden"
            )
        if hold.deployment_fingerprint != summary.scope.deployment_fingerprint:
            raise StateError(
                "Current semantic rollout authority differs from the durable publication hold"
            )

    def _assert_constructive_mutation_authorized(
        self,
        manifest: RunManifest,
        *,
        lease_guard: LeaseHeartbeatGuard,
    ) -> None:
        """Revalidate exact durable authority immediately before a constructive write."""

        if manifest.publishing_login is None or manifest.publishing_api_origin is None:
            raise StateError("Publication mutation lacks its durable publishing identity")
        lease_guard.assert_owned()
        self.store.assert_circuit_breaker_clear()
        automatic = self.store.assert_publication_gate_hold_current(
            manifest.run_id,
            deployment_fingerprint=manifest.deployment_fingerprint,
            publishing_login=manifest.publishing_login,
            publishing_api_origin=manifest.publishing_api_origin,
        )
        lease_guard.assert_owned()
        if automatic and not auto_publish_opt_in_enabled(self.config.publishing):
            raise AutomaticRolloutBlocked(
                "Automatic publication was disabled before the next remote mutation"
            )
        self.store.assert_circuit_breaker_clear()
        lease_guard.assert_owned()
        if automatic and not auto_publish_opt_in_enabled(self.config.publishing):
            raise AutomaticRolloutBlocked(
                "Automatic publication was disabled before the next remote mutation"
            )

    def _require_exact_review_recovery(
        self,
        manifest: RunManifest,
    ) -> ExactHumanApproval:
        """Prove exact ledger-bound human authority for a review recovery."""

        self.store.verify_event_chains(run_id=manifest.run_id)
        authority = classify_exact_human_approval(
            manifest,
            tuple(self.store.events(manifest.run_id)),
        )
        if authority is None or manifest.approval is None:
            raise StateError(
                "Submitting recovery without an automatic gate hold requires one exact "
                "ledger-bound human approval preceding publication intent"
            )
        return authority

    def _validate_exact_review_recovery_payload(
        self,
        manifest: RunManifest,
        authority: ExactHumanApproval,
    ) -> None:
        """Revalidate the exact approved payload before a constructive recovery write."""

        patch = _read_approval_artifact(
            self.store,
            manifest.run_id,
            "contribution.patch",
            description="Contribution patch",
        )
        validate_preparation_fingerprint(manifest, diff=patch)
        approval_manifest = build_approval_manifest(
            manifest,
            diff=patch,
            disclosure=self.config.policy.ai_disclosure,
            draft=_required_publication_draft(manifest),
            ready_for_review=_required_publication_ready_for_review(manifest),
        )
        assert manifest.approval is not None
        validate_approval(
            manifest.approval,
            approval_manifest,
            now=authority.publication_intent_at,
        )

    def _observe_pull_request_before_mutation(
        self,
        manifest: RunManifest,
        details: PullRequestDetails,
        *,
        lease_guard: LeaseHeartbeatGuard,
    ) -> PullRequestDetails:
        """Persist complete current safety evidence before mutating one exact pull request."""

        if (
            manifest.candidate is None
            or manifest.commit_sha is None
            or manifest.pull_request_url is None
            or manifest.pull_request_node_id is None
            or manifest.publishing_api_origin is None
        ):
            raise StateError("Pull-request safety observation lacks durable publication identity")
        repository, number = parse_pull_request_url(
            manifest.pull_request_url,
            api_origin=manifest.publishing_api_origin,
        )
        if (
            repository.casefold() != manifest.candidate.repository.casefold()
            or details.repository.casefold() != repository.casefold()
            or details.number != number
            or details.html_url != manifest.pull_request_url
            or details.node_id != manifest.pull_request_node_id
        ):
            raise StateError("Pull-request safety observation differs from durable identity")
        lease_guard.assert_owned()
        observation = LifecycleObserver(
            self.github,
            self.store,
            assert_owned=lease_guard.assert_owned,
        ).observe(
            manifest.run_id,
            repository=repository,
            number=number,
            expected_head_sha=manifest.commit_sha,
        )
        lease_guard.assert_owned()
        self.store.assert_circuit_breaker_clear()
        return observation.snapshot.pull_request

    def _bind_or_validate_upstream_identity(
        self,
        manifest: RunManifest,
        *,
        allow_new: bool,
        lease_guard: LeaseHeartbeatGuard,
    ) -> RepositoryIdentity:
        """Bind a mutable upstream name once, then validate only by immutable repository ID."""

        if manifest.candidate is None:
            raise StateError("Publication lacks an upstream repository identity")
        repository = manifest.candidate.repository
        if manifest.upstream_repository_id is None or manifest.upstream_repository_node_id is None:
            if not allow_new:
                raise StateError(
                    "Existing publication evidence predates immutable upstream identity; "
                    "autonomous recovery is forbidden"
                )
            lease_guard.assert_owned()
            identity = self.github.get_repository_identity(repository)
            lease_guard.assert_owned()
            if identity.full_name.casefold() != repository.casefold():
                raise PolicyError("The upstream repository name resolved to a different identity")
            manifest.upstream_repository_id = identity.database_id
            manifest.upstream_repository_node_id = identity.node_id
            self.store.save(
                manifest,
                event="publication.upstream_identity.bound",
                details={
                    "repository": repository,
                    "repository_id": str(identity.database_id),
                    "repository_node_id": identity.node_id,
                },
            )
            return identity
        lease_guard.assert_owned()
        identity = self.github.assert_repository_identity(
            repository,
            expected_database_id=manifest.upstream_repository_id,
            expected_node_id=manifest.upstream_repository_node_id,
        )
        lease_guard.assert_owned()
        return identity

    def _bind_or_validate_fork_identity(
        self,
        manifest: RunManifest,
        *,
        fork: str,
        allow_new: bool,
        lease_guard: LeaseHeartbeatGuard,
    ) -> RepositoryIdentity:
        """Bind the exact fork and immutable upstream parent before any branch mutation."""

        if manifest.upstream_repository_id is None or manifest.upstream_repository_node_id is None:
            raise StateError("Fork identity lacks its durable upstream identity")
        if manifest.fork_repository_id is None or manifest.fork_repository_node_id is None:
            if not allow_new:
                raise StateError(
                    "Existing publication evidence predates immutable fork identity; "
                    "autonomous recovery is forbidden"
                )
            lease_guard.assert_owned()
            observed = self.github.get_fork_identity(fork)
            lease_guard.assert_owned()
            if observed.repository.full_name.casefold() != fork.casefold():
                raise PolicyError("The publication fork name resolved to a different identity")
            if (
                observed.parent.database_id != manifest.upstream_repository_id
                or observed.parent.node_id != manifest.upstream_repository_node_id
            ):
                raise PolicyError("The publication fork has a different immutable upstream parent")
            manifest.fork_repository_id = observed.repository.database_id
            manifest.fork_repository_node_id = observed.repository.node_id
            self.store.save(
                manifest,
                event="publication.fork_identity.bound",
                details={
                    "fork": fork,
                    "fork_repository_id": str(observed.repository.database_id),
                    "fork_repository_node_id": observed.repository.node_id,
                    "upstream_repository_id": str(observed.parent.database_id),
                    "upstream_repository_node_id": observed.parent.node_id,
                },
            )
            return observed.repository
        lease_guard.assert_owned()
        identity = self.github.assert_repository_identity(
            fork,
            expected_database_id=manifest.fork_repository_id,
            expected_node_id=manifest.fork_repository_node_id,
        )
        lease_guard.assert_owned()
        return identity

    def _assert_compensation_remote_identities(
        self,
        manifest: RunManifest,
        *,
        fork: str,
        lease_guard: LeaseHeartbeatGuard,
    ) -> None:
        """Revalidate both immutable repositories immediately before destructive cleanup."""

        if (
            manifest.candidate is None
            or manifest.upstream_repository_id is None
            or manifest.upstream_repository_node_id is None
            or manifest.fork_repository_id is None
            or manifest.fork_repository_node_id is None
        ):
            raise StateError("Publication compensation lacks immutable repository identity")
        lease_guard.assert_owned()
        self.github.assert_repository_identity(
            manifest.candidate.repository,
            expected_database_id=manifest.upstream_repository_id,
            expected_node_id=manifest.upstream_repository_node_id,
        )
        lease_guard.assert_owned()
        self.github.assert_repository_identity(
            fork,
            expected_database_id=manifest.fork_repository_id,
            expected_node_id=manifest.fork_repository_node_id,
        )
        lease_guard.assert_owned()

    def _assert_constructive_remote_identities(
        self,
        manifest: RunManifest,
        *,
        fork: str,
        lease_guard: LeaseHeartbeatGuard,
    ) -> None:
        """Bracket immutable repository checks with constructive authority at a write boundary."""

        self._assert_constructive_mutation_authorized(
            manifest,
            lease_guard=lease_guard,
        )
        self._assert_compensation_remote_identities(
            manifest,
            fork=fork,
            lease_guard=lease_guard,
        )
        assert manifest.candidate is not None
        assert manifest.upstream_repository_id is not None
        assert manifest.upstream_repository_node_id is not None
        assert manifest.fork_repository_id is not None
        assert manifest.fork_repository_node_id is not None
        lease_guard.assert_owned()
        observed_fork = self.github.get_fork_identity(fork)
        lease_guard.assert_owned()
        if (
            observed_fork.repository.full_name.casefold() != fork.casefold()
            or observed_fork.repository.database_id != manifest.fork_repository_id
            or observed_fork.repository.node_id != manifest.fork_repository_node_id
            or observed_fork.parent.full_name.casefold() != manifest.candidate.repository.casefold()
            or observed_fork.parent.database_id != manifest.upstream_repository_id
            or observed_fork.parent.node_id != manifest.upstream_repository_node_id
        ):
            raise GitHubError(
                "The publication fork no longer has its durable immutable upstream parent"
            )
        self._assert_constructive_mutation_authorized(
            manifest,
            lease_guard=lease_guard,
        )

    def _ensure_durable_existing_branch_evidence(
        self,
        manifest: RunManifest,
        *,
        fork: str,
        branch: str,
        commit_sha: str,
        lease_guard: LeaseHeartbeatGuard,
    ) -> None:
        """Adopt one exact existing publication head without inventing a push event."""

        if (
            manifest.upstream_repository_id is None
            or manifest.upstream_repository_node_id is None
            or manifest.fork_repository_id is None
            or manifest.fork_repository_node_id is None
        ):
            raise StateError("Existing branch evidence lacks immutable repository identity")
        expected = {
            "fork": fork,
            "fork_repository_id": str(manifest.fork_repository_id),
            "fork_repository_node_id": manifest.fork_repository_node_id,
            "upstream_repository_id": str(manifest.upstream_repository_id),
            "upstream_repository_node_id": manifest.upstream_repository_node_id,
            "branch": branch,
            "commit_sha": commit_sha,
        }
        lease_guard.assert_owned()
        self.store.verify_event_chains(run_id=manifest.run_id)
        branch_events = tuple(
            event
            for event in self.store.events(manifest.run_id)
            if event["event_type"] in {"branch.pushed", "branch.reconciled"}
        )
        lease_guard.assert_owned()
        if len(branch_events) > 1:
            raise StateError("Publication has conflicting durable branch evidence")
        if branch_events:
            try:
                recorded = json.loads(branch_events[0]["details"])
            except (TypeError, json.JSONDecodeError) as exc:
                raise StateError("Publication branch evidence is malformed") from exc
            if recorded != expected:
                raise StateError("Publication branch evidence differs from immutable intent")
            return

        self._assert_constructive_remote_identities(
            manifest,
            fork=fork,
            lease_guard=lease_guard,
        )
        lease_guard.assert_owned()
        confirmed_sha = self.github.ref_sha(fork, f"heads/{branch}")
        lease_guard.assert_owned()
        if confirmed_sha is None or confirmed_sha.casefold() != commit_sha.casefold():
            raise PublicationResumeRequired(
                "GitHub did not preserve the exact existing contribution branch while its "
                "recovery evidence was recorded"
            )
        self._assert_constructive_mutation_authorized(
            manifest,
            lease_guard=lease_guard,
        )
        self.store.save(
            manifest,
            event="branch.reconciled",
            details=expected,
        )

    def publish(self, run_id: str) -> RunManifest:
        with LeaseHeartbeatGuard(
            self.store,
            PUBLICATION_LEASE_NAME,
            ttl=PUBLICATION_LEASE_TTL,
            heartbeat_interval=PUBLICATION_HEARTBEAT_INTERVAL,
        ) as lease_guard:
            lease_guard.assert_owned()
            return self._publish(run_id, lease_guard=lease_guard)

    def _publish(
        self,
        run_id: str,
        *,
        lease_guard: LeaseHeartbeatGuard,
    ) -> RunManifest:
        lease_guard.assert_owned()
        manifest = self.store.get(run_id)
        if manifest.status == RunStatus.PR_OPEN and manifest.pull_request_url:
            return manifest
        if manifest.status == RunStatus.SUBMITTING and manifest.publication_compensation_reason:
            return self._resume_started_compensation(
                manifest,
                lease_guard=lease_guard,
            )
        self.store.assert_circuit_breaker_clear()
        if manifest.status not in {
            RunStatus.READY_FOR_APPROVAL,
            RunStatus.APPROVED,
            RunStatus.SUBMITTING,
        }:
            raise StateError(f"Run {run_id} cannot be published from {manifest.status.value}")
        recovering = manifest.status == RunStatus.SUBMITTING
        context: _PublicationContext | None = None
        branch: str | None = None
        head: str | None = None
        recovered_remote_sha: str | None = None
        review_recovery_authority: ExactHumanApproval | None = None
        deployment_fingerprint: str | None = None
        rollout_summary: RolloutSummary | None = None
        if recovering:
            if (
                manifest.candidate is None
                or manifest.repository is None
                or manifest.proposal is None
                or manifest.base_sha is None
                or not manifest.branch_name
            ):
                raise StateError(f"Submitting run {run_id} lacks durable publication evidence")
            context = _durable_publication_context(
                self.config,
                manifest,
                login=self.github.authenticated_login(),
                api_origin=self.github.api_origin,
            )
            publication_hold = self.store.publication_gate_hold(run_id)
            if publication_hold is not None:
                _validate_current_config(self.config)
                if (
                    publication_hold.deployment_fingerprint is None
                    or publication_hold.outcome_corpus_cursor is None
                ):
                    raise StateError(
                        "Publication gate hold predates schema-v6 upstream-outcome authority; "
                        "automatic recovery is forbidden"
                    )
                creation_deployment_fingerprint = self.store.run_deployment_fingerprint(run_id)
                if (
                    manifest.deployment_fingerprint != creation_deployment_fingerprint
                    or publication_hold.deployment_fingerprint != creation_deployment_fingerprint
                ):
                    raise PolicyError(
                        "Automatic publication recovery differs from its immutable deployment "
                        "evidence"
                    )
                deployment_fingerprint = validate_deployment_fingerprint(
                    creation_deployment_fingerprint,
                    self.config,
                )
                rollout_summary = self._require_automatic_rollout(
                    run_id=run_id,
                    deployment_fingerprint=deployment_fingerprint,
                    context=context,
                    lease_guard=lease_guard,
                )
                self._validate_recovery_hold(publication_hold, rollout_summary)
            else:
                review_recovery_authority = self._require_exact_review_recovery(manifest)
            branch = manifest.branch_name
            head = f"{context.login}:{branch}"
            self.store.assert_circuit_breaker_clear()
            lease_guard.assert_owned()
            manifest = self.store.begin_publication(
                manifest,
                manifest.candidate.repository,
                branch_name=branch,
                publishing_login=context.login,
                publishing_api_origin=context.api_origin,
                commit_author_name=context.author_name,
                commit_author_email=context.author_email,
                commit_committer_name=context.committer_name,
                commit_committer_email=context.committer_email,
                publication_draft=context.draft,
                publication_ready_for_review=context.ready_for_review,
                max_per_utc_day=self.config.publishing.max_new_pull_requests_per_day,
                repository_cooldown=timedelta(days=self.config.publishing.repository_cooldown_days),
                evaluation_corpus_cursor=(
                    rollout_summary.evaluation_corpus_cursor if rollout_summary else None
                ),
                evaluation_deployment_fingerprint=(
                    rollout_summary.scope.deployment_fingerprint if rollout_summary else None
                ),
                outcome_corpus_cursor=(
                    rollout_summary.outcome_corpus_cursor if rollout_summary else None
                ),
            )
            assert manifest.candidate is not None
            assert manifest.repository is not None
            assert manifest.base_sha is not None
            assert manifest.branch_name is not None
            self._bind_or_validate_upstream_identity(
                manifest,
                allow_new=(
                    manifest.commit_sha is None
                    and manifest.pull_request_url is None
                    and not manifest.pull_request_creation_started
                ),
                lease_guard=lease_guard,
            )
            existing_pr = manifest.pull_request_url
            if existing_pr is None and manifest.commit_sha:
                existing_pr = self.github.find_pull_request(
                    manifest.candidate.repository,
                    head=head,
                )
            if existing_pr is not None:
                return self._accept_existing_pull_request(
                    manifest,
                    existing_pr,
                    login=context.login,
                    head=head,
                    allow_remote_mutation=True,
                    allow_new_repository_identity=False,
                    review_recovery_authority=review_recovery_authority,
                    lease_guard=lease_guard,
                )
            if manifest.pull_request_creation_started:
                self._stop_ambiguous_pull_request_creation(manifest)
            expected_fork = f"{context.login}/{manifest.candidate.repository.split('/', 1)[1]}"
            lease_guard.assert_owned()
            recovered_remote_sha = self.github.ref_sha(
                expected_fork,
                f"heads/{branch}",
            )
            lease_guard.assert_owned()
            if manifest.commit_sha:
                manifest.commit_sha = _validated_git_sha(
                    manifest.commit_sha,
                    field="stored commit SHA",
                )
                if (
                    recovered_remote_sha is not None
                    and recovered_remote_sha.casefold() != manifest.commit_sha
                ):
                    raise PolicyError(
                        "Remote publication branch does not match the stored contribution commit"
                    )
                workspace_path = self.store.workspace_dir(run_id) / "repository"
                if recovered_remote_sha is None and not workspace_path.is_dir():
                    return self._finalize_absent_pre_post_publication(
                        manifest,
                        login=context.login,
                        head=head,
                        reason=(
                            "verified absent remote publication state after the approved "
                            "workspace became unavailable"
                        ),
                        lease_guard=lease_guard,
                    )
            elif recovered_remote_sha is not None:
                raise PublicationResumeRequired(
                    "The durable publication branch exists without a stored commit identity; "
                    "autonomous recovery cannot safely adopt or replace it"
                )

        if not recovering:
            _validate_current_config(self.config)
            if not manifest.quality or not manifest.quality.ready:
                raise PolicyError("Run has not passed every quality gate")
            if not manifest.candidate or not manifest.repository or not manifest.base_sha:
                raise PolicyError("Run is missing repository freshness evidence")
            creation_deployment_fingerprint = self.store.run_deployment_fingerprint(run_id)
            if manifest.deployment_fingerprint != creation_deployment_fingerprint:
                raise PolicyError(
                    "Run deployment fingerprint differs from its immutable creation evidence"
                )
            validate_preparation_config_fingerprint(manifest, self.config)
            deployment_fingerprint = validate_deployment_fingerprint(
                creation_deployment_fingerprint,
                self.config,
            )
        assert manifest.candidate is not None
        assert manifest.repository is not None
        assert manifest.base_sha is not None
        validate_publication_text(
            manifest,
            required_disclosure=(None if recovering else self.config.policy.ai_disclosure),
        )
        try:
            patch_path = self.store.artifact_dir(run_id) / "contribution.patch"
            if not patch_path.is_file() or patch_path.is_symlink():
                raise PolicyError("Contribution patch artifact is missing or unsafe")
            patch = patch_path.read_bytes()
            validate_preparation_fingerprint(manifest, diff=patch)
            _validate_command_evidence(self.store, manifest)
        except (OSError, PolicyError):
            if recovering and recovered_remote_sha is None:
                assert context is not None and head is not None
                return self._finalize_absent_pre_post_publication(
                    manifest,
                    login=context.login,
                    head=head,
                    reason=(
                        "verified absent remote publication state after durable local publication "
                        "evidence became unavailable"
                    ),
                    lease_guard=lease_guard,
                )
            raise
        if review_recovery_authority is not None:
            self._validate_exact_review_recovery_payload(
                manifest,
                review_recovery_authority,
            )
        if context is None:
            context = _publication_context(
                self.config,
                login=self.github.authenticated_login(),
                api_origin=self.github.api_origin,
            )
            context_bound = _bind_publication_context(
                manifest,
                context,
                allow_new=manifest.status == RunStatus.READY_FOR_APPROVAL,
            )
            if context_bound:
                self.store.assert_circuit_breaker_clear()
                lease_guard.assert_owned()
                self.store.save(
                    manifest,
                    event="publication.context.bound",
                    details={
                        "publishing_login": context.login,
                        "publishing_api_origin": context.api_origin,
                        "publication_draft": str(context.draft).lower(),
                        "publication_ready_for_review": str(context.ready_for_review).lower(),
                    },
                )
        if not recovering and self.config.publishing.mode == "review_required":
            if manifest.approval is None:
                raise PolicyError("A human approval is required before publication")
        elif not recovering:
            if manifest.status != RunStatus.READY_FOR_APPROVAL:
                raise PolicyError(
                    "Automatic publication requires an unapproved ready-for-approval run"
                )
            assert deployment_fingerprint is not None
            rollout_summary = self._require_automatic_rollout(
                run_id=run_id,
                deployment_fingerprint=deployment_fingerprint,
                context=context,
                lease_guard=lease_guard,
            )
        login = context.login
        if manifest.eligibility is None or manifest.proposal is None:
            raise PolicyError("Run is missing durable legal-publication evidence")
        validate_legal_publication(
            self.config,
            manifest.eligibility,
            repository=manifest.candidate.repository,
            publishing_login=login,
            commit_message=manifest.proposal.commit_message,
        )
        if not recovering and self.config.publishing.mode == "review_required":
            assert manifest.approval is not None
            approval_manifest = build_approval_manifest(
                manifest,
                diff=patch,
                disclosure=self.config.policy.ai_disclosure,
                draft=context.draft,
                ready_for_review=context.ready_for_review,
            )
            validate_approval(manifest.approval, approval_manifest)
        branch = manifest.branch_name or self._branch_name(manifest)
        head = f"{login}:{branch}"

        if not recovering:
            self._check_account_limits(login, manifest)
            self._check_freshness(manifest)
        workspace_path = self.store.workspace_dir(run_id) / "repository"
        expected_fork = f"{context.login}/{manifest.candidate.repository.split('/', 1)[1]}"

        self.store.assert_circuit_breaker_clear()
        lease_guard.assert_owned()
        if not recovering:
            manifest = self.store.begin_publication(
                manifest,
                manifest.candidate.repository,
                branch_name=branch,
                publishing_login=context.login,
                publishing_api_origin=context.api_origin,
                commit_author_name=context.author_name,
                commit_author_email=context.author_email,
                commit_committer_name=context.committer_name,
                commit_committer_email=context.committer_email,
                publication_draft=context.draft,
                publication_ready_for_review=context.ready_for_review,
                max_per_utc_day=self.config.publishing.max_new_pull_requests_per_day,
                repository_cooldown=timedelta(days=self.config.publishing.repository_cooldown_days),
                evaluation_corpus_cursor=(
                    rollout_summary.evaluation_corpus_cursor if rollout_summary else None
                ),
                evaluation_deployment_fingerprint=(
                    rollout_summary.scope.deployment_fingerprint if rollout_summary else None
                ),
                outcome_corpus_cursor=(
                    rollout_summary.outcome_corpus_cursor if rollout_summary else None
                ),
            )
        assert manifest.candidate is not None
        assert manifest.repository is not None
        assert manifest.base_sha is not None
        if manifest.status != RunStatus.SUBMITTING or manifest.branch_name != branch:
            raise StateError("Publication intent was not durably established")

        self._bind_or_validate_upstream_identity(
            manifest,
            allow_new=not recovering,
            lease_guard=lease_guard,
        )

        existing_pr = self.github.find_pull_request(
            manifest.candidate.repository,
            head=head,
        )
        if existing_pr:
            return self._accept_existing_pull_request(
                manifest,
                existing_pr,
                login=login,
                head=head,
                allow_remote_mutation=True,
                allow_new_repository_identity=not recovering,
                review_recovery_authority=review_recovery_authority,
                lease_guard=lease_guard,
            )

        if manifest.commit_sha and not workspace_path.is_dir():
            manifest.commit_sha = _validated_git_sha(
                manifest.commit_sha,
                field="stored commit SHA",
            )
            if recovered_remote_sha is None:
                recovered_remote_sha = self.github.ref_sha(
                    expected_fork,
                    f"heads/{branch}",
                )
            if recovered_remote_sha is None:
                return self._finalize_absent_pre_post_publication(
                    manifest,
                    login=context.login,
                    head=head,
                    reason=(
                        "verified absent remote publication state after the approved workspace "
                        "became unavailable"
                    ),
                    lease_guard=lease_guard,
                )
            if recovered_remote_sha.casefold() != manifest.commit_sha:
                raise PolicyError(
                    "Remote publication branch does not match the stored contribution commit"
                )
            workspace = None
        else:
            workspace = self._prepare_workspace(manifest, workspace_path, patch)

        upstream_repository = manifest.candidate.repository

        def authorize_fork_creation() -> None:
            self._assert_constructive_mutation_authorized(
                manifest,
                lease_guard=lease_guard,
            )
            if (
                manifest.upstream_repository_id is None
                or manifest.upstream_repository_node_id is None
            ):
                raise StateError("Fork creation lacks immutable upstream identity")
            self.github.assert_repository_identity(
                upstream_repository,
                expected_database_id=manifest.upstream_repository_id,
                expected_node_id=manifest.upstream_repository_node_id,
            )
            self._assert_constructive_mutation_authorized(
                manifest,
                lease_guard=lease_guard,
            )

        fork = self.github.ensure_fork(
            upstream_repository,
            login,
            before_mutation=authorize_fork_creation,
        )
        if fork.casefold() != expected_fork.casefold():
            raise PolicyError("GitHub returned a fork outside the durable publishing account")
        self.store.assert_circuit_breaker_clear()
        lease_guard.assert_owned()
        self._wait_for_fork(fork, manifest.repository.default_branch)
        self.store.assert_circuit_breaker_clear()
        self._bind_or_validate_fork_identity(
            manifest,
            fork=fork,
            allow_new=not recovering or manifest.commit_sha is None,
            lease_guard=lease_guard,
        )
        self.store.assert_circuit_breaker_clear()
        lease_guard.assert_owned()
        if manifest.commit_sha:
            commit_sha = manifest.commit_sha
        else:
            if workspace is None:
                raise PolicyError("Publication workspace is missing its approved working tree")
            commit_sha = self._commit(workspace, manifest, patch)
        manifest.commit_sha = commit_sha
        self.store.assert_circuit_breaker_clear()
        lease_guard.assert_owned()
        self.store.save(
            manifest,
            event="commit.created",
            details={"commit_sha": commit_sha, "branch": branch},
        )

        remote_sha = recovered_remote_sha or self.github.ref_sha(fork, f"heads/{branch}")
        if remote_sha is None:
            if not workspace_path.is_dir() or workspace_path.is_symlink():
                return self._finalize_absent_pre_post_publication(
                    manifest,
                    login=login,
                    head=head,
                    reason=(
                        "verified absent remote publication state before the required branch "
                        "push, with no safe approved workspace remaining"
                    ),
                    lease_guard=lease_guard,
                )
            if recovering:
                try:
                    self._check_freshness(manifest)
                except PolicyError as exc:
                    self._finalize_absent_pre_post_publication(
                        manifest,
                        login=login,
                        head=head,
                        reason=(
                            "verified absent remote publication state after upstream freshness "
                            "invalidated safe branch resumption"
                        ),
                        lease_guard=lease_guard,
                    )
                    raise PolicyError(
                        "The durable publication intent became stale before its absent remote "
                        "branch could be resumed; no remote publication state remains"
                    ) from exc
            self._push(
                workspace_path,
                fork,
                branch,
                commit_sha,
                before_mutation=lambda: self._assert_constructive_remote_identities(
                    manifest,
                    fork=fork,
                    lease_guard=lease_guard,
                ),
            )
            self.store.assert_circuit_breaker_clear()
            lease_guard.assert_owned()
            self.store.save(
                manifest,
                event="branch.pushed",
                details={
                    "fork": fork,
                    "fork_repository_id": str(manifest.fork_repository_id),
                    "fork_repository_node_id": str(manifest.fork_repository_node_id),
                    "upstream_repository_id": str(manifest.upstream_repository_id),
                    "upstream_repository_node_id": str(manifest.upstream_repository_node_id),
                    "branch": branch,
                    "commit_sha": commit_sha,
                },
            )
        elif remote_sha.casefold() != commit_sha.casefold():
            raise PolicyError(
                "Publication branch already exists with different content; refusing to force-push"
            )

        self.store.assert_circuit_breaker_clear()
        lease_guard.assert_owned()
        verified_remote_sha = self.github.ref_sha(fork, f"heads/{branch}")
        if verified_remote_sha is None or verified_remote_sha.casefold() != commit_sha.casefold():
            raise PublicationResumeRequired(
                "GitHub did not confirm the exact contribution branch after push; "
                "the durable publication intent requires reconciliation"
            )
        if remote_sha is not None:
            self._ensure_durable_existing_branch_evidence(
                manifest,
                fork=fork,
                branch=branch,
                commit_sha=commit_sha,
                lease_guard=lease_guard,
            )

        self.store.assert_circuit_breaker_clear()
        lease_guard.assert_owned()
        current_base_sha = self.github.default_branch_sha(
            manifest.candidate.repository,
            manifest.repository.default_branch,
        )
        if current_base_sha.casefold() != manifest.base_sha.casefold():
            manifest.publication_compensation_reason = "pre_pr_base_moved"
            self.store.save(
                manifest,
                event="publication.base_moved_before_pull_request",
                details={
                    "approved_base_sha": manifest.base_sha,
                    "current_base_sha": current_base_sha,
                    "fork": fork,
                    "fork_repository_id": str(manifest.fork_repository_id),
                    "fork_repository_node_id": str(manifest.fork_repository_node_id),
                    "upstream_repository_id": str(manifest.upstream_repository_id),
                    "upstream_repository_node_id": str(manifest.upstream_repository_node_id),
                    "branch": branch,
                    "commit_sha": commit_sha,
                },
            )
            self._resume_started_compensation(
                manifest,
                lease_guard=lease_guard,
            )
            raise PolicyError(
                "The upstream base branch moved after the contribution branch was pushed; "
                "the exact remote branch was removed and validation and approval must be rerun"
            )

        try:
            self._check_pre_pull_request_policy_freshness(manifest)
        except PolicyError as exc:
            self._compensate_stale_pre_pull_request_branch(
                manifest,
                fork=fork,
                branch=branch,
                commit_sha=commit_sha,
                lease_guard=lease_guard,
            )
            raise PolicyError(
                "Issue or repository freshness evidence changed after the contribution branch "
                "was pushed; the exact remote branch was removed and the candidate must be "
                "reevaluated"
            ) from exc

        proposal = manifest.proposal
        assert proposal is not None
        self._assert_constructive_mutation_authorized(
            manifest,
            lease_guard=lease_guard,
        )
        if manifest.pull_request_creation_started:
            self._stop_ambiguous_pull_request_creation(manifest)
        repository_name = manifest.candidate.repository
        base_branch = manifest.repository.default_branch
        approved_base_sha = manifest.base_sha
        creation_details = {
            "repository": repository_name,
            "head": head,
            "head_sha": commit_sha,
            "base": base_branch,
            "base_sha": approved_base_sha,
        }
        callback_failure: Exception | None = None
        mutation_boundary_failure: Exception | None = None
        pull_request_callback_completed = False

        def begin_pull_request_creation() -> None:
            nonlocal mutation_boundary_failure
            nonlocal callback_failure
            nonlocal pull_request_callback_completed
            try:
                self._assert_constructive_remote_identities(
                    manifest,
                    fork=fork,
                    lease_guard=lease_guard,
                )
                try:
                    self._check_mutation_boundary_freshness(manifest)
                except (GitHubError, PolicyError, StateError) as exc:
                    mutation_boundary_failure = exc
                    raise
                self._assert_constructive_remote_identities(
                    manifest,
                    fork=fork,
                    lease_guard=lease_guard,
                )
                try:
                    lease_guard.assert_owned()
                    boundary_head_sha = self.github.ref_sha(
                        fork,
                        f"heads/{branch}",
                    )
                    lease_guard.assert_owned()
                    if (
                        boundary_head_sha is None
                        or boundary_head_sha.casefold() != commit_sha.casefold()
                    ):
                        raise PolicyError(
                            "The exact contribution branch changed at the pull-request "
                            "mutation boundary"
                        )
                except (GitHubError, PolicyError, StateError) as exc:
                    mutation_boundary_failure = exc
                    raise
                self._assert_constructive_mutation_authorized(
                    manifest,
                    lease_guard=lease_guard,
                )
                manifest.pull_request_creation_started = True
                try:
                    self.store.save(
                        manifest,
                        event="pull_request.creation.started",
                        details=creation_details,
                    )
                except Exception:
                    try:
                        marker_is_durable = self.store.get(
                            manifest.run_id
                        ).pull_request_creation_started
                    except Exception:
                        # The durable state is unknown, so retain the conservative in-memory
                        # marker. A fresh process will reload the authoritative state.
                        pass
                    else:
                        if not marker_is_durable:
                            manifest.pull_request_creation_started = False
                    raise
                self._assert_constructive_mutation_authorized(
                    manifest,
                    lease_guard=lease_guard,
                )
            except Exception as exc:
                callback_failure = exc
                raise
            pull_request_callback_completed = True

        try:
            created_pull_request = self.github.create_pull_request(
                repository_name,
                title=proposal.pull_request_title,
                body=proposal.pull_request_body,
                head=head,
                expected_head_sha=commit_sha,
                expected_head_repository=fork,
                base=base_branch,
                expected_base_sha=approved_base_sha,
                draft=_required_publication_draft(manifest),
                before_mutation=begin_pull_request_creation,
            )
        except Exception as exc:
            if mutation_boundary_failure is not None:
                self._compensate_stale_pre_pull_request_branch(
                    manifest,
                    fork=fork,
                    branch=branch,
                    commit_sha=commit_sha,
                    lease_guard=lease_guard,
                )
                raise PolicyError(
                    "Issue or repository freshness evidence changed at the pull-request "
                    "mutation boundary; the exact remote branch was removed and the candidate "
                    "must be reevaluated"
                ) from mutation_boundary_failure
            if not pull_request_callback_completed:
                if callback_failure is None or callback_failure is exc:
                    raise
                raise callback_failure from exc
            if isinstance(exc, GitHubRequestNotSentError):
                # The POST provably never left this client, so no remote pull request can
                # exist for this durable intent. Release the creation marker; a later
                # scheduled run retries the exact same POST without a global stop.
                if self._release_unsent_pull_request_creation(
                    manifest,
                    creation_details=creation_details,
                    error_type=type(exc).__name__,
                ):
                    raise
            else:
                # A transport or response failure may follow a successful POST. Reconcile the
                # exact head once: an existing PR is adopted as the durable canonical identity,
                # while an absent or unreadable result keeps the conservative stop because a
                # slow POST could still land after this read.
                reconciled_pr: str | None = None
                try:
                    reconciled_pr = self.github.find_pull_request(
                        repository_name,
                        head=head,
                    )
                except GitHubSafetyError:
                    raise
                except Exception:
                    reconciled_pr = None
                if reconciled_pr is not None:
                    return self._accept_existing_pull_request(
                        manifest,
                        reconciled_pr,
                        login=login,
                        head=head,
                        allow_remote_mutation=True,
                        allow_new_repository_identity=False,
                        lease_guard=lease_guard,
                    )
            self._trip_ambiguous_pull_request_creation(
                manifest,
                error_type=type(exc).__name__,
            )
            raise PublicationResumeRequired(
                "Pull-request creation may have succeeded, but GitHub did not return a durable "
                "canonical identity. Autonomous retries will not send a second POST; exact remote "
                "reconciliation is required"
            ) from exc
        try:
            self._persist_created_pull_request(
                manifest,
                created_pull_request,
            )
        except PublicationResumeRequired:
            raise
        except Exception as exc:
            self._trip_ambiguous_pull_request_creation(
                manifest,
                error_type=type(exc).__name__,
            )
            raise PublicationResumeRequired(
                "GitHub returned from pull-request creation, but its canonical identity could not "
                "be persisted. Autonomous retries will not send a second POST"
            ) from exc
        mismatches = self._created_pull_request_mismatches(
            created_pull_request,
            manifest=manifest,
            head=head,
            fork=fork,
            commit_sha=commit_sha,
        )
        if created_pull_request.merged and set(mismatches) <= {
            "state",
            "merged state",
            "draft state",
        }:
            self.store.assert_circuit_breaker_clear()
            lease_guard.assert_owned()
            self.store.transition(
                manifest,
                RunStatus.PR_OPEN,
                reason="exact created PR was already merged and is lifecycle-managed",
            )
            return manifest
        created_identity_mismatches = {
            "repository",
            "head branch",
            "head label",
            "head repository",
            "head commit",
        }.intersection(mismatches)
        if (
            created_pull_request.state == "closed"
            and not created_pull_request.merged
            and not created_identity_mismatches
        ):
            self._trip_publication_breaker(
                source="publication:closed_unmerged_pr",
                reason=(
                    "An exact created pull request was already closed without merge; lifecycle "
                    "management is retained and autonomous publication is stopped for review"
                ),
                evidence={
                    "url": manifest.pull_request_url or created_pull_request.html_url,
                    "repository": created_pull_request.repository,
                    "number": str(created_pull_request.number),
                    "head_sha": created_pull_request.head_sha,
                    "mismatches": ",".join(mismatches),
                },
            )
            lease_guard.assert_owned()
            self.store.transition(
                manifest,
                RunStatus.PR_OPEN,
                reason="exact created closed-unmerged PR is lifecycle-managed",
            )
            return manifest
        if mismatches:
            self._reject_created_pull_request(
                manifest,
                created_pull_request,
                mismatches=mismatches,
                fork=fork,
                branch=branch,
                commit_sha=commit_sha,
                lease_guard=lease_guard,
            )
        created_pull_request = self._ensure_pull_request_ready_for_review(
            manifest,
            created_pull_request,
            head=head,
            fork=fork,
            allow_remote_mutation=True,
            lease_guard=lease_guard,
        )
        self.store.assert_circuit_breaker_clear()
        lease_guard.assert_owned()
        self.store.transition(manifest, RunStatus.PR_OPEN, reason="pull request opened")
        return manifest

    def _persist_created_pull_request(
        self,
        manifest: RunManifest,
        created: PullRequestDetails,
    ) -> None:
        """Persist the canonical POST result before applying any response policy checks."""

        assert manifest.candidate is not None and manifest.publishing_api_origin is not None
        if (
            manifest.upstream_repository_id is None
            or manifest.upstream_repository_node_id is None
            or manifest.fork_repository_id is None
            or manifest.fork_repository_node_id is None
            or not created.node_id
        ):
            raise StateError("Created pull request lacks durable immutable remote identity")
        repository, number = parse_pull_request_url(
            created.html_url,
            api_origin=manifest.publishing_api_origin,
        )
        if (
            repository.casefold() != manifest.candidate.repository.casefold()
            or created.repository.casefold() != repository.casefold()
            or created.number != number
        ):
            raise GitHubError("GitHub returned an inconsistent created pull-request identity")
        manifest.pull_request_url = created.html_url
        manifest.pull_request_node_id = created.node_id
        try:
            self.store.save(
                manifest,
                event="pull_request.created.response",
                details={
                    "url": created.html_url,
                    "repository": repository,
                    "number": str(number),
                    "state": "merged" if created.merged else created.state,
                    "head_sha": created.head_sha,
                    "base_sha": created.base_sha,
                    "pull_request_node_id": created.node_id,
                    "upstream_repository_id": str(manifest.upstream_repository_id),
                    "upstream_repository_node_id": str(manifest.upstream_repository_node_id),
                    "fork_repository_id": str(manifest.fork_repository_id),
                    "fork_repository_node_id": str(manifest.fork_repository_node_id),
                },
            )
        except Exception as exc:
            self._trip_publication_breaker(
                source="publication:created_pr_not_persisted",
                reason=(
                    "GitHub created a pull request but its canonical identity could not be "
                    "persisted; autonomous publication is stopped for reconciliation"
                ),
                evidence={
                    "url": created.html_url,
                    "repository": repository,
                    "number": str(number),
                    "head_sha": created.head_sha,
                },
            )
            raise PublicationResumeRequired(
                "GitHub created a pull request whose durable save failed; publication is "
                f"stopped and the canonical URL must be reconciled: {created.html_url}"
            ) from exc

    def _ensure_pull_request_ready_for_review(
        self,
        manifest: RunManifest,
        details: PullRequestDetails,
        *,
        head: str,
        fork: str,
        allow_remote_mutation: bool,
        lease_guard: LeaseHeartbeatGuard,
    ) -> PullRequestDetails:
        """Finish the durably authorized draft-to-ready transition for one exact PR."""

        should_be_ready = _required_publication_ready_for_review(manifest)
        if not should_be_ready:
            if manifest.pull_request_ready_started or manifest.pull_request_ready_completed:
                raise StateError("Draft publication has inconsistent ready-for-review evidence")
            return details
        if (
            manifest.commit_sha is None
            or manifest.pull_request_url is None
            or manifest.pull_request_node_id is None
            or manifest.branch_name is None
        ):
            raise StateError(
                "Ready-for-review publication lacks durable PR, branch, or commit identity"
            )
        if details.draft and allow_remote_mutation and not manifest.pull_request_ready_completed:
            details = self._observe_pull_request_before_mutation(
                manifest,
                details,
                lease_guard=lease_guard,
            )
        mismatches = tuple(
            mismatch
            for mismatch in self._created_pull_request_mismatches(
                details,
                manifest=manifest,
                head=head,
                fork=fork,
                commit_sha=manifest.commit_sha,
            )
            if mismatch != "draft state"
        )
        if mismatches:
            self._trip_publication_breaker(
                source="publication:ready_for_review_identity_mismatch",
                reason=(
                    "The pull request selected for ready-for-review differs from durable "
                    "publication intent; autonomous publication is stopped"
                ),
                evidence={
                    "url": details.html_url,
                    "head_sha": details.head_sha,
                    "mismatches": ",".join(mismatches),
                },
            )
            raise PublicationResumeRequired(
                "The pull request cannot be marked ready because its exact identity changed"
            )
        if manifest.pull_request_ready_completed:
            if details.draft:
                self._trip_publication_breaker(
                    source="publication:ready_for_review_regressed",
                    reason=(
                        "A pull request durably confirmed ready for review is a draft again; "
                        "autonomous publication is stopped"
                    ),
                    evidence={"url": details.html_url, "head_sha": details.head_sha},
                )
                raise PublicationResumeRequired(
                    "The pull request reverted to draft after ready-for-review confirmation"
                )
            return details

        if details.draft and not allow_remote_mutation:
            raise PublicationResumeRequired(
                "The exact draft pull request requires authorized publication resumption "
                "before it can be marked ready for review"
            )

        if not manifest.pull_request_ready_started:
            manifest.pull_request_ready_started = True
            self.store.assert_circuit_breaker_clear()
            lease_guard.assert_owned()
            self.store.save(
                manifest,
                event="pull_request.ready_for_review.started",
                details={
                    "url": details.html_url,
                    "repository": details.repository,
                    "number": str(details.number),
                    "head_sha": details.head_sha,
                },
            )

        confirmed = details
        if details.draft:
            mutation_callback_failed = False

            def assert_ready_observation_authorized() -> None:
                nonlocal mutation_callback_failed
                try:
                    self._assert_constructive_remote_identities(
                        manifest,
                        fork=fork,
                        lease_guard=lease_guard,
                    )
                except Exception:
                    mutation_callback_failed = True
                    raise

            def assert_ready_mutation_authorized() -> None:
                nonlocal mutation_callback_failed
                try:
                    self._assert_constructive_mutation_authorized(
                        manifest,
                        lease_guard=lease_guard,
                    )
                except Exception:
                    mutation_callback_failed = True
                    raise

            try:
                confirmed = self.github.mark_pull_request_ready_for_review(
                    details.repository,
                    details.number,
                    expected_url=manifest.pull_request_url,
                    expected_node_id=manifest.pull_request_node_id,
                    expected_head_repository=fork,
                    expected_head_ref=manifest.branch_name,
                    expected_head_sha=manifest.commit_sha,
                    before_observation=assert_ready_observation_authorized,
                    before_mutation=assert_ready_mutation_authorized,
                )
            except (AutomaticRolloutBlocked, StateError):
                raise
            except GitHubSafetyError:
                raise
            except Exception as exc:
                if mutation_callback_failed:
                    raise
                # A transport or response failure may follow a successful mutation. Re-read the
                # exact PR once; a still-draft result remains safely retryable from SUBMITTING.
                try:
                    confirmed = self.github.get_pull_request(
                        details.repository,
                        details.number,
                    )
                except Exception as reconciliation_exc:
                    raise PublicationResumeRequired(
                        "Ready-for-review may have succeeded, but GitHub state could not be "
                        "reconciled; the run remains submitting"
                    ) from reconciliation_exc
                if confirmed.draft:
                    raise PublicationResumeRequired(
                        "GitHub did not confirm ready-for-review; the exact draft PR remains "
                        "durable and retryable"
                    ) from exc

        mismatches = tuple(
            mismatch
            for mismatch in self._created_pull_request_mismatches(
                confirmed,
                manifest=manifest,
                head=head,
                fork=fork,
                commit_sha=manifest.commit_sha,
            )
            if mismatch != "draft state"
        )
        if mismatches or confirmed.draft:
            self._trip_publication_breaker(
                source="publication:ready_for_review_not_confirmed",
                reason=(
                    "GitHub did not confirm the exact pull request as ready for review; "
                    "autonomous publication is stopped"
                ),
                evidence={
                    "url": confirmed.html_url,
                    "head_sha": confirmed.head_sha,
                    "draft": str(confirmed.draft).lower(),
                    "mismatches": ",".join(mismatches),
                },
            )
            raise PublicationResumeRequired(
                "The exact ready-for-review result could not be confirmed"
            )

        manifest.pull_request_ready_completed = True
        self.store.assert_circuit_breaker_clear()
        lease_guard.assert_owned()
        self.store.save(
            manifest,
            event="pull_request.ready_for_review.completed",
            details={
                "url": confirmed.html_url,
                "repository": confirmed.repository,
                "number": str(confirmed.number),
                "head_sha": confirmed.head_sha,
            },
        )
        return confirmed

    def _created_pull_request_mismatches(
        self,
        created: PullRequestDetails,
        *,
        manifest: RunManifest,
        head: str,
        fork: str,
        commit_sha: str,
    ) -> tuple[str, ...]:
        assert (
            manifest.candidate and manifest.repository and manifest.proposal and manifest.base_sha
        )
        expected: dict[str, tuple[object, object]] = {
            "pull request node": (created.node_id, manifest.pull_request_node_id),
            "repository": (
                created.repository.casefold(),
                manifest.candidate.repository.casefold(),
            ),
            "state": (created.state, "open"),
            "merged state": (created.merged, False),
            "draft state": (created.draft, _required_publication_draft(manifest)),
            "base branch": (created.base_ref, manifest.repository.default_branch),
            "base commit": (created.base_sha.casefold(), manifest.base_sha.casefold()),
            "head branch": (created.head_ref, manifest.branch_name),
            "head label": (created.head_label.casefold(), head.casefold()),
            "head repository": (
                created.head_repository.casefold(),
                fork.casefold(),
            ),
            "head commit": (created.head_sha.casefold(), commit_sha.casefold()),
            "title": (created.title, manifest.proposal.pull_request_title),
            "body": (created.body, manifest.proposal.pull_request_body),
        }
        return tuple(name for name, (actual, wanted) in expected.items() if actual != wanted)

    def _reject_created_pull_request(
        self,
        manifest: RunManifest,
        created: PullRequestDetails,
        *,
        mismatches: tuple[str, ...],
        fork: str,
        branch: str,
        commit_sha: str,
        lease_guard: LeaseHeartbeatGuard,
    ) -> None:
        """Stop after an invalid POST result, compensating only a proven base race."""

        assert manifest.candidate and manifest.base_sha and manifest.pull_request_url
        self.store.save(
            manifest,
            event="pull_request.created.rejected",
            details={
                "url": manifest.pull_request_url,
                "mismatches": ", ".join(mismatches),
                "expected_base_sha": manifest.base_sha,
                "returned_base_sha": created.base_sha,
            },
        )
        base_moved = "base commit" in mismatches
        self._trip_publication_breaker(
            source=(
                "publication:base_moved_during_pr_creation"
                if base_moved
                else "publication:created_pr_response_mismatch"
            ),
            reason=(
                "The upstream base moved during pull-request creation; autonomous publication "
                "is stopped until the created PR is safely reconciled"
                if base_moved
                else "GitHub returned a created pull request that differs from the durable "
                "publication intent; autonomous publication is stopped for reconciliation"
            ),
            evidence={
                "url": manifest.pull_request_url,
                "repository": created.repository,
                "number": str(created.number),
                "mismatches": ",".join(mismatches),
                "expected_base_sha": manifest.base_sha,
                "returned_base_sha": created.base_sha,
                "expected_head_sha": commit_sha,
                "returned_head_sha": created.head_sha,
            },
        )

        exact_compensation_identity = (
            created.repository.casefold() == manifest.candidate.repository.casefold()
            and manifest.pull_request_node_id is not None
            and created.node_id == manifest.pull_request_node_id
            and created.head_repository.casefold() == fork.casefold()
            and created.head_ref == branch
            and created.head_sha.casefold() == commit_sha.casefold()
            and not created.merged
        )
        if base_moved and exact_compensation_identity:
            manifest.publication_compensation_reason = "created_pr_base_moved"
            lease_guard.assert_owned()
            self.store.save(
                manifest,
                event="publication.compensation.started",
                details={
                    "reason": manifest.publication_compensation_reason,
                    "url": manifest.pull_request_url,
                    "pull_request_node_id": str(manifest.pull_request_node_id),
                    "repository": created.repository,
                    "number": str(created.number),
                    "upstream_repository_id": str(manifest.upstream_repository_id),
                    "upstream_repository_node_id": str(manifest.upstream_repository_node_id),
                    "fork": fork,
                    "fork_repository_id": str(manifest.fork_repository_id),
                    "fork_repository_node_id": str(manifest.fork_repository_node_id),
                    "branch": branch,
                    "commit_sha": commit_sha,
                    "approved_base_sha": manifest.base_sha,
                    "returned_base_sha": created.base_sha,
                },
            )
            compensated = self._resume_started_compensation(
                manifest,
                lease_guard=lease_guard,
            )
            if compensated.status == RunStatus.PR_OPEN:
                raise PublicationResumeRequired(
                    "The exact compensating pull request merged before cleanup and is now "
                    "retained for lifecycle management; the global safety stop requires "
                    "operator reconciliation"
                )
            raise PublicationResumeRequired(
                "The upstream base moved during pull-request creation. The exact created PR was "
                "closed, its exact branch was removed, and its canonical URL remains durable; "
                "the global safety stop requires operator reconciliation"
            )

        self.store.save(
            manifest,
            event="pull_request.compensation.deferred",
            details={
                "url": manifest.pull_request_url,
                "reason": "created pull-request identity was not safe for automatic cleanup",
            },
        )
        raise PublicationResumeRequired(
            "The created pull request differs from durable publication intent. Its canonical URL "
            "was retained and autonomous retries are blocked pending manual reconciliation"
        )

    def _compensate_created_pull_request(
        self,
        manifest: RunManifest,
        created: PullRequestDetails,
        *,
        fork: str,
        branch: str,
        commit_sha: str,
        lease_guard: LeaseHeartbeatGuard,
    ) -> None:
        assert manifest.candidate and manifest.pull_request_url
        if manifest.pull_request_node_id is None:
            raise StateError("Pull-request compensation lacks immutable node identity")
        candidate_repository = manifest.candidate.repository
        try:

            def assert_compensation_identity_before_observation() -> None:
                self._assert_compensation_remote_identities(
                    manifest,
                    fork=fork,
                    lease_guard=lease_guard,
                )

            def assert_owned_before_close_mutation() -> None:
                lease_guard.assert_owned()

            lease_guard.assert_owned()
            closed = self.github.close_pull_request(
                candidate_repository,
                created.number,
                expected_node_id=manifest.pull_request_node_id,
                expected_head_repository=fork,
                expected_head_ref=branch,
                expected_head_sha=commit_sha,
                before_observation=assert_compensation_identity_before_observation,
                before_mutation=assert_owned_before_close_mutation,
            )
            lease_guard.assert_owned()
            if (
                closed.repository.casefold() != candidate_repository.casefold()
                or closed.number != created.number
                or closed.html_url != manifest.pull_request_url
                or closed.node_id != manifest.pull_request_node_id
                or closed.state != "closed"
                or closed.merged
            ):
                raise GitHubError(
                    "GitHub did not confirm closure of the exact created pull request"
                )
            self.store.save(
                manifest,
                event="pull_request.compensation.closed",
                details={"url": manifest.pull_request_url, "state": "closed_unmerged"},
            )

            def assert_pull_request_closed_before_branch_delete() -> None:
                lease_guard.assert_owned()
                current = self.github.get_pull_request(
                    candidate_repository,
                    created.number,
                )
                lease_guard.assert_owned()
                expected_head_label = f"{fork.split('/', 1)[0]}:{branch}"
                identity = {
                    "repository": (
                        current.repository.casefold(),
                        candidate_repository.casefold(),
                    ),
                    "number": (current.number, created.number),
                    "canonical URL": (current.html_url, manifest.pull_request_url),
                    "pull request node": (
                        current.node_id,
                        manifest.pull_request_node_id,
                    ),
                    "head branch": (current.head_ref, branch),
                    "head label": (
                        current.head_label.casefold(),
                        expected_head_label.casefold(),
                    ),
                    "head repository": (
                        current.head_repository.casefold(),
                        fork.casefold(),
                    ),
                    "head commit": (
                        current.head_sha.casefold(),
                        commit_sha.casefold(),
                    ),
                    "state": (current.state, "closed"),
                    "merged": (current.merged, False),
                }
                mismatches = tuple(
                    name for name, (actual, expected) in identity.items() if actual != expected
                )
                if mismatches:
                    raise PublicationResumeRequired(
                        "The exact compensating pull request changed immediately before branch "
                        "deletion; its branch was retained for reconciliation"
                    )

            self._compensate_branch_only(
                manifest,
                fork=fork,
                branch=branch,
                commit_sha=commit_sha,
                lease_guard=lease_guard,
                before_mutation=assert_pull_request_closed_before_branch_delete,
            )
        except StateError:
            raise
        except PublicationResumeRequired:
            raise
        except Exception as exc:
            self.store.save(
                manifest,
                event="pull_request.compensation.failed",
                details={
                    "url": manifest.pull_request_url,
                    "stage": "close_or_verify",
                    "error_type": type(exc).__name__,
                },
            )
            raise PublicationResumeRequired(
                "The exact created pull request could not be safely closed and verified. Its URL "
                "remains durable, SUBMITTING is retained, and manual or retry reconciliation is "
                "required"
            ) from exc

    def _compensate_branch_only(
        self,
        manifest: RunManifest,
        *,
        fork: str,
        branch: str,
        commit_sha: str,
        lease_guard: LeaseHeartbeatGuard,
        before_mutation: Callable[[], None],
    ) -> None:
        if manifest.fork_repository_id is None or manifest.fork_repository_node_id is None:
            raise StateError("Branch compensation lacks immutable fork identity")
        try:
            self._assert_compensation_remote_identities(
                manifest,
                fork=fork,
                lease_guard=lease_guard,
            )
            self._delete_remote_branch(
                fork,
                branch,
                commit_sha,
                expected_repository_id=manifest.fork_repository_id,
                expected_repository_node_id=manifest.fork_repository_node_id,
                lease_guard=lease_guard,
                before_mutation=before_mutation,
            )
        except StateError:
            raise
        except Exception as exc:
            self.store.save(
                manifest,
                event="branch.compensation.failed",
                details={
                    "fork": fork,
                    "fork_repository_id": str(manifest.fork_repository_id),
                    "fork_repository_node_id": str(manifest.fork_repository_node_id),
                    "branch": branch,
                    "commit_sha": commit_sha,
                    "error_type": type(exc).__name__,
                },
            )
            raise PublicationResumeRequired(
                "The exact contribution branch could not be conditionally removed and verified; "
                "SUBMITTING and the daily reservation are retained for reconciliation"
            ) from exc
        lease_guard.assert_owned()
        self.store.save(
            manifest,
            event="branch.compensated",
            details={
                "fork": fork,
                "fork_repository_id": str(manifest.fork_repository_id),
                "fork_repository_node_id": str(manifest.fork_repository_node_id),
                "branch": branch,
                "commit_sha": commit_sha,
            },
        )

    def _trip_publication_breaker(
        self,
        *,
        source: str,
        reason: str,
        evidence: dict[str, str],
    ) -> None:
        trigger_hash = hashlib.sha256(
            json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        self.store.trip_circuit_breaker(
            source=source,
            reason=reason,
            trigger_hash=trigger_hash,
        )

    def _release_unsent_pull_request_creation(
        self,
        manifest: RunManifest,
        *,
        creation_details: dict[str, str],
        error_type: str,
    ) -> bool:
        """Durably release a creation intent whose POST provably never left this client.

        Returns True only when the release is durable; a False result means the durable
        marker may still claim an in-flight creation, so the caller must keep the
        conservative ambiguity stop.
        """

        manifest.pull_request_creation_started = False
        try:
            self.store.save(
                manifest,
                event="pull_request.creation.not_sent",
                details={**creation_details, "error_type": error_type},
            )
        except Exception:
            try:
                marker_is_durable = self.store.get(manifest.run_id).pull_request_creation_started
            except Exception:
                # The durable state is unknown, so retain the conservative in-memory
                # marker. A fresh process will reload the authoritative state.
                manifest.pull_request_creation_started = True
            else:
                manifest.pull_request_creation_started = marker_is_durable
            return not manifest.pull_request_creation_started
        return True

    def _trip_ambiguous_pull_request_creation(
        self,
        manifest: RunManifest,
        *,
        error_type: str,
    ) -> None:
        if manifest.candidate is None or not manifest.branch_name or not manifest.commit_sha:
            raise StateError(
                "Ambiguous pull-request creation lacks durable repository, branch, or commit "
                "evidence"
            )
        self._trip_publication_breaker(
            source="publication:pull_request_creation_ambiguous",
            reason=(
                "A pull-request creation attempt has no durably resolved canonical PR identity; "
                "autonomous publication is stopped so the attempt cannot be duplicated"
            ),
            evidence={
                "repository": manifest.candidate.repository,
                "branch": manifest.branch_name,
                "commit_sha": manifest.commit_sha,
                "error_type": error_type,
            },
        )

    def _stop_ambiguous_pull_request_creation(self, manifest: RunManifest) -> None:
        self._trip_ambiguous_pull_request_creation(
            manifest,
            error_type="unresolved_retry",
        )
        raise PublicationResumeRequired(
            "The durable pull-request creation attempt has no resolved canonical PR. A second POST "
            "is forbidden; reconcile the exact head or retain SUBMITTING for operator review"
        )

    def _finalize_absent_pre_post_publication(
        self,
        manifest: RunManifest,
        *,
        login: str,
        head: str,
        reason: str,
        lease_guard: LeaseHeartbeatGuard,
    ) -> RunManifest:
        """Fail only after re-verifying that neither an exact PR nor branch remains."""

        if manifest.candidate is None or not manifest.branch_name:
            raise StateError("Absent publication compensation lacks durable branch evidence")
        if (
            manifest.publishing_api_origin is None
            or manifest.upstream_repository_id is None
            or manifest.upstream_repository_node_id is None
        ):
            raise StateError(
                "Absent publication compensation lacks durable publishing or upstream identity"
            )
        if (manifest.fork_repository_id is None) != (manifest.fork_repository_node_id is None):
            raise StateError("Absent publication compensation has partial immutable fork identity")
        if manifest.pull_request_creation_started:
            raise PublicationResumeRequired(
                "Post-intent publication state cannot use pre-POST absence compensation"
            )
        if manifest.pull_request_url is not None:
            raise PublicationResumeRequired(
                "A durable pull-request URL exists, so branch-only absence cannot be finalized"
            )
        expected_fork = f"{login}/{manifest.candidate.repository.split('/', 1)[1]}"
        commit_evidence = manifest.commit_sha or "not_persisted"
        fork_identity_bound = manifest.fork_repository_id is not None
        if not fork_identity_bound and manifest.commit_sha is not None:
            raise StateError(
                "Absent publication compensation has a commit without immutable fork identity"
            )
        if not fork_identity_bound and any(
            event["event_type"] in {"branch.pushed", "branch.reconciled"}
            for event in self.store.events(manifest.run_id)
        ):
            raise StateError(
                "Absent publication compensation has remote branch evidence without immutable "
                "fork identity"
            )
        identity_evidence = {
            "repository": manifest.candidate.repository,
            "publishing_api_origin": manifest.publishing_api_origin,
            "upstream_repository_id": str(manifest.upstream_repository_id),
            "upstream_repository_node_id": manifest.upstream_repository_node_id,
            "head": head,
            "fork": expected_fork,
            "fork_identity_state": "bound" if fork_identity_bound else "not_bound",
            "branch": manifest.branch_name,
            "commit_sha": commit_evidence,
        }
        if fork_identity_bound:
            assert manifest.fork_repository_id is not None
            assert manifest.fork_repository_node_id is not None
            identity_evidence.update(
                {
                    "fork_repository_id": str(manifest.fork_repository_id),
                    "fork_repository_node_id": manifest.fork_repository_node_id,
                }
            )
            self._assert_compensation_remote_identities(
                manifest,
                fork=expected_fork,
                lease_guard=lease_guard,
            )
        lease_guard.assert_owned()
        existing_pr = self.github.find_pull_request(
            manifest.candidate.repository,
            head=head,
        )
        lease_guard.assert_owned()
        if existing_pr is not None:
            raise PublicationResumeRequired(
                "A pull request appeared while absent pre-POST state was being verified; "
                "reconcile its exact identity before finalization"
            )
        lease_guard.assert_owned()
        remote_sha = self.github.ref_sha(
            expected_fork,
            f"heads/{manifest.branch_name}",
        )
        lease_guard.assert_owned()
        if remote_sha is not None:
            raise PublicationResumeRequired(
                "The contribution branch exists, so absent pre-POST state cannot be finalized"
            )
        lease_guard.assert_owned()
        confirmed_absent_pr = self.github.find_pull_request(
            manifest.candidate.repository,
            head=head,
        )
        lease_guard.assert_owned()
        if confirmed_absent_pr is not None:
            raise PublicationResumeRequired(
                "A pull request appeared while absent pre-POST state was being confirmed; "
                "reconcile its exact identity before finalization"
            )
        if fork_identity_bound:
            self._assert_compensation_remote_identities(
                manifest,
                fork=expected_fork,
                lease_guard=lease_guard,
            )
        self.store.save(
            manifest,
            event="publication.absence.verified",
            details={
                **identity_evidence,
                "reason": reason,
            },
        )
        lease_guard.assert_owned()
        return self.store.finalize_publication_compensation(
            manifest,
            reason=reason,
            evidence={
                **identity_evidence,
                "pull_request": "absent",
                "remote_branch": "absent",
            },
        )

    def _assert_durable_compensation_marker(
        self,
        manifest: RunManifest,
        *,
        expected_fork: str,
    ) -> None:
        """Bind a recovery cleanup to its one exact immutable marker event."""

        reason = manifest.publication_compensation_reason
        if (
            reason is None
            or manifest.candidate is None
            or manifest.base_sha is None
            or manifest.branch_name is None
            or manifest.commit_sha is None
            or manifest.upstream_repository_id is None
            or manifest.upstream_repository_node_id is None
            or manifest.fork_repository_id is None
            or manifest.fork_repository_node_id is None
        ):
            raise StateError("Started publication compensation lacks durable marker evidence")
        self.store.verify_event_chains(run_id=manifest.run_id)
        events = tuple(self.store.events(manifest.run_id))
        marker_types = {
            "pre_pr_base_moved": "publication.base_moved_before_pull_request",
            "pre_pr_policy_stale": "publication.policy_stale_before_pull_request",
            "created_pr_base_moved": "publication.compensation.started",
        }
        try:
            marker_type = marker_types[reason]
        except KeyError:
            raise StateError("Unsupported publication compensation reason") from None
        markers = tuple(
            (index, event)
            for index, event in enumerate(events)
            if event["event_type"] == marker_type
        )
        if len(markers) != 1:
            raise StateError("Started publication compensation lacks one exact marker event")
        marker_index, marker = markers[0]
        try:
            details = json.loads(marker["details"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise StateError("Publication compensation marker is malformed") from exc
        if not isinstance(details, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in details.items()
        ):
            raise StateError("Publication compensation marker is malformed")
        expected_common = {
            "fork": expected_fork,
            "fork_repository_id": str(manifest.fork_repository_id),
            "fork_repository_node_id": manifest.fork_repository_node_id,
            "upstream_repository_id": str(manifest.upstream_repository_id),
            "upstream_repository_node_id": manifest.upstream_repository_node_id,
            "branch": manifest.branch_name,
            "commit_sha": manifest.commit_sha,
        }
        if reason == "pre_pr_base_moved":
            if set(details) != {
                "approved_base_sha",
                "current_base_sha",
                *expected_common,
            } or any(details.get(key) != value for key, value in expected_common.items()):
                raise StateError("Pre-PR base compensation marker differs from durable intent")
            current_base = _validated_git_sha(
                details["current_base_sha"],
                field="compensation marker current base SHA",
            )
            if (
                details["approved_base_sha"].casefold() != manifest.base_sha.casefold()
                or current_base == manifest.base_sha.casefold()
            ):
                raise StateError("Pre-PR base compensation marker lacks an exact base race")
        elif reason == "pre_pr_policy_stale":
            expected = {
                "repository": manifest.candidate.repository,
                **expected_common,
            }
            if details != expected:
                raise StateError("Pre-PR policy compensation marker differs from durable intent")
        else:
            if (
                manifest.pull_request_url is None
                or manifest.pull_request_node_id is None
                or manifest.publishing_api_origin is None
            ):
                raise StateError("Created-PR compensation lacks its durable canonical URL")
            repository, number = parse_pull_request_url(
                manifest.pull_request_url,
                api_origin=manifest.publishing_api_origin,
            )
            expected = {
                "reason": reason,
                "url": manifest.pull_request_url,
                "pull_request_node_id": manifest.pull_request_node_id,
                "repository": repository,
                "number": str(number),
                **expected_common,
                "approved_base_sha": manifest.base_sha,
                "returned_base_sha": details.get("returned_base_sha", ""),
            }
            if details != expected:
                raise StateError("Created-PR compensation marker differs from durable intent")

            returned_base = _validated_git_sha(
                details["returned_base_sha"],
                field="compensation marker returned base SHA",
            )
            if (
                details["approved_base_sha"].casefold() != manifest.base_sha.casefold()
                or returned_base == manifest.base_sha.casefold()
            ):
                raise StateError("Created-PR compensation marker lacks an exact base race")

        event_types = tuple(event["event_type"] for event in events[:marker_index])
        branch_evidence_types = {"branch.pushed", "branch.reconciled"}
        if "publication.intent.begun" not in event_types or not branch_evidence_types.intersection(
            event_types
        ):
            raise StateError("Publication compensation marker precedes durable remote intent")
        branch_events = tuple(
            event for event in events[:marker_index] if event["event_type"] in branch_evidence_types
        )
        if len(branch_events) != 1:
            raise StateError("Publication compensation lacks one exact branch event")
        try:
            branch_details = json.loads(branch_events[0]["details"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise StateError("Publication compensation branch evidence is malformed") from exc
        if branch_details != expected_common:
            raise StateError("Publication compensation branch differs from immutable intent")
        if reason == "created_pr_base_moved":
            response_events = tuple(
                (index, event)
                for index, event in enumerate(events[:marker_index])
                if event["event_type"] == "pull_request.created.response"
            )
            rejected_events = tuple(
                (index, event)
                for index, event in enumerate(events[:marker_index])
                if event["event_type"] == "pull_request.created.rejected"
            )
            if len(response_events) != 1 or len(rejected_events) != 1:
                raise StateError("Created-PR compensation lacks one exact response and rejection")
            response_index, response_event = response_events[0]
            rejected_index, rejected_event = rejected_events[0]
            if response_index >= rejected_index:
                raise StateError("Created-PR compensation evidence is out of order")
            try:
                response = json.loads(response_event["details"])
                rejection = json.loads(rejected_event["details"])
            except (TypeError, json.JSONDecodeError) as exc:
                raise StateError("Created-PR compensation evidence is malformed") from exc
            if not isinstance(response, dict) or not isinstance(rejection, dict):
                raise StateError("Created-PR compensation evidence is malformed")
            expected_response = {
                "url": details["url"],
                "repository": details["repository"],
                "number": details["number"],
                "state": "open",
                "head_sha": details["commit_sha"],
                "base_sha": details["returned_base_sha"],
                "pull_request_node_id": details["pull_request_node_id"],
                "upstream_repository_id": details["upstream_repository_id"],
                "upstream_repository_node_id": details["upstream_repository_node_id"],
                "fork_repository_id": details["fork_repository_id"],
                "fork_repository_node_id": details["fork_repository_node_id"],
            }
            if response != expected_response:
                raise StateError("Created-PR response differs from its compensation marker")
            expected_rejection_keys = {
                "url",
                "mismatches",
                "expected_base_sha",
                "returned_base_sha",
            }
            if set(rejection) != expected_rejection_keys or not all(
                isinstance(value, str) for value in rejection.values()
            ):
                raise StateError("Created-PR rejection evidence is malformed")
            mismatches = tuple(mismatch.strip() for mismatch in rejection["mismatches"].split(","))
            if (
                rejection["url"] != details["url"]
                or rejection["expected_base_sha"].casefold()
                != details["approved_base_sha"].casefold()
                or rejection["returned_base_sha"].casefold()
                != details["returned_base_sha"].casefold()
                or "base commit" not in mismatches
            ):
                raise StateError("Created-PR rejection does not prove the exact base race")

    def _resume_started_compensation(
        self,
        manifest: RunManifest,
        *,
        lease_guard: LeaseHeartbeatGuard,
    ) -> RunManifest:
        """Idempotently reduce exact marked remote state despite constructive gate drift."""

        reason = manifest.publication_compensation_reason
        if (
            manifest.status != RunStatus.SUBMITTING
            or reason is None
            or manifest.candidate is None
            or manifest.repository is None
            or manifest.base_sha is None
            or not manifest.branch_name
            or not manifest.commit_sha
            or not manifest.publishing_api_origin
            or manifest.upstream_repository_id is None
            or manifest.upstream_repository_node_id is None
            or manifest.fork_repository_id is None
            or manifest.fork_repository_node_id is None
        ):
            raise StateError("Started publication compensation lacks durable evidence")
        candidate_repository = manifest.candidate.repository
        context = _durable_publication_context(
            self.config,
            manifest,
            login=self.github.authenticated_login(),
            api_origin=self.github.api_origin,
        )
        login = context.login
        head = f"{login}:{manifest.branch_name}"
        expected_fork = f"{login}/{manifest.candidate.repository.split('/', 1)[1]}"
        self._assert_durable_compensation_marker(
            manifest,
            expected_fork=expected_fork,
        )
        self._assert_compensation_remote_identities(
            manifest,
            fork=expected_fork,
            lease_guard=lease_guard,
        )

        if reason in {"pre_pr_base_moved", "pre_pr_policy_stale"}:
            if manifest.pull_request_url is not None or manifest.pull_request_creation_started:
                raise StateError("Pre-PR compensation contains pull-request creation evidence")
            lease_guard.assert_owned()
            existing_pr = self.github.find_pull_request(
                manifest.candidate.repository,
                head=head,
            )
            lease_guard.assert_owned()
            if existing_pr is not None:
                self._trip_publication_breaker(
                    source="publication:unexpected_pr_during_pre_pr_compensation",
                    reason=(
                        "A pull request exists for a branch whose pre-PR cleanup was already "
                        "durably started"
                    ),
                    evidence={
                        "repository": manifest.candidate.repository,
                        "head": head,
                        "url": existing_pr,
                    },
                )
                raise PublicationResumeRequired(
                    "A pull request exists for a durably marked pre-PR compensation; autonomous "
                    "cleanup is unsafe"
                )
            remote_sha = self.github.ref_sha(
                expected_fork,
                f"heads/{manifest.branch_name}",
            )
            lease_guard.assert_owned()
            if remote_sha is not None:
                remote_commit = _validated_git_sha(
                    remote_sha,
                    field="remote compensation branch SHA",
                )
                if remote_commit != manifest.commit_sha.casefold():
                    self._trip_publication_breaker(
                        source="publication:compensation_branch_mismatch",
                        reason="A durably compensating branch changed before cleanup",
                        evidence={
                            "fork": expected_fork,
                            "branch": manifest.branch_name,
                            "expected_head_sha": manifest.commit_sha,
                            "returned_head_sha": remote_commit,
                        },
                    )
                    raise PublicationResumeRequired(
                        "The durably compensating branch no longer matches exact publication intent"
                    )

                def assert_pull_request_absent_before_branch_delete() -> None:
                    lease_guard.assert_owned()
                    appeared_pr = self.github.find_pull_request(
                        candidate_repository,
                        head=head,
                    )
                    lease_guard.assert_owned()
                    if appeared_pr is not None:
                        self._trip_publication_breaker(
                            source="publication:unexpected_pr_during_pre_pr_compensation",
                            reason=(
                                "A pull request appeared immediately before a durably marked "
                                "pre-PR branch cleanup"
                            ),
                            evidence={
                                "repository": candidate_repository,
                                "head": head,
                                "url": appeared_pr,
                            },
                        )
                        raise PublicationResumeRequired(
                            "A pull request appeared immediately before pre-PR branch deletion; "
                            "the exact branch was retained for reconciliation"
                        )

                self._compensate_branch_only(
                    manifest,
                    fork=expected_fork,
                    branch=manifest.branch_name,
                    commit_sha=manifest.commit_sha,
                    lease_guard=lease_guard,
                    before_mutation=assert_pull_request_absent_before_branch_delete,
                )
            return self._finalize_absent_pre_post_publication(
                manifest,
                login=login,
                head=head,
                reason=f"verified recovery of {reason.replace('_', '-')} compensation",
                lease_guard=lease_guard,
            )

        if (
            reason != "created_pr_base_moved"
            or manifest.pull_request_url is None
            or manifest.pull_request_node_id is None
        ):
            raise StateError("Created-PR compensation lacks its durable canonical URL")
        repository, number = parse_pull_request_url(
            manifest.pull_request_url,
            api_origin=manifest.publishing_api_origin,
        )
        if repository.casefold() != manifest.candidate.repository.casefold():
            raise StateError("Compensating pull request belongs to a different repository")
        lease_guard.assert_owned()
        details = self.github.get_pull_request(repository, number)
        lease_guard.assert_owned()
        identity = {
            "pull request node": (details.node_id, manifest.pull_request_node_id),
            "canonical URL": (details.html_url, manifest.pull_request_url),
            "repository": (
                details.repository.casefold(),
                manifest.candidate.repository.casefold(),
            ),
            "head branch": (details.head_ref, manifest.branch_name),
            "head label": (details.head_label.casefold(), head.casefold()),
            "head repository": (
                details.head_repository.casefold(),
                expected_fork.casefold(),
            ),
            "head commit": (
                details.head_sha.casefold(),
                manifest.commit_sha.casefold(),
            ),
        }
        mismatches = tuple(
            name for name, (actual, expected) in identity.items() if actual != expected
        )
        if mismatches:
            self._trip_publication_breaker(
                source="publication:compensation_identity_mismatch",
                reason=(
                    "A durably compensating pull request no longer has its exact publication "
                    "identity"
                ),
                evidence={
                    "url": manifest.pull_request_url,
                    "mismatches": ",".join(mismatches),
                    "returned_head_sha": details.head_sha,
                },
            )
            raise PublicationResumeRequired(
                "The durably compensating pull request no longer matches exact publication intent"
            )
        if details.merged:
            self.store.save(
                manifest,
                event="pull_request.compensation.reconciled",
                details={
                    "url": manifest.pull_request_url,
                    "pull_request_node_id": manifest.pull_request_node_id,
                    "state": "merged",
                    "head_sha": details.head_sha,
                    "upstream_repository_id": str(manifest.upstream_repository_id),
                    "upstream_repository_node_id": manifest.upstream_repository_node_id,
                    "fork_repository_id": str(manifest.fork_repository_id),
                    "fork_repository_node_id": manifest.fork_repository_node_id,
                },
            )
            lease_guard.assert_owned()
            return self.store.finalize_merged_publication_compensation(
                manifest,
                pull_request_url=manifest.pull_request_url,
                reason="exact compensating PR merged and is lifecycle-managed",
            )
        if details.state not in {"open", "closed"}:
            raise PublicationResumeRequired(
                "Created-PR compensation has an unsupported remote state"
            )
        self._compensate_created_pull_request(
            manifest,
            details,
            fork=expected_fork,
            branch=manifest.branch_name,
            commit_sha=manifest.commit_sha,
            lease_guard=lease_guard,
        )
        lease_guard.assert_owned()
        confirmed = self.github.get_pull_request(repository, number)
        lease_guard.assert_owned()
        confirmed_mismatches = {
            "pull request node": (confirmed.node_id, manifest.pull_request_node_id),
            "canonical URL": (confirmed.html_url, manifest.pull_request_url),
            "repository": (
                confirmed.repository.casefold(),
                manifest.candidate.repository.casefold(),
            ),
            "head branch": (confirmed.head_ref, manifest.branch_name),
            "head repository": (
                confirmed.head_repository.casefold(),
                expected_fork.casefold(),
            ),
            "head commit": (
                confirmed.head_sha.casefold(),
                manifest.commit_sha.casefold(),
            ),
            "state": (confirmed.state, "closed"),
            "merged": (confirmed.merged, False),
        }
        if any(actual != expected for actual, expected in confirmed_mismatches.values()):
            raise PublicationResumeRequired(
                "GitHub did not confirm exact closed-unmerged compensation state"
            )
        remaining = self.github.ref_sha(
            expected_fork,
            f"heads/{manifest.branch_name}",
        )
        lease_guard.assert_owned()
        if remaining is not None:
            raise PublicationResumeRequired(
                "Created-PR compensation did not remove the exact contribution branch"
            )
        lease_guard.assert_owned()
        final_details = self.github.get_pull_request(repository, number)
        lease_guard.assert_owned()
        final_mismatches = {
            "pull request node": (final_details.node_id, manifest.pull_request_node_id),
            "canonical URL": (final_details.html_url, manifest.pull_request_url),
            "repository": (
                final_details.repository.casefold(),
                manifest.candidate.repository.casefold(),
            ),
            "head branch": (final_details.head_ref, manifest.branch_name),
            "head label": (final_details.head_label.casefold(), head.casefold()),
            "head repository": (
                final_details.head_repository.casefold(),
                expected_fork.casefold(),
            ),
            "head commit": (
                final_details.head_sha.casefold(),
                manifest.commit_sha.casefold(),
            ),
            "state": (final_details.state, "closed"),
            "merged": (final_details.merged, False),
        }
        if any(actual != expected for actual, expected in final_mismatches.values()):
            raise PublicationResumeRequired(
                "The exact compensating pull request changed during final branch verification"
            )
        return self.store.finalize_publication_compensation(
            manifest,
            reason="verified recovery of created-PR base-race compensation",
            evidence={
                "url": manifest.pull_request_url,
                "repository": repository,
                "number": str(number),
                "pull_request_node_id": manifest.pull_request_node_id,
                "upstream_repository_id": str(manifest.upstream_repository_id),
                "upstream_repository_node_id": manifest.upstream_repository_node_id,
                "fork": expected_fork,
                "fork_repository_id": str(manifest.fork_repository_id),
                "fork_repository_node_id": manifest.fork_repository_node_id,
                "branch": manifest.branch_name,
                "commit_sha": manifest.commit_sha,
                "pull_request": "closed_unmerged",
                "remote_branch": "absent",
            },
        )

    def reconcile_submitting(self, run_id: str) -> RunManifest:
        """Reconcile only an already-persisted publication intent; never create remote state."""

        with LeaseHeartbeatGuard(
            self.store,
            PUBLICATION_LEASE_NAME,
            ttl=PUBLICATION_LEASE_TTL,
            heartbeat_interval=PUBLICATION_HEARTBEAT_INTERVAL,
        ) as lease_guard:
            return self._reconcile_submitting(
                run_id,
                lease_guard=lease_guard,
            )

    def _reconcile_submitting(
        self,
        run_id: str,
        *,
        lease_guard: LeaseHeartbeatGuard,
    ) -> RunManifest:
        """Reconcile under an already-owned publication lease."""

        lease_guard.assert_owned()
        manifest = self.store.get(run_id)
        if manifest.status != RunStatus.SUBMITTING:
            raise StateError(f"Run {run_id} cannot be reconciled from {manifest.status.value}")
        if (
            manifest.candidate is None
            or manifest.repository is None
            or manifest.proposal is None
            or manifest.base_sha is None
            or not manifest.branch_name
        ):
            raise StateError(f"Submitting run {run_id} lacks durable publication evidence")
        if manifest.publication_compensation_reason is not None:
            return self._resume_started_compensation(
                manifest,
                lease_guard=lease_guard,
            )
        context = _durable_publication_context(
            self.config,
            manifest,
            login=self.github.authenticated_login(),
            api_origin=self.github.api_origin,
        )
        login = context.login
        publication_hold = self.store.publication_gate_hold(run_id)
        if publication_hold is not None and (
            publication_hold.deployment_fingerprint is None
            or publication_hold.outcome_corpus_cursor is None
        ):
            raise StateError(
                "Publication gate hold predates schema-v6 upstream-outcome authority; "
                "automatic recovery is forbidden"
            )
        if publication_hold is None:
            self._require_exact_review_recovery(manifest)
        lease_guard.assert_owned()
        manifest = self.store.begin_publication(
            manifest,
            manifest.candidate.repository,
            branch_name=manifest.branch_name,
            publishing_login=context.login,
            publishing_api_origin=context.api_origin,
            commit_author_name=context.author_name,
            commit_author_email=context.author_email,
            commit_committer_name=context.committer_name,
            commit_committer_email=context.committer_email,
            publication_draft=context.draft,
            publication_ready_for_review=context.ready_for_review,
            max_per_utc_day=self.config.publishing.max_new_pull_requests_per_day,
            repository_cooldown=timedelta(days=self.config.publishing.repository_cooldown_days),
            # Reconciliation adopts already-durable state without constructive mutations, so
            # it must not proffer the hold's anchored cursors as current rollout authority:
            # they may legitimately lag the live corpus after a crash. The store validates
            # the hold's identity instead, and any remote mutation would still revalidate
            # its own hold currency immediately before acting.
            evaluation_corpus_cursor=None,
            evaluation_deployment_fingerprint=None,
            outcome_corpus_cursor=None,
        )
        assert manifest.candidate is not None
        assert manifest.branch_name is not None
        if not manifest.commit_sha:
            if manifest.pull_request_creation_started:
                self._stop_ambiguous_pull_request_creation(manifest)
            raise PublicationResumeRequired(
                f"Submitting run {run_id} has no stored commit or pull request yet"
            )
        head = f"{login}:{manifest.branch_name}"
        existing_pr = manifest.pull_request_url
        if existing_pr is None:
            existing_pr = self.github.find_pull_request(
                manifest.candidate.repository,
                head=head,
            )
        if not existing_pr:
            if manifest.pull_request_creation_started:
                self._stop_ambiguous_pull_request_creation(manifest)
            raise PublicationResumeRequired(
                f"Submitting run {run_id} has no matching pull request; "
                "its pre-POST durable publication intent can be resumed idempotently"
            )
        return self._accept_existing_pull_request(
            manifest,
            existing_pr,
            login=login,
            head=head,
            allow_remote_mutation=False,
            allow_new_repository_identity=False,
            lease_guard=lease_guard,
        )

    def _reject_reconciled_pull_request(
        self,
        manifest: RunManifest,
        details: PullRequestDetails,
        *,
        mismatches: tuple[str, ...],
    ) -> None:
        """Retain exact discovered identity while stopping on semantic drift."""

        if manifest.pull_request_url is None:
            raise StateError("Reconciled mismatch lacks a durable canonical pull-request URL")
        self.store.save(
            manifest,
            event="pull_request.reconciliation.rejected",
            details={
                "url": manifest.pull_request_url,
                "repository": details.repository,
                "number": str(details.number),
                "mismatches": ", ".join(mismatches),
            },
        )
        self._trip_publication_breaker(
            source="publication:reconciled_pr_semantic_mismatch",
            reason=(
                "An exact pull request discovered for durable publication intent differs from "
                "its approved semantics; autonomous publication is stopped"
            ),
            evidence={
                "url": manifest.pull_request_url,
                "repository": details.repository,
                "number": str(details.number),
                "mismatches": ",".join(mismatches),
            },
        )
        raise PublicationResumeRequired(
            "The exact pull request differs from durable publication intent: "
            + ", ".join(mismatches)
        )

    def _accept_existing_pull_request(
        self,
        manifest: RunManifest,
        pull_request_url: str,
        *,
        login: str,
        head: str,
        allow_remote_mutation: bool,
        allow_new_repository_identity: bool,
        lease_guard: LeaseHeartbeatGuard,
        review_recovery_authority: ExactHumanApproval | None = None,
    ) -> RunManifest:
        """Bind exact remote PR evidence to one durable intent before lifecycle monitoring."""

        if manifest.status != RunStatus.SUBMITTING:
            raise StateError(
                "An existing pull request can only be accepted from a durable SUBMITTING intent"
            )
        if not manifest.commit_sha:
            raise PolicyError(
                "Cannot reconcile an existing pull request without a stored commit SHA"
            )
        if (
            manifest.candidate is None
            or manifest.repository is None
            or manifest.proposal is None
            or manifest.base_sha is None
            or not manifest.publishing_api_origin
            or not manifest.branch_name
        ):
            raise PolicyError(
                "Cannot reconcile a pull request without complete publication evidence"
            )
        repository, number = parse_pull_request_url(
            pull_request_url,
            api_origin=manifest.publishing_api_origin,
        )
        if repository.casefold() != manifest.candidate.repository.casefold():
            raise PolicyError("Existing pull request belongs to a different repository")
        self._bind_or_validate_upstream_identity(
            manifest,
            allow_new=False,
            lease_guard=lease_guard,
        )
        expected_fork = f"{login}/{manifest.candidate.repository.split('/', 1)[1]}"
        self._bind_or_validate_fork_identity(
            manifest,
            fork=expected_fork,
            allow_new=allow_new_repository_identity,
            lease_guard=lease_guard,
        )
        details = self.github.get_pull_request(repository, number)
        if manifest.pull_request_url is not None and manifest.pull_request_node_id is None:
            raise StateError(
                "Existing publication evidence predates immutable pull-request identity; "
                "autonomous recovery is forbidden"
            )
        identity_expected = {
            "canonical URL": (details.html_url, pull_request_url),
            "head branch": (details.head_ref, manifest.branch_name),
            "head label": (details.head_label.casefold(), head.casefold()),
            "head repository": (
                details.head_repository.casefold(),
                expected_fork.casefold(),
            ),
            "head commit": (
                details.head_sha.casefold(),
                manifest.commit_sha.casefold(),
            ),
        }
        if manifest.pull_request_node_id is not None:
            identity_expected["pull request node"] = (
                details.node_id,
                manifest.pull_request_node_id,
            )
        identity_mismatches = tuple(
            name for name, (actual, wanted) in identity_expected.items() if actual != wanted
        )
        if identity_mismatches:
            self._trip_publication_breaker(
                source="publication:discovered_pr_identity_mismatch",
                reason=(
                    "A pull request found for a durable publication branch does not have its exact "
                    "repository/head identity; autonomous publication is stopped"
                ),
                evidence={
                    "url": pull_request_url,
                    "repository": details.repository,
                    "number": str(details.number),
                    "mismatches": ",".join(identity_mismatches),
                    "expected_head_sha": manifest.commit_sha,
                    "returned_head_sha": details.head_sha,
                },
            )
            raise PublicationResumeRequired(
                "A pull request was found for the publication branch, but its exact head identity "
                "does not match durable intent. No second POST will be attempted"
            )

        if manifest.pull_request_url is None:
            manifest.pull_request_url = pull_request_url
            manifest.pull_request_node_id = details.node_id
            lease_guard.assert_owned()
            self.store.save(
                manifest,
                event="pull_request.discovered",
                details={
                    "url": pull_request_url,
                    "repository": repository,
                    "number": str(number),
                    "head_sha": details.head_sha,
                    "pull_request_node_id": details.node_id,
                    "upstream_repository_id": str(manifest.upstream_repository_id),
                    "upstream_repository_node_id": str(manifest.upstream_repository_node_id),
                    "fork_repository_id": str(manifest.fork_repository_id),
                    "fork_repository_node_id": str(manifest.fork_repository_node_id),
                },
            )
        elif manifest.pull_request_url != pull_request_url:
            raise StateError("Reconciled pull request differs from its durable canonical URL")

        expected: dict[str, tuple[object, object]] = {
            "base branch": (details.base_ref, manifest.repository.default_branch),
            "base commit": (details.base_sha.casefold(), manifest.base_sha.casefold()),
            "title": (details.title, manifest.proposal.pull_request_title),
            "body": (details.body, manifest.proposal.pull_request_body),
        }
        if not _required_publication_ready_for_review(manifest):
            expected["draft state"] = (
                details.draft,
                _required_publication_draft(manifest),
            )
        remote_sha = self.github.ref_sha(expected_fork, f"heads/{manifest.branch_name}")
        if details.state == "open" and (
            remote_sha is None or remote_sha.casefold() != manifest.commit_sha.casefold()
        ):
            expected["remote head branch"] = (remote_sha, manifest.commit_sha.casefold())
        mismatches = tuple(name for name, (actual, wanted) in expected.items() if actual != wanted)
        lease_guard.assert_owned()
        self.store.save(
            manifest,
            event="pull_request.reconciled",
            details={
                "url": pull_request_url,
                "state": (
                    "merged"
                    if details.merged
                    else "closed_unmerged"
                    if details.state == "closed"
                    else "open"
                ),
                "base_sha": details.base_sha,
            },
        )

        if details.merged:
            lease_guard.assert_owned()
            self.store.transition(
                manifest,
                RunStatus.PR_OPEN,
                reason="exact existing merged PR reconciled for lifecycle management",
            )
            return manifest
        if details.state == "closed":
            self._trip_publication_breaker(
                source="publication:closed_unmerged_pr",
                reason=(
                    "An exact publication pull request was closed without merge; lifecycle "
                    "management is retained and autonomous publication is stopped for review"
                ),
                evidence={
                    "url": pull_request_url,
                    "repository": details.repository,
                    "number": str(details.number),
                    "head_sha": details.head_sha,
                    "closed_at": (
                        details.closed_at.isoformat() if details.closed_at else "unknown"
                    ),
                    "mismatches": ",".join(mismatches),
                },
            )
            lease_guard.assert_owned()
            self.store.transition(
                manifest,
                RunStatus.PR_OPEN,
                reason="exact existing closed-unmerged PR is lifecycle-managed",
            )
            return manifest
        if mismatches:
            self._reject_reconciled_pull_request(
                manifest,
                details,
                mismatches=mismatches,
            )
        if (
            review_recovery_authority is not None
            and allow_remote_mutation
            and details.draft
            and _required_publication_ready_for_review(manifest)
        ):
            self._validate_exact_review_recovery_payload(
                manifest,
                review_recovery_authority,
            )
        self._ensure_pull_request_ready_for_review(
            manifest,
            details,
            head=head,
            fork=expected_fork,
            allow_remote_mutation=allow_remote_mutation,
            lease_guard=lease_guard,
        )
        lease_guard.assert_owned()
        self.store.transition(
            manifest,
            RunStatus.PR_OPEN,
            reason="exact existing open PR reconciled",
        )
        return manifest

    def _compensate_stale_pre_pull_request_branch(
        self,
        manifest: RunManifest,
        *,
        fork: str,
        branch: str,
        commit_sha: str,
        lease_guard: LeaseHeartbeatGuard,
    ) -> None:
        """Durably remove the exact pushed branch after a proven pre-POST stale read."""

        assert manifest.candidate is not None
        lease_guard.assert_owned()
        manifest.publication_compensation_reason = "pre_pr_policy_stale"
        self.store.save(
            manifest,
            event="publication.policy_stale_before_pull_request",
            details={
                "repository": manifest.candidate.repository,
                "fork": fork,
                "fork_repository_id": str(manifest.fork_repository_id),
                "fork_repository_node_id": str(manifest.fork_repository_node_id),
                "upstream_repository_id": str(manifest.upstream_repository_id),
                "upstream_repository_node_id": str(manifest.upstream_repository_node_id),
                "branch": branch,
                "commit_sha": commit_sha,
            },
        )
        self._resume_started_compensation(
            manifest,
            lease_guard=lease_guard,
        )

    def _check_mutation_boundary_freshness(self, manifest: RunManifest) -> None:
        """Minimize, but cannot eliminate, GitHub's unavoidable pre-POST state race.

        GitHub offers no conditional multi-resource pull-request creation. Keep the issue read
        last within this policy snapshot. The caller then revalidates immutable repository
        identities and the exact contribution head before its local durable creation marker.
        """

        assert manifest.candidate and manifest.repository and manifest.base_sha
        if manifest.eligibility is None:
            raise PolicyError("Run is missing durable eligibility evidence")

        competing = self.github.search_competing_pull_requests(
            manifest.candidate.repository,
            manifest.candidate.number,
        )
        if competing:
            raise PolicyError(
                "A competing pull request appeared at the publication mutation boundary: "
                + competing[0]
            )

        repository = self.github.get_repository(manifest.repository.full_name)
        if (
            repository.full_name.casefold() != manifest.repository.full_name.casefold()
            or repository.default_branch != manifest.repository.default_branch
        ):
            raise PolicyError(
                "The upstream repository identity or default branch changed at the publication "
                "mutation boundary"
            )

        owner_policy_repository = f"{repository.full_name.split('/', 1)[0]}/.github"
        organization_ref = self.github.default_branch_sha_if_exists(owner_policy_repository)
        observed_organization_ref = organization_ref or "absent"
        expected_organization_ref = manifest.eligibility.evidence.get(
            POLICY_ORGANIZATION_REF_EVIDENCE_KEY
        )
        if (
            not expected_organization_ref
            or observed_organization_ref.casefold() != expected_organization_ref.casefold()
        ):
            raise PolicyError(
                "The organization policy repository moved at the publication mutation boundary"
            )

        current_base_sha = self.github.default_branch_sha(
            repository.full_name,
            repository.default_branch,
        )
        if current_base_sha.casefold() != manifest.base_sha.casefold():
            raise PolicyError("The upstream base branch moved at the publication mutation boundary")

        issue = self.github.get_issue(
            manifest.candidate.repository,
            manifest.candidate.number,
        )
        eligibility = DiscoveryService(self.config, self.github, self.store).evaluate(
            issue,
            repository,
            check_remote_policy=False,
            check_competing_pull_requests=False,
        )
        if not eligibility.eligible:
            reasons = "; ".join(eligibility.blockers)
            raise PolicyError(
                "Candidate no longer passes mutation-boundary eligibility: " + reasons
            )
        changed_issue_evidence = self._changed_issue_evidence(manifest.candidate, issue)
        if changed_issue_evidence:
            raise PolicyError(
                "Issue evidence changed at the publication mutation boundary ("
                + ", ".join(changed_issue_evidence)
                + "); approval is stale"
            )

    def _check_freshness(self, manifest: RunManifest) -> None:
        assert manifest.candidate and manifest.repository and manifest.base_sha
        issue = self.github.get_issue(manifest.candidate.repository, manifest.candidate.number)
        repository = self.github.get_repository(manifest.repository.full_name)
        if repository.full_name.casefold() != manifest.repository.full_name.casefold():
            raise PolicyError("The upstream repository identity changed; approval is stale")
        if repository.default_branch != manifest.repository.default_branch:
            raise PolicyError("The upstream default branch changed; approval is stale")

        current_sha = self.github.default_branch_sha(
            repository.full_name,
            repository.default_branch,
        )
        if current_sha.casefold() != manifest.base_sha.casefold():
            raise PolicyError("The upstream base branch moved; rerun validation and approval")
        eligibility = DiscoveryService(self.config, self.github, self.store).evaluate(
            issue,
            repository,
            repository_ref=current_sha,
        )
        self._assert_current_eligibility_evidence(manifest, eligibility)

        changed_issue_evidence = self._changed_issue_evidence(manifest.candidate, issue)
        if changed_issue_evidence:
            raise PolicyError(
                "Issue evidence changed after preparation ("
                + ", ".join(changed_issue_evidence)
                + "); approval is stale"
            )

        closing_repository = self.github.get_repository(manifest.repository.full_name)
        if (
            closing_repository.full_name.casefold() != manifest.repository.full_name.casefold()
            or closing_repository.default_branch != manifest.repository.default_branch
        ):
            raise PolicyError(
                "The upstream repository identity or default branch changed during freshness "
                "verification"
            )
        closing_issue = self.github.get_issue(
            manifest.candidate.repository,
            manifest.candidate.number,
        )
        closing_eligibility = DiscoveryService(self.config, self.github, self.store).evaluate(
            closing_issue,
            closing_repository,
            check_remote_policy=False,
        )
        if not closing_eligibility.eligible:
            reasons = "; ".join(closing_eligibility.blockers)
            raise PolicyError(
                "Candidate changed during publication freshness verification: " + reasons
            )
        closing_issue_changes = self._changed_issue_evidence(
            manifest.candidate,
            closing_issue,
        )
        if closing_issue_changes:
            raise PolicyError(
                "Issue evidence changed during publication freshness verification ("
                + ", ".join(closing_issue_changes)
                + "); approval is stale"
            )

        owner_policy_repository = f"{repository.full_name.split('/', 1)[0]}/.github"
        final_organization_ref = self.github.default_branch_sha_if_exists(
            owner_policy_repository,
        )
        observed_organization_ref = final_organization_ref or "absent"
        evaluated_organization_ref = eligibility.evidence.get(POLICY_ORGANIZATION_REF_EVIDENCE_KEY)
        if (
            not evaluated_organization_ref
            or observed_organization_ref.casefold() != evaluated_organization_ref.casefold()
        ):
            raise PolicyError(
                "The organization policy repository moved while policy evidence was fetched; "
                "retry publication"
            )

        final_repository = self.github.get_repository(manifest.repository.full_name)
        if (
            final_repository.full_name.casefold() != manifest.repository.full_name.casefold()
            or final_repository.default_branch != manifest.repository.default_branch
        ):
            raise PolicyError(
                "The upstream repository identity or default branch changed during final "
                "freshness verification"
            )
        final_issue = self.github.get_issue(
            manifest.candidate.repository,
            manifest.candidate.number,
        )
        final_eligibility = DiscoveryService(self.config, self.github, self.store).evaluate(
            final_issue,
            final_repository,
            check_remote_policy=False,
            check_competing_pull_requests=False,
        )
        if not final_eligibility.eligible:
            reasons = "; ".join(final_eligibility.blockers)
            raise PolicyError(
                "Candidate changed during final publication freshness verification: " + reasons
            )
        final_issue_changes = self._changed_issue_evidence(
            manifest.candidate,
            final_issue,
        )
        if final_issue_changes:
            raise PolicyError(
                "Issue evidence changed during final publication freshness verification ("
                + ", ".join(final_issue_changes)
                + "); approval is stale"
            )

        final_sha = self.github.default_branch_sha(
            final_repository.full_name,
            final_repository.default_branch,
        )
        if final_sha.casefold() != current_sha.casefold():
            raise PolicyError(
                "The upstream base branch moved while policy evidence was fetched; "
                "retry publication"
            )

    def _check_pre_pull_request_policy_freshness(self, manifest: RunManifest) -> None:
        """Re-read canonical issue, repository, and policy evidence before opening a PR."""

        try:
            self._check_freshness(manifest)
        except GitHubError as exc:
            raise PolicyError(
                "GitHub did not provide a complete stable final freshness snapshot"
            ) from exc
        except StateError as exc:
            assert manifest.candidate is not None
            expected_source = f"github_issue_discussion:{manifest.candidate.reference}"
            breaker = self.store.circuit_breaker_status()
            if not any(trigger.source == expected_source for trigger in breaker.active_triggers):
                raise
            raise PolicyError(
                "A trusted maintainer stop was observed in the final issue discussion"
            ) from exc

    @staticmethod
    def _changed_issue_evidence(
        recorded: IssueCandidate,
        current: IssueCandidate,
    ) -> list[str]:
        changed: list[str] = []
        if current.state.casefold() != recorded.state.casefold():
            changed.append("state")
        if current.title != recorded.title:
            changed.append("title")
        if current.body != recorded.body:
            changed.append("body")
        if {label.casefold() for label in current.labels} != {
            label.casefold() for label in recorded.labels
        }:
            changed.append("labels")
        if current.comments != recorded.comments or current.discussion != recorded.discussion:
            changed.append("discussion")
        if {assignee.casefold() for assignee in current.assignees} != {
            assignee.casefold() for assignee in recorded.assignees
        }:
            changed.append("assignment")
        if current.updated_at != recorded.updated_at:
            changed.append("updated timestamp")
        return changed

    @staticmethod
    def _assert_current_eligibility_evidence(
        manifest: RunManifest,
        eligibility: EligibilityResult,
        *,
        require_eligible: bool = True,
    ) -> None:
        if manifest.eligibility is None:
            raise PolicyError("Run is missing its recorded eligibility evidence")
        recorded_policy = manifest.eligibility.evidence.get(POLICY_SOURCES_EVIDENCE_KEY)
        current_policy = eligibility.evidence.get(POLICY_SOURCES_EVIDENCE_KEY)
        if not recorded_policy or not current_policy:
            raise PolicyError("Run is missing complete repository-policy freshness evidence")
        if recorded_policy != current_policy:
            raise PolicyError(
                "Repository or organization contribution policy changed; approval is stale"
            )
        for key in (
            LEGAL_POLICY_EVIDENCE_KEY,
            LEGAL_REQUIREMENTS_EVIDENCE_KEY,
            LEGAL_ATTESTATION_EVIDENCE_KEY,
        ):
            if manifest.eligibility.evidence.get(key) != eligibility.evidence.get(key):
                raise PolicyError(
                    "Repository legal requirements or attestation changed; approval is stale"
                )
        if require_eligible and not eligibility.eligible:
            reasons = "; ".join(eligibility.blockers)
            raise PolicyError(f"Candidate no longer passes deterministic eligibility: {reasons}")

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
        expected_clone_url = git_push_url(
            self.config.github.api_url,
            manifest.repository.full_name,
        )
        if manifest.repository.clone_url != expected_clone_url:
            raise PolicyError(
                "Stored repository clone URL is outside the configured GitHub origin; "
                "refusing workspace reconstruction"
            )
        if manifest.commit_sha:
            if not path.is_dir():
                raise PolicyError(
                    "Publication workspace containing the stored commit is missing; refusing "
                    "to reconstruct or push a different HEAD"
                )
            if path.is_symlink():
                raise PolicyError("Publication workspace cannot be a symlink")
            commit_sha = _validated_git_sha(manifest.commit_sha, field="stored commit SHA")
            head = _git(path, ["rev-parse", "--verify", "HEAD^{commit}"]).strip().casefold()
            if head != commit_sha:
                raise PolicyError(
                    "Publication workspace HEAD does not match the stored contribution commit"
                )
            self._validate_exact_commit(
                path,
                manifest,
                patch,
                commit_sha=commit_sha,
                require_clean=True,
            )
            manifest.commit_sha = commit_sha
            # A prior attempt committed before an uncertain push. The caller can reconcile or
            # push this exact commit without regenerating it.
            return None
        if path.is_dir():
            if path.is_symlink():
                raise PolicyError("Publication workspace cannot be a symlink")
            head = _git(path, ["rev-parse", "--verify", "HEAD^{commit}"]).strip().casefold()
            if head == manifest.base_sha.casefold():
                workspace = RepositoryWorkspace(path, manifest.base_sha)
                if workspace.diff_bytes() != patch:
                    raise PolicyError("Workspace diff no longer matches the approved artifact")
                return workspace
            if manifest.status != RunStatus.SUBMITTING:
                raise PolicyError("Publication workspace HEAD no longer matches the approved base")
            self._validate_exact_commit(
                path,
                manifest,
                patch,
                commit_sha=head,
                require_clean=True,
            )
            # A crash can occur after Git creates the commit but before commit_sha is saved.
            # Recover only the unique clean commit that is exactly derivable from durable intent.
            manifest.commit_sha = head
            return None
        workspace = RepositoryWorkspace.clone(
            manifest.repository.clone_url,
            manifest.base_sha,
            path,
        )
        _git_apply(workspace.path, patch)
        if workspace.diff_bytes() != patch:
            raise PolicyError("Reconstructed diff does not match the approved artifact")
        return workspace

    def _commit(
        self,
        workspace: RepositoryWorkspace,
        manifest: RunManifest,
        patch: bytes,
    ) -> str:
        proposal = manifest.proposal
        assert proposal is not None and manifest.base_sha is not None
        name = manifest.commit_author_name
        email = manifest.commit_author_email
        if (
            not name
            or not email
            or manifest.commit_committer_name != name
            or manifest.commit_committer_email != email
        ):
            raise PolicyError("Run is missing its exact resolved Git commit identity")
        _validate_git_identity_credentials(
            self.config,
            name,
            email,
            manifest.commit_committer_name,
            manifest.commit_committer_email,
        )
        head = _git(
            workspace.path,
            ["rev-parse", "--verify", "HEAD^{commit}"],
        ).strip()
        if head.casefold() != manifest.base_sha.casefold():
            raise PolicyError("Publication workspace HEAD moved from the approved base")
        if workspace.diff_bytes() != patch:
            raise PolicyError("Workspace diff changed after publication preflight")
        _git(workspace.path, ["add", "--all"])
        head = _git(
            workspace.path,
            ["rev-parse", "--verify", "HEAD^{commit}"],
        ).strip()
        if head.casefold() != manifest.base_sha.casefold():
            raise PolicyError("Publication workspace HEAD moved while staging the approved patch")
        if _git_diff_bytes(workspace.path, cached=True) != patch:
            raise PolicyError("Staged diff does not match the approved patch")
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
        commit_sha = (
            _git(
                workspace.path,
                ["rev-parse", "--verify", "HEAD^{commit}"],
            )
            .strip()
            .casefold()
        )
        self._validate_exact_commit(
            workspace.path,
            manifest,
            patch,
            commit_sha=commit_sha,
            require_clean=True,
        )
        return commit_sha

    def _validate_exact_commit(
        self,
        workspace: Path,
        manifest: RunManifest,
        patch: bytes,
        *,
        commit_sha: str,
        require_clean: bool,
    ) -> None:
        """Bind a local commit to the exact durable publication intent."""

        proposal = manifest.proposal
        if proposal is None or manifest.base_sha is None:
            raise PolicyError("Run lacks the proposal or base needed to validate its commit")
        commit = _validated_git_sha(commit_sha, field="contribution commit SHA")
        base = _validated_git_sha(manifest.base_sha, field="approved base SHA")
        ancestry = (
            _git(
                workspace,
                ["rev-list", "--parents", "--max-count=1", commit],
            )
            .strip()
            .casefold()
            .split()
        )
        if ancestry != [commit, base]:
            raise PolicyError("Contribution commit is not a direct child of the approved base")
        message = _git(
            workspace,
            ["show", "--no-patch", "--format=%B", commit],
        ).rstrip("\n")
        if message != proposal.commit_message:
            raise PolicyError("Contribution commit message differs from durable intent")
        identity = (
            _git(
                workspace,
                ["show", "--no-patch", "--format=%an%x00%ae%x00%cn%x00%ce", commit],
            )
            .rstrip("\n")
            .split("\0")
        )
        expected_identity = [
            manifest.commit_author_name,
            manifest.commit_author_email,
            manifest.commit_committer_name,
            manifest.commit_committer_email,
        ]
        if identity != expected_identity:
            raise PolicyError("Contribution commit identity differs from durable intent")
        if _git_diff_bytes(workspace, old=base, new=commit) != patch:
            raise PolicyError("Contribution commit diff does not match the approved patch")
        if require_clean:
            status = _git(
                workspace,
                ["status", "--porcelain=v1", "--untracked-files=all"],
            )
            if status:
                raise PolicyError("Committed publication workspace is not clean")

    def _push(
        self,
        workspace: Path,
        fork: str,
        branch: str,
        commit_sha: str,
        *,
        before_mutation: Callable[[], None],
    ) -> None:
        commit = _validated_git_sha(commit_sha, field="contribution commit SHA")
        branch = _validated_git_branch(branch)
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
            before_mutation()
            _git(
                workspace,
                [
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "http.followRedirects=false",
                    "push",
                    f"--force-with-lease=refs/heads/{branch}:",
                    git_push_url(self.github.api_origin, fork),
                    f"{commit}:refs/heads/{branch}",
                ],
                extra_env={
                    "GIT_ASKPASS": str(askpass),
                    "GIT_TERMINAL_PROMPT": "0",
                    "AUTOCONTRIBUTE_GIT_TOKEN": self.github.token,
                },
            )

    def _delete_remote_branch(
        self,
        fork: str,
        branch: str,
        commit_sha: str,
        *,
        expected_repository_id: int,
        expected_repository_node_id: str,
        lease_guard: LeaseHeartbeatGuard,
        before_mutation: Callable[[], None],
    ) -> None:
        """Delete only ``branch`` at ``commit_sha`` and verify that it is absent."""

        branch = _validated_git_branch(branch)
        commit = _validated_git_sha(commit_sha, field="compensation commit SHA")
        ref = f"heads/{branch}"
        lease_guard.assert_owned()
        current = self.github.ref_sha(fork, ref)
        lease_guard.assert_owned()
        if current is None:
            return
        current = _validated_git_sha(current, field="remote compensation branch SHA")
        if current != commit:
            raise PolicyError(
                "Remote contribution branch changed; refusing compensation branch deletion"
            )

        lease_guard.assert_owned()
        with tempfile.TemporaryDirectory(prefix="autocontribute-compensation-") as temporary:
            repository = Path(temporary) / "repository"
            repository.mkdir(mode=0o700)
            _git(repository, ["init", "--quiet"])
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
            lease_guard.assert_owned()
            self.github.assert_repository_identity(
                fork,
                expected_database_id=expected_repository_id,
                expected_node_id=expected_repository_node_id,
            )
            lease_guard.assert_owned()
            before_mutation()
            lease_guard.assert_owned()
            _git(
                repository,
                [
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "http.followRedirects=false",
                    "push",
                    f"--force-with-lease=refs/heads/{branch}:{commit}",
                    git_push_url(self.github.api_origin, fork),
                    f":refs/heads/{branch}",
                ],
                extra_env={
                    "GIT_ASKPASS": str(askpass),
                    "GIT_TERMINAL_PROMPT": "0",
                    "AUTOCONTRIBUTE_GIT_TOKEN": self.github.token,
                },
            )
        lease_guard.assert_owned()

        lease_guard.assert_owned()
        remaining = self.github.ref_sha(fork, ref)
        lease_guard.assert_owned()
        if remaining is not None:
            raise RepositoryError(
                "GitHub did not verify that the compensated contribution branch is absent"
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


def _git_diff_bytes(
    workspace: Path,
    *,
    cached: bool = False,
    old: str | None = None,
    new: str | None = None,
) -> bytes:
    """Render the same binary-safe patch bytes used by preparation."""

    arguments = [
        "diff",
        "--binary",
        "--full-index",
        "--no-color",
        "--no-ext-diff",
        "--no-renames",
        "--src-prefix=a/",
        "--dst-prefix=b/",
    ]
    if cached:
        if old is not None or new is not None:
            raise ValueError("cached diffs cannot specify revisions")
        arguments.extend(["--cached", "HEAD", "--"])
    else:
        if old is None or new is None:
            raise ValueError("committed diffs require both revisions")
        arguments.extend([old, new, "--"])
    return _git_bytes(workspace, arguments)


def _git_bytes(workspace: Path, arguments: list[str]) -> bytes:
    environment = _git_environment()
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=workspace,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RepositoryError(f"Git operation failed to start: {type(exc).__name__}") from exc
    if result.returncode != 0:
        detail = redact_text((result.stderr or result.stdout).decode("utf-8", errors="replace"))
        raise RepositoryError(f"Git operation failed: {detail.strip()[:1_000]}")
    return result.stdout


def _validated_git_sha(value: str, *, field: str) -> str:
    canonical = value.casefold()
    if not _GIT_SHA.fullmatch(canonical):
        raise PolicyError(f"{field} must be a full 40- or 64-character hexadecimal SHA")
    return canonical


def _validated_git_branch(value: str) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or not value
        or len(value) > 255
        or "\0" in value
    ):
        raise PolicyError("Publication branch name is invalid")
    try:
        result = subprocess.run(
            ["git", "check-ref-format", f"refs/heads/{value}"],
            env=_git_environment(),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RepositoryError(
            f"Git branch validation failed to start: {type(exc).__name__}"
        ) from exc
    if result.returncode != 0:
        raise PolicyError("Publication branch name is not a valid git branch")
    return value


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
        # Git's global and system configuration are disabled below.  Keep the fallback outside
        # shared temporary storage as an additional defence if a future Git invocation consults
        # HOME for a non-configuration file.
        "HOME": os.environ.get("HOME", "/nonexistent"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_LFS_SKIP_SMUDGE": "1",
    }


__all__ = [
    "Publisher",
    "approve_run",
    "build_approval_review",
    "validate_publication_text",
]
