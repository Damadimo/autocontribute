"""Typed configuration with reputation-preserving defaults."""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    ValidationInfo,
    field_validator,
    model_validator,
)

from autocontribute.exceptions import ConfigurationError

_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_GIT_OBJECT_ID = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_GITHUB_LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_CANONICAL_UTC_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$"
)
_MODEL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")
_IMAGE_DIGEST = re.compile(r"@sha256:[0-9a-fA-F]{64}$")
_DEFAULT_SANDBOX_IMAGE = (
    "python:3.12-bookworm@sha256:9bed8554e926c07c6f908841d5ee88c33e8df9236b191526bbce81a9062ab43a"
)
# Values the starter templates ship with; they parse, but no command may act on them.
_STARTER_REPOSITORY = "your-org/your-repo"
_STARTER_REGISTRY_HOST = "example.invalid"
_STARTER_IDENTITY_NAME = "Your Name"
_STARTER_IDENTITY_EMAIL = "your-handle@users.noreply.github.com"

CLA_ATTESTATION_STATEMENT = (
    "I attest that the GitHub account named by attested_by has completed every account-level "
    "Contributor License Agreement action required by the reviewed policy surface for this "
    "repository; no per-contribution signature or assent remains, and I authorize Autocontribute "
    "to rely on that completed enrollment."
)
DCO_ATTESTATION_STATEMENT = (
    "I have reviewed the Developer Certificate of Origin policy surface for this repository, "
    "certify that each contribution Autocontribute publishes under this attestation is eligible "
    "for certification by the named signatory, and explicitly authorize Autocontribute to append "
    "that signatory's exact Signed-off-by trailer."
)


def validate_model_identifier(value: object) -> str:
    """Return one bounded canonical provider model ID or reject it."""

    if not isinstance(value, str) or not _MODEL_ID.fullmatch(value):
        raise ValueError("model identifiers must be canonical provider IDs")
    return value


class StrictModel(BaseModel):
    """Configuration base model that rejects silent misspellings."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class IdentityConfig(StrictModel):
    name: str = ""
    email: str = ""


def _label_names(values: list[str], *, field: str) -> list[str]:
    """Strip label names and reject ones that cannot be quoted in a GitHub search."""

    names: list[str] = []
    for value in values:
        name = value.strip()
        if not name or '"' in name or not name.isprintable():
            raise ValueError(f"{field} must hold label names without double quotes")
        if name.casefold() not in {existing.casefold() for existing in names}:
            names.append(name)
    return names


class RepositoryLabels(StrictModel):
    """Labels that replace github.include_labels or github.exclude_labels for one repository."""

    include: list[str] | None = None
    exclude: list[str] | None = None

    @field_validator("include", "exclude")
    @classmethod
    def labels_are_searchable(
        cls, values: list[str] | None, info: ValidationInfo
    ) -> list[str] | None:
        if values is None:
            return None
        names = _label_names(values, field=f"github.labels {info.field_name}")
        if info.field_name == "include" and not names:
            raise ValueError("github.labels include must name at least one label")
        return names


class GitHubConfig(StrictModel):
    auth: Literal["gh", "token"] = "gh"
    token_env: str = "AUTOCONTRIBUTE_GITHUB_TOKEN"
    api_url: HttpUrl = HttpUrl("https://api.github.com")
    repositories: list[str] = Field(default_factory=list)
    owners: list[str] = Field(default_factory=list)
    include_labels: list[str] = Field(
        default_factory=lambda: [
            "help wanted",
            "bug",
            "confirmed",
            "accepted",
            "status: help wanted",
            "contributions welcome",
            "pr welcome",
        ]
    )
    exclude_labels: list[str] = Field(
        default_factory=lambda: [
            "security",
            "breaking change",
            "needs design",
            "discussion",
            "blocked",
            # Maintainers keep these for people making their first contribution.
            "good first issue",
            "first-timers-only",
        ]
    )
    labels: dict[str, RepositoryLabels] = Field(default_factory=dict)
    min_stars: int = Field(default=0, ge=0)
    repository_limit_per_owner: int = Field(default=8, ge=1, le=30)
    issue_limit_per_repository: int = Field(default=10, ge=1, le=50)
    require_unassigned: bool = True
    max_issue_age_days: int = Field(default=365, ge=1, le=3_650)
    max_repository_inactivity_days: int = Field(default=180, ge=1, le=3_650)

    @field_validator("include_labels", "exclude_labels")
    @classmethod
    def labels_are_searchable(cls, values: list[str], info: ValidationInfo) -> list[str]:
        return _label_names(values, field=f"github.{info.field_name}")

    @field_validator("labels")
    @classmethod
    def label_overrides_are_repository_scoped(
        cls, values: dict[str, RepositoryLabels]
    ) -> dict[str, RepositoryLabels]:
        normalized: dict[str, RepositoryLabels] = {}
        for repository, labels in values.items():
            if not _REPOSITORY.fullmatch(repository):
                raise ValueError("github.labels keys must use owner/name syntax")
            key = repository.casefold()
            if key in normalized:
                raise ValueError(
                    f"duplicate github.labels repository after case-folding: {repository}"
                )
            normalized[key] = labels
        return normalized

    @field_validator("token_env")
    @classmethod
    def token_env_is_a_name(cls, value: str) -> str:
        if not _ENV_NAME.fullmatch(value):
            raise ValueError("token_env must be an environment variable name, not a token")
        return value

    @field_validator("api_url")
    @classmethod
    def api_url_is_secure(cls, value: HttpUrl) -> HttpUrl:
        if value.scheme != "https":
            raise ValueError("api_url must use HTTPS")
        if value.username is not None or value.password is not None:
            raise ValueError("api_url cannot contain credentials")
        if value.query is not None or value.fragment is not None:
            raise ValueError("api_url cannot contain a query string or fragment")
        return value

    @field_validator("repositories")
    @classmethod
    def repositories_are_full_names(cls, values: list[str]) -> list[str]:
        invalid = [value for value in values if not _REPOSITORY.fullmatch(value)]
        if invalid:
            raise ValueError(f"repositories must use owner/name syntax: {invalid}")
        return list(dict.fromkeys(values))


class ModelPricing(StrictModel):
    """Operator-supplied token prices used for a conservative per-run spend ceiling."""

    input_usd_per_million_tokens: Decimal = Field(gt=0, max_digits=12, decimal_places=6)
    cached_input_usd_per_million_tokens: Decimal | None = Field(
        default=None, gt=0, max_digits=12, decimal_places=6
    )
    cache_write_usd_per_million_tokens: Decimal | None = Field(
        default=None, gt=0, max_digits=12, decimal_places=6
    )
    output_usd_per_million_tokens: Decimal = Field(gt=0, max_digits=12, decimal_places=6)

    @property
    def cached_input_rate(self) -> Decimal:
        return self.cached_input_usd_per_million_tokens or self.input_usd_per_million_tokens

    @property
    def cache_write_rate(self) -> Decimal:
        return self.cache_write_usd_per_million_tokens or self.input_usd_per_million_tokens

    def upper_bound_cost(self, *, input_tokens: int, output_tokens: int) -> Decimal:
        """Price a reservation without assuming a discounted cache hit."""

        input_rate = max(
            self.input_usd_per_million_tokens,
            self.cached_input_rate,
            self.cache_write_rate,
        )
        return (
            Decimal(input_tokens) * input_rate
            + Decimal(output_tokens) * self.output_usd_per_million_tokens
        ) / Decimal(1_000_000)

    def cost(
        self,
        *,
        input_tokens: int,
        cached_input_tokens: int,
        cache_write_tokens: int,
        output_tokens: int,
    ) -> Decimal:
        regular_input_tokens = input_tokens - cached_input_tokens - cache_write_tokens
        if regular_input_tokens < 0:
            raise ValueError("cached and cache-write tokens cannot exceed input tokens")
        return (
            Decimal(regular_input_tokens) * self.input_usd_per_million_tokens
            + Decimal(cached_input_tokens) * self.cached_input_rate
            + Decimal(cache_write_tokens) * self.cache_write_rate
            + Decimal(output_tokens) * self.output_usd_per_million_tokens
        ) / Decimal(1_000_000)


class ModelProfile(StrictModel):
    provider: Literal["openai", "openai_compatible"] = "openai"
    model: str = "gpt-5.6"
    expected_response_model: str | None = None
    api_key_env: str = "OPENAI_API_KEY"
    base_url: HttpUrl | None = None
    reasoning_effort: Literal["none", "minimal", "low", "medium", "high", "xhigh", "max"] = "high"
    reasoning_mode: Literal["standard", "pro"] | None = "standard"
    max_input_tokens: int = Field(default=500_000, ge=1_000, le=2_000_000)
    max_output_tokens: int = Field(default=40_000, ge=1_000, le=128_000)
    timeout_seconds: float = Field(default=900, ge=10, le=3_600)
    pricing: ModelPricing | None = None

    @field_validator("model", "expected_response_model")
    @classmethod
    def model_ids_are_canonical(cls, value: str | None) -> str | None:
        return None if value is None else validate_model_identifier(value)

    @field_validator("api_key_env")
    @classmethod
    def api_key_env_is_a_name(cls, value: str) -> str:
        if not _ENV_NAME.fullmatch(value):
            raise ValueError("api_key_env must be an environment variable name, not a key")
        return value

    @field_validator("base_url")
    @classmethod
    def base_url_is_secure(cls, value: HttpUrl | None) -> HttpUrl | None:
        if value is None:
            return None
        if value.scheme != "https":
            raise ValueError("base_url must use HTTPS")
        if value.username is not None or value.password is not None:
            raise ValueError("base_url cannot contain credentials")
        if value.query is not None or value.fragment is not None:
            raise ValueError("base_url cannot contain a query string or fragment")
        return value

    @model_validator(mode="after")
    def compatible_provider_has_url(self) -> ModelProfile:
        if self.provider == "openai_compatible" and self.base_url is None:
            raise ValueError("openai_compatible profiles require base_url")
        if self.provider == "openai_compatible" and self.reasoning_mode == "pro":
            raise ValueError(
                "openai_compatible profiles cannot portably enforce pro reasoning mode; "
                "use standard or null"
            )
        return self

    def require_api_key(self) -> str:
        value = os.environ.get(self.api_key_env)
        if not value:
            raise ConfigurationError(
                f"Model credential is missing; set environment variable {self.api_key_env}"
            )
        return value


class ModelsConfig(StrictModel):
    scout: ModelProfile = Field(
        default_factory=lambda: ModelProfile(reasoning_mode="standard", reasoning_effort="high")
    )
    builder: ModelProfile = Field(
        default_factory=lambda: ModelProfile(reasoning_mode="standard", reasoning_effort="high")
    )
    critic: ModelProfile = Field(
        default_factory=lambda: ModelProfile(reasoning_mode="pro", reasoning_effort="high")
    )

    @model_validator(mode="before")
    @classmethod
    def apply_role_reasoning_defaults(cls, value: object) -> object:
        if not isinstance(value, dict):
            return value
        result = dict(value)
        for role, mode in (("scout", "standard"), ("builder", "standard"), ("critic", "pro")):
            profile = result.get(role)
            if isinstance(profile, dict) and "reasoning_mode" not in profile:
                normalized = dict(profile)
                normalized["reasoning_mode"] = mode
                result[role] = normalized
        return result


class SandboxConfig(StrictModel):
    backend: Literal["docker", "local"] = "docker"
    image: str = _DEFAULT_SANDBOX_IMAGE
    command_timeout_seconds: int = Field(default=900, ge=10, le=3_600)
    memory: str = "4g"
    cpus: float = Field(default=2.0, gt=0, le=16)
    pids_limit: int = Field(default=256, ge=32, le=4_096)
    allow_unsafe_local: bool = False
    max_commands: int = Field(default=8, ge=1, le=30)

    @field_validator("image")
    @classmethod
    def image_is_a_single_reference(cls, value: str) -> str:
        if (
            not value
            or value.startswith("-")
            or "\0" in value
            or any(character.isspace() for character in value)
        ):
            raise ValueError("image must be one Docker image reference")
        return value

    @model_validator(mode="after")
    def backend_safety_requirements(self) -> SandboxConfig:
        if self.backend == "local" and not self.allow_unsafe_local:
            raise ValueError("local sandbox requires allow_unsafe_local: true")
        if self.backend == "docker" and not _IMAGE_DIGEST.search(self.image):
            raise ValueError("docker sandbox image must be pinned with @sha256:<64 hex digits>")
        return self


class ValidationConfig(StrictModel):
    """Operator-owned validation commands keyed by canonical repository name."""

    required_commands: dict[str, list[str]] = Field(default_factory=dict)

    @field_validator("required_commands")
    @classmethod
    def required_commands_are_safe(cls, values: dict[str, list[str]]) -> dict[str, list[str]]:
        normalized: dict[str, list[str]] = {}
        for repository, commands in values.items():
            if not _REPOSITORY.fullmatch(repository):
                raise ValueError("validation.required_commands keys must use owner/name syntax")
            cleaned: list[str] = []
            for command in commands:
                value = command.strip()
                if not value or "\0" in value:
                    raise ValueError("trusted validation commands must be non-empty and NUL-free")
                if len(value) > 20_000:
                    raise ValueError("trusted validation command exceeds 20,000 characters")
                if value not in cleaned:
                    cleaned.append(value)
            if not cleaned:
                raise ValueError(
                    f"validation.required_commands[{repository!r}] must contain a command"
                )
            key = repository.casefold()
            if key in normalized:
                raise ValueError(
                    f"duplicate validation repository after case-folding: {repository}"
                )
            normalized[key] = cleaned
        return normalized

    def commands_for(self, repository: str) -> list[str]:
        """Return a copy of the operator-owned commands for one repository."""

        return list(self.required_commands.get(repository.casefold(), []))


class CLAAuthorization(StrictModel):
    """Explicit confirmation of a completed, account-level CLA enrollment."""

    statement: str

    @field_validator("statement")
    @classmethod
    def statement_is_exact(cls, value: str) -> str:
        if value != CLA_ATTESTATION_STATEMENT:
            raise ValueError("CLA authorization must use the exact fixed attestation statement")
        return value


class DCOAuthorization(StrictModel):
    """Explicit authority to append one exact repository-scoped DCO signoff."""

    statement: str
    signoff_name: str
    signoff_email: str

    @field_validator("statement")
    @classmethod
    def statement_is_exact(cls, value: str) -> str:
        if value != DCO_ATTESTATION_STATEMENT:
            raise ValueError("DCO authorization must use the exact fixed attestation statement")
        return value

    @field_validator("signoff_name")
    @classmethod
    def signoff_name_is_canonical(cls, value: str) -> str:
        if (
            not value
            or value != value.strip()
            or len(value) > 200
            or not value.isprintable()
            or any(character in value for character in ("<", ">"))
        ):
            raise ValueError("DCO signoff_name must be a printable canonical single-line name")
        return value

    @field_validator("signoff_email")
    @classmethod
    def signoff_email_is_canonical(cls, value: str) -> str:
        if (
            not value
            or value != value.strip()
            or len(value) > 320
            or value.count("@") != 1
            or any(not character.isprintable() or character.isspace() for character in value)
            or any(character in value for character in ("<", ">"))
        ):
            raise ValueError("DCO signoff_email must be a canonical email address")
        local_part, domain = value.split("@", 1)
        if not local_part or not domain:
            raise ValueError("DCO signoff_email must be a canonical email address")
        return value

    @property
    def trailer(self) -> str:
        return f"Signed-off-by: {self.signoff_name} <{self.signoff_email}>"


class LegalAttestation(StrictModel):
    """One operator assertion bound to one reviewed repository-policy surface."""

    repository: str
    reviewed_repository_ref: str
    reviewed_organization_policy_ref: str
    legal_policy_sha256: str
    legal_requirements: list[Literal["cla", "dco"]]
    attested_by: str
    attested_at: datetime
    cla: CLAAuthorization | None = None
    dco: DCOAuthorization | None = None

    @field_validator("repository")
    @classmethod
    def repository_is_exact(cls, value: str) -> str:
        if not _REPOSITORY.fullmatch(value):
            raise ValueError("legal attestation repository must use owner/name syntax")
        return value.casefold()

    @field_validator("reviewed_repository_ref")
    @classmethod
    def repository_ref_is_immutable(cls, value: str) -> str:
        if not _GIT_OBJECT_ID.fullmatch(value):
            raise ValueError("reviewed_repository_ref must be a full immutable Git object ID")
        return value.casefold()

    @field_validator("reviewed_organization_policy_ref")
    @classmethod
    def organization_ref_is_explicit(cls, value: str) -> str:
        if value == "absent":
            return value
        if not _GIT_OBJECT_ID.fullmatch(value):
            raise ValueError(
                "reviewed_organization_policy_ref must be a full immutable Git object ID or "
                "'absent'"
            )
        return value.casefold()

    @field_validator("legal_policy_sha256")
    @classmethod
    def policy_digest_is_sha256(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("legal_policy_sha256 must be a SHA-256 hex digest")
        return value.casefold()

    @field_validator("legal_requirements")
    @classmethod
    def requirements_are_exact_and_canonical(
        cls, values: list[Literal["cla", "dco"]]
    ) -> list[Literal["cla", "dco"]]:
        canonical = [value for value in ("cla", "dco") if value in values]
        if not values or values != canonical:
            raise ValueError("legal_requirements must be a non-empty canonical CLA/DCO set")
        return values

    @field_validator("attested_by")
    @classmethod
    def attesting_login_is_canonical(cls, value: str) -> str:
        canonical = value.strip().casefold()
        if not _GITHUB_LOGIN.fullmatch(canonical):
            raise ValueError("attested_by must be a canonical GitHub login")
        return canonical

    @field_validator("attested_at", mode="before")
    @classmethod
    def attestation_time_has_canonical_input(cls, value: object) -> object:
        if isinstance(value, str) and not _CANONICAL_UTC_TIMESTAMP.fullmatch(value):
            raise ValueError("attested_at string must use canonical RFC 3339 UTC (`Z`) format")
        if not isinstance(value, (str, datetime)):
            raise ValueError("attested_at must be a canonical UTC timestamp")
        return value

    @field_validator("attested_at")
    @classmethod
    def attestation_time_is_current_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("attested_at must use UTC")
        canonical = value.astimezone(UTC)
        if canonical > datetime.now(UTC) + timedelta(minutes=5):
            raise ValueError("attested_at cannot be materially in the future")
        return canonical

    @model_validator(mode="after")
    def includes_an_explicit_authorization(self) -> LegalAttestation:
        if self.cla is None and self.dco is None:
            raise ValueError("legal attestation must include an explicit CLA or DCO authorization")
        authorized = [
            name
            for name, authorization in (("cla", self.cla), ("dco", self.dco))
            if authorization is not None
        ]
        if authorized != self.legal_requirements:
            raise ValueError(
                "legal authorizations must exactly match the attested legal_requirements"
            )
        return self


class PolicyConfig(StrictModel):
    require_maintainer_signal: bool = True
    require_contribution_guidelines: bool = True
    allow_assigned_issues: bool = False
    allow_security_issues: bool = False
    allow_dependency_changes: bool = False
    allow_workflow_changes: bool = False
    legal_attestations: dict[str, LegalAttestation] = Field(default_factory=dict)
    ai_disclosure: str = (
        "This contribution was prepared autonomously by an AI agent. Its validation evidence "
        "comes from Autocontribute's configured automated checks; no human review is implied."
    )

    @field_validator("legal_attestations")
    @classmethod
    def legal_attestations_are_repository_scoped(
        cls, values: dict[str, LegalAttestation]
    ) -> dict[str, LegalAttestation]:
        normalized: dict[str, LegalAttestation] = {}
        for repository, attestation in values.items():
            if not _REPOSITORY.fullmatch(repository):
                raise ValueError("policy.legal_attestations keys must use owner/name syntax")
            key = repository.casefold()
            if key in normalized:
                raise ValueError(
                    f"duplicate legal-attestation repository after case-folding: {repository}"
                )
            if attestation.repository != key:
                raise ValueError(
                    "legal-attestation mapping key must exactly match its repository field"
                )
            normalized[key] = attestation
        return normalized

    def legal_attestation_for(self, repository: str) -> LegalAttestation | None:
        return self.legal_attestations.get(repository.casefold())


class QualityConfig(StrictModel):
    min_candidate_score: int = Field(default=85, ge=0, le=100)
    min_readiness_score: int = Field(default=90, ge=0, le=100)
    min_dimension_score: int = Field(default=80, ge=0, le=100)
    max_files_changed: int = Field(default=8, ge=1, le=100)
    max_changed_lines: int = Field(default=400, ge=1, le=10_000)
    max_context_files: int = Field(default=20, ge=1, le=100)
    max_context_characters: int = Field(default=160_000, ge=10_000, le=2_000_000)
    require_regression_evidence_for_bugfix: bool = True
    forbidden_paths: list[str] = Field(
        default_factory=lambda: [
            ".github/workflows/**",
            ".github/actions/**",
            "**/*.pem",
            "**/*.key",
            "**/generated/**",
            "vendor/**",
        ]
    )


class PublishingConfig(StrictModel):
    approval_expires_hours: int = Field(default=24, ge=1, le=168)
    branch_prefix: str = "autocontribute"
    draft: bool = True
    ready_for_review: bool = False
    max_new_pull_requests_per_day: int = Field(default=1, ge=1, le=5)
    max_open_pull_requests: int = Field(default=2, ge=1, le=20)
    repository_cooldown_days: int = Field(default=7, ge=0, le=365)

    @model_validator(mode="after")
    def ready_transition_starts_from_a_draft(self) -> PublishingConfig:
        if self.ready_for_review and not self.draft:
            raise ValueError(
                "publishing.draft must be true when publishing.ready_for_review is enabled"
            )
        return self


class BudgetConfig(StrictModel):
    # A maximum-length run makes 6 distinct calls (plan, replan, propose, critique,
    # repair, re-critique); the remainder is headroom for transient-failure retries,
    # each of which consumes a call so retried requests stay visible in the billable
    # accounting.
    max_model_calls_per_run: int = Field(default=9, ge=3, le=30)
    max_candidates_per_run: int = Field(default=25, ge=1, le=200)
    max_input_tokens_per_run: int = Field(default=3_000_000, ge=1_000, le=20_000_000)
    max_output_tokens_per_run: int = Field(default=240_000, ge=1_000, le=4_000_000)
    max_model_seconds_per_run: float = Field(default=3_600, ge=10, le=86_400)
    max_model_cost_usd_per_run: Decimal | None = Field(
        default=None, gt=0, max_digits=10, decimal_places=4
    )


class StorageConfig(StrictModel):
    path: Path = Path(".autocontribute")


class AutocontributeConfig(StrictModel):
    identity: IdentityConfig = Field(default_factory=IdentityConfig)
    github: GitHubConfig = Field(default_factory=GitHubConfig)
    models: ModelsConfig = Field(default_factory=ModelsConfig)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    validation: ValidationConfig = Field(default_factory=ValidationConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    quality: QualityConfig = Field(default_factory=QualityConfig)
    publishing: PublishingConfig = Field(default_factory=PublishingConfig)
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)

    @model_validator(mode="after")
    def trusted_validation_is_complete(self) -> AutocontributeConfig:
        missing = [
            repository
            for repository in self.github.repositories
            if not self.validation.commands_for(repository)
        ]
        if missing:
            raise ValueError(
                "explicit repositories require validation.required_commands entries: "
                + ", ".join(missing)
            )
        oversized = [
            repository
            for repository, commands in self.validation.required_commands.items()
            if len(commands) > self.sandbox.max_commands
        ]
        if oversized:
            raise ValueError(
                "trusted validation commands exceed sandbox.max_commands for: "
                + ", ".join(oversized)
            )
        for repository, attestation in self.policy.legal_attestations.items():
            if attestation.dco is None:
                continue
            if (
                self.identity.name != attestation.dco.signoff_name
                or self.identity.email != attestation.dco.signoff_email
            ):
                raise ValueError(
                    "DCO signatory must exactly match identity.name and identity.email for "
                    + repository
                )
        profiles = (
            ("scout", self.models.scout),
            ("builder", self.models.builder),
            ("critic", self.models.critic),
        )
        missing_pricing = [role for role, profile in profiles if profile.pricing is None]
        configured_pricing = [role for role, profile in profiles if profile.pricing is not None]
        if configured_pricing and missing_pricing:
            raise ValueError(
                "model token pricing must be configured for every role; missing: "
                + ", ".join(missing_pricing)
            )
        if self.budget.max_model_cost_usd_per_run is not None and missing_pricing:
            raise ValueError(
                "budget.max_model_cost_usd_per_run requires token pricing for model roles: "
                + ", ".join(missing_pricing)
            )
        return self

    def model_for(self, role: Literal["scout", "builder", "critic"]) -> ModelProfile:
        if role == "scout":
            return self.models.scout
        if role == "builder":
            return self.models.builder
        return self.models.critic


def load_config(path: Path) -> AutocontributeConfig:
    """Load and validate a YAML configuration without resolving secret values."""

    config_path = path.expanduser().resolve()
    if not config_path.is_file():
        raise ConfigurationError(
            f"Configuration file not found: {config_path}. Run `autocontribute init`."
        )
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigurationError(f"Could not read {config_path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigurationError("The configuration root must be a YAML mapping")
    try:
        config = AutocontributeConfig.model_validate(raw)
    except ValueError as exc:
        raise ConfigurationError(str(exc)) from exc
    if not config.storage.path.is_absolute():
        config.storage.path = (config_path.parent / config.storage.path).resolve()
    return config


def starter_placeholders(config: AutocontributeConfig) -> list[str]:
    """Describe each starter-template placeholder that still needs a real value."""

    placeholders: list[str] = []
    if any(
        repository.casefold() == _STARTER_REPOSITORY for repository in config.github.repositories
    ):
        placeholders.append(
            f"github.repositories lists {_STARTER_REPOSITORY}: replace it with the repositories "
            "you want to contribute to, and give each one a validation.required_commands entry"
        )
    # The local backend never pulls or runs the image, so a leftover starter image is harmless.
    image_registry, separator, _ = config.sandbox.image.partition("/")
    if (
        config.sandbox.backend == "docker"
        and separator
        and image_registry.partition(":")[0].casefold() == _STARTER_REGISTRY_HOST
    ):
        placeholders.append(
            f"sandbox.image comes from the {_STARTER_REGISTRY_HOST} placeholder registry: build, "
            "digest-pin, and pre-pull your own validation image (see docs/sandbox-image.md)"
        )
    if config.identity.name.strip() == _STARTER_IDENTITY_NAME:
        placeholders.append(
            f'identity.name is "{_STARTER_IDENTITY_NAME}": set your own name, or leave it empty '
            "to use your GitHub login"
        )
    if config.identity.email.strip().casefold() == _STARTER_IDENTITY_EMAIL:
        placeholders.append(
            f'identity.email is "{_STARTER_IDENTITY_EMAIL}": set your own address, or leave it '
            "empty to use your GitHub noreply address"
        )
    return placeholders


def example_config() -> str:
    """Return a documented starter configuration with no embedded credentials."""

    return """# Credentials are read only from the named environment variables.
identity:                          # empty = your GitHub login and its noreply email address
  name: ""
  email: ""

github:
  auth: gh                         # use `gh auth login`, or change to `token`
  token_env: AUTOCONTRIBUTE_GITHUB_TOKEN
  repositories:                   # explicit repositories are safest
    - your-org/your-repo
  owners: []                       # optional discovery across selected owners
  include_labels: ["help wanted", "bug", "confirmed", "accepted", "status: help wanted",
                   "contributions welcome", "pr welcome"]
  exclude_labels: ["security", "breaking change", "needs design", "discussion", "blocked",
                   "good first issue", "first-timers-only"]
  labels: {}                       # per repository: {owner/repo: {include: [...], exclude: [...]}}
  min_stars: 0
  require_unassigned: true
  max_repository_inactivity_days: 180

models:
  scout: &builder_model
    provider: openai
    model: gpt-5.6
    # Optional: refuse any response whose provider-reported model ID differs from this one.
    # expected_response_model: gpt-5.6-YYYY-MM-DD
    api_key_env: OPENAI_API_KEY
    reasoning_effort: high
    reasoning_mode: standard
    max_input_tokens: 500000
    max_output_tokens: 40000
    timeout_seconds: 900
    pricing:                         # conservative ceilings; verify for the selected model
      input_usd_per_million_tokens: 10
      cached_input_usd_per_million_tokens: 10
      cache_write_usd_per_million_tokens: 10
      output_usd_per_million_tokens: 100
  builder: *builder_model
  critic:
    <<: *builder_model
    reasoning_mode: pro

sandbox:
  backend: docker
  # Validation always runs offline, so this one global image must already contain the complete
  # toolchain (pytest, project dependencies) for every configured repository; a bare interpreter
  # image fails doctor. Build, digest-pin, and pre-pull your own: see docs/sandbox-image.md.
  image: >-
    example.invalid/sandbox@sha256:0000000000000000000000000000000000000000000000000000000000000000
  command_timeout_seconds: 900
  memory: 4g
  cpus: 2

validation:
  required_commands:               # operator-owned; model commands are supplementary only
    your-org/your-repo:
      - python -m pytest

policy:
  require_maintainer_signal: true
  require_contribution_guidelines: true
  allow_security_issues: false
  allow_dependency_changes: false
  allow_workflow_changes: false
  legal_attestations: {}            # generate only with `autocontribute policy attest`
  ai_disclosure: >-
    This contribution was prepared autonomously by an AI agent. Its validation
    evidence comes from Autocontribute's configured automated checks; no human
    review is implied.

quality:
  min_candidate_score: 85
  min_readiness_score: 90
  min_dimension_score: 80
  max_files_changed: 8
  max_changed_lines: 400
  require_regression_evidence_for_bugfix: true

publishing:
  approval_expires_hours: 24
  draft: true
  ready_for_review: false
  max_new_pull_requests_per_day: 1
  max_open_pull_requests: 2
  repository_cooldown_days: 7

budget:
  max_model_calls_per_run: 9
  max_candidates_per_run: 25
  max_input_tokens_per_run: 3000000
  max_output_tokens_per_run: 240000
  max_model_seconds_per_run: 3600
  max_model_cost_usd_per_run: 50

storage:
  path: .autocontribute
"""


__all__ = [
    "CLA_ATTESTATION_STATEMENT",
    "DCO_ATTESTATION_STATEMENT",
    "AutocontributeConfig",
    "CLAAuthorization",
    "DCOAuthorization",
    "GitHubConfig",
    "LegalAttestation",
    "ModelPricing",
    "ModelProfile",
    "RepositoryLabels",
    "ValidationConfig",
    "example_config",
    "load_config",
    "starter_placeholders",
    "validate_model_identifier",
]
