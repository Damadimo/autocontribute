"""Typed configuration with reputation-preserving defaults."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
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

from autocontribute.environments import EnvironmentOverride
from autocontribute.exceptions import ConfigurationError
from autocontribute.pricing import (
    API_KEY_ENVS,
    AUTO_MODEL,
    DEFAULT_EFFORTS,
    MODELS,
    Effort,
    ModelSpec,
    Role,
    resolve_critic,
    resolve_model,
)

_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_GIT_OBJECT_ID = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_GITHUB_LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_CANONICAL_UTC_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$"
)
_MODEL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")
# Values the starter templates ship with; they parse, but no command may act on them.
_STARTER_REPOSITORY = "your-org/your-repo"
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
    """Configuration base model that rejects silent misspellings.

    Errors leave out the rejected value: a key or token pasted into the wrong field must not
    reach a log.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True, hide_input_in_errors=True)


class IdentityConfig(StrictModel):
    name: str = ""
    email: str = ""


def _label_names(values: list[str], *, field: str) -> list[str]:
    """Strip label names and reject ones that cannot be quoted in a GitHub search."""

    names: list[str] = []
    for value in values:
        name = value.strip()
        if not name or '"' in name or not name.isprintable():
            raise ValueError(
                f"{field} must hold non-empty, printable label names without double quotes"
            )
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
            # Undecided, unconfirmed or closed-in-spirit work; * matches any text.
            "needs-*",
            "question",
            "discussion",
            "design",
            "rfc",
            "proposal",
            "wontfix",
            "duplicate",
            "invalid",
            "stale",
            "blocked",
            # Maintainers keep these for people making their first contribution.
            "good first issue",
            "first-timers-only",
            "beginner",
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


class ModelsConfig(StrictModel):
    """The model of each role: ``auto``, or an id from the built-in table in ``pricing``."""

    agent: str = AUTO_MODEL
    # auto: the agent's model, or the other provider's when both providers' keys are set.
    critic: str = AUTO_MODEL
    setup: str = AUTO_MODEL
    triage: str = AUTO_MODEL
    # Reasoning effort per role, where the default does not suit; pricing.DEFAULT_EFFORTS.
    effort: dict[Role, Effort] = Field(default_factory=dict)

    @field_validator("agent", "critic", "setup", "triage")
    @classmethod
    def model_is_known(cls, value: str, info: ValidationInfo) -> str:
        if value != AUTO_MODEL and value not in MODELS:
            raise ValueError(
                f"models.{info.field_name} must be auto or one of: {', '.join(MODELS)}"
            )
        return value

    def resolve(self, environ: Mapping[str, str]) -> ResolvedModels:
        """Resolve ``auto`` from the API keys in ``environ`` and check each role's key is set.

        Raises :class:`ConfigurationError` when a key is missing or a role's model does not
        support its effort. An empty variable counts as unset.
        """

        agent = resolve_model(self.agent, "agent", environ)
        resolved = ResolvedModels(
            agent=agent,
            critic=resolve_critic(self.critic, agent, environ),
            setup=resolve_model(self.setup, "setup", environ),
            triage=resolve_model(self.triage, "triage", environ),
            efforts={
                role: self.effort.get(role, default) for role, default in DEFAULT_EFFORTS.items()
            },
        )
        for role in DEFAULT_EFFORTS:
            spec = resolved.spec(role)
            key = API_KEY_ENVS[spec.provider]
            if not environ.get(key):
                raise ConfigurationError(f"models.{role} is {spec.id}; set {key} to use it")
            if resolved.efforts[role] not in spec.efforts:
                raise ConfigurationError(
                    f"models.effort.{role} is {resolved.efforts[role]}, which {spec.id} does "
                    "not support"
                )
        return resolved


@dataclass(frozen=True, slots=True)
class ResolvedModels:
    """The model and reasoning effort of each role, with ``auto`` resolved."""

    agent: ModelSpec
    critic: ModelSpec
    setup: ModelSpec
    triage: ModelSpec
    efforts: Mapping[Role, Effort]

    def spec(self, role: Role) -> ModelSpec:
        return {
            "agent": self.agent,
            "critic": self.critic,
            "setup": self.setup,
            "triage": self.triage,
        }[role]


class SandboxConfig(StrictModel):
    # Each tool command, test run and setup step; agent commands get at most 300 seconds.
    command_timeout_seconds: int = Field(default=900, ge=10, le=3_600)
    memory: str = "6g"
    cpus: float = Field(default=2.0, gt=0, le=16)
    pids_limit: int = Field(default=1024, ge=32, le=4_096)


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
    # Repositories whose AI policy asks for human-written PR text, where the user still wants
    # to contribute and will write that text.
    allow_conditional_ai_policy: list[str] = Field(default_factory=list)
    # {version} and {model} are filled when the run is prepared; the approval binds the result.
    ai_disclosure: str = (
        "AI assistance: an AI coding agent (autocontribute {version}, {model}) drafted this "
        "change and its test and ran the tests listed above in a sandbox. I reviewed the diff "
        "and the test results before opening this PR and will handle the review."
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

    @field_validator("allow_conditional_ai_policy")
    @classmethod
    def conditional_ai_policy_entries_are_repositories(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            if not _REPOSITORY.fullmatch(value):
                raise ValueError(
                    "policy.allow_conditional_ai_policy entries must use owner/name syntax"
                )
            if value.casefold() not in normalized:
                normalized.append(value.casefold())
        return normalized

    def legal_attestation_for(self, repository: str) -> LegalAttestation | None:
        return self.legal_attestations.get(repository.casefold())


class QualityConfig(StrictModel):
    # Every changed file counts here, tests included.
    max_files_changed: int = Field(default=8, ge=1, le=100)
    max_changed_lines: int = Field(default=400, ge=1, le=10_000)
    # Files that are not tests, and their changed lines.
    max_source_files: int = Field(default=3, ge=1, le=100)
    max_source_lines: int = Field(default=150, ge=1, le=10_000)
    forbidden_paths: list[str] = Field(
        default_factory=lambda: [
            ".github/workflows/**",
            ".github/actions/**",
            "**/*.pem",
            "**/*.key",
            "**/generated/**",
            "vendor/**",
            ".github/**",
            # Hooks that run on commit or install, and build scripts that run on build.
            "**/.husky/**",
            "**/.githooks/**",
            "**/.pre-commit-config.yaml",
            "**/lefthook.yml",
            "**/build.rs",
            "**/binding.gyp",
            "**/.cargo/config",
            "**/.cargo/config.toml",
        ]
    )


class PublishingConfig(StrictModel):
    # Empty means the token owner. Setting it lets a job without the publishing token prepare
    # and render reviews; approve and publish still require the token to belong to this login.
    login: str = ""
    # auto: push the branch to the upstream itself when the login owns the repository;
    # otherwise use a fork, even where the login can push.
    head_strategy: Literal["auto", "fork"] = "auto"
    approval_expires_hours: int = Field(default=72, ge=1, le=168)
    branch_prefix: str = "autocontribute"
    draft: bool = False
    # Only a draft can be marked ready, so this applies when ``draft`` is true.
    ready_for_review: bool = True
    max_new_pull_requests_per_day: int = Field(default=1, ge=1, le=5)
    max_open_pull_requests: int = Field(default=3, ge=1, le=20)
    repository_cooldown_days: int = Field(default=7, ge=0, le=365)

    @field_validator("login")
    @classmethod
    def login_is_a_github_account(cls, value: str) -> str:
        if value and not _GITHUB_LOGIN.fullmatch(value):
            raise ValueError("publishing.login must be a GitHub login or empty")
        return value


class BudgetConfig(StrictModel):
    # Prices come from the built-in model table; every request reserves its worst case first.
    max_cost_usd_per_run: Decimal = Field(
        default=Decimal(10), gt=0, le=1_000, max_digits=10, decimal_places=4
    )
    # Over the last 24 hours; a run starts only while a quarter of the per-run cap is left.
    max_cost_usd_per_day: Decimal = Field(
        default=Decimal(25), gt=0, le=10_000, max_digits=10, decimal_places=4
    )
    # Every request counts, retries included; the turn caps per phase are in ``budget.py``.
    max_model_calls_per_run: int = Field(default=200, ge=10, le=1_000)
    # Covers model and tool time alike.
    max_run_minutes: int = Field(default=90, ge=5, le=360)
    max_candidates_per_run: int = Field(default=25, ge=1, le=200)


class StorageConfig(StrictModel):
    path: Path = Path(".autocontribute")


class AutocontributeConfig(StrictModel):
    identity: IdentityConfig = Field(default_factory=IdentityConfig)
    github: GitHubConfig = Field(default_factory=GitHubConfig)
    models: ModelsConfig = Field(default_factory=ModelsConfig)
    # Per repository, keyed by owner/name: what detection gets wrong about its environment.
    environments: dict[str, EnvironmentOverride] = Field(default_factory=dict)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    quality: QualityConfig = Field(default_factory=QualityConfig)
    publishing: PublishingConfig = Field(default_factory=PublishingConfig)
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)

    @field_validator("environments")
    @classmethod
    def environments_are_repository_scoped(
        cls, values: dict[str, EnvironmentOverride]
    ) -> dict[str, EnvironmentOverride]:
        normalized: dict[str, EnvironmentOverride] = {}
        for repository, override in values.items():
            if not _REPOSITORY.fullmatch(repository):
                raise ValueError("environments keys must use owner/name syntax")
            key = repository.casefold()
            if key in normalized:
                raise ValueError(
                    f"duplicate environments repository after case-folding: {repository}"
                )
            normalized[key] = override
        return normalized

    @model_validator(mode="after")
    def dco_signatory_is_the_identity(self) -> AutocontributeConfig:
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
        return self

    def environment_for(self, repository: str) -> EnvironmentOverride | None:
        return self.environments.get(repository.casefold())

    def secret_env_names(self) -> frozenset[str]:
        """Name the variables that hold this machine's secrets: the GitHub token, the model keys."""

        return frozenset({self.github.token_env, *API_KEY_ENVS.values()})


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
            "you want to contribute to"
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
    """Return a short starter configuration with no embedded credentials."""

    return """# Every key and its default: docs/configuration.md.
# API keys and tokens never go in this file. Set OPENAI_API_KEY or ANTHROPIC_API_KEY, and sign
# in with `gh auth login` or set AUTOCONTRIBUTE_GITHUB_TOKEN.
github:
  repositories:      # the public repositories to contribute to, as owner/name
    - your-org/your-repo

models:              # auto picks each model from the API key that is set
  agent: auto
  critic: auto
  setup: auto
  triage: auto

budget:              # in US dollars
  max_cost_usd_per_run: 10
  max_cost_usd_per_day: 25
"""


__all__ = [
    "CLA_ATTESTATION_STATEMENT",
    "DCO_ATTESTATION_STATEMENT",
    "AutocontributeConfig",
    "BudgetConfig",
    "CLAAuthorization",
    "DCOAuthorization",
    "GitHubConfig",
    "LegalAttestation",
    "ModelsConfig",
    "PolicyConfig",
    "QualityConfig",
    "RepositoryLabels",
    "ResolvedModels",
    "SandboxConfig",
    "example_config",
    "load_config",
    "starter_placeholders",
    "validate_model_identifier",
]
