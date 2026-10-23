"""Application-specific exceptions with safe, user-facing messages."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class AutocontributeError(Exception):
    """Base class for expected application failures."""


class ConfigurationError(AutocontributeError):
    """The local configuration is missing or invalid."""


class GitHubError(AutocontributeError):
    """A GitHub request or authentication operation failed."""


class StopScope(StrEnum):
    """How much work one safety event stops."""

    GLOBAL = "global"
    # Every publication, while preparation goes on.
    PUBLICATION = "publication"
    REPOSITORY = "repository"
    PULL_REQUEST = "pull_request"


@dataclass(frozen=True, slots=True)
class CircuitBreakerTrigger:
    """Credential-free evidence identifying one immutable safety event.

    A global trigger trips the circuit breaker. Any other scope holds only ``scope_key`` (an
    owner/name, pull-request URL, or API origin) until it expires or an operator releases it.
    """

    source: str
    reason: str
    trigger_hash: str
    scope: StopScope = StopScope.GLOBAL
    scope_key: str = ""
    expires_at: datetime | None = None
    # A maintainer turned this tool's own pull request away as automation. Such holds in two
    # repositories within 30 days escalate to a global stop.
    counts_toward_escalation: bool = False


class GitHubSafetyError(GitHubError):
    """A GitHub response that must be persisted as a safety stop at the trigger's scope."""

    def __init__(self, message: str, *, trigger: CircuitBreakerTrigger) -> None:
        super().__init__(message)
        self.trigger = trigger


class GitHubRateLimitError(GitHubError):
    """GitHub kept rate limiting past the waits this run allows; a later run can retry."""


class GitHubRequestNotSentError(GitHubError):
    """A GitHub request provably failed before any bytes reached the remote host.

    Only connection-establishment failures (DNS, TCP, TLS, or connection-pool
    acquisition) are classified this way, so a mutation that fails with this error
    cannot have changed remote state and is safe to retry.
    """


class ModelError(AutocontributeError):
    """A model request failed or returned an invalid result."""


class ModelRequestError(ModelError):
    """A provider HTTP request failed before it produced a valid model response.

    ``status_code`` is the provider's HTTP status when one was observed (4xx/5xx),
    or ``None`` for network-level failures where no response arrived.
    ``provider_code`` is an allowlisted provider error code such as ``insufficient_quota``, and
    ``retry_after_seconds`` the wait the provider asked for, when it sent either.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        provider_code: str | None = None,
        retry_after_seconds: float | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.provider_code = provider_code
        self.retry_after_seconds = retry_after_seconds


class ModelTimeoutError(ModelError):
    """The application killed a model worker after its absolute deadline."""

    def __init__(
        self,
        *,
        timeout_seconds: float,
        elapsed_seconds: float,
        term_sent: bool,
        kill_sent: bool,
        child_exit_code: int | None,
    ) -> None:
        super().__init__(
            f"Model call exceeded its {timeout_seconds:.3f}-second application deadline"
        )
        self.timeout_seconds = timeout_seconds
        self.elapsed_seconds = elapsed_seconds
        self.term_sent = term_sent
        self.kill_sent = kill_sent
        self.child_exit_code = child_exit_code


class RepositoryError(AutocontributeError):
    """A repository operation could not be completed safely."""


class PolicyError(AutocontributeError):
    """A contribution violated a non-negotiable policy."""


class PatchEncodingError(PolicyError):
    """A patch is not UTF-8 text, so it fails a gate instead of crashing the run (G7)."""

    def __init__(self, paths: tuple[str, ...]) -> None:
        listed = ", ".join(paths) if paths else "unknown files"
        super().__init__(f"The patch is not UTF-8 text; non-UTF-8 content in: {listed}")
        self.paths = paths


class SandboxError(AutocontributeError):
    """An isolated validation command could not be executed."""


class EnvironmentRecipeError(AutocontributeError):
    """No recipe for building a repository's test environment could be found."""


class EnvironmentSetupError(AutocontributeError):
    """A recipe did not build an accepted environment, through the repository's doing.

    Sandbox failures raise :class:`SandboxError` instead, so they never count against the
    repository.
    """

    def __init__(self, message: str, *, log_tail: str = "") -> None:
        super().__init__(message)
        # The end of the output that explains the failure, for the setup agent.
        self.log_tail = log_tail


class EnvironmentUnavailable(AutocontributeError):
    """No environment could be built for a repository; its run is skipped (DESIGN §1)."""


class SuiteReportError(AutocontributeError):
    """A test runner's report is malformed, too large, or of an unsupported kind."""


class StateError(AutocontributeError):
    """A run attempted an invalid or stale state transition."""


class PublicationResumeRequired(StateError):
    """A durable publication intent has no PR yet and may be resumed idempotently."""
