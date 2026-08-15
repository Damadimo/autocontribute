"""Application-specific exceptions with safe, user-facing messages."""

from __future__ import annotations

from dataclasses import dataclass


class AutocontributeError(Exception):
    """Base class for expected application failures."""


class ConfigurationError(AutocontributeError):
    """The local configuration is missing or invalid."""


class GitHubError(AutocontributeError):
    """A GitHub request or authentication operation failed."""


@dataclass(frozen=True, slots=True)
class CircuitBreakerTrigger:
    """Credential-free evidence identifying one immutable global safety event."""

    source: str
    reason: str
    trigger_hash: str


class GitHubSafetyError(GitHubError):
    """A GitHub response that must be persisted as a global safety stop."""

    def __init__(self, message: str, *, trigger: CircuitBreakerTrigger) -> None:
        super().__init__(message)
        self.trigger = trigger


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
    """

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


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


class AutomaticRolloutBlocked(PolicyError):
    """Measured rollout evidence does not currently authorize automatic publication."""


class SandboxError(AutocontributeError):
    """An isolated validation command could not be executed."""


class StateError(AutocontributeError):
    """A run attempted an invalid or stale state transition."""


class PublicationResumeRequired(StateError):
    """A durable publication intent has no PR yet and may be resumed idempotently."""
