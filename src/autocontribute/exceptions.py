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


class ModelError(AutocontributeError):
    """A model request failed or returned an invalid result."""


class RepositoryError(AutocontributeError):
    """A repository operation could not be completed safely."""


class PolicyError(AutocontributeError):
    """A contribution violated a non-negotiable policy."""


class SandboxError(AutocontributeError):
    """An isolated validation command could not be executed."""


class StateError(AutocontributeError):
    """A run attempted an invalid or stale state transition."""


class PublicationResumeRequired(StateError):
    """A durable publication intent has no PR yet and may be resumed idempotently."""
