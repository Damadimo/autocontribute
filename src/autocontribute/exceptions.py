"""Application-specific exceptions with safe, user-facing messages."""


class AutocontributeError(Exception):
    """Base class for expected application failures."""


class ConfigurationError(AutocontributeError):
    """The local configuration is missing or invalid."""


class GitHubError(AutocontributeError):
    """A GitHub request or authentication operation failed."""


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
