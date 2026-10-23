"""Where the fix checks and the critic run repository code: the accepted environment's image.

Every test run, check command and review session starts a fresh network-less container from
the environment image on a workspace copy, as baselines do (DESIGN §4.1, §5.4), and runs the
recipe's offline build commands first. :class:`ValidationSandbox` is what the checks and the
critic call; :class:`DockerValidation` does it with Docker.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from autocontribute.config import SandboxConfig
from autocontribute.environments import TOOL_ROOT, EnvironmentRecipe
from autocontribute.exceptions import SandboxError
from autocontribute.sandbox import SessionContainer
from autocontribute.suite_runs import (
    CheckRun,
    SuiteRun,
    offline_environment,
    run_build_commands,
    run_check,
    run_suite,
)


class ValidationSandbox(Protocol):
    """Offline runs in the run's accepted environment."""

    @property
    def environment(self) -> Mapping[str, str]:
        """The variables commands run with."""
        ...

    def run_suite(
        self, source: Path, *, timeout_seconds: int, test_command: str | None = None
    ) -> SuiteRun:
        """Run the test command, or ``test_command``, on a fresh copy of ``source``."""
        ...

    def run_check(self, source: Path, command: str, *, timeout_seconds: int) -> CheckRun:
        """Run one command on a fresh copy of ``source``."""
        ...

    def session(
        self, workspace: Path, *, timeout_seconds: int
    ) -> AbstractContextManager[SessionContainer]:
        """Start a session on ``workspace`` itself, built and ready for commands."""
        ...


@dataclass(frozen=True, slots=True)
class DockerValidation:
    """The validation sandbox of one run, on its environment image."""

    config: SandboxConfig
    image_id: str
    recipe: EnvironmentRecipe
    run_id: str
    store_root: Path

    @property
    def environment(self) -> Mapping[str, str]:
        return offline_environment(self.recipe)

    def run_suite(
        self, source: Path, *, timeout_seconds: int, test_command: str | None = None
    ) -> SuiteRun:
        return run_suite(
            self.config,
            image_id=self.image_id,
            recipe=self.recipe,
            source=source,
            run_id=self.run_id,
            store_root=self.store_root,
            timeout_seconds=timeout_seconds,
            test_command=test_command,
        )

    def run_check(self, source: Path, command: str, *, timeout_seconds: int) -> CheckRun:
        return run_check(
            self.config,
            image_id=self.image_id,
            recipe=self.recipe,
            source=source,
            run_id=self.run_id,
            store_root=self.store_root,
            command=command,
            timeout_seconds=timeout_seconds,
        )

    @contextmanager
    def session(self, workspace: Path, *, timeout_seconds: int) -> Iterator[SessionContainer]:
        """Start a session on ``workspace`` and run the build commands in it.

        Raises :class:`SandboxError` when a build command fails: the checks built the same tree
        moments earlier, so the sandbox is what changed.
        """

        with SessionContainer(
            self.config,
            image=self.image_id,
            workspace=workspace,
            run_id=self.run_id,
            store_root=self.store_root,
            volumes=(TOOL_ROOT,),
        ) as container:
            build = run_build_commands(container, self.recipe, timeout_seconds=timeout_seconds)
            if build is not None:
                raise SandboxError(f"The review session could not be built: {build[1]}")
            yield container


__all__ = ["DockerValidation", "ValidationSandbox"]
