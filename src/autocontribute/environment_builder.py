"""Preparing a repository's test environment for a run (DESIGN §5.2-§5.6).

Recipes are tried in order: the operator's ``environments.<repo>`` override (completed by
detection), else the cached recipe whose cache key still matches, else detection; when they
fail, the setup agent may propose one, which is replayed from scratch. A recipe is accepted
once its image is built (or a matching local one reused) and the baseline on the post-setup
snapshot passes the acceptance gate. A repository with no accepted recipe is recorded as
failed, which blocks it for 7 days unless the configuration overrides its environment.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from autocontribute.config import EnvironmentOverride, SandboxConfig
from autocontribute.environment_detection import detect_recipe
from autocontribute.environment_setup import EnvironmentImage, EnvironmentSetup, python_distribution
from autocontribute.environment_signals import RepositorySignals, read_signals
from autocontribute.environments import (
    EnvironmentBaseline,
    EnvironmentRecipe,
    dependency_digest,
    environment_cache_key,
)
from autocontribute.exceptions import (
    EnvironmentRecipeError,
    EnvironmentSetupError,
    EnvironmentUnavailable,
    RepositoryError,
    SandboxError,
)
from autocontribute.repository import RepositoryWorkspace
from autocontribute.sandbox import ImageIdentity, detect_docker_daemon_mode, pull_image
from autocontribute.setup_policy import agent_recipe_violations
from autocontribute.store import RunStore
from autocontribute.suite_runs import acceptance_failure, run_baseline
from autocontribute.workspace_copies import copy_workspace, remove_workspace_copy


@dataclass(frozen=True, slots=True)
class FailedAttempt:
    """What the setup agent is told about a recipe that did not work (DESIGN §5.2, step 4)."""

    recipe: EnvironmentRecipe
    reason: str
    # The end of the failing step's output, or of the baseline's test output.
    log_tail: str


class SetupAgent(Protocol):
    """The LLM fallback that proposes a recipe after the deterministic ones failed."""

    def propose_recipe(
        self, signals: RepositorySignals, failed: FailedAttempt
    ) -> EnvironmentRecipe | None:
        """Return a recipe to replay from scratch, or ``None`` when there is none to offer."""
        ...


@dataclass(frozen=True, slots=True)
class PreparedEnvironment:
    """An accepted environment: its image, recipe, baseline and post-setup snapshot ``S``."""

    image: EnvironmentImage
    recipe: EnvironmentRecipe
    baseline: EnvironmentBaseline
    snapshot: Path


class EnvironmentBuilder:
    """Find, build and accept the test environment of a run's repository."""

    def __init__(
        self,
        config: SandboxConfig,
        store: RunStore,
        *,
        run_id: str,
    ) -> None:
        self.config = config
        self.store = store
        self.run_id = run_id
        self._setup = EnvironmentSetup(config, run_id=run_id, store_root=store.root)
        # Base images resolved during one prepare, so a tag is pulled once.
        self._bases: dict[str, ImageIdentity] = {}

    def prepare(
        self,
        repository: str,
        workspace: RepositoryWorkspace,
        override: EnvironmentOverride | None,
        setup_agent: SetupAgent | None,
    ) -> PreparedEnvironment:
        """Return an accepted environment for ``workspace``, the clone ``W`` at its base.

        Raises :class:`EnvironmentUnavailable` when no recipe works, and
        :class:`SandboxError` when Docker itself fails, which says nothing about the
        repository.
        """

        if override is None and (blocked := self.store.environment_block(repository)):
            raise EnvironmentUnavailable(
                f"The environment of {repository} failed in the last 7 days: {blocked}"
            )
        # Fails before any attempt when Docker is unusable, so that is never blamed on the
        # repository.
        detect_docker_daemon_mode()
        self._bases = {}
        signals = read_signals(workspace)
        allow_hosts = () if override is None else tuple(override.allow_hosts)
        failures: list[FailedAttempt] = []
        tried: list[EnvironmentRecipe] = []
        try:
            for recipe, cache_key in self._candidates(repository, signals, override):
                if any(_same_setup(recipe, earlier) for earlier in tried):
                    continue
                tried.append(recipe)
                try:
                    return self._attempt(
                        workspace, recipe, cache_key, signals, allow_hosts, fresh=bool(failures)
                    )
                except EnvironmentSetupError as exc:
                    failures.append(FailedAttempt(recipe, str(exc), exc.log_tail))
        except EnvironmentRecipeError as exc:
            if not failures:
                self.store.mark_environment_failed(repository, reason=str(exc))
                raise EnvironmentUnavailable(str(exc)) from exc
        proposal = None
        if setup_agent is not None and failures:
            proposal = setup_agent.propose_recipe(signals, failures[-1])
        if proposal is not None:
            agent_recipe = proposal.model_copy(update={"source": "agent"})
            violations = agent_recipe_violations(agent_recipe, signals)
            try:
                if violations:
                    raise EnvironmentSetupError(
                        "The setup agent's recipe breaks the setup policy: " + "; ".join(violations)
                    )
                return self._attempt(
                    workspace, agent_recipe, None, signals, allow_hosts, fresh=True
                )
            except EnvironmentSetupError as exc:
                failures.append(FailedAttempt(agent_recipe, str(exc), exc.log_tail))
        last = failures[-1]
        self.store.mark_environment_failed(repository, reason=last.reason, recipe=last.recipe)
        raise EnvironmentUnavailable(last.reason)

    def _candidates(
        self,
        repository: str,
        signals: RepositorySignals,
        override: EnvironmentOverride | None,
    ) -> Iterator[tuple[EnvironmentRecipe, str | None]]:
        """Yield recipes to try with their cache key when already known."""

        if override is not None:
            yield detect_recipe(repository, signals, override), None
            return
        stored = self.store.environment(repository)
        if stored is not None and stored.status == "ok" and stored.recipe is not None:
            cached = stored.recipe.model_copy(
                update={
                    "source": "cached",
                    "dependency_digest": dependency_digest(signals.dependency_files),
                }
            )
            # The key covers the base image's current digest and today's dependency files.
            try:
                current_key = self._cache_key(cached)
            except EnvironmentSetupError:
                current_key = None
            if current_key == stored.cache_key:
                yield cached, stored.cache_key
        yield detect_recipe(repository, signals), None

    def _attempt(
        self,
        workspace: RepositoryWorkspace,
        recipe: EnvironmentRecipe,
        cache_key: str | None,
        signals: RepositorySignals,
        allow_hosts: tuple[str, ...],
        *,
        fresh: bool,
    ) -> PreparedEnvironment:
        if fresh:
            # A replay starts from the clone as it was, without an earlier attempt's output.
            try:
                workspace.restore_base()
                workspace.remove_ignored()
            except RepositoryError as exc:
                raise EnvironmentSetupError(
                    f"An earlier attempt left changes that cannot be undone: {exc}"
                ) from exc
        base = self._base_image(recipe)
        key = cache_key or self._cache_key(recipe)
        image = None
        if recipe.source != "agent":
            image = self._setup.reuse(workspace, recipe, base=base, cache_key=key)
        if image is None:
            image, recipe = self._setup.build(
                workspace,
                recipe,
                base=base,
                cache_key=key,
                allow_hosts=allow_hosts,
                distribution=_import_checked_distribution(recipe, signals),
            )
        if recipe.source == "agent" and recipe.setup_dirty_paths:
            raise EnvironmentSetupError(
                "The setup agent's recipe changed tracked files: "
                + ", ".join(recipe.setup_dirty_paths[:10])
            )
        snapshot = workspace.path.with_name(f"{workspace.path.name}.snapshot")
        try:
            remove_workspace_copy(snapshot)
            copy_workspace(workspace.path, snapshot)
            baseline, runs = run_baseline(
                self.config,
                image_id=image.image_id,
                recipe=recipe,
                snapshot=snapshot,
                base_sha=workspace.base_sha,
                run_id=self.run_id,
                store_root=self.store.root,
            )
        except RepositoryError as exc:
            # Setup decides what the workspace holds, so a tree that cannot be copied is
            # the recipe's failure.
            raise EnvironmentSetupError(
                f"The post-setup workspace cannot be copied: {exc}"
            ) from exc
        rejection = acceptance_failure(baseline, runs)
        if rejection is not None:
            raise EnvironmentSetupError(
                f"The baseline was not accepted: {rejection}", log_tail=runs[-1].output_tail
            )
        self.store.save_environment(recipe, cache_key=key, baseline=baseline)
        return PreparedEnvironment(image, recipe, baseline, snapshot)

    def _cache_key(self, recipe: EnvironmentRecipe) -> str:
        base = self._base_image(recipe)
        return environment_cache_key(
            language=recipe.language,
            arch=base.platform,
            base_image_digest=base.digest,
            dependency_digest=recipe.dependency_digest,
        )

    def _base_image(self, recipe: EnvironmentRecipe) -> ImageIdentity:
        if recipe.base_image not in self._bases:
            try:
                base = pull_image(recipe.base_image)
            except SandboxError as exc:
                # Docker answered moments ago, so the image reference is what failed.
                raise EnvironmentSetupError(str(exc)) from exc
            self._bases[recipe.base_image] = base
        return self._bases[recipe.base_image]


def _same_setup(recipe: EnvironmentRecipe, other: EnvironmentRecipe) -> bool:
    fields = {"source", "dependency_digest", "setup_dirty_paths"}
    return recipe.model_dump(exclude=fields) == other.model_dump(exclude=fields)


def _import_checked_distribution(
    recipe: EnvironmentRecipe, signals: RepositorySignals
) -> str | None:
    """The Python project to check, unless the tests run in an environment nox builds."""

    if recipe.language != "python" or recipe.test_command.startswith("nox "):
        return None
    return python_distribution(signals)


__all__ = ["EnvironmentBuilder", "FailedAttempt", "PreparedEnvironment", "SetupAgent"]
