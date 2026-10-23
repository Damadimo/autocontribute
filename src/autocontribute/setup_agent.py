"""The setup agent behind the environment builder's fallback (DESIGN §5.2, step 4).

When the configured, cached and detected recipes fail, the setup agent works in the setup
container that :meth:`EnvironmentSetup.build` would use: the failed recipe's base image with
its system packages installed, network through the egress proxy only. It gets the repository's
signals and the failed attempt, and ends with ``submit_setup``. Each submission is turned into
a recipe at once and checked against the setup policy, so the agent can correct a refused
one; the builder checks the policy again and replays the recipe from scratch.
"""

from __future__ import annotations

from collections.abc import Collection

from pydantic import ValidationError

from autocontribute.agent_loop import AgentLoop, Finished, LoopFailure, SubmitReply
from autocontribute.agent_tools import SessionTools
from autocontribute.budget import RunBudget
from autocontribute.config import SandboxConfig
from autocontribute.edit_tools import describe_validation_error
from autocontribute.environment_builder import FailedAttempt
from autocontribute.environment_detection import reported_test_command
from autocontribute.environment_setup import DEFAULT_ALLOWED_HOSTS, EnvironmentSetup
from autocontribute.environment_signals import RepositorySignals
from autocontribute.environments import EnvironmentRecipe
from autocontribute.exceptions import (
    EnvironmentSetupError,
    ModelError,
    RepositoryError,
    SandboxError,
)
from autocontribute.instructions import load_instructions
from autocontribute.pricing import DEFAULT_EFFORTS, Effort
from autocontribute.providers import TurnProvider
from autocontribute.repository import RepositoryWorkspace
from autocontribute.sandbox import ImageIdentity, inspect_image, pull_image
from autocontribute.setup_policy import agent_recipe_violations
from autocontribute.store import RunStore
from autocontribute.submissions import SetupSubmission
from autocontribute.suite_runs import baseline_time_limit
from autocontribute.task_messages import setup_task
from autocontribute.transcript import start_transcript
from autocontribute.workspace_files import WorkspaceFiles


class ModelSetupAgent:
    """The builder's :class:`autocontribute.environment_builder.SetupAgent`.

    ``workspace`` is the clone ``W`` the builder prepares. ``model`` is the setup model's id
    and ``allow_hosts`` the hosts ``environments.<repo>.allow_hosts`` adds to the proxy's list.
    """

    def __init__(
        self,
        workspace: RepositoryWorkspace,
        config: SandboxConfig,
        *,
        provider: TurnProvider,
        model: str,
        budget: RunBudget,
        store: RunStore,
        host_values: frozenset[str],
        allow_hosts: Collection[str] = (),
        effort: Effort = DEFAULT_EFFORTS["setup"],
    ) -> None:
        self._workspace = workspace
        self._config = config
        self._provider = provider
        self._model = model
        self._budget = budget
        self._store = store
        self._host_values = host_values
        self._allow_hosts = frozenset(allow_hosts)
        self._effort = effort
        self._setup = EnvironmentSetup(config, run_id=budget.manifest.run_id, store_root=store.root)
        self._transcripts = 0

    def propose_recipe(
        self, signals: RepositorySignals, failed: FailedAttempt
    ) -> EnvironmentRecipe | None:
        """Return the agent's recipe, or ``None`` when it ends without an acceptable one.

        Raises ``ModelError`` when the provider fails and ``SandboxError`` when Docker does.
        """

        recipe = failed.recipe
        try:
            # The agent starts from the clone as it was, as a replay does.
            self._workspace.restore_base()
            self._workspace.remove_ignored()
            base = _base_image(recipe.base_image)
        except (RepositoryError, SandboxError):
            return None
        self._transcripts += 1
        transcript = start_transcript(
            model=self._model,
            effort=self._effort,
            kind="setup",
            run_id=self._budget.manifest.run_id,
            instructions=load_instructions("setup"),
            task=setup_task(
                recipe.repository,
                signals,
                failed,
                allowed_hosts=sorted(DEFAULT_ALLOWED_HOSTS | self._allow_hosts),
                test_time_limit_seconds=baseline_time_limit(self._config),
                host_values=self._host_values,
            ),
            host_values=self._host_values,
        )
        proposals: list[EnvironmentRecipe] = []

        def on_submit(submission: SetupSubmission, *, last_turn: bool) -> SubmitReply:
            try:
                proposal = _recipe(submission, recipe)
            except ValidationError as exc:
                return SubmitReply(
                    "continue",
                    f"The recipe is not valid: {describe_validation_error(exc)}. Correct it and "
                    "call submit_setup again.",
                )
            violations = agent_recipe_violations(proposal, signals)
            if violations:
                return SubmitReply(
                    "continue",
                    "The setup policy refuses this recipe: "
                    + "; ".join(violations)
                    + ". Change it and call submit_setup again.",
                )
            proposals.append(proposal)
            return SubmitReply("accept", "Recipe received; the controller replays it now.")

        try:
            with self._setup.session(
                self._workspace, recipe, base=base, allow_hosts=self._allow_hosts
            ) as (container, environment):
                outcome = AgentLoop(
                    transcript,
                    number=self._transcripts,
                    submission=SetupSubmission,
                    provider=self._provider,
                    budget=self._budget,
                    store=self._store,
                    host_values=self._host_values,
                    tools=SessionTools(
                        container,
                        WorkspaceFiles(self._workspace.path),
                        command_timeout_seconds=self._config.command_timeout_seconds,
                        seconds_left=self._budget.seconds_left,
                        environment=environment,
                    ),
                    on_submit=on_submit,
                ).run()
        except EnvironmentSetupError:
            # The failed recipe's own bootstrap failed, so there is no container to work in.
            return None
        if isinstance(outcome, LoopFailure):
            if outcome.source == "sandbox":
                raise SandboxError(outcome.message)
            raise ModelError(outcome.message)
        if isinstance(outcome, Finished):
            return proposals[-1]
        return None


def _base_image(reference: str) -> ImageIdentity:
    found = inspect_image(reference)
    return found if found is not None else pull_image(reference)


def _recipe(submission: SetupSubmission, failed: EnvironmentRecipe) -> EnvironmentRecipe:
    """The failed recipe with the agent's fields; its test command gets a per-test reporter."""

    command, framework, report = reported_test_command(submission.test_command)
    fields = {
        **failed.model_dump(),
        "base_image": submission.base_image,
        "system_packages": sorted(set(submission.system_packages)),
        "setup_commands": submission.setup_commands,
        "build_commands": submission.build_commands,
        "test_command": command,
        "test_framework": framework,
        "test_report": report,
        "setup_dirty_paths": [],
        "source": "agent",
    }
    return EnvironmentRecipe.model_validate(fields)


__all__ = ["ModelSetupAgent"]
