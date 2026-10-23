"""The triage model behind discovery's issue triage and AI-policy classification (DESIGN §8).

Each question is a one-turn transcript with the triage model: the first message holds the
facts and the model answers with its submit tool, from the run budget's triage scope. Policy
quotes are attributed to the file that holds them, so that discovery's ``checked_ai_policy``
can verify each one verbatim; a quote no file holds keeps an empty path and fails that check.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TypeVar

from pydantic import BaseModel

from autocontribute.agent_loop import AgentLoop, DidNotFinish, Finished
from autocontribute.ai_policy import AiPolicyQuote, PolicyFile, RepositoryAiPolicy
from autocontribute.budget import RunBudget
from autocontribute.discovery import TriageVerdict
from autocontribute.domain import IssueCandidate, RepositoryInfo
from autocontribute.exceptions import ModelError
from autocontribute.instructions import load_instructions
from autocontribute.pricing import DEFAULT_EFFORTS, Effort
from autocontribute.providers import TurnProvider
from autocontribute.store import RunStore
from autocontribute.submissions import PolicySubmission, TriageSubmission
from autocontribute.task_messages import policy_task, triage_task
from autocontribute.transcript import TranscriptKind, start_transcript

SubmissionT = TypeVar("SubmissionT", bound=BaseModel)


class _OneTurn:
    """Ask the triage model one question per transcript, numbering transcripts per kind."""

    def __init__(
        self,
        *,
        provider: TurnProvider,
        model: str,
        budget: RunBudget,
        store: RunStore,
        host_values: frozenset[str],
        effort: Effort,
    ) -> None:
        self._provider = provider
        self._model = model
        self._budget = budget
        self._store = store
        self._host_values = host_values
        self._effort = effort
        self._asked: dict[TranscriptKind, int] = {}

    def ask(self, kind: TranscriptKind, task: str, submission: type[SubmissionT]) -> SubmissionT:
        """Return the model's answer; raises ``ModelError`` when it gives none."""

        number = self._asked.get(kind, 0) + 1
        self._asked[kind] = number
        transcript = start_transcript(
            model=self._model,
            effort=self._effort,
            kind=kind,
            run_id=self._budget.manifest.run_id,
            instructions=load_instructions(kind),
            task=task,
            host_values=self._host_values,
        )
        outcome = AgentLoop(
            transcript,
            number=number,
            submission=submission,
            provider=self._provider,
            budget=self._budget,
            store=self._store,
            host_values=self._host_values,
        ).run()
        if isinstance(outcome, Finished):
            return outcome.submission
        if isinstance(outcome, DidNotFinish):
            raise ModelError(f"The {kind} model gave no answer: {outcome.detail}")
        # Discovery goes on to other questions, which must be able to reserve.
        self._budget.charge_failed_request(reason=outcome.message)
        raise ModelError(f"The {kind} model gave no answer: {outcome.message}")


class ModelIssueTriage:
    """Discovery's :class:`autocontribute.discovery.IssueTriage`, answered by the triage model.

    ``model`` is the triage model's id from the built-in table.
    """

    def __init__(
        self,
        *,
        provider: TurnProvider,
        model: str,
        budget: RunBudget,
        store: RunStore,
        host_values: frozenset[str],
        effort: Effort = DEFAULT_EFFORTS["triage"],
    ) -> None:
        self._host_values = host_values
        self._model = _OneTurn(
            provider=provider,
            model=model,
            budget=budget,
            store=store,
            host_values=host_values,
            effort=effort,
        )

    def triage(self, issue: IssueCandidate, repository: RepositoryInfo) -> TriageVerdict:
        task = triage_task(issue, repository, host_values=self._host_values)
        answer = self._model.ask("triage", task, TriageSubmission)
        return TriageVerdict.model_validate(answer.model_dump())


class ModelPolicyClassifier:
    """Discovery's :class:`autocontribute.discovery.PolicyClassifier`, on the triage model."""

    def __init__(
        self,
        *,
        provider: TurnProvider,
        model: str,
        budget: RunBudget,
        store: RunStore,
        host_values: frozenset[str],
        effort: Effort = DEFAULT_EFFORTS["triage"],
    ) -> None:
        self._host_values = host_values
        self._model = _OneTurn(
            provider=provider,
            model=model,
            budget=budget,
            store=store,
            host_values=host_values,
            effort=effort,
        )

    def classify(
        self, repository: RepositoryInfo, files: Sequence[PolicyFile]
    ) -> RepositoryAiPolicy:
        task = policy_task(repository, files, host_values=self._host_values)
        answer = self._model.ask("policy", task, PolicySubmission)
        return RepositoryAiPolicy(
            stance=answer.stance,
            requires_disclosure=answer.requires_disclosure,
            disclosure_requirements=answer.disclosure_requirements,
            requires_human_written_text=answer.requires_human_written_text,
            quotes=[_attributed(quote, repository, files) for quote in answer.quotes],
        )


def _attributed(
    quote: str, repository: RepositoryInfo, files: Sequence[PolicyFile]
) -> AiPolicyQuote:
    collapsed = " ".join(quote.split())
    holder = next(
        (file for file in files if collapsed and collapsed in " ".join(file.text.split())), None
    )
    if holder is None:
        return AiPolicyQuote(repository=repository.full_name, path="", text=quote)
    return AiPolicyQuote(repository=holder.repository, path=holder.path, text=quote)


__all__ = ["ModelIssueTriage", "ModelPolicyClassifier"]
