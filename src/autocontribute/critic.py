"""The critic: a fresh reviewer for each round of a fix that passed its checks (DESIGN §7.2).

Each round starts a new transcript with the shell tool only, in a network-less session on a
throwaway copy of ``V``, and ends with ``submit_review``. It never sees the agent's transcript;
its first message holds the inputs §7.2 lists. The controller then confirms each blocker: it
re-runs the blocker's ``check_command`` on a clean copy of ``V`` and keeps the blocker only
when the check runs and fails. A scope, policy or text blocker needs no command; it stands
when the passage it quotes is really there.

A round approves when no blocker is confirmed, sends the confirmed blockers back to the agent,
or rejects the run: on ``abandon``, on a blocker that the previous round already reported, and
on any blocker in the last round.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

from autocontribute.agent_loop import AgentLoop, DidNotFinish, Finished, LoopFailure, SubmittedFix
from autocontribute.agent_tools import MAX_AGENT_COMMAND_SECONDS, SessionTools
from autocontribute.budget import RunBudget
from autocontribute.exceptions import RepositoryError
from autocontribute.fix_checks import FixCheckResult
from autocontribute.instructions import load_instructions
from autocontribute.pricing import DEFAULT_EFFORTS, Effort
from autocontribute.providers import TurnProvider
from autocontribute.store import RunStore
from autocontribute.submissions import BlockerCategory, ReviewBlocker, ReviewSubmission
from autocontribute.task_messages import RunFacts, critic_task
from autocontribute.transcript import start_transcript
from autocontribute.validation_sandbox import ValidationSandbox
from autocontribute.workspace_copies import copy_workspace, remove_workspace_copy
from autocontribute.workspace_files import WorkspaceFiles

MAX_CRITIC_ROUNDS: Final = 2
# These categories need no command: the passage a blocker quotes is the evidence (§7.2).
QUOTED_CATEGORIES: Final[frozenset[BlockerCategory]] = frozenset(
    {"scope_creep", "policy_violation", "misleading_text"}
)
# A shell's "cannot execute" and "not found": the check did not run.
_NOT_RUN_EXIT_CODES: Final = frozenset({126, 127})
# Shorter quotes match too much to prove anything.
_MIN_QUOTE_CHARACTERS: Final = 8
_QUOTED: Final = re.compile(r"```[^\n]*\n(.*?)```|`([^`\n]+)`|\"([^\"\n]+)\"|“([^”\n]+)”", re.S)
_WAIVER_BLOCKER: Final = ReviewBlocker(
    category="weak_test",
    path=None,
    line=None,
    evidence=(
        "The change edits source files without adding or changing a test, and the review did "
        "not find a test unnecessary."
    ),
    check_command=None,
    fix_hint="Add a test in the project's test suite that fails without the fix.",
)


@dataclass(frozen=True, slots=True)
class DroppedBlocker:
    """A reported blocker the controller could not confirm, and why."""

    blocker: ReviewBlocker
    reason: str


@dataclass(frozen=True, slots=True)
class CriticRound:
    """One round's review and what the controller made of it."""

    number: int
    decision: Literal["approve", "request_changes", "reject"]
    # Why the run is rejected; empty otherwise.
    reason: str
    review: ReviewSubmission
    # What goes back to the agent on request_changes.
    confirmed: tuple[ReviewBlocker, ...]
    dropped: tuple[DroppedBlocker, ...]


CriticOutcome = CriticRound | DidNotFinish | LoopFailure


class Critic:
    """The critic rounds of one run.

    ``model`` is the critic's model id: ``pricing.resolve_critic`` picks the other provider's
    flagship when both providers' keys are set, and ``provider`` must serve it.
    ``guidance_paths`` name the repository's guidance files, which the critic reads itself.
    """

    def __init__(
        self,
        facts: RunFacts,
        sandbox: ValidationSandbox,
        *,
        provider: TurnProvider,
        model: str,
        budget: RunBudget,
        store: RunStore,
        host_values: frozenset[str],
        command_timeout_seconds: int,
        guidance_paths: Sequence[str] = (),
        effort: Effort = DEFAULT_EFFORTS["critic"],
    ) -> None:
        self._facts = facts
        self._sandbox = sandbox
        self._provider = provider
        self._model = model
        self._effort = effort
        self._budget = budget
        self._store = store
        self._host_values = host_values
        self._timeout_limit = command_timeout_seconds
        self._guidance_paths = tuple(guidance_paths)
        self.rounds: list[CriticRound] = []

    def review(
        self, fix: SubmittedFix, check: FixCheckResult, *, patch: str, validated: Path
    ) -> CriticOutcome:
        """Review a confirmed fix: ``patch`` is its diff and ``validated`` its tree ``V``.

        Returns the round, or how its transcript ended without a review.
        """

        number = len(self.rounds) + 1
        if number > MAX_CRITIC_ROUNDS:
            raise ValueError(f"the critic reviews at most {MAX_CRITIC_ROUNDS} rounds")
        earlier = self.rounds[-1].confirmed if self.rounds else ()
        transcript = start_transcript(
            model=self._model,
            effort=self._effort,
            kind="critic",
            run_id=self._budget.manifest.run_id,
            instructions=load_instructions("critic"),
            task=critic_task(
                self._facts,
                round_number=number,
                submission=fix.submission,
                patch=patch,
                check=check,
                guidance_paths=self._guidance_paths,
                earlier_blockers=earlier,
                host_values=self._host_values,
            ),
            host_values=self._host_values,
        )
        copy = validated.with_name(f"{validated.name}.review-{secrets.token_hex(4)}")
        copy_workspace(validated, copy)
        try:
            with self._sandbox.session(copy, timeout_seconds=self._timeout()) as session:
                loop = AgentLoop(
                    transcript,
                    number=number,
                    submission=ReviewSubmission,
                    provider=self._provider,
                    budget=self._budget,
                    store=self._store,
                    host_values=self._host_values,
                    tools=SessionTools(
                        session,
                        WorkspaceFiles(copy),
                        command_timeout_seconds=self._timeout_limit,
                        seconds_left=self._budget.seconds_left,
                        environment=self._sandbox.environment,
                    ),
                )
                outcome = loop.run()
        finally:
            remove_workspace_copy(copy)
        if not isinstance(outcome, Finished):
            return outcome
        review = outcome.submission
        confirmed, dropped = self._confirm(review.blockers, fix, patch, validated)
        if check.test_waiver_needed and not review.no_test_needed:
            confirmed.append(_WAIVER_BLOCKER)
        decision, reason = _decide(number, review, confirmed, earlier)
        result = CriticRound(number, decision, reason, review, tuple(confirmed), tuple(dropped))
        self.rounds.append(result)
        return result

    def _confirm(
        self, blockers: Sequence[ReviewBlocker], fix: SubmittedFix, patch: str, validated: Path
    ) -> tuple[list[ReviewBlocker], list[DroppedBlocker]]:
        confirmed: list[ReviewBlocker] = []
        dropped: list[DroppedBlocker] = []
        for blocker in blockers:
            if blocker.category in QUOTED_CATEGORIES:
                reason = self._quote_missing(blocker, fix, patch, validated)
            else:
                reason = self._check_passes(blocker, validated)
            if reason is None:
                confirmed.append(blocker)
            else:
                dropped.append(DroppedBlocker(blocker, reason))
        return confirmed, dropped

    def _check_passes(self, blocker: ReviewBlocker, validated: Path) -> str | None:
        """Why the blocker's check does not confirm it, or None when it fails as it should."""

        command = (blocker.check_command or "").strip()
        if not command:
            return "it has no check command"
        timeout = min(self._timeout(), MAX_AGENT_COMMAND_SECONDS)
        if timeout < 1:
            return "the run is out of time for its check"
        run = self._sandbox.run_check(validated, command, timeout_seconds=timeout)
        if run.failure is not None:
            return f"its check could not run: {run.failure}"
        if run.timed_out or run.exit_code in _NOT_RUN_EXIT_CODES:
            return "its check could not run"
        if run.exit_code == 0:
            return "its check passes"
        return None

    def _quote_missing(
        self, blocker: ReviewBlocker, fix: SubmittedFix, patch: str, validated: Path
    ) -> str | None:
        """Why the blocker's quote does not confirm it, or None when the passage is there."""

        submission = fix.submission
        sources: list[str]
        if blocker.category == "scope_creep":
            sources = [patch, _without_diff_markers(patch)]
        elif blocker.category == "misleading_text":
            sources = [submission.pr_title or "", submission.pr_body or ""]
            sources.append(submission.commit_message or "")
        else:
            policy = self._facts.ai_policy
            sources = [quote.text for quote in policy.quotes] if policy is not None else []
            if blocker.path is not None:
                # A rule must be quoted from the file the blocker names, which may be absent.
                with suppress(RepositoryError):
                    sources.append(WorkspaceFiles(validated).read_text(blocker.path))
        texts = [_collapsed(source) for source in sources]
        quotes = [_collapsed(quote) for quote in _quotes(blocker.evidence)]
        if any(quote and quote in text for quote in quotes for text in texts):
            return None
        return "the passage it quotes is not there"

    def _timeout(self) -> int:
        return self._budget.command_timeout(self._timeout_limit)


def _decide(
    number: int,
    review: ReviewSubmission,
    confirmed: Sequence[ReviewBlocker],
    earlier: Sequence[ReviewBlocker],
) -> tuple[Literal["approve", "request_changes", "reject"], str]:
    if review.verdict == "abandon":
        return "reject", f"the reviewer abandoned the change: {review.summary}"
    repeated = [blocker for blocker in confirmed if any(_same(blocker, old) for old in earlier)]
    if repeated:
        listed = ", ".join(_describe(blocker) for blocker in repeated)
        return "reject", f"blockers from review round {number - 1} are still there: {listed}"
    if confirmed and number >= MAX_CRITIC_ROUNDS:
        listed = ", ".join(_describe(blocker) for blocker in confirmed)
        return "reject", f"blockers remain after the last review round: {listed}"
    if confirmed:
        return "request_changes", ""
    return "approve", ""


def _same(blocker: ReviewBlocker, other: ReviewBlocker) -> bool:
    # Lines move when the agent edits, so a repeated blocker has the category and path.
    return blocker.category == other.category and blocker.path == other.path


def _describe(blocker: ReviewBlocker) -> str:
    return f"{blocker.category} in {blocker.path}" if blocker.path else blocker.category


def _quotes(evidence: str) -> list[str]:
    """The passages a blocker's evidence quotes, or the whole evidence when it quotes none."""

    found = [
        next(group for group in match.groups() if group is not None)
        for match in _QUOTED.finditer(evidence)
    ]
    passages = [passage for passage in found if len(passage.strip()) >= _MIN_QUOTE_CHARACTERS]
    return passages or [evidence]


def _without_diff_markers(patch: str) -> str:
    return "\n".join(
        line[1:] if line[:1] in {"+", "-", " "} else line for line in patch.split("\n")
    )


def _collapsed(text: str) -> str:
    return " ".join(text.split())


__all__ = [
    "MAX_CRITIC_ROUNDS",
    "QUOTED_CATEGORIES",
    "Critic",
    "CriticOutcome",
    "CriticRound",
    "DroppedBlocker",
]
