"""The agent loop of DESIGN §6: model turns one at a time, tools in the session, until submit.

An :class:`AgentLoop` drives one transcript. Before each request it reserves the request's worst
case in the run budget, and it settles the turn's usage afterwards. It runs the turn's tool calls
in order and appends one result per call, followed by any message for the model: guidance from a
nested AGENTS.md, a reminder to finish, or a nudge after a turn without tool calls. A valid call
of the transcript's submit tool goes to the caller's submit handler, which accepts it, answers it
and lets the model go on, or ends the loop at its submit limit.

A loop ends with one of:

- ``Finished``: a submission was accepted.
- ``DidNotFinish``: a limit ended the transcript first: its turns, the budget, the run's time,
  the context limit, a model that stopped calling tools, kept sending malformed calls or kept
  repeating a failing command, or the handler's submit limit. DESIGN §1 rejects such a run.
- ``LoopFailure``: the provider failed after its retries, or the sandbox failed. The run fails.

:class:`Solver` is the loop of the agent transcript. It checks each submitted fix with the
caller's :class:`FixChecker` and asks for a confirming submit (DESIGN §6.5), and it takes the
critic's blockers back on the same transcript.
"""

from __future__ import annotations

import json
import secrets
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from typing import Final, Generic, Literal, Protocol, TypeVar

from pydantic import BaseModel, JsonValue, ValidationError

from autocontribute.agent_tools import SessionTools, ToolOutcome, refused
from autocontribute.budget import SCOPES, TRANSCRIPT_SCOPES, RunBudget
from autocontribute.edit_tools import describe_validation_error
from autocontribute.exceptions import (
    BudgetExhaustedError,
    ModelError,
    ModelRequestError,
    ModelTimeoutError,
    SandboxError,
    StateError,
)
from autocontribute.model_retry import retry_decision
from autocontribute.pricing import MODELS, TURN_OUTPUT_CAPS, ModelSpec
from autocontribute.providers import OPAQUE_FIELDS, TurnProvider
from autocontribute.redaction import HIGH_CONFIDENCE_TOKEN_PATTERNS, redact_text, scrub_for_model
from autocontribute.store import RunStore
from autocontribute.submissions import AgentSubmission, ReviewBlocker
from autocontribute.transcript import (
    SUBMIT_TOOLS,
    TOOL_SETS,
    ToolCall,
    ToolResult,
    Transcript,
    Turn,
    append_tool_results,
    append_turn,
    append_user_text,
    next_input_reservation,
    read_submission,
)
from autocontribute.untrusted import untrusted_block

SubmissionT = TypeVar("SubmissionT", bound=BaseModel)
SubmissionT_contra = TypeVar("SubmissionT_contra", bound=BaseModel, contravariant=True)

# A request whose input may pass this ends the transcript with one last turn (DESIGN §6.6). The
# room between it and the model's long-context tier is what that last turn uses.
CONTEXT_LIMIT_TOKENS: Final = 200_000
MAX_NUDGES: Final = 2
MAX_MALFORMED_TURNS: Final = 3
MAX_REPEATED_FAILURES: Final = 3
REMINDER_TURNS_LEFT: Final = 10
REMINDER_COST_SHARE: Final = Decimal("0.25")
# The smallest per-turn cap in the model table; with less room a turn mostly stops at its limit.
MIN_TURN_OUTPUT_TOKENS: Final = 4_000
# Submits of a fix per round, the confirming one included.
MAX_FIX_SUBMITS: Final = 4
_SYSTEM_RANDOM: Final = secrets.SystemRandom()
_TOKEN_REFUSAL: Final = (
    "Refused: the arguments contain what looks like a credential. Nothing ran. Write a "
    "placeholder such as <TOKEN> in its place and call the tool again."
)

_SECOND_SUBMIT: Final = (
    "Not run: a turn may call submit once. Read the result of the first call, then call submit "
    "again in a later turn."
)

StopReason = Literal[
    "turns",
    "budget",
    "time",
    "context",
    "no_tool_call",
    "malformed",
    "repeated_failure",
    "submit_limit",
]


@dataclass(frozen=True)
class Finished(Generic[SubmissionT]):
    """The submit handler accepted this submission."""

    submission: SubmissionT


@dataclass(frozen=True, slots=True)
class DidNotFinish:
    """A limit ended the transcript before a submission was accepted."""

    reason: StopReason
    detail: str


@dataclass(frozen=True, slots=True)
class LoopFailure:
    """The provider, after its retries, or the sandbox failed."""

    source: Literal["provider", "sandbox"]
    message: str


LoopOutcome = Finished[SubmissionT] | DidNotFinish | LoopFailure


@dataclass(frozen=True, slots=True)
class SubmitReply:
    """The controller's answer to a valid submit call, sent back as its tool result.

    ``accept`` ends the loop with the submission; ``continue`` lets the model go on; ``stop``
    ends the loop because no further submit is allowed.
    """

    action: Literal["accept", "continue", "stop"]
    text: str


class SubmitHandler(Protocol[SubmissionT_contra]):
    def __call__(self, submission: SubmissionT_contra, *, last_turn: bool) -> SubmitReply:
        """Answer one valid submission; ``last_turn`` is true when no turn can follow it."""
        ...


class AgentLoop(Generic[SubmissionT]):
    """Drive one transcript until a submission ends it or a limit does.

    ``submission`` is the transcript kind's submit model. ``tools`` runs the shell and edit
    calls; transcripts with only a submit tool have none. ``on_submit`` answers valid
    submissions; without one, the first valid submission ends the loop. ``nested_guidance``
    maps a directory below the workspace root to a message carrying its AGENTS.md, already
    wrapped as untrusted text; it is appended after the first edit under that directory.
    ``number`` counts the run's transcripts of this kind: the loop keeps the transcript, redacted,
    in ``runs/<run id>/<kind>-<number>.jsonl``. ``host_values`` are the host secret values.
    """

    def __init__(
        self,
        transcript: Transcript,
        *,
        number: int,
        submission: type[SubmissionT],
        provider: TurnProvider,
        budget: RunBudget,
        store: RunStore,
        host_values: frozenset[str],
        tools: SessionTools | None = None,
        on_submit: SubmitHandler[SubmissionT] | None = None,
        nested_guidance: Mapping[str, str] | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        kind = transcript.kind
        if SUBMIT_TOOLS[kind].arguments is not submission:
            raise ValueError(f"{kind} transcripts submit {SUBMIT_TOOLS[kind].arguments.__name__}")
        if ("shell" in TOOL_SETS[kind]) != (tools is not None):
            raise ValueError(
                f"{kind} transcripts need session tools exactly when they have a shell"
            )
        if transcript.run_id != budget.manifest.run_id or number < 1:
            raise ValueError("the transcript must belong to the budget's run and have a number")
        guidance = {
            directory.strip("/"): text for directory, text in (nested_guidance or {}).items()
        }
        if "" in guidance:
            raise ValueError("the root's guidance belongs in the first user message")
        self.transcript = transcript
        self._name = f"{kind}-{number}"
        self._submission = submission
        self._provider = provider
        self._budget = budget
        self._store = store
        self._host_values = host_values
        self._tools = tools
        self._on_submit = on_submit
        self._guidance = guidance
        self._sleep = sleep
        self._spec = MODELS[transcript.model]
        self._scope = TRANSCRIPT_SCOPES[kind]
        self._max_turns = SCOPES[self._scope].max_turns
        self._output_cap = TURN_OUTPUT_CAPS[self._spec.provider][self._scope]
        self._input_ceiling = _input_ceiling(self._spec)
        self._context_limit = min(CONTEXT_LIMIT_TOKENS, self._input_ceiling)
        self._submit_name = SUBMIT_TOOLS[kind].name
        self._turns = 0
        self._nudges = 0
        self._malformed_turns = 0
        self._failing_command: str | None = None
        self._failures_in_a_row = 0
        self._guided: set[str] = set()
        self._reminded_turns = False
        self._reminded_cost = False

    @property
    def turns(self) -> int:
        """Return the model turns this transcript has taken, across every round."""

        return self._turns

    def run(self) -> LoopOutcome[SubmissionT]:
        """Request turns until the transcript ends; it must be waiting for a model turn."""

        if not self.transcript.awaiting_model:
            raise ValueError("the transcript is not waiting for a model turn")
        try:
            return self._run_turns()
        finally:
            self._write()

    def resume(self, text: str) -> LoopOutcome[SubmissionT]:
        """Append a user message, such as the critic's blockers, and run the loop again."""

        append_user_text(self.transcript, text, host_values=self._host_values)
        return self.run()

    def _run_turns(self) -> LoopOutcome[SubmissionT]:
        while True:
            if self._turns >= self._max_turns:
                return DidNotFinish(
                    "turns", f"The transcript reached its turn cap of {self._max_turns}"
                )
            last_turn = next_input_reservation(self.transcript) > self._context_limit
            if last_turn:
                append_user_text(
                    self.transcript, self._last_turn_text(), host_values=self._host_values
                )
                if next_input_reservation(self.transcript) > self._input_ceiling:
                    return DidNotFinish("context", "The transcript is too long for one more turn")
            requested = self._request()
            if not isinstance(requested, Turn):
                return requested
            append_turn(self.transcript, requested)
            self._turns += 1
            try:
                outcome = self._answer(requested, last_turn=last_turn)
            except SandboxError as exc:
                return LoopFailure("sandbox", str(exc))
            except ModelError as exc:
                return LoopFailure("provider", str(exc))
            self._write()
            if outcome is not None:
                return outcome
            if last_turn:
                return DidNotFinish("context", "The transcript reached its context limit")

    def _request(self) -> Turn | DidNotFinish | LoopFailure:
        """Send the next request, retrying what ``retry_decision`` allows, and settle it.

        A turn cut off at its output limit is sent again once with a larger limit.
        """

        cap = self._output_cap
        minimum = min(cap, MIN_TURN_OUTPUT_TOKENS)
        failures = 0
        enlarged = False
        while True:
            try:
                reservation = self._budget.reserve(
                    self._scope,
                    self._spec,
                    input_tokens=next_input_reservation(self.transcript),
                    max_output_tokens=cap,
                    min_output_tokens=minimum,
                    details={"transcript": self._name, "turn": str(self._turns + 1)},
                )
            except BudgetExhaustedError as exc:
                return DidNotFinish("time" if exc.limit == "time" else "budget", str(exc))
            try:
                turn = self._provider.step(
                    transcript=self.transcript,
                    max_output_tokens=reservation.output_tokens,
                    timeout_seconds=reservation.timeout_seconds,
                )
            except ModelError as exc:
                self._budget.record_failure(reservation, exc)
                if not isinstance(exc, (ModelRequestError, ModelTimeoutError)):
                    return LoopFailure("provider", str(exc))
                failures += 1
                request_error = exc if isinstance(exc, ModelRequestError) else None
                decision = retry_decision(
                    status_code=request_error.status_code if request_error else None,
                    provider_code=request_error.provider_code if request_error else None,
                    retry_after=request_error.retry_after_seconds if request_error else None,
                    timed_out=isinstance(exc, ModelTimeoutError),
                    attempt=failures,
                    jitter=_SYSTEM_RANDOM.random(),
                )
                if not decision.retry:
                    return LoopFailure("provider", f"{exc} ({decision.reason})")
                if decision.wait_seconds >= self._budget.seconds_left():
                    return LoopFailure("provider", f"{exc} (no time is left to retry)")
                self._budget.charge_for_retry(
                    reservation, wait_seconds=decision.wait_seconds, reason=decision.reason
                )
                self._sleep(decision.wait_seconds)
                continue
            self._budget.settle(reservation, turn)
            if turn.stop != "max_output_tokens":
                return turn
            if reservation.output_tokens < cap:
                return DidNotFinish("budget", "The budget left too little room for the turn")
            larger = _larger_output_cap(self._spec, cap)
            if enlarged or larger <= cap:
                return LoopFailure(
                    "provider", f"The model's turn did not fit in {cap} output tokens"
                )
            enlarged = True
            minimum = cap + 1
            cap = larger

    def _answer(self, turn: Turn, *, last_turn: bool) -> LoopOutcome[SubmissionT] | None:
        """Answer a turn; return an outcome when the transcript ends with it."""

        if not turn.tool_calls:
            if last_turn:
                return None
            if self._nudges >= MAX_NUDGES:
                return DidNotFinish(
                    "no_tool_call", "The model kept ending turns without a tool call"
                )
            self._nudges += 1
            append_user_text(self.transcript, self._nudge_text(), host_values=self._host_values)
            return None
        results: list[ToolResult] = []
        messages: list[str] = []
        outcome: LoopOutcome[SubmissionT] | None = None
        invalid = 0
        submitted = False
        for call in turn.tool_calls:
            if outcome is not None:
                results.append(
                    refused(call, "Not run: an earlier call in this turn ended the task.")
                )
                continue
            if _holds_token(call.arguments):
                self._end_failure_streak()
                results.append(refused(call, _TOKEN_REFUSAL))
                invalid += 1
            elif call.name == self._submit_name and submitted:
                # A second submit would answer the first one's result unread, such as a fix
                # confirmed before its check report was seen.
                results.append(refused(call, _SECOND_SUBMIT))
                invalid += 1
            elif call.name == self._submit_name:
                self._end_failure_streak()
                submitted = True
                result, outcome, was_invalid = self._submit(call, last_turn=last_turn)
                results.append(result)
                invalid += was_invalid
            else:
                tool_outcome = self._run_tool(call)
                results.append(tool_outcome.result)
                invalid += tool_outcome.invalid
                if tool_outcome.changed_path is not None:
                    messages.extend(self._guidance_for(tool_outcome.changed_path))
                outcome = self._after_tool(tool_outcome)
        append_tool_results(self.transcript, results, host_values=self._host_values)
        self._malformed_turns = self._malformed_turns + 1 if invalid == len(results) else 0
        if outcome is None and self._malformed_turns >= MAX_MALFORMED_TURNS:
            outcome = DidNotFinish(
                "malformed", f"{MAX_MALFORMED_TURNS} turns in a row had only invalid tool calls"
            )
        if outcome is None and not last_turn:
            messages.extend(self._reminders())
        for message in messages:
            append_user_text(self.transcript, message, host_values=self._host_values)
        return outcome

    def _submit(
        self, call: ToolCall, *, last_turn: bool
    ) -> tuple[ToolResult, LoopOutcome[SubmissionT] | None, bool]:
        try:
            submission = read_submission(call, self._submission)
        except ValidationError as exc:
            text = (
                f"Invalid {self._submit_name} call: {describe_validation_error(exc)}. "
                f"Correct the arguments and call {self._submit_name} again."
            )
            return ToolResult(call_id=call.call_id, output=text, is_error=True), None, True
        if self._on_submit is None:
            return ToolResult(call_id=call.call_id, output="Received."), Finished(submission), False
        reply = self._on_submit(submission, last_turn=last_turn)
        result = ToolResult(call_id=call.call_id, output=reply.text)
        if reply.action == "accept":
            return result, Finished(submission), False
        if reply.action == "stop":
            return result, DidNotFinish("submit_limit", "No further submit is allowed"), False
        return result, None, False

    def _run_tool(self, call: ToolCall) -> ToolOutcome:
        if self._tools is None:
            raise ModelError(f"Model called {call.name}, which this transcript does not have")
        return self._tools.run(call)

    def _after_tool(self, outcome: ToolOutcome) -> DidNotFinish | None:
        if outcome.out_of_time:
            return DidNotFinish("time", "The run reached its time limit")
        if not outcome.commands:
            self._end_failure_streak()
        for run in outcome.commands:
            if run.passed:
                self._end_failure_streak()
            elif run.command == self._failing_command:
                self._failures_in_a_row += 1
            else:
                self._failing_command = run.command
                self._failures_in_a_row = 1
            if self._failures_in_a_row >= MAX_REPEATED_FAILURES:
                return DidNotFinish(
                    "repeated_failure",
                    f"The same command failed {MAX_REPEATED_FAILURES} times in a row",
                )
        return None

    def _end_failure_streak(self) -> None:
        self._failing_command = None
        self._failures_in_a_row = 0

    def _guidance_for(self, path: str) -> list[str]:
        messages = []
        for directory in sorted(self._guidance):
            if directory not in self._guided and path.startswith(f"{directory}/"):
                self._guided.add(directory)
                messages.append(self._guidance[directory])
        return messages

    def _reminders(self) -> list[str]:
        reminders = []
        turns_left = self._max_turns - self._turns
        if (
            not self._reminded_turns
            and self._max_turns > REMINDER_TURNS_LEFT
            and turns_left <= REMINDER_TURNS_LEFT
        ):
            self._reminded_turns = True
            reminders.append(
                f"Reminder: {turns_left} turns are left. Finish up and {self._finish()}."
            )
        budget = self._budget
        if not self._reminded_cost and budget.cost_left(self._scope) <= (
            budget.scope_size(self._scope) * REMINDER_COST_SHARE
        ):
            self._reminded_cost = True
            reminders.append(
                "Reminder: about a quarter of the budget for this task is left. Finish up and "
                f"{self._finish()}."
            )
        return reminders

    def _finish(self) -> str:
        if self.transcript.kind == "agent":
            return "call submit, or submit with outcome skip"
        return f"call {self._submit_name}"

    def _nudge_text(self) -> str:
        if self.transcript.kind == "agent":
            return "Continue the task; call submit when you are done or submit with outcome skip."
        return f"Continue the task; call {self._submit_name} when you are done."

    def _last_turn_text(self) -> str:
        if self.transcript.kind == "agent":
            ask = (
                "Call submit now with what you have: outcome fixed if the change is complete "
                "and tested, otherwise outcome skip with the reason."
            )
        else:
            ask = f"Call {self._submit_name} now with what you have."
        return f"This conversation has reached its length limit, and this is your last turn. {ask}"

    def _write(self) -> None:
        transcript = self.transcript
        header: dict[str, JsonValue] = {
            "kind": transcript.kind,
            "model": transcript.model,
            "effort": transcript.effort,
            "instructions": transcript.instructions,
        }
        lines = (
            json.dumps(
                _redacted(value, self._host_values), ensure_ascii=False, separators=(",", ":")
            )
            for value in (header, *transcript.items)
        )
        self._store.write_artifact(
            transcript.run_id, f"{self._name}.jsonl", "\n".join(lines) + "\n"
        )


@dataclass(frozen=True, slots=True)
class CheckReport:
    """The controller's checks of one submitted fix (DESIGN §7.1)."""

    passed: bool
    # Names the checked diff: a later submit with the same diff confirms it.
    diff_sha256: str
    # For the agent: the full diff, the gate, red/green and regression results, and a short
    # checklist. The checker keeps it to a size the transcript can hold.
    text: str


class FixChecker(Protocol):
    """The deterministic checks a submitted fix goes through; the caller implements them."""

    def diff_sha256(self) -> str:
        """Return the digest of the workspace's current diff, without running a check."""
        ...

    def check(self, submission: AgentSubmission) -> CheckReport:
        """Check the workspace's current diff and the submission's text."""
        ...

    def check_text(self, submission: AgentSubmission) -> str | None:
        """Say why the submission's pull request text cannot be published, or return None.

        The confirming submit of an unchanged diff goes through this check only.
        """
        ...


@dataclass(frozen=True, slots=True)
class SubmittedFix:
    """A fix whose checks passed and that the agent confirmed."""

    submission: AgentSubmission
    check: CheckReport


@dataclass(frozen=True, slots=True)
class SkippedIssue:
    """The agent declined the issue."""

    reason: str
    submission: AgentSubmission


SolverOutcome = SubmittedFix | SkippedIssue | DidNotFinish | LoopFailure


class Solver:
    """The agent transcript's loop: a checked, confirmed fix, or a skip.

    Every ``fixed`` submit runs ``checker.check``. When the checks pass, the next submit with the
    same diff confirms the fix; a changed diff is checked again. A round allows
    ``MAX_FIX_SUBMITS`` submits, and ends early once the remaining submits cannot check and
    confirm a fix. On the last turn the context allows, a passing check is accepted without the
    confirming submit. The critic's blockers start a new round on the same transcript.
    """

    def __init__(
        self,
        transcript: Transcript,
        *,
        checker: FixChecker,
        provider: TurnProvider,
        budget: RunBudget,
        store: RunStore,
        host_values: frozenset[str],
        tools: SessionTools,
        nested_guidance: Mapping[str, str] | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if transcript.kind != "agent":
            raise ValueError("the solver drives an agent transcript")
        self._checker = checker
        self._host_values = host_values
        self._submits = 0
        self._passed: CheckReport | None = None
        self._accepted: CheckReport | None = None
        self.loop = AgentLoop(
            transcript,
            number=1,
            submission=AgentSubmission,
            provider=provider,
            budget=budget,
            store=store,
            host_values=host_values,
            tools=tools,
            on_submit=self._on_submit,
            nested_guidance=nested_guidance,
            sleep=sleep,
        )

    def run(self) -> SolverOutcome:
        """Run the first round."""

        return self._outcome(self.loop.run())

    def address_blockers(self, blockers: Sequence[ReviewBlocker]) -> SolverOutcome:
        """Send the critic's confirmed blockers back on the same transcript and continue.

        The new round gets its own submits; turns and the budget count across rounds.
        """

        if not blockers:
            raise ValueError("a new round needs at least one blocker")
        self._submits = 0
        self._passed = None
        self._accepted = None
        return self._outcome(self.loop.resume(_blocker_message(blockers, self._host_values)))

    def _outcome(self, outcome: LoopOutcome[AgentSubmission]) -> SolverOutcome:
        if not isinstance(outcome, Finished):
            return outcome
        submission = outcome.submission
        if submission.outcome == "skip":
            return SkippedIssue(
                reason=(submission.skip_reason or "").strip(), submission=submission
            )
        if self._accepted is None:
            raise StateError("A fix ended the loop without a passing check")
        return SubmittedFix(submission=submission, check=self._accepted)

    def _on_submit(self, submission: AgentSubmission, *, last_turn: bool) -> SubmitReply:
        if submission.outcome == "skip":
            return SubmitReply("accept", "Skip recorded.")
        self._submits += 1
        passed = self._passed
        left = MAX_FIX_SUBMITS - self._submits
        if passed is not None and self._checker.diff_sha256() == passed.diff_sha256:
            # The confirming submit's text is the one the pull request gets.
            problem = self._checker.check_text(submission)
            if problem is None:
                self._accepted = passed
                return SubmitReply("accept", "Fix confirmed.")
            reply = (
                f"The diff is unchanged, but the pull request text cannot be published: {problem}."
            )
            if left == 0:
                return SubmitReply(
                    "stop", f"{reply} No submits are left, so the attempt ends here."
                )
            return SubmitReply(
                "continue", f"{reply} Correct it and call submit again. Submits left: {left}."
            )
        if left == 0:
            return SubmitReply(
                "stop",
                f"This was submit {MAX_FIX_SUBMITS} of {MAX_FIX_SUBMITS}, and it did not confirm "
                "a diff that passed the checks. The attempt ends here.",
            )
        report = self._checker.check(submission)
        self._passed = report if report.passed else None
        if report.passed and last_turn:
            self._accepted = report
            return SubmitReply("accept", report.text)
        if report.passed:
            return SubmitReply(
                "continue",
                f"{report.text}\n\nEvery check passed. Read the diff above as a maintainer "
                "would. If it is final, call submit again without changing anything to confirm "
                f"it; otherwise fix it and submit again. Submits left: {left}.",
            )
        if left < 2:
            return SubmitReply(
                "stop",
                f"{report.text}\n\nNo submits are left for a fix and its confirmation, so the "
                "attempt ends here.",
            )
        return SubmitReply(
            "continue",
            f"{report.text}\n\nFix the problems above and call submit again. Submits left: {left}.",
        )


def _blocker_message(blockers: Sequence[ReviewBlocker], host_values: frozenset[str]) -> str:
    # A reviewing model wrote them, quoting the repository: data, like the issue.
    listed = untrusted_block(
        "reviewer's blockers",
        [blocker.model_dump(mode="json") for blocker in blockers],
        host_values=host_values,
    )
    return (
        "A reviewer checked the change you submitted and found problems that block it. Fix "
        "them, run the tests again, and call submit again; the checks and the confirming submit "
        f"work as before. The blockers:\n{listed}"
    )


def _input_ceiling(spec: ModelSpec) -> int:
    # No request may cross a long-context tier, which bills the whole request at higher rates.
    tier = spec.long_context
    if tier is None:
        return spec.context_tokens
    return min(spec.context_tokens, tier.above_input_tokens)


def _larger_output_cap(spec: ModelSpec, cap: int) -> int:
    # DESIGN §3.3-§3.4: OpenAI retries with double the cap, Anthropic with the model maximum.
    if spec.provider == "openai":
        return min(2 * cap, spec.max_output_tokens)
    return spec.max_output_tokens


def _holds_token(value: JsonValue) -> bool:
    # The token patterns, without the bare private-key header: that header is a constant in
    # every TLS library, which an agent may well grep for or edit around.
    if isinstance(value, str):
        return any(pattern.search(value) for _label, pattern in HIGH_CONFIDENCE_TOKEN_PATTERNS)
    if isinstance(value, list):
        return any(_holds_token(item) for item in value)
    if isinstance(value, dict):
        return any(_holds_token(item) for item in value.values())
    return False


def _redacted(value: JsonValue, host_values: frozenset[str]) -> JsonValue:
    """Redact every string for an artifact, except the provider-opaque fields (DESIGN §3.6)."""

    if isinstance(value, str):
        return redact_text(scrub_for_model(value, host_values))
    if isinstance(value, list):
        return [_redacted(item, host_values) for item in value]
    if isinstance(value, dict):
        item_type = value.get("type")
        opaque = OPAQUE_FIELDS.get(item_type) if isinstance(item_type, str) else None
        return {
            key: item if key == opaque else _redacted(item, host_values)
            for key, item in value.items()
        }
    return value


__all__ = [
    "CONTEXT_LIMIT_TOKENS",
    "MAX_FIX_SUBMITS",
    "MAX_MALFORMED_TURNS",
    "MAX_NUDGES",
    "MAX_REPEATED_FAILURES",
    "REMINDER_COST_SHARE",
    "REMINDER_TURNS_LEFT",
    "AgentLoop",
    "CheckReport",
    "DidNotFinish",
    "Finished",
    "FixChecker",
    "LoopFailure",
    "LoopOutcome",
    "SkippedIssue",
    "Solver",
    "SolverOutcome",
    "StopReason",
    "SubmitHandler",
    "SubmitReply",
    "SubmittedFix",
]
