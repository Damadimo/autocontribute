"""Run an agent's shell and edit tool calls in its session (DESIGN §6.1).

Shell commands run in the session container, each in a fresh shell. Edits run on the host
through :class:`WorkspaceFiles` and are then syntax-checked in the container. Output is cut to
its head and tail here, once, and the whole of a cut output is saved in the container for the
agent to search. A call whose arguments do not fit its tool does nothing and gets an error
result the model can correct.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Final

from pydantic import Field, ValidationError

from autocontribute.domain import CommandResult, DomainModel
from autocontribute.edit_tools import (
    EditResult,
    apply_patch_operation,
    describe_validation_error,
    run_text_editor,
    syntax_check,
)
from autocontribute.exceptions import ModelError, SandboxError
from autocontribute.sandbox import MAX_COMMAND_CHARACTERS, SessionCommandResult, SessionContainer
from autocontribute.tool_output import TOOL_OUTPUT_CHARACTERS, truncate_tool_output
from autocontribute.transcript import NATIVE_CALL_NAMES, ShellChunk, ToolCall, ToolResult
from autocontribute.workspace_files import WorkspaceFiles

# Agent commands get at most this long, however long the sandbox lets test runs take.
MAX_AGENT_COMMAND_SECONDS: Final = 300
# Reported for a command that was refused or never started: the shell's "cannot execute".
_NOT_RUN_EXIT_CODE: Final = 126
_OPENAI_SHELL: Final = NATIVE_CALL_NAMES["openai"]["shell"]
_OPENAI_EDIT: Final = NATIVE_CALL_NAMES["openai"]["edit"]
_ANTHROPIC_SHELL: Final = NATIVE_CALL_NAMES["anthropic"]["shell"]
_ANTHROPIC_EDIT: Final = NATIVE_CALL_NAMES["anthropic"]["edit"]
_RESTART_NOTE: Final = (
    "\n[The sandbox restarted after this command to stop the processes it left running; "
    "/tmp is now empty.]"
)
_OUT_OF_TIME: Final = "Not run: the run is out of time."


def _restart_note(outcome: SessionCommandResult) -> str:
    if outcome.out_of_memory:
        return (
            f"\n[The command was stopped: {outcome.infrastructure_failure}. The sandbox "
            "restarted and /tmp is now empty. Use less memory, for example fewer parallel "
            "jobs or a smaller test selection.]"
        )
    return _RESTART_NOTE if outcome.restarted else ""


class _ShellAction(DomainModel):
    commands: list[str]
    timeout_ms: int | None = Field(default=None, ge=1)
    max_output_length: int | None = Field(default=None, ge=0)


class _BashCall(DomainModel):
    command: str | None = None
    restart: bool = False


@dataclass(frozen=True, slots=True)
class CommandRun:
    """One shell command a call ran."""

    command: str
    passed: bool


@dataclass(frozen=True, slots=True)
class ToolOutcome:
    """A tool call's result and what the loop needs to know about the call."""

    result: ToolResult
    # The arguments did not fit the tool, so the call did nothing.
    invalid: bool = False
    # The shell commands the call ran, in order.
    commands: tuple[CommandRun, ...] = ()
    # The workspace-relative path an edit created, changed or deleted.
    changed_path: str | None = None
    # The run's time ran out before a command could start.
    out_of_time: bool = False


class SessionTools:
    """The shell and edit tools of one transcript, over one session and its workspace.

    ``seconds_left`` returns the time left before the run's deadline; a command never gets more.
    ``environment`` holds the recipe's variables, which commands and syntax checks run with.
    """

    def __init__(
        self,
        session: SessionContainer,
        files: WorkspaceFiles,
        *,
        command_timeout_seconds: int,
        seconds_left: Callable[[], float],
        environment: Mapping[str, str] | None = None,
    ) -> None:
        self._session = session
        self._files = files
        self._timeout = min(command_timeout_seconds, MAX_AGENT_COMMAND_SECONDS)
        self._seconds_left = seconds_left
        self._environment = environment
        self._saved_outputs = 0

    def run(self, call: ToolCall) -> ToolOutcome:
        """Run one shell or edit call.

        Raises ``SandboxError`` when the sandbox itself failed, and ``ModelError`` for an
        OpenAI shell call without a list of commands, which no result can answer.
        """

        if call.name == _OPENAI_SHELL:
            return self._shell(call)
        if call.name == _ANTHROPIC_SHELL:
            return self._bash(call)
        if call.name == _OPENAI_EDIT:
            return self._edited(call, apply_patch_operation(self._files, call.arguments))
        if call.name == _ANTHROPIC_EDIT:
            return self._edited(call, run_text_editor(self._files, call.arguments))
        raise ValueError(f"{call.name} is not a shell or edit tool")

    def _shell(self, call: ToolCall) -> ToolOutcome:
        _commands(call)
        try:
            action = _ShellAction.model_validate(call.arguments)
        except ValidationError as exc:
            message = f"Invalid shell call: {describe_validation_error(exc)}"
            return ToolOutcome(refused(call, message), invalid=True)
        requested = None if action.timeout_ms is None else math.ceil(action.timeout_ms / 1_000)
        chunks: list[ShellChunk] = []
        runs: list[CommandRun] = []
        refusals = 0
        out_of_time = False
        for command in action.commands:
            problem = _command_problem(command)
            if problem is not None:
                refusals += 1
                chunks.append(_not_run(problem))
                continue
            timeout = self._command_timeout(requested)
            if timeout < 1:
                out_of_time = True
                chunks.append(_not_run(_OUT_OF_TIME))
                continue
            outcome = self._exec(command, timeout)
            result = outcome.result
            limit = action.max_output_length
            stderr = self._bounded(result.stderr, limit)
            chunks.append(
                ShellChunk(
                    stdout=self._bounded(result.stdout, limit),
                    stderr=stderr + _restart_note(outcome),
                    exit_code=None if result.timed_out else result.exit_code,
                )
            )
            runs.append(CommandRun(command, result.passed))
        return ToolOutcome(
            ToolResult(call_id=call.call_id, output=tuple(chunks)),
            invalid=refusals == len(action.commands),
            commands=tuple(runs),
            out_of_time=out_of_time,
        )

    def _bash(self, call: ToolCall) -> ToolOutcome:
        try:
            action = _BashCall.model_validate(call.arguments)
        except ValidationError as exc:
            message = f"Invalid bash call: {describe_validation_error(exc)}"
            return ToolOutcome(refused(call, message), invalid=True)
        if action.restart:
            self._session.restart()
            message = (
                "The sandbox restarted: every process was stopped and /tmp is empty. "
                "/workspace is unchanged."
            )
            return ToolOutcome(ToolResult(call_id=call.call_id, output=message))
        command = action.command
        if command is None:
            message = "Invalid bash call: give a command, or restart: true"
            return ToolOutcome(refused(call, message), invalid=True)
        problem = _command_problem(command)
        if problem is not None:
            return ToolOutcome(refused(call, f"Invalid bash call: {problem}"), invalid=True)
        timeout = self._command_timeout(None)
        if timeout < 1:
            return ToolOutcome(refused(call, _OUT_OF_TIME), out_of_time=True)
        outcome = self._exec(command, timeout)
        result = outcome.result
        output = (
            self._bounded(_combined(result), None)
            + _status(result, timeout)
            + _restart_note(outcome)
        )
        return ToolOutcome(
            ToolResult(call_id=call.call_id, output=output or "(no output)"),
            commands=(CommandRun(command, result.passed),),
        )

    def _edited(self, call: ToolCall, edit: EditResult) -> ToolOutcome:
        output = edit.output
        changed = edit.changed_path if edit.status == "completed" else None
        if changed is not None:
            error = syntax_check(self._session, changed, environment=self._environment)
            if error is not None:
                output += f"\n\nThe syntax check of {self._files.display(changed)} failed:\n{error}"
        return ToolOutcome(
            ToolResult(
                call_id=call.call_id,
                output=truncate_tool_output(output),
                is_error=edit.status == "failed",
            ),
            invalid=edit.invalid_arguments,
            changed_path=changed,
        )

    def _command_timeout(self, requested: int | None) -> int:
        limit = self._timeout if requested is None else min(self._timeout, requested)
        return min(limit, math.floor(self._seconds_left()))

    def _exec(self, command: str, timeout: int) -> SessionCommandResult:
        outcome = self._session.exec(
            command, timeout_seconds=timeout, environment=self._environment
        )
        # A command that exceeds the memory limit is the agent's to fix; the session has
        # already restarted. A stopped or unreadable container is not.
        if outcome.infrastructure_failure is not None and not outcome.out_of_memory:
            raise SandboxError(
                f"The sandbox failed during an agent command: {outcome.infrastructure_failure}"
            )
        return outcome

    def _bounded(self, text: str, max_characters: int | None) -> str:
        limit = TOOL_OUTPUT_CHARACTERS
        if max_characters is not None:
            limit = min(limit, max_characters)
        if len(text) <= limit:
            return text
        self._saved_outputs += 1
        path = self._session.save_output(self._saved_outputs, text)
        return truncate_tool_output(text, max_characters=max_characters, full_output_path=path)


def refused(call: ToolCall, message: str) -> ToolResult:
    """Return an error result, in the shape its tool needs, for a call that did nothing.

    Raises ``ModelError`` for an OpenAI shell call without a list of commands.
    """

    if call.name == _OPENAI_SHELL:
        return ToolResult(
            call_id=call.call_id, output=tuple(_not_run(message) for _ in _commands(call))
        )
    return ToolResult(call_id=call.call_id, output=message, is_error=True)


def _commands(call: ToolCall) -> list[str]:
    # Its result needs one chunk per command, so a call without a list cannot be answered.
    commands = call.arguments.get("commands")
    if not isinstance(commands, list) or not all(isinstance(item, str) for item in commands):
        raise ModelError("Model sent a shell call without a list of commands")
    return [str(item) for item in commands]


def _command_problem(command: str) -> str | None:
    if not command.strip():
        return "The command is empty"
    if "\0" in command:
        return "The command contains a NUL byte"
    if len(command) > MAX_COMMAND_CHARACTERS:
        return f"The command is longer than {MAX_COMMAND_CHARACTERS} characters; write a script"
    return None


def _not_run(message: str) -> ShellChunk:
    return ShellChunk(stdout="", stderr=message, exit_code=_NOT_RUN_EXIT_CODE)


def _combined(result: CommandResult) -> str:
    stdout, stderr = result.stdout, result.stderr
    if stdout and stderr and not stdout.endswith("\n"):
        stdout += "\n"
    return stdout + stderr


def _status(result: CommandResult, timeout: int) -> str:
    if result.timed_out:
        return f"\n[The command timed out after {timeout} seconds; its output so far is above.]"
    if result.exit_code != 0:
        return f"\n[Exit code {result.exit_code}]"
    return ""


__all__ = [
    "MAX_AGENT_COMMAND_SECONDS",
    "CommandRun",
    "SessionTools",
    "ToolOutcome",
    "refused",
]
