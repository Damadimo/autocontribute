from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import JsonValue

from autocontribute.agent_tools import (
    MAX_AGENT_COMMAND_SECONDS,
    CommandRun,
    SessionTools,
    refused,
)
from autocontribute.domain import CommandResult
from autocontribute.exceptions import ModelError, SandboxError
from autocontribute.sandbox import SessionCommandResult, SessionContainer
from autocontribute.transcript import ShellChunk, ToolCall
from autocontribute.workspace_files import WorkspaceFiles

_ENVIRONMENT = {"PATH": "/opt/venv/bin:/usr/bin:/bin"}


def _result(
    command: str,
    *,
    exit_code: int = 0,
    stdout: str = "",
    stderr: str = "",
    timed_out: bool = False,
) -> CommandResult:
    return CommandResult(
        command=command,
        exit_code=124 if timed_out else exit_code,
        duration_seconds=0.1,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
    )


class FakeSession:
    """Answers commands from a function; syntax checks pass unless ``syntax_error`` is set."""

    def __init__(self, answer: Callable[[str], CommandResult] | None = None) -> None:
        self.answer = answer or (lambda command: _result(command))
        self.execs: list[tuple[str, int, Mapping[str, str] | None]] = []
        self.saved: list[tuple[int, str]] = []
        self.restarts = 0
        self.syntax_error = ""
        self.infrastructure_failure: str | None = None
        self.reap_failed = False

    def exec(
        self,
        command: str,
        *,
        timeout_seconds: int,
        environment: Mapping[str, str] | None = None,
    ) -> SessionCommandResult:
        self.execs.append((command, timeout_seconds, environment))
        if command.startswith("file="):
            result = _result(command, exit_code=1 if self.syntax_error else 0)
            if self.syntax_error:
                result = result.model_copy(update={"stderr": self.syntax_error})
        else:
            result = self.answer(command)
        failure = self.infrastructure_failure
        return SessionCommandResult(
            result,
            failure,
            restarted=self.reap_failed or failure is not None,
            out_of_memory=failure is not None and "out of memory" in failure,
        )

    def save_output(self, number: int, text: str) -> str | None:
        self.saved.append((number, text))
        return f"/tmp/ac-out/{number}.log"

    def restart(self) -> None:
        self.restarts += 1

    @property
    def commands(self) -> list[str]:
        return [command for command, _, _ in self.execs if not command.startswith("file=")]


def _tools(
    session: FakeSession,
    root: Path,
    *,
    command_timeout: int = 900,
    seconds_left: float = 3_600,
) -> SessionTools:
    return SessionTools(
        cast(SessionContainer, session),
        WorkspaceFiles(root),
        command_timeout_seconds=command_timeout,
        seconds_left=lambda: seconds_left,
        environment=_ENVIRONMENT,
    )


def _shell(*commands: str, **options: JsonValue) -> ToolCall:
    arguments: dict[str, JsonValue] = {"commands": list(commands), **options}
    return ToolCall(call_id="call_shell", name="shell", arguments=arguments)


def _bash(**arguments: JsonValue) -> ToolCall:
    return ToolCall(call_id="toolu_bash", name="bash", arguments=arguments)


def _chunks(output: object) -> tuple[ShellChunk, ...]:
    assert isinstance(output, tuple)
    return cast(tuple[ShellChunk, ...], output)


def test_openai_shell_runs_each_command_in_order_with_its_own_chunk(tmp_path: Path) -> None:
    def answer(command: str) -> CommandResult:
        if command == "pytest -q":
            return _result(command, exit_code=1, stdout="1 failed\n", stderr="E assert\n")
        if command == "sleep 999":
            return _result(command, stdout="partial", timed_out=True)
        return _result(command, stdout="ok\n")

    session = FakeSession(answer)
    outcome = _tools(session, tmp_path).run(_shell("ls", "pytest -q", "sleep 999"))

    assert session.commands == ["ls", "pytest -q", "sleep 999"]
    assert all(environment == _ENVIRONMENT for _, _, environment in session.execs)
    assert _chunks(outcome.result.output) == (
        ShellChunk(stdout="ok\n", stderr="", exit_code=0),
        ShellChunk(stdout="1 failed\n", stderr="E assert\n", exit_code=1),
        ShellChunk(stdout="partial", stderr="", exit_code=None),
    )
    assert outcome.commands == (
        CommandRun("ls", passed=True),
        CommandRun("pytest -q", passed=False),
        CommandRun("sleep 999", passed=False),
    )
    assert not outcome.invalid and not outcome.out_of_time


@pytest.mark.parametrize(
    ("command_timeout", "timeout_ms", "seconds_left", "expected"),
    [
        (900, None, 3_600, MAX_AGENT_COMMAND_SECONDS),
        (120, None, 3_600, 120),
        (900, 30_500, 3_600, 31),
        (900, 9_000_000, 3_600, MAX_AGENT_COMMAND_SECONDS),
        (900, None, 42.9, 42),
    ],
)
def test_shell_timeouts_honour_the_call_the_tool_cap_and_the_deadline(
    tmp_path: Path,
    command_timeout: int,
    timeout_ms: int | None,
    seconds_left: float,
    expected: int,
) -> None:
    session = FakeSession()
    options: dict[str, JsonValue] = {} if timeout_ms is None else {"timeout_ms": timeout_ms}
    tools = _tools(session, tmp_path, command_timeout=command_timeout, seconds_left=seconds_left)

    tools.run(_shell("make test", **options))

    assert session.execs[0][1] == expected


def test_long_output_is_cut_once_and_saved_whole_in_the_container(tmp_path: Path) -> None:
    long_stdout = "".join(f"line {number}\n" for number in range(3_000))
    session = FakeSession(lambda command: _result(command, stdout=long_stdout, stderr="warn\n"))
    tools = _tools(session, tmp_path)

    first = _chunks(tools.run(_shell("pytest")).result.output)[0]
    second = _chunks(tools.run(_shell("pytest", max_output_length=1_000)).result.output)[0]

    assert session.saved == [(1, long_stdout), (2, long_stdout)]
    assert len(first.stdout) < 10_200
    assert first.stdout.startswith("line 0\n") and first.stdout.endswith("line 2999\n")
    assert "The full output is in /tmp/ac-out/1.log." in first.stdout
    assert first.stderr == "warn\n"
    assert len(second.stdout) < 1_200
    assert "/tmp/ac-out/2.log" in second.stdout


@pytest.mark.parametrize(
    "arguments",
    [
        {"commands": ["ls"], "timeout_ms": 0},
        {"commands": ["ls"], "working_directory": "/"},
        {"commands": ["ls"], "max_output_length": -1},
    ],
)
def test_shell_arguments_that_do_not_fit_get_an_error_per_command(
    tmp_path: Path, arguments: dict[str, JsonValue]
) -> None:
    session = FakeSession()

    outcome = _tools(session, tmp_path).run(
        ToolCall(call_id="call_1", name="shell", arguments=arguments)
    )

    assert outcome.invalid
    assert session.execs == []
    (chunk,) = _chunks(outcome.result.output)
    assert chunk.exit_code == 126
    assert chunk.stderr.startswith("Invalid shell call: ")


def test_unrunnable_commands_are_refused_one_by_one(tmp_path: Path) -> None:
    session = FakeSession()
    tools = _tools(session, tmp_path)

    mixed = tools.run(_shell("  ", "ls", "x" * 20_001, "a\0b"))
    refused_only = tools.run(_shell(" "))

    assert session.commands == ["ls"]
    chunks = _chunks(mixed.result.output)
    assert [chunk.exit_code for chunk in chunks] == [126, 0, 126, 126]
    assert chunks[0].stderr == "The command is empty"
    assert "write a script" in chunks[2].stderr
    assert "NUL" in chunks[3].stderr
    assert not mixed.invalid
    assert refused_only.invalid


def test_commands_wait_for_no_time_the_run_does_not_have(tmp_path: Path) -> None:
    session = FakeSession()

    outcome = _tools(session, tmp_path, seconds_left=0.6).run(_shell("ls", "pytest"))

    assert session.execs == []
    assert outcome.out_of_time
    assert not outcome.invalid
    assert {chunk.stderr for chunk in _chunks(outcome.result.output)} == {
        "Not run: the run is out of time."
    }


def test_a_shell_call_without_a_command_list_cannot_be_answered(tmp_path: Path) -> None:
    call = ToolCall(call_id="call_1", name="shell", arguments={"commands": "ls"})

    with pytest.raises(ModelError, match="list of commands"):
        _tools(FakeSession(), tmp_path).run(call)
    with pytest.raises(ModelError, match="list of commands"):
        refused(call, "Refused")


def test_bash_returns_combined_output_with_the_exit_status(tmp_path: Path) -> None:
    answers = {
        "python -c 'boom'": _result("", exit_code=2, stdout="out", stderr="Traceback\n"),
        "true": _result("true"),
        "sleep 999": _result("", stdout="waiting\n", timed_out=True),
    }
    session = FakeSession(lambda command: answers[command])
    tools = _tools(session, tmp_path, command_timeout=60)

    failed = tools.run(_bash(command="python -c 'boom'"))
    quiet = tools.run(_bash(command="true"))
    slow = tools.run(_bash(command="sleep 999"))

    assert failed.result.output == "out\nTraceback\n\n[Exit code 2]"
    assert not failed.result.is_error
    assert failed.commands == (CommandRun("python -c 'boom'", passed=False),)
    assert quiet.result.output == "(no output)"
    assert slow.result.output == (
        "waiting\n\n[The command timed out after 60 seconds; its output so far is above.]"
    )


def test_bash_restart_restarts_the_session(tmp_path: Path) -> None:
    session = FakeSession()

    outcome = _tools(session, tmp_path).run(_bash(restart=True))

    assert session.restarts == 1
    assert session.execs == []
    assert "/tmp is empty" in str(outcome.result.output)
    assert not outcome.result.is_error


@pytest.mark.parametrize(
    "arguments",
    [{}, {"command": ""}, {"command": "ls", "timeout": 5}, {"restart": "yes please"}],
)
def test_bash_arguments_that_do_not_fit_are_refused(
    tmp_path: Path, arguments: dict[str, JsonValue]
) -> None:
    session = FakeSession()

    outcome = _tools(session, tmp_path).run(_bash(**arguments))

    assert outcome.invalid
    assert outcome.result.is_error
    assert str(outcome.result.output).startswith("Invalid bash call: ")
    assert session.execs == [] and session.restarts == 0


def test_a_command_that_left_processes_behind_reports_the_restart(tmp_path: Path) -> None:
    session = FakeSession(lambda command: _result(command, stdout="started\n"))
    session.reap_failed = True
    tools = _tools(session, tmp_path)

    bash = tools.run(_bash(command="daemon &"))
    shell = tools.run(_shell("daemon &"))

    assert str(bash.result.output).endswith("/tmp is now empty.]")
    assert _chunks(shell.result.output)[0].stderr.endswith("/tmp is now empty.]")


def test_a_stopped_sandbox_is_an_infrastructure_error(tmp_path: Path) -> None:
    session = FakeSession()
    session.infrastructure_failure = "the sandbox container stopped"

    with pytest.raises(SandboxError, match="container stopped"):
        _tools(session, tmp_path).run(_shell("pytest"))


def test_a_command_over_the_memory_limit_is_reported_to_the_agent(tmp_path: Path) -> None:
    session = FakeSession()
    session.infrastructure_failure = "the sandbox ran out of memory (limit 6g)"
    tools = _tools(session, tmp_path)

    bash = tools.run(_bash(command="cargo test"))
    shell = tools.run(_shell("cargo test"))

    for text in (str(bash.result.output), _chunks(shell.result.output)[0].stderr):
        assert "The command was stopped: the sandbox ran out of memory (limit 6g)" in text
        assert "Use less memory" in text


def test_apply_patch_edits_on_the_host_and_checks_the_syntax(tmp_path: Path) -> None:
    session = FakeSession()
    tools = _tools(session, tmp_path)
    create = ToolCall(
        call_id="call_patch",
        name="apply_patch",
        arguments={"type": "create_file", "path": "/workspace/pkg/mod.py", "diff": "+x = 1\n"},
    )

    outcome = tools.run(create)

    assert (tmp_path / "pkg" / "mod.py").read_text() == "x = 1\n"
    assert outcome.changed_path == "pkg/mod.py"
    assert outcome.result.output == "Created /workspace/pkg/mod.py"
    assert not outcome.result.is_error
    check, _timeout, environment = session.execs[0]
    assert check.startswith("file=/workspace/pkg/mod.py")
    assert environment == _ENVIRONMENT


def test_a_syntax_error_after_an_edit_is_added_to_its_result(tmp_path: Path) -> None:
    (tmp_path / "mod.py").write_text("x = 1\n")
    session = FakeSession()
    session.syntax_error = 'File "/workspace/mod.py", line 1\n    x = (\nSyntaxError'
    call = ToolCall(
        call_id="toolu_edit",
        name="str_replace_based_edit_tool",
        arguments={"command": "str_replace", "path": "mod.py", "old_str": "1", "new_str": "("},
    )

    outcome = _tools(session, tmp_path).run(call)

    output = str(outcome.result.output)
    assert output.startswith("The file /workspace/mod.py has been edited.")
    assert output.endswith(
        "The syntax check of /workspace/mod.py failed:\n"
        'File "/workspace/mod.py", line 1\n    x = (\nSyntaxError'
    )
    assert outcome.changed_path == "mod.py"


@pytest.mark.parametrize(
    ("call", "invalid"),
    [
        (
            ToolCall(
                call_id="call_1",
                name="apply_patch",
                arguments={"type": "rename_file", "path": "a.py"},
            ),
            True,
        ),
        (
            ToolCall(
                call_id="call_1",
                name="apply_patch",
                arguments={"type": "update_file", "path": "missing.py", "diff": "@@\n-a\n+b\n"},
            ),
            False,
        ),
        (
            ToolCall(
                call_id="toolu_1",
                name="str_replace_based_edit_tool",
                arguments={"command": "undo_edit", "path": "a.py"},
            ),
            True,
        ),
    ],
)
def test_failed_edits_are_errors_and_only_bad_arguments_are_invalid(
    tmp_path: Path, call: ToolCall, invalid: bool
) -> None:
    session = FakeSession()

    outcome = _tools(session, tmp_path).run(call)

    assert outcome.result.is_error
    assert outcome.invalid is invalid
    assert outcome.changed_path is None
    assert session.execs == []


def test_viewing_a_file_changes_nothing_and_long_views_are_cut(tmp_path: Path) -> None:
    (tmp_path / "big.txt").write_text("".join(f"row {number}\n" for number in range(5_000)))
    session = FakeSession()
    call = ToolCall(
        call_id="toolu_view",
        name="str_replace_based_edit_tool",
        arguments={"command": "view", "path": "/workspace/big.txt"},
    )

    outcome = _tools(session, tmp_path).run(call)

    output = str(outcome.result.output)
    assert outcome.changed_path is None
    assert session.execs == [] and session.saved == []
    assert len(output) < 10_200
    assert "characters omitted" in output


def test_refused_answers_in_the_shape_of_each_tool() -> None:
    message = "Refused: write a placeholder"
    shell = refused(_shell("ls", "pwd"), message)
    submit = refused(ToolCall(call_id="call_s", name="submit", arguments={}), message)

    assert _chunks(shell.output) == (
        ShellChunk(stdout="", stderr=message, exit_code=126),
        ShellChunk(stdout="", stderr=message, exit_code=126),
    )
    assert submit.output == message and submit.is_error


def test_only_shell_and_edit_calls_run_in_the_session(tmp_path: Path) -> None:
    call: dict[str, Any] = {"call_id": "call_s", "name": "submit", "arguments": {}}

    with pytest.raises(ValueError, match="not a shell or edit tool"):
        _tools(FakeSession(), tmp_path).run(ToolCall.model_validate(call))
