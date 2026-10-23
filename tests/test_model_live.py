"""Opt-in canary that runs a short tool loop against each real model API.

For every provider whose API key is set, a model reads, edits and runs a one-line file and then
submits, through the real worker process. The sandbox is an in-memory stand-in, so the test needs
only the key and this package. The normal suite skips it.
"""

from __future__ import annotations

import ast
import os
import shlex

import pytest
from pydantic import JsonValue

from autocontribute.pricing import API_KEY_ENVS, MODELS, ROLE_MODELS, TURN_OUTPUT_CAPS, Provider
from autocontribute.providers import SubprocessTurnProvider
from autocontribute.submissions import AgentSubmission
from autocontribute.transcript import (
    NATIVE_CALL_NAMES,
    ShellChunk,
    ToolCall,
    ToolResult,
    Turn,
    append_tool_results,
    append_turn,
    append_user_text,
    next_input_reservation,
    read_submission,
    start_transcript,
    tool_call_names,
)

_MAX_TURNS = 8
_TURN_SECONDS = 300.0
_BEFORE = "Hello, world!"
_AFTER = "Hello, autocontribute!"
_INSTRUCTIONS = f"""\
You are checking a tool harness. The repository is in /workspace and holds one file, hello.py.
The shell runs only cat, ls and python; any other command fails.

Do these steps in order, one step per turn:
1. Read hello.py with the shell tool.
2. Change hello.py with the file edit tool so that it prints exactly "{_AFTER}".
3. Run python hello.py with the shell tool and check its output.
4. Call submit with outcome "fixed", skip_reason null, a one-sentence summary, a pr_title, a
   short pr_body, a one-line commit_message, test_files [] and test_command null.
"""
_TASK = f'hello.py prints "{_BEFORE}". Make it print "{_AFTER}", run it, then submit.'


def _live_models_enabled() -> bool:
    return os.environ.get("AUTOCONTRIBUTE_RUN_MODEL_TESTS") == "1"


class _Refused(Exception):
    pass


def _relative(path: str) -> str:
    return path.removeprefix("/workspace/").removeprefix("./")


class _Workspace:
    """An in-memory stand-in for the sandbox.

    Its shell knows cat, ls and python, and python only prints string literals, so code the
    model writes is parsed but never executed.
    """

    def __init__(self) -> None:
        self.files = {"hello.py": f"print({_BEFORE!r})\n"}

    def run(self, call: ToolCall) -> ToolResult:
        """Run one shell or edit call, checking that it has its tool's argument shape."""

        if call.name == "shell":
            commands = call.arguments["commands"]
            assert isinstance(commands, list) and commands
            chunks = []
            for command in commands:
                assert isinstance(command, str)
                output, exit_code = self.shell(command)
                failed = exit_code != 0
                chunks.append(
                    ShellChunk(
                        stdout="" if failed else output,
                        stderr=output if failed else "",
                        exit_code=exit_code,
                    )
                )
            return ToolResult(call_id=call.call_id, output=tuple(chunks))
        if call.name == "bash":
            if call.arguments == {"restart": True}:
                return ToolResult(call_id=call.call_id, output="The shell was restarted.")
            command = call.arguments["command"]
            assert isinstance(command, str)
            output, exit_code = self.shell(command)
            return ToolResult(call_id=call.call_id, output=output, is_error=exit_code != 0)
        try:
            if call.name == "apply_patch":
                output = self.apply_patch(call.arguments)
            elif call.name == "str_replace_based_edit_tool":
                output = self.edit(call.arguments)
            else:
                raise AssertionError(f"unexpected tool call {call.name}")
        except _Refused as refusal:
            return ToolResult(call_id=call.call_id, output=str(refusal), is_error=True)
        return ToolResult(call_id=call.call_id, output=output)

    def shell(self, command: str) -> tuple[str, int]:
        try:
            words = shlex.split(command)
        except ValueError:
            return "unbalanced quotes\n", 2
        # Models often chain with && and merge stderr; both are harmless here.
        words = [word for word in words if word != "2>&1"]
        output = ""
        exit_code = 0
        while words and exit_code == 0:
            end = words.index("&&") if "&&" in words else len(words)
            part_output, exit_code = self._program(words[:end])
            output += part_output
            words = words[end + 1 :]
        return output, exit_code

    def _program(self, words: list[str]) -> tuple[str, int]:
        if not words:
            return "", 0
        program, *arguments = words
        paths = [word for word in arguments if not word.startswith("-")]
        if program == "cd" and paths in ([], ["/workspace"]):
            return "", 0
        if program == "ls":
            return "".join(f"{name}\n" for name in sorted(self.files)), 0
        if program == "cat" and paths:
            missing = [path for path in paths if _relative(path) not in self.files]
            if missing:
                return f"cat: {missing[0]}: No such file or directory\n", 1
            return "".join(self.files[_relative(path)] for path in paths), 0
        if program in ("python", "python3") and len(paths) == 1:
            return self.python(paths[0])
        return f"{program}: not available in this shell; use cat, ls or python\n", 127

    def python(self, path: str) -> tuple[str, int]:
        source = self.files.get(_relative(path))
        if source is None:
            return f"python: can't open file '{path}': No such file or directory\n", 2
        try:
            module = ast.parse(source)
        except SyntaxError as error:
            return f"SyntaxError: {error.msg}\n", 1
        printed = []
        for statement in module.body:
            match statement:
                case ast.Expr(ast.Call(ast.Name("print"), [ast.Constant(str() as text)], [])):
                    printed.append(f"{text}\n")
                case _:
                    return "this shell's python only runs print() of a string literal\n", 1
        return "".join(printed), 0

    def apply_patch(self, operation: dict[str, JsonValue]) -> str:
        kind = operation["type"]
        path = operation["path"]
        assert kind in ("create_file", "update_file", "delete_file") and isinstance(path, str)
        name = _relative(path)
        if kind == "delete_file":
            if self.files.pop(name, None) is None:
                raise _Refused(f"{path} does not exist")
            return f"Deleted {path}"
        diff = operation["diff"]
        assert isinstance(diff, str)
        if kind == "create_file":
            lines = [line[1:] for line in diff.splitlines() if line.startswith("+")]
            self.files[name] = "".join(f"{line}\n" for line in lines)
            return f"Created {path}"
        if name not in self.files:
            raise _Refused(f"{path} does not exist")
        # One V4A hunk: context lines start with a space, removals with -, additions with +.
        old: list[str] = []
        new: list[str] = []
        for line in diff.splitlines():
            if line.startswith(("@@", "***")):
                continue
            marker, text = line[:1], line[1:]
            if marker in (" ", ""):
                old.append(text)
                new.append(text)
            elif marker == "-":
                old.append(text)
            elif marker == "+":
                new.append(text)
            else:
                raise _Refused(f"invalid diff line: {line!r}")
        lines = self.files[name].splitlines()
        for start in range(len(lines) - len(old) + 1):
            if lines[start : start + len(old)] == old:
                lines[start : start + len(old)] = new
                self.files[name] = "".join(f"{line}\n" for line in lines)
                return f"Updated {path}"
        raise _Refused("the diff's context does not match the file")

    def edit(self, arguments: dict[str, JsonValue]) -> str:
        command = arguments["command"]
        path = arguments["path"]
        assert isinstance(command, str) and isinstance(path, str)
        name = _relative(path)
        if command == "create":
            file_text = arguments["file_text"]
            assert isinstance(file_text, str)
            self.files[name] = file_text
            return f"Created {path}"
        if command == "view" and path.rstrip("/") in ("/workspace", "."):
            return "".join(f"{name}\n" for name in sorted(self.files))
        text = self.files.get(name)
        if text is None:
            raise _Refused(f"{path} does not exist")
        if command == "view":
            return "".join(
                f"{number}\t{line}\n" for number, line in enumerate(text.splitlines(), start=1)
            )
        if command == "str_replace":
            old_str = arguments["old_str"]
            new_str = arguments.get("new_str", "")
            assert isinstance(old_str, str) and isinstance(new_str, str)
            matches = text.count(old_str)
            if matches != 1:
                raise _Refused(f"old_str matched {matches} times; it must match exactly once")
            self.files[name] = text.replace(old_str, new_str)
            return f"Edited {path}"
        if command == "insert":
            line_number = arguments["insert_line"]
            insert_text = arguments["insert_text"]
            assert isinstance(line_number, int) and isinstance(insert_text, str)
            lines = text.splitlines(keepends=True)
            lines.insert(line_number, insert_text.removesuffix("\n") + "\n")
            self.files[name] = "".join(lines)
            return f"Edited {path}"
        raise _Refused(f"unsupported command: {command}")


@pytest.mark.skipif(
    not _live_models_enabled(),
    reason="set AUTOCONTRIBUTE_RUN_MODEL_TESTS=1 to run live model API tests",
)
@pytest.mark.parametrize("provider", ["openai", "anthropic"])
def test_live_tool_loop_through_the_model_worker(provider: Provider) -> None:
    if not os.environ.get(API_KEY_ENVS[provider]):
        pytest.skip(f"set {API_KEY_ENVS[provider]} to run the {provider} canary")
    # The setup role's model has the agent's tools at a lower price.
    spec = MODELS[ROLE_MODELS[provider]["setup"]]
    output_cap = TURN_OUTPUT_CAPS[provider]["setup"]
    model = SubprocessTurnProvider(spec, "low")
    transcript = start_transcript(
        model=spec.id,
        kind="agent",
        run_id="live-canary",
        instructions=_INSTRUCTIONS,
        task=_TASK,
    )
    workspace = _Workspace()
    turns: list[Turn] = []
    calls: list[ToolCall] = []
    submission: AgentSubmission | None = None

    while submission is None and len(turns) < _MAX_TURNS:
        reservation = next_input_reservation(transcript)
        turn = model.step(
            transcript=transcript, max_output_tokens=output_cap, timeout_seconds=_TURN_SECONDS
        )
        assert turn.stop != "max_output_tokens", f"turn {len(turns) + 1} hit the output cap"
        assert turn.usage.input_tokens <= reservation, (
            f"turn {len(turns) + 1} used {turn.usage.input_tokens} input tokens; "
            f"{reservation} were reserved"
        )
        assert turn.usage.output_tokens <= output_cap
        turns.append(turn)
        append_turn(transcript, turn)
        if not turn.tool_calls:
            append_user_text(transcript, "Continue with the next step, using the tools.")
            continue
        results = []
        for call in turn.tool_calls:
            calls.append(call)
            if call.name != "submit":
                results.append(workspace.run(call))
                continue
            try:
                submission = read_submission(call, AgentSubmission)
            except ValueError as error:
                results.append(
                    ToolResult(call_id=call.call_id, output=f"Invalid: {error}", is_error=True)
                )
            else:
                results.append(ToolResult(call_id=call.call_id, output="Submitted."))
        append_tool_results(transcript, results, reminder=f"{_MAX_TURNS - len(turns)} turns left.")

    assert submission is not None, f"no valid submission in {len(turns)} turns"
    assert submission.outcome == "fixed"
    assert workspace.python("hello.py") == (f"{_AFTER}\n", 0)
    names = {call.name for call in calls}
    assert names <= tool_call_names(provider, "agent")
    assert {*NATIVE_CALL_NAMES[provider].values(), "submit"} <= names
    # Every request after the first replayed the earlier turns, reasoning and thinking included.
    assert len(turns) >= 2
    for turn in turns:
        cache_tokens = turn.usage.cached_input_tokens + turn.usage.cache_write_tokens
        assert cache_tokens <= turn.usage.input_tokens
    assert any(turn.usage.cached_input_tokens + turn.usage.cache_write_tokens for turn in turns)
