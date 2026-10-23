from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

from autocontribute.domain import CommandResult
from autocontribute.edit_tools import apply_patch_operation, run_text_editor, syntax_check
from autocontribute.sandbox import SessionCommandResult, SessionContainer
from autocontribute.workspace_files import WorkspaceFiles


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "workspace"
    (root / "src").mkdir(parents=True)
    (root / "src" / "calc.py").write_text(
        "def add(a, b):\n    return a - b\n\n\ndef sub(a, b):\n    return a - b\n",
        encoding="utf-8",
    )
    return root


@pytest.fixture
def files(workspace: Path) -> WorkspaceFiles:
    return WorkspaceFiles(workspace)


def _read(workspace: Path, relative: str) -> str:
    return (workspace / relative).read_bytes().decode("utf-8")


def test_apply_patch_updates_creates_and_deletes_files(
    files: WorkspaceFiles, workspace: Path
) -> None:
    updated = apply_patch_operation(
        files,
        {
            "type": "update_file",
            "path": "/workspace/src/calc.py",
            "diff": "@@ def add(a, b):\n-    return a - b\n+    return a + b\n",
        },
    )
    created = apply_patch_operation(
        files,
        {"type": "create_file", "path": "tests/test_calc.py", "diff": "+def test():\n+    pass"},
    )
    deleted = apply_patch_operation(files, {"type": "delete_file", "path": "src/calc.py"})

    assert (updated.status, updated.output) == ("completed", "Updated /workspace/src/calc.py")
    assert updated.changed_path == "src/calc.py"
    assert (created.status, created.output) == (
        "completed",
        "Created /workspace/tests/test_calc.py",
    )
    assert _read(workspace, "tests/test_calc.py") == "def test():\n    pass\n"
    assert (deleted.status, deleted.changed_path) == ("completed", "src/calc.py")
    assert not (workspace / "src" / "calc.py").exists()


def test_apply_patch_update_changes_only_the_anchored_hunk(
    files: WorkspaceFiles, workspace: Path
) -> None:
    result = apply_patch_operation(
        files,
        {
            "type": "update_file",
            "path": "src/calc.py",
            "diff": "@@ def add(a, b):\n-    return a - b\n+    return a + b\n",
        },
    )

    assert result.status == "completed"
    assert _read(workspace, "src/calc.py") == (
        "def add(a, b):\n    return a + b\n\n\ndef sub(a, b):\n    return a - b\n"
    )


@pytest.mark.parametrize(
    ("operation", "message"),
    [
        (
            {"type": "update_file", "path": "src/calc.py", "diff": " nope\n-x\n+y\n"},
            "Error: Invalid Context",
        ),
        (
            {"type": "update_file", "path": "src/missing.py", "diff": "+x\n"},
            "use create_file",
        ),
        ({"type": "update_file", "path": "src/calc.py"}, "Invalid apply_patch operation"),
        ({"type": "rename_file", "path": "src/calc.py"}, "Invalid apply_patch operation"),
        ({"type": "delete_file", "path": "src/missing.py"}, "does not exist"),
        ({"type": "create_file", "path": "/etc/cron.d/x", "diff": "+x"}, "outside /workspace"),
        ({"type": "create_file", "path": ".git/hooks/pre-commit", "diff": "+x"}, ".git"),
        (
            {
                "type": "update_file",
                "path": "src/calc.py",
                "diff": "-    return a - b\n+    token = '[REDACTED:CREDENTIAL]'\n",
            },
            "redaction marker",
        ),
    ],
)
def test_apply_patch_failures_are_results_not_exceptions(
    files: WorkspaceFiles, workspace: Path, operation: dict[str, object], message: str
) -> None:
    before = _read(workspace, "src/calc.py")

    result = apply_patch_operation(files, operation)

    assert result.status == "failed"
    assert result.output.startswith("Error: ")
    assert message in result.output
    assert result.changed_path is None
    assert _read(workspace, "src/calc.py") == before


def test_apply_patch_refuses_planted_symlinks(
    files: WorkspaceFiles, workspace: Path, tmp_path: Path
) -> None:
    host_file = tmp_path / "host.txt"
    host_file.write_text("host\n", encoding="utf-8")
    (workspace / "src" / "link.py").symlink_to(host_file)

    for operation in (
        {"type": "update_file", "path": "src/link.py", "diff": "-host\n+owned\n"},
        {"type": "create_file", "path": "src/link.py", "diff": "+owned"},
        {"type": "delete_file", "path": "src/link.py"},
    ):
        result = apply_patch_operation(files, operation)
        assert result.status == "failed"
        assert "symlink" in result.output
    assert host_file.read_text(encoding="utf-8") == "host\n"


def test_view_numbers_lines_and_honours_view_range(files: WorkspaceFiles) -> None:
    whole = run_text_editor(files, {"command": "view", "path": "/workspace/src/calc.py"})
    ranged = run_text_editor(
        files, {"command": "view", "path": "src/calc.py", "view_range": [5, -1]}
    )

    assert whole.status == "completed"
    assert whole.output.startswith(
        "Here's the result of running `cat -n` on /workspace/src/calc.py:\n"
    )
    assert "     1\tdef add(a, b):\n     2\t    return a - b\n" in whole.output
    assert ranged.output.endswith("     5\tdef sub(a, b):\n     6\t    return a - b\n")
    assert "add" not in ranged.output
    assert whole.changed_path is None


@pytest.mark.parametrize(
    ("view_range", "message"),
    [
        ([0, 2], "first element"),
        ([3, 2], "second element"),
        ([1, 99], "second element"),
        ([1], "two"),
    ],
)
def test_view_rejects_invalid_ranges(
    files: WorkspaceFiles, view_range: list[int], message: str
) -> None:
    result = run_text_editor(
        files, {"command": "view", "path": "src/calc.py", "view_range": view_range}
    )

    assert result.status == "failed"
    assert message in result.output


def test_view_lists_directories_and_reports_binary_files(
    files: WorkspaceFiles, workspace: Path
) -> None:
    (workspace / "src" / "data.bin").write_bytes(b"\xff\xfe\x00")
    (workspace / ".hidden").mkdir()

    listing = run_text_editor(files, {"command": "view", "path": "/workspace"})
    binary = run_text_editor(files, {"command": "view", "path": "src/data.bin"})

    assert listing.output == (
        "Here are the files and directories up to 2 levels deep in /workspace, excluding "
        "hidden items:\n/workspace/src/\n/workspace/src/calc.py\n/workspace/src/data.bin\n"
    )
    assert binary.status == "failed"
    assert "binary or non-UTF-8" in binary.output


def test_view_output_is_capped_by_max_characters(files: WorkspaceFiles) -> None:
    result = run_text_editor(files, {"command": "view", "path": "src/calc.py"}, max_characters=40)

    assert result.output.startswith("Here's the result of running `cat -n` on\n")
    assert "truncated at 40 characters" in result.output


def test_create_writes_and_overwrites_files(files: WorkspaceFiles, workspace: Path) -> None:
    result = run_text_editor(
        files, {"command": "create", "path": "src/calc.py", "file_text": "VALUE = 1\n"}
    )

    assert result.status == "completed"
    assert result.output == "File created successfully at: /workspace/src/calc.py"
    assert _read(workspace, "src/calc.py") == "VALUE = 1\n"


def test_str_replace_requires_exactly_one_match(files: WorkspaceFiles, workspace: Path) -> None:
    twice = run_text_editor(
        files,
        {
            "command": "str_replace",
            "path": "src/calc.py",
            "old_str": "return a - b",
            "new_str": "x",
        },
    )
    never = run_text_editor(
        files, {"command": "str_replace", "path": "src/calc.py", "old_str": "absent"}
    )
    once = run_text_editor(
        files,
        {
            "command": "str_replace",
            "path": "src/calc.py",
            "old_str": "def add(a, b):\n    return a - b",
            "new_str": "def add(a, b):\n    return a + b",
        },
    )

    assert twice.status == "failed"
    assert "matched 2 times" in twice.output
    assert never.status == "failed"
    assert "matched 0 times" in never.output
    assert once.status == "completed"
    assert once.changed_path == "src/calc.py"
    assert "     2\t    return a + b\n" in once.output
    assert _read(workspace, "src/calc.py").startswith("def add(a, b):\n    return a + b\n")


def test_str_replace_and_insert_keep_crlf_line_endings(
    files: WorkspaceFiles, workspace: Path
) -> None:
    (workspace / "win.txt").write_bytes(b"alpha\r\nbeta\r\n")

    replaced = run_text_editor(
        files,
        {"command": "str_replace", "path": "win.txt", "old_str": "alpha\nbeta", "new_str": "A\nB"},
    )
    inserted = run_text_editor(
        files, {"command": "insert", "path": "win.txt", "insert_line": 1, "insert_text": "mid\n"}
    )

    assert (replaced.status, inserted.status) == ("completed", "completed")
    assert (workspace / "win.txt").read_bytes() == b"A\r\nmid\r\nB\r\n"


@pytest.mark.parametrize(
    ("insert_line", "expected"),
    [
        (0, "top\nfirst\nsecond\n"),
        (1, "first\ntop\nsecond\n"),
        (2, "first\nsecond\ntop\n"),
    ],
)
def test_insert_places_text_after_the_given_line(
    files: WorkspaceFiles, workspace: Path, insert_line: int, expected: str
) -> None:
    (workspace / "notes.txt").write_text("first\nsecond\n", encoding="utf-8")

    result = run_text_editor(
        files,
        {
            "command": "insert",
            "path": "notes.txt",
            "insert_line": insert_line,
            "insert_text": "top",
        },
    )

    assert result.status == "completed"
    assert _read(workspace, "notes.txt") == expected


def test_insert_rejects_lines_outside_the_file(files: WorkspaceFiles) -> None:
    result = run_text_editor(
        files, {"command": "insert", "path": "src/calc.py", "insert_line": 7, "insert_text": "x"}
    )

    assert result.status == "failed"
    assert "within [0, 6]" in result.output


@pytest.mark.parametrize(
    "arguments",
    [
        {"command": "create", "path": "a.py", "file_text": "key = '[REDACTED:CREDENTIAL]'\n"},
        {"command": "str_replace", "path": "src/calc.py", "old_str": "[REDACTED:X]"},
        {
            "command": "str_replace",
            "path": "src/calc.py",
            "old_str": "def sub",
            "new_str": "[REDACTED:SENSITIVE_MODEL_INPUT]",
        },
        {"command": "insert", "path": "src/calc.py", "insert_line": 0, "insert_text": "[REDACTED:"},
    ],
)
def test_editor_refuses_text_with_redaction_markers(
    files: WorkspaceFiles, workspace: Path, arguments: dict[str, object]
) -> None:
    before = _read(workspace, "src/calc.py")

    result = run_text_editor(files, arguments)

    assert result.status == "failed"
    assert "redaction marker" in result.output
    assert _read(workspace, "src/calc.py") == before
    assert not (workspace / "a.py").exists()


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        ({"command": "str_replace", "path": "src/calc.py"}, "str_replace.old_str"),
        ({"command": "insert", "path": "src/calc.py", "insert_text": "x"}, "insert.insert_line"),
        ({"command": "undo_edit", "path": "src/calc.py"}, "Invalid text editor call"),
        ({"command": "view", "path": "../outside"}, "'..'"),
        ({"command": "view", "path": "/etc/passwd"}, "outside /workspace"),
    ],
)
def test_editor_reports_invalid_calls(
    files: WorkspaceFiles, arguments: dict[str, object], message: str
) -> None:
    result = run_text_editor(files, arguments)

    assert result.status == "failed"
    assert message in result.output


def test_editor_refuses_planted_directory_symlinks(
    files: WorkspaceFiles, workspace: Path, tmp_path: Path
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (workspace / "escape").symlink_to(outside, target_is_directory=True)

    for arguments in (
        {"command": "view", "path": "escape"},
        {"command": "create", "path": "escape/planted.py", "file_text": "x = 1\n"},
    ):
        result = run_text_editor(files, arguments)
        assert result.status == "failed"
        assert "symlink" in result.output
    assert list(outside.iterdir()) == []


class _RecordingSession:
    def __init__(self, result: CommandResult, *, infrastructure_failure: str | None = None) -> None:
        self.result = result
        self.infrastructure_failure = infrastructure_failure
        self.commands: list[str] = []

    def exec(
        self, command: str, *, timeout_seconds: int, environment: dict[str, str] | None
    ) -> SessionCommandResult:
        self.commands.append(command)
        return SessionCommandResult(
            self.result, self.infrastructure_failure, self.infrastructure_failure is not None
        )


def _command_result(exit_code: int, *, stderr: str = "", timed_out: bool = False) -> CommandResult:
    return CommandResult(
        command="check",
        exit_code=exit_code,
        duration_seconds=0.1,
        stdout="",
        stderr=stderr,
        timed_out=timed_out,
    )


def test_syntax_check_returns_compiler_errors_for_python_files() -> None:
    error = '  File "/workspace/src/a b.py", line 1\n    def (\n        ^\nSyntaxError: invalid\n'
    session = _RecordingSession(_command_result(1, stderr=error))

    message = syntax_check(cast(SessionContainer, session), "src/a b.py")

    assert message == error.strip()
    assert session.commands[0].startswith("file='/workspace/src/a b.py'\n")
    assert "-m py_compile" in session.commands[0]
    assert "PYTHONPYCACHEPREFIX=/tmp/" in session.commands[0]


@pytest.mark.parametrize(
    ("result", "failure"),
    [
        (_command_result(0), None),
        (_command_result(124, timed_out=True), None),
        (_command_result(1, stderr="Error response from daemon"), "the sandbox container stopped"),
    ],
)
def test_syntax_check_is_silent_when_it_learns_nothing_about_the_file(
    result: CommandResult, failure: str | None
) -> None:
    session = _RecordingSession(result, infrastructure_failure=failure)

    assert syntax_check(cast(SessionContainer, session), "src/a.py") is None


def test_syntax_check_skips_files_that_are_not_python() -> None:
    session = _RecordingSession(_command_result(1, stderr="unused"))

    assert syntax_check(cast(SessionContainer, session), "src/main.rs") is None
    assert session.commands == []
