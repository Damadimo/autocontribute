"""Host-side executors for the models' file editing tools.

OpenAI models edit through ``apply_patch`` (V4A diffs) and Anthropic models through the
``text_editor_20250728`` tool. Both run on the host against the agent's workspace through
:class:`WorkspaceFiles`, and both report problems as failed tool results the model can
recover from rather than as exceptions.
"""

from __future__ import annotations

import shlex
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Annotated, Final, Literal

from pydantic import Field, TypeAdapter, ValidationError

from autocontribute.apply_diff import apply_diff
from autocontribute.domain import DomainModel
from autocontribute.exceptions import RepositoryError
from autocontribute.sandbox import SessionContainer
from autocontribute.workspace_files import CONTAINER_WORKSPACE, WorkspaceFiles

# Text the model copied from a scrubbed tool result; writing it would replace real file
# content with the marker.
_REDACTION_MARKER: Final = "[REDACTED:"
_DIRECTORY_VIEW_DEPTH: Final = 2
_SNIPPET_CONTEXT_LINES: Final = 4
_SYNTAX_CHECK_TIMEOUT_SECONDS: Final = 30
# Runs after `file=<path>`. Bytecode goes to /tmp so the check never adds __pycache__
# files to the workspace.
_PYTHON_SYNTAX_CHECK: Final = """
[ -f "$file" ] || exit 0
export PYTHONPYCACHEPREFIX=/tmp/ac-pycache
for python in python3 python; do
  if command -v "$python" >/dev/null 2>&1; then
    exec "$python" -m py_compile "$file"
  fi
done
"""


@dataclass(frozen=True, slots=True)
class EditResult:
    """One tool call's outcome, ready to return to the model."""

    status: Literal["completed", "failed"]
    output: str
    # The workspace-relative path the call wrote or deleted, for the syntax check and
    # for loading guidance that applies to it.
    changed_path: str | None = None
    # The arguments did not fit the tool, so the call did nothing.
    invalid_arguments: bool = False


class _CreateFile(DomainModel):
    type: Literal["create_file"]
    path: str
    diff: str


class _UpdateFile(DomainModel):
    type: Literal["update_file"]
    path: str
    diff: str


class _DeleteFile(DomainModel):
    type: Literal["delete_file"]
    path: str


class _View(DomainModel):
    command: Literal["view"]
    path: str
    view_range: list[int] | None = None


class _Create(DomainModel):
    command: Literal["create"]
    path: str
    file_text: str


class _StrReplace(DomainModel):
    command: Literal["str_replace"]
    path: str
    old_str: str
    new_str: str = ""


class _Insert(DomainModel):
    command: Literal["insert"]
    path: str
    insert_line: int
    insert_text: str


_PATCH_OPERATION: Final = TypeAdapter[_CreateFile | _UpdateFile | _DeleteFile](
    Annotated[_CreateFile | _UpdateFile | _DeleteFile, Field(discriminator="type")]
)
_EDITOR_CALL: Final = TypeAdapter[_View | _Create | _StrReplace | _Insert](
    Annotated[_View | _Create | _StrReplace | _Insert, Field(discriminator="command")]
)


def apply_patch_operation(files: WorkspaceFiles, operation: Mapping[str, object]) -> EditResult:
    """Run one ``apply_patch_call`` operation: create, update or delete a file."""

    try:
        parsed = _PATCH_OPERATION.validate_python(operation)
    except ValidationError as exc:
        return _invalid(f"Invalid apply_patch operation: {describe_validation_error(exc)}")
    if not isinstance(parsed, _DeleteFile) and _REDACTION_MARKER in parsed.diff:
        return _failed(_redaction_message("diff"))
    try:
        path = files.normalize(parsed.path)
        shown = files.display(path)
        if isinstance(parsed, _DeleteFile):
            files.delete(path)
            return EditResult("completed", f"Deleted {shown}", path)
        if isinstance(parsed, _CreateFile):
            content = apply_diff("", parsed.diff, mode="create")
            if content and not content.endswith("\n"):
                content += "\r\n" if "\r\n" in content else "\n"
            files.write_text(path, content)
            return EditResult("completed", f"Created {shown}", path)
        if files.kind(path) is None:
            return _failed(f"File does not exist: {shown}; use create_file for a new file")
        files.write_text(path, apply_diff(files.read_text(path), parsed.diff))
        return EditResult("completed", f"Updated {shown}", path)
    except (RepositoryError, ValueError) as exc:
        return _failed(str(exc))


def run_text_editor(
    files: WorkspaceFiles,
    arguments: Mapping[str, object],
    *,
    max_characters: int | None = None,
) -> EditResult:
    """Run one ``str_replace_based_edit_tool`` call.

    ``max_characters`` is the tool declaration's cap on ``view`` output.
    """

    try:
        call = _EDITOR_CALL.validate_python(arguments)
    except ValidationError as exc:
        return _invalid(f"Invalid text editor call: {describe_validation_error(exc)}")
    for name in ("file_text", "old_str", "new_str", "insert_text"):
        if _REDACTION_MARKER in getattr(call, name, ""):
            return _failed(_redaction_message(name))
    try:
        path = files.normalize(call.path)
        if isinstance(call, _View):
            return _view(files, path, call.view_range, max_characters)
        if isinstance(call, _Create):
            files.write_text(path, call.file_text)
            shown = files.display(path)
            return EditResult("completed", f"File created successfully at: {shown}", path)
        if isinstance(call, _StrReplace):
            return _str_replace(files, path, call.old_str, call.new_str)
        return _insert(files, path, call.insert_line, call.insert_text)
    except RepositoryError as exc:
        return _failed(str(exc))


def syntax_check(
    session: SessionContainer,
    path: str,
    *,
    environment: Mapping[str, str] | None = None,
) -> str | None:
    """Compile an edited Python file in the session and return the error, if any.

    Returns ``None`` when the file compiles, is not Python, no longer exists, or the image
    has no interpreter. ``environment`` is the one the agent's commands run with, so the
    recipe's interpreter is found first.
    """

    if not path.endswith(".py"):
        return None
    outcome = session.exec(
        f"file={shlex.quote(f'{CONTAINER_WORKSPACE}/{path}')}{_PYTHON_SYNTAX_CHECK}",
        timeout_seconds=_SYNTAX_CHECK_TIMEOUT_SECONDS,
        environment=environment,
    )
    result = outcome.result
    # A timeout or a sandbox failure says nothing about the file.
    if result.passed or result.timed_out or outcome.infrastructure_failure is not None:
        return None
    return (result.stderr + result.stdout).strip() or f"Syntax check exited {result.exit_code}"


def _view(
    files: WorkspaceFiles,
    path: str,
    view_range: list[int] | None,
    max_characters: int | None,
) -> EditResult:
    shown = files.display(path)
    if files.kind(path) == "directory":
        if view_range is not None:
            return _failed("The `view_range` parameter is not allowed when `path` is a directory")
        entries = files.list_directory(path, depth=_DIRECTORY_VIEW_DEPTH)
        listing = "\n".join(files.display(entry) for entry in entries)
        output = (
            f"Here are the files and directories up to {_DIRECTORY_VIEW_DEPTH} levels deep "
            f"in {shown}, excluding hidden items:\n{listing}\n"
        )
        return EditResult("completed", _limit(output, max_characters))
    data = files.read_bytes(path)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return _failed(f"{shown} is a binary or non-UTF-8 file ({len(data)} bytes)")
    lines = _lines(text)
    first, last = 1, len(lines)
    if view_range is not None:
        if len(view_range) != 2:
            return _failed("Invalid `view_range`: it must be a list of two integers")
        first, requested_last = view_range
        if not 1 <= first <= max(len(lines), 1):
            return _failed(
                f"Invalid `view_range` {view_range}: its first element must be within "
                f"[1, {len(lines)}]"
            )
        if requested_last != -1:
            if not first <= requested_last <= len(lines):
                return _failed(
                    f"Invalid `view_range` {view_range}: its second element must be -1 or "
                    f"within [{first}, {len(lines)}]"
                )
            last = requested_last
    numbered = _numbered(lines[first - 1 : last], first)
    output = f"Here's the result of running `cat -n` on {shown}:\n{numbered}"
    return EditResult("completed", _limit(output, max_characters))


def _str_replace(files: WorkspaceFiles, path: str, old: str, new: str) -> EditResult:
    shown = files.display(path)
    if not old:
        return _failed("Parameter `old_str` cannot be empty")
    text = files.read_text(path)
    if "\r\n" in text:
        old = old.replace("\r\n", "\n").replace("\n", "\r\n")
        new = new.replace("\r\n", "\n").replace("\n", "\r\n")
    count = text.count(old)
    if count != 1:
        return _failed(
            f"No replacement was performed: old_str matched {count} times in {shown}; "
            "it must match exactly once, so include more surrounding lines"
        )
    start = text.index(old)
    updated = text[:start] + new + text[start + len(old) :]
    files.write_text(path, updated)
    first_line = text.count("\n", 0, start) + 1
    return _edited(shown, updated, first_line, new.count("\n") + 1, path)


def _insert(files: WorkspaceFiles, path: str, after_line: int, insert: str) -> EditResult:
    shown = files.display(path)
    text = files.read_text(path)
    newline = "\r\n" if "\r\n" in text else "\n"
    lines = _lines(text.replace("\r\n", "\n"))
    if not 0 <= after_line <= len(lines):
        return _failed(f"Invalid `insert_line` {after_line}: it must be within [0, {len(lines)}]")
    inserted = _lines(insert.replace("\r\n", "\n"))
    updated_lines = [*lines[:after_line], *inserted, *lines[after_line:]]
    updated = newline.join(updated_lines)
    if updated_lines and (text.endswith("\n") or not text):
        updated += newline
    files.write_text(path, updated)
    return _edited(shown, updated, after_line + 1, len(inserted), path)


def _edited(shown: str, updated: str, first_line: int, line_count: int, path: str) -> EditResult:
    lines = _lines(updated)
    start = max(first_line - _SNIPPET_CONTEXT_LINES, 1)
    end = min(first_line + line_count - 1 + _SNIPPET_CONTEXT_LINES, len(lines))
    snippet = _numbered(lines[start - 1 : end], start)
    return EditResult(
        "completed",
        f"The file {shown} has been edited. Here's the result of running `cat -n` on a "
        f"snippet of {shown}:\n{snippet}"
        "Review the changes and make sure they are as expected. Edit the file again if "
        "necessary.",
        path,
    )


def _lines(text: str) -> list[str]:
    """Split text into lines; a final newline ends the last line rather than starting one."""

    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    return lines


def _numbered(lines: list[str], first: int) -> str:
    # Carriage returns of CRLF files are hidden; str_replace and insert add them back.
    shown = (line.removesuffix("\r") for line in lines)
    return "".join(f"{number:6}\t{line}\n" for number, line in enumerate(shown, first))


def _limit(output: str, max_characters: int | None) -> str:
    if max_characters is None or len(output) <= max_characters:
        return output
    return (
        f"{output[:max_characters]}\n[Output truncated at {max_characters} characters; "
        "view a smaller `view_range`.]\n"
    )


def _redaction_message(name: str) -> str:
    return (
        f"Refusing `{name}` that contains a redaction marker ({_REDACTION_MARKER}...]). "
        "That text was removed from your view of the file; edit around it with a smaller "
        "replacement instead of rewriting it."
    )


def describe_validation_error(error: ValidationError) -> str:
    """Return a validation error as one line of ``field: message`` parts for the model."""

    return "; ".join(
        ".".join(str(part) for part in item["loc"]) + f": {item['msg']}"
        if item["loc"]
        else item["msg"]
        for item in error.errors()
    )


def _failed(message: str) -> EditResult:
    return EditResult("failed", f"Error: {message}")


def _invalid(message: str) -> EditResult:
    return EditResult("failed", f"Error: {message}", invalid_arguments=True)


__all__ = [
    "EditResult",
    "apply_patch_operation",
    "describe_validation_error",
    "run_text_editor",
    "syntax_check",
]
