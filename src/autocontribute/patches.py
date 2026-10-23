"""The agent's patch: extraction from its workspace and the split into tests and sources.

Validation applies the whole patch to a copy of the post-setup snapshot, and red/green applies
only its test part, so neither sees stray files or build output from the agent's workspace
(DESIGN §5.4-§5.5, §7.1).
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Final

from autocontribute.exceptions import PatchEncodingError, RepositoryError
from autocontribute.repository import RepositoryWorkspace
from autocontribute.workspace_files import WorkspaceFiles

_FILE_HEADER: Final = "diff --git "
_FILE_START: Final = re.compile(r"^(?=diff --git )", re.MULTILINE)
_FILE_START_BYTES: Final = re.compile(rb"^(?=diff --git )", re.MULTILINE)
_HUNK_START: Final = re.compile(r"^(?=@@ )", re.MULTILINE)
_HUNK_HEADER: Final = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_LINE: Final = re.compile(r"[^\n]*\n|[^\n]+\Z")
_OCTAL_ESCAPE: Final = re.compile(r"[0-7]{3}")
# research-envsetup.md §B10, plus `test/`, the directory mocha, CPython and Maven use.
_TEST_DIRECTORIES: Final = frozenset({"__tests__", "test", "tests"})
_TEST_FILE_NAMES: Final = ("test_*.py", "*_test.py", "*_test.go", "*.test.*", "*.spec.*")
_RUST_TEST_ATTRIBUTE: Final = re.compile(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]")
_RUST_RAW_STRING: Final = re.compile(r'[bc]?r(#*)"')
_RUST_CHARACTER: Final = re.compile(
    r"'(?:[^'\\\n]|\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F_]{1,8}\}|[^\n]))'"
)
_GIT_QUOTED_ESCAPES: Final = {
    "a": 7,
    "b": 8,
    "t": 9,
    "n": 10,
    "v": 11,
    "f": 12,
    "r": 13,
    '"': 34,
    "\\": 92,
}


@dataclass(frozen=True, slots=True)
class FilePatch:
    """One file's section of a Git patch."""

    path: str
    # Everything before the first hunk; the whole section for binary and mode-only changes.
    header: str
    hunks: tuple[str, ...]

    @property
    def text(self) -> str:
        return self.header + "".join(self.hunks)

    @property
    def changed_lines(self) -> int:
        return sum(
            1 for hunk in self.hunks for line in _lines(hunk)[1:] if line.startswith(("+", "-"))
        )


@dataclass(frozen=True, slots=True)
class Patch:
    """A Git patch as produced by ``git diff --binary --full-index --no-renames``."""

    files: tuple[FilePatch, ...]

    @property
    def text(self) -> str:
        return "".join(file.text for file in self.files)

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(file.path for file in self.files)

    @property
    def changed_lines(self) -> int:
        return sum(file.changed_lines for file in self.files)


@dataclass(frozen=True, slots=True)
class PatchSplit:
    """The test part of a patch, for red/green, and the rest."""

    tests: Patch
    sources: Patch


def extract_patch(workspace: RepositoryWorkspace) -> Patch:
    """Return every change in the agent's workspace since the base commit.

    That is tracked changes plus new files Git does not ignore. Raises
    :class:`PatchEncodingError` when the patch is not UTF-8 text.
    """

    raw = workspace.patch_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PatchEncodingError(_non_utf8_paths(raw)) from exc
    return parse_patch(text)


def parse_patch(text: str) -> Patch:
    """Split a Git patch into its file sections and their hunks, losslessly."""

    if not text:
        return Patch(())
    if not text.startswith(_FILE_HEADER):
        raise RepositoryError("Patch does not start with a `diff --git` line")
    files = []
    for section in _FILE_START.split(text)[1:]:
        header, *hunks = _HUNK_START.split(section)
        files.append(FilePatch(_header_path(header.split("\n", 1)[0]), header, tuple(hunks)))
    return Patch(tuple(files))


def is_test_path(path: str) -> bool:
    """Return whether a repository path is a test file by its directory or name."""

    *directories, name = PurePosixPath(path).parts
    if any(directory in _TEST_DIRECTORIES for directory in directories):
        return True
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in _TEST_FILE_NAMES)


def split_patch(patch: Patch, post_image: WorkspaceFiles) -> PatchSplit:
    """Separate test changes from source changes.

    Files are classified by :func:`is_test_path`. Rust keeps unit tests inside source files,
    so a Rust hunk counts as a test when every non-blank line it changes lies in a
    ``#[cfg(test)]`` item of the file after the patch, read from ``post_image``.
    """

    tests: list[FilePatch] = []
    sources: list[FilePatch] = []
    for file in patch.files:
        if is_test_path(file.path):
            tests.append(file)
            continue
        if not file.path.endswith(".rs") or not file.hunks or "\ndeleted file mode " in file.header:
            sources.append(file)
            continue
        test_lines = _rust_test_lines(post_image.read_text(file.path))
        flags = [_changes_within(hunk, test_lines) for hunk in file.hunks]
        if all(flags):
            tests.append(file)
        elif not any(flags):
            sources.append(file)
        else:
            tests.append(_keep_hunks(file, flags, keep=True))
            sources.append(_keep_hunks(file, flags, keep=False))
    return PatchSplit(Patch(tuple(tests)), Patch(tuple(sources)))


def _keep_hunks(file: FilePatch, flags: list[bool], *, keep: bool) -> FilePatch:
    """Return the file's section with only the hunks whose flag equals ``keep``.

    Later hunks' new-side start lines move by what the dropped hunks added or removed. The
    ``index`` line goes because its post-image blob no longer matches.
    """

    header = "".join(line for line in _lines(file.header) if not line.startswith("index "))
    shift = 0
    hunks: list[str] = []
    for hunk, flag in zip(file.hunks, flags, strict=True):
        old_start, old_count, new_start, new_count, header_end = _hunk_range(hunk)
        if flag != keep:
            shift += new_count - old_count
            continue
        hunks.append(
            f"@@ -{_range(old_start, old_count)} +{_range(new_start - shift, new_count)} @@"
            + hunk[header_end:]
        )
    return FilePatch(file.path, header, tuple(hunks))


def _changes_within(hunk: str, lines: set[int]) -> bool:
    """Return whether every non-blank line the hunk adds or removes lies within ``lines``.

    A removed line is placed at the new-side line that now follows it.
    """

    _, _, current, _, _ = _hunk_range(hunk)
    placed: list[bool] = []
    for line in _lines(hunk)[1:]:
        if line.startswith(("+", "-")):
            if line[1:].strip():
                placed.append(current in lines)
            if line.startswith("+"):
                current += 1
        elif line.startswith(" "):
            current += 1
    return bool(placed) and all(placed)


def _rust_test_lines(text: str) -> set[int]:
    """Return the line numbers of every ``#[cfg(test)]`` item, attribute included."""

    code = _rust_code_only(text)
    lines: set[int] = set()
    for match in _RUST_TEST_ATTRIBUTE.finditer(code):
        first = code.count("\n", 0, match.start()) + 1
        last = code.count("\n", 0, _rust_item_end(code, match.end())) + 1
        lines.update(range(first, last + 1))
    return lines


def _rust_item_end(code: str, start: int) -> int:
    """Return the offset of the ``;`` or closing ``}`` that ends the item after ``start``."""

    nesting = 0
    for index in range(start, len(code)):
        character = code[index]
        if character in "([":
            nesting += 1
        elif character in ")]":
            nesting -= 1
        elif nesting == 0 and character == ";":
            return index
        elif nesting == 0 and character == "{":
            depth = 0
            for end in range(index, len(code)):
                if code[end] == "{":
                    depth += 1
                elif code[end] == "}":
                    depth -= 1
                    if depth == 0:
                        return end
            break
    return len(code)


def _rust_code_only(text: str) -> str:
    """Blank comments, strings and character literals, keeping offsets and newlines.

    Braces and brackets inside them would otherwise end an item early.
    """

    blanked = list(text)

    def blank(start: int, end: int) -> None:
        for index in range(start, min(end, len(text))):
            if blanked[index] != "\n":
                blanked[index] = " "

    index = 0
    while index < len(text):
        character = text[index]
        follows_identifier = index > 0 and (text[index - 1].isalnum() or text[index - 1] == "_")
        raw_string = None if follows_identifier else _RUST_RAW_STRING.match(text, index)
        if text.startswith("//", index):
            end = text.find("\n", index)
            end = len(text) if end == -1 else end
        elif text.startswith("/*", index):
            depth, end = 0, index
            while end < len(text):
                if text.startswith("/*", end):
                    depth, end = depth + 1, end + 2
                elif text.startswith("*/", end):
                    depth, end = depth - 1, end + 2
                    if depth == 0:
                        break
                else:
                    end += 1
        elif raw_string is not None:
            closing = '"' + raw_string.group(1)
            found = text.find(closing, raw_string.end())
            end = len(text) if found == -1 else found + len(closing)
        elif character == '"':
            end = index + 1
            while end < len(text) and text[end] != '"':
                end += 2 if text[end] == "\\" else 1
            end += 1
        elif character == "'" and (literal := _RUST_CHARACTER.match(text, index)) is not None:
            end = literal.end()
        else:
            index += 1
            continue
        blank(index, end)
        index = end
    return "".join(blanked)


def _hunk_range(hunk: str) -> tuple[int, int, int, int, int]:
    """Return a hunk's old start and count, new start and count, and its header's end."""

    match = _HUNK_HEADER.match(hunk)
    if match is None:
        first_line = hunk.split("\n", 1)[0]
        raise RepositoryError(f"Malformed hunk header: {first_line}")
    old_start, old_count, new_start, new_count = match.groups()
    return (
        int(old_start),
        1 if old_count is None else int(old_count),
        int(new_start),
        1 if new_count is None else int(new_count),
        match.end(),
    )


def _range(start: int, count: int) -> str:
    return str(start) if count == 1 else f"{start},{count}"


def _header_path(line: str, *, strict: bool = True) -> str:
    """Return the path of a ``diff --git a/<path> b/<path>`` line, unquoting Git's C-style quotes.

    With ``--no-renames`` both sides name the same path, which is what makes an unquoted
    path that contains spaces unambiguous.
    """

    rest = line.removeprefix(_FILE_HEADER)
    if rest.startswith('"'):
        source, rest = _unquote(rest, strict=strict)
        destination, rest = _unquote(rest[1:], strict=strict) if rest.startswith(' "') else ("", "")
    else:
        middle = (len(rest) - 1) // 2
        source, destination = rest[:middle], rest[middle + 1 :]
        rest = rest[middle : middle + 1].strip()
    if rest or not source.startswith("a/") or destination != f"b/{source[2:]}":
        raise RepositoryError(f"Cannot read the path of patch header: {line}")
    return destination[2:]


def _unquote(text: str, *, strict: bool) -> tuple[str, str]:
    """Decode a C-quoted Git path at the start of ``text``; return it and the remainder."""

    decoded = bytearray()
    index = 1
    while index < len(text):
        character = text[index]
        if character == '"':
            remainder = text[index + 1 :]
            if not strict:
                return decoded.decode("utf-8", errors="replace"), remainder
            try:
                return decoded.decode("utf-8"), remainder
            except UnicodeDecodeError as exc:
                raise PatchEncodingError((decoded.decode("utf-8", errors="replace"),)) from exc
        escape = text[index + 1 : index + 4]
        if character != "\\":
            decoded.extend(character.encode("utf-8"))
            index += 1
        elif escape[:1] in _GIT_QUOTED_ESCAPES:
            decoded.append(_GIT_QUOTED_ESCAPES[escape[0]])
            index += 2
        elif _OCTAL_ESCAPE.fullmatch(escape):
            decoded.append(int(escape, 8))
            index += 4
        else:
            raise RepositoryError(f"Malformed quoted path in patch header: {text}")
    raise RepositoryError(f"Unterminated quoted path in patch header: {text}")


def _non_utf8_paths(raw: bytes) -> tuple[str, ...]:
    paths = []
    for section in _FILE_START_BYTES.split(raw)[1:]:
        try:
            section.decode("utf-8")
        except UnicodeDecodeError:
            header = section.split(b"\n", 1)[0].decode("utf-8", errors="replace")
            paths.append(_header_path(header, strict=False))
    return tuple(paths)


def _lines(text: str) -> list[str]:
    """Split on newlines only, keeping them; other line breaks are content in a patch."""

    return _LINE.findall(text)


__all__ = [
    "FilePatch",
    "Patch",
    "PatchSplit",
    "extract_patch",
    "is_test_path",
    "parse_patch",
    "split_patch",
]
