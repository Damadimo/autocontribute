"""Signatures of a broken test environment, and the paths a git diff touches."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from autocontribute.diff_gates import is_workflow_path

# Tests run offline by design, so these alone do not mean the environment is broken.
_NETWORK_FAILURE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "network name resolution failed",
        re.compile(
            r"\b(?:temporary failure in name resolution|name or service not known|"
            r"could not resolve host(?:name)?|getaddrinfo (?:failed|error)|gaierror|"
            r"getaddrinfo ENOTFOUND|ENOTFOUND|EAI_AGAIN|EAI_NONAME|unknown host|"
            r"UnknownHostException|nodename nor servname provided)\b",
            re.I,
        ),
    ),
    (
        "the validation command failed because the network was unavailable",
        re.compile(
            r"\b(?:network is unreachable|failed to establish a new connection|"
            r"could not connect to (?:the )?server|connection refused|connection timed out|"
            r"cannot connect to proxy|ProxyError|tunnel connection failed|"
            r"ENETUNREACH|ECONNREFUSED|ETIMEDOUT)\b",
            re.I,
        ),
    ),
)
_INFRASTRUCTURE_FAILURE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("the validation command was not installed", re.compile(r"\bcommand not found\b", re.I)),
    (
        "the test runner failed internally",
        re.compile(r"(?m)^INTERNALERROR(?:>|:|\s)", re.I),
    ),
    (
        "a required file or executable was missing",
        re.compile(r"\b(?:no such file or directory|file or directory not found)\b", re.I),
    ),
    (
        "the test runner discovered no tests",
        re.compile(
            r"\b(?:no tests (?:ran|found|collected|were executed)|"
            r"no test files? (?:found|were found)|collected 0 items?|ran 0 tests?)\b",
            re.I,
        ),
    ),
    (
        "a Python module was unavailable",
        re.compile(
            r"\b(?:ModuleNotFoundError|ImportError)\s*:\s*No module named\b",
            re.I,
        ),
    ),
    (
        "a language module was unavailable",
        re.compile(
            r"\b(?:(?:error:\s*)?cannot find module|no such module|could not find module|"
            r"could not load module|missing required module)\b|"
            r"\bmodule\s+(?:'[^'\r\n]{1,128}'|\"[^\"\r\n]{1,128}\"|"
            r"`[^`\r\n]{1,128}`)\s+not found\b",
            re.I,
        ),
    ),
    (
        "a package script was missing",
        re.compile(
            r"\b(?:missing script|error command [\"'][^\r\n\"']{1,128}[\"'] not found)\b",
            re.I,
        ),
    ),
    (
        "a runtime dependency was unavailable",
        re.compile(
            r"\b(?:ClassNotFoundException|NoClassDefFoundError|"
            r"LoadError:\s*cannot load such file)\b",
            re.I,
        ),
    ),
    (
        "a compiled-language dependency or type environment was unavailable",
        re.compile(
            r"\berror\[E0463\]:\s*can't find crate for\b|"
            r"\berror\s+TS2688:|"
            r"(?m:^[^\r\n]{0,1000}\berror:\s+package\s+"
            r"[^\r\n]{1,256}\s+does not exist\b)|"
            r"\berror\s+CS0246:",
            re.I,
        ),
    ),
    (
        "the configured compiler or target toolchain was unavailable",
        re.compile(
            r"\btarget may not be installed\b|"
            r"\binvalid (?:source|target) release\b|"
            r"\brelease version [^\r\n]{1,64} not supported\b",
            re.I,
        ),
    ),
    (
        "sandbox storage was unavailable",
        re.compile(
            r"\b(?:no space left on device|disk quota exceeded|read-only file system|ENOSPC)\b",
            re.I,
        ),
    ),
    (
        "sandbox memory was exhausted",
        re.compile(
            r"\b(?:OutOfMemoryError|out of memory|cannot allocate memory|ENOMEM|OOMKilled)\b",
            re.I,
        ),
    ),
    (
        "the validation command lacked permission",
        re.compile(
            r"\b(?:permission denied|operation not permitted|access is denied|EACCES)\b",
            re.I,
        ),
    ),
    *_NETWORK_FAILURE_PATTERNS,
    (
        "the Docker validation service was unavailable",
        re.compile(
            r"\b(?:cannot connect to the docker daemon|is the docker daemon running)\b",
            re.I,
        ),
    ),
)


@dataclass
class _DiffFile:
    old_path: str
    new_path: str


def environment_failure_signature(output: str) -> str | None:
    """Name the broken-environment pattern in one failing test's output, if any.

    Network failures are left out: the tests that need the network fail on the unmodified
    base too and are ignored like any other failing-before test.
    """

    for reason, pattern in _INFRASTRUCTURE_FAILURE_PATTERNS:
        if (reason, pattern) not in _NETWORK_FAILURE_PATTERNS and pattern.search(output):
            return reason
    return None


def _parse_git_diff(diff: str) -> list[_DiffFile]:
    files: list[_DiffFile] = []
    current: _DiffFile | None = None

    for line in diff.splitlines():
        if line.startswith("diff --git "):
            if current is not None:
                files.append(current)
            paths = _header_paths(line)
            if paths is None:
                current = _DiffFile(old_path="<unparseable>", new_path="<unparseable>")
            else:
                current = _DiffFile(old_path=paths[0], new_path=paths[1])
        elif current is not None and line.startswith("rename from "):
            current.old_path = _unquote_path(line.removeprefix("rename from "))
        elif current is not None and line.startswith("rename to "):
            current.new_path = _unquote_path(line.removeprefix("rename to "))

    if current is not None:
        files.append(current)
    return files


def _header_paths(line: str) -> tuple[str, str] | None:
    try:
        parts = shlex.split(line)
    except ValueError:
        return None
    if len(parts) != 4:
        return None
    return _strip_diff_prefix(parts[2]), _strip_diff_prefix(parts[3])


def _strip_diff_prefix(path: str) -> str:
    return path[2:] if path.startswith(("a/", "b/")) else path


def _unquote_path(path: str) -> str:
    try:
        parts = shlex.split(path)
    except ValueError:
        return "<unparseable>"
    return parts[0] if len(parts) == 1 else path


def patch_paths(diff: str) -> list[str]:
    """Return every repository path a patch adds, changes, or removes."""

    paths = {
        path
        for item in _parse_git_diff(diff)
        for path in (item.old_path, item.new_path)
        if path != "/dev/null"
    }
    if "<unparseable>" in paths:
        raise ValueError("patch has a file header whose paths cannot be parsed")
    return sorted(paths)


def workflow_paths(diff: str) -> list[str]:
    """Return the CI configuration paths a patch adds, changes, or removes."""

    return sorted(
        {
            path
            for item in _parse_git_diff(diff)
            for path in (item.old_path, item.new_path)
            if path != "/dev/null" and is_workflow_path(path)
        }
    )


__all__ = ["environment_failure_signature", "patch_paths", "workflow_paths"]
