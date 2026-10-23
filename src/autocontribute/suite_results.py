"""Per-test results from the reports test runners write (DESIGN §5.3, research-envsetup.md §B7).

Each recipe's test command writes one structured report: JUnit XML for pytest, Jest's JSON for
Jest and Vitest, Mocha's JSON, ``go test -json`` events, or libtest's text for cargo. Reports
are written by repository code, so they are untrusted input: the caller caps their size, XML
is parsed without any DTD or entity, and test counts, identifiers and messages are bounded.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Final, Literal
from xml.parsers import expat

from autocontribute.environments import TestFramework
from autocontribute.exceptions import SuiteReportError
from autocontribute.workspace_files import CONTAINER_WORKSPACE

CaseStatus = Literal["passed", "failed", "error", "skipped"]

MAX_REPORT_BYTES: Final = 64 * 1024 * 1024
_MAX_TESTS: Final = 200_000
_MAX_ID_CHARACTERS: Final = 1_000
_MAX_MESSAGE_CHARACTERS: Final = 2_000
# When one test appears twice, as libtest names can across a workspace's test binaries, the
# worse result stands.
_SEVERITY: Final[Mapping[CaseStatus, int]] = {"skipped": 0, "passed": 1, "failed": 2, "error": 3}
_JEST_STATUSES: Final[Mapping[str, CaseStatus]] = {
    "passed": "passed",
    "failed": "failed",
    "skipped": "skipped",
    "pending": "skipped",
    "todo": "skipped",
    "disabled": "skipped",
}
_JUNIT_OUTCOMES: Final[Mapping[str, CaseStatus]] = {
    "failure": "failed",
    "error": "error",
    "skipped": "skipped",
}
_GO_STATUSES: Final[Mapping[str, CaseStatus]] = {
    "pass": "passed",
    "fail": "failed",
    "skip": "skipped",
}
_LIBTEST_RESULT: Final = re.compile(
    r"^test (?P<name>.+?) \.\.\. (?P<status>ok|FAILED|ignored(?:, .*)?)$"
)
_LIBTEST_SHOULD_PANIC: Final = re.compile(r" - should panic(?: with .*)?$")
_LIBTEST_OUTPUT_HEADER: Final = re.compile(r"^---- (?P<name>.+?) std(?:out|err) ----$")
_MOCHA_HOOK: Final = re.compile(r'"(?:before|after)(?: all| each)?" hook')


@dataclass(frozen=True, slots=True)
class CaseResult:
    """One test's outcome in one run of a suite."""

    test_id: str
    status: CaseStatus
    duration_seconds: float | None
    # The start of the failure or skip message; empty for a pass.
    message: str
    # The result stands for a whole file, module or package, which test_id names, rather than
    # one test: its tests could not be collected, imported or built, or it failed outside them.
    collection_error: bool = False


def parse_report(framework: TestFramework, data: bytes) -> dict[str, CaseResult]:
    """Read a test report into results by test ID.

    Raises :class:`SuiteReportError` when the report is malformed, too large, or of a framework
    that writes no per-test report.
    """

    if len(data) > MAX_REPORT_BYTES:
        raise SuiteReportError(f"The test report exceeds {MAX_REPORT_BYTES:,} bytes")
    parsers: dict[str, Callable[[bytes], Iterable[CaseResult]]] = {
        "pytest": _junit_results,
        "jest": _jest_results,
        "vitest": _jest_results,
        "mocha": _mocha_results,
        "go": _go_results,
        "cargo": _libtest_results,
    }
    parser = parsers.get(framework)
    if parser is None:
        raise SuiteReportError(f"{framework} writes no per-test report")
    results: dict[str, CaseResult] = {}
    for result in parser(data):
        existing = results.get(result.test_id)
        if existing is None and len(results) >= _MAX_TESTS:
            raise SuiteReportError(f"The test report lists more than {_MAX_TESTS:,} tests")
        if existing is None or _SEVERITY[result.status] > _SEVERITY[existing.status]:
            results[result.test_id] = result
    return results


def _result(
    test_id: str,
    status: CaseStatus,
    duration_seconds: float | None,
    message: str,
    *,
    collection_error: bool = False,
) -> CaseResult:
    identifier = "".join(c if c.isprintable() else " " for c in test_id).strip()
    if not identifier:
        raise SuiteReportError("The test report names a test without an identifier")
    valid_duration = (
        duration_seconds is not None and math.isfinite(duration_seconds) and duration_seconds >= 0
    )
    return CaseResult(
        identifier[:_MAX_ID_CHARACTERS],
        status,
        duration_seconds if valid_duration else None,
        "" if status == "passed" else message.strip()[:_MAX_MESSAGE_CHARACTERS],
        collection_error,
    )


# JUnit XML (pytest)


class _JUnitReader:
    def __init__(self) -> None:
        self.results: list[CaseResult] = []
        self._test: dict[str, str] | None = None
        self._status: CaseStatus | None = None
        self._message = ""
        self._outcome_depth = 0
        self._text: list[str] = []

    def start(self, name: str, attributes: dict[str, str]) -> None:
        if name == "testcase":
            self._test = attributes
            self._status = None
            self._message = ""
        elif self._test is not None and (status := _JUNIT_OUTCOMES.get(name)) is not None:
            if self._status is None or _SEVERITY[status] > _SEVERITY[self._status]:
                self._status = status
                self._message = attributes.get("message", "")
                self._outcome_depth = 1
                self._text = []
        elif self._outcome_depth:
            self._outcome_depth += 1

    def end(self, name: str) -> None:
        if self._outcome_depth:
            self._outcome_depth -= 1
            if not self._outcome_depth and not self._message:
                self._message = "".join(self._text)
        if name == "testcase" and self._test is not None:
            classname = self._test.get("classname", "")
            test_name = self._test.get("name", "")
            status = self._status or "passed"
            self.results.append(
                _result(
                    f"{classname}::{test_name}" if classname else test_name,
                    status,
                    _seconds(self._test.get("time")),
                    self._message,
                    # pytest reports a module it could not collect as an error case without
                    # a class name, named by the module's dotted path.
                    collection_error=not classname and status == "error",
                )
            )
            self._test = None

    def text(self, data: str) -> None:
        if self._outcome_depth and sum(map(len, self._text)) < _MAX_MESSAGE_CHARACTERS:
            self._text.append(data)


def _junit_results(data: bytes) -> list[CaseResult]:
    reader = _JUnitReader()
    parser = expat.ParserCreate()
    parser.buffer_text = True

    def refuse_declarations(*_arguments: object) -> None:
        # No DTD means no entity can be defined, so no expansion bomb and no external file.
        raise SuiteReportError("The JUnit report declares a DTD or entity")

    parser.StartDoctypeDeclHandler = refuse_declarations
    parser.EntityDeclHandler = refuse_declarations
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    parser.StartElementHandler = reader.start
    parser.EndElementHandler = reader.end
    parser.CharacterDataHandler = reader.text
    try:
        parser.Parse(data, True)
    except expat.ExpatError as exc:
        raise SuiteReportError(f"The JUnit report is not well-formed XML: {exc}") from exc
    return reader.results


# Jest and Vitest JSON


def _jest_results(data: bytes) -> list[CaseResult]:
    report = _json_object(data)
    results: list[CaseResult] = []
    for suite in _objects(report.get("testResults")):
        path = _workspace_relative(_text(suite.get("name")) or _text(suite.get("testFilePath")))
        assertions = _objects(suite.get("assertionResults"))
        if not assertions and suite.get("status") == "failed":
            # The file failed before any test ran: a syntax or import error.
            results.append(
                _result(path, "error", None, _text(suite.get("message")), collection_error=True)
            )
        for assertion in assertions:
            titles = [*_strings(assertion.get("ancestorTitles")), _text(assertion.get("title"))]
            full_name = _text(assertion.get("fullName")) or " ".join(t for t in titles if t)
            status = _JEST_STATUSES.get(_text(assertion.get("status")))
            if status is None:
                continue
            duration = assertion.get("duration")
            results.append(
                _result(
                    f"{path}::{full_name}",
                    status,
                    duration / 1_000 if isinstance(duration, int | float) else None,
                    "\n".join(_strings(assertion.get("failureMessages"))),
                )
            )
    return results


# Mocha JSON


def _mocha_results(data: bytes) -> list[CaseResult]:
    report = _json_object(data)
    results: list[CaseResult] = []
    sections: tuple[tuple[str, CaseStatus], ...] = (
        ("passes", "passed"),
        ("pending", "skipped"),
        ("failures", "failed"),
    )
    for key, status in sections:
        for test in _objects(report.get(key)):
            title = _text(test.get("fullTitle")) or _text(test.get("title"))
            path = _workspace_relative(_text(test.get("file")))
            error = test.get("err")
            message = _text(error.get("message")) if isinstance(error, dict) else ""
            duration = test.get("duration")
            results.append(
                _result(
                    f"{path}::{title}" if path else title,
                    "error" if status == "failed" and _MOCHA_HOOK.search(title) else status,
                    duration / 1_000 if isinstance(duration, int | float) else None,
                    message,
                )
            )
    return results


# go test -json


def _go_results(data: bytes) -> list[CaseResult]:
    outcomes: dict[tuple[str, str], tuple[str, float | None]] = {}
    output: dict[tuple[str, str], list[str]] = {}
    failed_packages: dict[str, float | None] = {}
    for line in data.splitlines():
        if not line.startswith(b"{"):
            continue
        try:
            event = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
            continue
        if not isinstance(event, dict):
            continue
        action, package, test = (_text(event.get(k)) for k in ("Action", "Package", "Test"))
        elapsed = event.get("Elapsed")
        seconds = float(elapsed) if isinstance(elapsed, int | float) else None
        key = (package, test)
        if action == "output":
            lines = output.setdefault(key, [])
            if sum(map(len, lines)) < _MAX_MESSAGE_CHARACTERS:
                lines.append(_text(event.get("Output")))
        elif test and action in {"run", "pass", "fail", "skip"}:
            outcomes[key] = (action, seconds)
        elif not test and action == "fail":
            failed_packages[package] = seconds
    results: list[CaseResult] = []
    for (package, test), (action, seconds) in outcomes.items():
        message = "".join(output.get((package, test), []))
        status = _GO_STATUSES.get(action)
        if status is None:
            # Started but never finished: the test binary crashed or was killed.
            status, message = "error", message or "the test did not finish"
        results.append(_result(f"{package}::{test}", status, seconds, message))
    failing = {
        package for (package, _), (action, _) in outcomes.items() if action in {"fail", "run"}
    }
    for package, seconds in failed_packages.items():
        if package not in failing:
            # A build failure, a panic outside any test, or a failing TestMain.
            message = "".join(output.get((package, ""), [])) or "the package failed"
            results.append(_result(package, "error", seconds, message, collection_error=True))
    return results


# libtest text (cargo test)


def _libtest_results(data: bytes) -> list[CaseResult]:
    statuses: list[tuple[str, CaseStatus]] = []
    messages: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in data.decode("utf-8", errors="replace").splitlines():
        if (match := _LIBTEST_RESULT.match(line)) is not None:
            name = _LIBTEST_SHOULD_PANIC.sub("", match["name"])
            status: CaseStatus = (
                "passed"
                if match["status"] == "ok"
                else "failed"
                if match["status"] == "FAILED"
                else "skipped"
            )
            statuses.append((name, status))
            current = None
        elif (header := _LIBTEST_OUTPUT_HEADER.match(line)) is not None:
            current = messages.setdefault(header["name"], [])
        elif line in {"failures:", "successes:"} or line.startswith("test result:"):
            current = None
        elif current is not None and sum(map(len, current)) < _MAX_MESSAGE_CHARACTERS:
            current.append(line + "\n")
    return [
        _result(name, status, None, "".join(messages.get(name, []))) for name, status in statuses
    ]


def _json_object(data: bytes) -> dict[str, object]:
    try:
        value = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
        raise SuiteReportError(f"The JSON test report is malformed: {exc}") from exc
    if not isinstance(value, dict):
        raise SuiteReportError("The JSON test report is not an object")
    return value


def _objects(value: object) -> list[dict[str, object]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _strings(value: object) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""


def _seconds(value: str | None) -> float | None:
    try:
        return float(value) if value is not None else None
    except ValueError:
        return None


def _workspace_relative(path: str) -> str:
    return path.removeprefix(f"{CONTAINER_WORKSPACE}/")


__all__ = ["MAX_REPORT_BYTES", "CaseResult", "CaseStatus", "parse_report"]
