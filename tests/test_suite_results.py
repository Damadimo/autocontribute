from __future__ import annotations

import json

import pytest

import autocontribute.suite_results as suite_results
from autocontribute.environments import TestFramework
from autocontribute.exceptions import SuiteReportError
from autocontribute.suite_results import CaseResult, parse_report

_JUNIT = b"""<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="pytest" errors="1" failures="2" skipped="1" tests="6">
<testcase classname="tests.test_mod" name="test_pass" time="0.001" />
<testcase classname="tests.test_mod" name="test_fail" time="0.25">
<failure message="assert 1 == 2">def test_fail():
&gt;       assert 1 == 2</failure></testcase>
<testcase classname="tests.test_mod" name="test_skip" time="0.000">
<skipped type="pytest.skip" message="needs network">tests/test_mod.py:9: needs network</skipped>
</testcase>
<testcase classname="" name="tests.test_broken" time="nan">
<error message="">ImportError while importing test module</error></testcase>
<testcase classname="tests.test_mod.TestA" name="test_param[1-2]" time="0.01">
<failure message="boom">trace</failure><error message="error in teardown">fixture</error>
</testcase>
<testcase classname="tests.test_mod" name="test_output" time="-1"><system-out>noise</system-out>
</testcase>
</testsuite></testsuites>
"""


def test_junit_reports_give_each_test_its_worst_outcome_and_message() -> None:
    results = parse_report("pytest", _JUNIT)

    assert results == {
        "tests.test_mod::test_pass": CaseResult("tests.test_mod::test_pass", "passed", 0.001, ""),
        "tests.test_mod::test_fail": CaseResult(
            "tests.test_mod::test_fail", "failed", 0.25, "assert 1 == 2"
        ),
        "tests.test_mod::test_skip": CaseResult(
            "tests.test_mod::test_skip", "skipped", 0.0, "needs network"
        ),
        "tests.test_broken": CaseResult(
            "tests.test_broken", "error", None, "ImportError while importing test module"
        ),
        "tests.test_mod.TestA::test_param[1-2]": CaseResult(
            "tests.test_mod.TestA::test_param[1-2]", "error", 0.01, "error in teardown"
        ),
        "tests.test_mod::test_output": CaseResult(
            "tests.test_mod::test_output", "passed", None, ""
        ),
    }


@pytest.mark.parametrize(
    "report",
    [
        b'<?xml version="1.0"?><!DOCTYPE t [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]>'
        b"<testsuites>&b;</testsuites>",
        b'<!DOCTYPE t SYSTEM "file:///etc/passwd"><testsuites/>',
        b"<testsuites>&undefined;</testsuites>",
        b"<testsuites><testcase name='x'></testsuites>",
        b"<testsuites><testcase classname='' name=''/></testsuites>",
    ],
)
def test_junit_reports_with_declarations_or_bad_markup_are_refused(report: bytes) -> None:
    with pytest.raises(SuiteReportError):
        parse_report("pytest", report)


def test_jest_and_vitest_reports_name_tests_by_file_and_full_name() -> None:
    report = {
        "testResults": [
            {
                "name": "/workspace/src/sum.test.js",
                "status": "failed",
                "assertionResults": [
                    {
                        "ancestorTitles": ["sum"],
                        "title": "adds",
                        "fullName": "sum adds",
                        "status": "passed",
                        "duration": 12,
                        "failureMessages": [],
                    },
                    {
                        "ancestorTitles": ["sum"],
                        "title": "overflows",
                        "status": "failed",
                        "duration": None,
                        "failureMessages": ["Error: expected 2", "  at sum.test.js:9"],
                    },
                    {"title": "later", "fullName": "later", "status": "todo"},
                    {"title": "odd", "fullName": "odd", "status": "focused"},
                ],
            },
            {
                "name": "/workspace/src/broken.test.js",
                "status": "failed",
                "message": "SyntaxError: Unexpected token",
                "assertionResults": [],
            },
        ]
    }

    for framework in ("jest", "vitest"):
        results = parse_report(framework, json.dumps(report).encode())
        assert results == {
            "src/sum.test.js::sum adds": CaseResult(
                "src/sum.test.js::sum adds", "passed", 0.012, ""
            ),
            "src/sum.test.js::sum overflows": CaseResult(
                "src/sum.test.js::sum overflows",
                "failed",
                None,
                "Error: expected 2\n  at sum.test.js:9",
            ),
            "src/sum.test.js::later": CaseResult("src/sum.test.js::later", "skipped", None, ""),
            "src/broken.test.js": CaseResult(
                "src/broken.test.js", "error", None, "SyntaxError: Unexpected token"
            ),
        }


def test_mocha_reports_count_hook_failures_as_errors() -> None:
    report = {
        "stats": {"tests": 3},
        "passes": [{"title": "works", "fullTitle": "app works", "file": "/workspace/test/app.js"}],
        "pending": [{"title": "later", "fullTitle": "app later", "file": "/workspace/test/app.js"}],
        "failures": [
            {
                "title": "breaks",
                "fullTitle": "app breaks",
                "file": "/workspace/test/app.js",
                "duration": 3,
                "err": {"message": "expected 1 to equal 2"},
            },
            {
                "title": '"before all" hook for "works"',
                "fullTitle": 'db "before all" hook for "works"',
                "err": {"message": "connect ECONNREFUSED"},
            },
        ],
    }

    results = parse_report("mocha", json.dumps(report).encode())

    assert results["test/app.js::app works"].status == "passed"
    assert results["test/app.js::app later"].status == "skipped"
    assert results["test/app.js::app breaks"] == CaseResult(
        "test/app.js::app breaks", "failed", 0.003, "expected 1 to equal 2"
    )
    assert results['db "before all" hook for "works"'].status == "error"


def test_go_test_events_give_per_test_results_and_package_failures() -> None:
    events = [
        {"Action": "start", "Package": "example.com/m/a"},
        {"Action": "run", "Package": "example.com/m/a", "Test": "TestOK"},
        {"Action": "pass", "Package": "example.com/m/a", "Test": "TestOK", "Elapsed": 0.01},
        {"Action": "run", "Package": "example.com/m/a", "Test": "TestBad"},
        {"Action": "output", "Package": "example.com/m/a", "Test": "TestBad", "Output": "a.go:9:"},
        {"Action": "output", "Package": "example.com/m/a", "Test": "TestBad", "Output": " no\n"},
        {"Action": "fail", "Package": "example.com/m/a", "Test": "TestBad", "Elapsed": 0.02},
        {"Action": "run", "Package": "example.com/m/a", "Test": "TestBad/sub"},
        {"Action": "skip", "Package": "example.com/m/a", "Test": "TestBad/sub", "Elapsed": 0},
        {"Action": "fail", "Package": "example.com/m/a", "Elapsed": 0.05},
        {"Action": "run", "Package": "example.com/m/b", "Test": "TestCrash"},
        {"Action": "output", "Package": "example.com/m/b", "Output": "panic: boom\n"},
        {"Action": "fail", "Package": "example.com/m/b", "Elapsed": 0.1},
        {"Action": "output", "Package": "example.com/m/c", "Output": "# example.com/m/c\n"},
        {"Action": "fail", "Package": "example.com/m/c", "Elapsed": 0},
        {"Action": "skip", "Package": "example.com/m/d", "Elapsed": 0},
    ]
    report = b"\n".join(json.dumps(event).encode() for event in events) + b"\nnot json\n"

    results = parse_report("go", report)

    assert results == {
        "example.com/m/a::TestOK": CaseResult("example.com/m/a::TestOK", "passed", 0.01, ""),
        "example.com/m/a::TestBad": CaseResult(
            "example.com/m/a::TestBad", "failed", 0.02, "a.go:9: no"
        ),
        "example.com/m/a::TestBad/sub": CaseResult(
            "example.com/m/a::TestBad/sub", "skipped", 0.0, ""
        ),
        "example.com/m/b::TestCrash": CaseResult(
            "example.com/m/b::TestCrash", "error", None, "the test did not finish"
        ),
        "example.com/m/c": CaseResult("example.com/m/c", "error", 0.0, "# example.com/m/c"),
    }


def test_libtest_output_gives_results_and_failure_output_across_binaries() -> None:
    report = b"""
running 3 tests
test tests::adds ... ok
test tests::panics - should panic ... ok
test tests::breaks ... FAILED
test tests::slow ... ignored, needs a network

failures:

---- tests::breaks stdout ----
thread 'tests::breaks' panicked at src/lib.rs:9:5:
assertion `left == right` failed

failures:
    tests::breaks

test result: FAILED. 2 passed; 1 failed; 1 ignored; 0 measured; 0 filtered out

running 1 test
test tests::adds ... FAILED
test src/lib.rs - add (line 3) ... ok
"""

    results = parse_report("cargo", report)

    assert results == {
        "tests::adds": CaseResult("tests::adds", "failed", None, ""),
        "tests::panics": CaseResult("tests::panics", "passed", None, ""),
        "tests::breaks": CaseResult(
            "tests::breaks",
            "failed",
            None,
            "thread 'tests::breaks' panicked at src/lib.rs:9:5:\nassertion `left == right` failed",
        ),
        "tests::slow": CaseResult("tests::slow", "skipped", None, ""),
        "src/lib.rs - add (line 3)": CaseResult("src/lib.rs - add (line 3)", "passed", None, ""),
    }


@pytest.mark.parametrize(
    ("framework", "report", "message"),
    [
        ("unittest", b"", "no per-test report"),
        ("other", b"", "no per-test report"),
        ("jest", b"[]", "not an object"),
        ("mocha", b"{", "malformed"),
        ("vitest", b"[" * 100_000 + b"]" * 100_000, "malformed"),
    ],
)
def test_unsupported_or_malformed_reports_are_refused(
    framework: TestFramework, report: bytes, message: str
) -> None:
    with pytest.raises(SuiteReportError, match=message):
        parse_report(framework, report)


def test_reports_over_the_size_or_test_limit_are_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(suite_results, "MAX_REPORT_BYTES", 10)
    with pytest.raises(SuiteReportError, match="exceeds"):
        parse_report("cargo", b"test a ... ok\n")

    monkeypatch.setattr(suite_results, "MAX_REPORT_BYTES", 1_000)
    monkeypatch.setattr(suite_results, "_MAX_TESTS", 2)
    with pytest.raises(SuiteReportError, match="more than 2 tests"):
        parse_report("cargo", b"test a ... ok\ntest b ... ok\ntest c ... ok\n")
    assert len(parse_report("cargo", b"test a ... ok\ntest b ... ok\ntest a ... ok\n")) == 2
