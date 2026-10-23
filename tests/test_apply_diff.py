from __future__ import annotations

import pytest

from autocontribute.apply_diff import apply_diff


def test_create_mode_takes_the_added_lines() -> None:
    assert apply_diff("", "+first\n+second\n", mode="create") == "first\nsecond"


def test_create_mode_rejects_lines_without_a_plus() -> None:
    with pytest.raises(ValueError, match="Invalid Add File Line"):
        apply_diff("", "+first\nsecond\n", mode="create")


def test_update_replaces_lines_located_by_context_and_anchor() -> None:
    source = "def first():\n    return 1\n\n\ndef second():\n    return 1\n"
    diff = "@@ def second():\n-    return 1\n+    return 2\n"

    assert apply_diff(source, diff) == (
        "def first():\n    return 1\n\n\ndef second():\n    return 2\n"
    )


def test_update_keeps_crlf_line_endings() -> None:
    source = "alpha\r\nbeta\r\ngamma\r\n"
    diff = " alpha\n-beta\n+BETA\n gamma\n"

    assert apply_diff(source, diff) == "alpha\r\nBETA\r\ngamma\r\n"


def test_update_with_unknown_context_reports_invalid_context() -> None:
    with pytest.raises(ValueError, match="Invalid Context"):
        apply_diff("alpha\nbeta\n", " missing\n-beta\n+BETA\n")


def test_end_of_file_hunk_appends_after_the_last_line() -> None:
    diff = " beta\n+gamma\n*** End of File\n"

    assert apply_diff("alpha\nbeta\n", diff) == "alpha\nbeta\ngamma\n"
