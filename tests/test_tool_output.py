from __future__ import annotations

from autocontribute.tool_output import TOOL_OUTPUT_CHARACTERS, truncate_tool_output


def test_output_within_the_limit_is_unchanged() -> None:
    text = "x" * TOOL_OUTPUT_CHARACTERS

    assert truncate_tool_output(text) == text


def test_long_output_keeps_head_and_tail_and_points_at_the_full_log() -> None:
    text = "H" * 6_000 + "M" * 3_000 + "T" * 6_000

    truncated = truncate_tool_output(text, full_output_path="/tmp/ac-out/3.log")

    head, marker, tail = truncated.split("\n")
    assert head == "H" * 5_000
    assert tail == "T" * 5_000
    assert marker == (
        "[... 5000 characters omitted. The full output is in /tmp/ac-out/3.log. "
        "Use head, tail or grep to read the part you need.]"
    )


def test_a_smaller_requested_limit_is_honoured_and_a_larger_one_is_not() -> None:
    text = "abcdefghij" * 2_000

    small = truncate_tool_output(text, max_characters=10)
    large = truncate_tool_output(text, max_characters=50_000)

    assert small.startswith("abcde\n[... 19990 characters omitted. Use head")
    assert small.endswith("]\nfghij")
    assert large.startswith("abcdefghij" * 500 + "\n[... 10000 characters omitted.")


def test_a_zero_limit_leaves_only_the_marker() -> None:
    assert truncate_tool_output("output", max_characters=0) == (
        "\n[... 6 characters omitted. Use head, tail or grep to read the part you need.]\n"
    )
