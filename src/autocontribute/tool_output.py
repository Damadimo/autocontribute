"""Bounded tool output for agent transcripts."""

from __future__ import annotations

from typing import Final

TOOL_OUTPUT_CHARACTERS: Final = 10_000


def truncate_tool_output(
    text: str,
    *,
    max_characters: int | None = None,
    full_output_path: str | None = None,
) -> str:
    """Keep the head and tail of output over the limit, with a marker line between them.

    The limit is 10,000 characters, or a smaller ``max_characters`` the model asked for
    (the OpenAI shell tool's ``max_output_length``). ``full_output_path`` is where
    ``SessionContainer.save_output`` left the whole output; the marker points the agent at
    it so a slow command need not run again.
    """

    limit = TOOL_OUTPUT_CHARACTERS
    if max_characters is not None:
        limit = max(0, min(limit, max_characters))
    if len(text) <= limit:
        return text
    head = limit // 2
    tail = limit - head
    location = f" The full output is in {full_output_path}." if full_output_path else ""
    marker = (
        f"\n[... {len(text) - limit} characters omitted.{location} Use head, tail or grep "
        "to read the part you need.]\n"
    )
    return f"{text[:head]}{marker}{text[len(text) - tail :]}"


__all__ = ["TOOL_OUTPUT_CHARACTERS", "truncate_tool_output"]
