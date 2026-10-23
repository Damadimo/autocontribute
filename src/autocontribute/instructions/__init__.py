"""System prompts for each kind of transcript, shipped as package data.

A transcript replays its instructions on every request, so they stay byte-stable for the whole
run: no timestamps, budgets or counters. Per-run facts go in the first user message.
"""

from __future__ import annotations

import importlib.resources

from autocontribute.transcript import TranscriptKind


def load_instructions(kind: TranscriptKind) -> str:
    """Return the system prompt of a kind of transcript, such as ``agent``."""

    resource = importlib.resources.files(__name__).joinpath(f"{kind}.md")
    return resource.read_text(encoding="utf-8")


__all__ = ["load_instructions"]
