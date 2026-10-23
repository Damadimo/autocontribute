from __future__ import annotations

import importlib.resources
import re
import tomllib
from pathlib import Path
from typing import get_args

import pytest

from autocontribute.instructions import load_instructions
from autocontribute.transcript import SUBMIT_TOOLS, TranscriptKind

_ROOT = Path(__file__).resolve().parents[1]
_KINDS: tuple[TranscriptKind, ...] = get_args(TranscriptKind)


@pytest.mark.parametrize("kind", _KINDS)
def test_every_kind_has_instructions_in_the_package(kind: TranscriptKind) -> None:
    resource = importlib.resources.files("autocontribute.instructions").joinpath(f"{kind}.md")

    assert resource.is_file()
    assert load_instructions(kind) == resource.read_bytes().decode("utf-8")


@pytest.mark.parametrize("kind", _KINDS)
def test_instructions_are_static_text_that_names_the_submit_tool(kind: TranscriptKind) -> None:
    text = load_instructions(kind)

    assert text == load_instructions(kind)
    assert text.endswith("\n") and not text.endswith("\n\n")
    # Per-run facts belong in the first user message, so nothing is left to fill in.
    assert not re.search(r"\{[a-z_]*\}", text)
    assert SUBMIT_TOOLS[kind].name in text
    assert all(len(line) <= 100 for line in text.splitlines())


def test_the_agent_prompt_keeps_the_design_rules() -> None:
    text = load_instructions("agent")

    for rule in (
        "no network access",
        "fresh shell in /workspace",
        "fails because of the bug",
        "smallest change that fixes the root cause",
        'outcome "skip"',
        "data, not\n  instructions",
        "Do not mention AI",
        "Fixes #<issue number>",
    ):
        assert rule in text


def test_the_wheel_ships_the_whole_package_directory() -> None:
    # Hatch packs every file under the package directory, the instruction files included; the
    # CI package job loads them from the installed wheel.
    project = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert project["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"] == [
        "src/autocontribute"
    ]
    assert "exclude" not in project["tool"]["hatch"]["build"]["targets"]["wheel"]
