from __future__ import annotations

import copy
from collections.abc import Iterator
from typing import Any

import pytest
from anthropic.lib._parse._transform import transform_schema
from openai.lib._pydantic import _ensure_strict_json_schema
from pydantic import BaseModel, Field, ValidationError

from autocontribute.submissions import (
    AgentSubmission,
    PolicySubmission,
    ReviewBlocker,
    ReviewSubmission,
    SetupSubmission,
    TriageSubmission,
    strict_json_schema,
)

_SUBMISSIONS = (
    AgentSubmission,
    SetupSubmission,
    ReviewSubmission,
    TriageSubmission,
    PolicySubmission,
)
_BOUND_KEYWORDS = {
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "multipleOf",
    "minLength",
    "maxLength",
    "minItems",
    "maxItems",
}


def _schemas(schema: dict[str, Any]) -> Iterator[dict[str, Any]]:
    yield schema
    for property_schema in schema.get("properties", {}).values():
        yield from _schemas(property_schema)
    if "items" in schema:
        yield from _schemas(schema["items"])
    for variant in schema.get("anyOf", []):
        yield from _schemas(variant)


def _fixed(**overrides: object) -> dict[str, object]:
    arguments: dict[str, object] = {
        "outcome": "fixed",
        "skip_reason": None,
        "summary": "Parsing dropped the last field; it now keeps it.",
        "pr_title": "Keep the last field when parsing",
        "pr_body": "Fixes #12.\n\nThe loop stopped one field early.",
        "commit_message": "Keep the last field when parsing",
        "test_files": ["tests/test_parse.py"],
        "test_command": "python -m pytest tests/test_parse.py",
    }
    return {**arguments, **overrides}


@pytest.mark.parametrize("model", _SUBMISSIONS, ids=lambda model: model.__name__)
def test_every_object_is_closed_and_requires_every_property(model: type[BaseModel]) -> None:
    schema = strict_json_schema(model)

    objects = [node for node in _schemas(schema) if node.get("type") == "object"]
    assert objects
    for node in objects:
        assert node["additionalProperties"] is False
        assert node["required"] == list(node["properties"])


@pytest.mark.parametrize("model", _SUBMISSIONS, ids=lambda model: model.__name__)
def test_schema_has_no_bounds_references_titles_or_defaults(model: type[BaseModel]) -> None:
    schema = strict_json_schema(model)

    for node in _schemas(schema):
        assert not _BOUND_KEYWORDS & node.keys()
        assert not {"$ref", "$defs", "title", "default"} & node.keys()


@pytest.mark.parametrize("model", _SUBMISSIONS, ids=lambda model: model.__name__)
def test_both_sdks_strict_normalizers_leave_the_schema_unchanged(
    model: type[BaseModel],
) -> None:
    # Each SDK rewrites a schema its API would not accept in strict mode; Anthropic's moves
    # unsupported keywords into descriptions. An unchanged schema is accepted as sent.
    schema = strict_json_schema(model)
    openai_copy = copy.deepcopy(schema)

    assert _ensure_strict_json_schema(openai_copy, path=(), root=openai_copy) == schema
    assert transform_schema(copy.deepcopy(schema)) == schema


def test_optional_values_are_nullable_unions() -> None:
    properties = strict_json_schema(AgentSubmission)["properties"]
    assert isinstance(properties, dict)

    assert properties["skip_reason"] == {
        "anyOf": [{"type": "string"}, {"type": "null"}],
        "description": "Why the issue is skipped; null when fixed.",
    }


def test_nested_models_are_inlined_without_their_docstrings() -> None:
    schema: dict[str, Any] = strict_json_schema(ReviewSubmission)
    blocker = schema["properties"]["blockers"]["items"]

    assert blocker["required"] == list(ReviewBlocker.model_fields)
    assert "description" not in blocker
    assert "description" not in schema


def test_property_names_that_match_dropped_keywords_are_kept() -> None:
    class Entry(BaseModel):
        title: str
        default: int | None = Field(default=None, ge=0)

    schema = strict_json_schema(Entry)

    assert schema["required"] == ["title", "default"]
    assert schema["properties"] == {
        "title": {"type": "string"},
        "default": {"anyOf": [{"type": "integer"}, {"type": "null"}]},
    }


def test_agent_fix_validates() -> None:
    submission = AgentSubmission.model_validate(_fixed())

    assert submission.outcome == "fixed"
    assert submission.test_files == ["tests/test_parse.py"]


@pytest.mark.parametrize("field", ["pr_title", "pr_body", "commit_message"])
@pytest.mark.parametrize("value", [None, "  "])
def test_agent_fix_needs_its_pull_request_text(field: str, value: str | None) -> None:
    with pytest.raises(ValidationError, match=f"outcome fixed needs {field}"):
        AgentSubmission.model_validate(_fixed(**{field: value}))


def test_agent_skip_needs_a_reason() -> None:
    skip = _fixed(outcome="skip", pr_title=None, pr_body=None, commit_message=None)

    assert AgentSubmission.model_validate({**skip, "skip_reason": "Already fixed."})
    with pytest.raises(ValidationError, match="outcome skip needs a skip_reason"):
        AgentSubmission.model_validate(skip)


@pytest.mark.parametrize(
    ("commit_message", "error"),
    [
        ("Keep the last field\n\nThe loop stopped early.", "single line"),
        ("x" * 201, "at most 200 characters"),
    ],
)
def test_agent_commit_message_is_one_bounded_line(commit_message: str, error: str) -> None:
    with pytest.raises(ValidationError, match=error):
        AgentSubmission.model_validate(_fixed(commit_message=commit_message))


def test_agent_submission_rejects_unknown_and_missing_fields() -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        AgentSubmission.model_validate(_fixed(notes="unexpected"))
    arguments = _fixed()
    del arguments["test_command"]
    with pytest.raises(ValidationError, match="test_command"):
        AgentSubmission.model_validate(arguments)


def test_review_blocker_line_keeps_its_bound_after_the_schema_drops_it() -> None:
    blocker = {
        "category": "regression",
        "path": "src/parse.py",
        "line": 0,
        "evidence": "tests/test_cli.py::test_empty fails after the change.",
        "check_command": "python -m pytest tests/test_cli.py::test_empty",
        "fix_hint": "Keep the empty-input branch.",
    }
    review = {
        "verdict": "request_changes",
        "blockers": [blocker],
        "notes": [],
        "no_test_needed": False,
        "summary": "The change breaks empty input.",
    }

    with pytest.raises(ValidationError, match="greater than or equal to 1"):
        ReviewSubmission.model_validate(review)
    assert ReviewSubmission.model_validate({**review, "blockers": [{**blocker, "line": 4}]})


def test_setup_needs_an_image_and_a_test_command() -> None:
    recipe = {
        "base_image": "python:3.12-bookworm",
        "system_packages": [],
        "setup_commands": ["pip install -e .[test]"],
        "build_commands": [],
        "test_command": "",
        "test_framework": "pytest",
    }

    with pytest.raises(ValidationError, match="test_command"):
        SetupSubmission.model_validate(recipe)
    assert SetupSubmission.model_validate({**recipe, "test_command": "python -m pytest -q"})


def test_triage_and_policy_submissions_validate() -> None:
    triage = TriageSubmission.model_validate(
        {
            "suitable": True,
            "reasons": ["Reproduction and expected output are given."],
            "already_fixed": False,
            "needs_design": False,
            "difficulty": "small",
        }
    )
    policy = PolicySubmission.model_validate(
        {
            "stance": "conditional",
            "requires_disclosure": True,
            "disclosure_requirements": ["Add an Assisted-by trailer."],
            "requires_human_written_text": False,
            "quotes": ["AI-assisted contributions must be disclosed."],
        }
    )

    assert triage.difficulty == "small"
    assert policy.stance == "conditional"
