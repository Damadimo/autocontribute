"""Arguments of the submit tools that end each transcript, and their strict JSON schemas.

Strict tool mode on both providers rejects numeric and length bounds and needs every property to
be required. The schemas therefore leave the bounds out, and the parent re-validates every call
with these models; a call that fails validation goes back to the model as an error tool result.
"""

from __future__ import annotations

from typing import Any, Final, Literal

from pydantic import BaseModel, Field, JsonValue, model_validator

from autocontribute.domain import DomainModel

# Keywords strict tool schemas reject, plus titles and defaults, which only cost tokens.
_DROPPED_KEYWORDS: Final = frozenset(
    {
        "title",
        "default",
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
)
_DEFINITION_PREFIX: Final = "#/$defs/"

TestFramework = Literal["pytest", "unittest", "jest", "vitest", "mocha", "go", "cargo", "other"]
BlockerCategory = Literal[
    "issue_not_fixed",
    "regression",
    "definite_bug",
    "weak_test",
    "scope_creep",
    "policy_violation",
    "misleading_text",
    "risky_change",
]


class AgentSubmission(DomainModel):
    """The solver's final answer: a finished fix, or a reason to skip the issue."""

    outcome: Literal["fixed", "skip"]
    skip_reason: str | None = Field(description="Why the issue is skipped; null when fixed.")
    summary: str = Field(
        min_length=1, description="What was wrong and what changed, for the reviewer."
    )
    pr_title: str | None = Field(description="Pull request title; null when skipping.")
    pr_body: str | None = Field(
        description=(
            "Pull request body without a testing note or AI disclosure, which are added for "
            "you; null when skipping."
        )
    )
    commit_message: str | None = Field(
        max_length=200,
        description="One line, at most 72 characters preferred; null when skipping.",
    )
    test_files: list[str] = Field(
        description="Repository paths of the tests added or changed for this issue."
    )
    test_command: str | None = Field(
        description="Command that runs those tests in this environment; null if there are none."
    )

    @model_validator(mode="after")
    def outcome_has_its_fields(self) -> AgentSubmission:
        if self.outcome == "skip" and not (self.skip_reason or "").strip():
            raise ValueError("outcome skip needs a skip_reason")
        if self.outcome == "fixed":
            missing = [
                name
                for name, value in (
                    ("pr_title", self.pr_title),
                    ("pr_body", self.pr_body),
                    ("commit_message", self.commit_message),
                )
                if not (value or "").strip()
            ]
            if missing:
                raise ValueError(f"outcome fixed needs {', '.join(missing)}")
        if self.commit_message is not None and "\n" in self.commit_message.strip():
            raise ValueError("commit_message must be a single line")
        return self


class SetupSubmission(DomainModel):
    """The setup agent's recipe; the controller replays it from scratch before trusting it."""

    base_image: str = Field(
        min_length=1, description="Docker base image, for example python:3.12-bookworm."
    )
    system_packages: list[str] = Field(
        description="apt packages to install as root before the setup commands."
    )
    setup_commands: list[str] = Field(
        description="Commands that install the project and its test dependencies, with network."
    )
    build_commands: list[str] = Field(
        description="Commands run offline before every test run; often empty."
    )
    test_command: str = Field(
        min_length=1,
        description="Offline command that runs the full test suite, or the closest equivalent.",
    )
    test_framework: TestFramework


class ReviewBlocker(DomainModel):
    category: BlockerCategory
    path: str | None = Field(description="Repository path the blocker is about; null if none.")
    line: int | None = Field(ge=1, description="Line number in path; null if none.")
    evidence: str = Field(
        min_length=1, description="What you observed, quoting the code or command output."
    )
    check_command: str | None = Field(
        description="Command that fails while the blocker holds; null if there is none."
    )
    fix_hint: str = Field(description="What the author should change.")


class ReviewSubmission(DomainModel):
    """The critic's verdict on one prepared change."""

    verdict: Literal["approve", "request_changes", "abandon"]
    blockers: list[ReviewBlocker] = Field(
        description="Problems that must be fixed before a maintainer would merge the change."
    )
    notes: list[str] = Field(description="Observations that do not block the change.")
    no_test_needed: bool = Field(
        description="True if the change needs no new test, for example a docs or typing fix."
    )
    summary: str = Field(min_length=1, description="One paragraph for the human reviewer.")


class TriageSubmission(DomainModel):
    """The triage model's assessment of one candidate issue."""

    suitable: bool
    reasons: list[str] = Field(description="Short reasons for the assessment.")
    already_fixed: bool = Field(
        description="True if the default branch or an open pull request already fixes the issue."
    )
    needs_design: bool = Field(
        description="True if maintainers must first decide what the expected behaviour is."
    )
    difficulty: Literal["small", "medium", "large"]


class PolicySubmission(DomainModel):
    """A repository's stance on AI-assisted contributions, with the quotes that support it."""

    stance: Literal["ban", "conditional", "permissive", "none"] = Field(
        description=(
            "ban: AI-assisted contributions are not accepted; conditional: accepted under "
            "stated conditions; permissive: explicitly allowed; none: the files do not say."
        )
    )
    requires_disclosure: bool = Field(
        description="True if contributors must disclose AI assistance."
    )
    disclosure_requirements: list[str] = Field(
        description="Each disclosure requirement, in the policy's own words."
    )
    requires_human_written_text: bool = Field(
        description="True if pull request text or comments must be written by a human."
    )
    quotes: list[str] = Field(
        description="Verbatim sentences from the policy files that support the classification."
    )


def strict_json_schema(model: type[BaseModel]) -> dict[str, JsonValue]:
    """Return ``model``'s JSON schema in the form OpenAI and Anthropic strict tools accept."""

    schema = model.model_json_schema()
    # Class docstrings document the code; the tool's own description is what the model reads.
    schema.pop("description", None)
    definitions = {
        name: {keyword: value for keyword, value in definition.items() if keyword != "description"}
        for name, definition in schema.pop("$defs", {}).items()
    }
    return _strict(schema, definitions)


def _strict(schema: dict[str, Any], definitions: dict[str, Any]) -> dict[str, JsonValue]:
    reference = schema.get("$ref")
    if isinstance(reference, str):
        # OpenAI rejects keywords beside a $ref, so references are inlined; none is recursive.
        sibling_keywords = {key: value for key, value in schema.items() if key != "$ref"}
        schema = {**definitions[reference.removeprefix(_DEFINITION_PREFIX)], **sibling_keywords}
    strict: dict[str, JsonValue] = {}
    for keyword, value in schema.items():
        if keyword in _DROPPED_KEYWORDS:
            continue
        if keyword == "properties":
            strict[keyword] = {
                name: _strict(property_schema, definitions)
                for name, property_schema in value.items()
            }
        elif keyword == "items":
            strict[keyword] = _strict(value, definitions)
        elif keyword == "anyOf":
            strict[keyword] = [_strict(variant, definitions) for variant in value]
        else:
            strict[keyword] = value
    if strict.get("type") == "object":
        strict["additionalProperties"] = False
        strict["required"] = list(schema.get("properties", {}))
    return strict


__all__ = [
    "AgentSubmission",
    "BlockerCategory",
    "PolicySubmission",
    "ReviewBlocker",
    "ReviewSubmission",
    "SetupSubmission",
    "TestFramework",
    "TriageSubmission",
    "strict_json_schema",
]
