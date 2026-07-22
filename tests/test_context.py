from datetime import UTC, datetime

from autocontribute.context import (
    issue_search_queries,
    plan_search_queries,
    rank_matching_paths,
    render_text_matches,
)
from autocontribute.domain import ContributionPlan, IssueCandidate
from autocontribute.redaction import SENSITIVE_FILE_REDACTION
from autocontribute.repository import TextMatch


def _issue() -> IssueCandidate:
    now = datetime(2026, 7, 21, tzinfo=UTC)
    return IssueCandidate(
        repository="example/project",
        number=42,
        title="parse_document drops nested metadata",
        body="Calling `parse_document` should preserve `metadata_map` at the boundary.",
        html_url="https://github.com/example/project/issues/42",
        state="open",
        author="maintainer",
        labels=["bug"],
        assignees=[],
        comments=0,
        created_at=now,
        updated_at=now,
    )


def _plan() -> ContributionPlan:
    return ContributionPlan(
        decision="proceed",
        decision_reason="Narrow regression.",
        contribution_kind="bugfix",
        issue_understanding="Preserve metadata_map in parse_document.",
        acceptance_criteria=["parse_document returns nested metadata_map"],
        implementation_steps=["Update DocumentParser", "Add a regression"],
        files_to_read=["src/document_parser.py"],
        reproduction_command="python -m pytest tests/test_document_parser.py",
        validation_commands=["python -m pytest tests/test_document_parser.py"],
        risks=[],
        maintainer_fit="Direct fix.",
    )


def test_queries_prioritize_code_spans_and_deduplicate() -> None:
    queries = issue_search_queries(_issue())

    assert queries[:2] == ["parse_document", "metadata_map"]
    assert queries.count("parse_document") == 1
    assert "should" not in queries


def test_plan_queries_include_derived_symbol_and_path_terms() -> None:
    queries = plan_search_queries(_issue(), _plan())

    assert "DocumentParser" in queries
    assert "document" in queries
    assert len(queries) <= 20


def test_matching_paths_prioritize_tests_then_render_bounded_evidence() -> None:
    matches = [
        TextMatch("parse_document", "src/parser.py", 2, "def parse_document():"),
        TextMatch("metadata_map", "src/parser.py", 3, "metadata_map = {}"),
        TextMatch("parse_document", "tests/test_parser.py", 8, "parse_document(value)"),
        TextMatch("parse_document", "src/ignored.py", 1, "parse_document(value)"),
    ]

    ranked = rank_matching_paths(matches, exclude=["src/parser.py"], limit=2)

    assert ranked == ["tests/test_parser.py", "src/ignored.py"]
    rendered = render_text_matches(matches, max_characters=100)
    assert "src/parser.py:2" in rendered
    assert len(rendered) <= 130


def test_rendered_search_evidence_withholds_sensitive_file_lines() -> None:
    rendered = render_text_matches(
        [TextMatch("password", ".env.production", 1, "PASSWORD=live-value-123456")]
    )

    assert ".env.production:1" in rendered
    assert SENSITIVE_FILE_REDACTION in rendered
    assert "live-value-123456" not in rendered
