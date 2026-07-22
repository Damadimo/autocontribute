"""Deterministic, bounded context expansion around an issue and proposed change."""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from pathlib import PurePosixPath

from autocontribute.domain import ContributionPlan, IssueCandidate
from autocontribute.redaction import redact_model_input, truncate_artifact
from autocontribute.repository import TextMatch

_CODE_SPAN = re.compile(r"`([^`\n]{3,100})`")
_TERM = re.compile(r"\b[A-Za-z_][A-Za-z0-9_.:-]{3,99}\b")
_STOP_WORDS = {
    "about",
    "actual",
    "after",
    "before",
    "behavior",
    "change",
    "could",
    "documented",
    "expected",
    "issue",
    "please",
    "project",
    "repository",
    "should",
    "tests",
    "their",
    "there",
    "these",
    "this",
    "value",
    "where",
    "which",
    "would",
}


def issue_search_queries(issue: IssueCandidate, *, limit: int = 12) -> list[str]:
    """Extract conservative literal search terms without involving a model or regex input."""

    if not 1 <= limit <= 20:
        raise ValueError("search query limit must be between 1 and 20")
    text = f"{issue.title}\n{issue.body}"
    candidates = [*(_CODE_SPAN.findall(text)), *(_TERM.findall(text))]
    return _unique_queries(candidates, limit=limit)


def plan_search_queries(
    issue: IssueCandidate,
    plan: ContributionPlan,
    *,
    limit: int = 20,
) -> list[str]:
    """Add plan-derived symbols and path stems to the issue's literal search terms."""

    if not 1 <= limit <= 20:
        raise ValueError("search query limit must be between 1 and 20")
    values: list[str] = issue_search_queries(issue, limit=min(12, limit))
    plan_text = "\n".join(
        [
            plan.issue_understanding,
            *plan.acceptance_criteria,
            *plan.implementation_steps,
        ]
    )
    values.extend(_CODE_SPAN.findall(plan_text))
    values.extend(_TERM.findall(plan_text))
    for path in plan.files_to_read:
        pure_path = PurePosixPath(path)
        values.extend(part for part in pure_path.stem.split("_") if len(part) >= 4)
    return _unique_queries(values, limit=limit)


def rank_matching_paths(
    matches: Sequence[TextMatch],
    *,
    exclude: Iterable[str] = (),
    limit: int = 8,
) -> list[str]:
    """Rank callers, tests, and configuration paths represented in bounded search results."""

    if limit < 1:
        raise ValueError("matching path limit must be positive")
    excluded = {path.casefold() for path in exclude}
    queries_by_path: dict[str, set[str]] = {}
    canonical: dict[str, str] = {}
    for match in matches:
        folded = match.path.casefold()
        if folded in excluded:
            continue
        canonical.setdefault(folded, match.path)
        queries_by_path.setdefault(folded, set()).add(match.query.casefold())

    def score(path: str) -> tuple[int, int, int, str]:
        name = PurePosixPath(path).name
        test_boost = 1 if "test" in path or name.startswith("spec") else 0
        config_boost = 1 if name.startswith(("config", "pyproject", "package")) else 0
        return (
            -len(queries_by_path[path]),
            -test_boost,
            -config_boost,
            canonical[path],
        )

    ranked = sorted(canonical, key=score)
    return [canonical[path] for path in ranked[:limit]]


def render_text_matches(matches: Sequence[TextMatch], *, max_characters: int = 30_000) -> str:
    """Render bounded reference evidence for an untrusted prompt section."""

    if max_characters < 1:
        raise ValueError("match rendering limit must be positive")
    lines = []
    for match in matches:
        safe_query = redact_model_input(match.query)
        safe_line = redact_model_input(match.line, source_path=match.path)
        lines.append(f"{match.path}:{match.line_number}\tquery={safe_query!r}\t{safe_line}")
    return truncate_artifact("\n".join(lines), limit=max_characters)


def _unique_queries(values: Iterable[str], *, limit: int) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for raw in values:
        value = " ".join(raw.strip().split())
        folded = value.casefold()
        if (
            not value
            or len(value) > 100
            or folded in _STOP_WORDS
            or folded in seen
            or (" " in value and not any(character in value for character in "_.:-/"))
        ):
            continue
        seen.add(folded)
        result.append(value)
        if len(result) >= limit:
            break
    return result


__all__ = [
    "issue_search_queries",
    "plan_search_queries",
    "rank_matching_paths",
    "render_text_matches",
]
