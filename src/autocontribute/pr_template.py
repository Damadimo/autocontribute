"""Deterministic checks for repository-owned pull-request templates."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Mapping
from pathlib import PurePosixPath

from autocontribute.exceptions import PolicyError

_HEADING = re.compile(r"^\s{0,3}#{1,6}\s+(?P<text>.+?)\s*#*\s*$", re.MULTILINE)
_TASK = re.compile(r"^\s*[-*+]\s+\[(?P<state>[ xX])\]\s+(?P<text>.+?)\s*$", re.MULTILINE)
_UNRESOLVED = re.compile(
    r"(?:\b(?:TODO|TBD|YOUR[ _-]TEXT[ _-]HERE)\b|"
    r"\[(?:describe|explain|insert|add)\b[^\]\n]{0,100}\]|"
    r"<(?:describe|explain|insert|add)\b[^>\n]{0,100}>)",
    re.IGNORECASE,
)
_FIRST_PERSON_ATTESTATION = re.compile(r"\b(?:i|i've|we|we've|my|our)\b", re.IGNORECASE)
_LEGAL_ATTESTATION = re.compile(
    r"\b(?:cla|contributor license agreement|dco|developer certificate of origin|"
    r"legal(?:ly)?|license rights?|copyright ownership|signed[- ]off|certif(?:y|ication)|"
    r"attest|declare|agree)\b",
    re.IGNORECASE,
)
_EXCLUSIVE_HEADING = re.compile(
    r"\b(?:(?:type|kind|category)\b.*\b(?:change|contribution|pull request|pr)\b|"
    r"(?:change|contribution|pull request|pr)\b.*\b(?:type|kind|category)\b)",
    re.IGNORECASE,
)
_CATEGORY_TASK = re.compile(
    r"^(?:bug\s*fix|fix|new\s+feature|feature|breaking\s+change|documentation|docs|"
    r"refactor(?:ing)?|performance|maintenance|chore|tests?|other)\b",
    re.IGNORECASE,
)
_DEFAULT_PATHS = (
    ".github/pull_request_template.md",
    "pull_request_template.md",
    "docs/pull_request_template.md",
)


def select_pull_request_template(guidance: Mapping[str, str]) -> tuple[str, str] | None:
    """Select the unambiguous GitHub PR template represented in bounded guidance."""

    candidates = {
        path: content
        for path, content in guidance.items()
        if _is_pull_request_template(path) and content.strip()
    }
    if not candidates:
        return None
    by_folded_path = {path.casefold(): (path, content) for path, content in candidates.items()}
    for default_path in _DEFAULT_PATHS:
        selected = by_folded_path.get(default_path)
        if selected is not None:
            return selected
    if len(candidates) == 1:
        return next(iter(candidates.items()))
    paths = ", ".join(sorted(candidates))
    raise PolicyError(
        "Repository exposes multiple pull-request templates without a canonical default; "
        f"configure a repository-specific template before publication: {paths}"
    )


def validate_pull_request_template(body: str, guidance: Mapping[str, str]) -> None:
    """Fail closed when a proposed body omits visible template structure.

    The final body must contain every visible template heading, every normalized checklist item in
    its completed form, and no unresolved task or common visible placeholder. Legal, manual, and
    ambiguous attestations are never completed automatically.
    """

    _validate_pull_request_template(body, guidance, allow_deferred_tasks=False)


def validate_pull_request_template_draft(body: str, guidance: Mapping[str, str]) -> None:
    """Validate a proposed final body before its automated checks have run.

    Required safe template tasks may remain unchecked at this stage. Their text must already be
    present, while legal/manual attestations, ambiguous choices, missing structure, placeholders,
    and unrelated incomplete tasks still fail closed.
    """

    _validate_pull_request_template(body, guidance, allow_deferred_tasks=True)


def complete_pull_request_template_tasks(body: str, guidance: Mapping[str, str]) -> str:
    """Complete exact required template tasks after deterministic validation has passed.

    Callers own the evidence gate. This function changes only visible unchecked tasks whose
    normalized text and multiplicity match the selected safe template, then applies the strict
    final validator. Hidden comments, fenced examples, and extra tasks are never changed.
    """

    validate_pull_request_template_draft(body, guidance)
    selected = select_pull_request_template(guidance)
    if selected is None:
        return body
    _, template = selected
    expected_tasks = list(_TASK.finditer(visible_markdown(template)))
    remaining = Counter(_normalize(match.group("text")) for match in expected_tasks)
    actual_tasks = list(_TASK.finditer(_visible_markdown_mask(body)))
    for match in actual_tasks:
        item = _normalize(match.group("text"))
        if match.group("state").casefold() == "x" and remaining[item] > 0:
            remaining[item] -= 1

    completed = list(body)
    for match in actual_tasks:
        item = _normalize(match.group("text"))
        if match.group("state") == " " and remaining[item] > 0:
            completed[match.start("state")] = "x"
            remaining[item] -= 1
    result = "".join(completed)
    validate_pull_request_template(result, guidance)
    return result


def _validate_pull_request_template(
    body: str,
    guidance: Mapping[str, str],
    *,
    allow_deferred_tasks: bool,
) -> None:
    selected = select_pull_request_template(guidance)
    if selected is None:
        return
    path, template = selected
    visible_template = visible_markdown(template)
    visible_body = visible_markdown(body)
    expected_headings = {
        _normalize(match.group("text")) for match in _HEADING.finditer(visible_template)
    }
    actual_headings = {_normalize(match.group("text")) for match in _HEADING.finditer(visible_body)}
    missing = sorted(heading for heading in expected_headings if heading not in actual_headings)
    if missing:
        raise PolicyError(
            f"Pull-request body does not complete {path}; missing template heading(s): "
            + ", ".join(missing)
        )

    expected_tasks = list(_TASK.finditer(visible_template))
    _validate_safe_template_tasks(path, visible_template, expected_tasks)
    actual_tasks = list(_TASK.finditer(visible_body))
    if expected_tasks and not actual_tasks:
        raise PolicyError(f"Pull-request body omits the checklist required by {path}")
    expected_items = Counter(_normalize(match.group("text")) for match in expected_tasks)
    if allow_deferred_tasks:
        actual_items = Counter(_normalize(match.group("text")) for match in actual_tasks)
        missing_items = list((expected_items - actual_items).elements())
        if missing_items:
            raise PolicyError(
                f"Pull-request body has a missing checklist item from {path}: "
                + ", ".join(missing_items)
            )
        remaining = expected_items.copy()
        for match in actual_tasks:
            item = _normalize(match.group("text"))
            if match.group("state").casefold() == "x" and remaining[item] > 0:
                remaining[item] -= 1
        unexpected_incomplete: list[str] = []
        for match in actual_tasks:
            if match.group("state") != " ":
                continue
            item = _normalize(match.group("text"))
            if remaining[item] > 0:
                remaining[item] -= 1
            else:
                unexpected_incomplete.append(match.group("text").strip())
        if unexpected_incomplete:
            raise PolicyError(
                f"Pull-request body contains an incomplete checklist item not required by {path}: "
                + ", ".join(unexpected_incomplete)
            )
        if _UNRESOLVED.search(visible_body):
            raise PolicyError(f"Pull-request body contains an unresolved placeholder from {path}")
        return

    if any(match.group("state") == " " for match in actual_tasks):
        raise PolicyError(f"Pull-request body contains an incomplete checklist item from {path}")
    completed_items = Counter(
        _normalize(match.group("text"))
        for match in actual_tasks
        if match.group("state").casefold() == "x"
    )
    missing_items = list((expected_items - completed_items).elements())
    if missing_items:
        raise PolicyError(
            f"Pull-request body has a missing or incomplete checklist item from {path}: "
            + ", ".join(missing_items)
        )
    if _UNRESOLVED.search(visible_body):
        raise PolicyError(f"Pull-request body contains an unresolved placeholder from {path}")


def _validate_safe_template_tasks(
    path: str,
    template: str,
    tasks: list[re.Match[str]],
) -> None:
    unsafe_attestations = [
        match.group("text").strip()
        for match in tasks
        if _FIRST_PERSON_ATTESTATION.search(match.group("text"))
        or _LEGAL_ATTESTATION.search(match.group("text"))
    ]
    if unsafe_attestations:
        raise PolicyError(
            f"Pull-request template {path} requires a legal or manual attestation that an "
            "autonomous agent cannot make: " + ", ".join(unsafe_attestations)
        )

    headings = list(_HEADING.finditer(template))
    grouped_tasks: dict[str, list[str]] = {}
    heading_index = 0
    current_heading = ""
    for task in tasks:
        while heading_index < len(headings) and headings[heading_index].start() < task.start():
            current_heading = headings[heading_index].group("text")
            heading_index += 1
        grouped_tasks.setdefault(current_heading, []).append(task.group("text"))
    exclusive_group = next(
        (
            items
            for heading, items in grouped_tasks.items()
            if len(items) > 1 and _EXCLUSIVE_HEADING.search(heading)
        ),
        None,
    )
    category_tasks = [
        match.group("text").strip()
        for match in tasks
        if _CATEGORY_TASK.search(_normalize(match.group("text")))
    ]
    if exclusive_group is not None or len(category_tasks) > 1:
        choices = exclusive_group or category_tasks
        raise PolicyError(
            f"Pull-request template {path} contains mutually exclusive checklist choices that "
            "cannot all be completed: " + ", ".join(choices)
        )


def _is_pull_request_template(path: str) -> bool:
    lowered = path.casefold().strip("/")
    name = PurePosixPath(lowered).name
    markdown = name.endswith((".md", ".markdown"))
    return markdown and (
        name.startswith("pull_request_template")
        or lowered.startswith(".github/pull_request_template/")
    )


def _normalize(value: str) -> str:
    without_markup = re.sub(r"[`*_~]", "", value)
    return " ".join(re.findall(r"[a-z0-9]+", without_markup.casefold()))


def visible_markdown(value: str) -> str:
    """Remove Markdown regions that cannot satisfy visible template structure."""

    without_comments = re.sub(r"<!--.*?(?:-->|$)", "", value, flags=re.DOTALL)
    rendered: list[str] = []
    fence_character: str | None = None
    fence_length = 0
    for line in without_comments.splitlines(keepends=True):
        marker = re.match(r"^[ \t]{0,3}(?P<fence>`{3,}|~{3,})(?P<tail>.*)$", line)
        if fence_character is None:
            if marker is None:
                rendered.append(line)
                continue
            fence = marker.group("fence")
            fence_character = fence[0]
            fence_length = len(fence)
            rendered.append("\n" if line.endswith(("\n", "\r")) else "")
            continue
        if marker is not None:
            fence = marker.group("fence")
            if (
                fence[0] == fence_character
                and len(fence) >= fence_length
                and not marker.group("tail").strip()
            ):
                fence_character = None
                fence_length = 0
        rendered.append("\n" if line.endswith(("\n", "\r")) else "")
    return "".join(rendered)


def _visible_markdown_mask(value: str) -> str:
    """Mask hidden Markdown while preserving offsets into the original value."""

    rendered = list(value)

    def blank(start: int, end: int) -> None:
        for index in range(start, end):
            if rendered[index] not in {"\n", "\r"}:
                rendered[index] = " "

    for comment in re.finditer(r"<!--.*?(?:-->|$)", value, flags=re.DOTALL):
        blank(comment.start(), comment.end())

    comment_masked = "".join(rendered)
    fence_character: str | None = None
    fence_length = 0
    offset = 0
    for line in comment_masked.splitlines(keepends=True):
        marker = re.match(r"^[ \t]{0,3}(?P<fence>`{3,}|~{3,})(?P<tail>.*)$", line)
        if fence_character is None:
            if marker is not None:
                fence = marker.group("fence")
                fence_character = fence[0]
                fence_length = len(fence)
                blank(offset, offset + len(line))
        else:
            blank(offset, offset + len(line))
            if marker is not None:
                fence = marker.group("fence")
                if (
                    fence[0] == fence_character
                    and len(fence) >= fence_length
                    and not marker.group("tail").strip()
                ):
                    fence_character = None
                    fence_length = 0
        offset += len(line)
    return "".join(rendered)


__all__ = [
    "complete_pull_request_template_tasks",
    "select_pull_request_template",
    "validate_pull_request_template",
    "validate_pull_request_template_draft",
    "visible_markdown",
]
