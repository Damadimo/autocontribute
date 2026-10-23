"""A repository's pull request template, and the Markdown of a body that a reader sees."""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import PurePosixPath

from autocontribute.exceptions import PolicyError

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
        if is_pull_request_template(path) and content.strip()
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


def is_pull_request_template(path: str) -> bool:
    """Return whether a repository path is a GitHub pull request template."""

    lowered = path.casefold().strip("/")
    name = PurePosixPath(lowered).name
    markdown = name.endswith((".md", ".markdown"))
    return markdown and (
        name.startswith("pull_request_template")
        or lowered.startswith(".github/pull_request_template/")
    )


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


__all__ = [
    "is_pull_request_template",
    "select_pull_request_template",
    "visible_markdown",
]
