import pytest

from autocontribute.exceptions import PolicyError
from autocontribute.pr_template import select_pull_request_template


def test_guidance_without_a_template_selects_none() -> None:
    assert select_pull_request_template({"CONTRIBUTING.md": "Run tests."}) is None


def test_default_template_wins_over_specialized_templates() -> None:
    selected = select_pull_request_template(
        {
            ".github/PULL_REQUEST_TEMPLATE/bug.md": "# Bug",
            ".github/PULL_REQUEST_TEMPLATE.md": "# Summary",
        }
    )

    assert selected == (".github/PULL_REQUEST_TEMPLATE.md", "# Summary")


def test_multiple_specialized_templates_are_ambiguous() -> None:
    with pytest.raises(PolicyError, match="multiple pull-request templates"):
        select_pull_request_template(
            {
                ".github/PULL_REQUEST_TEMPLATE/bug.md": "# Bug",
                ".github/PULL_REQUEST_TEMPLATE/docs.md": "# Documentation",
            }
        )
