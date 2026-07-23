import pytest

from autocontribute.exceptions import PolicyError
from autocontribute.pr_template import (
    complete_pull_request_template_tasks,
    select_pull_request_template,
    validate_pull_request_template,
    validate_pull_request_template_draft,
)


def test_no_template_requires_no_extra_structure() -> None:
    validate_pull_request_template("A focused explanation.", {"CONTRIBUTING.md": "Run tests."})


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


def test_template_headings_and_checklist_must_be_completed() -> None:
    guidance = {
        ".github/PULL_REQUEST_TEMPLATE.md": (
            "# Summary\n\n# Validation\n\n- [ ] Tests added and passing\n"
        )
    }

    validate_pull_request_template(
        "# Summary\n\nFix the boundary.\n\n# Validation\n\n- [x] Tests added and passing\n",
        guidance,
    )
    with pytest.raises(PolicyError, match="missing template heading"):
        validate_pull_request_template("# Summary\n\nComplete.\n", guidance)
    with pytest.raises(PolicyError, match="incomplete checklist"):
        validate_pull_request_template(
            "# Summary\n\nDone.\n\n# Validation\n\n- [ ] Tests added and passing\n",
            guidance,
        )


def test_draft_defers_only_exact_required_template_tasks() -> None:
    guidance = {
        ".github/PULL_REQUEST_TEMPLATE.md": (
            "# Summary\n\n# Validation\n\n- [ ] Tests pass\n- [ ] Lint passes\n"
        )
    }
    draft = (
        "# Summary\n\nFix the boundary.\n\n# Validation\n\n- [ ] Tests pass\n- [x] Lint passes\n"
    )

    validate_pull_request_template_draft(draft, guidance)
    with pytest.raises(PolicyError, match="missing checklist item"):
        validate_pull_request_template_draft(
            "# Summary\n\nDone.\n\n# Validation\n\n- [ ] Tests pass\n",
            guidance,
        )
    with pytest.raises(PolicyError, match="not required"):
        validate_pull_request_template_draft(
            draft + "- [ ] Run something later\n",
            guidance,
        )


def test_completion_checks_only_visible_exact_required_tasks() -> None:
    guidance = {"PULL_REQUEST_TEMPLATE.md": "# Validation\n\n- [ ] Tests pass\n"}
    draft = (
        "# Validation\n\n"
        "<!-- - [ ] Tests pass -->\n"
        "```markdown\n- [ ] Tests pass\n```\n"
        "- [ ] Tests pass\n"
    )

    completed = complete_pull_request_template_tasks(draft, guidance)

    assert "<!-- - [ ] Tests pass -->" in completed
    assert "```markdown\n- [ ] Tests pass\n```" in completed
    assert completed.endswith("- [x] Tests pass\n")
    validate_pull_request_template(completed, guidance)


def test_every_normalized_template_checklist_item_must_be_completed() -> None:
    guidance = {
        ".github/PULL_REQUEST_TEMPLATE.md": (
            "# Checklist\n\n"
            "- [ ] Contribution guide requirements are satisfied\n"
            "- [ ] Tests cover this change\n"
        )
    }

    validate_pull_request_template(
        "# Checklist\n\n"
        "- [x] Contribution guide requirements are satisfied.\n"
        "- [X] Tests cover this change!\n",
        guidance,
    )
    with pytest.raises(PolicyError, match="missing or incomplete checklist item"):
        validate_pull_request_template(
            "# Checklist\n\n"
            "- [x] Contribution guide requirements are satisfied\n"
            "- [x] Something else\n",
            guidance,
        )


@pytest.mark.parametrize(
    "item",
    [
        "I have manually tested this change",
        "I have read and agree to the contribution terms",
        "The contributor license agreement (CLA) is signed",
        "This contribution certifies the Developer Certificate of Origin",
    ],
)
def test_template_legal_or_manual_attestations_are_rejected(item: str) -> None:
    guidance = {"PULL_REQUEST_TEMPLATE.md": f"# Checklist\n\n- [ ] {item}\n"}

    with pytest.raises(PolicyError, match="legal or manual attestation"):
        validate_pull_request_template(f"# Checklist\n\n- [x] {item}\n", guidance)


def test_mutually_exclusive_template_choices_cannot_all_be_checked() -> None:
    guidance = {
        "PULL_REQUEST_TEMPLATE.md": (
            "# Type of change\n\n- [ ] Bug fix\n- [ ] Feature\n- [ ] Documentation\n"
        )
    }

    with pytest.raises(PolicyError, match="mutually exclusive checklist choices"):
        validate_pull_request_template(
            "# Type of change\n\n- [x] Bug fix\n- [x] Feature\n- [x] Documentation\n",
            guidance,
        )


def test_duplicate_template_checklist_items_cannot_be_collapsed() -> None:
    guidance = {"PULL_REQUEST_TEMPLATE.md": "# Checklist\n\n- [ ] Confirmed\n- [ ] Confirmed\n"}

    with pytest.raises(PolicyError, match="missing or incomplete checklist item"):
        validate_pull_request_template("# Checklist\n\n- [x] Confirmed\n", guidance)


def test_hidden_checked_item_does_not_satisfy_visible_template_checklist() -> None:
    guidance = {"PULL_REQUEST_TEMPLATE.md": "# Checklist\n\n- [ ] Confirmed\n"}

    with pytest.raises(PolicyError, match="omits the checklist"):
        validate_pull_request_template(
            "# Checklist\n\n<!-- - [x] Confirmed -->\n",
            guidance,
        )


def test_fenced_checked_item_does_not_satisfy_visible_template_checklist() -> None:
    guidance = {"PULL_REQUEST_TEMPLATE.md": "# Checklist\n\n- [ ] Confirmed\n"}

    with pytest.raises(PolicyError, match="omits the checklist"):
        validate_pull_request_template(
            "# Checklist\n\n```markdown\n- [x] Confirmed\n```\n",
            guidance,
        )


def test_fenced_template_examples_do_not_create_requirements() -> None:
    guidance = {
        "PULL_REQUEST_TEMPLATE.md": (
            "# Summary\n\n```markdown\n# Example only\n- [ ] Example task\n```\n"
        )
    }

    validate_pull_request_template("# Summary\n\nImplemented.\n", guidance)


def test_visible_placeholders_fail_but_template_comments_may_remain() -> None:
    guidance = {"PULL_REQUEST_TEMPLATE.md": "# Summary\n<!-- Explain why. -->\n"}

    validate_pull_request_template(
        "# Summary\n<!-- Explain why. -->\nA real explanation.\n", guidance
    )
    with pytest.raises(PolicyError, match="unresolved placeholder"):
        validate_pull_request_template("# Summary\n[Describe the change]\n", guidance)
