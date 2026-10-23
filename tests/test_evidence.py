"""validation.json, and the evidence of a ready run that other test modules build on."""

from __future__ import annotations

import hashlib
import json

import pytest
from pydantic import ValidationError
from test_task_messages import _check, _facts

from autocontribute.config import AutocontributeConfig
from autocontribute.critic import CriticRound
from autocontribute.domain import (
    GateResult,
    PatchProposal,
    QualityReport,
    RunEnvironment,
    RunManifest,
    RunModels,
)
from autocontribute.evidence import (
    ValidationEvidence,
    read_validation_evidence,
    render_validation_evidence,
)
from autocontribute.exceptions import PolicyError
from autocontribute.pr_text import fill_disclosure
from autocontribute.store import RunStore
from autocontribute.submissions import ReviewSubmission

MODELS = RunModels(
    agent="gpt-5.6-sol", critic="gpt-5.6-sol", setup="gpt-5.6-terra", triage="gpt-5.6-luna"
)
# The autocontribute version the fixture runs record as the one that prepared them.
VERSION = "0.1.0"
ENVIRONMENT = RunEnvironment(
    recipe_source="detected",
    image_id="sha256:" + "e" * 64,
    base_image="python:3.12-bookworm",
    base_digest="sha256:" + "f" * 64,
    test_command="python -m pytest",
)


def validation_evidence() -> ValidationEvidence:
    facts = _facts()
    review = ReviewSubmission(
        verdict="approve",
        blockers=[],
        notes=["The new test could also cover negative numbers."],
        no_test_needed=False,
        summary="The fix adds the arguments, and its test fails before it.",
    )
    return ValidationEvidence(
        recipe=facts.recipe,
        baseline=facts.baseline,
        check=_check(),
        critic_rounds=[
            CriticRound(
                number=1, decision="approve", reason="", review=review, confirmed=[], dropped=[]
            )
        ],
    )


def disclosure(config: AutocontributeConfig) -> str:
    return fill_disclosure(config.policy.ai_disclosure, version=VERSION, model=MODELS.agent)


def proposal(config: AutocontributeConfig, **changes: object) -> PatchProposal:
    """A proposal whose body shows the filled disclosure, as ``pr_text`` assembles it."""

    fields: dict[str, object] = {
        "summary": "The answer was 1; it is 2 now.",
        "commit_message": "Correct documented answer",
        "pull_request_title": "Correct documented answer",
        "pull_request_body": f"Fixes #42.\n\n---\n\n{disclosure(config)}",
        "test_files": ["test_fix.py"],
        "test_command": "python -m pytest test_fix.py",
        "disclosure": disclosure(config),
    }
    return PatchProposal.model_validate({**fields, **changes})


def ready_quality() -> QualityReport:
    return QualityReport(
        ready=True,
        gates=[GateResult(gate="fixture", passed=True, evidence="passed")],
        review_rounds=1,
        review_summary="The fix adds the arguments, and its test fails before it.",
        review_notes=["The new test could also cover negative numbers."],
    )


def seal_evidence(store: RunStore, run: RunManifest) -> None:
    """Give a fixture run what a ready run records besides its proposal and fingerprints."""

    text = render_validation_evidence(validation_evidence())
    store.write_artifact(run.run_id, "validation.json", text)
    run.models = MODELS
    run.autocontribute_version = VERSION
    run.environment = ENVIRONMENT
    run.quality = ready_quality()
    run.validation_sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_validation_evidence_reads_back_what_was_written() -> None:
    evidence = validation_evidence()

    text = render_validation_evidence(evidence)

    assert read_validation_evidence(text.encode("utf-8")) == evidence
    assert text.endswith("}\n")
    assert json.loads(text)["critic_rounds"][0]["decision"] == "approve"


@pytest.mark.parametrize("artifact", [b'{"baseline": null, "patched": []}', b"not json"])
def test_validation_evidence_refuses_anything_else(artifact: bytes) -> None:
    with pytest.raises(PolicyError, match="not the evidence of a prepared run"):
        read_validation_evidence(artifact)


@pytest.mark.parametrize("version", ["0.1.0) wrote this by hand (", "", "v1"])
def test_manifest_records_only_a_version_number(version: str) -> None:
    with pytest.raises(ValidationError):
        RunManifest.model_validate(
            {
                "run_id": "0123456789abcdef",
                "status": "discovering",
                "created_at": "2026-10-22T12:00:00Z",
                "updated_at": "2026-10-22T12:00:00Z",
                "autocontribute_version": version,
            }
        )


def test_run_models_come_from_the_model_table() -> None:
    with pytest.raises(ValidationError, match="not a model in the built-in table"):
        RunModels.model_validate({**MODELS.model_dump(), "agent": "a person"})
