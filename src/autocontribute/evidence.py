"""What ``runs/<id>/validation.json`` holds: the evidence behind a prepared change (DESIGN §7.5).

The orchestrator writes it once, from what the environment builder, the fix checks and the
critic recorded, all of it scrubbed when it was made. A ready run keeps its SHA-256, which the
preparation fingerprint covers, and the approval review reads these bytes back; nothing renders
them a second time.
"""

from __future__ import annotations

import json

from pydantic import ValidationError

from autocontribute.critic import CriticRound
from autocontribute.domain import DomainModel
from autocontribute.environments import EnvironmentBaseline, EnvironmentRecipe
from autocontribute.exceptions import PolicyError
from autocontribute.fix_checks import FixCheckResult


class ValidationEvidence(DomainModel):
    """The environment, the tests before the change, and how the fix was checked and reviewed."""

    recipe: EnvironmentRecipe
    baseline: EnvironmentBaseline
    # The last check of the agent's fix: red/green, the patched suite against the baseline and
    # the gates. None when the agent submitted no fix.
    check: FixCheckResult | None
    critic_rounds: list[CriticRound]


def render_validation_evidence(evidence: ValidationEvidence) -> str:
    """Return the text of ``validation.json``."""

    return json.dumps(evidence.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"


def read_validation_evidence(artifact: bytes) -> ValidationEvidence:
    """Parse ``validation.json``; raises :class:`PolicyError` when it is not that evidence."""

    try:
        return ValidationEvidence.model_validate_json(artifact)
    except ValidationError as exc:
        raise PolicyError("Validation artifact is not the evidence of a prepared run") from exc


__all__ = ["ValidationEvidence", "read_validation_evidence", "render_validation_evidence"]
