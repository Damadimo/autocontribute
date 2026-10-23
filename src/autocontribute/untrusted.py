"""Text from outside the controller, wrapped so that a model reads it as data.

Repository files, issues and their comments, test names and output, and what another model
wrote all reach the models this way: an ``<untrusted_data>`` block of JSON whose ``<``, ``>``
and ``&`` are escaped, so nothing inside can close the block, with the host's secret values
scrubbed before encoding.
"""

from __future__ import annotations

import json
from typing import Final

from pydantic import JsonValue

from autocontribute.redaction import scrub_for_model

UNTRUSTED_OPEN: Final = '<untrusted_data encoding="json">'
UNTRUSTED_CLOSE: Final = "</untrusted_data>"


def untrusted_block(label: str, value: JsonValue, *, host_values: frozenset[str]) -> str:
    """Wrap text from outside the controller so the model reads it as data."""

    payload = {"label": label, "trust": "untrusted", "data": _scrubbed(value, host_values)}
    encoded = json.dumps(payload, ensure_ascii=False, indent=2)
    # JSON leaves angle brackets alone; escaped, nothing inside can close the block.
    encoded = encoded.replace("&", r"\u0026").replace("<", r"\u003c").replace(">", r"\u003e")
    return f"{UNTRUSTED_OPEN}\n{encoded}\n{UNTRUSTED_CLOSE}"


def _scrubbed(value: JsonValue, host_values: frozenset[str]) -> JsonValue:
    if isinstance(value, str):
        return scrub_for_model(value, host_values)
    if isinstance(value, list):
        return [_scrubbed(item, host_values) for item in value]
    if isinstance(value, dict):
        return {key: _scrubbed(item, host_values) for key, item in value.items()}
    return value


__all__ = ["UNTRUSTED_CLOSE", "UNTRUSTED_OPEN", "untrusted_block"]
