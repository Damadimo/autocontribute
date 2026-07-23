from __future__ import annotations

import pytest

from autocontribute.redaction import (
    MAX_ARTIFACT_CHARACTERS,
    MODEL_INPUT_REDACTION,
    SENSITIVE_FILE_REDACTION,
    redact_model_input,
    truncate_artifact,
)


def test_model_input_redacts_credentials_but_preserves_obvious_examples(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment_secret = "-".join(("environment", "secret", "472839"))
    monkeypatch.setenv("AUTOCONTRIBUTE_TEST_SECRET", environment_secret)
    text = "\n".join(
        [
            f"environment = {environment_secret}",
            "Authorization: Bearer opaqueBearerValue123456789",
            "database = https://alice:correct-horse-battery-staple@example.test/db",
            'client_secret = "live-client-value-829374"',
            'client_secret = "example-placeholder-value"',
            "token = ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ",
        ]
    )

    redacted = redact_model_input(text)

    for value in (
        environment_secret,
        "opaqueBearerValue123456789",
        "correct-horse-battery-staple",
        "live-client-value-829374",
        "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ",
    ):
        assert value not in redacted
    assert MODEL_INPUT_REDACTION in redacted
    assert 'client_secret = "example-placeholder-value"' in redacted


def test_sensitive_files_are_withheld_while_example_files_remain_usable() -> None:
    content = "SETTING=ordinary-value\n"

    assert redact_model_input(content, source_path="config/private.pem") == SENSITIVE_FILE_REDACTION
    assert redact_model_input(content, source_path=".env.production") == SENSITIVE_FILE_REDACTION
    assert redact_model_input(content, source_path=".env.example") == content


def test_artifact_truncation_boundary_uses_the_exported_limit() -> None:
    exact = "x" * MAX_ARTIFACT_CHARACTERS

    assert truncate_artifact(exact) == exact
    assert truncate_artifact(exact + "y").endswith("[truncated 1 characters]")
