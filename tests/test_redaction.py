from __future__ import annotations

import pytest

from autocontribute.providers import _assert_secret_free_model_output
from autocontribute.redaction import (
    HIGH_CONFIDENCE_TOKEN_PATTERNS,
    MAX_ARTIFACT_CHARACTERS,
    MODEL_INPUT_REDACTION,
    SENSITIVE_FILE_REDACTION,
    contains_high_confidence_token,
    contains_host_secret,
    high_confidence_token_labels,
    host_secret_values,
    redact_model_input,
    redact_text,
    scrub_for_model,
    truncate_artifact,
)

# Token-shaped fixtures are assembled at runtime so the repository secret scan does not report
# this file.
_TOKENS = {
    "GitHub token": "ghp_" + "A1b2" * 9,
    "OpenAI API key": "sk-" + "test-0123456789abcdefghijkl",
    "AWS access key": "ASIA" + "ABCDEFGHIJKLMNOP",
    "Google API key": "AIza" + "B" * 35,
    "GitLab token": "glpat-" + "c" * 20,
    "npm token": "npm_" + "d" * 36,
    "Slack token": "xoxb-" + "1234567890-abcdef",
    "Stripe live key": "sk_live_" + "e" * 24,
    "JSON Web Token": ".".join(
        (
            "eyJ" + "hbGciOiJIUzI1NiJ9",
            "eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0",
            "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        )
    ),
    "private key": "-----BEGIN " + "EC PRIVATE KEY-----\nMHcCAQEE\n-----END EC PRIVATE KEY-----",
}
# Probe rows from the phase 2 provider review: routine repository content that the model must
# see exactly as written.
_ROUTINE_LINES = (
    'DATABASE_URL = "postgresql://user:password@localhost:5432/test"',
    'BROKER = "amqp://guest:guest@localhost//"',
    'url = f"postgresql://{user}:{password}@{host}/{db}"',
    'REDIS = "redis://:s3cretpass@localhost:6379/0"',
    'url = "https://alice:example@db.example.test"',
    "password = " + '"testpassword123"',
    'password = "hunter2"',
    "connect(password=" + '"correcthorse12")',
    'headers = {"Authorization": "Bearer abcdef123456"}',
    'headers = {"Authorization": f"Bearer {token}"}',
    "git clone ssh://git@github.com:22/org/repo.git",
    "pip install --index-url https://__token__:pypi-AgEIcHlwaS5vcmc@upload.pypi.org/legacy/",
    f'password = "{MODEL_INPUT_REDACTION}"',
)
_HOST_TOKEN = "-".join(("host", "github", "token", "8813"))
_HOST_MODEL_KEY = "-".join(("host", "model", "key", "5521"))


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


def test_host_secret_values_cover_named_and_secret_like_variables() -> None:
    environ = {
        "GH_PAT": _HOST_TOKEN,
        "ANTHROPIC_API_KEY": _HOST_MODEL_KEY,
        "DATABASE_PASSWORD": "database-password-value",
        "SHORT_TOKEN": "seven77",
        "EMPTY_SECRET": "",
        "HOME": "/home/runner/work",
        "LANG": "C.UTF-8",
    }

    values = host_secret_values(["GH_PAT", "UNSET_NAME"], environ)

    assert values == frozenset({_HOST_TOKEN, _HOST_MODEL_KEY, "database-password-value"})


@pytest.mark.parametrize("line", _ROUTINE_LINES)
def test_routine_urls_and_test_passwords_reach_the_model_unchanged(line: str) -> None:
    host_values = frozenset({_HOST_TOKEN, _HOST_MODEL_KEY})

    assert scrub_for_model(line, host_values) == line
    assert not contains_host_secret(line, host_values)
    assert not contains_high_confidence_token(line)


def test_every_high_confidence_pattern_has_a_fixture() -> None:
    assert [label for label, _pattern in HIGH_CONFIDENCE_TOKEN_PATTERNS] == list(_TOKENS)


@pytest.mark.parametrize("label", list(_TOKENS))
def test_high_confidence_tokens_are_replaced_in_model_input_and_artifacts(label: str) -> None:
    token = _TOKENS[label]
    text = f"before {token} after\n"

    scrubbed = scrub_for_model(text, frozenset())

    assert contains_high_confidence_token(text)
    assert scrubbed == f"before {MODEL_INPUT_REDACTION} after\n"
    assert token not in redact_text(text)
    assert not contains_host_secret(text, frozenset({_HOST_TOKEN}))


def test_exact_host_values_are_replaced_wherever_they_appear() -> None:
    longer = _HOST_TOKEN + "-rotated"
    text = f"https://x-access-token:{longer}@github.com/o/r.git and {_HOST_TOKEN}"
    host_values = frozenset({_HOST_TOKEN, longer})

    scrubbed = scrub_for_model(text, host_values)

    assert contains_host_secret(text, host_values)
    assert scrubbed == (
        f"https://x-access-token:{MODEL_INPUT_REDACTION}@github.com/o/r.git "
        f"and {MODEL_INPUT_REDACTION}"
    )
    assert not contains_host_secret(scrubbed, host_values)


_PEM_HEADER = "-----BEGIN " + "PRIVATE KEY-----"


@pytest.mark.parametrize(
    "line",
    [
        f'PEM_HEADER = "{_PEM_HEADER}"',
        f"if data.startswith(b'{_PEM_HEADER}'):",
        f"{_PEM_HEADER}\n    return parse(data)\n",
    ],
)
def test_a_private_key_header_without_key_material_is_left_alone(line: str) -> None:
    assert scrub_for_model(line, frozenset()) == line
    assert redact_model_input(line) == line
    assert redact_text(line) == line
    _assert_secret_free_model_output("OPENAI_API_KEY", "openai-key-placeholder", line)
    # Publication text has no reason to quote a header, so the check still flags it.
    assert contains_high_confidence_token(line)


def test_token_labels_name_each_kind_found_without_its_value() -> None:
    text = f"{_TOKENS['GitHub token']} {_TOKENS['npm token']}\n{_PEM_HEADER}\n"

    labels = high_confidence_token_labels(text)

    assert labels == ["GitHub token", "npm token", "private key"]
    assert high_confidence_token_labels("password = 'hunter2-fixture-value'") == []


def test_a_cut_off_private_key_loses_its_body_but_not_the_following_line() -> None:
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n  VJTUt9Us8cKjMzEfYyjiWA4R4\n"
    text = f"$ head -3 key.pem\n{_PEM_HEADER}\n{body}$ ls\n"

    scrubbed = scrub_for_model(text, frozenset())

    assert scrubbed == f"$ head -3 key.pem\n{MODEL_INPUT_REDACTION}\n$ ls\n"
    assert redact_text(text) == "$ head -3 key.pem\n[REDACTED:CREDENTIAL]\n$ ls\n"
    assert scrub_for_model(f"{_PEM_HEADER}\n{body.rstrip()}", frozenset()) == MODEL_INPUT_REDACTION
