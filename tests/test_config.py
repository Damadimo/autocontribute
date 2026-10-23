from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
import yaml

from autocontribute.config import (
    CLA_ATTESTATION_STATEMENT,
    DCO_ATTESTATION_STATEMENT,
    AutocontributeConfig,
    ModelsConfig,
    RepositoryLabels,
    example_config,
    load_config,
    starter_placeholders,
)
from autocontribute.environments import EnvironmentOverride
from autocontribute.exceptions import ConfigurationError

ROOT = Path(__file__).resolve().parents[1]
_OPENAI = "OPENAI_API_KEY"
_ANTHROPIC = "ANTHROPIC_API_KEY"
# Key-shaped values are assembled at runtime so the repository secret scan does not report them.
_KEY = "sk-" + "test-value-0123456789"


def test_starter_file_is_short_and_lists_repositories_models_and_budget() -> None:
    raw = yaml.safe_load(example_config())
    config = AutocontributeConfig.model_validate(raw)

    assert set(raw) == {"github", "models", "budget"}
    assert config.github.repositories == ["your-org/your-repo"]
    assert config.models == ModelsConfig()
    assert config.budget.max_cost_usd_per_run == Decimal(10)
    assert config.budget.max_cost_usd_per_day == Decimal(25)
    assert "docs/configuration.md" in example_config()
    assert starter_placeholders(config) == [
        "github.repositories lists your-org/your-repo: replace it with the repositories you "
        "want to contribute to"
    ]


@pytest.mark.parametrize(
    "path",
    [
        ROOT / "autocontribute.example.yml",
        ROOT / "autocontribute.staging.example.yml",
        ROOT / "template" / "autocontribute.yml",
    ],
    ids=["example", "staging", "runner-template"],
)
def test_shipped_configs_parse(path: Path) -> None:
    raw = path.read_text(encoding="utf-8")

    config = AutocontributeConfig.model_validate(yaml.safe_load(raw))

    # Comments must not pin store schema versions; those drift silently as the schema evolves.
    assert "schema-v" not in raw
    assert "sandbox-image.md" not in raw
    assert config.models.agent == "auto"


def test_example_names_only_placeholders_that_commands_refuse() -> None:
    config = AutocontributeConfig.model_validate(
        yaml.safe_load((ROOT / "autocontribute.example.yml").read_text(encoding="utf-8"))
    )

    # An empty identity falls back to the GitHub login and its noreply address.
    assert config.identity.name == ""
    assert config.identity.email == ""
    assert config.github.repositories == ["your-org/your-repo"]
    # A label list in the file replaces the default, so a shorter list there would drop deny
    # labels for everyone who starts from it.
    assert config.github.include_labels == AutocontributeConfig().github.include_labels
    assert config.github.exclude_labels == AutocontributeConfig().github.exclude_labels
    assert config.policy.ai_disclosure == AutocontributeConfig().policy.ai_disclosure
    assert len(starter_placeholders(config)) == 1


def test_starter_placeholders_list_every_template_value_still_present() -> None:
    template = AutocontributeConfig.model_validate(
        {
            "identity": {
                "name": "Your Name",
                "email": "your-handle@users.noreply.github.com",
            },
            "github": {"repositories": ["example/project", "Your-Org/Your-Repo"]},
        }
    )

    placeholders = starter_placeholders(template)

    assert len(placeholders) == 3
    assert "your-org/your-repo" in placeholders[0]
    assert placeholders[1].startswith('identity.name is "Your Name"')
    assert placeholders[2].startswith('identity.email is "your-handle@users.noreply.github.com"')

    completed = template.model_copy(
        update={
            "identity": template.identity.model_copy(
                update={"name": "Octo Cat", "email": "octocat@users.noreply.github.com"}
            ),
            "github": template.github.model_copy(update={"repositories": ["example/project"]}),
        }
    )
    assert starter_placeholders(completed) == []


def test_default_disclosure_names_the_tool_and_model_and_the_human_review() -> None:
    disclosure = AutocontributeConfig().policy.ai_disclosure

    assert disclosure == (
        "AI assistance: an AI coding agent (autocontribute {version}, {model}) drafted this "
        "change and its test and ran the tests listed above in a sandbox. I reviewed the diff "
        "and the test results before opening this PR and will handle the review."
    )


def test_defaults_match_the_design() -> None:
    config = AutocontributeConfig()

    assert config.github.max_repository_inactivity_days == 180
    assert (config.models.agent, config.models.critic) == ("auto", "auto")
    assert (config.models.setup, config.models.triage) == ("auto", "auto")
    assert config.models.effort == {}
    assert config.environments == {}
    sandbox = config.sandbox
    assert (sandbox.command_timeout_seconds, sandbox.memory, sandbox.cpus) == (900, "6g", 2.0)
    assert sandbox.pids_limit == 1024
    budget = config.budget
    assert (budget.max_cost_usd_per_run, budget.max_cost_usd_per_day) == (10, 25)
    assert (budget.max_model_calls_per_run, budget.max_run_minutes) == (200, 90)
    assert budget.max_candidates_per_run == 25
    quality = config.quality
    assert (quality.max_files_changed, quality.max_changed_lines) == (8, 400)
    assert (quality.max_source_files, quality.max_source_lines) == (3, 150)


@pytest.mark.parametrize(
    "removed",
    [
        {"models": {"scout": {}}},
        {"models": {"builder": {}}},
        {"models": {"critic": {"provider": "openai"}}},
        {"models": {"api_key_env": "OPENAI_API_KEY"}},
        {"sandbox": {"backend": "docker"}},
        {"sandbox": {"image": "python:3.12"}},
        {"sandbox": {"allow_unsafe_local": True}},
        {"sandbox": {"max_commands": 8}},
        {"validation": {"required_commands": {}}},
        {"quality": {"min_candidate_score": 60}},
        {"quality": {"min_readiness_score": 90}},
        {"quality": {"min_dimension_score": 80}},
        {"quality": {"max_context_files": 20}},
        {"quality": {"max_context_characters": 160_000}},
        {"quality": {"require_regression_evidence_for_bugfix": True}},
        {"budget": {"max_input_tokens_per_run": 1_000}},
        {"budget": {"max_output_tokens_per_run": 1_000}},
        {"budget": {"max_model_seconds_per_run": 60}},
        {"budget": {"max_model_cost_usd_per_run": 5}},
    ],
)
def test_removed_keys_are_unknown(removed: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        AutocontributeConfig.model_validate(removed)


def test_models_are_auto_or_from_the_model_table_and_errors_never_echo_them() -> None:
    config = AutocontributeConfig.model_validate(
        {"models": {"agent": "claude-opus-5-5", "effort": {"critic": "max"}}}
    )
    assert config.models.agent == "claude-opus-5-5"

    with pytest.raises(ValueError, match=r"models\.agent must be auto or one of") as error:
        AutocontributeConfig.model_validate({"models": {"agent": _KEY}})
    assert _KEY not in str(error.value)
    for effort in ({"agent": "extreme"}, {"scout": "high"}):
        with pytest.raises(ValueError):
            AutocontributeConfig.model_validate({"models": {"effort": effort}})


def test_loading_needs_no_model_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(_OPENAI, raising=False)
    # An Actions secret that is not set arrives as an empty variable.
    monkeypatch.setenv(_ANTHROPIC, "")
    path = tmp_path / "autocontribute.yml"
    path.write_text(example_config(), encoding="utf-8")

    config = load_config(path)

    assert config.models.agent == "auto"
    with pytest.raises(ConfigurationError, match="ANTHROPIC_API_KEY or OPENAI_API_KEY"):
        config.models.resolve({_OPENAI: "", _ANTHROPIC: ""})


def test_auto_prefers_the_anthropic_key_and_takes_each_providers_tiers() -> None:
    anthropic = ModelsConfig().resolve({_ANTHROPIC: _KEY, _OPENAI: ""})
    openai = ModelsConfig().resolve({_OPENAI: _KEY})

    assert [anthropic.spec(role).id for role in ("agent", "critic", "setup", "triage")] == [
        "claude-opus-5-5",
        "claude-opus-5-5",
        "claude-sonnet-5-5",
        "claude-haiku-5-5",
    ]
    assert [openai.spec(role).id for role in ("agent", "critic", "setup", "triage")] == [
        "gpt-5.6-sol",
        "gpt-5.6-sol",
        "gpt-5.6-terra",
        "gpt-5.6-luna",
    ]
    assert dict(openai.efforts) == {
        "agent": "high",
        "critic": "high",
        "setup": "medium",
        "triage": "low",
    }


def test_auto_critic_uses_the_other_provider_when_both_keys_are_set() -> None:
    models = ModelsConfig().resolve({_ANTHROPIC: _KEY, _OPENAI: _KEY})

    assert (models.agent.id, models.critic.id) == ("claude-opus-5-5", "gpt-5.6-sol")


def test_an_explicit_model_needs_its_providers_key() -> None:
    with pytest.raises(ConfigurationError, match=r"models\.critic is claude-opus-5-5; set ANTH"):
        ModelsConfig(critic="claude-opus-5-5").resolve({_OPENAI: _KEY})


def test_an_effort_override_must_suit_the_model() -> None:
    models = ModelsConfig(agent="gpt-5.6-sol", effort={"agent": "max"}).resolve({_OPENAI: _KEY})
    assert models.efforts["agent"] == "max"

    with pytest.raises(ConfigurationError, match=r"effort\.agent is max, which gpt-5\.5 does not"):
        ModelsConfig(agent="gpt-5.5", effort={"agent": "max"}).resolve({_OPENAI: _KEY})


def test_environments_are_keyed_by_case_folded_repository() -> None:
    config = AutocontributeConfig.model_validate(
        {
            "environments": {
                "Example/Project": {
                    "image": "python:3.12-bookworm",
                    "setup": ["pip install -e .[test]"],
                    "test": "python -m pytest -q",
                    "allow_hosts": ["Files.Example.org"],
                }
            }
        }
    )

    assert config.environment_for("EXAMPLE/project") == EnvironmentOverride(
        image="python:3.12-bookworm",
        setup=["pip install -e .[test]"],
        test="python -m pytest -q",
        allow_hosts=["files.example.org"],
    )
    assert config.environment_for("example/other") is None
    for environments, message in (
        ({"*/*": {}}, "owner/name"),
        ({"a/b": {}, "A/B": {}}, "duplicate environments repository"),
        ({"a/b": {"commands": []}}, "Extra inputs are not permitted"),
        ({"a/b": {"allow_hosts": ["https://example.org"]}}, "DNS host names"),
    ):
        with pytest.raises(ValueError, match=message):
            AutocontributeConfig.model_validate({"environments": environments})


def test_secret_env_names_are_the_github_token_and_both_model_keys() -> None:
    config = AutocontributeConfig.model_validate({"github": {"token_env": "MY_TOKEN"}})

    assert config.secret_env_names() == {"MY_TOKEN", _OPENAI, _ANTHROPIC}


def test_discovery_defaults_search_listed_repositories_and_spare_newcomer_issues() -> None:
    github = AutocontributeConfig().github

    assert github.min_stars == 0
    assert github.include_labels == [
        "help wanted",
        "bug",
        "confirmed",
        "accepted",
        "status: help wanted",
        "contributions welcome",
        "pr welcome",
    ]
    assert {"good first issue", "first-timers-only"} <= set(github.exclude_labels)
    assert github.labels == {}


def test_repository_label_overrides_are_canonical_and_searchable() -> None:
    config = AutocontributeConfig.model_validate(
        {"github": {"labels": {"Example/Project": {"include": [" E-easy ", "e-easy"]}}}}
    )

    assert config.github.labels == {"example/project": RepositoryLabels(include=["E-easy"])}
    for labels, message in (
        ({"*/*": {}}, "owner/name"),
        ({"example/project": {}, "Example/Project": {}}, "duplicate github.labels"),
        ({"example/project": {"include": []}}, "at least one label"),
        ({"example/project": {"exclude": ['wontfix" repo:other/project']}}, "double quotes"),
    ):
        with pytest.raises(ValueError, match=message):
            AutocontributeConfig.model_validate({"github": {"labels": labels}})
    for label in ('help" wanted', " ", "help\twanted"):
        with pytest.raises(ValueError, match="printable label names without double quotes"):
            AutocontributeConfig.model_validate({"github": {"include_labels": [label]}})


def test_publishing_mode_is_not_a_setting() -> None:
    with pytest.raises(ValueError, match="Extra inputs are not permitted"):
        AutocontributeConfig.model_validate({"publishing": {"mode": "review_required"}})


@pytest.mark.parametrize("login", ["octocat", "Octo-Cat", ""])
def test_publishing_login_accepts_github_logins(login: str) -> None:
    config = AutocontributeConfig.model_validate({"publishing": {"login": login}})

    assert config.publishing.login == login


@pytest.mark.parametrize("login", ["octo cat", "-octocat", "octo/cat", "ghp_" + "a" * 40])
def test_publishing_login_rejects_values_that_are_not_logins(login: str) -> None:
    with pytest.raises(ValueError, match=r"publishing\.login must be a GitHub login"):
        AutocontributeConfig.model_validate({"publishing": {"login": login}})


def test_publishing_defaults_open_ready_pull_requests() -> None:
    publishing = AutocontributeConfig().publishing

    assert publishing.draft is False
    assert publishing.ready_for_review is True
    assert publishing.max_open_pull_requests == 3
    assert publishing.approval_expires_hours == 72


def _legal_attestation(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "repository": "example/project",
        "reviewed_repository_ref": "a" * 40,
        "reviewed_organization_policy_ref": "absent",
        "legal_policy_sha256": "b" * 64,
        "legal_requirements": ["cla"],
        "attested_by": "octocat",
        "attested_at": "2026-07-22T12:00:00Z",
        "cla": {"statement": CLA_ATTESTATION_STATEMENT},
    }
    value.update(updates)
    return value


def test_legal_attestation_requires_exact_fixed_statement_and_repository_key() -> None:
    with pytest.raises(ValueError, match="exact fixed attestation"):
        AutocontributeConfig.model_validate(
            {
                "policy": {
                    "legal_attestations": {
                        "example/project": _legal_attestation(
                            cla={"statement": "I agree to whatever the repository says."}
                        )
                    }
                }
            }
        )
    with pytest.raises(ValueError, match="owner/name"):
        AutocontributeConfig.model_validate(
            {"policy": {"legal_attestations": {"*/*": _legal_attestation()}}}
        )
    with pytest.raises(ValueError, match="mapping key must exactly match"):
        AutocontributeConfig.model_validate(
            {"policy": {"legal_attestations": {"other/project": _legal_attestation()}}}
        )


def test_legal_attestation_authorizations_must_match_requirement_set() -> None:
    with pytest.raises(ValueError, match="exactly match"):
        AutocontributeConfig.model_validate(
            {
                "policy": {
                    "legal_attestations": {
                        "example/project": _legal_attestation(legal_requirements=["cla", "dco"])
                    }
                }
            }
        )


def test_dco_signatory_must_match_explicit_git_identity() -> None:
    dco = {
        "statement": DCO_ATTESTATION_STATEMENT,
        "signoff_name": "Example Signer",
        "signoff_email": "signer@example.invalid",
    }
    with pytest.raises(ValueError, match="DCO signatory must exactly match"):
        AutocontributeConfig.model_validate(
            {
                "identity": {
                    "name": "Different Signer",
                    "email": "different@example.invalid",
                },
                "policy": {
                    "legal_attestations": {
                        "example/project": _legal_attestation(
                            legal_requirements=["dco"],
                            cla=None,
                            dco=dco,
                        )
                    }
                },
            }
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("signoff_name", "Example\tSigner"),
        ("signoff_name", "Example\x7fSigner"),
        ("signoff_email", "signer@@example.invalid"),
        ("signoff_email", "signer @example.invalid"),
        ("signoff_email", "signer\t@example.invalid"),
        ("signoff_email", "@example.invalid"),
        ("signoff_email", "signer@"),
    ],
)
def test_dco_signatory_rejects_noncanonical_identity(field: str, value: str) -> None:
    dco = {
        "statement": DCO_ATTESTATION_STATEMENT,
        "signoff_name": "Example Signer",
        "signoff_email": "signer@example.invalid",
    }
    dco[field] = value

    with pytest.raises(ValueError, match="canonical"):
        AutocontributeConfig.model_validate(
            {
                "identity": {
                    "name": dco["signoff_name"],
                    "email": dco["signoff_email"],
                },
                "policy": {
                    "legal_attestations": {
                        "example/project": _legal_attestation(
                            legal_requirements=["dco"],
                            cla=None,
                            dco=dco,
                        )
                    }
                },
            }
        )


@pytest.mark.parametrize(
    "attested_at",
    [
        "2026-07-22T08:00:00-04:00",
        "2026-07-22T12:00:00",
        1_753_184_000,
    ],
)
def test_legal_attestation_requires_canonical_utc_timestamp(attested_at: object) -> None:
    with pytest.raises(ValueError, match="attested_at"):
        AutocontributeConfig.model_validate(
            {
                "policy": {
                    "legal_attestations": {
                        "example/project": _legal_attestation(attested_at=attested_at)
                    }
                }
            }
        )


def test_legal_attestation_rejects_materially_future_timestamp() -> None:
    future = (datetime.now(UTC) + timedelta(days=1)).isoformat().replace("+00:00", "Z")

    with pytest.raises(ValueError, match="materially in the future"):
        AutocontributeConfig.model_validate(
            {
                "policy": {
                    "legal_attestations": {
                        "example/project": _legal_attestation(attested_at=future)
                    }
                }
            }
        )


@pytest.mark.parametrize("days", [0, 3_651])
def test_repository_inactivity_window_is_bounded(days: int) -> None:
    with pytest.raises(ValueError, match="max_repository_inactivity_days"):
        AutocontributeConfig.model_validate({"github": {"max_repository_inactivity_days": days}})


def test_load_config_resolves_storage_relative_to_config(tmp_path: Path) -> None:
    path = tmp_path / "autocontribute.yml"
    path.write_text("storage:\n  path: state\n", encoding="utf-8")

    config = load_config(path)

    assert config.storage.path == tmp_path / "state"


def test_secret_value_cannot_be_mistaken_for_environment_name() -> None:
    with pytest.raises(ValueError, match="environment variable name"):
        AutocontributeConfig.model_validate(
            {"github": {"token_env": "-".join(("ghp", "live", "secret"))}}
        )


def test_missing_config_has_actionable_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="autocontribute init"):
        load_config(tmp_path / "missing.yml")


@pytest.mark.parametrize(
    "api_url",
    [
        "http://api.github.example.test",
        "https://token@api.github.example.test",
        "https://api.github.example.test?access_token=secret",
    ],
)
def test_github_api_url_cannot_expose_credentials(api_url: str) -> None:
    with pytest.raises(ValueError, match="api_url"):
        AutocontributeConfig.model_validate({"github": {"api_url": api_url}})


def test_conditional_ai_policy_opt_ins_are_case_folded_repository_names() -> None:
    config = AutocontributeConfig.model_validate(
        {"policy": {"allow_conditional_ai_policy": ["NumPy/numpy", "numpy/NumPy"]}}
    )

    assert config.policy.allow_conditional_ai_policy == ["numpy/numpy"]
    with pytest.raises(ValueError, match="owner/name"):
        AutocontributeConfig.model_validate(
            {"policy": {"allow_conditional_ai_policy": ["https://github.com/numpy/numpy"]}}
        )
