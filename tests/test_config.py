from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
import yaml

from autocontribute.config import (
    CLA_ATTESTATION_STATEMENT,
    DCO_ATTESTATION_STATEMENT,
    AutocontributeConfig,
    ModelPricing,
    RepositoryLabels,
    example_config,
    load_config,
    starter_placeholders,
)
from autocontribute.exceptions import ConfigurationError


def test_example_config_is_valid() -> None:
    config = AutocontributeConfig.model_validate(yaml.safe_load(example_config()))

    assert config.models.builder.model == "gpt-5.6"
    assert config.models.critic.reasoning_mode == "pro"
    assert config.publishing.draft is True
    assert config.budget.max_model_cost_usd_per_run == Decimal("50")
    assert config.models.scout.pricing is not None
    assert all(
        config.validation.commands_for(repository) for repository in config.github.repositories
    )


def test_shipped_example_configs_are_valid_and_self_consistent() -> None:
    root = Path(__file__).resolve().parents[1]
    for name in ("autocontribute.example.yml", "autocontribute.staging.example.yml"):
        raw = (root / name).read_text(encoding="utf-8")
        config = AutocontributeConfig.model_validate(yaml.safe_load(raw))
        assert all(
            config.validation.commands_for(repository) for repository in config.github.repositories
        )
        # Comments must not pin store schema versions; those drift silently as the schema evolves.
        assert "schema-v" not in raw
        assert "docs/sandbox-image.md" in raw

    example = (root / "autocontribute.example.yml").read_text(encoding="utf-8")
    staging = (root / "autocontribute.staging.example.yml").read_text(encoding="utf-8")
    # The starter repository's pytest command needs project dependencies. A pullable
    # bare-interpreter image would pass config validation yet fail doctor, so the shipped image
    # must be an unresolvable, unmistakable placeholder the operator has to replace.
    placeholder = "example.invalid/sandbox@sha256:" + "0" * 64
    assert placeholder in example
    assert placeholder in example_config()
    # The staging fixture's stdlib-only validation recipe is the one case a bare image satisfies.
    assert "python:3.12-bookworm@sha256:" in staging
    assert (root / "docs" / "sandbox-image.md").exists()


def test_starter_configs_name_only_placeholders_that_commands_refuse() -> None:
    root = Path(__file__).resolve().parents[1]
    for raw in (
        example_config(),
        (root / "autocontribute.example.yml").read_text(encoding="utf-8"),
    ):
        config = AutocontributeConfig.model_validate(yaml.safe_load(raw))
        # An empty identity falls back to the GitHub login and its noreply address.
        assert config.identity.name == ""
        assert config.identity.email == ""
        assert config.github.repositories == ["your-org/your-repo"]
        assert config.validation.commands_for("your-org/your-repo") == ["python -m pytest"]

        placeholders = starter_placeholders(config)

        assert len(placeholders) == 2
        assert "your-org/your-repo" in placeholders[0]
        assert "example.invalid" in placeholders[1]


def test_starter_placeholders_list_every_template_value_still_present() -> None:
    template = AutocontributeConfig.model_validate(
        {
            "identity": {
                "name": "Your Name",
                "email": "your-handle@users.noreply.github.com",
            },
            "github": {"repositories": ["example/project", "Your-Org/Your-Repo"]},
            "validation": {
                "required_commands": {
                    "example/project": ["python -m pytest"],
                    "Your-Org/Your-Repo": ["python -m pytest"],
                }
            },
            "sandbox": {"image": "example.invalid:5000/sandbox@sha256:" + "0" * 64},
        }
    )

    placeholders = starter_placeholders(template)

    assert len(placeholders) == 4
    assert "your-org/your-repo" in placeholders[0]
    assert "example.invalid" in placeholders[1]
    assert placeholders[2].startswith('identity.name is "Your Name"')
    assert placeholders[3].startswith('identity.email is "your-handle@users.noreply.github.com"')

    completed = template.model_copy(
        update={
            "identity": template.identity.model_copy(
                update={"name": "Octo Cat", "email": "octocat@users.noreply.github.com"}
            ),
            "github": template.github.model_copy(update={"repositories": ["example/project"]}),
            "sandbox": template.sandbox.model_copy(
                update={"image": "ghcr.io/example/sandbox@sha256:" + "1" * 64}
            ),
        }
    )
    assert starter_placeholders(completed) == []
    # Only the registry host is a placeholder; an image merely named after it is not.
    renamed = completed.sandbox.model_copy(
        update={"image": "ghcr.io/example.invalid/sandbox@sha256:" + "1" * 64}
    )
    assert starter_placeholders(completed.model_copy(update={"sandbox": renamed})) == []


def test_starter_image_is_not_a_placeholder_for_the_local_backend() -> None:
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"]},
            "validation": {"required_commands": {"example/project": ["python -m pytest"]}},
            "sandbox": {
                "backend": "local",
                "allow_unsafe_local": True,
                "image": "example.invalid/sandbox@sha256:" + "0" * 64,
            },
        }
    )

    assert starter_placeholders(config) == []


def test_defaults_disclose_autonomous_work_without_claiming_human_validation() -> None:
    config = AutocontributeConfig()
    disclosure = config.policy.ai_disclosure.casefold()

    assert "autonomously" in disclosure
    assert "automated checks" in disclosure
    assert "independently validated" not in disclosure
    assert "validated by the contributor" not in disclosure
    assert config.publishing.draft is True
    assert config.github.max_repository_inactivity_days == 180


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


def test_ready_for_review_requires_draft_staging() -> None:
    with pytest.raises(ValueError, match=r"publishing\.draft must be true"):
        AutocontributeConfig.model_validate(
            {"publishing": {"draft": False, "ready_for_review": True}}
        )


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


def test_explicit_repositories_require_operator_owned_validation_commands() -> None:
    with pytest.raises(ValueError, match="explicit repositories require"):
        AutocontributeConfig.model_validate({"github": {"repositories": ["example/project"]}})


def test_trusted_validation_commands_must_not_be_empty() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        AutocontributeConfig.model_validate(
            {
                "github": {"repositories": ["example/project"]},
                "validation": {"required_commands": {"example/project": ["  "]}},
            }
        )


def test_required_validation_commands_must_fit_the_sandbox_budget() -> None:
    with pytest.raises(ValueError, match=r"exceed sandbox\.max_commands"):
        AutocontributeConfig.model_validate(
            {
                "github": {"repositories": ["example/project"]},
                "sandbox": {"max_commands": 1},
                "validation": {
                    "required_commands": {
                        "example/project": ["python -m pytest", "python -m ruff check ."]
                    }
                },
            }
        )


def test_load_config_resolves_storage_relative_to_config(tmp_path: Path) -> None:
    path = tmp_path / "autocontribute.yml"
    path.write_text("storage:\n  path: state\n", encoding="utf-8")

    config = load_config(path)

    assert config.storage.path == tmp_path / "state"


def test_secret_value_cannot_be_mistaken_for_environment_name() -> None:
    with pytest.raises(ValueError, match="environment variable name"):
        AutocontributeConfig.model_validate(
            {"models": {"builder": {"api_key_env": "sk-live-secret"}}}
        )


def test_local_execution_requires_explicit_unsafe_opt_in() -> None:
    with pytest.raises(ValueError, match="allow_unsafe_local"):
        AutocontributeConfig.model_validate({"sandbox": {"backend": "local"}})


def test_partial_model_profiles_keep_role_specific_reasoning_defaults() -> None:
    config = AutocontributeConfig.model_validate(
        {
            "models": {
                "scout": {"model": "scout-model"},
                "builder": {"model": "builder-model"},
                "critic": {"model": "critic-model"},
            }
        }
    )

    assert config.models.scout.reasoning_mode == "standard"
    assert config.models.builder.reasoning_mode == "standard"
    assert config.models.critic.reasoning_mode == "pro"


def test_cost_budget_requires_pricing_for_every_model_role() -> None:
    with pytest.raises(ValueError, match=r"requires token pricing.*scout, builder, critic"):
        AutocontributeConfig.model_validate({"budget": {"max_model_cost_usd_per_run": "5.00"}})


def test_partial_model_pricing_is_rejected_to_prevent_underreported_cost() -> None:
    with pytest.raises(ValueError, match="pricing must be configured for every role"):
        AutocontributeConfig.model_validate(
            {
                "models": {
                    "scout": {
                        "pricing": {
                            "input_usd_per_million_tokens": "2",
                            "output_usd_per_million_tokens": "10",
                        }
                    }
                }
            }
        )


def test_decimal_model_pricing_handles_cached_and_cache_write_tokens_exactly() -> None:
    pricing = ModelPricing(
        input_usd_per_million_tokens="2",
        cached_input_usd_per_million_tokens="0.5",
        cache_write_usd_per_million_tokens="3",
        output_usd_per_million_tokens="10",
    )

    cost = pricing.cost(
        input_tokens=1_000_000,
        cached_input_tokens=200_000,
        cache_write_tokens=100_000,
        output_tokens=50_000,
    )

    assert cost == Decimal("2.3")


@pytest.mark.parametrize("value", ["NaN", "Infinity", "-1", "0"])
def test_model_pricing_rejects_non_finite_or_non_positive_rates(value: str) -> None:
    with pytest.raises(ValueError):
        ModelPricing(
            input_usd_per_million_tokens=value,
            output_usd_per_million_tokens="10",
        )


def test_compatible_provider_rejects_nonportable_pro_mode() -> None:
    with pytest.raises(ValueError, match="cannot portably enforce pro"):
        AutocontributeConfig.model_validate(
            {
                "models": {
                    "critic": {
                        "provider": "openai_compatible",
                        "base_url": "https://models.example.test/v1",
                    }
                }
            }
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


@pytest.mark.parametrize(
    "base_url",
    [
        "http://models.example.test/v1",
        "https://api-key@models.example.test/v1",
        "https://models.example.test/v1?key=secret",
    ],
)
def test_model_base_url_cannot_expose_credentials(base_url: str) -> None:
    with pytest.raises(ValueError, match="base_url"):
        AutocontributeConfig.model_validate(
            {
                "models": {
                    "builder": {
                        "provider": "openai_compatible",
                        "base_url": base_url,
                    }
                }
            }
        )


def test_conditional_ai_policy_opt_ins_are_case_folded_repository_names() -> None:
    config = AutocontributeConfig.model_validate(
        {"policy": {"allow_conditional_ai_policy": ["NumPy/numpy", "numpy/NumPy"]}}
    )

    assert config.policy.allow_conditional_ai_policy == ["numpy/numpy"]
    with pytest.raises(ValueError, match="owner/name"):
        AutocontributeConfig.model_validate(
            {"policy": {"allow_conditional_ai_policy": ["https://github.com/numpy/numpy"]}}
        )
