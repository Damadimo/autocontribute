from decimal import Decimal
from pathlib import Path

import pytest
import yaml

from autocontribute.config import AutocontributeConfig, ModelPricing, example_config, load_config
from autocontribute.exceptions import ConfigurationError


def _priced_models() -> dict[str, object]:
    profile = {
        "expected_response_model": "immutable-model-snapshot-v1",
        "immutable_response_model_attested": True,
        "pricing": {
            "input_usd_per_million_tokens": "2",
            "output_usd_per_million_tokens": "10",
        },
    }
    return {role: profile for role in ("scout", "builder", "critic")}


def test_example_config_is_valid() -> None:
    config = AutocontributeConfig.model_validate(yaml.safe_load(example_config()))

    assert config.models.builder.model == "gpt-5.6"
    assert config.models.critic.reasoning_mode == "pro"
    assert config.publishing.mode == "review_required"
    assert config.publishing.draft is True
    assert config.sandbox.network == "none"
    assert config.budget.max_model_cost_usd_per_run == Decimal("50")
    assert config.models.scout.pricing is not None
    assert all(
        config.validation.commands_for(repository) for repository in config.github.repositories
    )


def test_defaults_disclose_autonomous_work_without_claiming_human_validation() -> None:
    config = AutocontributeConfig()
    disclosure = config.policy.ai_disclosure.casefold()

    assert "autonomously" in disclosure
    assert "automated checks" in disclosure
    assert "independently validated" not in disclosure
    assert "validated by the contributor" not in disclosure
    assert config.publishing.draft is True
    assert config.github.max_repository_inactivity_days == 180


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


def test_validation_cannot_be_disabled() -> None:
    with pytest.raises(ValueError, match="require_validation_commands"):
        AutocontributeConfig.model_validate({"quality": {"require_validation_commands": False}})


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


def test_guarded_auto_mode_accepts_one_repository_weekly_draft_pilot() -> None:
    config = AutocontributeConfig.model_validate(
        {
            "github": {"repositories": ["example/project"], "owners": []},
            "validation": {"required_commands": {"example/project": ["python -m pytest"]}},
            "publishing": {
                "mode": "auto",
                "draft": True,
                "max_new_pull_requests_per_day": 1,
                "max_open_pull_requests": 1,
                "repository_cooldown_days": 7,
            },
            "models": _priced_models(),
            "budget": {"max_model_cost_usd_per_run": "25"},
        }
    )

    assert config.publishing.mode == "auto"


def test_guarded_auto_mode_requires_the_dedicated_publication_switch() -> None:
    with pytest.raises(
        ValueError,
        match=r"publishing\.auto_publish_env must equal AUTOCONTRIBUTE_ALLOW_AUTO_PUBLISH",
    ):
        AutocontributeConfig.model_validate(
            {
                "github": {"repositories": ["example/project"], "owners": []},
                "validation": {"required_commands": {"example/project": ["python -m pytest"]}},
                "publishing": {
                    "mode": "auto",
                    "max_open_pull_requests": 1,
                    "auto_publish_env": "CI",
                },
                "models": _priced_models(),
                "budget": {"max_model_cost_usd_per_run": "25"},
            }
        )


@pytest.mark.parametrize(
    ("github", "publishing", "message"),
    [
        ({"repositories": []}, {}, "exactly one explicit"),
        (
            {"repositories": ["example/one", "example/two"]},
            {},
            "exactly one explicit",
        ),
        (
            {"repositories": ["example/project"], "owners": ["example"]},
            {},
            "github.owners must be empty",
        ),
        ({"repositories": ["example/project"]}, {"draft": False}, "draft must be true"),
        (
            {"repositories": ["example/project"]},
            {"max_new_pull_requests_per_day": 2},
            "max_new_pull_requests_per_day must equal 1",
        ),
        (
            {"repositories": ["example/project"]},
            {"repository_cooldown_days": 6},
            "repository_cooldown_days must be at least 7",
        ),
        (
            {"repositories": ["example/project"]},
            {"max_open_pull_requests": 2},
            "max_open_pull_requests must equal 1",
        ),
    ],
)
def test_guarded_auto_mode_rejects_broader_rollout(
    github: dict[str, object], publishing: dict[str, object], message: str
) -> None:
    repositories = github.get("repositories", [])
    assert isinstance(repositories, list)
    required_commands = {
        repository: ["python -m pytest"]
        for repository in repositories
        if isinstance(repository, str)
    }

    with pytest.raises(ValueError, match=message):
        AutocontributeConfig.model_validate(
            {
                "github": github,
                "validation": {"required_commands": required_commands},
                "publishing": {"mode": "auto", **publishing},
                "models": _priced_models(),
                "budget": {"max_model_cost_usd_per_run": "25"},
            }
        )


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"sandbox": {"backend": "local", "allow_unsafe_local": True}}, "must be docker"),
        (
            {"policy": {"require_maintainer_signal": False}},
            "require_maintainer_signal must be true",
        ),
        (
            {"policy": {"allow_dependency_changes": True}},
            "allow_dependency_changes must be false",
        ),
        ({"quality": {"min_readiness_score": 89}}, "min_readiness_score must be at least 90"),
        ({"quality": {"max_changed_lines": 401}}, "max_changed_lines must be at most 400"),
        ({"quality": {"forbidden_paths": []}}, "must retain guarded paths"),
    ],
)
def test_guarded_auto_mode_rejects_unsafe_runtime_policy(
    overrides: dict[str, object], message: str
) -> None:
    raw: dict[str, object] = {
        "github": {"repositories": ["example/project"]},
        "validation": {"required_commands": {"example/project": ["python -m pytest"]}},
        "publishing": {"mode": "auto", "max_open_pull_requests": 1},
        "models": _priced_models(),
        "budget": {"max_model_cost_usd_per_run": "25"},
    }
    raw.update(overrides)

    with pytest.raises(ValueError, match=message):
        AutocontributeConfig.model_validate(raw)


def test_guarded_auto_requires_complete_pricing_and_usd_ceiling() -> None:
    base = {
        "github": {"repositories": ["example/project"]},
        "validation": {"required_commands": {"example/project": ["python -m pytest"]}},
        "publishing": {"mode": "auto", "max_open_pull_requests": 1},
    }

    with pytest.raises(ValueError, match="pricing is required for every role"):
        AutocontributeConfig.model_validate(base)
    with pytest.raises(ValueError, match="max_model_cost_usd_per_run must be configured"):
        AutocontributeConfig.model_validate({**base, "models": _priced_models()})


def test_guarded_auto_requires_exact_provider_model_attestation_for_every_role() -> None:
    models = _priced_models()
    assert isinstance(models["critic"], dict)
    models["critic"] = {
        key: value
        for key, value in models["critic"].items()
        if key not in {"expected_response_model", "immutable_response_model_attested"}
    }

    with pytest.raises(ValueError, match=r"expected_response_model.*critic"):
        AutocontributeConfig.model_validate(
            {
                "github": {"repositories": ["example/project"]},
                "validation": {"required_commands": {"example/project": ["python -m pytest"]}},
                "publishing": {"mode": "auto", "max_open_pull_requests": 1},
                "models": models,
                "budget": {"max_model_cost_usd_per_run": "25"},
            }
        )


def test_guarded_auto_requires_explicit_immutable_model_identity_attestation() -> None:
    models = _priced_models()
    assert isinstance(models["critic"], dict)
    models["critic"] = {
        **models["critic"],
        "immutable_response_model_attested": False,
    }

    with pytest.raises(ValueError, match=r"immutable_response_model_attested.*critic"):
        AutocontributeConfig.model_validate(
            {
                "github": {"repositories": ["example/project"]},
                "validation": {"required_commands": {"example/project": ["python -m pytest"]}},
                "publishing": {"mode": "auto", "max_open_pull_requests": 1},
                "models": models,
                "budget": {"max_model_cost_usd_per_run": "25"},
            }
        )


def test_immutable_model_identity_attestation_requires_an_expected_model() -> None:
    with pytest.raises(ValueError, match="requires expected_response_model"):
        AutocontributeConfig.model_validate(
            {"models": {"scout": {"immutable_response_model_attested": True}}}
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
