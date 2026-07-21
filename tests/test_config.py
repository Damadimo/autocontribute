from pathlib import Path

import pytest
import yaml

from autocontribute.config import AutocontributeConfig, example_config, load_config
from autocontribute.exceptions import ConfigurationError


def test_example_config_is_valid() -> None:
    config = AutocontributeConfig.model_validate(yaml.safe_load(example_config()))

    assert config.models.builder.model == "gpt-5.6"
    assert config.models.critic.reasoning_mode == "pro"
    assert config.publishing.mode == "review_required"
    assert config.publishing.draft is True
    assert config.sandbox.network == "none"
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
