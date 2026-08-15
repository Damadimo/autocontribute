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
    example_config,
    load_config,
)
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


def _s3_replication() -> dict[str, object]:
    return {
        "bundle_directory": "/var/backups/autocontribute",
        "receipt_directory": "/var/backups/autocontribute/receipts",
        "scratch_directory": "/var/backups/autocontribute/replication-scratch",
        "bucket": "autocontribute-backup",
        "expected_bucket_owner": "123456789012",
        "region": "ca-central-1",
        "prefix": "production/worker-1",
    }


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


def test_shipped_example_configs_are_valid_and_self_consistent() -> None:
    root = Path(__file__).resolve().parents[1]
    for name in ("autocontribute.example.yml", "autocontribute.staging.example.yml"):
        raw = (root / name).read_text(encoding="utf-8")
        config = AutocontributeConfig.model_validate(yaml.safe_load(raw))
        assert config.sandbox.network == "none"
        assert config.publishing.mode == "review_required"
        assert all(
            config.validation.commands_for(repository) for repository in config.github.repositories
        )
        # Comments must not pin store schema versions; those drift silently as the schema evolves.
        assert "schema-v" not in raw
        assert "docs/sandbox-image.md" in raw

    example = (root / "autocontribute.example.yml").read_text(encoding="utf-8")
    staging = (root / "autocontribute.staging.example.yml").read_text(encoding="utf-8")
    # The starter config names real repositories whose pytest commands need project dependencies.
    # A pullable bare-interpreter image would pass config validation yet fail doctor, so the
    # shipped image must be an unresolvable, unmistakable placeholder the operator has to replace.
    placeholder = "example.invalid/sandbox@sha256:" + "0" * 64
    assert placeholder in example
    assert placeholder in example_config()
    # The staging fixture's stdlib-only validation recipe is the one case a bare image satisfies.
    assert "python:3.12-bookworm@sha256:" in staging
    assert (root / "docs" / "sandbox-image.md").exists()


def test_defaults_disclose_autonomous_work_without_claiming_human_validation() -> None:
    config = AutocontributeConfig()
    disclosure = config.policy.ai_disclosure.casefold()

    assert "autonomously" in disclosure
    assert "automated checks" in disclosure
    assert "independently validated" not in disclosure
    assert "validated by the contributor" not in disclosure
    assert config.publishing.draft is True
    assert config.github.max_repository_inactivity_days == 180
    assert config.s3_replication is None


def test_s3_replication_configuration_is_strict_and_contains_no_credentials() -> None:
    config = AutocontributeConfig.model_validate({"s3_replication": _s3_replication()})

    assert config.s3_replication is not None
    assert config.s3_replication.bucket == "autocontribute-backup"
    assert config.s3_replication.retention_days == 90
    with pytest.raises(ValueError, match="Extra inputs are not permitted"):
        AutocontributeConfig.model_validate(
            {
                "s3_replication": {
                    **_s3_replication(),
                    "secret_access_key": "must-never-live-in-config",
                }
            }
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("bucket", "Backup.With.Dots", "DNS-safe lowercase"),
        ("expected_bucket_owner", "1234", "12-digit"),
        ("region", "cn-north-1", "standard commercial AWS partition"),
        ("prefix", "../production", "prefix is unsafe"),
        ("bundle_directory", "../backups", "safe filesystem paths"),
    ],
)
def test_s3_replication_configuration_rejects_unsafe_boundaries(
    field: str,
    value: object,
    message: str,
) -> None:
    replication = _s3_replication()
    replication[field] = value

    with pytest.raises(ValueError, match=message):
        AutocontributeConfig.model_validate({"s3_replication": replication})


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
                "ready_for_review": True,
                "max_new_pull_requests_per_day": 1,
                "max_open_pull_requests": 1,
                "repository_cooldown_days": 7,
            },
            "models": _priced_models(),
            "budget": {"max_model_cost_usd_per_run": "25"},
            "s3_replication": _s3_replication(),
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
                    "ready_for_review": True,
                    "max_open_pull_requests": 1,
                    "auto_publish_env": "CI",
                },
                "models": _priced_models(),
                "budget": {"max_model_cost_usd_per_run": "25"},
            }
        )


def test_guarded_auto_mode_requires_s3_replication_configuration() -> None:
    with pytest.raises(ValueError, match="s3_replication must be configured"):
        AutocontributeConfig.model_validate(
            {
                "github": {"repositories": ["example/project"], "owners": []},
                "validation": {"required_commands": {"example/project": ["python -m pytest"]}},
                "publishing": {
                    "mode": "auto",
                    "ready_for_review": True,
                    "max_open_pull_requests": 1,
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
            {"ready_for_review": False},
            "ready_for_review must be true",
        ),
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
                "publishing": {
                    "mode": "auto",
                    "ready_for_review": True,
                    **publishing,
                },
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
        "publishing": {
            "mode": "auto",
            "ready_for_review": True,
            "max_open_pull_requests": 1,
        },
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
        "publishing": {
            "mode": "auto",
            "ready_for_review": True,
            "max_open_pull_requests": 1,
        },
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
                "publishing": {
                    "mode": "auto",
                    "ready_for_review": True,
                    "max_open_pull_requests": 1,
                },
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
                "publishing": {
                    "mode": "auto",
                    "ready_for_review": True,
                    "max_open_pull_requests": 1,
                },
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


def test_load_config_resolves_s3_replication_paths_relative_to_config(tmp_path: Path) -> None:
    path = tmp_path / "autocontribute.yml"
    replication = _s3_replication()
    replication.update(
        {
            "bundle_directory": "backups",
            "receipt_directory": "backups/receipts",
            "scratch_directory": "scratch",
        }
    )
    path.write_text(yaml.safe_dump({"s3_replication": replication}), encoding="utf-8")

    config = load_config(path)

    assert config.s3_replication is not None
    assert config.s3_replication.bundle_directory == tmp_path / "backups"
    assert config.s3_replication.receipt_directory == tmp_path / "backups" / "receipts"
    assert config.s3_replication.scratch_directory == tmp_path / "scratch"


def test_load_config_preserves_replication_symlink_for_runtime_rejection(tmp_path: Path) -> None:
    real = tmp_path / "real-backups"
    real.mkdir()
    linked = tmp_path / "linked-backups"
    linked.symlink_to(real, target_is_directory=True)
    path = tmp_path / "autocontribute.yml"
    replication = _s3_replication()
    replication["bundle_directory"] = str(linked)
    path.write_text(yaml.safe_dump({"s3_replication": replication}), encoding="utf-8")

    config = load_config(path)

    assert config.s3_replication is not None
    assert config.s3_replication.bundle_directory == linked
    assert config.s3_replication.bundle_directory.is_symlink()


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
