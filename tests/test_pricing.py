from __future__ import annotations

from datetime import date
from decimal import Decimal

import pytest

from autocontribute.exceptions import ConfigurationError
from autocontribute.pricing import (
    API_KEY_ENVS,
    DEFAULT_EFFORTS,
    MODEL_TABLE_DATE,
    MODELS,
    ROLE_MODELS,
    TURN_OUTPUT_CAPS,
    Effort,
    LongContextTier,
    ModelSpec,
    ModelUsage,
    Rates,
    TierRole,
    cost,
    resolve_critic,
    resolve_model,
    upper_bound_cost,
)

_ALL: frozenset[Effort] = frozenset({"low", "medium", "high", "xhigh", "max"})


def _usd(*rates: str) -> Rates:
    return Rates(*(Decimal(rate) for rate in rates))


_EXPECTED_MODELS = {
    "gpt-5.6-sol": ModelSpec(
        id="gpt-5.6-sol",
        provider="openai",
        context_tokens=1_050_000,
        max_output_tokens=128_000,
        efforts=_ALL,
        response_models=frozenset({"gpt-5.6-sol"}),
        standard=_usd("5.00", "0.50", "6.25", "30.00"),
        long_context=LongContextTier(272_000, _usd("10.00", "1.00", "12.50", "45.00")),
    ),
    "gpt-5.6-terra": ModelSpec(
        id="gpt-5.6-terra",
        provider="openai",
        context_tokens=1_050_000,
        max_output_tokens=128_000,
        efforts=_ALL,
        response_models=frozenset({"gpt-5.6-terra"}),
        standard=_usd("2.00", "0.20", "2.50", "12.00"),
        long_context=LongContextTier(272_000, _usd("4.00", "0.40", "5.00", "18.00")),
    ),
    "gpt-5.6-luna": ModelSpec(
        id="gpt-5.6-luna",
        provider="openai",
        context_tokens=400_000,
        max_output_tokens=128_000,
        efforts=_ALL,
        response_models=frozenset({"gpt-5.6-luna"}),
        standard=_usd("0.20", "0.02", "0.25", "1.20"),
        long_context=LongContextTier(272_000, _usd("0.40", "0.04", "0.50", "1.80")),
    ),
    "gpt-5.5": ModelSpec(
        id="gpt-5.5",
        provider="openai",
        context_tokens=1_050_000,
        max_output_tokens=128_000,
        efforts=frozenset({"low", "medium", "high", "xhigh"}),
        response_models=frozenset({"gpt-5.5", "gpt-5.5-2026-04-23"}),
        standard=_usd("5.00", "0.50", "5.00", "30.00"),
        long_context=LongContextTier(272_000, _usd("10.00", "1.00", "10.00", "45.00")),
    ),
    "claude-opus-5-5": ModelSpec(
        id="claude-opus-5-5",
        provider="anthropic",
        context_tokens=1_000_000,
        max_output_tokens=128_000,
        efforts=_ALL,
        response_models=frozenset({"claude-opus-5-5"}),
        standard=_usd("4.00", "0.20", "5.00", "20.00"),
    ),
    "claude-sonnet-5-5": ModelSpec(
        id="claude-sonnet-5-5",
        provider="anthropic",
        context_tokens=1_000_000,
        max_output_tokens=128_000,
        efforts=_ALL,
        response_models=frozenset({"claude-sonnet-5-5"}),
        standard=_usd("2.00", "0.20", "2.50", "10.00"),
    ),
    "claude-haiku-5-5": ModelSpec(
        id="claude-haiku-5-5",
        provider="anthropic",
        context_tokens=1_000_000,
        max_output_tokens=128_000,
        efforts=_ALL,
        response_models=frozenset({"claude-haiku-5-5"}),
        standard=_usd("0.10", "0.01", "0.125", "0.50"),
        long_context=LongContextTier(100_000, _usd("0.50", "0.05", "0.625", "2.50")),
    ),
}


def test_model_table_is_pinned_to_its_date() -> None:
    assert date(2026, 10, 22) == MODEL_TABLE_DATE
    assert dict(MODELS) == _EXPECTED_MODELS


def test_role_defaults_efforts_caps_and_key_names_are_pinned() -> None:
    assert {provider: dict(models) for provider, models in ROLE_MODELS.items()} == {
        "openai": {"agent": "gpt-5.6-sol", "setup": "gpt-5.6-terra", "triage": "gpt-5.6-luna"},
        "anthropic": {
            "agent": "claude-opus-5-5",
            "setup": "claude-sonnet-5-5",
            "triage": "claude-haiku-5-5",
        },
    }
    assert dict(DEFAULT_EFFORTS) == {
        "agent": "high",
        "critic": "high",
        "setup": "medium",
        "triage": "low",
    }
    assert {provider: dict(caps) for provider, caps in TURN_OUTPUT_CAPS.items()} == {
        "openai": {"agent": 32_000, "critic": 32_000, "setup": 16_000, "triage": 4_000},
        "anthropic": {"agent": 64_000, "critic": 64_000, "setup": 16_000, "triage": 4_000},
    }
    assert dict(API_KEY_ENVS) == {"openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY"}


def test_role_defaults_fit_their_provider_models() -> None:
    for provider, models in ROLE_MODELS.items():
        for role, model_id in models.items():
            spec = MODELS[model_id]
            assert spec.provider == provider
            assert DEFAULT_EFFORTS[role] in spec.efforts
            assert TURN_OUTPUT_CAPS[provider][role] <= spec.max_output_tokens


def test_model_table_cannot_be_modified() -> None:
    with pytest.raises(TypeError):
        MODELS["gpt-5.6-sol"] = MODELS["gpt-5.5"]  # type: ignore[index]
    with pytest.raises(TypeError):
        ROLE_MODELS["openai"]["agent"] = "gpt-5.5"  # type: ignore[index]


@pytest.mark.parametrize(
    ("environ", "expected"),
    [
        ({"ANTHROPIC_API_KEY": "anthropic-key", "OPENAI_API_KEY": "openai-key"}, "anthropic"),
        ({"ANTHROPIC_API_KEY": "anthropic-key"}, "anthropic"),
        ({"OPENAI_API_KEY": "openai-key"}, "openai"),
        ({"ANTHROPIC_API_KEY": "", "OPENAI_API_KEY": "openai-key"}, "openai"),
    ],
)
@pytest.mark.parametrize("role", ["agent", "setup", "triage"])
def test_auto_prefers_anthropic_then_openai_and_uses_the_role_default(
    environ: dict[str, str],
    expected: str,
    role: TierRole,
) -> None:
    spec = resolve_model("auto", role, environ)

    assert spec.provider == expected
    assert spec.id == ROLE_MODELS[spec.provider][role]


@pytest.mark.parametrize("environ", [{}, {"ANTHROPIC_API_KEY": "", "OPENAI_API_KEY": ""}])
def test_auto_without_a_model_key_names_both_variables(environ: dict[str, str]) -> None:
    with pytest.raises(ConfigurationError) as raised:
        resolve_model("auto", "triage", environ)

    message = str(raised.value)
    assert "models.triage" in message
    assert "ANTHROPIC_API_KEY" in message
    assert "OPENAI_API_KEY" in message


def test_explicit_model_resolves_without_consulting_keys() -> None:
    assert resolve_model("gpt-5.6-terra", "setup", {}) is MODELS["gpt-5.6-terra"]
    assert resolve_model("claude-haiku-5-5", "agent", {}) is MODELS["claude-haiku-5-5"]


@pytest.mark.parametrize(
    ("agent", "environ", "expected"),
    [
        ("auto", {"ANTHROPIC_API_KEY": "anthropic-key"}, "claude-opus-5-5"),
        ("auto", {"OPENAI_API_KEY": "openai-key"}, "gpt-5.6-sol"),
        ("gpt-5.6-terra", {"OPENAI_API_KEY": "openai-key"}, "gpt-5.6-terra"),
        (
            "auto",
            {"ANTHROPIC_API_KEY": "anthropic-key", "OPENAI_API_KEY": "openai-key"},
            "gpt-5.6-sol",
        ),
        (
            "gpt-5.6-terra",
            {"ANTHROPIC_API_KEY": "anthropic-key", "OPENAI_API_KEY": "openai-key"},
            "claude-opus-5-5",
        ),
        (
            "claude-haiku-5-5",
            {"ANTHROPIC_API_KEY": "anthropic-key", "OPENAI_API_KEY": ""},
            "claude-haiku-5-5",
        ),
    ],
    ids=[
        "anthropic-only",
        "openai-only",
        "explicit-agent",
        "both-keys",
        "both-keys-explicit-agent",
        "empty-other-key",
    ],
)
def test_auto_critic_is_the_agent_model_or_the_other_providers_with_both_keys(
    agent: str,
    environ: dict[str, str],
    expected: str,
) -> None:
    agent_spec = resolve_model(agent, "agent", environ)

    assert resolve_critic("auto", agent_spec, environ) is MODELS[expected]


def test_explicit_critic_ignores_the_agent_and_rejects_unknown_ids() -> None:
    environ = {"ANTHROPIC_API_KEY": "anthropic-key", "OPENAI_API_KEY": "openai-key"}
    opus = MODELS["claude-opus-5-5"]

    assert resolve_critic("claude-sonnet-5-5", opus, environ) is MODELS["claude-sonnet-5-5"]
    with pytest.raises(ConfigurationError, match=r"^models\.critic is not a known model"):
        resolve_critic("gpt-5.6", opus, environ)


@pytest.mark.parametrize("name", ["gpt-5.6", "claude-opus-5", "Claude Opus 5.5"])
def test_unknown_model_lists_known_ids_without_echoing_the_value(name: str) -> None:
    with pytest.raises(ConfigurationError) as raised:
        resolve_model(name, "agent", {"OPENAI_API_KEY": "openai-key"})

    assert str(raised.value) == (
        "models.agent is not a known model; use auto or one of: gpt-5.6-sol, gpt-5.6-terra, "
        "gpt-5.6-luna, gpt-5.5, claude-opus-5-5, claude-sonnet-5-5, claude-haiku-5-5"
    )


def test_cost_prices_regular_cached_write_and_output_tokens_separately() -> None:
    usage = ModelUsage(
        input_tokens=100_000,
        cached_input_tokens=60_000,
        cache_write_tokens=10_000,
        output_tokens=5_000,
        reasoning_tokens=3_000,
        total_tokens=105_000,
    )

    # 30K x 5.00 + 60K x 0.50 + 10K x 6.25 + 5K x 30.00, per million tokens
    assert cost(MODELS["gpt-5.6-sol"], usage) == Decimal("0.3925")
    # 30K x 4.00 + 60K x 0.20 + 10K x 5.00 + 5K x 20.00
    assert cost(MODELS["claude-opus-5-5"], usage) == Decimal("0.282")


def test_long_context_rates_price_the_whole_request_above_the_threshold() -> None:
    sol = MODELS["gpt-5.6-sol"]
    at_threshold = ModelUsage(input_tokens=272_000, output_tokens=1_000, total_tokens=273_000)
    above = ModelUsage(
        input_tokens=300_000,
        cached_input_tokens=200_000,
        cache_write_tokens=50_000,
        output_tokens=1_000,
        total_tokens=301_000,
    )

    assert cost(sol, at_threshold) == Decimal("1.39")
    # 50K x 10.00 + 200K x 1.00 + 50K x 12.50 + 1K x 45.00
    assert cost(sol, above) == Decimal("1.37")


def test_haiku_long_context_tier_starts_above_one_hundred_thousand_tokens() -> None:
    haiku = MODELS["claude-haiku-5-5"]

    assert cost(haiku, ModelUsage(input_tokens=100_000, total_tokens=100_000)) == Decimal("0.01")
    assert cost(
        haiku,
        ModelUsage(input_tokens=100_001, output_tokens=1_000, total_tokens=101_001),
    ) == Decimal("0.0525005")


def test_models_without_a_long_tier_keep_standard_rates_at_any_size() -> None:
    usage = ModelUsage(input_tokens=900_000, output_tokens=10_000, total_tokens=910_000)

    assert cost(MODELS["claude-sonnet-5-5"], usage) == Decimal("1.9")


def test_cost_rejects_cache_counts_above_input() -> None:
    usage = ModelUsage(input_tokens=10, cached_input_tokens=8, cache_write_tokens=3)

    with pytest.raises(ValueError, match="cannot exceed input tokens"):
        cost(MODELS["gpt-5.6-terra"], usage)


def test_upper_bound_uses_the_highest_input_side_rate_of_the_tier() -> None:
    sol = MODELS["gpt-5.6-sol"]
    previous = MODELS["gpt-5.5"]

    # 200K x 6.25 (cache write) + 32K x 30.00
    assert upper_bound_cost(sol, input_tokens=200_000, output_tokens=32_000) == Decimal("2.21")
    # 300K x 12.50 + 1K x 45.00
    assert upper_bound_cost(sol, input_tokens=300_000, output_tokens=1_000) == Decimal("3.795")
    # gpt-5.5 bills cache writes as input, so the input rate is its highest input-side rate.
    assert upper_bound_cost(previous, input_tokens=100_000, output_tokens=0) == Decimal("0.5")


@pytest.mark.parametrize("model_id", list(_EXPECTED_MODELS))
def test_upper_bound_covers_any_usage_with_the_same_totals(model_id: str) -> None:
    spec = MODELS[model_id]
    for input_tokens in (1_000, 100_000, 100_001, 272_000, 272_001, 399_000):
        bound = upper_bound_cost(spec, input_tokens=input_tokens, output_tokens=4_000)
        for cached, written in ((0, 0), (input_tokens, 0), (0, input_tokens), (500, 500)):
            usage = ModelUsage(
                input_tokens=input_tokens,
                cached_input_tokens=cached,
                cache_write_tokens=written,
                output_tokens=4_000,
                total_tokens=input_tokens + 4_000,
            )
            assert cost(spec, usage) <= bound
