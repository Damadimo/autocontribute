"""Built-in model table: limits, efforts, list prices and per-role defaults.

Prices are list prices in USD per million tokens. Cache-write prices assume the TTL the adapters
use: OpenAI's default 30 minutes and Anthropic's 5-minute ephemeral cache.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from decimal import Decimal
from types import MappingProxyType
from typing import Final, Literal

from autocontribute.exceptions import ConfigurationError

Provider = Literal["openai", "anthropic"]
Role = Literal["agent", "critic", "setup", "triage"]
Effort = Literal["low", "medium", "high", "xhigh", "max"]

MODEL_TABLE_DATE: Final = date(2026, 10, 22)
AUTO_MODEL: Final = "auto"
_TOKENS_PER_PRICE_UNIT: Final = Decimal(1_000_000)
_ALL_EFFORTS: Final[frozenset[Effort]] = frozenset({"low", "medium", "high", "xhigh", "max"})
_AUTO_PROVIDER_ORDER: Final[tuple[Provider, ...]] = ("anthropic", "openai")


@dataclass(frozen=True)
class ModelUsage:
    """Normalized usage of one request: input counts cached and cache-write tokens too."""

    input_tokens: int = 0
    cached_input_tokens: int = 0
    cache_write_tokens: int = 0
    output_tokens: int = 0
    reasoning_tokens: int = 0
    total_tokens: int = 0


@dataclass(frozen=True, slots=True)
class Rates:
    """USD per million tokens."""

    input: Decimal
    cached_input: Decimal
    cache_write: Decimal
    output: Decimal


@dataclass(frozen=True, slots=True)
class LongContextTier:
    """Rates billed for the whole request once its input exceeds ``above_input_tokens``."""

    above_input_tokens: int
    rates: Rates


@dataclass(frozen=True, slots=True)
class ModelSpec:
    id: str
    provider: Provider
    context_tokens: int
    max_output_tokens: int
    efforts: frozenset[Effort]
    # The provider reports the model that served the request; any other value fails the turn.
    response_models: frozenset[str]
    standard: Rates
    long_context: LongContextTier | None = None


def _usd(input_rate: str, cached_input_rate: str, cache_write_rate: str, output_rate: str) -> Rates:
    return Rates(
        input=Decimal(input_rate),
        cached_input=Decimal(cached_input_rate),
        cache_write=Decimal(cache_write_rate),
        output=Decimal(output_rate),
    )


_SPECS: Final = (
    ModelSpec(
        id="gpt-5.6-sol",
        provider="openai",
        context_tokens=1_050_000,
        max_output_tokens=128_000,
        efforts=_ALL_EFFORTS,
        response_models=frozenset({"gpt-5.6-sol"}),
        # List price. The promotional $4/$20 (through at least 2026-11-21) is not used, so
        # reservations and recorded costs stay upper bounds after the promotion ends.
        standard=_usd("5.00", "0.50", "6.25", "30.00"),
        long_context=LongContextTier(272_000, _usd("10.00", "1.00", "12.50", "45.00")),
    ),
    ModelSpec(
        id="gpt-5.6-terra",
        provider="openai",
        context_tokens=1_050_000,
        max_output_tokens=128_000,
        efforts=_ALL_EFFORTS,
        response_models=frozenset({"gpt-5.6-terra"}),
        standard=_usd("2.00", "0.20", "2.50", "12.00"),
        long_context=LongContextTier(272_000, _usd("4.00", "0.40", "5.00", "18.00")),
    ),
    ModelSpec(
        id="gpt-5.6-luna",
        provider="openai",
        # The upgrade guide gives Luna a 400K context while its model page says 1.05M.
        context_tokens=400_000,
        max_output_tokens=128_000,
        efforts=_ALL_EFFORTS,
        response_models=frozenset({"gpt-5.6-luna"}),
        standard=_usd("0.20", "0.02", "0.25", "1.20"),
        long_context=LongContextTier(272_000, _usd("0.40", "0.04", "0.50", "1.80")),
    ),
    ModelSpec(
        id="gpt-5.5",
        provider="openai",
        context_tokens=1_050_000,
        max_output_tokens=128_000,
        efforts=frozenset({"low", "medium", "high", "xhigh"}),
        # Requests for the alias are served by its dated default snapshot.
        response_models=frozenset({"gpt-5.5", "gpt-5.5-2026-04-23"}),
        # gpt-5.5 bills cache writes as ordinary input.
        standard=_usd("5.00", "0.50", "5.00", "30.00"),
        long_context=LongContextTier(272_000, _usd("10.00", "1.00", "10.00", "45.00")),
    ),
    ModelSpec(
        id="claude-opus-5-5",
        provider="anthropic",
        context_tokens=1_000_000,
        max_output_tokens=128_000,
        efforts=_ALL_EFFORTS,
        response_models=frozenset({"claude-opus-5-5"}),
        standard=_usd("4.00", "0.20", "5.00", "20.00"),
    ),
    ModelSpec(
        id="claude-sonnet-5-5",
        provider="anthropic",
        context_tokens=1_000_000,
        max_output_tokens=128_000,
        efforts=_ALL_EFFORTS,
        response_models=frozenset({"claude-sonnet-5-5"}),
        standard=_usd("2.00", "0.20", "2.50", "10.00"),
    ),
    ModelSpec(
        id="claude-haiku-5-5",
        provider="anthropic",
        context_tokens=1_000_000,
        max_output_tokens=128_000,
        efforts=_ALL_EFFORTS,
        response_models=frozenset({"claude-haiku-5-5"}),
        standard=_usd("0.10", "0.01", "0.125", "0.50"),
        long_context=LongContextTier(100_000, _usd("0.50", "0.05", "0.625", "2.50")),
    ),
)
MODELS: Final[Mapping[str, ModelSpec]] = MappingProxyType({spec.id: spec for spec in _SPECS})

API_KEY_ENVS: Final[Mapping[Provider, str]] = MappingProxyType(
    {"openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY"}
)
ROLE_MODELS: Final[Mapping[Provider, Mapping[Role, str]]] = MappingProxyType(
    {
        "openai": MappingProxyType(
            {
                "agent": "gpt-5.6-sol",
                "critic": "gpt-5.6-sol",
                "setup": "gpt-5.6-terra",
                "triage": "gpt-5.6-luna",
            }
        ),
        "anthropic": MappingProxyType(
            {
                "agent": "claude-opus-5-5",
                "critic": "claude-opus-5-5",
                "setup": "claude-sonnet-5-5",
                "triage": "claude-haiku-5-5",
            }
        ),
    }
)
DEFAULT_EFFORTS: Final[Mapping[Role, Effort]] = MappingProxyType(
    {"agent": "high", "critic": "high", "setup": "medium", "triage": "low"}
)
# Per-turn caps cover reasoning as well as visible output. Anthropic recommends 64K for long
# agentic turns, because adaptive thinking cannot be turned off on these models.
TURN_OUTPUT_CAPS: Final[Mapping[Provider, Mapping[Role, int]]] = MappingProxyType(
    {
        "openai": MappingProxyType(
            {"agent": 32_000, "critic": 32_000, "setup": 16_000, "triage": 4_000}
        ),
        "anthropic": MappingProxyType(
            {"agent": 64_000, "critic": 64_000, "setup": 16_000, "triage": 4_000}
        ),
    }
)


def resolve_model(name: str, role: Role, environ: Mapping[str, str]) -> ModelSpec:
    """Return the table entry for a configured model name.

    ``auto`` picks Anthropic when its API key is set, else OpenAI when its key is set, and then
    that provider's default model for the role.
    """

    if name == AUTO_MODEL:
        for provider in _AUTO_PROVIDER_ORDER:
            if environ.get(API_KEY_ENVS[provider]):
                return MODELS[ROLE_MODELS[provider][role]]
        raise ConfigurationError(
            f"models.{role} is auto, but no model API key is set; set "
            f"{API_KEY_ENVS['anthropic']} or {API_KEY_ENVS['openai']}"
        )
    spec = MODELS.get(name)
    if spec is None:
        # The value is not echoed: a key pasted into the wrong field must not reach the logs.
        raise ConfigurationError(
            f"models.{role} is not a known model; use auto or one of: {', '.join(MODELS)}"
        )
    return spec


def _rates(spec: ModelSpec, input_tokens: int) -> Rates:
    tier = spec.long_context
    if tier is not None and input_tokens > tier.above_input_tokens:
        return tier.rates
    return spec.standard


def cost(spec: ModelSpec, usage: ModelUsage) -> Decimal:
    """Price one request's usage at the rates of the tier its input falls in."""

    regular_input_tokens = usage.input_tokens - usage.cached_input_tokens - usage.cache_write_tokens
    if regular_input_tokens < 0:
        raise ValueError("cached and cache-write tokens cannot exceed input tokens")
    rates = _rates(spec, usage.input_tokens)
    return (
        Decimal(regular_input_tokens) * rates.input
        + Decimal(usage.cached_input_tokens) * rates.cached_input
        + Decimal(usage.cache_write_tokens) * rates.cache_write
        + Decimal(usage.output_tokens) * rates.output
    ) / _TOKENS_PER_PRICE_UNIT


def upper_bound_cost(spec: ModelSpec, *, input_tokens: int, output_tokens: int) -> Decimal:
    """Price a reservation without assuming a cache hit, in the tier its input falls in."""

    rates = _rates(spec, input_tokens)
    input_rate = max(rates.input, rates.cached_input, rates.cache_write)
    return (
        Decimal(input_tokens) * input_rate + Decimal(output_tokens) * rates.output
    ) / _TOKENS_PER_PRICE_UNIT


__all__ = [
    "API_KEY_ENVS",
    "AUTO_MODEL",
    "DEFAULT_EFFORTS",
    "MODELS",
    "MODEL_TABLE_DATE",
    "ROLE_MODELS",
    "TURN_OUTPUT_CAPS",
    "Effort",
    "LongContextTier",
    "ModelSpec",
    "ModelUsage",
    "Provider",
    "Rates",
    "Role",
    "cost",
    "resolve_model",
    "upper_bound_cost",
]
