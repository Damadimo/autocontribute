from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path

import pytest
from pydantic import JsonValue
from test_agent_loop import ScriptedProvider, Submit, turn
from test_task_messages import _issue, _repository

from autocontribute.ai_policy import PolicyFile, RepositoryAiPolicy, checked_ai_policy
from autocontribute.budget import RunBudget
from autocontribute.discovery import TriageVerdict
from autocontribute.exceptions import ModelError, ModelRequestError
from autocontribute.pricing import Provider
from autocontribute.store import RunStore
from autocontribute.transcript import Turn
from autocontribute.triage import ModelIssueTriage, ModelPolicyClassifier

_MODELS: dict[Provider, str] = {"openai": "gpt-5.6-luna", "anthropic": "claude-haiku-5-5"}
_PROVIDERS = pytest.mark.parametrize("provider", ["openai", "anthropic"])
_HOST_SECRET = "host-secret-value-0123456789"
_VERDICT: dict[str, JsonValue] = {
    "suitable": True,
    "reasons": ["A maintainer confirmed the bug and named the function."],
    "already_fixed": False,
    "needs_design": False,
    "difficulty": "small",
}
_FILES = [
    PolicyFile(
        "acme/calc",
        "CONTRIBUTING.md",
        "Thanks!\n\nWe do not accept   AI-generated\npull requests.\n",
    ),
    PolicyFile("acme/.github", "AI_POLICY.md", "Disclose AI use with an Assisted-by: trailer.\n"),
]


def _budget(tmp_path: Path) -> tuple[RunStore, RunBudget]:
    store = RunStore(tmp_path / "state")
    budget = RunBudget(
        store,
        store.create_run(),
        max_cost_usd=Decimal(10),
        max_model_calls=200,
        max_run_minutes=90,
        assert_lease=lambda: None,
    )
    return store, budget


def _artifact(store: RunStore, budget: RunBudget, name: str) -> list[dict[str, object]]:
    path = store.runs_dir / budget.manifest.run_id / name
    return [json.loads(line) for line in path.read_text().splitlines()]


@_PROVIDERS
def test_triage_is_one_turn_in_the_triage_scope(tmp_path: Path, provider: Provider) -> None:
    store, budget = _budget(tmp_path)
    script = ScriptedProvider(
        turn(provider, Submit(_VERDICT, name="submit_triage")),
        turn(provider, Submit({**_VERDICT, "difficulty": "large"}, name="submit_triage")),
    )
    triage = ModelIssueTriage(
        provider=script,
        model=_MODELS[provider],
        budget=budget,
        store=store,
        host_values=frozenset({_HOST_SECRET}),
    )
    issue = _issue(body=f"add(1, 2) returns -1. My token is {_HOST_SECRET}.")

    first = triage.triage(issue, _repository())
    second = triage.triage(_issue(number=8), _repository())

    assert first == TriageVerdict.model_validate(_VERDICT)
    assert second.problems == ["too large"]
    header, task, *_ = _artifact(store, budget, "triage-1.jsonl")
    assert header["kind"] == "triage" and header["effort"] == "low"
    assert _HOST_SECRET not in json.dumps(task)
    assert "Assess issue #7 of acme/calc" in json.dumps(task)
    assert (store.runs_dir / budget.manifest.run_id / "triage-2.jsonl").is_file()
    started = [
        json.loads(event["details"])
        for event in store.events(budget.manifest.run_id)
        if event["event_type"] == "model.call.started"
    ]
    assert [details["scope"] for details in started] == ["triage", "triage"]


@pytest.mark.parametrize(
    "answer",
    [
        turn("openai"),
        turn("openai", Submit({**_VERDICT, "difficulty": "huge"}, name="submit_triage")),
    ],
)
def test_triage_without_a_valid_answer_raises_a_model_error(tmp_path: Path, answer: Turn) -> None:
    store, budget = _budget(tmp_path)
    triage = ModelIssueTriage(
        provider=ScriptedProvider(answer),
        model=_MODELS["openai"],
        budget=budget,
        store=store,
        host_values=frozenset(),
    )

    with pytest.raises(ModelError, match="The triage model gave no answer: The transcript reached"):
        triage.triage(_issue(), _repository())


@_PROVIDERS
def test_policy_quotes_name_the_file_that_holds_them(tmp_path: Path, provider: Provider) -> None:
    store, budget = _budget(tmp_path)
    answer: dict[str, JsonValue] = {
        "stance": "ban",
        "requires_disclosure": True,
        "disclosure_requirements": ["Disclose AI use with an Assisted-by: trailer."],
        "requires_human_written_text": False,
        "quotes": [
            "We do not accept AI-generated pull requests.",
            "Disclose AI use with an Assisted-by: trailer.",
        ],
    }
    classifier = ModelPolicyClassifier(
        provider=ScriptedProvider(turn(provider, Submit(answer, name="submit_policy"))),
        model=_MODELS[provider],
        budget=budget,
        store=store,
        host_values=frozenset(),
    )

    policy = classifier.classify(_repository(), _FILES)

    assert policy.stance == "ban" and policy.requires_disclosure
    assert [(quote.repository, quote.path) for quote in policy.quotes] == [
        ("acme/calc", "CONTRIBUTING.md"),
        ("acme/.github", "AI_POLICY.md"),
    ]
    fallback = RepositoryAiPolicy(stance="none")
    assert checked_ai_policy(policy, _FILES, fallback=fallback) == policy
    header, *_ = _artifact(store, budget, "policy-1.jsonl")
    assert header["kind"] == "policy"


def test_a_quote_no_file_holds_fails_the_discovery_check(tmp_path: Path) -> None:
    store, budget = _budget(tmp_path)
    answer: dict[str, JsonValue] = {
        "stance": "ban",
        "requires_disclosure": False,
        "disclosure_requirements": [],
        "requires_human_written_text": False,
        "quotes": ["Bots are banned."],
    }
    classifier = ModelPolicyClassifier(
        provider=ScriptedProvider(turn("openai", Submit(answer, name="submit_policy"))),
        model=_MODELS["openai"],
        budget=budget,
        store=store,
        host_values=frozenset(),
    )

    policy = classifier.classify(_repository(), _FILES)

    assert [(quote.repository, quote.path) for quote in policy.quotes] == [("acme/calc", "")]
    checked = checked_ai_policy(policy, _FILES, fallback=RepositoryAiPolicy(stance="none"))
    assert checked.stance == "unclear" and checked.quotes == []


def test_a_failed_request_is_charged_so_later_questions_can_reserve(tmp_path: Path) -> None:
    store, budget = _budget(tmp_path)
    script = ScriptedProvider(
        ModelRequestError("flagged", status_code=400, provider_code="cyber_policy"),
        turn("openai", Submit(_VERDICT, name="submit_triage")),
    )
    triage = ModelIssueTriage(
        provider=script,
        model=_MODELS["openai"],
        budget=budget,
        store=store,
        host_values=frozenset(),
    )

    with pytest.raises(ModelError, match="flagged"):
        triage.triage(_issue(number=1), _repository())

    assert budget.manifest.model_reservation is None
    assert budget.manifest.model_cost_usd > 0
    assert triage.triage(_issue(number=2), _repository()) == TriageVerdict.model_validate(_VERDICT)
    events = [event["event_type"] for event in store.events(budget.manifest.run_id)]
    assert events.count("model.call.failure_charged") == 1
