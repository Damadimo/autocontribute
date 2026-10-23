import pytest

from autocontribute.discovery import _is_maintainer_stop, _targets_automation
from autocontribute.lifecycle import LifecycleSignalKind, _stop_kind
from autocontribute.stop_text import AUTOMATION_STOP

# Discovery reads these on issues and lifecycle sync on this tool's own pull requests; both must
# turn the same sentence into a repository hold.
TURNS_AWAY_AUTOMATION = [
    "Please stop opening AI-generated PRs.",
    "Please stop submitting AI-generated pull requests to this repo.",
    "Stop sending us LLM-generated PRs.",
    "We don't want AI-generated PRs here. Closing.",
    "Please stop using bots to open pull requests here.",
    "Stop opening PRs with an AI agent.",
    "We are no longer accepting contributions from AI agents.",
    "Do not open AI pull requests.",
    "Agent-generated PRs will be closed.",
    "We do not accept pull requests from bots.",
    "Closing this PR: we don\u2019t take AI-written patches.",
    "We will not accept automated submissions.",
    "AI-generated PRs will be closed without review.",
]
MENTIONS_AUTOMATION_ONLY = [
    "Could you stop the bot from reformatting unrelated files?",
    "This PR should stop agents from retrying forever.",
    "Don't open the agents module here; keep the change in parser.py.",
    "Please hold off on opening a PR until the AI model refactor lands.",
    "Do not send automated PRs more than once a day.",
    "Automated inputs are not allowed to exceed 10 KiB.",
    "This should stop automated retries from exhausting the rate limit.",
]


@pytest.mark.parametrize("text", TURNS_AWAY_AUTOMATION)
def test_discovery_and_lifecycle_both_hold_the_repository(text: str) -> None:
    assert AUTOMATION_STOP.search(text.replace("\u2019", "'"))
    assert _stop_kind(text) is LifecycleSignalKind.AUTOMATION_STOP
    assert _is_maintainer_stop(text)
    assert _targets_automation(text)


@pytest.mark.parametrize("text", MENTIONS_AUTOMATION_ONLY)
def test_naming_automation_without_turning_it_away_holds_nothing(text: str) -> None:
    assert _stop_kind(text) is not LifecycleSignalKind.AUTOMATION_STOP
    assert not _targets_automation(text)
