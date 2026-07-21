import json
from pathlib import Path

import pytest

from autocontribute.domain import RunStatus
from autocontribute.exceptions import StateError
from autocontribute.store import RunStore


def test_store_persists_transitions_and_hash_chains_events(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "state")
    run = store.create_run()

    store.transition(run, RunStatus.DISCOVERING, reason="start")
    store.transition(run, RunStatus.SKIPPED, reason="no worthy candidate")

    loaded = store.get(run.run_id)
    events = store.events(run.run_id)
    assert loaded.status == RunStatus.SKIPPED
    assert len(events) == 3
    assert events[0]["previous_hash"] == "0" * 64
    assert events[1]["previous_hash"] == events[0]["event_hash"]
    assert json.loads(events[-1]["details"])["to"] == "skipped"
    assert (store.artifact_dir(run.run_id) / "manifest.json").is_file()


def test_store_rejects_illegal_transition(tmp_path: Path) -> None:
    store = RunStore(tmp_path)
    run = store.create_run()

    with pytest.raises(StateError, match="Invalid run transition"):
        store.transition(run, RunStatus.PR_OPEN, reason="skip every gate")


def test_artifact_path_cannot_escape_run_directory(tmp_path: Path) -> None:
    store = RunStore(tmp_path)
    run = store.create_run()

    with pytest.raises(StateError, match="escaped"):
        store.write_artifact(run.run_id, "../secret", "no")
