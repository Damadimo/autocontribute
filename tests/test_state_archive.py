from __future__ import annotations

import hashlib
import io
import sqlite3
import tarfile
from contextlib import closing
from datetime import timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from autocontribute.cli import app
from autocontribute.domain import RunStatus
from autocontribute.exceptions import StateError
from autocontribute.state_archive import export_state, import_state
from autocontribute.store import RunStore

runner = CliRunner()
_PATCH = "diff --git a/x b/x\r\n+kept with CRLF\r\n"


def _state(root: Path) -> tuple[RunStore, str, str]:
    store = RunStore(root)
    waiting = store.create_run()
    store.transition(waiting, RunStatus.DISCOVERING, reason="fixture")
    store.write_artifact(waiting.run_id, "contribution.patch", _PATCH)
    store.write_artifact(waiting.run_id, "nested/notes.txt", "kept")
    finished = store.create_run()
    store.transition(finished, RunStatus.FAILED, reason="fixture")
    store.write_artifact(finished.run_id, "contribution.patch", "left out")
    workspace = store.workspace_dir(waiting.run_id) / "repository"
    workspace.mkdir()
    (workspace / "module.py").write_text("left out", encoding="utf-8")
    return store, waiting.run_id, finished.run_id


def test_export_holds_unfinished_evidence_and_imports_it_byte_for_byte(tmp_path: Path) -> None:
    store, waiting, finished = _state(tmp_path / "source")
    archive = tmp_path / "out" / "state.tar.gz"

    exported = export_state(store, archive)

    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
    names = [member.name for member in members]
    assert names == sorted(names)
    assert {
        "state.sqlite3",
        f"runs/{waiting}/contribution.patch",
        f"runs/{waiting}/manifest.json",
        f"runs/{waiting}/nested/notes.txt",
    } <= set(names)
    assert not [name for name in names if finished in name or "workspaces" in name]
    assert all(
        (member.mtime, member.uid, member.gid, member.mode, member.uname) == (0, 0, 0, 0o644, "")
        for member in members
    )
    assert exported.unfinished_runs == 1
    assert exported.sha256 == hashlib.sha256(archive.read_bytes()).hexdigest()

    target = tmp_path / "restored"
    assert import_state(archive, target) == 0

    restored = RunStore(target)
    restored.verify_event_chains()
    assert restored.get(waiting) == store.get(waiting)
    assert restored.events(finished) == store.events(finished)
    assert (target / "runs" / waiting / "contribution.patch").read_bytes() == _PATCH.encode()
    assert not (target / "runs" / finished).exists()
    assert list((target / "workspaces").iterdir()) == []


def test_export_of_unchanged_state_is_byte_identical(tmp_path: Path) -> None:
    store, _, _ = _state(tmp_path / "source")

    first = export_state(store, tmp_path / "first.tar.gz")
    second = export_state(store, tmp_path / "second.tar.gz")

    assert first == second
    assert (tmp_path / "first.tar.gz").read_bytes() == (tmp_path / "second.tar.gz").read_bytes()


def test_export_refuses_a_symbolic_link_in_run_evidence(tmp_path: Path) -> None:
    store, waiting, _ = _state(tmp_path / "source")
    (store.artifact_dir(waiting) / "linked").symlink_to(tmp_path / "elsewhere")

    with pytest.raises(StateError, match="not a plainly named file or directory"):
        export_state(store, tmp_path / "state.tar.gz")

    assert sorted(path.name for path in tmp_path.iterdir()) == ["source"]


def test_import_replaces_existing_state_only_when_forced(tmp_path: Path) -> None:
    store, waiting, _ = _state(tmp_path / "source")
    archive = tmp_path / "state.tar.gz"
    export_state(store, archive)
    target = tmp_path / "target"
    existing = RunStore(target).create_run()

    with pytest.raises(StateError, match="already holds state; pass --force"):
        import_state(archive, target)
    assert RunStore(target).get(existing.run_id).run_id == existing.run_id

    import_state(archive, target, force=True)

    replaced = RunStore(target)
    with pytest.raises(StateError, match="Unknown run"):
        replaced.get(existing.run_id)
    assert replaced.get(waiting).status is RunStatus.DISCOVERING
    assert sorted(path.name for path in tmp_path.iterdir()) == ["source", "state.tar.gz", "target"]


def test_import_releases_leases_only_when_asked(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "source")
    held = store.acquire_lease("autocontribute.publish", "crashed-job", ttl=timedelta(minutes=15))
    assert held is not None
    archive = tmp_path / "state.tar.gz"
    export_state(store, archive)

    assert import_state(archive, tmp_path / "kept") == 0
    assert import_state(archive, tmp_path / "released", release_leases=True) == 1

    kept = RunStore(tmp_path / "kept").get_lease("autocontribute.publish")
    assert kept is not None and kept.owner == "crashed-job"
    released = RunStore(tmp_path / "released")
    assert released.get_lease("autocontribute.publish") is None
    renewed = released.acquire_lease("autocontribute.publish", "next-job", ttl=timedelta(minutes=1))
    assert renewed is not None and renewed.generation > held.generation


def _database_bytes(tmp_path: Path) -> bytes:
    snapshot = tmp_path / "snapshot.sqlite3"
    RunStore(tmp_path / "database-source").backup(snapshot)
    data = snapshot.read_bytes()
    snapshot.unlink()
    return data


def _file(name: str, data: bytes) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    return info


def _link(name: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = tarfile.SYMTYPE
    info.linkname = "/etc/passwd"
    return info


_RUN = "0123456789abcdef"


@pytest.mark.parametrize(
    ("entries", "message"),
    [
        ([("../escape", b"x")], "unexpected entry '../escape'"),
        ([(f"runs/{_RUN}/../../escape", b"x")], "unexpected entry"),
        ([("runs/not-a-run-id/file", b"x")], "unexpected entry"),
        ([(f"runs/{_RUN}/link", None)], "unexpected entry"),
        ([(f"runs/{_RUN}/patch", b"x")], "has no state.sqlite3"),
        ([("state.sqlite3", b"database"), ("state.sqlite3", b"database")], "repeats"),
        ([("state.sqlite3", b"not a database")], "not usable state"),
    ],
)
def test_import_rejects_unexpected_archives_without_touching_the_target(
    tmp_path: Path,
    entries: list[tuple[str, bytes | None]],
    message: str,
) -> None:
    database = _database_bytes(tmp_path)
    archive = tmp_path / "state.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for name, data in entries:
            if data is None:
                tar.addfile(_link(name))
            else:
                content = database if data == b"database" else data
                tar.addfile(_file(name, content), io.BytesIO(content))
    target = tmp_path / "target"

    with pytest.raises(StateError, match=message):
        import_state(archive, target)

    assert not target.exists()
    assert sorted(path.name for path in tmp_path.iterdir()) == ["database-source", "state.tar.gz"]


def test_import_rejects_a_file_that_is_not_an_archive(tmp_path: Path) -> None:
    archive = tmp_path / "state.tar.gz"
    archive.write_bytes(b"not gzip")

    with pytest.raises(StateError, match="could not be read"):
        import_state(archive, tmp_path / "target")

    assert sorted(path.name for path in tmp_path.iterdir()) == ["state.tar.gz"]


def test_state_commands_round_trip_through_the_cli(tmp_path: Path) -> None:
    source = tmp_path / "source.yml"
    target = tmp_path / "target.yml"
    source.write_text(f"storage:\n  path: {tmp_path / 'source'}\n", encoding="utf-8")
    target.write_text(f"storage:\n  path: {tmp_path / 'target'}\n", encoding="utf-8")
    run = RunStore(tmp_path / "source").create_run()
    archive = tmp_path / "state.tar.gz"

    exported = runner.invoke(
        app,
        ["state", "export", "--output", str(archive), "--config", str(source)],
    )
    imported = runner.invoke(app, ["state", "import", str(archive), "--config", str(target)])
    refused = runner.invoke(app, ["state", "import", str(archive), "--config", str(target)])
    forced = runner.invoke(
        app,
        ["state", "import", str(archive), "--force", "--release-leases", "--config", str(target)],
    )

    assert exported.exit_code == 0, exported.output
    assert "with 1 unfinished run(s)" in exported.output
    assert imported.exit_code == 0, imported.output
    assert refused.exit_code == 1
    assert "pass --force to replace it" in " ".join(refused.output.split())
    assert forced.exit_code == 0, forced.output
    assert "released 0 lease(s)" in " ".join(forced.output.split())
    assert RunStore(tmp_path / "target").get(run.run_id).status is RunStatus.QUEUED


def _saved_run(store: RunStore, status: RunStatus, **fields: object) -> str:
    manifest = store.create_run()
    manifest.status = status
    for name, value in fields.items():
        setattr(manifest, name, value)
    store.save(manifest, event="fixture.saved", details={})
    return manifest.run_id


def _trusted_state(root: Path) -> tuple[RunStore, dict[RunStatus, str]]:
    store = RunStore(root)
    runs = {
        status: _saved_run(store, status)
        for status in (
            RunStatus.READY_FOR_APPROVAL,
            RunStatus.APPROVED,
            RunStatus.SUBMITTING,
            RunStatus.FAILED,
        )
    }
    runs[RunStatus.PR_OPEN] = _saved_run(
        store, RunStatus.PR_OPEN, pull_request_url="https://github.com/example/project/pull/7"
    )
    return store, runs


def _preparation_of(trusted: RunStore, tmp_path: Path) -> RunStore:
    archive = tmp_path / "base.tar.gz"
    export_state(trusted, archive)
    import_state(archive, tmp_path / "prepared")
    return RunStore(tmp_path / "prepared")


def test_append_only_import_takes_what_a_preparation_may_add(tmp_path: Path) -> None:
    trusted, runs = _trusted_state(tmp_path / "trusted")
    prepared = _preparation_of(trusted, tmp_path)
    ready = prepared.get(runs[RunStatus.READY_FOR_APPROVAL])
    prepared.transition(ready, RunStatus.CANCELLED, reason="its review cannot be built")
    approved = prepared.get(runs[RunStatus.APPROVED])
    prepared.transition(approved, RunStatus.CANCELLED, reason="the approval expired")
    published = prepared.get(runs[RunStatus.PR_OPEN])
    prepared.save(published, event="lifecycle.observed", details={})
    added = _saved_run(prepared, RunStatus.READY_FOR_APPROVAL)
    prepared.trip_circuit_breaker(source="maintainer", reason="stop", trigger_hash="d" * 64)
    archive = tmp_path / "prepared.tar.gz"
    export_state(prepared, archive)

    import_state(archive, trusted.root, append_only=True)

    saved = RunStore(trusted.root)
    assert saved.get(added).status is RunStatus.READY_FOR_APPROVAL
    assert saved.get(runs[RunStatus.APPROVED]).status is RunStatus.CANCELLED
    assert saved.get(runs[RunStatus.SUBMITTING]).status is RunStatus.SUBMITTING
    assert saved.circuit_breaker_status().is_tripped


def _forge(prepared: RunStore, runs: dict[RunStatus, str], change: str) -> None:
    if change == "approve":
        ready = prepared.get(runs[RunStatus.READY_FOR_APPROVAL])
        ready.status = RunStatus.APPROVED
        prepared.save(ready, event="forged.approval", details={})
    elif change == "end_submitting":
        submitting = prepared.get(runs[RunStatus.SUBMITTING])
        submitting.status = RunStatus.FAILED
        prepared.save(submitting, event="forged.failure", details={})
    elif change == "forget_pull_request":
        published = prepared.get(runs[RunStatus.PR_OPEN])
        published.pull_request_url = "https://github.com/example/project/pull/8"
        prepared.save(published, event="forged.url", details={})
    elif change == "add_published":
        _saved_run(prepared, RunStatus.PR_OPEN)
    elif change == "end_stop":
        prepared.resume_circuit_breaker(
            actor="forger",
            reason="forged",
            expected_trigger_hash=prepared.circuit_breaker_status().active_revision or "",
        )
    elif change == "rewrite_status_column":
        with closing(sqlite3.connect(prepared.database_path)) as connection, connection:
            connection.execute(
                "UPDATE runs SET status = 'cancelled' WHERE run_id = ?",
                (runs[RunStatus.APPROVED],),
            )


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ("approve", r"\(ready_for_approval to approved\)"),
        ("end_submitting", r"\(submitting to failed\)"),
        ("forget_pull_request", r"rewrites run .* \(pr_open to pr_open\)"),
        ("add_published", "adds run"),
        ("end_stop", "ends a safety stop"),
        ("rewrite_status_column", "disagrees with its state row"),
    ],
)
def test_append_only_import_refuses_what_only_an_approval_or_operator_may_do(
    tmp_path: Path,
    change: str,
    message: str,
) -> None:
    trusted, runs = _trusted_state(tmp_path / "trusted")
    trusted.trip_circuit_breaker(source="maintainer", reason="stop", trigger_hash="c" * 64)
    prepared = _preparation_of(trusted, tmp_path)
    _forge(prepared, runs, change)
    archive = tmp_path / "prepared.tar.gz"
    export_state(prepared, archive)
    before = export_state(trusted, tmp_path / "before.tar.gz").sha256

    with pytest.raises(StateError, match=message):
        import_state(archive, trusted.root, append_only=True)

    assert export_state(RunStore(trusted.root), tmp_path / "after.tar.gz").sha256 == before


def test_append_only_import_refuses_a_fresh_state_in_place_of_saved_work(tmp_path: Path) -> None:
    trusted, runs = _trusted_state(tmp_path / "trusted")
    trusted.trip_circuit_breaker(source="maintainer", reason="stop", trigger_hash="c" * 64)
    archive = tmp_path / "fresh.tar.gz"
    export_state(RunStore(tmp_path / "fresh"), archive)

    with pytest.raises(StateError, match="drops or rewrites"):
        import_state(archive, trusted.root, append_only=True)

    saved = RunStore(trusted.root)
    assert saved.circuit_breaker_status().is_tripped
    assert saved.get(runs[RunStatus.READY_FOR_APPROVAL]).status is RunStatus.READY_FOR_APPROVAL
