from pathlib import Path

from typer.testing import CliRunner

from autocontribute.cli import app
from autocontribute.domain import RunStatus
from autocontribute.store import RunStore

runner = CliRunner()


def test_init_and_config_validation_are_offline(tmp_path: Path) -> None:
    config = tmp_path / "autocontribute.yml"

    initialized = runner.invoke(app, ["init", "--path", str(config)])
    validated = runner.invoke(
        app,
        ["config", "validate", "--config", str(config)],
    )

    assert initialized.exit_code == 0, initialized.output
    assert config.is_file()
    assert "Configuration is valid" in validated.output
    assert "gpt-5.6" in validated.output


def test_init_does_not_overwrite_without_force(tmp_path: Path) -> None:
    config = tmp_path / "autocontribute.yml"
    config.write_text("sentinel", encoding="utf-8")

    result = runner.invoke(app, ["init", "--path", str(config)])

    assert result.exit_code == 1
    assert config.read_text(encoding="utf-8") == "sentinel"


def test_expert_evaluation_cli_records_and_reports_shadow_gate(tmp_path: Path) -> None:
    config = tmp_path / "autocontribute.yml"
    state = tmp_path / "state"
    config.write_text(f"storage:\n  path: {state}\n", encoding="utf-8")
    store = RunStore(state)
    run = store.create_run()
    store.transition(run, RunStatus.DISCOVERING, reason="fixture")
    store.transition(run, RunStatus.SKIPPED, reason="fixture")

    recorded = runner.invoke(
        app,
        [
            "eval",
            "record",
            run.run_id,
            "--reviewer",
            "expert",
            "--verdict",
            "correct_abstention",
            "--config",
            str(config),
        ],
    )
    report = runner.invoke(app, ["eval", "report", "--config", str(config), "--json"])

    assert recorded.exit_code == 0, recorded.output
    assert "correct_abstention" in recorded.output
    assert report.exit_code == 0, report.output
    assert '"total_cases": 1' in report.output
    assert '"shadow_gate_passed": false' in report.output
