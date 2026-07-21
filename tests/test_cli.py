from pathlib import Path

from typer.testing import CliRunner

from autocontribute.cli import app

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
