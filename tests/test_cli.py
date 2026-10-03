import json
from click.testing import CliRunner
import pytest

from rlcheck.cli import cli


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(cli, ["version"])
    assert result.exit_code == 0
    assert "RLCheck Pro" in result.output
    assert "1.0.0" in result.output


def test_cli_web_safety_restriction():
    runner = CliRunner()
    result = runner.invoke(cli, ["web", "--host", "0.0.0.0"])
    assert result.exit_code == 1
    assert "Safety restriction" in result.output


def test_cli_login_safety_validation_failure():
    runner = CliRunner()
    result = runner.invoke(cli, ["login", "https://example.com", "--attempts", "0"])
    assert result.exit_code == 1
    assert "Safety check failed" in result.output


def test_cli_auth_aborted_without_authorization():
    runner = CliRunner()
    # When prompted for authorization, input 'n'
    result = runner.invoke(cli, ["auth", "https://example.com"], input="n\n")
    assert result.exit_code == 0
    assert "Aborted" in result.output


def test_cli_report_command_json(tmp_path):
    report_data = {
        "tool": "RLCheck Pro",
        "version": "1.0.0",
        "generated_utc": "2026-10-04T00:00:00Z",
        "target": "https://example.com",
        "flow": {},
        "assessment": {"findings": []},
        "evidence": [],
        "timeline": [],
        "test_configuration": {},
    }
    report_file = tmp_path / "test-report.json"
    report_file.write_text(json.dumps(report_data), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["report", str(report_file), "--format", "json"])
    assert result.exit_code == 0
    assert "RLCheck Pro" in result.output


def test_cli_report_command_html(tmp_path):
    report_data = {
        "tool": "RLCheck Pro",
        "version": "1.0.0",
        "generated_utc": "2026-10-04T00:00:00Z",
        "target": "https://example.com",
        "flow": {},
        "assessment": {"findings": [], "overall_confidence": "LOW"},
        "evidence": [],
        "timeline": [],
        "test_configuration": {},
    }
    report_file = tmp_path / "test-report.json"
    report_file.write_text(json.dumps(report_data), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["report", str(report_file), "--format", "html"])
    assert result.exit_code == 0
    html_file = tmp_path / "test-report.html"
    assert html_file.exists()
    assert "HTML report written" in result.output


def test_main_entry_point():
    from unittest.mock import patch
    import rlcheck.main as main_mod

    with patch("rlcheck.main.cli") as mock_cli:
        main_mod.main()
        assert mock_cli.called
