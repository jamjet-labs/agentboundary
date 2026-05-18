"""Tests for the agentboundary CLI (in-process; no subprocess)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from agentboundary.cli import main


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def valid_receipt(tmp_path: Path, examples_dir: Path) -> Path:
    src = examples_dir / "github-merge.json"
    out = tmp_path / "r.json"
    out.write_text(src.read_text())
    return out


class TestVersion:
    def test_version_prints_package_version(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["version"])
        assert result.exit_code == 0
        from agentboundary import __version__

        assert __version__ in result.output


class TestValidate:
    def test_validate_passes_on_valid_receipt(self, runner: CliRunner, valid_receipt: Path) -> None:
        result = runner.invoke(main, ["validate", str(valid_receipt)])
        assert result.exit_code == 0
        assert "valid" in result.output.lower()

    def test_validate_fails_on_invalid_receipt(self, runner: CliRunner, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("{}")
        result = runner.invoke(main, ["validate", str(bad)])
        assert result.exit_code == 1
        assert "invalid" in result.output.lower() or "fail" in result.output.lower()

    def test_validate_emits_json_when_flagged(self, runner: CliRunner, valid_receipt: Path) -> None:
        result = runner.invoke(main, ["validate", "--json", str(valid_receipt)])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["valid"] is True
        assert payload["errors"] == []


class TestRunSingleScenario:
    def test_run_passes_for_happy_path(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["run", "scenarios/01-merge-allow.yaml"])
        assert result.exit_code == 0
        assert "PASS" in result.output
        assert "01-merge-allow" in result.output

    def test_run_passes_for_expected_negative(self, runner: CliRunner) -> None:
        # Scenario 06 EXPECTS a schema failure; the scenario itself should PASS.
        result = runner.invoke(main, ["run", "scenarios/06-missing-policy-block.yaml"])
        assert result.exit_code == 0
        assert "PASS" in result.output

    def test_run_json_mode_emits_structured_document(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["run", "--json", "scenarios/01-merge-allow.yaml"])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["passed"] == 1
        assert payload["failed"] == 0
        assert payload["results"][0]["scenario"] == "01-merge-allow"
        assert payload["results"][0]["passed"] is True


class TestRunDirectory:
    def test_run_all_scenarios(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["run", "scenarios/"])
        assert result.exit_code == 0
        # All 10 should be present in the matrix
        for n in range(1, 11):
            assert f"{n:02d}-" in result.output
        assert "10 passed · 0 failed" in result.output
