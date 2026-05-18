"""End-to-end CLI tests that spawn real subprocesses.

Marked ``slow`` so they don't run on every push. Enable with:
    hatch test -m slow
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.slow


_REPO_ROOT = Path(__file__).resolve().parent.parent


def _agentboundary(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "agentboundary", *args],
        capture_output=True,
        text=True,
        check=False,
        cwd=_REPO_ROOT,
    )


def test_version_command() -> None:
    r = _agentboundary("version")
    assert r.returncode == 0
    assert "agentboundary " in r.stdout


def test_run_single_scenario() -> None:
    r = _agentboundary("run", "scenarios/01-merge-allow.yaml")
    assert r.returncode == 0
    assert "PASS" in r.stdout


def test_run_directory_all_pass() -> None:
    r = _agentboundary("run", "scenarios/")
    assert r.returncode == 0
    assert "10 passed · 0 failed" in r.stdout


def test_run_json_mode() -> None:
    r = _agentboundary("run", "--json", "scenarios/01-merge-allow.yaml")
    assert r.returncode == 0
    payload = json.loads(r.stdout)
    assert payload["passed"] == 1


def test_validate_command_on_worked_example() -> None:
    r = _agentboundary("validate", "docs/receipts/github-merge.json")
    assert r.returncode == 0
    assert "valid" in r.stdout.lower()


def test_help_text() -> None:
    r = _agentboundary("--help")
    assert r.returncode == 0
    assert "conformance" in r.stdout.lower()
