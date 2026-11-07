"""A Level 4 scenario must not pass on a check that was skipped."""

from __future__ import annotations

from pathlib import Path

import yaml

from agentboundary.cli import _run_one
from agentboundary.runtime import ReferenceImplementation
from agentboundary.scenarios import load_scenario

ROOT = Path(__file__).resolve().parent.parent


def _run(path: Path) -> dict:
    return _run_one(load_scenario(path), ReferenceImplementation())


def test_run_result_lists_skipped_checks() -> None:
    result = _run(ROOT / "scenarios/17-approval-inside-window.yaml")
    assert "skipped" in result
    assert "LEVEL_4_SKIPPED_NO_PRIOR_APPROVALS" not in result["skipped"]
    assert "LEVEL_4_SKIPPED_NO_PRIOR_RECEIPTS" not in result["skipped"]


def test_replay_check_runs_in_scenario_38() -> None:
    result = _run(ROOT / "scenarios/38-approval-without-context.yaml")
    assert result["passed"], result
    assert result["skipped"] == []


def _positive_l4_without_policies(tmp_path: Path, **expect: object) -> Path:
    scenario = yaml.safe_load((ROOT / "scenarios/01-merge-allow.yaml").read_text())
    scenario["setup"] = {}  # no policy: implicit deny, and no policy context
    scenario["expect"] = {"decision": "deny", "conformance_level": 4, **expect}
    path = tmp_path / "s.yaml"
    path.write_text(yaml.safe_dump(scenario))
    return path


def test_unallowed_skip_fails_a_positive_level_4_scenario(tmp_path: Path) -> None:
    result = _run(_positive_l4_without_policies(tmp_path))
    assert not result["passed"]
    assert any("LEVEL_4_SKIPPED_NO_POLICY_STORE" in f for f in result["failures"])


def test_declared_skips_are_allowed_and_still_reported(tmp_path: Path) -> None:
    allowed = ["LEVEL_4_SKIPPED_NO_POLICY_CONTEXT", "LEVEL_4_SKIPPED_NO_POLICY_STORE"]
    result = _run(_positive_l4_without_policies(tmp_path, allowed_skips=allowed))
    assert result["passed"], result
    assert result["skipped"] == allowed


def test_an_allowance_that_never_matches_fails(tmp_path: Path) -> None:
    allowed = [
        "LEVEL_4_SKIPPED_NO_POLICY_CONTEXT",
        "LEVEL_4_SKIPPED_NO_POLICY_STORE",
        "LEVEL_4_SKIPPED_NO_PRIOR_APPROVALS",  # not skipped: stale allowance
    ]
    result = _run(_positive_l4_without_policies(tmp_path, allowed_skips=allowed))
    assert not result["passed"]
    assert any("LEVEL_4_SKIPPED_NO_PRIOR_APPROVALS" in f for f in result["failures"])


def test_checks_against_empty_records_are_marked() -> None:
    result = _run(ROOT / "scenarios/38-approval-without-context.yaml")
    assert result["passed"], result
    notes = " ".join(result["empty_context"])
    assert "0 prior approvals" in notes
    assert "0 prior receipt ids" in notes
