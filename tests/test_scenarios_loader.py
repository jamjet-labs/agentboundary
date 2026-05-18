"""Tests for the YAML scenario loader + meta-schema validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentboundary.scenarios import Scenario, load_scenario, load_scenarios_dir


@pytest.fixture
def valid_scenario_text() -> str:
    return """\
name: t1
description: minimal scenario
setup:
  policies:
    - name: p
      version: "1"
      rule: allow
      capabilities: [test.cap]
action:
  actor: { type: agent, id: a }
  agent: { framework: f, framework_version: "1", model: m, model_version: "1" }
  tool: { name: t, version: "1", capability: test.cap }
  target: { system: s, environment: test, resource_id: r }
  arguments: { k: v }
expect:
  decision: allow
  conformance_level: 3
  receipt_must_validate: true
"""


def test_loads_valid_scenario(tmp_path: Path, valid_scenario_text: str) -> None:
    path = tmp_path / "t1.yaml"
    path.write_text(valid_scenario_text)
    scenario = load_scenario(path)
    assert isinstance(scenario, Scenario)
    assert scenario.name == "t1"
    assert scenario.path == path
    assert scenario.expect["decision"] == "allow"


def test_meta_schema_rejects_missing_name(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("description: no name\nsetup: {}\naction: {}\nexpect: {}\n")
    with pytest.raises(ValueError) as exc:
        load_scenario(path)
    assert "name" in str(exc.value)


def test_loads_directory_of_scenarios(tmp_path: Path, valid_scenario_text: str) -> None:
    for n in ("a.yaml", "b.yaml"):
        (tmp_path / n).write_text(valid_scenario_text)
    scenarios = load_scenarios_dir(tmp_path)
    assert sorted(s.path.name for s in scenarios) == ["a.yaml", "b.yaml"]


def test_directory_loader_skips_non_yaml(tmp_path: Path, valid_scenario_text: str) -> None:
    (tmp_path / "a.yaml").write_text(valid_scenario_text)
    (tmp_path / "README.md").write_text("hello")
    (tmp_path / "_meta-schema.json").write_text("{}")  # underscore-prefixed = skipped
    scenarios = load_scenarios_dir(tmp_path)
    assert len(scenarios) == 1


def test_path_error_includes_file_location(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("not: valid: yaml: :\n")
    with pytest.raises(ValueError) as exc:
        load_scenario(path)
    assert str(path) in str(exc.value)
