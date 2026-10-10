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


class TestSuiteShape:
    """The v0.1 suite is frozen at 40 scenarios; README, the vendor matrices
    and published write-ups cite that number. New scenarios go in
    scenarios-v0.2-alpha/. These tests keep the numbers in prose honest."""

    _ROOT = Path(__file__).resolve().parent.parent

    def _counts(self) -> tuple[int, int]:
        frozen = len(list((self._ROOT / "scenarios").glob("[0-9]*.yaml")))
        draft = len(list((self._ROOT / "scenarios-v0.2-alpha").glob("[0-9]*.yaml")))
        return frozen, draft

    def test_v01_suite_is_frozen_at_40(self) -> None:
        assert self._counts()[0] == 40

    def test_scenario_numbers_are_unique_across_both_suites(self) -> None:
        names = [
            p.name[:2]
            for d in ("scenarios", "scenarios-v0.2-alpha")
            for p in (self._ROOT / d).rglob("[0-9]*.yaml")
        ]
        assert len(names) == len(set(names))

    def test_frozen_suite_uses_only_setup_keys_a_released_runner_knows(self) -> None:
        """0.2.0a1's meta-schema closes setup; a new key in scenarios/ makes
        that runner reject the whole directory."""
        import yaml

        released = {
            "policies",
            "prior_receipt_ids",
            "seed_receipt_id",
            "minimum_completeness",
            "prior_receipt_hashes",
            "approvals",
        }
        for path in (self._ROOT / "scenarios").glob("[0-9]*.yaml"):
            setup = yaml.safe_load(path.read_text("utf-8"))["setup"]
            assert set(setup) <= released, path.name

    def test_readme_counts_match_the_tree(self) -> None:
        import re

        frozen, draft = self._counts()
        readme = (self._ROOT / "README.md").read_text("utf-8")
        counted = re.findall(
            r"(?<![\w.])(\d+) (?:deterministic )?(?:conformance )?scenarios\b", readme
        )
        assert counted
        assert {int(n) for n in counted} == {frozen}
        drafts = re.findall(r"(?<![\w.])(\d+) v0\.2-alpha (?:draft )?scenarios\b", readme)
        assert drafts
        assert {int(n) for n in drafts} == {draft}


class TestMetaSchemaEnvelopeRules:
    """Scenarios the envelope harness cannot run must fail at load time."""

    _BASE = """\
name: t
setup:
  envelope:
    kid: k
    seed_hex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
{extra_setup}  policies:
    - {{ name: p, version: "1", rule: allow, capabilities: [c] }}
action:
  actor: {{ type: agent, id: a }}
  agent: {{ framework: f, framework_version: "1", model: m }}
  tool: {{ name: t, capability: c }}
  target: {{ system: s, environment: prod }}
  arguments: {{}}
{extra_action}expect: {{}}
"""

    @pytest.mark.parametrize(
        ("extra_setup", "extra_action"),
        [
            ("    issuer: i\n", ""),
            ("    subject: s\n", ""),
            ("", "  envelope_inject:\n    - { op: resign_with_alg }\n"),
            ("", "  envelope_inject:\n    - { op: replace_in_payload, find: a }\n"),
        ],
    )
    def test_rejected_at_load(self, tmp_path: Path, extra_setup: str, extra_action: str) -> None:
        path = tmp_path / "t.yaml"
        path.write_text(self._BASE.format(extra_setup=extra_setup, extra_action=extra_action))
        with pytest.raises(ValueError, match="meta-schema"):
            load_scenario(path)

    def test_complete_envelope_scenario_loads(self, tmp_path: Path) -> None:
        path = tmp_path / "t.yaml"
        path.write_text(
            self._BASE.format(
                extra_setup="    issuer: i\n    subject: s\n",
                extra_action="  envelope_inject:\n    - { op: resign_with_alg, alg: -8 }\n",
            )
        )
        assert load_scenario(path).name == "t"
