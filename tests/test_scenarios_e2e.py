"""End-to-end harness over every scenario file in scenarios/."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from agentboundary.conformance import check_conformance
from agentboundary.runtime import ReferenceImplementation
from agentboundary.scenarios import load_scenarios_dir
from agentboundary.scenarios.context import conformance_context, offline_failure_codes
from agentboundary.validator import validate_receipt


def _scenarios_dir() -> Path:
    """Return the absolute path to the repo-root scenarios/ directory.

    Anchored to ``tests/`` so the harness works regardless of pytest CWD.
    """
    return Path(__file__).resolve().parent.parent / "scenarios"


def _scenarios() -> list[Any]:
    # The frozen v0.1 suite, then the v0.2-alpha draft scenarios. The draft
    # ones live in a sibling directory so a released runner pointed at
    # scenarios/ never meets setup keys its meta-schema does not know.
    draft = _scenarios_dir().parent / "scenarios-v0.2-alpha"
    return load_scenarios_dir(_scenarios_dir()) + load_scenarios_dir(draft)


_SCENARIOS = _scenarios()
_IDS = [s.name for s in _SCENARIOS]


@pytest.mark.parametrize("scenario", _SCENARIOS, ids=_IDS)
def test_scenario_runs_to_its_declared_expectation(scenario) -> None:
    impl = ReferenceImplementation()
    outcome = impl.attempt(scenario.action, setup=scenario.setup)

    expect = scenario.expect
    receipt = outcome.receipt or {}

    # Schema check
    schema_errors = validate_receipt(receipt)
    expects_valid = expect.get("receipt_must_validate", True)
    expects_schema_fail = "SCHEMA_INVALID" in expect.get("failures_must_include", [])

    if expects_valid and not expects_schema_fail:
        assert schema_errors == [], (
            f"{scenario.name}: receipt expected to validate; got {schema_errors}"
        )
    if expects_schema_fail:
        assert schema_errors != [], (
            f"{scenario.name}: scenario asserts SCHEMA_INVALID but receipt validated"
        )

    # Decision check
    if "decision" in expect:
        assert outcome.decision == expect["decision"], (
            f"{scenario.name}: expected decision={expect['decision']!r}, got {outcome.decision!r}"
        )

    # Conformance check
    if expect.get("conformance_level") is not None and receipt:
        level = expect["conformance_level"]
        # Same context the CLI runner builds (scenarios/context.py).
        checks = check_conformance(receipt, level=level, **conformance_context(scenario, outcome))
        actual_fails = {c.code for c in checks if c.severity == "fail"}
        actual_fails |= offline_failure_codes(scenario, receipt)
        for code in expect.get("failures_must_include", []):
            if code == "SCHEMA_INVALID":
                continue  # already asserted above
            assert code in actual_fails, (
                f"{scenario.name}: expected failure code {code} missing from {actual_fails}"
            )
        # If the scenario expects no failures, there must be none.
        if not expect.get("failures_must_include"):
            assert not actual_fails, f"{scenario.name}: unexpected failures {actual_fails}"


def test_harness_runs_both_suites() -> None:
    root = _scenarios_dir().parent
    expected = len(list((root / "scenarios").glob("[0-9]*.yaml"))) + len(
        list((root / "scenarios-v0.2-alpha").glob("[0-9]*.yaml"))
    )
    assert len(_SCENARIOS) == expected
