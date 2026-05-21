"""End-to-end harness over every scenario file in scenarios/."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from agentboundary.conformance import check_conformance
from agentboundary.runtime import ReferenceImplementation
from agentboundary.scenarios import load_scenarios_dir
from agentboundary.validator import validate_receipt


def _scenarios_dir() -> Path:
    """Return the absolute path to the repo-root scenarios/ directory.

    Anchored to ``tests/`` so the harness works regardless of pytest CWD.
    """
    return Path(__file__).resolve().parent.parent / "scenarios"


def _scenarios() -> list[Any]:
    return load_scenarios_dir(_scenarios_dir())


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
        # Level 4 reads the matching policy and prior-receipt set out of setup
        # so scenarios can declare adversarial context inline. For L<=3 these
        # extras are ignored by check_conformance.
        capability = scenario.action.get("tool", {}).get("capability")
        policy_full = next(
            (
                p
                for p in scenario.setup.get("policies", [])
                if capability in p.get("capabilities", [])
            ),
            None,
        )
        prior_receipt_ids: set[str] | None = (
            set(scenario.setup["prior_receipt_ids"])
            if "prior_receipt_ids" in scenario.setup
            else None
        )
        # The verifier's policy store is the union of declared policies in
        # the scenario's setup — everything the scenario considers known-good.
        policy_store = {
            (p["name"], p["version"]) for p in scenario.setup.get("policies", [])
        } or None
        minimum_completeness = scenario.setup.get("minimum_completeness")
        prior_receipt_hashes = scenario.setup.get("prior_receipt_hashes")
        checks = check_conformance(
            receipt,
            level=level,
            arguments=outcome.arguments,
            policy_full=policy_full,
            prior_receipt_ids=prior_receipt_ids,
            policy_store=policy_store,
            minimum_completeness=minimum_completeness,
            prior_receipt_hashes=prior_receipt_hashes,
        )
        actual_fails = {c.code for c in checks if c.severity == "fail"}
        for code in expect.get("failures_must_include", []):
            if code == "SCHEMA_INVALID":
                continue  # already asserted above
            assert code in actual_fails, (
                f"{scenario.name}: expected failure code {code} missing from {actual_fails}"
            )
        # If the scenario expects no failures, there must be none.
        if not expect.get("failures_must_include"):
            assert not actual_fails, f"{scenario.name}: unexpected failures {actual_fails}"
