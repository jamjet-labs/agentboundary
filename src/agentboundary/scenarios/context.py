"""What a scenario hands the verifier, built in one place.

``agentboundary run`` and the test harness both grade a scenario's receipt
with the context its ``setup`` declares. Building that context in two places
let them drift; both now call these functions.

The verifier in a scenario knows exactly what ``setup`` says. Records the
setup does not list are empty, not missing: no prior receipt_ids, no prior
approvals, no prior receipt hashes. So the Level 4 checks that need those
records run (and pass on an honest receipt) instead of being skipped. A
Level 4 scenario that expects no failure fails on any check that is still
skipped unless it lists that skip in ``expect.allowed_skips``: a skipped
check must not read as a passed one. A scenario that expects failures
passes only when those fire, so a skip cannot make it pass; its skips are
reported but not failed (the frozen v0.1 suite cannot take a new expect
key).
"""

from __future__ import annotations

from typing import Any

from agentboundary.conformance import approval_fingerprint
from agentboundary.runtime import RuntimeOutcome
from agentboundary.scenarios.chain import chain_failure_codes
from agentboundary.scenarios.envelope import envelope_failure_codes
from agentboundary.scenarios.loader import Scenario


def conformance_context(scenario: Scenario, outcome: RuntimeOutcome) -> dict[str, Any]:
    """Keyword arguments for ``check_conformance`` beyond the receipt and level."""
    setup = scenario.setup
    capability = scenario.action.get("tool", {}).get("capability")
    policies = setup.get("policies", [])
    policy_full = next((p for p in policies if capability in p.get("capabilities", [])), None)
    prior_receipt_ids = set(setup.get("prior_receipt_ids", []))
    # The verifier's policy store is every policy the scenario declares.
    policy_store = {(p["name"], p["version"]) for p in policies} or None
    prior_approvals = {
        approval_fingerprint(a["approval"]): a["receipt_hash"]
        for a in setup.get("prior_approvals", [])
    }
    return {
        "arguments": outcome.arguments,
        "policy_full": policy_full,
        "prior_receipt_ids": prior_receipt_ids,
        "policy_store": policy_store,
        "minimum_completeness": setup.get("minimum_completeness"),
        "prior_receipt_hashes": setup.get("prior_receipt_hashes", {}),
        # What the runtime reports it ran with stands in for the target
        # system's own record.
        "executed_arguments": outcome.executed_arguments,
        "prior_approvals": prior_approvals,
    }


def offline_failure_codes(scenario: Scenario, receipt: dict[str, Any]) -> set[str]:
    """Failure codes from the offline verifier: the envelope and the chain, if declared."""
    return envelope_failure_codes(scenario.setup, scenario.action, receipt) | chain_failure_codes(
        scenario.setup, scenario.action, receipt
    )


def skipped_codes(checks: list[Any]) -> list[str]:
    """Codes of the checks that were skipped for want of context."""
    return sorted({c.code for c in checks if c.severity == "info" and "SKIPPED" in c.code})


def unallowed_skips(scenario: Scenario, checks: list[Any]) -> list[str]:
    """Skipped checks a positive Level 4 scenario has not declared in expect.allowed_skips."""
    if scenario.expect.get("conformance_level") != 4 or scenario.expect.get(
        "failures_must_include"
    ):
        return []
    allowed = set(scenario.expect.get("allowed_skips", []))
    return [c for c in skipped_codes(checks) if c not in allowed]
