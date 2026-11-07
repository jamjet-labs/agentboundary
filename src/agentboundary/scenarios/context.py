"""What a scenario hands the verifier, built in one place.

``agentboundary run`` and the test harness both grade a scenario's receipt
with the context its ``setup`` declares. Building that context in two places
let them drift; both now call these functions.
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
    prior_receipt_ids = set(setup["prior_receipt_ids"]) if "prior_receipt_ids" in setup else None
    # The verifier's policy store is every policy the scenario declares.
    policy_store = {(p["name"], p["version"]) for p in policies} or None
    prior_approvals = (
        {approval_fingerprint(a["approval"]): a["receipt_hash"] for a in setup["prior_approvals"]}
        if "prior_approvals" in setup
        else None
    )
    return {
        "arguments": outcome.arguments,
        "policy_full": policy_full,
        "prior_receipt_ids": prior_receipt_ids,
        "policy_store": policy_store,
        "minimum_completeness": setup.get("minimum_completeness"),
        "prior_receipt_hashes": setup.get("prior_receipt_hashes"),
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
