"""Reference implementation of the AgentBoundary v0.1 lifecycle.

This is the bundled implementation that ``agentboundary run`` exercises
out of the box. Third-party implementations (Microsoft AGT, Statis, etc.)
plug in as additional ``Implementation`` subclasses in W7+.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal

from agentboundary.hashing import compute_arguments_hash, compute_receipt_hash

Decision = Literal["allow", "deny", "require-approval", "escalate"]


@dataclass(frozen=True)
class RuntimeOutcome:
    """Result of a single ``Implementation.attempt`` call.

    ``decision`` is the runtime outcome (the action ran or not).
    ``receipt`` is the emitted Action Receipt, or None if the
    implementation chose not to emit one.
    ``arguments`` is the original arguments object (kept so
    conformance checks can recompute the arguments_hash).
    """

    decision: Decision
    receipt: dict[str, Any] | None
    arguments: dict[str, Any]


class Implementation(ABC):
    """Abstract base for AgentBoundary implementations under test."""

    @abstractmethod
    def attempt(self, action: dict[str, Any], *, setup: dict[str, Any]) -> RuntimeOutcome:
        """Process ``action`` under ``setup`` and return the outcome."""


class ReferenceImplementation(Implementation):
    """In-memory reference implementation used by the W3 conformance suite."""

    def attempt(self, action: dict[str, Any], *, setup: dict[str, Any]) -> RuntimeOutcome:
        arguments = action.get("arguments", {})
        capability = action.get("tool", {}).get("capability", "")

        policy = _match_policy(setup.get("policies", []), capability)
        if policy is None:
            # No matching policy = deny by default (fail-closed).
            policy = {"name": "implicit.deny", "version": "0", "rule": "deny"}

        approvals = setup.get("approvals", [])
        approval_for_cap = next((a for a in approvals if a.get("capability") == capability), None)

        rule = policy["rule"]
        if rule == "allow":
            decision: Decision = "allow"
            executed = True
        elif rule == "deny":
            decision = "deny"
            executed = False
        elif rule == "escalate":
            decision = "escalate"
            executed = False
        elif rule == "require-approval":
            if approval_for_cap is not None:
                decision = "allow"
                executed = True
            else:
                decision = "require-approval"
                executed = False
        else:
            decision = "deny"
            executed = False

        receipt = _build_receipt(
            action=action,
            arguments=arguments,
            policy=policy,
            decision=rule,  # policy.decision in the receipt = the rule itself
            executed=executed,
            approval=approval_for_cap,
        )

        return RuntimeOutcome(decision=decision, receipt=receipt, arguments=arguments)


def _match_policy(policies: list[dict[str, Any]], capability: str) -> dict[str, Any] | None:
    """Return the first policy whose ``capabilities`` list contains ``capability``."""
    for p in policies:
        if capability in p.get("capabilities", []):
            return p
    return None


def _now_rfc3339() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_receipt(
    *,
    action: dict[str, Any],
    arguments: dict[str, Any],
    policy: dict[str, Any],
    decision: str,
    executed: bool,
    approval: dict[str, Any] | None,
) -> dict[str, Any]:
    receipt: dict[str, Any] = {
        "version": "agentboundary/v0.1",
        "receipt_id": str(uuid.uuid4()),
        "issued_at": _now_rfc3339(),
        "actor": action["actor"],
        "agent": action["agent"],
        "tool": action["tool"],
        "target": action["target"],
        "arguments_hash": compute_arguments_hash(arguments),
        "policy": {
            "name": policy["name"],
            "version": policy["version"],
            "decision": decision,
        },
    }
    if approval is not None:
        receipt["approval"] = {
            "approver": approval["approver"],
            "approved_at": approval["approved_at"],
            "context": approval.get("context", {}),
        }
    if executed:
        receipt["execution"] = {
            "status": "success",
            "completed_at": _now_rfc3339(),
            "result_ref": f"ref:{receipt['receipt_id'][:8]}",
        }
    receipt["receipt_hash"] = compute_receipt_hash(receipt)
    return receipt
