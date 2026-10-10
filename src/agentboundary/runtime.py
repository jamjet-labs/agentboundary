"""Reference implementation of the AgentBoundary v0.1 lifecycle.

This is the bundled implementation that ``agentboundary run`` exercises
out of the box. Third-party implementations plug in as additional
``Implementation`` subclasses via vendor adapters under ``adapters/``.
"""

from __future__ import annotations

import json
import math
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Final, Literal

from agentboundary.conformance import _parse_rfc3339
from agentboundary.hashing import (
    compute_arguments_hash,
    compute_receipt_hash,
)

Decision = Literal["allow", "deny", "require-approval", "escalate"]

V01: Final = "agentboundary/v0.1"
V02_ALPHA: Final = "agentboundary/v0.2-alpha"

# Returned by ``_match_policy`` when no policy in setup covers the requested
# capability. Fail-closed: the action is denied and the receipt records that
# no operator-authored policy participated in the decision.
IMPLICIT_DENY_POLICY: dict[str, Any] = {
    "name": "implicit.deny",
    "version": "0",
    "rule": "deny",
}


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
    """In-memory reference implementation used by the conformance suite.

    By default it emits v0.1 receipts and does not enforce the approval
    window or approver list itself; scenarios 11 and 12 rely on that to hand
    the verifier a receipt with a bad approval. With
    ``setup.receipt_version = "agentboundary/v0.2-alpha"`` it emits v0.2-alpha
    receipts, refuses an action whose approval is stale or from an approver
    the policy does not list, and records every refusal in a ``refusal``
    block (spec v0.2-alpha section 2.3).
    """

    def attempt(self, action: dict[str, Any], *, setup: dict[str, Any]) -> RuntimeOutcome:
        arguments = action.get("arguments", {})
        capability = action.get("tool", {}).get("capability", "")
        emit_v02 = setup.get("receipt_version") == V02_ALPHA
        stamp = setup.get("now") or _now_rfc3339()

        policy = _match_policy(setup.get("policies", []), capability)
        if policy is None:
            # No matching policy = deny by default (fail-closed).
            policy = IMPLICIT_DENY_POLICY

        approvals = setup.get("approvals", [])
        approval_for_cap = next((a for a in approvals if a.get("capability") == capability), None)

        rule = policy["rule"]
        refusal: dict[str, str] | None = None
        if rule == "allow":
            decision: Decision = "allow"
            executed = True
        elif rule == "deny":
            decision = "deny"
            executed = False
            reason = "no-matching-policy" if policy is IMPLICIT_DENY_POLICY else "policy-deny"
            refusal = {"verdict": "deny", "reason_code": reason}
        elif rule == "escalate":
            decision = "escalate"
            executed = False
            refusal = {"verdict": "require-approval", "reason_code": "escalation-unresolved"}
        elif rule == "require-approval":
            problem = (
                _approval_problem(policy, approval_for_cap, stamp)
                if emit_v02 and approval_for_cap is not None
                else None
            )
            if approval_for_cap is None:
                decision = "require-approval"
                executed = False
                refusal = {"verdict": "require-approval", "reason_code": "approval-missing"}
            elif problem is not None:
                decision = "deny"
                executed = False
                refusal = problem
            else:
                decision = "allow"
                executed = True
        else:
            decision = "deny"
            executed = False
            refusal = {"verdict": "deny", "reason_code": "unknown-rule"}

        receipt = _build_receipt(
            action=action,
            arguments=arguments,
            policy=policy,
            policy_decision=rule,
            executed=executed,
            approval=_recordable(approval_for_cap),
            seed_receipt_id=setup.get("seed_receipt_id"),
            now=stamp,
            version=V02_ALPHA if emit_v02 else V01,
            refusal=refusal if emit_v02 else None,
        )

        for op in action.get("inject", []):
            receipt = _apply_inject(receipt, op)

        return RuntimeOutcome(decision=decision, receipt=receipt, arguments=arguments)


def _recordable(approval: dict[str, Any] | None) -> dict[str, Any] | None:
    """Return ``approval`` if the receipt can record it faithfully, else None.

    A receipt's approval block needs an approver with a non-empty string id
    and a string timestamp. An approval without them never authorizes
    anything (the approver check refuses it) and is left out of the receipt
    rather than recorded in a shape the schema rejects.
    """
    if not isinstance(approval, dict):
        return None
    approver = approval.get("approver")
    ok = (
        isinstance(approver, dict)
        and isinstance(approver.get("id"), str)
        and bool(approver.get("id"))
        and isinstance(approval.get("approved_at"), str)
    )
    return approval if ok else None


# How far an approval may postdate the runtime's clock before it is refused.
# A small allowance absorbs skew between the approval system and the runtime;
# beyond it, a forward-dated approval would stretch the window without limit.
APPROVAL_CLOCK_SKEW_SECONDS: Final = 60


def _approval_problem(
    policy: dict[str, Any], approval: dict[str, Any], now: str
) -> dict[str, str] | None:
    """Return a refusal if ``approval`` does not authorize the action under ``policy``.

    Checks the approver list first (who), then the approval window (when).
    Every guard is written positively, so a value it cannot evaluate (a
    missing or non-string id, an unparseable timestamp, a NaN or non-numeric
    window) refuses rather than passes.
    """
    approvers = policy.get("approvers")
    if approvers is not None:
        allowed = {
            a.get("id")
            for a in (approvers if isinstance(approvers, list) else [])
            if isinstance(a, dict) and isinstance(a.get("id"), str) and a.get("id")
        }
        approver = approval.get("approver")
        approver_id = approver.get("id") if isinstance(approver, dict) else None
        if not (isinstance(approver_id, str) and approver_id in allowed):
            return {"verdict": "deny", "reason_code": "approver-not-authorized"}

    max_age = policy.get("approval_max_age_seconds")
    if max_age is not None:
        usable = (type(max_age) is int and max_age >= 0) or (
            type(max_age) is float and math.isfinite(max_age) and max_age >= 0
        )
        if not usable:
            return {"verdict": "deny", "reason_code": "approval-window-invalid"}
        approved_at = _parse_rfc3339(approval.get("approved_at"))
        current = _parse_rfc3339(now)
        if approved_at is None or current is None:
            return {"verdict": "deny", "reason_code": "approval-time-unreadable"}
        age = (current - approved_at).total_seconds()
        if not age >= -APPROVAL_CLOCK_SKEW_SECONDS:
            return {"verdict": "deny", "reason_code": "approval-postdates-action"}
        if not age <= max_age:
            return {"verdict": "expired", "reason_code": "approval-window-elapsed"}
    return None


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
    policy_decision: str,
    executed: bool,
    approval: dict[str, Any] | None,
    seed_receipt_id: str | None = None,
    now: str | None = None,
    version: str = "agentboundary/v0.1",
    refusal: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Assemble an Action Receipt for the given action + policy outcome.

    ``policy_decision`` records the POLICY RULE that fired (e.g.
    "require-approval", "allow"). This is intentionally distinct from
    the RUNTIME OUTCOME (``RuntimeOutcome.decision``), which can differ
    when a require-approval policy is satisfied by a pre-existing
    approval block — in that case ``policy_decision="require-approval"``
    while ``RuntimeOutcome.decision="allow"``. Scenarios depend on the
    bifurcation; do not flatten it.

    ``now`` pins the clock (an RFC 3339 string) for ``issued_at`` and
    ``execution.completed_at``. Scenarios that test a time window set it so
    the outcome does not depend on when the suite runs.
    """
    stamp = now or _now_rfc3339()
    receipt: dict[str, Any] = {
        "version": version,
        "receipt_id": seed_receipt_id or str(uuid.uuid4()),
        "issued_at": stamp,
        "actor": action["actor"],
        "agent": action["agent"],
        "tool": action["tool"],
        "target": action["target"],
        "arguments_hash": compute_arguments_hash(arguments),
        "policy": {
            "name": policy["name"],
            "version": policy["version"],
            "decision": policy_decision,
        },
    }
    if approval is not None:
        # Translate setup-shape approver ({type, id}) to schema-shape approver
        # ({id, display_name?, role?}). Setup's "type" is metadata for matching;
        # the receipt records only what the schema permits.
        setup_approver = approval["approver"]
        receipt_approver: dict[str, Any] = {"id": setup_approver["id"]}
        if "display_name" in setup_approver:
            receipt_approver["display_name"] = setup_approver["display_name"]
        if "role" in setup_approver:
            receipt_approver["role"] = setup_approver["role"]
        approval_block: dict[str, Any] = {
            "approver": receipt_approver,
            "approved_at": approval["approved_at"],
        }
        # Schema requires approval.context to be a string. Setup commonly carries
        # a structured context object; collapse it to a deterministic string
        # representation so the receipt validates.
        ctx = approval.get("context")
        if ctx is not None:
            if isinstance(ctx, str):
                approval_block["context"] = ctx
            else:
                approval_block["context"] = json.dumps(ctx, sort_keys=True, separators=(",", ":"))
        receipt["approval"] = approval_block
    if executed:
        receipt["execution"] = {
            "status": "success",
            "completed_at": stamp,
            "result_ref": f"ref:{receipt['receipt_id'][:8]}",
        }
    else:
        # Spec §3.3/§3.5: deny/escalate/require-approval still emit an
        # execution block with status=blocked so receipts have a uniform shape.
        receipt["execution"] = {
            "status": "blocked",
            "completed_at": stamp,
        }
    if refusal is not None:
        receipt["refusal"] = dict(refusal)
    receipt["receipt_hash"] = compute_receipt_hash(receipt)
    return receipt


def _apply_inject(receipt: dict[str, Any], op: dict[str, Any]) -> dict[str, Any]:
    """Apply one inject op to ``receipt``. Returns the (possibly mutated) receipt dict.

    Inject ops are used by negative-path scenarios (06-10) to simulate
    real-world receipt corruption: a missing field, a malformed value, or
    a tampered hash. The reference implementation honours the inject AFTER
    emitting a fully-formed valid receipt, so each negative scenario isolates
    exactly one failure mode.

    ``path`` for ``omit_field`` / ``mutate_field`` accepts dotted segments
    (``execution.completed_at``) so scenarios can target nested fields without
    needing a bespoke op per leaf. Hash tamperers stay specific because they
    must recompute the digest in a known-bad way.
    """
    kind = op["op"]
    if kind == "omit_field":
        _delete_path(receipt, op["path"])
        if op.get("recompute_hash"):
            receipt.pop("receipt_hash", None)
            receipt["receipt_hash"] = compute_receipt_hash(receipt)
        return receipt
    if kind == "mutate_field":
        _set_path(receipt, op["path"], op["value"])
        # When the scenario wants to isolate a semantic failure (e.g. a
        # timeline violation) rather than the L3 hash-mismatch cascade,
        # ``recompute_hash: true`` re-digests the mutated receipt so it
        # looks internally consistent. The L4 invariants then catch the
        # planted lie on its own merits.
        if op.get("recompute_hash"):
            receipt.pop("receipt_hash", None)
            receipt["receipt_hash"] = compute_receipt_hash(receipt)
        return receipt
    if kind == "tamper_arguments_hash":
        # Flip the first hex byte; result is still 64-char hex but no longer
        # matches the canonical-JSON SHA-256 of the original arguments.
        current = receipt.get("arguments_hash", "0" * 64)
        receipt["arguments_hash"] = _flip_first_hex_byte(current)
        return receipt
    if kind == "tamper_receipt_hash":
        current = receipt.get("receipt_hash", "0" * 64)
        receipt["receipt_hash"] = _flip_first_hex_byte(current)
        return receipt
    raise ValueError(f"unknown inject op: {kind}")


def _split_path(path: str) -> list[str]:
    return [p for p in path.split(".") if p]


def _delete_path(receipt: dict[str, Any], path: str) -> None:
    """Delete the leaf at ``path``; no-op if any segment is missing."""
    parts = _split_path(path)
    if not parts:
        return
    cursor: Any = receipt
    for seg in parts[:-1]:
        if not isinstance(cursor, dict) or seg not in cursor:
            return
        cursor = cursor[seg]
    if isinstance(cursor, dict):
        cursor.pop(parts[-1], None)


def _set_path(receipt: dict[str, Any], path: str, value: Any) -> None:
    """Set the leaf at ``path`` to ``value``, creating intermediate dicts if needed."""
    parts = _split_path(path)
    if not parts:
        return
    cursor: Any = receipt
    for seg in parts[:-1]:
        nxt = cursor.get(seg)
        if not isinstance(nxt, dict):
            nxt = {}
            cursor[seg] = nxt
        cursor = nxt
    cursor[parts[-1]] = value


def _flip_first_hex_byte(h: str) -> str:
    """Return ``h`` with its first hex character XOR-flipped (still valid hex)."""
    if not h:
        return "f" * 64
    first = h[0]
    flipped = format(int(first, 16) ^ 0xF, "x")
    return flipped + h[1:]
