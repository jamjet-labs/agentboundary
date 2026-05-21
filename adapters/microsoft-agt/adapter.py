"""Best-effort adapter: Microsoft AGT AuditEntry -> AgentBoundary v0.1 receipt.

Given an AGT ``AuditEntry`` dictionary (per
``microsoft/agent-governance-toolkit`` ``docs/specs/AUDIT-COMPLIANCE-1.0.md``
section 4.2) and optionally a ``DecisionBOM`` plus a workflow approval
event, produce a structurally-valid AgentBoundary v0.1 receipt the suite
can grade. See ``mapping.md`` for translation notes; see ``results.md``
for which conformance scenarios survive the round-trip.

This is intentionally a *lossy* mapping. Fields AGT does not require are
filled with adapter defaults (``"unknown"``, omitted, or computed locally
where the inputs are available). Where lossage compromises a conformance
property, ``results.md`` lists it as NOT COVERED rather than papering
over the gap.
"""

from __future__ import annotations

from typing import Any

from agentboundary.hashing import compute_arguments_hash, compute_receipt_hash


# AGT decision enum -> AgentBoundary policy.decision enum
_DECISION_MAP: dict[str, str] = {
    "allow": "allow",
    "deny": "deny",
    "audit": "allow",       # AGT 'audit' = passed but logged; closest L2 value
    "quarantine": "deny",   # AGT 'quarantine' = stop with stronger consequence
    "warning": "allow",     # AGT 'warning' = passed with a note
}

# AGT outcome -> AgentBoundary execution.status
_OUTCOME_MAP: dict[str, str] = {
    "success": "success",
    "failure": "blocked",
    "denied": "blocked",
    "error": "blocked",
}


def agt_entry_to_receipt(
    entry: dict[str, Any],
    *,
    decision_bom: dict[str, Any] | None = None,
    approval_event: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Translate one AGT AuditEntry into an AgentBoundary v0.1 receipt.

    ``decision_bom`` supplies richer policy + rule provenance when available.
    ``approval_event`` is the workflow-side approval record (out of scope
    for AGT's audit schema), included here so a deployment that DOES track
    approver identity can produce a Level 4-grade receipt.
    """
    receipt_id = entry["entry_id"]
    issued_at = entry["timestamp"]

    actor_id = entry.get("agent_id") or entry.get("agent_did") or "unknown"
    arguments = _extract_arguments(entry)
    arguments_hash = compute_arguments_hash(arguments)

    decision = _DECISION_MAP.get(entry.get("decision", "allow"), "allow")
    outcome = _OUTCOME_MAP.get(entry.get("outcome", "success"), "success")

    receipt: dict[str, Any] = {
        "version": "agentboundary/v0.1",
        "receipt_id": receipt_id,
        "issued_at": issued_at,
        "actor": {
            "type": _infer_actor_type(actor_id),
            "id": actor_id,
        },
        "agent": _build_agent_block(entry, decision_bom),
        "tool": _build_tool_block(entry, decision_bom),
        "target": _build_target_block(entry),
        "arguments_hash": arguments_hash,
        "policy": _build_policy_block(entry, decision_bom),
    }

    if approval_event is not None:
        receipt["approval"] = _build_approval_block(approval_event)

    receipt["execution"] = _build_execution_block(entry, outcome)
    receipt["receipt_hash"] = compute_receipt_hash(receipt)
    return receipt


def _extract_arguments(entry: dict[str, Any]) -> dict[str, Any]:
    """AGT puts tool arguments in entry.data (mesh-level) or
    entry.metadata.args (custom). Prefer data, fall back to metadata.
    Returns an empty dict if neither carries arguments — that empty dict
    has its own stable canonical hash, signalling the loss honestly."""
    data = entry.get("data")
    if isinstance(data, dict):
        # Filter to fields that look like tool inputs vs runtime metadata
        candidate_keys = {k: v for k, v in data.items() if k != "tool"}
        if candidate_keys:
            return candidate_keys
    metadata = entry.get("metadata", {})
    args = metadata.get("args") if isinstance(metadata, dict) else None
    if isinstance(args, dict):
        return args
    return {}


def _infer_actor_type(actor_id: str) -> str:
    """AGT uses DIDs; the method hints at agent vs human vs service."""
    if actor_id.startswith("did:web:") and ("agent" in actor_id or "bot" in actor_id):
        return "agent"
    if actor_id.startswith("did:web:") and ("user" in actor_id or "person" in actor_id):
        return "human"
    # Default: AGT-managed identities are usually agents in practice
    return "agent"


def _build_agent_block(
    entry: dict[str, Any], bom: dict[str, Any] | None
) -> dict[str, Any]:
    metadata = entry.get("metadata", {}) if isinstance(entry.get("metadata"), dict) else {}
    return {
        "framework": metadata.get("framework", "unknown"),
        "framework_version": metadata.get("framework_version", "unknown"),
        "model": metadata.get("model", "unknown"),
    }


def _build_tool_block(
    entry: dict[str, Any], bom: dict[str, Any] | None
) -> dict[str, Any]:
    data = entry.get("data", {}) if isinstance(entry.get("data"), dict) else {}
    metadata = entry.get("metadata", {}) if isinstance(entry.get("metadata"), dict) else {}
    return {
        "name": data.get("tool") or metadata.get("tool_name") or "unknown",
        "version": metadata.get("tool_version", "unknown"),
        "capability": entry.get("event_type", "unknown"),
    }


def _build_target_block(entry: dict[str, Any]) -> dict[str, Any]:
    # AGT collapses target into 'resource'. Split on first '/' to give
    # a system + resource_id; environment defaults to 'prod' (AGT does
    # not normatively distinguish environments at the audit-entry layer).
    resource = entry.get("resource", "unknown")
    if "/" in resource:
        system, _, resource_id = resource.partition("/")
    else:
        system, resource_id = resource, resource
    return {
        "system": system,
        "environment": "prod",
        "resource_id": resource_id,
    }


def _build_policy_block(
    entry: dict[str, Any], bom: dict[str, Any] | None
) -> dict[str, Any]:
    metadata = entry.get("metadata", {}) if isinstance(entry.get("metadata"), dict) else {}
    matched_rule = entry.get("matched_rule") or metadata.get("matched_rule") or "unknown"
    decision = _DECISION_MAP.get(entry.get("decision", "allow"), "allow")
    # AGT carries no normative policy version; mark it 'unknown' rather than
    # fabricate something verifier-checkable.
    return {
        "name": matched_rule,
        "version": "unknown",
        "decision": decision,
    }


def _build_approval_block(approval_event: dict[str, Any]) -> dict[str, Any]:
    """Approval block synthesised from an external workflow event.

    The shape of ``approval_event`` is deployment-specific; this helper
    expects ``{approver_id, approved_at}`` at minimum. Optional fields
    enrich the v0.1 receipt where they exist.
    """
    block: dict[str, Any] = {
        "approver": {"id": approval_event["approver_id"]},
        "approved_at": approval_event["approved_at"],
    }
    if "approver_display_name" in approval_event:
        block["approver"]["display_name"] = approval_event["approver_display_name"]
    if "approver_role" in approval_event:
        block["approver"]["role"] = approval_event["approver_role"]
    if "context" in approval_event:
        block["context"] = approval_event["context"]
    return block


def _build_execution_block(entry: dict[str, Any], outcome: str) -> dict[str, Any]:
    metadata = entry.get("metadata", {}) if isinstance(entry.get("metadata"), dict) else {}
    block: dict[str, Any] = {
        "status": outcome,
        "completed_at": entry["timestamp"],
    }
    if outcome == "success":
        result_ref = metadata.get("result_ref")
        if result_ref:
            block["result_ref"] = result_ref
        else:
            # Spec requires result_ref on success. Fall back to a synthetic
            # ref derived from entry_id so the receipt validates; document
            # the lossage so a verifier knows this came from translation.
            block["result_ref"] = f"agt://{entry['entry_id']}"
    return block
