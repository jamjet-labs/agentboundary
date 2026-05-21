"""Best-effort adapter: Microsoft AGT AuditEntry -> AgentBoundary receipt.

Given an AGT ``AuditEntry`` dictionary (per
``microsoft/agent-governance-toolkit`` ``docs/specs/AUDIT-COMPLIANCE-1.0.md``
section 4.2) and optionally a ``DecisionBOM`` plus a workflow approval
event, produce a structurally-valid AgentBoundary receipt the suite can
grade. See ``mapping.md`` for translation notes; see ``results.md`` for
which conformance scenarios survive the round-trip.

This is intentionally a *lossy* mapping. Fields AGT does not require are
filled with adapter defaults (``"unknown"``, omitted, or computed locally
where the inputs are available). Where lossage compromises a conformance
property, ``results.md`` lists it as NOT COVERED rather than papering
over the gap.

Output format defaults to v0.2-alpha with a populated ``provenance`` block
so a verifier can see at a glance which fields came from AGT directly and
which the adapter synthesized. Pass ``schema_version="agentboundary/v0.1"``
to produce a v0.1 receipt instead (no provenance, smaller surface) for
callers that haven't migrated.
"""

from __future__ import annotations

from typing import Any

from agentboundary.hashing import compute_arguments_hash, compute_receipt_hash
from agentboundary.provenance import compute_completeness_score

# AGT decision enum -> AgentBoundary policy.decision enum
_DECISION_MAP: dict[str, str] = {
    "allow": "allow",
    "deny": "deny",
    "audit": "allow",  # AGT 'audit' = passed but logged; closest L2 value
    "quarantine": "deny",  # AGT 'quarantine' = stop with stronger consequence
    "warning": "allow",  # AGT 'warning' = passed with a note
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
    schema_version: str = "agentboundary/v0.2-alpha",
    prior_entry_id: str | None = None,
) -> dict[str, Any]:
    """Translate one AGT AuditEntry into an AgentBoundary receipt.

    ``decision_bom`` supplies richer policy + rule provenance when available.
    ``approval_event`` is the workflow-side approval record (out of scope
    for AGT's audit schema), included here so a deployment that DOES track
    approver identity can produce a Level 4-grade receipt.

    ``schema_version`` defaults to v0.2-alpha. v0.2-alpha receipts include
    a populated provenance block + computed completeness_score so a
    verifier can see exactly which fields the adapter synthesized vs
    pulled from AGT directly. Pass ``"agentboundary/v0.1"`` to suppress
    the provenance fields.

    ``prior_entry_id`` is the AGT entry_id of the immediately preceding
    audit entry. When supplied alongside the entry's ``previous_hash``
    field, the adapter populates AgentBoundary's ``prior_receipt`` link
    so the Merkle-style chain check works. AGT's audit log records
    ``previous_hash`` natively but does NOT record the prior entry_id;
    the caller (or a chain-walking driver) supplies it.
    """
    receipt_id = entry["entry_id"]
    issued_at = entry["timestamp"]

    actor_id = entry.get("agent_id") or entry.get("agent_did") or "unknown"
    arguments = _extract_arguments(entry)
    arguments_hash = compute_arguments_hash(arguments)

    # `decision` is computed by _build_policy_block from the same entry;
    # only `outcome` is used at this level (passed into _build_execution_block).
    outcome = _OUTCOME_MAP.get(entry.get("outcome", "success"), "success")

    receipt: dict[str, Any] = {
        "version": schema_version,
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

    # Chain link: AGT carries previous_hash natively but not the prior
    # entry_id. When the caller supplies prior_entry_id, the adapter
    # builds the v0.2-alpha prior_receipt block.
    prior_hash = entry.get("previous_hash")
    if (
        schema_version == "agentboundary/v0.2-alpha"
        and prior_entry_id
        and isinstance(prior_hash, str)
    ):
        receipt["prior_receipt"] = {
            "receipt_id": prior_entry_id,
            "receipt_hash": prior_hash,
        }

    if schema_version == "agentboundary/v0.2-alpha":
        receipt["provenance"] = _build_provenance(entry, approval_event, prior_entry_id)
        receipt["completeness_score"] = compute_completeness_score(receipt)

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


def _build_agent_block(entry: dict[str, Any], bom: dict[str, Any] | None) -> dict[str, Any]:
    metadata = entry.get("metadata", {}) if isinstance(entry.get("metadata"), dict) else {}
    return {
        "framework": metadata.get("framework", "unknown"),
        "framework_version": metadata.get("framework_version", "unknown"),
        "model": metadata.get("model", "unknown"),
    }


def _build_tool_block(entry: dict[str, Any], bom: dict[str, Any] | None) -> dict[str, Any]:
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


def _build_policy_block(entry: dict[str, Any], bom: dict[str, Any] | None) -> dict[str, Any]:
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


def _build_provenance(
    entry: dict[str, Any],
    approval_event: dict[str, Any] | None,
    prior_entry_id: str | None = None,
) -> dict[str, str]:
    """Honestly tag each receipt field by what the adapter actually had.

    Rules:
    - AGT-required fields (entry_id, timestamp, agent_id, decision, outcome)
      map straight across -> ``observed``
    - Fields the adapter derives deterministically from AGT data
      (actor.type from DID method; tool.capability from event_type;
      target.{system,resource_id} from resource splitting) -> ``inferred``
    - Fields AGT does not require (tool.version, policy.version, agent
      metadata, target.environment default, execution.result_ref synthetic)
      -> ``synthesized``
    - Approval block fields are ``observed`` iff approval_event was supplied
    """
    metadata = entry.get("metadata", {}) if isinstance(entry.get("metadata"), dict) else {}
    data = entry.get("data", {}) if isinstance(entry.get("data"), dict) else {}

    prov: dict[str, str] = {
        # Adapter-side translation: receipt_id and issued_at are direct
        # copies from AGT's entry_id and timestamp -> observed.
        "receipt_id": "observed",
        "issued_at": "observed",
        # Actor: id comes directly from agent_id; type is inferred from DID
        # method conventions (no normative AGT enum).
        "actor.type": "inferred",
        "actor.id": "observed",
        # Agent block: framework/version/model usually live in custom
        # metadata. If present, observed; if missing, synthesized to "unknown".
        "agent.framework": "observed" if metadata.get("framework") else "synthesized",
        "agent.framework_version": "observed"
        if metadata.get("framework_version")
        else "synthesized",
        "agent.model": "observed" if metadata.get("model") else "synthesized",
        # Tool block:
        # - name: AGT sample shape puts tool name in data.tool; observed when present
        # - capability: derived from AGT's event_type enum -> inferred
        "tool.name": "observed"
        if (data.get("tool") or metadata.get("tool_name"))
        else "synthesized",
        "tool.capability": "inferred",
        # Target block: AGT collapses target into one 'resource' string.
        # Splitting on / to derive system+resource_id is deterministic -> inferred.
        # AGT has no environment field; the adapter defaults to "prod" -> synthesized.
        "target.system": "inferred",
        "target.environment": "synthesized",
        # arguments_hash: computed from data field at translation time -> observed
        # (the adapter saw the raw arguments and hashed them itself).
        "arguments_hash": "observed",
        # Policy block:
        # - name: maps to AGT's matched_rule -> observed
        # - version: AGT has no version field -> always synthesized
        # - decision: maps from AGT's decision enum -> observed
        "policy.name": "observed" if entry.get("matched_rule") else "synthesized",
        "policy.version": "synthesized",
        "policy.decision": "observed",
        # Execution: status/completed_at map straight across.
        # AGT only has one timestamp so completed_at == issued_at -> inferred
        # because the verifier reading the receipt should know the time was
        # the audit-entry timestamp, not a separate execution-finish timestamp.
        "execution.status": "observed",
        "execution.completed_at": "inferred",
    }

    # Conditional paths: only set provenance for fields that will actually appear.
    if metadata.get("model_version"):
        prov["agent.model_version"] = "observed"
    if metadata.get("tool_version"):
        prov["tool.version"] = "observed"
    # target.resource_id is always derived if resource has '/' -> inferred when present
    resource = entry.get("resource", "")
    if isinstance(resource, str) and "/" in resource:
        prov["target.resource_id"] = "inferred"

    if entry.get("outcome") == "success":
        # result_ref is observed when AGT metadata.result_ref exists; otherwise
        # synthesized (the adapter falls back to "agt://<entry_id>")
        prov["execution.result_ref"] = "observed" if metadata.get("result_ref") else "synthesized"

    if approval_event is not None:
        prov["approval.approver.id"] = "observed"
        prov["approval.approved_at"] = "observed"
        if approval_event.get("approver_display_name"):
            prov["approval.approver.display_name"] = "observed"
        if approval_event.get("approver_role"):
            prov["approval.approver.role"] = "observed"
        if approval_event.get("context"):
            prov["approval.context"] = "observed"

    # Chain link provenance: AGT carries previous_hash natively (observed)
    # but the prior entry_id is caller-supplied (the adapter does not see
    # AGT's earlier entries on its own).
    prior_hash = entry.get("previous_hash")
    if prior_entry_id and isinstance(prior_hash, str):
        prov["prior_receipt.receipt_id"] = "inferred"
        prov["prior_receipt.receipt_hash"] = "observed"

    return prov


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
