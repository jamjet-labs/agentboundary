"""Adapter: Cloudflare HITL approval_audit row -> AgentBoundary v0.2-alpha.

Cloudflare's HITL is a workflow primitive, not an emitted artifact format.
The SDK does not prescribe a structured audit record; the documentation
recommends developers persist their own via ``this.sql`` using a 6-column
suggested schema. This adapter takes one such row plus the surrounding
tool-call context (what the agent had in scope at decision time) and
produces a structurally-valid AgentBoundary v0.2-alpha receipt.

The adapter is intentionally honest about translation losses: nearly all
v0.2-alpha receipt fields not in the audit row are tagged ``synthesized``
in ``provenance``. A Cloudflare-using team that wants high-quality
receipts should populate ``tool_call_context`` from their own captured
state — denormalising what the recommended audit row doesn't carry.

See ``mapping.md`` for the field-by-field translation; ``results.md`` for
the conformance grade.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, TypedDict
from uuid import uuid4

from agentboundary.hashing import compute_arguments_hash, compute_receipt_hash
from agentboundary.provenance import compute_completeness_score


# Cloudflare's recommended approval_audit row shape.
class ApprovalAuditRow(TypedDict):
    """One row from the developer-implemented approval_audit table.

    Matches the SQL schema recommended in
    https://developers.cloudflare.com/agents/guides/human-in-the-loop/
    """

    id: int
    workflow_id: str
    decision: str  # "approved" | "rejected"
    decided_by: str
    decided_at: int  # millis since epoch
    reason: str | None


# Tool-call context the agent had in scope at decision time. Must be
# threaded externally because Cloudflare's audit row carries none of it.
class ToolCallContext(TypedDict, total=False):
    actor_id: str
    actor_type: str  # "human" | "system" | "agent"
    actor_display_name: str
    agent_framework: str
    agent_framework_version: str
    agent_model: str
    agent_model_version: str
    tool_name: str
    tool_version: str
    tool_capability: str
    target_system: str
    target_environment: str  # "prod" | "staging" | "dev"
    target_resource_id: str
    arguments: dict[str, Any]
    policy_name: str
    policy_version: str
    # Execution outcome — captured AFTER the approved tool's `execute` ran
    execution_status: str  # "success" | "failure" | "blocked"
    execution_completed_at: str  # RFC 3339
    execution_result_ref: str
    execution_error_code: str


_DECISION_MAP: dict[str, str] = {
    "approved": "allow",
    "rejected": "deny",
}


def cloudflare_audit_to_receipt(
    row: ApprovalAuditRow,
    *,
    context: ToolCallContext | None = None,
    prior_receipt: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Translate one Cloudflare approval_audit row into an AgentBoundary v0.2-alpha receipt.

    ``context`` carries the tool-call state Cloudflare doesn't put in
    the audit row. Omitted fields are synthesized to sensible defaults
    and tagged ``synthesized`` in provenance — the receipt validates but
    a verifier sees exactly where the translation reached.

    ``prior_receipt`` is the AgentBoundary chain link to the previous
    receipt this emitter produced. Cloudflare has no chain primitive;
    the adapter caller must maintain this state externally.
    """
    ctx: ToolCallContext = context or {}
    decision = _DECISION_MAP.get(row["decision"], "deny")
    issued_at = _millis_to_rfc3339(row["decided_at"])
    arguments = ctx.get("arguments", {})

    actor = {
        "type": ctx.get("actor_type", "agent"),
        "id": ctx.get("actor_id") or _synthetic_actor_id(row["workflow_id"]),
    }
    if "actor_display_name" in ctx:
        actor["display_name"] = ctx["actor_display_name"]

    agent = {
        "framework": ctx.get("agent_framework", "cloudflare-agents"),
        "framework_version": ctx.get("agent_framework_version", "unknown"),
        "model": ctx.get("agent_model", "unknown"),
    }
    if "agent_model_version" in ctx:
        agent["model_version"] = ctx["agent_model_version"]

    tool: dict[str, Any] = {
        "name": ctx.get("tool_name", "unknown"),
        "capability": ctx.get(
            "tool_capability", f"cloudflare.tool.{ctx.get('tool_name', 'unknown')}"
        ),
    }
    if "tool_version" in ctx:
        tool["version"] = ctx["tool_version"]

    target: dict[str, Any] = {
        "system": ctx.get("target_system", "cloudflare.workers"),
        "environment": ctx.get("target_environment", "prod"),
    }
    if "target_resource_id" in ctx:
        target["resource_id"] = ctx["target_resource_id"]

    receipt: dict[str, Any] = {
        "version": "agentboundary/v0.2-alpha",
        "receipt_id": str(uuid4()),
        "issued_at": issued_at,
        "actor": actor,
        "agent": agent,
        "tool": tool,
        "target": target,
        "arguments_hash": compute_arguments_hash(arguments),
        "policy": {
            "name": ctx.get("policy_name", "cloudflare.needs_approval"),
            "version": ctx.get("policy_version", "unknown"),
            "decision": decision,
        },
    }

    # Cloudflare's `approved` is itself the approval evidence: who + when + reason
    approval: dict[str, Any] = {
        "approver": {"id": row["decided_by"]},
        "approved_at": issued_at,
    }
    if row.get("reason"):
        approval["context"] = row["reason"]
    receipt["approval"] = approval

    # Execution status: Cloudflare's audit row records the DECISION, not
    # the execution. If context supplies execution_status the adapter
    # respects it; otherwise blocked (the action's outcome is unknown).
    execution: dict[str, Any] = {
        "status": ctx.get("execution_status", "blocked"),
        "completed_at": ctx.get("execution_completed_at", issued_at),
    }
    if "execution_result_ref" in ctx and execution["status"] == "success":
        execution["result_ref"] = ctx["execution_result_ref"]
    if "execution_error_code" in ctx:
        execution["error_code"] = ctx["execution_error_code"]
    receipt["execution"] = execution

    if prior_receipt is not None:
        receipt["prior_receipt"] = {
            "receipt_id": prior_receipt["receipt_id"],
            "receipt_hash": prior_receipt["receipt_hash"],
        }

    receipt["provenance"] = _build_provenance(ctx, row, prior_receipt is not None)
    receipt["completeness_score"] = compute_completeness_score(receipt)
    receipt["receipt_hash"] = compute_receipt_hash(receipt)
    return receipt


def _millis_to_rfc3339(millis: int) -> str:
    dt = datetime.fromtimestamp(millis / 1000.0, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _synthetic_actor_id(workflow_id: str) -> str:
    """When no actor_id is supplied, derive one from the Cloudflare workflow_id.

    Tagged ``synthesized`` in provenance so a verifier can see it didn't
    come from a real agent-identity primitive.
    """
    return f"cloudflare:workflow:{workflow_id}"


def _build_provenance(
    ctx: ToolCallContext, row: ApprovalAuditRow, has_chain: bool
) -> dict[str, str]:
    """Tag every receipt field by whether Cloudflare's row provided it,
    the caller's tool_call_context provided it, or the adapter synthesized it.

    Cloudflare's audit row is THIN — most receipt fields are not derivable
    from the row alone. The provenance map therefore tends toward synthesized.
    """
    prov: dict[str, str] = {
        # The adapter generates receipt_id and converts decided_at; both
        # are deterministic transformations of the audit row.
        "receipt_id": "synthesized",  # adapter-generated UUID, not from Cloudflare
        "issued_at": "inferred",  # derived from decided_at
        # Actor: context-supplied if present, else synthesized from workflow_id.
        "actor.type": "observed" if "actor_type" in ctx else "synthesized",
        "actor.id": "observed" if "actor_id" in ctx else "synthesized",
        # Agent: context-supplied if present, else default.
        "agent.framework": "observed" if "agent_framework" in ctx else "synthesized",
        "agent.framework_version": "observed"
        if "agent_framework_version" in ctx
        else "synthesized",
        "agent.model": "observed" if "agent_model" in ctx else "synthesized",
        # Tool: name comes from context; capability synthesized unless context provides.
        "tool.name": "observed" if "tool_name" in ctx else "synthesized",
        "tool.capability": "observed" if "tool_capability" in ctx else "inferred",
        # Target: defaults unless context supplies.
        "target.system": "observed" if "target_system" in ctx else "synthesized",
        "target.environment": "observed" if "target_environment" in ctx else "synthesized",
        # arguments_hash: observed when context supplies arguments (adapter has them in hand).
        "arguments_hash": "observed" if "arguments" in ctx else "synthesized",
        # Policy: synthetic identifier — Cloudflare has no policy primitive.
        "policy.name": "observed" if "policy_name" in ctx else "synthesized",
        "policy.version": "observed" if "policy_version" in ctx else "synthesized",
        "policy.decision": "observed",  # straight from row['decision']
        # Execution: blocked default unless context supplies real outcome.
        "execution.status": "observed" if "execution_status" in ctx else "synthesized",
        "execution.completed_at": "observed" if "execution_completed_at" in ctx else "synthesized",
    }

    # Conditional paths
    if "actor_display_name" in ctx:
        prov["actor.display_name"] = "observed"
    if "agent_model_version" in ctx:
        prov["agent.model_version"] = "observed"
    if "tool_version" in ctx:
        prov["tool.version"] = "observed"
    if "target_resource_id" in ctx:
        prov["target.resource_id"] = "observed"
    if "execution_result_ref" in ctx:
        prov["execution.result_ref"] = "observed"
    if "execution_error_code" in ctx:
        prov["execution.error_code"] = "observed"

    # Approval block: row directly provides decided_by + decided_at + reason
    prov["approval.approver.id"] = "observed"
    prov["approval.approved_at"] = "inferred"  # converted from millis
    if row.get("reason"):
        prov["approval.context"] = "observed"

    if has_chain:
        # Chain is maintained externally to Cloudflare; adapter caller supplies.
        prov["prior_receipt.receipt_id"] = "synthesized"
        prov["prior_receipt.receipt_hash"] = "synthesized"

    return prov
