"""Adapter: Anthropic permission-decision event -> AgentBoundary v0.2-alpha.

Anthropic does not publish an audit-log schema; the Managed Agents Console
maintains one internally but doesn't expose it as a portable artifact.
This adapter works against a *synthetic* permission-decision event that
the integrating team captures at the SDK boundary (typically inside a
``canUseTool`` callback, a hook, or a wrapper around ``query()``).

See ``mapping.md`` for the recommended capture shape and field-by-field
translation. The adapter is honest about translation losses: nearly
everything beyond the decision itself + tool name + arguments is
caller-supplied or synthesized, and provenance reflects that.
"""

from __future__ import annotations

from typing import Any, TypedDict
from uuid import uuid4

from agentboundary.hashing import compute_arguments_hash, compute_receipt_hash
from agentboundary.provenance import compute_completeness_score


class PermissionDecisionEvent(TypedDict, total=False):
    """Synthetic capture of one Anthropic permission decision.

    Not a normative Anthropic schema. Teams that want to emit AgentBoundary
    receipts from Claude Agent SDK calls should capture this shape inside
    their canUseTool callback or via a wrapper around `query()`.
    """

    session_id: str
    tool_name: str
    tool_input: dict[str, Any]
    decision: str  # "allow" | "deny" | "ask"
    decided_via: str  # "hook" | "deny_rule" | "permission_mode" | "allow_rule" | "canUseTool"
    matched_rule: str | None  # e.g. "Bash(rm *)" when decided by a rule
    permission_mode: (
        str  # "default" | "dontAsk" | "acceptEdits" | "bypassPermissions" | "plan" | "auto"
    )
    decided_at: str  # RFC 3339
    decided_by: str | None  # only present for canUseTool-resolved decisions
    reason: str | None
    updated_input: dict[str, Any] | None  # canUseTool may modify args


class AdapterContext(TypedDict, total=False):
    """Out-of-band caller context Anthropic's SDK doesn't expose."""

    agent_framework_version: str
    agent_model: str
    agent_model_version: str
    target_system: str
    target_environment: str
    target_resource_id: str
    policy_name: str
    policy_version: str
    execution_status: str  # "success" | "failure" | "blocked"
    execution_completed_at: str
    execution_result_ref: str
    execution_error_code: str
    actor_display_name: str
    approver_role: str


_DECISION_MAP: dict[str, str] = {
    "allow": "allow",
    "deny": "deny",
    "ask": "require-approval",
}


def anthropic_event_to_receipt(
    event: PermissionDecisionEvent,
    *,
    context: AdapterContext | None = None,
    prior_receipt: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Translate one Anthropic permission-decision event into a v0.2-alpha receipt.

    ``event`` is the synthesized capture (not a normative Anthropic schema)
    described in ``mapping.md``. ``context`` carries caller-side fields
    Anthropic doesn't expose. ``prior_receipt`` populates the chain link.
    """
    ctx: AdapterContext = context or {}
    decision = _DECISION_MAP.get(event["decision"], "deny")
    # When canUseTool modifies the input, the hash must reflect the args
    # that actually execute, not the args Claude originally proposed.
    args = event.get("updated_input") or event.get("tool_input") or {}
    arguments_hash = compute_arguments_hash(args)
    tool_name = event["tool_name"]

    actor_id = f"anthropic:session:{event.get('session_id', 'unknown')}"
    receipt: dict[str, Any] = {
        "version": "agentboundary/v0.2-alpha",
        "receipt_id": str(uuid4()),
        "issued_at": event["decided_at"],
        "actor": {"type": "agent", "id": actor_id},
        "agent": {
            "framework": "claude-agent-sdk",
            "framework_version": ctx.get("agent_framework_version", "unknown"),
            "model": ctx.get("agent_model", "unknown"),
        },
        "tool": {
            "name": tool_name,
            "capability": f"anthropic.tool.{tool_name}",
        },
        "target": {
            "system": ctx.get("target_system", "anthropic.managed-agents"),
            "environment": ctx.get("target_environment", "prod"),
        },
        "arguments_hash": arguments_hash,
        "policy": {
            "name": (
                event.get("matched_rule")
                or ctx.get("policy_name")
                or f"anthropic.permission_policy.{event.get('permission_mode', 'default')}"
            ),
            "version": ctx.get("policy_version", "unknown"),
            "decision": decision,
        },
    }

    if "actor_display_name" in ctx:
        receipt["actor"]["display_name"] = ctx["actor_display_name"]
    if "agent_model_version" in ctx:
        receipt["agent"]["model_version"] = ctx["agent_model_version"]
    if "target_resource_id" in ctx:
        receipt["target"]["resource_id"] = ctx["target_resource_id"]

    # Approval block: only when canUseTool resolved the decision and the
    # team identified the approver
    if event.get("decided_via") == "canUseTool" and event.get("decided_by"):
        approval: dict[str, Any] = {
            "approver": {"id": event["decided_by"]},
            "approved_at": event["decided_at"],
        }
        if "approver_role" in ctx:
            approval["approver"]["role"] = ctx["approver_role"]
        if event.get("reason"):
            approval["context"] = event["reason"]
        receipt["approval"] = approval

    # Execution outcome: caller-supplied; default to blocked when
    # decision wasn't allow (the action didn't run)
    execution: dict[str, Any] = {
        "status": ctx.get(
            "execution_status",
            "success" if decision == "allow" else "blocked",
        ),
        "completed_at": ctx.get("execution_completed_at", event["decided_at"]),
    }
    if execution["status"] == "success":
        result_ref = ctx.get("execution_result_ref")
        if result_ref:
            execution["result_ref"] = result_ref
        else:
            execution["result_ref"] = f"anthropic://decision/{receipt['receipt_id']}"
    if "execution_error_code" in ctx:
        execution["error_code"] = ctx["execution_error_code"]
    receipt["execution"] = execution

    if prior_receipt is not None:
        receipt["prior_receipt"] = {
            "receipt_id": prior_receipt["receipt_id"],
            "receipt_hash": prior_receipt["receipt_hash"],
        }

    receipt["provenance"] = _build_provenance(event, ctx, prior_receipt is not None)
    receipt["completeness_score"] = compute_completeness_score(receipt)
    receipt["receipt_hash"] = compute_receipt_hash(receipt)
    return receipt


def _build_provenance(
    event: PermissionDecisionEvent,
    ctx: AdapterContext,
    has_chain: bool,
) -> dict[str, str]:
    """Honest provenance tagging. Most fields are synthesized or inferred —
    Anthropic's decision event is narrow; the bulk of a receipt comes
    from caller-supplied context or adapter defaults."""
    decided_via_callback = event.get("decided_via") == "canUseTool"
    has_approver = decided_via_callback and bool(event.get("decided_by"))

    prov: dict[str, str] = {
        # adapter-generated UUID, derived from decision event:
        "receipt_id": "synthesized",
        "issued_at": "observed",  # event.decided_at
        # actor.type is always 'agent' for Anthropic SDK boundary
        "actor.type": "inferred",
        # actor.id is synthesized from session_id (no portable identity primitive)
        "actor.id": "synthesized",
        # agent fields: framework is constant; version/model from context
        "agent.framework": "inferred",
        "agent.framework_version": "observed"
        if "agent_framework_version" in ctx
        else "synthesized",
        "agent.model": "observed" if "agent_model" in ctx else "synthesized",
        # tool: name observed from event; capability inferred from name
        "tool.name": "observed",
        "tool.capability": "inferred",
        # target: defaults unless context supplies
        "target.system": "observed" if "target_system" in ctx else "synthesized",
        "target.environment": "observed" if "target_environment" in ctx else "synthesized",
        # arguments_hash: observed — adapter has the args
        "arguments_hash": "observed",
        # policy: name inferred when matched_rule available, synthesized otherwise
        "policy.name": "observed"
        if (event.get("matched_rule") or "policy_name" in ctx)
        else "synthesized",
        "policy.version": "observed" if "policy_version" in ctx else "synthesized",
        "policy.decision": "observed",
        # execution: caller-supplied or synthesized
        "execution.status": "observed" if "execution_status" in ctx else "synthesized",
        "execution.completed_at": "observed" if "execution_completed_at" in ctx else "synthesized",
    }

    # Conditional paths
    if "actor_display_name" in ctx:
        prov["actor.display_name"] = "observed"
    if "agent_model_version" in ctx:
        prov["agent.model_version"] = "observed"
    if "target_resource_id" in ctx:
        prov["target.resource_id"] = "observed"
    if "execution_result_ref" in ctx:
        prov["execution.result_ref"] = "observed"
    else:
        # synthesized anthropic://decision/<id> fallback for allow decisions
        # (only present when execution.status is success)
        default_status = "success" if event["decision"] == "allow" else "blocked"
        effective_status = ctx.get("execution_status", default_status)
        if (
            decided_via_callback or "execution_status" not in ctx
        ) and effective_status == "success":
            prov["execution.result_ref"] = "synthesized"
    if "execution_error_code" in ctx:
        prov["execution.error_code"] = "observed"

    if has_approver:
        prov["approval.approver.id"] = "observed"
        prov["approval.approved_at"] = "observed"
        if "approver_role" in ctx:
            prov["approval.approver.role"] = "observed"
        if event.get("reason"):
            prov["approval.context"] = "observed"

    if has_chain:
        prov["prior_receipt.receipt_id"] = "synthesized"
        prov["prior_receipt.receipt_hash"] = "synthesized"

    return prov
