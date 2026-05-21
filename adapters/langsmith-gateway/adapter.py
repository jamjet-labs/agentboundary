"""Adapter: LangSmith Run -> AgentBoundary v0.2-alpha receipt.

LangSmith is observability-first; the Run object captures rich runtime
data but does NOT have a normative schema for policy decisions, approver
identity, or tamper-evidence. This adapter translates a Run into a
v0.2-alpha receipt, pulling policy/identity/approval signals from
team-level tag/feedback conventions documented in ``mapping.md``.

The adapter is honest about translation losses: fields not reachable from
the Run or its conventions are tagged ``synthesized`` in provenance, and
the completeness_score reflects how much of the receipt was filled vs
guessed. A team that follows the convention shape exhaustively gets a
high-quality receipt; a bare Run yields a low-completeness receipt
honestly tagged as such.
"""

from __future__ import annotations

from typing import Any, TypedDict
from uuid import uuid4

from agentboundary.hashing import compute_arguments_hash, compute_receipt_hash
from agentboundary.provenance import compute_completeness_score


class LangSmithRun(TypedDict, total=False):
    """Subset of LangSmith Run fields the adapter consumes.

    LangSmith Runs carry many more fields (token counts, child runs,
    feedback stats); the adapter ignores observability-specific signals
    and reads only what maps to receipt fields.
    """

    id: str
    name: str
    run_type: str  # "llm" | "tool" | "chain" | ...
    inputs: dict[str, Any]
    outputs: dict[str, Any] | None
    error: dict[str, Any] | None
    start_time: str  # RFC 3339
    end_time: str
    status: str  # "success" | "error"
    tags: list[str]
    trace_id: str
    parent_run_id: str | None
    session_id: str
    extra: dict[str, Any]
    feedback_stats: dict[str, Any]


class AdapterContext(TypedDict, total=False):
    """Out-of-band signals the adapter caller can supply when team
    conventions don't carry them. Useful when calling against a Run
    captured before the team adopted strict tagging.
    """

    actor_id: str
    actor_type: str
    agent_framework: str
    agent_framework_version: str
    agent_model: str
    tool_capability: str
    target_system: str
    target_environment: str
    target_resource_id: str
    policy_name: str
    policy_version: str
    policy_decision: str
    execution_result_ref: str


_DECISION_TAG_PREFIX = "decision:"
_POLICY_TAG_PREFIX = "policy:"
_POLICY_VERSION_TAG_PREFIX = "policy_version:"
_ACTOR_TAG_PREFIX = "actor:"
_USER_TAG_PREFIX = "user:"
_TARGET_TAG_PREFIX = "target:"
_ENV_TAG_PREFIX = "env:"
_CAPABILITY_TAG_PREFIX = "capability:"


def langsmith_run_to_receipt(
    run: LangSmithRun,
    *,
    context: AdapterContext | None = None,
    prior_receipt: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Translate one LangSmith Run into an AgentBoundary v0.2-alpha receipt.

    ``context`` supplies fields the Run's tags / extra / feedback don't
    carry. Omitted fields fall to sensible defaults and are tagged
    ``synthesized`` in provenance.

    ``prior_receipt`` populates the v0.2-alpha chain link. LangSmith's
    ``parent_run_id`` is hierarchical (per-trace tree); chain across
    traces is adapter-maintained state.
    """
    ctx: AdapterContext = context or {}
    tags = run.get("tags", []) or []
    extra = run.get("extra", {}) or {}
    tagmap = _parse_tags(tags)

    inputs = run.get("inputs", {}) or {}
    arguments_hash = compute_arguments_hash(inputs)

    decision = (
        ctx.get("policy_decision")
        or tagmap.get(_DECISION_TAG_PREFIX)
        or _decision_from_status(run.get("status"))
    )

    actor_type = ctx.get("actor_type") or tagmap.get(_ACTOR_TAG_PREFIX) or "agent"
    actor_id = (
        ctx.get("actor_id")
        or tagmap.get(_USER_TAG_PREFIX)
        or extra.get("user_id")
        or f"langsmith:session:{run.get('session_id', 'unknown')}"
    )

    receipt: dict[str, Any] = {
        "version": "agentboundary/v0.2-alpha",
        "receipt_id": run.get("id") or str(uuid4()),
        "issued_at": run.get("end_time") or run.get("start_time") or _now_rfc3339(),
        "actor": {"type": actor_type, "id": actor_id},
        "agent": {
            "framework": ctx.get("agent_framework") or extra.get("framework", "langchain"),
            "framework_version": (
                ctx.get("agent_framework_version") or extra.get("framework_version", "unknown")
            ),
            "model": ctx.get("agent_model") or extra.get("model", "unknown"),
        },
        "tool": {
            "name": run.get("name") or "unknown",
            "capability": (
                ctx.get("tool_capability")
                or tagmap.get(_CAPABILITY_TAG_PREFIX)
                or f"langsmith.tool.{run.get('name', 'unknown')}"
            ),
        },
        "target": {
            "system": (
                ctx.get("target_system") or tagmap.get(_TARGET_TAG_PREFIX) or "langsmith.unknown"
            ),
            "environment": (ctx.get("target_environment") or tagmap.get(_ENV_TAG_PREFIX) or "prod"),
        },
        "arguments_hash": arguments_hash,
        "policy": {
            "name": (
                ctx.get("policy_name") or tagmap.get(_POLICY_TAG_PREFIX) or "langsmith.implicit"
            ),
            "version": (
                ctx.get("policy_version") or tagmap.get(_POLICY_VERSION_TAG_PREFIX) or "unknown"
            ),
            "decision": decision,
        },
    }

    if "target_resource_id" in ctx:
        receipt["target"]["resource_id"] = ctx["target_resource_id"]
    elif "resource_id" in inputs:
        receipt["target"]["resource_id"] = str(inputs["resource_id"])

    # Execution outcome from Run.status / outputs / error
    status = run.get("status", "success")
    execution: dict[str, Any] = {
        "status": _map_status(status, decision),
        "completed_at": run.get("end_time") or _now_rfc3339(),
    }
    if execution["status"] == "success":
        result_ref = ctx.get("execution_result_ref") or (
            extra.get("result_ref") if isinstance(extra, dict) else None
        )
        if result_ref:
            execution["result_ref"] = str(result_ref)
        else:
            execution["result_ref"] = f"langsmith://runs/{run.get('id', 'unknown')}"
    if status == "error" and isinstance(run.get("error"), dict):
        code = run["error"].get("code")
        if code:
            execution["error_code"] = str(code)
    receipt["execution"] = execution

    # Approval block from feedback_stats / annotations (convention)
    feedback = run.get("feedback_stats") or {}
    approver_id = (
        feedback.get("approver", {}).get("id")
        if isinstance(feedback.get("approver"), dict)
        else None
    )
    if approver_id:
        receipt["approval"] = {
            "approver": {"id": approver_id},
            "approved_at": run.get("end_time", _now_rfc3339()),
        }

    if prior_receipt is not None:
        receipt["prior_receipt"] = {
            "receipt_id": prior_receipt["receipt_id"],
            "receipt_hash": prior_receipt["receipt_hash"],
        }

    receipt["provenance"] = _build_provenance(
        run, ctx, tagmap, prior_receipt is not None, approver_id
    )
    receipt["completeness_score"] = compute_completeness_score(receipt)
    receipt["receipt_hash"] = compute_receipt_hash(receipt)
    return receipt


def _parse_tags(tags: list[str]) -> dict[str, str]:
    """Return {prefix: value-after-prefix} for known prefixes."""
    out: dict[str, str] = {}
    for tag in tags:
        for prefix in (
            _DECISION_TAG_PREFIX,
            _POLICY_TAG_PREFIX,
            _POLICY_VERSION_TAG_PREFIX,
            _ACTOR_TAG_PREFIX,
            _USER_TAG_PREFIX,
            _TARGET_TAG_PREFIX,
            _ENV_TAG_PREFIX,
            _CAPABILITY_TAG_PREFIX,
        ):
            if tag.startswith(prefix):
                out[prefix] = tag[len(prefix) :]
                break
    return out


def _decision_from_status(status: str | None) -> str:
    """Best-effort decision from Run.status when no tag is set."""
    if status == "error":
        return "deny"
    return "allow"


def _map_status(langsmith_status: str, decision: str) -> str:
    """LangSmith status -> AgentBoundary execution.status.

    `error` -> failure; `success` with a non-allow decision -> blocked
    (the action didn't actually execute because policy denied/escalated).
    """
    if langsmith_status == "error":
        return "failure"
    if decision == "allow":
        return "success"
    return "blocked"


def _now_rfc3339() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_provenance(
    run: LangSmithRun,
    ctx: AdapterContext,
    tagmap: dict[str, str],
    has_chain: bool,
    approver_id: str | None,
) -> dict[str, str]:
    """Tag every receipt field by what the adapter pulled from where."""
    extra = run.get("extra", {}) or {}

    def from_ctx_or_tag_or_extra(
        ctx_key: str, tag_prefix: str, extra_key: str | None = None
    ) -> str:
        if ctx_key in ctx:
            return "observed"
        if tag_prefix in tagmap:
            return "observed"
        if extra_key and extra_key in extra:
            return "observed"
        return "synthesized"

    prov: dict[str, str] = {
        # receipt_id and issued_at come directly from the Run
        "receipt_id": "observed",
        "issued_at": "observed",
        "actor.type": from_ctx_or_tag_or_extra("actor_type", _ACTOR_TAG_PREFIX),
        "actor.id": from_ctx_or_tag_or_extra("actor_id", _USER_TAG_PREFIX, "user_id"),
        "agent.framework": from_ctx_or_tag_or_extra("agent_framework", "", "framework"),
        "agent.framework_version": from_ctx_or_tag_or_extra(
            "agent_framework_version", "", "framework_version"
        ),
        "agent.model": from_ctx_or_tag_or_extra("agent_model", "", "model"),
        # Tool name is observed (Run.name); capability is inferred or observed via tag.
        "tool.name": "observed",
        "tool.capability": (
            "observed"
            if (_CAPABILITY_TAG_PREFIX in tagmap or "tool_capability" in ctx)
            else "inferred"
        ),
        "target.system": from_ctx_or_tag_or_extra("target_system", _TARGET_TAG_PREFIX),
        "target.environment": from_ctx_or_tag_or_extra("target_environment", _ENV_TAG_PREFIX),
        # arguments_hash is observed (computed from raw Run.inputs)
        "arguments_hash": "observed",
        "policy.name": from_ctx_or_tag_or_extra("policy_name", _POLICY_TAG_PREFIX),
        "policy.version": from_ctx_or_tag_or_extra("policy_version", _POLICY_VERSION_TAG_PREFIX),
        "policy.decision": (
            "observed"
            if (_DECISION_TAG_PREFIX in tagmap or "policy_decision" in ctx)
            else "inferred"
        ),
        "execution.status": "observed",
        "execution.completed_at": "observed",
    }

    # Conditional paths
    if "target_resource_id" in ctx:
        prov["target.resource_id"] = "observed"
    elif "resource_id" in (run.get("inputs") or {}):
        prov["target.resource_id"] = "inferred"

    if "execution_result_ref" in ctx or extra.get("result_ref"):
        prov["execution.result_ref"] = "observed"
    elif run.get("status") == "success":
        # adapter synthesised a langsmith://runs/<id> ref
        prov["execution.result_ref"] = "synthesized"

    if isinstance(run.get("error"), dict) and run["error"].get("code"):
        prov["execution.error_code"] = "observed"

    if approver_id:
        prov["approval.approver.id"] = "observed"
        prov["approval.approved_at"] = "inferred"

    if has_chain:
        prov["prior_receipt.receipt_id"] = "synthesized"
        prov["prior_receipt.receipt_hash"] = "synthesized"

    return prov
