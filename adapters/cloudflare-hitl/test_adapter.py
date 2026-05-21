"""Smoke tests for the Cloudflare HITL adapter."""

from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))

from adapter import (  # noqa: E402
    ApprovalAuditRow,
    ToolCallContext,
    cloudflare_audit_to_receipt,
)

from agentboundary import check_conformance, validate_receipt  # noqa: E402


def _row(decision: str = "approved", reason: str | None = "weekly maintenance") -> ApprovalAuditRow:
    return {
        "id": 42,
        "workflow_id": "wf_2026_q2_refund_batch",
        "decision": decision,
        "decided_by": "user:eng-lead@acme",
        "decided_at": 1718459370000,  # 2024-06-15 ~14:29:30 UTC, ms since epoch
        "reason": reason,
    }


def _full_context() -> ToolCallContext:
    return {
        "actor_id": "agent:refund-bot",
        "actor_type": "agent",
        "agent_framework": "cloudflare-agents",
        "agent_framework_version": "0.1.5",
        "agent_model": "gpt-4o",
        "tool_name": "stripe.refund",
        "tool_capability": "stripe.refund",
        "tool_version": "2024-06-20",
        "target_system": "stripe.com",
        "target_environment": "prod",
        "target_resource_id": "charge_3PqLcwIuV5oBHnYR0H8jKQ4F",
        "arguments": {"charge_id": "charge_3PqLcwIuV5oBHnYR0H8jKQ4F", "amount_cents": 4200},
        "policy_name": "acme.payments.refunds",
        "policy_version": "5",
        "execution_status": "success",
        "execution_completed_at": "2024-06-15T14:29:35Z",
        "execution_result_ref": "stripe://refund/re_3PqLcwIuV5oBHnYR0H8jLQ8A",
    }


def test_minimal_row_with_no_context_produces_valid_receipt() -> None:
    """A bare Cloudflare row + no context — the worst case — still validates."""
    receipt = cloudflare_audit_to_receipt(_row())
    errors = validate_receipt(receipt)
    assert errors == [], f"adapter produced an invalid receipt: {errors}"


def test_full_context_populates_all_fields() -> None:
    receipt = cloudflare_audit_to_receipt(_row(), context=_full_context())
    errors = validate_receipt(receipt)
    assert errors == [], f"full-context receipt invalid: {errors}"
    assert receipt["tool"]["name"] == "stripe.refund"
    assert receipt["policy"]["name"] == "acme.payments.refunds"
    assert receipt["execution"]["status"] == "success"
    assert receipt["execution"]["result_ref"].startswith("stripe://refund/")


def test_approval_block_is_populated_from_row() -> None:
    receipt = cloudflare_audit_to_receipt(_row())
    assert receipt["approval"]["approver"]["id"] == "user:eng-lead@acme"
    assert receipt["approval"]["context"] == "weekly maintenance"


def test_rejected_decision_maps_to_deny() -> None:
    receipt = cloudflare_audit_to_receipt(_row(decision="rejected"))
    assert receipt["policy"]["decision"] == "deny"


def test_minimal_completeness_score_reflects_thin_audit_row() -> None:
    """The bare Cloudflare row has so few fields that the completeness
    score is low. This is the honest signal — the audit row alone
    cannot produce a high-quality receipt."""
    receipt = cloudflare_audit_to_receipt(_row())
    score = receipt["completeness_score"]
    assert 0.0 <= score < 0.6, f"thin-row score should be low; got {score}"


def test_full_context_completeness_score_is_high() -> None:
    """With context threaded through, the receipt is rich and the score
    reflects that — most fields are observed."""
    receipt = cloudflare_audit_to_receipt(_row(), context=_full_context())
    score = receipt["completeness_score"]
    assert score > 0.85, f"full-context score should be high; got {score}"


def test_completeness_score_matches_recomputed() -> None:
    """Adapter's declared score must equal what a verifier recomputes."""
    from agentboundary.provenance import compute_completeness_score

    for ctx in (None, _full_context()):
        receipt = cloudflare_audit_to_receipt(_row(), context=ctx)
        assert receipt["completeness_score"] == compute_completeness_score(receipt)


def test_chain_link_populates_when_supplied() -> None:
    prior = {
        "receipt_id": "0192c8d0-1f2a-7c3e-bf2a-aaaaaaaaaaaa",
        "receipt_hash": "1111111111111111111111111111111111111111111111111111111111111111",
    }
    receipt = cloudflare_audit_to_receipt(_row(), context=_full_context(), prior_receipt=prior)
    assert receipt["prior_receipt"] == prior


def test_no_prior_receipt_omits_chain_block() -> None:
    receipt = cloudflare_audit_to_receipt(_row(), context=_full_context())
    assert "prior_receipt" not in receipt


def test_l3_passes_with_full_context() -> None:
    """With arguments supplied, L3 hash recompute matches."""
    ctx = _full_context()
    receipt = cloudflare_audit_to_receipt(_row(), context=ctx)
    checks = check_conformance(receipt, level=3, arguments=ctx["arguments"])
    fails = [c for c in checks if c.severity == "fail"]
    assert fails == [], f"L3 failures: {[(c.code, c.message) for c in fails]}"


def test_l4_completeness_below_threshold_fires_on_thin_row() -> None:
    """A verifier with a quality bar rejects bare-row Cloudflare receipts."""
    receipt = cloudflare_audit_to_receipt(_row())
    checks = check_conformance(
        receipt, level=4, arguments={}, minimum_completeness=0.7
    )
    codes = {c.code for c in checks if c.severity == "fail"}
    assert "LEVEL_4_COMPLETENESS_BELOW_THRESHOLD" in codes
