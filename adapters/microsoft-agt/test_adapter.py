"""Smoke tests for the AGT adapter — confirm it produces schema-valid receipts.

These tests do not run as part of the main agentboundary suite; they live
alongside the adapter and can be invoked with::

    pytest adapters/microsoft-agt/test_adapter.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Adapter is not pip-installable; add its directory to sys.path so the
# import below works regardless of where pytest is launched.
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))

from adapter import agt_entry_to_receipt  # noqa: E402

from agentboundary import check_conformance, validate_receipt  # noqa: E402


def _agt_allow_entry() -> dict:
    """A representative AGT AuditEntry covering the spec's required + sample fields."""
    return {
        "entry_id": "0192c8d0-1f2a-7c3e-bf2a-1a4d3f5e6c7b",
        "timestamp": "2026-06-15T14:23:08Z",
        "event_type": "tool_invocation",
        "agent_id": "did:web:sales-assistant.example.com",
        "action": "tool_invocation",
        "decision": "allow",
        "outcome": "success",
        "resource": "crm.example.com/contacts/acme",
        "data": {"tool": "crm_lookup", "query": "acme corp"},
        "metadata": {
            "framework": "semantic-kernel",
            "framework_version": "1.0",
            "model": "gpt-4o",
            "tool_version": "2.1.0",
            "result_ref": "crm://lead/acme-123",
        },
        "matched_rule": "sales.crm.read.v1",
        "entry_hash": "abc123",
        "previous_hash": "xyz789",
    }


def _agt_escalate_entry() -> dict:
    """AGT entry that escalated for human review."""
    entry = _agt_allow_entry()
    entry["entry_id"] = "0192c8d0-1f2a-7c3e-bf2a-2b5e4f6e7d8c"
    entry["event_type"] = "human_review_requested"
    entry["decision"] = "audit"  # AGT 'audit' decision; closest to escalate
    entry["outcome"] = "success"
    return entry


def test_allow_entry_translates_to_valid_receipt() -> None:
    receipt = agt_entry_to_receipt(_agt_allow_entry())
    errors = validate_receipt(receipt)
    assert errors == [], f"adapter produced an invalid receipt: {errors}"


def test_default_output_is_v02_alpha() -> None:
    receipt = agt_entry_to_receipt(_agt_allow_entry())
    assert receipt["version"] == "agentboundary/v0.2-alpha"
    assert "provenance" in receipt
    assert "completeness_score" in receipt


def test_v01_opt_out_skips_provenance() -> None:
    receipt = agt_entry_to_receipt(
        _agt_allow_entry(), schema_version="agentboundary/v0.1"
    )
    assert receipt["version"] == "agentboundary/v0.1"
    assert "provenance" not in receipt
    assert "completeness_score" not in receipt
    # Schema still validates
    errors = validate_receipt(receipt)
    assert errors == [], f"v0.1 fallback produced invalid receipt: {errors}"


def test_allow_entry_passes_l2() -> None:
    receipt = agt_entry_to_receipt(_agt_allow_entry())
    checks = check_conformance(receipt, level=2)
    fails = [c for c in checks if c.severity == "fail"]
    assert fails == []


def test_allow_entry_passes_l3() -> None:
    receipt = agt_entry_to_receipt(_agt_allow_entry())
    arguments = {"query": "acme corp"}
    checks = check_conformance(receipt, level=3, arguments=arguments)
    fails = [c for c in checks if c.severity == "fail"]
    assert fails == [], f"L3 failures: {[(c.code, c.message) for c in fails]}"


def test_l4_policy_downgrade_fires_because_agt_has_no_version() -> None:
    """policy.version is "unknown" because AGT doesn't carry one. A verifier
    with a real policy_store will not find ("sales.crm.read.v1", "unknown")
    in the set — the gap is detected, which is the honest outcome."""
    receipt = agt_entry_to_receipt(_agt_allow_entry())
    policy_store = {("sales.crm.read.v1", "2")}
    checks = check_conformance(receipt, level=4, policy_store=policy_store)
    codes = {c.code for c in checks if c.severity == "fail"}
    assert "LEVEL_4_POLICY_DOWNGRADE" in codes


def test_provenance_marks_known_agt_gaps_as_synthesized() -> None:
    """The adapter must honestly mark fields AGT can't natively express."""
    receipt = agt_entry_to_receipt(_agt_allow_entry())
    prov = receipt["provenance"]
    # AGT has no policy version field — must be synthesized
    assert prov["policy.version"] == "synthesized"
    # AGT has no environment field — adapter defaults
    assert prov["target.environment"] == "synthesized"
    # AGT records observable fields
    assert prov["receipt_id"] == "observed"
    assert prov["actor.id"] == "observed"
    assert prov["policy.decision"] == "observed"


def test_completeness_score_score_below_one_for_typical_agt_entry() -> None:
    """A typical AGT entry should produce a score below 1.0 because the
    adapter has to synthesize policy.version + target.environment."""
    receipt = agt_entry_to_receipt(_agt_allow_entry())
    score = receipt["completeness_score"]
    assert 0.5 < score < 1.0


def test_completeness_score_matches_recomputed() -> None:
    """Score the adapter writes must equal what a verifier recomputes."""
    from agentboundary.provenance import compute_completeness_score

    receipt = agt_entry_to_receipt(_agt_allow_entry())
    assert receipt["completeness_score"] == compute_completeness_score(receipt)


def test_approval_event_populates_block() -> None:
    receipt = agt_entry_to_receipt(
        _agt_escalate_entry(),
        approval_event={
            "approver_id": "user:lead@acme",
            "approver_display_name": "Alice Lead",
            "approver_role": "maintainer",
            "approved_at": "2026-06-15T14:22:30Z",
            "context": "ACME-1287",
        },
    )
    assert "approval" in receipt
    assert receipt["approval"]["approver"]["id"] == "user:lead@acme"
    assert receipt["approval"]["approved_at"] == "2026-06-15T14:22:30Z"
    # And provenance reflects that approval came from a real workflow event
    assert receipt["provenance"]["approval.approver.id"] == "observed"
    assert receipt["provenance"]["approval.approver.role"] == "observed"
    errors = validate_receipt(receipt)
    assert errors == [], f"adapter produced an invalid receipt: {errors}"
