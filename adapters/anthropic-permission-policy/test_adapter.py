"""Smoke tests for the Anthropic permission_policy adapter."""

from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))

from adapter import (  # noqa: E402
    AdapterContext,
    PermissionDecisionEvent,
    anthropic_event_to_receipt,
)

from agentboundary import check_conformance, validate_receipt  # noqa: E402


def _allow_via_rule() -> PermissionDecisionEvent:
    return {
        "session_id": "ses_2026_q2_refund_batch",
        "tool_name": "Bash",
        "tool_input": {"command": "ls /tmp"},
        "decision": "allow",
        "decided_via": "allow_rule",
        "matched_rule": "Bash(ls *)",
        "permission_mode": "default",
        "decided_at": "2026-06-15T14:23:08Z",
    }


def _deny_via_disallowed() -> PermissionDecisionEvent:
    return {
        "session_id": "ses_2026_q2_refund_batch",
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /"},
        "decision": "deny",
        "decided_via": "deny_rule",
        "matched_rule": "Bash(rm *)",
        "permission_mode": "default",
        "decided_at": "2026-06-15T14:23:10Z",
    }


def _ask_via_callback(updated: bool = False) -> PermissionDecisionEvent:
    event: PermissionDecisionEvent = {
        "session_id": "ses_2026_q2_refund_batch",
        "tool_name": "Stripe.refund",
        "tool_input": {"charge_id": "ch_123", "amount_cents": 4200},
        "decision": "allow",
        "decided_via": "canUseTool",
        "matched_rule": None,
        "permission_mode": "default",
        "decided_at": "2026-06-15T14:23:15Z",
        "decided_by": "user:eng-lead@acme",
        "reason": "Within refund-policy threshold; routine approval",
    }
    if updated:
        event["updated_input"] = {"charge_id": "ch_123", "amount_cents": 4000}
    return event


def _full_context() -> AdapterContext:
    return {
        "agent_framework_version": "0.4.0",
        "agent_model": "claude-sonnet-4-7",
        "agent_model_version": "20260415",
        "target_system": "stripe.com",
        "target_environment": "prod",
        "target_resource_id": "ch_123",
        "policy_name": "acme.payments.refunds",
        "policy_version": "5",
        "execution_status": "success",
        "execution_completed_at": "2026-06-15T14:23:18Z",
        "execution_result_ref": "stripe://refund/re_456",
        "approver_role": "maintainer",
    }


def test_allow_via_rule_produces_valid_receipt() -> None:
    receipt = anthropic_event_to_receipt(_allow_via_rule())
    errors = validate_receipt(receipt)
    assert errors == [], f"allow-via-rule receipt invalid: {errors}"


def test_deny_via_disallowed_produces_valid_receipt() -> None:
    receipt = anthropic_event_to_receipt(_deny_via_disallowed())
    errors = validate_receipt(receipt)
    assert errors == [], f"deny receipt invalid: {errors}"
    assert receipt["policy"]["decision"] == "deny"
    assert receipt["execution"]["status"] == "blocked"


def test_ask_via_callback_populates_approval_block() -> None:
    receipt = anthropic_event_to_receipt(_ask_via_callback(), context=_full_context())
    errors = validate_receipt(receipt)
    assert errors == [], f"ask-via-callback receipt invalid: {errors}"
    assert receipt["approval"]["approver"]["id"] == "user:eng-lead@acme"
    assert receipt["approval"]["approver"]["role"] == "maintainer"


def test_matched_rule_populates_policy_name() -> None:
    receipt = anthropic_event_to_receipt(_deny_via_disallowed())
    assert receipt["policy"]["name"] == "Bash(rm *)"


def test_updated_input_drives_arguments_hash() -> None:
    """When canUseTool returns updatedInput, hash must reflect the args
    that actually executed — not Claude's original proposal."""
    from agentboundary.hashing import compute_arguments_hash

    original_event = _ask_via_callback(updated=False)
    updated_event = _ask_via_callback(updated=True)

    r_original = anthropic_event_to_receipt(original_event)
    r_updated = anthropic_event_to_receipt(updated_event)

    assert r_original["arguments_hash"] == compute_arguments_hash(
        original_event["tool_input"]
    )
    assert r_updated["arguments_hash"] == compute_arguments_hash(
        updated_event["updated_input"]
    )
    assert r_original["arguments_hash"] != r_updated["arguments_hash"]


def test_bare_event_completeness_score_is_low() -> None:
    receipt = anthropic_event_to_receipt(_allow_via_rule())
    score = receipt["completeness_score"]
    assert 0.0 <= score < 0.7, f"bare event should score low; got {score}"


def test_full_context_completeness_score_is_high() -> None:
    receipt = anthropic_event_to_receipt(
        _ask_via_callback(), context=_full_context()
    )
    score = receipt["completeness_score"]
    assert score > 0.8, f"full-context score should be high; got {score}"


def test_completeness_score_matches_recomputed() -> None:
    from agentboundary.provenance import compute_completeness_score

    for event, ctx in (
        (_allow_via_rule(), None),
        (_deny_via_disallowed(), None),
        (_ask_via_callback(), _full_context()),
        (_ask_via_callback(updated=True), _full_context()),
    ):
        receipt = anthropic_event_to_receipt(event, context=ctx)
        assert receipt["completeness_score"] == compute_completeness_score(receipt)


def test_l3_passes_with_args_provided() -> None:
    event = _allow_via_rule()
    receipt = anthropic_event_to_receipt(event)
    checks = check_conformance(
        receipt, level=3, arguments=event["tool_input"]
    )
    fails = [c for c in checks if c.severity == "fail"]
    assert fails == [], f"L3 failures: {[(c.code, c.message) for c in fails]}"


def test_chain_link_populates_when_supplied() -> None:
    prior = {
        "receipt_id": "0192c8d0-1f2a-7c3e-bf2a-aaaaaaaaaaaa",
        "receipt_hash": "a" * 64,
    }
    receipt = anthropic_event_to_receipt(_allow_via_rule(), prior_receipt=prior)
    assert receipt["prior_receipt"] == prior


def test_ask_decision_maps_to_require_approval() -> None:
    """Anthropic's 'ask' translates to AgentBoundary's 'require-approval'.
    With a canUseTool decided_by, the approval block populates."""
    event = _ask_via_callback()
    event["decision"] = "ask"
    receipt = anthropic_event_to_receipt(event, context=_full_context())
    assert receipt["policy"]["decision"] == "require-approval"
    assert "approval" in receipt
