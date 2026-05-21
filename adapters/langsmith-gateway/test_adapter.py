"""Smoke tests for the LangSmith Gateway adapter."""

from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))

from adapter import (  # noqa: E402
    AdapterContext,
    LangSmithRun,
    langsmith_run_to_receipt,
)

from agentboundary import check_conformance, validate_receipt  # noqa: E402


def _bare_run() -> LangSmithRun:
    """Minimal Run with no team conventions — worst case."""
    return {
        "id": "0192c8d0-1f2a-7c3e-bf2a-1a4d3f5e6c7b",
        "name": "stripe.refund",
        "run_type": "tool",
        "inputs": {"charge_id": "ch_123", "amount_cents": 4200},
        "outputs": {"refund_id": "re_456"},
        "start_time": "2026-06-15T14:23:00Z",
        "end_time": "2026-06-15T14:23:05Z",
        "status": "success",
        "tags": [],
        "trace_id": "0192c8d0-trace-aaaaaaaaaaaa",
        "parent_run_id": None,
        "session_id": "0192c8d0-session-bbbbbbbbbbb",
        "extra": {},
        "feedback_stats": {},
    }


def _convention_run() -> LangSmithRun:
    """Run with full production tag/extra/feedback conventions."""
    run = _bare_run()
    run["tags"] = [
        "decision:require-approval",
        "policy:acme.payments.refunds",
        "policy_version:5",
        "actor:agent",
        "user:agent:refund-bot",
        "target:stripe.com",
        "env:prod",
        "capability:stripe.refund",
    ]
    run["extra"] = {
        "framework": "langchain",
        "framework_version": "0.3.0",
        "model": "gpt-4o",
        "result_ref": "stripe://refund/re_456",
    }
    run["feedback_stats"] = {
        "approver": {"id": "user:eng-lead@acme"},
    }
    return run


def test_bare_run_produces_valid_receipt() -> None:
    receipt = langsmith_run_to_receipt(_bare_run())
    errors = validate_receipt(receipt)
    assert errors == [], f"bare-run receipt invalid: {errors}"


def test_convention_run_produces_valid_receipt() -> None:
    receipt = langsmith_run_to_receipt(_convention_run())
    errors = validate_receipt(receipt)
    assert errors == [], f"convention-run receipt invalid: {errors}"


def test_bare_run_has_low_completeness() -> None:
    receipt = langsmith_run_to_receipt(_bare_run())
    score = receipt["completeness_score"]
    assert 0.0 <= score < 0.7, f"bare run should score low; got {score}"


def test_convention_run_has_high_completeness() -> None:
    receipt = langsmith_run_to_receipt(_convention_run())
    score = receipt["completeness_score"]
    assert score > 0.85, f"convention run should score high; got {score}"


def test_tagmap_decision_overrides_status_inference() -> None:
    """When decision:deny tag is present, receipt records deny regardless of status."""
    run = _bare_run()
    run["tags"] = ["decision:deny"]
    receipt = langsmith_run_to_receipt(run)
    assert receipt["policy"]["decision"] == "deny"


def test_status_error_maps_to_failure() -> None:
    run = _bare_run()
    run["status"] = "error"
    run["error"] = {"code": "TIMEOUT", "message": "operation timed out"}
    receipt = langsmith_run_to_receipt(run)
    assert receipt["execution"]["status"] == "failure"
    assert receipt["execution"]["error_code"] == "TIMEOUT"


def test_feedback_approver_populates_approval_block() -> None:
    receipt = langsmith_run_to_receipt(_convention_run())
    assert "approval" in receipt
    assert receipt["approval"]["approver"]["id"] == "user:eng-lead@acme"


def test_l3_arguments_hash_recomputes() -> None:
    run = _bare_run()
    receipt = langsmith_run_to_receipt(run)
    checks = check_conformance(receipt, level=3, arguments=run["inputs"])
    fails = [c for c in checks if c.severity == "fail"]
    assert fails == [], f"L3 failures: {[(c.code, c.message) for c in fails]}"


def test_chain_link_populates_when_supplied() -> None:
    prior = {
        "receipt_id": "0192c8d0-1f2a-7c3e-bf2a-aaaaaaaaaaaa",
        "receipt_hash": "1" * 64,
    }
    receipt = langsmith_run_to_receipt(_bare_run(), prior_receipt=prior)
    assert receipt["prior_receipt"] == prior


def test_completeness_score_matches_recomputed() -> None:
    from agentboundary.provenance import compute_completeness_score

    for run in (_bare_run(), _convention_run()):
        receipt = langsmith_run_to_receipt(run)
        assert receipt["completeness_score"] == compute_completeness_score(receipt)


def test_l4_completeness_below_threshold_fires_on_bare_run() -> None:
    receipt = langsmith_run_to_receipt(_bare_run())
    checks = check_conformance(
        receipt, level=4, arguments=_bare_run()["inputs"], minimum_completeness=0.75
    )
    codes = {c.code for c in checks if c.severity == "fail"}
    assert "LEVEL_4_COMPLETENESS_BELOW_THRESHOLD" in codes
