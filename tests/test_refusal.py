"""v0.2-alpha refusal receipts: a refused action still produces a receipt.

Covers the schema (``refusal`` block, relaxed approval rule for blocked
actions), the conformance checks that keep a refusal honest, and the
reference implementation's v0.2-alpha mode that emits refusals.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from agentboundary.conformance import check_conformance
from agentboundary.hashing import compute_receipt_hash
from agentboundary.provenance import ALL_PROVENANCE_PATHS
from agentboundary.runtime import ReferenceImplementation
from agentboundary.validator import validate_receipt

V02 = "agentboundary/v0.2-alpha"
NOW = "2026-06-15T14:23:00Z"


def _rehash(receipt: dict[str, Any]) -> dict[str, Any]:
    receipt.pop("receipt_hash", None)
    receipt["receipt_hash"] = compute_receipt_hash(receipt)
    return receipt


def _receipt(
    *,
    decision: str = "deny",
    status: str = "blocked",
    refusal: dict[str, Any] | None = None,
    approval: dict[str, Any] | None = None,
    version: str = V02,
) -> dict[str, Any]:
    r: dict[str, Any] = {
        "version": version,
        "receipt_id": "0192c8d0-1f2a-7c3e-bf2a-1a4d3f5e6c7b",
        "issued_at": NOW,
        "actor": {"type": "agent", "id": "agent:test"},
        "agent": {"framework": "f", "framework_version": "1", "model": "m"},
        "tool": {"name": "t", "capability": "test.cap"},
        "target": {"system": "s.test", "environment": "prod"},
        "arguments_hash": "a" * 64,
        "policy": {"name": "p", "version": "1", "decision": decision},
        "execution": {"status": status, "completed_at": NOW},
    }
    if approval is not None:
        r["approval"] = approval
    if refusal is not None:
        r["refusal"] = refusal
    return _rehash(r)


def _fail_codes(checks: list[Any]) -> set[str]:
    return {c.code for c in checks if c.severity == "fail"}


STALE_APPROVAL = {"approver": {"id": "user:lead"}, "approved_at": "2024-01-01T00:00:00Z"}
POLICY_60S = {"approvers": [{"id": "user:lead"}], "approval_max_age_seconds": 60}


class TestSchema:
    def test_refusal_receipt_validates(self) -> None:
        r = _receipt(refusal={"verdict": "deny", "reason_code": "policy-deny"})
        assert validate_receipt(r) == []

    @pytest.mark.parametrize("verdict", ["deny", "require-approval", "expired"])
    def test_each_verdict_is_accepted(self, verdict: str) -> None:
        decision = "deny" if verdict == "deny" else "require-approval"
        assert validate_receipt(_receipt(decision=decision, refusal={"verdict": verdict})) == []

    def test_unknown_verdict_is_rejected(self) -> None:
        errors = validate_receipt(_receipt(refusal={"verdict": "timeout"}))
        assert any("refusal.verdict" in e for e in errors)

    def test_refusal_requires_verdict(self) -> None:
        errors = validate_receipt(_receipt(refusal={"reason_code": "x"}))
        assert any("verdict" in e for e in errors)

    def test_refusal_is_closed(self) -> None:
        errors = validate_receipt(_receipt(refusal={"verdict": "deny", "why": "x"}))
        assert any("refusal" in e for e in errors)

    def test_empty_reason_code_is_rejected(self) -> None:
        errors = validate_receipt(_receipt(refusal={"verdict": "deny", "reason_code": ""}))
        assert any("reason_code" in e for e in errors)

    def test_v02_blocked_require_approval_needs_no_approval_block(self) -> None:
        """Spec v0.1 §2.6/§4.10 says approval is required only if the action
        proceeded. The v0.2-alpha schema now says the same, so an honest
        "approval was never given" receipt validates."""
        r = _receipt(decision="require-approval", refusal={"verdict": "require-approval"})
        assert validate_receipt(r) == []

    def test_v02_executed_require_approval_still_needs_approval(self) -> None:
        r = _receipt(decision="require-approval", status="success")
        assert any("approval" in e for e in validate_receipt(r))

    def test_v02_failed_require_approval_still_needs_approval(self) -> None:
        r = _receipt(decision="require-approval", status="failure")
        assert any("approval" in e for e in validate_receipt(r))

    def test_v01_wire_format_is_unchanged(self) -> None:
        """The published v0.1 schema keeps rejecting both shapes."""
        no_approval = _receipt(decision="require-approval", version="agentboundary/v0.1")
        assert any("approval" in e for e in validate_receipt(no_approval))
        with_refusal = _receipt(refusal={"verdict": "deny"}, version="agentboundary/v0.1")
        assert any("refusal" in e for e in validate_receipt(with_refusal))


class TestConformanceRefusalExecuted:
    def test_refusal_with_success_fails(self) -> None:
        r = _receipt(status="success", refusal={"verdict": "deny"})
        assert "LEVEL_2_REFUSAL_EXECUTED" in _fail_codes(check_conformance(r, 2))

    def test_refusal_with_failure_fails(self) -> None:
        r = _receipt(status="failure", refusal={"verdict": "deny"})
        assert "LEVEL_2_REFUSAL_EXECUTED" in _fail_codes(check_conformance(r, 2))

    def test_refusal_with_blocked_passes(self) -> None:
        r = _receipt(status="blocked", refusal={"verdict": "deny"})
        assert _fail_codes(check_conformance(r, 2)) == set()

    def test_not_checked_below_level_2(self) -> None:
        r = _receipt(status="success", refusal={"verdict": "deny"})
        assert _fail_codes(check_conformance(r, 1)) == set()


_CONSISTENT = {
    ("deny", "deny"),
    ("require-approval", "deny"),
    ("require-approval", "require-approval"),
    ("require-approval", "expired"),
    ("escalate", "deny"),
    ("escalate", "require-approval"),
    ("escalate", "expired"),
}


class TestConformanceRefusalDecision:
    @pytest.mark.parametrize("decision", ["allow", "deny", "require-approval", "escalate"])
    @pytest.mark.parametrize("verdict", ["deny", "require-approval", "expired"])
    def test_decision_verdict_matrix(self, decision: str, verdict: str) -> None:
        r = _receipt(decision=decision, refusal={"verdict": verdict})
        fired = "LEVEL_2_REFUSAL_DECISION_MISMATCH" in _fail_codes(check_conformance(r, 2))
        assert fired is ((decision, verdict) not in _CONSISTENT)


class TestConformanceApprovalRelaxation:
    def test_blocked_require_approval_without_approval_passes_level_2(self) -> None:
        r = _receipt(decision="require-approval", refusal={"verdict": "require-approval"})
        assert _fail_codes(check_conformance(r, 2)) == set()

    def test_blocked_without_refusal_also_passes_level_2(self) -> None:
        """The relaxation follows the v0.1 prose (approval only if the action
        proceeded); it does not depend on the receipt carrying a refusal."""
        r = _receipt(decision="require-approval")
        assert _fail_codes(check_conformance(r, 2)) == set()


class TestLevel4ApprovalChecksOnRefusals:
    """The stale/unauthorized-approver checks exist to catch an action that
    RAN on a bad approval. A receipt that records the bad approval was
    refused is the system working, so those checks do not apply to it."""

    def test_refused_stale_approval_is_not_flagged(self) -> None:
        r = _receipt(
            decision="require-approval",
            refusal={"verdict": "expired"},
            approval=STALE_APPROVAL,
        )
        checks = check_conformance(r, 4, policy_full=POLICY_60S)
        assert _fail_codes(checks) == set()
        assert "LEVEL_4_APPROVAL_CHECKS_NOT_APPLICABLE" in {c.code for c in checks}

    def test_refused_unauthorized_approver_is_not_flagged(self) -> None:
        approval = {"approver": {"id": "user:intern"}, "approved_at": "2026-06-15T14:22:50Z"}
        r = _receipt(decision="require-approval", refusal={"verdict": "deny"}, approval=approval)
        assert _fail_codes(check_conformance(r, 4, policy_full=POLICY_60S)) == set()

    def test_stale_approval_on_executed_receipt_still_fires(self) -> None:
        r = _receipt(decision="require-approval", status="success", approval=STALE_APPROVAL)
        codes = _fail_codes(check_conformance(r, 4, policy_full=POLICY_60S))
        assert "LEVEL_4_STALE_APPROVAL" in codes

    def test_blocked_without_refusal_still_fires(self) -> None:
        """The exemption needs the refusal record, not just a blocked status."""
        r = _receipt(decision="require-approval", approval=STALE_APPROVAL)
        codes = _fail_codes(check_conformance(r, 4, policy_full=POLICY_60S))
        assert "LEVEL_4_STALE_APPROVAL" in codes

    def test_refusal_that_executed_still_fires(self) -> None:
        r = _receipt(
            decision="require-approval",
            status="success",
            refusal={"verdict": "expired"},
            approval=STALE_APPROVAL,
        )
        codes = _fail_codes(check_conformance(r, 4, policy_full=POLICY_60S))
        assert {"LEVEL_4_STALE_APPROVAL", "LEVEL_2_REFUSAL_EXECUTED"} <= codes


ACTION: dict[str, Any] = {
    "actor": {"type": "agent", "id": "agent:test"},
    "agent": {"framework": "f", "framework_version": "1", "model": "m"},
    "tool": {"name": "t", "version": "1", "capability": "test.cap"},
    "target": {"system": "s.test", "environment": "prod", "resource_id": "r"},
    "arguments": {"x": 1},
}


def _setup(rule: str, **policy_extra: Any) -> dict[str, Any]:
    return {
        "receipt_version": V02,
        "now": NOW,
        "policies": [
            {"name": "p", "version": "1", "rule": rule, "capabilities": ["test.cap"]} | policy_extra
        ],
    }


def _approval(approver_id: str = "user:lead", at: str = "2026-06-15T14:22:30Z") -> dict:
    return {
        "capability": "test.cap",
        "approver": {"type": "human", "id": approver_id},
        "approved_at": at,
    }


def _attempt(setup: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    outcome = ReferenceImplementation().attempt(copy.deepcopy(ACTION), setup=setup)
    assert outcome.receipt is not None
    assert validate_receipt(outcome.receipt) == [], validate_receipt(outcome.receipt)
    assert outcome.receipt["receipt_hash"] == compute_receipt_hash(outcome.receipt)
    return outcome.decision, outcome.receipt


class TestRuntimeV02Refusals:
    def test_policy_deny(self) -> None:
        decision, r = _attempt(_setup("deny"))
        assert decision == "deny"
        assert r["version"] == V02
        assert r["execution"]["status"] == "blocked"
        assert r["refusal"] == {"verdict": "deny", "reason_code": "policy-deny"}

    def test_no_matching_policy(self) -> None:
        setup = _setup("allow")
        setup["policies"][0]["capabilities"] = ["other.cap"]
        decision, r = _attempt(setup)
        assert decision == "deny"
        assert r["policy"]["name"] == "implicit.deny"
        assert r["refusal"] == {"verdict": "deny", "reason_code": "no-matching-policy"}

    def test_escalate_unresolved(self) -> None:
        decision, r = _attempt(_setup("escalate"))
        assert decision == "escalate"
        assert r["refusal"] == {
            "verdict": "require-approval",
            "reason_code": "escalation-unresolved",
        }

    def test_approval_missing(self) -> None:
        decision, r = _attempt(_setup("require-approval"))
        assert decision == "require-approval"
        assert "approval" not in r
        assert r["refusal"] == {"verdict": "require-approval", "reason_code": "approval-missing"}

    def test_unauthorized_approver(self) -> None:
        setup = _setup("require-approval", approvers=[{"id": "user:lead", "type": "human"}])
        setup["approvals"] = [_approval("user:intern")]
        decision, r = _attempt(setup)
        assert decision == "deny"
        assert r["approval"]["approver"]["id"] == "user:intern"
        assert r["execution"]["status"] == "blocked"
        assert r["refusal"] == {"verdict": "deny", "reason_code": "approver-not-authorized"}

    def test_expired_approval(self) -> None:
        setup = _setup("require-approval", approval_max_age_seconds=60)
        setup["approvals"] = [_approval(at="2026-06-15T14:21:59Z")]  # 61s before NOW
        decision, r = _attempt(setup)
        assert decision == "deny"
        assert r["approval"]["approved_at"] == "2026-06-15T14:21:59Z"
        assert r["refusal"] == {"verdict": "expired", "reason_code": "approval-window-elapsed"}

    def test_approval_exactly_at_window_edge_executes(self) -> None:
        setup = _setup("require-approval", approval_max_age_seconds=60)
        setup["approvals"] = [_approval(at="2026-06-15T14:22:00Z")]  # exactly 60s
        decision, r = _attempt(setup)
        assert decision == "allow"
        assert "refusal" not in r
        assert r["execution"]["status"] == "success"

    def test_nan_window_fails_closed(self) -> None:
        setup = _setup("require-approval", approval_max_age_seconds=float("nan"))
        setup["approvals"] = [_approval()]
        decision, r = _attempt(setup)
        assert decision == "deny"
        assert r["refusal"] == {"verdict": "deny", "reason_code": "approval-window-invalid"}

    def test_unreadable_approval_time_fails_closed(self) -> None:
        setup = _setup("require-approval", approval_max_age_seconds=60)
        setup["approvals"] = [_approval(at="last tuesday")]
        outcome = ReferenceImplementation().attempt(copy.deepcopy(ACTION), setup=setup)
        assert outcome.decision == "deny"
        assert outcome.receipt is not None
        assert outcome.receipt["refusal"] == {
            "verdict": "deny",
            "reason_code": "approval-time-unreadable",
        }

    def test_fresh_authorized_approval_executes(self) -> None:
        setup = _setup(
            "require-approval",
            approvers=[{"id": "user:lead", "type": "human"}],
            approval_max_age_seconds=60,
        )
        setup["approvals"] = [_approval()]
        decision, r = _attempt(setup)
        assert decision == "allow"
        assert r["policy"]["decision"] == "require-approval"
        assert r["execution"]["status"] == "success"
        assert "refusal" not in r

    def test_allow_carries_no_refusal(self) -> None:
        decision, r = _attempt(_setup("allow"))
        assert decision == "allow"
        assert "refusal" not in r

    @pytest.mark.parametrize("rule", ["deny", "escalate", "require-approval", "allow"])
    def test_refusal_receipts_pass_level_4_with_full_context(self, rule: str) -> None:
        setup = _setup(rule, approvers=[{"id": "user:lead", "type": "human"}])
        _, r = _attempt(setup)
        checks = check_conformance(
            r,
            4,
            arguments=ACTION["arguments"],
            policy_full=setup["policies"][0],
            prior_receipt_ids=set(),
            policy_store={("p", "1")},
        )
        assert _fail_codes(checks) == set()

    def test_v01_mode_is_unchanged(self) -> None:
        """Without receipt_version the runtime keeps its v0.1 behaviour,
        which scenarios 11 and 12 rely on to exercise the verifier."""
        setup = _setup("require-approval", approval_max_age_seconds=60)
        del setup["receipt_version"]
        setup["approvals"] = [_approval(at="2024-01-01T00:00:00Z")]
        decision, r = _attempt(setup)
        assert decision == "allow"
        assert r["version"] == "agentboundary/v0.1"
        assert "refusal" not in r


class TestProvenancePaths:
    def test_refusal_paths_are_provenance_paths(self) -> None:
        assert "refusal.verdict" in ALL_PROVENANCE_PATHS
        assert "refusal.reason_code" in ALL_PROVENANCE_PATHS

    def test_schema_and_code_path_sets_agree(self) -> None:
        schema_path = (
            Path(__file__).resolve().parent.parent
            / "docs"
            / "schemas"
            / "action-receipt-v0.2-alpha.json"
        )
        schema = json.loads(schema_path.read_text("utf-8"))
        assert set(schema["properties"]["provenance"]["properties"]) == set(ALL_PROVENANCE_PATHS)


class TestSpecPathClaims:
    """The spec states a path count and lists the paths; both are claims
    about code (the count once drifted to 28 while the code had 30)."""

    _SPEC = Path(__file__).resolve().parent.parent / "docs" / "spec" / "v0.2-alpha.md"

    def test_stated_counts_match_code(self) -> None:
        import re

        text = self._SPEC.read_text("utf-8")
        counts = {int(n) for n in re.findall(r"(?<![\w.])(\d+) (?:dotted )?paths\b", text)}
        assert counts == {len(ALL_PROVENANCE_PATHS)}

    def test_listed_paths_match_code(self) -> None:
        text = self._SPEC.read_text("utf-8")
        section = text[text.index("## 3. Provenance path set") : text.index("## 4. Score formula")]
        blocks = section.split("```")[1::2]
        listed = {tok for block in blocks for tok in block.split()}
        assert listed == set(ALL_PROVENANCE_PATHS)


class TestRuntimeApprovalGuardsFailClosed:
    """Regressions for the adversarial review: every approval guard in the
    v0.2-alpha runtime refuses on input it cannot evaluate."""

    def _refusal(self, approval: dict, **policy: Any) -> dict | None:
        setup = _setup("require-approval", **policy)
        setup["approvals"] = [approval]
        outcome = ReferenceImplementation().attempt(copy.deepcopy(ACTION), setup=setup)
        assert outcome.receipt is not None
        return outcome.receipt.get("refusal")

    def test_forward_dated_approval_is_refused(self) -> None:
        refusal = self._refusal(_approval(at="2027-06-15T14:23:00Z"), approval_max_age_seconds=60)
        assert refusal == {"verdict": "deny", "reason_code": "approval-postdates-action"}

    def test_small_clock_skew_is_tolerated(self) -> None:
        refusal = self._refusal(_approval(at="2026-06-15T14:23:30Z"), approval_max_age_seconds=60)
        assert refusal is None

    def test_approver_entry_without_id_matches_nobody(self) -> None:
        approval = {"capability": "test.cap", "approver": {"type": "human"}, "approved_at": NOW}
        refusal = self._refusal(approval, approvers=[{"type": "human"}])
        assert refusal == {"verdict": "deny", "reason_code": "approver-not-authorized"}

    def test_bool_id_does_not_match_int_id(self) -> None:
        approval = {"capability": "test.cap", "approver": {"id": True}, "approved_at": NOW}
        refusal = self._refusal(approval, approvers=[{"id": 1}])
        assert refusal == {"verdict": "deny", "reason_code": "approver-not-authorized"}

    @pytest.mark.parametrize("approver", ["bob", ["x"], None])
    def test_malformed_approver_is_refused(self, approver: Any) -> None:
        approval = {"capability": "test.cap", "approver": approver, "approved_at": NOW}
        refusal = self._refusal(approval, approvers=[{"id": "bob"}])
        assert refusal == {"verdict": "deny", "reason_code": "approver-not-authorized"}

    @pytest.mark.parametrize("window", ["abc", True, float("inf"), -1, [60]])
    def test_unusable_window_is_refused(self, window: Any) -> None:
        refusal = self._refusal(_approval(), approval_max_age_seconds=window)
        assert refusal == {"verdict": "deny", "reason_code": "approval-window-invalid"}

    def test_huge_integer_window_does_not_crash(self) -> None:
        assert self._refusal(_approval(), approval_max_age_seconds=10**400) is None


class TestRuntimeApproverIdEdges:
    def _refusal(self, approver: Any, approvers: list[Any]) -> Any:
        setup = _setup("require-approval", approvers=approvers)
        setup["approvals"] = [{"capability": "test.cap", "approver": approver, "approved_at": NOW}]
        outcome = ReferenceImplementation().attempt(copy.deepcopy(ACTION), setup=setup)
        assert outcome.receipt is not None
        return outcome.receipt.get("refusal")

    def test_empty_id_matches_nobody(self) -> None:
        refusal = self._refusal({"id": ""}, [{"id": ""}])
        assert refusal == {"verdict": "deny", "reason_code": "approver-not-authorized"}

    def test_unhashable_id_is_refused_not_crashed(self) -> None:
        refusal = self._refusal({"id": ["x"]}, [{"id": "x"}])
        assert refusal == {"verdict": "deny", "reason_code": "approver-not-authorized"}
