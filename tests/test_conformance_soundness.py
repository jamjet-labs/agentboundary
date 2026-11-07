"""Conformance rules that were missing or could not fire.

* Spec v0.1 section 5.4 has two Level 4 MUSTs with no check behind them:
  rejecting arguments that changed after policy evaluation, and rejecting an
  approval reused for a different action.
* The stale-approval check passed an approval dated after the receipt.
* LEVEL_2_APPROVAL_REQUIRED and LEVEL_2_DECISION_INVALID never fired, because
  the schema rejected the receipt first and the level codes were dropped.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from agentboundary.conformance import approval_fingerprint, check_conformance
from agentboundary.hashing import compute_arguments_hash, compute_receipt_hash
from agentboundary.runtime import ReferenceImplementation

ARGS = {"claim_id": 789, "payout_cents": 4200}
POLICY = {
    "name": "acme.claims.mutation",
    "version": "5",
    "rule": "require-approval",
    "capabilities": ["spring.service.mutation"],
    "approvers": [{"id": "user:eng-lead@acme", "type": "human"}],
    "approval_max_age_seconds": 600,
}


def _rehash(r: dict[str, Any]) -> dict[str, Any]:
    r.pop("receipt_hash", None)
    r["receipt_hash"] = compute_receipt_hash(r)
    return r


@pytest.fixture
def receipt() -> dict[str, Any]:
    return _rehash(
        {
            "version": "agentboundary/v0.1",
            "receipt_id": "0192c8d0-1f2a-7c3e-bf2a-0000000000a2",
            "issued_at": "2026-06-15T14:23:00Z",
            "actor": {"type": "agent", "id": "agent:copilot"},
            "agent": {"framework": "spring-ai", "framework_version": "1.0", "model": "gpt-4o"},
            "tool": {"name": "claims-service", "capability": "spring.service.mutation"},
            "target": {"system": "acme-claims.prod", "environment": "prod"},
            "arguments_hash": compute_arguments_hash(ARGS),
            "policy": {
                "name": "acme.claims.mutation",
                "version": "5",
                "decision": "require-approval",
            },
            "approval": {
                "approver": {"id": "user:eng-lead@acme"},
                "approved_at": "2026-06-15T14:20:00Z",
            },
            "execution": {"status": "success", "completed_at": "2026-06-15T14:23:00Z"},
        }
    )


def _fails(receipt: dict[str, Any], **kw: Any) -> set[str]:
    kw.setdefault("arguments", ARGS)
    return {c.code for c in check_conformance(receipt, 4, **kw) if c.severity == "fail"}


def _codes(receipt: dict[str, Any], level: int = 4, **kw: Any) -> set[str]:
    return {c.code for c in check_conformance(receipt, level, **kw)}


class TestFutureDatedApproval:
    def test_approval_dated_after_issuance_fails(self, receipt: dict[str, Any]) -> None:
        receipt["approval"]["approved_at"] = "2026-06-16T14:23:00Z"
        _rehash(receipt)
        assert "LEVEL_4_FUTURE_DATED_APPROVAL" in _fails(receipt, policy_full=POLICY)

    def test_fails_without_policy_context(self, receipt: dict[str, Any]) -> None:
        receipt["approval"]["approved_at"] = "2099-01-01T00:00:00Z"
        _rehash(receipt)
        assert "LEVEL_4_FUTURE_DATED_APPROVAL" in _fails(receipt)

    def test_small_clock_skew_is_tolerated(self, receipt: dict[str, Any]) -> None:
        receipt["approval"]["approved_at"] = "2026-06-15T14:24:00Z"  # 60s ahead
        _rehash(receipt)
        assert not _fails(receipt, policy_full=POLICY)

    def test_recorded_refusal_is_not_flagged(self, receipt: dict[str, Any]) -> None:
        receipt["version"] = "agentboundary/v0.2-alpha"
        receipt["approval"]["approved_at"] = "2026-06-16T14:23:00Z"
        receipt["execution"] = {"status": "blocked", "completed_at": "2026-06-15T14:23:00Z"}
        receipt["refusal"] = {"verdict": "deny", "reason_code": "approval-postdates-action"}
        _rehash(receipt)
        assert not _fails(receipt, policy_full=POLICY)


class TestStaleWindowFailsClosed:
    @pytest.mark.parametrize("window", [float("nan"), "600", -1, True, float("inf")])
    def test_unusable_window_fails(self, receipt: dict[str, Any], window: Any) -> None:
        policy = {**POLICY, "approval_max_age_seconds": window}
        assert "LEVEL_4_STALE_APPROVAL" in _fails(receipt, policy_full=policy)

    def test_window_edge_passes(self, receipt: dict[str, Any]) -> None:
        policy = {**POLICY, "approval_max_age_seconds": 180}
        assert not _fails(receipt, policy_full=policy)

    def test_one_second_past_the_window_fails(self, receipt: dict[str, Any]) -> None:
        policy = {**POLICY, "approval_max_age_seconds": 179}
        assert "LEVEL_4_STALE_APPROVAL" in _fails(receipt, policy_full=policy)


class TestArgumentMutation:
    def test_ran_with_other_arguments_fails(self, receipt: dict[str, Any]) -> None:
        mutated = {**ARGS, "payout_cents": 420000}
        assert "LEVEL_4_ARGUMENT_MUTATION" in _fails(receipt, executed_arguments=mutated)

    def test_ran_with_the_evaluated_arguments_passes(self, receipt: dict[str, Any]) -> None:
        # same logical arguments, different key order and an integer-valued float
        same = {"payout_cents": 4200.0, "claim_id": 789}
        assert not _fails(receipt, executed_arguments=same)

    def test_skipped_and_said_so_without_executed_arguments(self, receipt: dict[str, Any]) -> None:
        assert "LEVEL_4_SKIPPED_NO_EXECUTED_ARGUMENTS" in _codes(receipt, arguments=ARGS)

    def test_not_applicable_to_a_blocked_action(self, receipt: dict[str, Any]) -> None:
        receipt["execution"]["status"] = "blocked"
        receipt.pop("approval")
        receipt["policy"]["decision"] = "deny"
        _rehash(receipt)
        codes = _codes(receipt, arguments=ARGS, executed_arguments={"other": 1})
        assert "LEVEL_4_ARGUMENT_MUTATION" not in codes
        assert "LEVEL_4_SKIPPED_NO_EXECUTED_ARGUMENTS" not in codes


class TestApprovalReplay:
    def test_same_approval_on_another_action_fails(self, receipt: dict[str, Any]) -> None:
        seen = {approval_fingerprint(receipt["approval"]): "0192c8d0-1f2a-7c3e-bf2a-0000000000a1"}
        assert "LEVEL_4_APPROVAL_REPLAY" in _fails(receipt, prior_approvals=seen)

    def test_same_receipt_seen_again_is_not_a_replay(self, receipt: dict[str, Any]) -> None:
        seen = {approval_fingerprint(receipt["approval"]): receipt["receipt_id"]}
        assert "LEVEL_4_APPROVAL_REPLAY" not in _fails(receipt, prior_approvals=seen)

    def test_a_different_approval_passes(self, receipt: dict[str, Any]) -> None:
        other = deepcopy(receipt["approval"])
        other["approved_at"] = "2026-06-15T13:05:00Z"
        seen = {approval_fingerprint(other): "0192c8d0-1f2a-7c3e-bf2a-0000000000a1"}
        assert not _fails(receipt, prior_approvals=seen)

    def test_skipped_and_said_so_without_context(self, receipt: dict[str, Any]) -> None:
        assert "LEVEL_4_SKIPPED_NO_PRIOR_APPROVALS" in _codes(receipt, arguments=ARGS)

    def test_fingerprint_ignores_member_order(self) -> None:
        a = {"approver": {"id": "u", "role": "r"}, "approved_at": "2026-06-15T14:20:00Z"}
        b = {"approved_at": "2026-06-15T14:20:00Z", "approver": {"role": "r", "id": "u"}}
        assert approval_fingerprint(a) == approval_fingerprint(b)


class TestSchemaShadowedLevelCodes:
    def test_removed_approval_names_the_level_2_rule(self, receipt: dict[str, Any]) -> None:
        receipt.pop("approval")
        _rehash(receipt)
        codes = _codes(receipt, level=2)
        assert {"SCHEMA_INVALID", "LEVEL_2_APPROVAL_REQUIRED"} <= codes

    def test_decision_outside_enum_names_the_level_2_rule(self, receipt: dict[str, Any]) -> None:
        receipt["policy"]["decision"] = "approved"
        _rehash(receipt)
        assert {"SCHEMA_INVALID", "LEVEL_2_DECISION_INVALID"} <= _codes(receipt, level=2)

    def test_level_1_reports_only_the_schema(self, receipt: dict[str, Any]) -> None:
        receipt.pop("approval")
        _rehash(receipt)
        assert _codes(receipt, level=1) == {"SCHEMA_INVALID"}

    def test_unrelated_schema_errors_suppress_level_codes(self, receipt: dict[str, Any]) -> None:
        receipt.pop("approval")
        receipt.pop("actor")
        _rehash(receipt)
        assert _codes(receipt, level=2) == {"SCHEMA_INVALID"}


class TestRuntime:
    def _attempt(self, version: str | None, rule: str = "require-approval") -> Any:
        setup: dict[str, Any] = {
            "now": "2026-06-15T14:23:00Z",
            "policies": [{**POLICY, "rule": rule}],
            "approvals": [
                {
                    "capability": "spring.service.mutation",
                    "approver": {"type": "human", "id": "user:eng-lead@acme"},
                    "approved_at": "2026-06-15T14:20:00Z",
                }
            ],
        }
        if version:
            setup["receipt_version"] = version
        action = {
            "actor": {"type": "agent", "id": "agent:copilot"},
            "agent": {"framework": "spring-ai", "framework_version": "1.0", "model": "gpt-4o"},
            "tool": {"name": "claims-service", "capability": "spring.service.mutation"},
            "target": {"system": "acme-claims.prod", "environment": "prod"},
            "arguments": ARGS,
            "executed_arguments": {**ARGS, "payout_cents": 420000},
        }
        return ReferenceImplementation().attempt(action, setup=setup)

    def test_v02_refuses_changed_arguments(self) -> None:
        out = self._attempt("agentboundary/v0.2-alpha")
        assert out.decision == "deny"
        assert out.receipt["execution"]["status"] == "blocked"
        assert out.receipt["refusal"] == {"verdict": "deny", "reason_code": "arguments-mutated"}
        assert out.executed_arguments is None
        assert not _fails(out.receipt, arguments=ARGS, policy_full=POLICY)

    def test_v02_allow_rule_records_the_error_without_a_refusal(self) -> None:
        out = self._attempt("agentboundary/v0.2-alpha", rule="allow")
        assert out.receipt["execution"] == {
            "status": "blocked",
            "completed_at": "2026-06-15T14:23:00Z",
            "error_code": "arguments-mutated",
        }
        assert "refusal" not in out.receipt
        assert not _fails(out.receipt, arguments=ARGS)

    def test_v01_runs_them_and_the_verifier_catches_it(self) -> None:
        out = self._attempt(None)
        assert out.receipt["execution"]["status"] == "success"
        assert out.executed_arguments == {**ARGS, "payout_cents": 420000}
        fails = _fails(out.receipt, arguments=ARGS, executed_arguments=out.executed_arguments)
        assert fails == {"LEVEL_4_ARGUMENT_MUTATION"}

    def test_v02_refuses_a_forward_dated_approval_without_a_window(self) -> None:
        from agentboundary.runtime import _approval_problem

        policy = {k: v for k, v in POLICY.items() if k != "approval_max_age_seconds"}
        approval = {"approver": {"id": "user:eng-lead@acme"}, "approved_at": "2026-06-16T00:00:00Z"}
        assert _approval_problem(policy, approval, "2026-06-15T14:23:00Z") == {
            "verdict": "deny",
            "reason_code": "approval-postdates-action",
        }
