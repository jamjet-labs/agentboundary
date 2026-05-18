"""Tests for spec §5 conformance level invariants."""

from __future__ import annotations

from copy import deepcopy

import pytest

from agentboundary.conformance import ConformanceCheck, check_conformance  # noqa: F401
from agentboundary.hashing import compute_arguments_hash, compute_receipt_hash


@pytest.fixture
def minimal_l3_receipt() -> dict:
    base = {
        "version": "agentboundary/v0.1",
        "receipt_id": "0192c8d0-1f2a-7c3e-bf2a-1a4d3f5e6c7b",
        "issued_at": "2026-06-15T14:23:08Z",
        "actor": {"type": "agent", "id": "agent:test"},
        "agent": {
            "framework": "test",
            "framework_version": "1.0",
            "model": "test",
            "model_version": "1",
        },
        "tool": {"name": "t", "version": "0.1", "capability": "test.do"},
        "target": {"system": "test.example", "environment": "dev", "resource_id": "r1"},
        "arguments_hash": compute_arguments_hash({"x": 1}),
        "policy": {"name": "p", "version": "1", "decision": "allow"},
        "execution": {
            "status": "success",
            "completed_at": "2026-06-15T14:23:09Z",
            "result_ref": "ref:1",
        },
    }
    base["receipt_hash"] = compute_receipt_hash(base)
    return base


class TestSchemaShortCircuit:
    def test_schema_failure_short_circuits(self) -> None:
        # Receipt with no required fields at all
        checks = check_conformance({}, level=3)
        codes = [c.code for c in checks]
        assert "SCHEMA_INVALID" in codes
        # No level checks should appear when schema fails
        assert not any(c.code.startswith("LEVEL_") for c in checks)


class TestLevel1:
    def test_l1_passes_on_valid_receipt(self, minimal_l3_receipt: dict) -> None:
        checks = check_conformance(minimal_l3_receipt, level=1)
        assert [c for c in checks if c.severity == "fail"] == []


class TestLevel2:
    def test_l2_requires_policy_decision_enum(self, minimal_l3_receipt: dict) -> None:
        receipt = deepcopy(minimal_l3_receipt)
        # Wipe receipt_hash so the L3 check doesn't fire on a stale digest
        receipt.pop("receipt_hash", None)
        receipt["policy"]["decision"] = "approve"  # invalid enum
        checks = check_conformance(receipt, level=2)
        # The schema check fires first since "approve" violates the schema enum.
        # Either way we expect a failure.
        assert any(c.severity == "fail" for c in checks)

    def test_l2_requires_approval_when_decision_is_require_approval(
        self, minimal_l3_receipt: dict
    ) -> None:
        receipt = deepcopy(minimal_l3_receipt)
        receipt["policy"]["decision"] = "require-approval"
        # No approval block — schema's allOf should catch this; the L2 check
        # mirrors it so the failure is reported even if the schema is lenient.
        receipt.pop("receipt_hash", None)
        receipt["receipt_hash"] = compute_receipt_hash(receipt)
        checks = check_conformance(receipt, level=2)
        codes = {c.code for c in checks if c.severity == "fail"}
        # Either the schema check or the L2 check must catch it
        assert codes & {"SCHEMA_INVALID", "LEVEL_2_APPROVAL_REQUIRED"}


class TestLevel3:
    def test_l3_passes_on_minimal_valid(self, minimal_l3_receipt: dict) -> None:
        checks = check_conformance(
            minimal_l3_receipt,
            level=3,
            arguments={"x": 1},
        )
        assert [c for c in checks if c.severity == "fail"] == []

    def test_l3_arguments_hash_required(self, minimal_l3_receipt: dict) -> None:
        receipt = deepcopy(minimal_l3_receipt)
        del receipt["arguments_hash"]
        receipt.pop("receipt_hash", None)
        receipt["receipt_hash"] = compute_receipt_hash(receipt)
        checks = check_conformance(receipt, level=3)
        codes = {c.code for c in checks if c.severity == "fail"}
        assert "LEVEL_3_ARGUMENTS_HASH_REQUIRED" in codes

    def test_l3_arguments_hash_mismatch(self, minimal_l3_receipt: dict) -> None:
        # Receipt claims hash for {"x":1}, but we pass {"x":2} as arguments
        checks = check_conformance(
            minimal_l3_receipt,
            level=3,
            arguments={"x": 2},
        )
        codes = {c.code for c in checks if c.severity == "fail"}
        assert "LEVEL_3_ARGUMENTS_HASH_MISMATCH" in codes

    def test_l3_arguments_hash_skipped_when_no_arguments_supplied(
        self, minimal_l3_receipt: dict
    ) -> None:
        # arguments=None means "we don't have them; skip the mismatch check"
        checks = check_conformance(minimal_l3_receipt, level=3, arguments=None)
        codes = {c.code for c in checks}
        assert "LEVEL_3_ARGUMENTS_HASH_MISMATCH" not in codes
        assert "SKIPPED_NO_ARGUMENTS" in codes

    def test_l3_receipt_hash_mismatch(self, minimal_l3_receipt: dict) -> None:
        receipt = deepcopy(minimal_l3_receipt)
        receipt["receipt_hash"] = "0" * 64  # syntactically valid but wrong
        checks = check_conformance(receipt, level=3, arguments={"x": 1})
        codes = {c.code for c in checks if c.severity == "fail"}
        assert "LEVEL_3_RECEIPT_HASH_MISMATCH" in codes


class TestLevel4:
    def test_l4_returns_not_implemented_info(self, minimal_l3_receipt: dict) -> None:
        checks = check_conformance(minimal_l3_receipt, level=4, arguments={"x": 1})
        codes = {(c.code, c.severity) for c in checks}
        assert ("LEVEL_4_NOT_IMPLEMENTED", "info") in codes
        # No L4 failures should be reported for a Level 3-valid receipt
        l4_fails = [c for c in checks if c.severity == "fail" and c.code.startswith("LEVEL_4_")]
        assert l4_fails == []


class TestOutputOrdering:
    def test_checks_sorted_by_level_then_code(self, minimal_l3_receipt: dict) -> None:
        checks = check_conformance(minimal_l3_receipt, level=4, arguments={"x": 1})
        keys = [(c.level, c.code) for c in checks]
        assert keys == sorted(keys)
