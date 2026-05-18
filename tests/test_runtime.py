"""Tests for the Implementation ABC and ReferenceImplementation decisions."""

from __future__ import annotations

import pytest

from agentboundary.hashing import compute_arguments_hash, compute_receipt_hash
from agentboundary.runtime import (
    Implementation,
    ReferenceImplementation,
    RuntimeOutcome,
)


@pytest.fixture
def allow_setup() -> dict:
    return {
        "policies": [
            {
                "name": "p.test.allow",
                "version": "1",
                "rule": "allow",
                "capabilities": ["test.cap"],
            }
        ]
    }


@pytest.fixture
def basic_action() -> dict:
    return {
        "actor": {"type": "agent", "id": "agent:test"},
        "agent": {
            "framework": "test",
            "framework_version": "1",
            "model": "m",
            "model_version": "1",
        },
        "tool": {"name": "t", "version": "1", "capability": "test.cap"},
        "target": {"system": "s.test", "environment": "dev", "resource_id": "r"},
        "arguments": {"x": 1},
    }


class TestImplementationABC:
    def test_cannot_instantiate_abstract(self) -> None:
        with pytest.raises(TypeError):
            Implementation()  # type: ignore[abstract]


class TestReferenceImplementationAllow:
    def test_allow_returns_outcome_with_receipt(
        self, allow_setup: dict, basic_action: dict
    ) -> None:
        impl = ReferenceImplementation()
        outcome = impl.attempt(basic_action, setup=allow_setup)
        assert isinstance(outcome, RuntimeOutcome)
        assert outcome.decision == "allow"
        assert outcome.receipt is not None
        assert outcome.receipt["policy"]["name"] == "p.test.allow"
        assert outcome.receipt["policy"]["decision"] == "allow"
        assert outcome.receipt["execution"]["status"] == "success"


class TestReferenceImplementationDeny:
    def test_deny_returns_no_execution(self, basic_action: dict) -> None:
        impl = ReferenceImplementation()
        setup = {
            "policies": [
                {
                    "name": "p.deny",
                    "version": "1",
                    "rule": "deny",
                    "capabilities": ["test.cap"],
                }
            ]
        }
        outcome = impl.attempt(basic_action, setup=setup)
        assert outcome.decision == "deny"
        assert outcome.receipt is not None
        assert "execution" not in outcome.receipt


class TestReferenceImplementationEscalate:
    def test_escalate_returns_no_execution(self, basic_action: dict) -> None:
        impl = ReferenceImplementation()
        setup = {
            "policies": [
                {
                    "name": "p.esc",
                    "version": "1",
                    "rule": "escalate",
                    "capabilities": ["test.cap"],
                }
            ]
        }
        outcome = impl.attempt(basic_action, setup=setup)
        assert outcome.decision == "escalate"
        assert outcome.receipt is not None
        assert "execution" not in outcome.receipt


class TestReferenceImplementationRequireApproval:
    def test_require_approval_with_approval_block_succeeds(self, basic_action: dict) -> None:
        impl = ReferenceImplementation()
        setup = {
            "policies": [
                {
                    "name": "p.appr",
                    "version": "1",
                    "rule": "require-approval",
                    "capabilities": ["test.cap"],
                    "approvers": [{"id": "user:lead", "type": "human"}],
                }
            ],
            "approvals": [
                {
                    "capability": "test.cap",
                    "approver": {"type": "human", "id": "user:lead"},
                    "approved_at": "2026-06-15T14:22:30Z",
                    "context": {},
                }
            ],
        }
        outcome = impl.attempt(basic_action, setup=setup)
        assert outcome.decision == "allow"
        assert outcome.receipt is not None
        assert outcome.receipt["policy"]["decision"] == "require-approval"
        assert outcome.receipt["approval"]["approver"]["id"] == "user:lead"
        assert outcome.receipt["execution"]["status"] == "success"

    def test_outcome_decision_diverges_from_receipt_policy_decision_when_approved(
        self, basic_action: dict
    ) -> None:
        """When require-approval is satisfied by an existing approval, the
        runtime outcome MUST be ``allow`` while the receipt's
        ``policy.decision`` MUST stay ``require-approval``. This bifurcation
        is the canary for adapters that incorrectly flatten the two.
        """
        impl = ReferenceImplementation()
        setup = {
            "policies": [
                {
                    "name": "p.appr",
                    "version": "1",
                    "rule": "require-approval",
                    "capabilities": ["test.cap"],
                }
            ],
            "approvals": [
                {
                    "capability": "test.cap",
                    "approver": {"type": "human", "id": "user:lead"},
                    "approved_at": "2026-06-15T14:22:30Z",
                    "context": {},
                }
            ],
        }
        outcome = impl.attempt(basic_action, setup=setup)
        assert outcome.decision == "allow"
        assert outcome.receipt["policy"]["decision"] == "require-approval"
        assert outcome.decision != outcome.receipt["policy"]["decision"]


class TestInjectHooks:
    @pytest.fixture
    def allow_action_with_inject(self, basic_action: dict, allow_setup: dict) -> tuple[dict, dict]:
        return basic_action, allow_setup

    def test_omit_field_removes_top_level_key(
        self, allow_action_with_inject: tuple[dict, dict]
    ) -> None:
        action, setup = allow_action_with_inject
        action = {**action, "inject": [{"op": "omit_field", "path": "policy", "after": "emit"}]}
        outcome = ReferenceImplementation().attempt(action, setup=setup)
        assert "policy" not in outcome.receipt

    def test_mutate_field_replaces_value(self, allow_action_with_inject: tuple[dict, dict]) -> None:
        action, setup = allow_action_with_inject
        action = {
            **action,
            "inject": [
                {"op": "mutate_field", "path": "issued_at", "value": "garbage", "after": "emit"}
            ],
        }
        outcome = ReferenceImplementation().attempt(action, setup=setup)
        assert outcome.receipt["issued_at"] == "garbage"

    def test_tamper_arguments_hash_changes_value(
        self, allow_action_with_inject: tuple[dict, dict]
    ) -> None:
        action, setup = allow_action_with_inject
        action = {**action, "inject": [{"op": "tamper_arguments_hash", "after": "emit"}]}
        outcome = ReferenceImplementation().attempt(action, setup=setup)
        original = compute_arguments_hash(action["arguments"])
        assert outcome.receipt["arguments_hash"] != original
        assert len(outcome.receipt["arguments_hash"]) == 64

    def test_tamper_receipt_hash_changes_value(
        self, allow_action_with_inject: tuple[dict, dict]
    ) -> None:
        action, setup = allow_action_with_inject
        action = {**action, "inject": [{"op": "tamper_receipt_hash", "after": "emit"}]}
        outcome = ReferenceImplementation().attempt(action, setup=setup)
        # The tampered hash must NOT match the recomputed one
        assert outcome.receipt["receipt_hash"] != compute_receipt_hash(outcome.receipt)
        assert len(outcome.receipt["receipt_hash"]) == 64

    def test_omit_field_on_arguments_hash(
        self, allow_action_with_inject: tuple[dict, dict]
    ) -> None:
        action, setup = allow_action_with_inject
        action = {
            **action,
            "inject": [{"op": "omit_field", "path": "arguments_hash", "after": "emit"}],
        }
        outcome = ReferenceImplementation().attempt(action, setup=setup)
        assert "arguments_hash" not in outcome.receipt
