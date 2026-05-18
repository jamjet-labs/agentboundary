"""Tests for the Implementation ABC and ReferenceImplementation decisions."""

from __future__ import annotations

import pytest

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
