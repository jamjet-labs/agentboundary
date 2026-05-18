"""Validator positive-path tests. A well-formed receipt must validate cleanly."""

import copy
import json
from pathlib import Path
from typing import Any

from agentboundary.validator import validate_receipt


def test_minimal_receipt_validates(minimal_receipt: dict[str, object]) -> None:
    errors = validate_receipt(minimal_receipt)
    assert errors == [], f"Expected no errors, got: {errors}"


def test_require_approval_with_approval_block_validates(minimal_receipt: dict[str, Any]) -> None:
    """Counter-test to the negative `require-approval without approval` case:
    a receipt with policy.decision == 'require-approval' AND a proper approval
    block must validate cleanly."""
    receipt = copy.deepcopy(minimal_receipt)
    receipt["policy"]["decision"] = "require-approval"
    receipt["approval"] = {
        "approver": {"id": "u_bob", "role": "release-manager"},
        "approved_at": "2026-06-15T11:59:00Z",
    }
    errors = validate_receipt(receipt)
    assert errors == [], errors


def test_github_merge_example_validates(examples_dir: Path) -> None:
    receipt = json.loads((examples_dir / "github-merge.json").read_text())
    errors = validate_receipt(receipt)
    assert errors == [], f"github-merge.json should validate. Errors: {errors}"


def test_spring_service_mutation_example_validates(examples_dir: Path) -> None:
    receipt = json.loads((examples_dir / "spring-service-mutation.json").read_text())
    errors = validate_receipt(receipt)
    assert errors == [], f"spring-service-mutation.json should validate. Errors: {errors}"


def test_stripe_refund_example_validates(examples_dir: Path) -> None:
    receipt = json.loads((examples_dir / "stripe-refund.json").read_text())
    errors = validate_receipt(receipt)
    assert errors == [], f"stripe-refund.json should validate. Errors: {errors}"
