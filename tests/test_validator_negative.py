"""Validator negative-path tests. Each known-bad receipt must produce a
specific, human-readable error so downstream conformance tests (W3) can
assert against the message."""

import copy
from typing import Any

import pytest

from agentboundary.validator import validate_receipt


def _has_error_containing(errors: list[str], path: str, fragment: str) -> bool:
    """Return True if any error mentions both `path` and `fragment`."""
    return any(path in e and fragment in e for e in errors)


def test_missing_required_top_level_field_fails(minimal_receipt: dict[str, Any]) -> None:
    bad = copy.deepcopy(minimal_receipt)
    del bad["receipt_id"]
    errors = validate_receipt(bad)
    assert _has_error_containing(errors, "root", "receipt_id"), errors


def test_wrong_version_literal_fails(minimal_receipt: dict[str, Any]) -> None:
    bad = copy.deepcopy(minimal_receipt)
    bad["version"] = "agentboundary/v0.2"
    errors = validate_receipt(bad)
    assert any("version" in e and "agentboundary/v0.1" in e for e in errors), errors


def test_invalid_environment_enum_fails(minimal_receipt: dict[str, Any]) -> None:
    bad = copy.deepcopy(minimal_receipt)
    bad["target"]["environment"] = "preprod"  # type: ignore[index]
    errors = validate_receipt(bad)
    assert _has_error_containing(errors, "target.environment", "preprod"), errors


def test_short_arguments_hash_fails(minimal_receipt: dict[str, Any]) -> None:
    bad = copy.deepcopy(minimal_receipt)
    bad["arguments_hash"] = "a" * 32  # half-length, should fail the regex
    errors = validate_receipt(bad)
    # jsonschema reports "does not match '^[a-f0-9]{64}$'" — the regex is the signal
    assert _has_error_containing(errors, "arguments_hash", "[a-f0-9]{64}"), errors


def test_uppercase_arguments_hash_fails(minimal_receipt: dict[str, Any]) -> None:
    bad = copy.deepcopy(minimal_receipt)
    bad["arguments_hash"] = "A" * 64  # uppercase, must be lowercase
    errors = validate_receipt(bad)
    # jsonschema reports "does not match '^[a-f0-9]{64}$'" — the regex is the signal
    assert _has_error_containing(errors, "arguments_hash", "[a-f0-9]{64}"), errors


def test_unknown_actor_type_fails(minimal_receipt: dict[str, Any]) -> None:
    bad = copy.deepcopy(minimal_receipt)
    bad["actor"]["type"] = "robot"  # type: ignore[index]
    errors = validate_receipt(bad)
    assert _has_error_containing(errors, "actor.type", "robot"), errors


def test_require_approval_decision_without_approval_block_fails(
    minimal_receipt: dict[str, Any],
) -> None:
    """If policy.decision == 'require-approval', the receipt MUST include an `approval` block.
    This is the spec's tamper-resistance hinge: an action that needed approval can't
    have a valid receipt without the approver's identity."""
    bad = copy.deepcopy(minimal_receipt)
    bad["policy"]["decision"] = "require-approval"  # type: ignore[index]
    # Note: we deliberately don't add an `approval` block.
    errors = validate_receipt(bad)
    assert any("approval" in e for e in errors), (
        "Expected validator to require an `approval` block when "
        f"policy.decision == 'require-approval'. Got errors: {errors}"
    )


def test_additional_properties_at_root_are_rejected(minimal_receipt: dict[str, Any]) -> None:
    """The schema uses `additionalProperties: false` at the root so unknown top-level
    keys can't sneak past the validator. This prevents vendor extensions from being
    silently accepted as v0.1 receipts."""
    bad = copy.deepcopy(minimal_receipt)
    bad["vendor_extension"] = {"foo": "bar"}
    errors = validate_receipt(bad)
    assert any("vendor_extension" in e for e in errors), errors


def test_well_formed_receipt_with_approval_block_passes(minimal_receipt: dict[str, Any]) -> None:
    """Sanity counter-test: a require-approval receipt with a proper approval block validates."""
    receipt = copy.deepcopy(minimal_receipt)
    receipt["policy"]["decision"] = "require-approval"  # type: ignore[index]
    receipt["approval"] = {
        "approver": {"id": "u_bob", "role": "release-manager"},
        "approved_at": "2026-06-15T11:59:00Z",
    }
    errors = validate_receipt(receipt)
    assert errors == [], errors
