"""Validator negative-path tests. Each known-bad receipt must produce a
specific, human-readable error so downstream conformance tests (W3) can
assert against the message."""

import copy
from typing import Any

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


def test_missing_policy_does_not_spuriously_require_approval(
    minimal_receipt: dict[str, Any],
) -> None:
    """When `policy` is absent entirely, the validator must emit ONE error
    (policy is required) — not two (policy required AND approval required).
    This guards against the JSON Schema vacuous-truth bug where `if {properties: {policy: ...}}`
    evaluates to true when policy isn't present, spuriously triggering the
    `then: {required: [approval]}` branch."""
    bad = copy.deepcopy(minimal_receipt)
    del bad["policy"]
    errors = validate_receipt(bad)
    # Must have exactly one error about policy being missing
    assert any("policy" in e and "required" in e for e in errors), errors
    # Must NOT spuriously complain about approval being missing
    assert not any("approval" in e for e in errors), (
        f"Validator spuriously required `approval` when `policy` was missing. Errors: {errors}"
    )


def test_additional_properties_at_root_are_rejected(minimal_receipt: dict[str, Any]) -> None:
    """The schema uses `additionalProperties: false` at the root so unknown top-level
    keys can't sneak past the validator. This prevents vendor extensions from being
    silently accepted as v0.1 receipts."""
    bad = copy.deepcopy(minimal_receipt)
    bad["vendor_extension"] = {"foo": "bar"}
    errors = validate_receipt(bad)
    assert any("vendor_extension" in e for e in errors), errors


def test_invalid_uuid_in_receipt_id_fails(minimal_receipt: dict[str, Any]) -> None:
    """receipt_id has format: uuid in the schema. Enforced via FORMAT_CHECKER."""
    bad = copy.deepcopy(minimal_receipt)
    bad["receipt_id"] = "not-a-uuid-at-all"
    errors = validate_receipt(bad)
    assert _has_error_containing(errors, "receipt_id", "uuid"), errors


def test_invalid_datetime_in_issued_at_fails(minimal_receipt: dict[str, Any]) -> None:
    """issued_at has format: date-time (RFC 3339). Enforced via FORMAT_CHECKER."""
    bad = copy.deepcopy(minimal_receipt)
    bad["issued_at"] = "not-a-timestamp"
    errors = validate_receipt(bad)
    assert _has_error_containing(errors, "issued_at", "date-time"), errors
