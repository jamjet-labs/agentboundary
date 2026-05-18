"""Validator positive-path tests. A well-formed receipt must validate cleanly."""

from agentboundary.validator import validate_receipt


def test_minimal_receipt_validates(minimal_receipt: dict[str, object]) -> None:
    errors = validate_receipt(minimal_receipt)
    assert errors == [], f"Expected no errors, got: {errors}"
