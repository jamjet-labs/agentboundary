"""Validate Action Receipts against the v0.1 schema.

The validator returns a list of human-readable error strings rather than
raising. This shape supports the future CLI use case where we want to
report ALL problems with a receipt in one pass, not just the first.
"""

from __future__ import annotations

from typing import Any

from jsonschema import Draft202012Validator

from agentboundary._schema import load_action_receipt_schema


def validate_receipt(receipt: dict[str, Any]) -> list[str]:
    """Validate a receipt dict against the v0.1 schema.

    Returns an empty list if the receipt is valid. Otherwise returns a list
    of human-readable error messages, one per schema violation. The order
    matches the order jsonschema reports them; callers may sort if needed.
    """
    schema = load_action_receipt_schema()
    validator = Draft202012Validator(schema)
    return [
        _format_error(err) for err in sorted(validator.iter_errors(receipt), key=_error_sort_key)
    ]


def _format_error(err: Any) -> str:
    """Render a jsonschema ValidationError into a one-line human-readable string.

    Example outputs:
        "root: 'receipt_id' is a required property"
        "actor.type: 'invalid' is not one of ['human', 'system', 'agent']"
        "arguments_hash: 'not-a-hash' does not match '^[a-f0-9]{64}$'"
    """
    path = ".".join(str(p) for p in err.absolute_path) if err.absolute_path else "root"
    return f"{path}: {err.message}"


def _error_sort_key(err: Any) -> tuple[int, str]:
    """Sort errors by depth then path so root-level errors surface first."""
    return (len(err.absolute_path), ".".join(str(p) for p in err.absolute_path))
