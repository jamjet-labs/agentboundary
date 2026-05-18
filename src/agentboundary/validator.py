"""Validate Action Receipts against the v0.1 schema.

The validator returns a list of human-readable error strings rather than
raising. This shape supports the future CLI use case where we want to
report ALL problems with a receipt in one pass, not just the first.

For callers that need to inspect the underlying schema errors structurally
(e.g. conformance.py needs to detect "required" failures without coupling
to error message wording), use ``iter_schema_errors`` instead.
"""

from __future__ import annotations

from typing import Any

from jsonschema import Draft202012Validator, ValidationError

from agentboundary._schema import load_action_receipt_schema


def validate_receipt(receipt: dict[str, Any]) -> list[str]:
    """Validate a receipt dict against the v0.1 schema.

    Returns an empty list if the receipt is valid. Otherwise returns a list
    of human-readable error messages, one per schema violation, sorted by
    depth then path (root-level errors first, then nested errors in
    alphabetical path order).

    `format` keywords (uuid, date-time) are enforced via
    Draft202012Validator.FORMAT_CHECKER, which depends on the
    jsonschema[format-nongpl] extras installed by this package.
    """
    return [_format_error(err) for err in iter_schema_errors(receipt)]


def iter_schema_errors(receipt: dict[str, Any]) -> list[ValidationError]:
    """Return raw ``jsonschema.ValidationError`` objects for ``receipt``.

    Same sort order as ``validate_receipt`` (depth then path) so callers can
    rely on a stable ordering. Returns an empty list when the receipt is
    valid.

    This is the lower-level cousin of ``validate_receipt``: it exposes the
    structured ValidationError objects so callers can branch on
    ``err.validator`` (e.g. ``"required"``, ``"enum"``, ``"type"``) and
    ``err.validator_value`` without parsing the human-readable message.

    Downstream callers (conformance checks, CLI) use this to make decisions
    that must not couple to jsonschema's exact error-message wording.
    """
    schema = load_action_receipt_schema()
    validator = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
    return sorted(validator.iter_errors(receipt), key=_error_sort_key)


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
