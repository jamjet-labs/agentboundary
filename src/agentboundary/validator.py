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

from agentboundary._schema import load_action_receipt_schema, load_schema_for_version

_DEFAULT_VERSION = "agentboundary/v0.1"


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

    The schema is selected by the receipt's ``version`` field. Unknown
    versions fall back to the v0.1 schema so receipts that drift to an
    unrecognised future version still surface a structural failure rather
    than throwing — the caller sees the version-mismatch as a normal
    schema error rather than an import-time crash.
    """
    schema = _schema_for_receipt(receipt)
    validator = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
    return sorted(validator.iter_errors(receipt), key=_error_sort_key)


def _schema_for_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    """Pick the right schema based on the receipt's declared version.

    Defaults to v0.1 when the version field is missing or unrecognised so
    downstream validation still runs (and reports the version mismatch as
    a normal schema error rather than crashing).
    """
    version = receipt.get("version") if isinstance(receipt, dict) else None
    if not isinstance(version, str):
        return load_action_receipt_schema()
    try:
        return load_schema_for_version(version)
    except ValueError:
        return load_action_receipt_schema()


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
