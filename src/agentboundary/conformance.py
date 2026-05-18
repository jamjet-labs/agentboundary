"""Spec §5 conformance level checks.

Each level builds on the previous. Level 4 is intentionally not implemented
in W3 (it requires the adversarial lifecycle scenarios that ship in W6);
calling ``check_conformance(receipt, level=4)`` returns an info-severity
``LEVEL_4_NOT_IMPLEMENTED`` marker so callers can tell the difference
between "passed Level 4" and "Level 4 was not checked".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, cast

from agentboundary.hashing import compute_arguments_hash, compute_receipt_hash
from agentboundary.validator import iter_schema_errors, validate_receipt

Severity = Literal["fail", "info"]


@dataclass(frozen=True, order=True)
class ConformanceCheck:
    """A single conformance assertion result.

    Sortable by ``(level, code)`` so callers get stable output.
    """

    level: int
    code: str
    severity: Severity
    message: str
    field: str | None = None


_LEVEL_2_DECISIONS = {"allow", "deny", "require-approval", "escalate"}

_L3_HASH_FIELDS = frozenset({"arguments_hash", "receipt_hash"})


# TODO(W3-followup): remove when the v0.2 schema makes arguments_hash and
# receipt_hash optional at the top level. See the spec §5.1 / §5.3 ambiguity.
def _schema_failure_is_only_missing_hashes(receipt: dict[str, Any]) -> bool:
    """True iff every schema error is a missing-arguments_hash/receipt_hash error.

    Uses ``iter_schema_errors`` so the decision is made structurally
    (``err.validator == "required"`` plus the missing property name) rather
    than by string-matching jsonschema's human-readable wording. This keeps
    the workaround working across jsonschema version bumps that may reword
    error messages.

    Used to decide whether we can still emit the L3 hash-required checks
    after a schema short-circuit. If the receipt is broadly malformed (e.g.
    missing the actor block), we don't surface L3 codes because the caller
    has bigger problems to fix first.
    """
    errors = iter_schema_errors(receipt)
    if not errors:
        return False
    for err in errors:
        if err.validator != "required":
            return False
        # A required-property error at depth N reports a SINGLE missing
        # property in its message; the absolute path is the parent. We only
        # care about top-level (root) misses for the L3 hash workaround.
        if list(err.absolute_path):
            return False
        missing = _extract_missing_property(err)
        if missing is None or missing not in _L3_HASH_FIELDS:
            return False
    return True


def _extract_missing_property(err: Any) -> str | None:
    """Parse the missing property name out of a ``required`` ValidationError.

    jsonschema reports required-property failures with messages of the form
    ``"'foo' is a required property"`` and ``err.validator_value`` set to the
    list of required keys at that level. We pull the name out of the message
    rather than the validator_value list because the message identifies the
    *specific* missing property (validator_value is the full required set,
    not just the missing subset).
    """
    msg = err.message
    if "is a required property" not in msg:
        return None
    # Message format: "'<name>' is a required property"
    start = msg.find("'")
    if start < 0:
        return None
    end = msg.find("'", start + 1)
    if end < 0:
        return None
    return cast(str, msg[start + 1 : end])


def check_conformance(
    receipt: dict[str, Any],
    level: int,
    *,
    arguments: dict[str, Any] | None = None,
) -> list[ConformanceCheck]:
    """Run all conformance checks up to ``level`` against ``receipt``.

    ``arguments`` is the original arguments object the receipt's
    ``arguments_hash`` was computed over. If omitted, the Level 3
    arguments-hash-mismatch check is skipped with a ``SKIPPED_NO_ARGUMENTS``
    info marker so callers can tell the check did not run.
    """
    if level < 1 or level > 4:
        raise ValueError(f"level must be in 1..4, got {level}")

    results: list[ConformanceCheck] = []

    # 1. Schema short-circuit
    schema_errors = validate_receipt(receipt)
    if schema_errors:
        results.append(
            ConformanceCheck(
                level=0,
                code="SCHEMA_INVALID",
                severity="fail",
                message=f"Receipt fails schema validation: {schema_errors[0]}",
            )
        )
        # When L3 is requested and the schema failed *only* because the L3
        # hash fields are missing, also surface the L3-specific codes so
        # callers can distinguish "schema is broken in unrelated ways" from
        # "you forgot the L3 hashes". When the receipt is broadly malformed,
        # short-circuit entirely and let the caller fix the structural issues
        # first.
        # TODO(W3-followup): remove when the v0.2 schema makes arguments_hash
        # and receipt_hash optional at the top level. See the spec §5.1 /
        # §5.3 ambiguity.
        if level >= 3 and _schema_failure_is_only_missing_hashes(receipt):
            if "arguments_hash" not in receipt:
                results.append(
                    ConformanceCheck(
                        level=3,
                        code="LEVEL_3_ARGUMENTS_HASH_REQUIRED",
                        severity="fail",
                        message="Level 3 receipts must include arguments_hash",
                        field="arguments_hash",
                    )
                )
            if "receipt_hash" not in receipt:
                results.append(
                    ConformanceCheck(
                        level=3,
                        code="LEVEL_3_RECEIPT_HASH_REQUIRED",
                        severity="fail",
                        message="Level 3 receipts must include receipt_hash",
                        field="receipt_hash",
                    )
                )
        return sorted(results)

    # 2. Level 1 — Logged
    # All required fields are guaranteed present (schema passed); the L1
    # invariants in the spec are effectively "the schema's required set".
    # We add no additional fail-checks at L1 beyond schema.

    # 3. Level 2 — Policy-Bound
    if level >= 2:
        policy = receipt.get("policy") or {}
        decision = policy.get("decision")
        if decision not in _LEVEL_2_DECISIONS:
            results.append(
                ConformanceCheck(
                    level=2,
                    code="LEVEL_2_DECISION_INVALID",
                    severity="fail",
                    message=(f"policy.decision={decision!r} not in {sorted(_LEVEL_2_DECISIONS)}"),
                    field="policy.decision",
                )
            )
        if decision == "require-approval" and not receipt.get("approval"):
            results.append(
                ConformanceCheck(
                    level=2,
                    code="LEVEL_2_APPROVAL_REQUIRED",
                    severity="fail",
                    message="policy.decision=require-approval but no approval block present",
                    field="approval",
                )
            )

    # 4. Level 3 — Portable Proof
    if level >= 3:
        if "arguments_hash" not in receipt:
            results.append(
                ConformanceCheck(
                    level=3,
                    code="LEVEL_3_ARGUMENTS_HASH_REQUIRED",
                    severity="fail",
                    message="Level 3 receipts must include arguments_hash",
                    field="arguments_hash",
                )
            )
        if "receipt_hash" not in receipt:
            results.append(
                ConformanceCheck(
                    level=3,
                    code="LEVEL_3_RECEIPT_HASH_REQUIRED",
                    severity="fail",
                    message="Level 3 receipts must include receipt_hash",
                    field="receipt_hash",
                )
            )

        # arguments-hash recompute (needs the original arguments)
        if "arguments_hash" in receipt:
            if arguments is None:
                results.append(
                    ConformanceCheck(
                        level=3,
                        code="SKIPPED_NO_ARGUMENTS",
                        severity="info",
                        message=(
                            "arguments not supplied; LEVEL_3_ARGUMENTS_HASH_MISMATCH check skipped"
                        ),
                    )
                )
            else:
                expected = compute_arguments_hash(arguments)
                if expected != receipt["arguments_hash"]:
                    results.append(
                        ConformanceCheck(
                            level=3,
                            code="LEVEL_3_ARGUMENTS_HASH_MISMATCH",
                            severity="fail",
                            message=(
                                f"arguments_hash={receipt['arguments_hash']} "
                                f"but recomputed={expected}"
                            ),
                            field="arguments_hash",
                        )
                    )

        # receipt-hash recompute
        if "receipt_hash" in receipt:
            expected = compute_receipt_hash(receipt)
            if expected != receipt["receipt_hash"]:
                results.append(
                    ConformanceCheck(
                        level=3,
                        code="LEVEL_3_RECEIPT_HASH_MISMATCH",
                        severity="fail",
                        message=(
                            f"receipt_hash={receipt['receipt_hash']} but recomputed={expected}"
                        ),
                        field="receipt_hash",
                    )
                )

    # 5. Level 4 — Tamper-Evident (W3 stub)
    if level >= 4:
        results.append(
            ConformanceCheck(
                level=4,
                code="LEVEL_4_NOT_IMPLEMENTED",
                severity="info",
                message=(
                    "Level 4 adversarial checks are W6 work; "
                    "this result reports Level 3 conformance only"
                ),
            )
        )

    return sorted(results)
