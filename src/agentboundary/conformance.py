"""Spec §5 conformance level checks.

Each level builds on the previous. Level 4 (Tamper-Evident) examines the
receipt against verifier-supplied context: the matching policy definition
(for stale-approval and unauthorized-approver checks), and the set of
receipt_ids already observed (for replay detection). When that context is
missing, Level 4 emits info-severity ``LEVEL_4_SKIPPED_*`` markers so
callers can tell "passed Level 4" from "Level 4 was not checked."
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, cast

from agentboundary.hashing import compute_arguments_hash, compute_receipt_hash
from agentboundary.provenance import compute_completeness_score
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
    policy_full: dict[str, Any] | None = None,
    prior_receipt_ids: set[str] | None = None,
    policy_store: set[tuple[str, str]] | None = None,
    minimum_completeness: float | None = None,
    prior_receipt_hashes: dict[str, str] | None = None,
) -> list[ConformanceCheck]:
    """Run all conformance checks up to ``level`` against ``receipt``.

    ``arguments`` is the original arguments object the receipt's
    ``arguments_hash`` was computed over. If omitted, the Level 3
    arguments-hash-mismatch check is skipped with a ``SKIPPED_NO_ARGUMENTS``
    info marker so callers can tell the check did not run.

    ``policy_full`` is the matching policy definition the receipt was
    decided against, with optional ``approvers`` and
    ``approval_max_age_seconds`` keys. Required for Level 4 stale-approval
    and unauthorized-approver checks; absence emits
    ``LEVEL_4_SKIPPED_NO_POLICY_CONTEXT``.

    ``prior_receipt_ids`` is the set of receipt_ids the verifier has
    already observed. Required for Level 4 replay detection; absence emits
    ``LEVEL_4_SKIPPED_NO_PRIOR_RECEIPTS``.

    ``policy_store`` is the set of ``(policy.name, policy.version)`` tuples
    the verifier accepts as valid. Required for Level 4 policy-downgrade
    detection; absence emits ``LEVEL_4_SKIPPED_NO_POLICY_STORE``.

    ``minimum_completeness`` is a float in [0.0, 1.0] specifying the
    minimum acceptable v0.2-alpha completeness_score. Optional; if
    omitted, the threshold check does not fire. The mismatch check
    (LEVEL_4_COMPLETENESS_SCORE_MISMATCH) always runs when a receipt
    declares completeness_score, independent of this kwarg.

    ``prior_receipt_hashes`` maps prior receipt_id -> receipt_hash for
    chain verification (v0.2-alpha ``prior_receipt`` field). Required for
    the LEVEL_4_BROKEN_CHAIN check; absence emits
    ``LEVEL_4_SKIPPED_NO_PRIOR_RECEIPT_HASHES``. An explicitly empty dict
    is treated as "verifier has no chain to compare against" and the
    receipt's claimed prior_receipt link is rejected as a broken chain.
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

    # 5. Level 4 — Tamper-Evident
    if level >= 4:
        results.extend(
            _level_4_checks(
                receipt,
                policy_full=policy_full,
                prior_receipt_ids=prior_receipt_ids,
                policy_store=policy_store,
                minimum_completeness=minimum_completeness,
                prior_receipt_hashes=prior_receipt_hashes,
            )
        )

    return sorted(results)


def _level_4_checks(
    receipt: dict[str, Any],
    *,
    policy_full: dict[str, Any] | None,
    prior_receipt_ids: set[str] | None,
    policy_store: set[tuple[str, str]] | None,
    minimum_completeness: float | None,
    prior_receipt_hashes: dict[str, str] | None,
) -> list[ConformanceCheck]:
    """Run Level 4 (Tamper-Evident) checks.

    Each check is independently optional based on which context the verifier
    supplied. Missing context produces an info-severity SKIPPED marker so the
    caller can tell which checks ran.
    """
    out: list[ConformanceCheck] = []

    # Timeline: execution.completed_at must not precede receipt.issued_at.
    # Self-contained: needs no verifier context beyond the receipt itself.
    issued_at = _parse_rfc3339(receipt.get("issued_at"))
    completed_at_raw = (receipt.get("execution") or {}).get("completed_at")
    completed_at = _parse_rfc3339(completed_at_raw)
    if issued_at is not None and completed_at is not None and completed_at < issued_at:
        out.append(
            ConformanceCheck(
                level=4,
                code="LEVEL_4_COMPLETED_BEFORE_ISSUED",
                severity="fail",
                message=(
                    f"execution.completed_at={completed_at_raw} precedes "
                    f"issued_at={receipt.get('issued_at')!r}"
                ),
                field="execution.completed_at",
            )
        )

    # Approval-context checks
    approval = receipt.get("approval")
    if policy_full is None:
        out.append(
            ConformanceCheck(
                level=4,
                code="LEVEL_4_SKIPPED_NO_POLICY_CONTEXT",
                severity="info",
                message=(
                    "policy_full not supplied; "
                    "LEVEL_4_STALE_APPROVAL and LEVEL_4_UNAUTHORIZED_APPROVER skipped"
                ),
            )
        )
    elif approval is not None:
        approved_at = _parse_rfc3339(approval.get("approved_at"))
        max_age = policy_full.get("approval_max_age_seconds")
        if (
            max_age is not None
            and approved_at is not None
            and issued_at is not None
            and (issued_at - approved_at).total_seconds() > float(max_age)
        ):
            out.append(
                ConformanceCheck(
                    level=4,
                    code="LEVEL_4_STALE_APPROVAL",
                    severity="fail",
                    message=(
                        f"approval.approved_at={approval.get('approved_at')!r} is "
                        f"{(issued_at - approved_at).total_seconds():.0f}s before "
                        f"issued_at={receipt.get('issued_at')!r}; exceeds "
                        f"policy.approval_max_age_seconds={max_age}"
                    ),
                    field="approval.approved_at",
                )
            )

        approvers = policy_full.get("approvers")
        if isinstance(approvers, list) and approvers:
            approver_id = (approval.get("approver") or {}).get("id")
            allowed_ids = {a.get("id") for a in approvers if isinstance(a, dict)}
            if approver_id is not None and approver_id not in allowed_ids:
                out.append(
                    ConformanceCheck(
                        level=4,
                        code="LEVEL_4_UNAUTHORIZED_APPROVER",
                        severity="fail",
                        message=(
                            f"approver.id={approver_id!r} is not in policy.approvers "
                            f"{sorted(i for i in allowed_ids if i is not None)}"
                        ),
                        field="approval.approver.id",
                    )
                )

    # Decision/execution consistency: a deny or escalate decision must not
    # report a successful execution. Spec §3.3/§3.5 says non-allow paths
    # emit execution.status=blocked. A receipt with policy.decision=deny
    # and execution.status=success is either a broken runtime that ignored
    # the policy or a forgery.
    policy_decision = (receipt.get("policy") or {}).get("decision")
    execution_status = (receipt.get("execution") or {}).get("status")
    if policy_decision == "deny" and execution_status == "success":
        out.append(
            ConformanceCheck(
                level=4,
                code="LEVEL_4_DENY_EXECUTED",
                severity="fail",
                message=(
                    "policy.decision=deny but execution.status=success; "
                    "the action ran despite policy denial"
                ),
                field="execution.status",
            )
        )
    if policy_decision == "escalate" and execution_status == "success":
        out.append(
            ConformanceCheck(
                level=4,
                code="LEVEL_4_ESCALATE_EXECUTED",
                severity="fail",
                message=(
                    "policy.decision=escalate but execution.status=success "
                    "without an approval block resolving the escalation"
                ),
                field="execution.status",
            )
        )

    # Policy-downgrade: receipt's (policy.name, policy.version) must be a
    # tuple the verifier accepts. Spec §5.4 mandates this for L4 to defend
    # against an agent claiming an older policy version that would have
    # permitted an action the current policy denies.
    if policy_store is None:
        out.append(
            ConformanceCheck(
                level=4,
                code="LEVEL_4_SKIPPED_NO_POLICY_STORE",
                severity="info",
                message="policy_store not supplied; LEVEL_4_POLICY_DOWNGRADE skipped",
            )
        )
    else:
        rp = receipt.get("policy") or {}
        rkey = (rp.get("name"), rp.get("version"))
        if rkey[0] is not None and rkey[1] is not None and rkey not in policy_store:
            out.append(
                ConformanceCheck(
                    level=4,
                    code="LEVEL_4_POLICY_DOWNGRADE",
                    severity="fail",
                    message=(
                        f"receipt.policy={rkey!r} is not in verifier's policy_store; "
                        "claimed policy may be a downgrade or fabrication"
                    ),
                    field="policy",
                )
            )

    # v0.2-alpha completeness: emitter's declared completeness_score must
    # match the recomputed value derived from provenance. Score is a
    # self-honest primitive — lying about it is detectable when the
    # receipt's provenance map disagrees with the formula. Skipped silently
    # when the receipt has no completeness_score (v0.1 receipts, or
    # v0.2-alpha receipts that don't opt in).
    declared_score = receipt.get("completeness_score")
    if isinstance(declared_score, (int, float)):
        recomputed = compute_completeness_score(receipt)
        # Compare at 3-decimal precision (integer milli-units) so the
        # comparison is exact, never a float-epsilon question.
        declared_milli = round(float(declared_score) * 1000)
        recomputed_milli = round(recomputed * 1000)
        if declared_milli != recomputed_milli:
            out.append(
                ConformanceCheck(
                    level=4,
                    code="LEVEL_4_COMPLETENESS_SCORE_MISMATCH",
                    severity="fail",
                    message=(
                        f"completeness_score={declared_score} but recomputed "
                        f"from provenance = {recomputed:.3f}"
                    ),
                    field="completeness_score",
                )
            )
        if minimum_completeness is not None and recomputed < float(minimum_completeness):
            out.append(
                ConformanceCheck(
                    level=4,
                    code="LEVEL_4_COMPLETENESS_BELOW_THRESHOLD",
                    severity="fail",
                    message=(
                        f"completeness_score={recomputed:.3f} is below the "
                        f"verifier's minimum_completeness={minimum_completeness}"
                    ),
                    field="completeness_score",
                )
            )

    # Chain integrity: receipt's prior_receipt link must reference a
    # prior receipt whose hash matches what's in the verifier's records.
    # Detects deletion, reordering, and forged-hash insertion in the
    # emitter's stream — the v0.2-alpha Merkle-style chain semantics.
    prior_link = receipt.get("prior_receipt")
    if isinstance(prior_link, dict):
        if prior_receipt_hashes is None:
            out.append(
                ConformanceCheck(
                    level=4,
                    code="LEVEL_4_SKIPPED_NO_PRIOR_RECEIPT_HASHES",
                    severity="info",
                    message=(
                        "prior_receipt_hashes not supplied; LEVEL_4_BROKEN_CHAIN check skipped"
                    ),
                )
            )
        else:
            claimed_id = prior_link.get("receipt_id")
            claimed_hash = prior_link.get("receipt_hash")
            actual_hash = (
                prior_receipt_hashes.get(claimed_id) if isinstance(claimed_id, str) else None
            )
            if actual_hash is None:
                out.append(
                    ConformanceCheck(
                        level=4,
                        code="LEVEL_4_BROKEN_CHAIN",
                        severity="fail",
                        message=(
                            f"prior_receipt.receipt_id={claimed_id!r} is not in "
                            "the verifier's prior_receipt_hashes map; the chain "
                            "link points at a missing or deleted receipt"
                        ),
                        field="prior_receipt.receipt_id",
                    )
                )
            elif actual_hash != claimed_hash:
                out.append(
                    ConformanceCheck(
                        level=4,
                        code="LEVEL_4_BROKEN_CHAIN",
                        severity="fail",
                        message=(
                            f"prior_receipt.receipt_hash={claimed_hash!r} does "
                            f"not match the verifier's recorded hash "
                            f"{actual_hash!r} for receipt_id {claimed_id!r}"
                        ),
                        field="prior_receipt.receipt_hash",
                    )
                )

    # Replay
    if prior_receipt_ids is None:
        out.append(
            ConformanceCheck(
                level=4,
                code="LEVEL_4_SKIPPED_NO_PRIOR_RECEIPTS",
                severity="info",
                message=("prior_receipt_ids not supplied; LEVEL_4_RECEIPT_ID_REPLAY skipped"),
            )
        )
    else:
        rid = receipt.get("receipt_id")
        if rid is not None and rid in prior_receipt_ids:
            out.append(
                ConformanceCheck(
                    level=4,
                    code="LEVEL_4_RECEIPT_ID_REPLAY",
                    severity="fail",
                    message=f"receipt_id={rid!r} has been observed before",
                    field="receipt_id",
                )
            )

    return out


def _parse_rfc3339(value: Any) -> datetime | None:
    """Parse an RFC 3339 timestamp permissively; return None on failure.

    Returns None for None/non-string inputs so callers can short-circuit
    cleanly when a schema-required field is absent (the schema check at
    Level 0 has already flagged that case).
    """
    if not isinstance(value, str):
        return None
    s = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt
