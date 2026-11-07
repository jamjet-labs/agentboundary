"""Spec §5 conformance level checks.

Each level builds on the previous. Level 4 (Tamper-Evident) examines the
receipt against verifier-supplied context: the matching policy definition
(for stale-approval and unauthorized-approver checks), the set of
receipt_ids already observed (for replay detection), the arguments the
action actually executed with (for argument mutation), and the approvals
already used (for approval replay). When that context is missing, Level 4
emits info-severity ``LEVEL_4_SKIPPED_*`` markers so callers can tell
"passed Level 4" from "Level 4 was not checked."
"""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Final, Literal, cast

from agentboundary.hashing import canonical_json, compute_arguments_hash, compute_receipt_hash
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

# v0.2-alpha refusal verdicts and the policy decisions each one is consistent
# with. A refusal says why the action did not run; it must not contradict
# the policy output the receipt also records. "allow" appears nowhere: a
# policy that allowed the action has nothing to refuse (an allowed action
# that then failed to run is execution.status=blocked WITHOUT a refusal).
_REFUSAL_CONSISTENT_DECISIONS: dict[str, frozenset[str]] = {
    "deny": frozenset({"deny", "require-approval", "escalate"}),
    "require-approval": frozenset({"require-approval", "escalate"}),
    "expired": frozenset({"require-approval", "escalate"}),
}

_L3_HASH_FIELDS = frozenset({"arguments_hash", "receipt_hash"})

# How far an approval may postdate the receipt's issued_at before it is
# treated as forward-dated. The reference runtime refuses on the same bound.
APPROVAL_CLOCK_SKEW_SECONDS: Final = 60


def approval_fingerprint(approval: Mapping[str, Any]) -> str:
    """Identify an approval: SHA-256 hex of JCS over approver id, instant and context.

    A v0.1 approval carries no token identifier, so the approval is
    identified by who gave it (``approver.id``), when (``approved_at`` as a
    UTC instant, so ``Z``, ``+00:00`` and ``+01:00`` spellings of one moment
    match) and its ``context``. ``display_name`` and ``role`` are
    presentation and are left out, so adding them does not make a reused
    approval look new. An approval nobody can parse keeps its raw timestamp.
    """
    approver = approval.get("approver")
    approver_id = approver.get("id") if isinstance(approver, Mapping) else None
    raw_time = approval.get("approved_at")
    instant = _parse_rfc3339(raw_time)
    identity = {
        "approver_id": approver_id,
        "approved_at": (
            instant.astimezone(timezone.utc).isoformat() if instant is not None else raw_time
        ),
        "context": approval.get("context"),
    }
    return hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest()


def _schema_error_is_explained(err: Any) -> bool:
    """True if the Level 2 or Level 3 structural checks report this error by name.

    The schema enforces some Level 2 and Level 3 rules itself: a missing
    ``approval`` when one is required, a ``policy.decision`` outside the
    enum, and missing hash fields. When those are the only schema errors,
    the level codes are reported next to ``SCHEMA_INVALID`` so a caller
    learns which rule was broken. Decided structurally (validator kind,
    path, property name), never by matching jsonschema's wording alone.
    """
    path = list(err.absolute_path)
    if err.validator == "required" and not path:
        missing = _extract_missing_property(err)
        return missing in _L3_HASH_FIELDS or missing == "approval"
    return err.validator == "enum" and path == ["policy", "decision"]


def _schema_failure_is_explained(receipt: dict[str, Any]) -> bool:
    """True iff the receipt fails the schema and every error is one the
    structural checks name (see ``_schema_error_is_explained``)."""
    errors = iter_schema_errors(receipt)
    return bool(errors) and all(_schema_error_is_explained(e) for e in errors)


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
    executed_arguments: dict[str, Any] | None = None,
    prior_approvals: Mapping[str, str] | None = None,
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

    ``executed_arguments`` is the arguments object the action actually ran
    with, from a record the verifier trusts (the target system's log, for
    example). Spec v0.1 section 5.4 requires rejecting a receipt whose
    action ran with arguments other than the ones policy evaluated
    (``LEVEL_4_ARGUMENT_MUTATION``). Absence emits
    ``LEVEL_4_SKIPPED_NO_EXECUTED_ARGUMENTS`` for an action that ran.

    ``prior_approvals`` maps ``approval_fingerprint(approval)`` to the
    receipt_hash of the receipt that already used that approval. Spec v0.1
    section 5.4 requires rejecting an approval reused for a different action
    (``LEVEL_4_APPROVAL_REPLAY``). Absence emits
    ``LEVEL_4_SKIPPED_NO_PRIOR_APPROVALS`` for a receipt carrying an approval.
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
        # When the schema failed only on rules that Level 2 and Level 3
        # also state (see _schema_error_is_explained), report those levels'
        # codes too, so a caller can tell "you left out the approval" from
        # "the receipt is broken in unrelated ways". A broadly malformed
        # receipt short-circuits here with SCHEMA_INVALID alone.
        if _schema_failure_is_explained(receipt):
            results.extend(_structural_checks(receipt, level))
        return sorted(results)

    # 2. Level 1 — Logged
    # All required fields are guaranteed present (schema passed); the L1
    # invariants in the spec are effectively "the schema's required set".
    # We add no additional fail-checks at L1 beyond schema.

    # 3. Level 2 — Policy-Bound, and the Level 3 hash-presence rules. Both
    # schemas enforce these today, so on a schema-valid receipt they find
    # nothing; they run here too so a laxer future schema cannot silently
    # drop them.
    results.extend(_structural_checks(receipt, level))
    if level >= 2:
        results.extend(_refusal_checks(receipt))

    # 4. Level 3 — Portable Proof
    if level >= 3:
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
                executed_arguments=executed_arguments,
                prior_approvals=prior_approvals,
            )
        )

    return sorted(results)


def _structural_checks(receipt: dict[str, Any], level: int) -> list[ConformanceCheck]:
    """Level 2 decision/approval rules and Level 3 hash-presence rules.

    Reads only fields it can read safely, so it also runs on a receipt that
    failed the schema for the reasons ``_schema_error_is_explained`` allows.
    """
    out: list[ConformanceCheck] = []
    if level >= 2:
        policy = receipt.get("policy")
        decision = policy.get("decision") if isinstance(policy, dict) else None
        if decision not in _LEVEL_2_DECISIONS:
            out.append(
                ConformanceCheck(
                    level=2,
                    code="LEVEL_2_DECISION_INVALID",
                    severity="fail",
                    message=(f"policy.decision={decision!r} not in {sorted(_LEVEL_2_DECISIONS)}"),
                    field="policy.decision",
                )
            )
        # Spec v0.1 §2.6/§4.10: approval is required when the action
        # PROCEEDED. A blocked require-approval receipt without an approval
        # block is the honest record of an approval that never came. The
        # v0.1 schema is stricter than that prose (it requires approval on
        # every require-approval receipt); the v0.2-alpha schema matches it.
        execution = receipt.get("execution")
        status = execution.get("status") if isinstance(execution, dict) else None
        proceeded = status in ("success", "failure")
        if decision == "require-approval" and proceeded and not receipt.get("approval"):
            out.append(
                ConformanceCheck(
                    level=2,
                    code="LEVEL_2_APPROVAL_REQUIRED",
                    severity="fail",
                    message="policy.decision=require-approval but no approval block present",
                    field="approval",
                )
            )
    if level >= 3:
        if "arguments_hash" not in receipt:
            out.append(
                ConformanceCheck(
                    level=3,
                    code="LEVEL_3_ARGUMENTS_HASH_REQUIRED",
                    severity="fail",
                    message="Level 3 receipts must include arguments_hash",
                    field="arguments_hash",
                )
            )
        if "receipt_hash" not in receipt:
            out.append(
                ConformanceCheck(
                    level=3,
                    code="LEVEL_3_RECEIPT_HASH_REQUIRED",
                    severity="fail",
                    message="Level 3 receipts must include receipt_hash",
                    field="receipt_hash",
                )
            )
    return out


def _refusal_checks(receipt: dict[str, Any]) -> list[ConformanceCheck]:
    """Level 2 checks for the v0.2-alpha ``refusal`` block.

    A refusal records that the action did NOT run. Two lies are detectable
    from the receipt alone: a refusal on an action that reports it ran, and
    a refusal verdict that contradicts the recorded policy decision.
    """
    refusal = receipt.get("refusal")
    if not isinstance(refusal, dict):
        return []
    out: list[ConformanceCheck] = []
    status = (receipt.get("execution") or {}).get("status")
    if status != "blocked":
        out.append(
            ConformanceCheck(
                level=2,
                code="LEVEL_2_REFUSAL_EXECUTED",
                severity="fail",
                message=(
                    f"refusal is present but execution.status={status!r}; "
                    "a refused action must record execution.status=blocked"
                ),
                field="refusal",
            )
        )
    verdict = refusal.get("verdict")
    decision = (receipt.get("policy") or {}).get("decision")
    consistent = _REFUSAL_CONSISTENT_DECISIONS.get(verdict) if isinstance(verdict, str) else None
    if consistent is None or decision not in consistent:
        out.append(
            ConformanceCheck(
                level=2,
                code="LEVEL_2_REFUSAL_DECISION_MISMATCH",
                severity="fail",
                message=(
                    f"refusal.verdict={verdict!r} is inconsistent with policy.decision={decision!r}"
                ),
                field="refusal.verdict",
            )
        )
    return out


def _is_recorded_refusal(receipt: dict[str, Any]) -> bool:
    """True iff the receipt records a refusal AND reports the action blocked."""
    status = (receipt.get("execution") or {}).get("status")
    return isinstance(receipt.get("refusal"), dict) and status == "blocked"


def _level_4_checks(
    receipt: dict[str, Any],
    *,
    policy_full: dict[str, Any] | None,
    prior_receipt_ids: set[str] | None,
    policy_store: set[tuple[str, str]] | None,
    minimum_completeness: float | None,
    prior_receipt_hashes: dict[str, str] | None,
    executed_arguments: dict[str, Any] | None = None,
    prior_approvals: Mapping[str, str] | None = None,
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

    approval = receipt.get("approval")
    refused = _is_recorded_refusal(receipt)
    execution_status = (receipt.get("execution") or {}).get("status")
    proceeded = execution_status in ("success", "failure")

    # A forward-dated approval would stretch any approval window without
    # limit, and cannot have authorized an action that ran before it. Needs
    # only the receipt. Not applied to a recorded refusal, whose approval is
    # the evidence of what was refused.
    if isinstance(approval, dict) and not refused:
        approved_at = _parse_rfc3339(approval.get("approved_at"))
        lead = (
            (approved_at - issued_at).total_seconds()
            if approved_at is not None and issued_at is not None
            else math.nan  # cannot evaluate: fails the positive test below
        )
        if not lead <= APPROVAL_CLOCK_SKEW_SECONDS:
            out.append(
                ConformanceCheck(
                    level=4,
                    code="LEVEL_4_FUTURE_DATED_APPROVAL",
                    severity="fail",
                    message=(
                        f"approval.approved_at={approval.get('approved_at')!r} is "
                        f"{lead:.0f}s after issued_at={receipt.get('issued_at')!r}; "
                        f"more than the {APPROVAL_CLOCK_SKEW_SECONDS}s clock-skew allowance"
                        if not math.isnan(lead)
                        else "approval.approved_at or issued_at cannot be read, so the "
                        "approval cannot be shown to precede the action"
                    ),
                    field="approval.approved_at",
                )
            )

    # Argument mutation (spec v0.1 section 5.4): the arguments the action ran
    # with must be the ones arguments_hash commits to, which are the ones
    # policy evaluated.
    if proceeded:
        if executed_arguments is None:
            out.append(
                ConformanceCheck(
                    level=4,
                    code="LEVEL_4_SKIPPED_NO_EXECUTED_ARGUMENTS",
                    severity="info",
                    message=("executed_arguments not supplied; LEVEL_4_ARGUMENT_MUTATION skipped"),
                )
            )
        else:
            try:
                executed_hash = compute_arguments_hash(executed_arguments)
            except Exception:  # rfc8785 refuses NaN, huge integers, ...
                # arguments_hash can only commit to arguments JCS can encode,
                # so these cannot be the ones policy evaluated.
                executed_hash = "<not canonicalizable>"
            if executed_hash != receipt.get("arguments_hash"):
                out.append(
                    ConformanceCheck(
                        level=4,
                        code="LEVEL_4_ARGUMENT_MUTATION",
                        severity="fail",
                        message=(
                            f"the action ran with arguments hashing to {executed_hash}, "
                            f"not the arguments_hash={receipt.get('arguments_hash')} "
                            "policy evaluated"
                        ),
                        field="arguments_hash",
                    )
                )

    # Approval replay (spec v0.1 section 5.4): one approval authorizes one
    # action. The verifier supplies the approvals it has already seen used.
    if isinstance(approval, dict) and not refused:
        if prior_approvals is None:
            out.append(
                ConformanceCheck(
                    level=4,
                    code="LEVEL_4_SKIPPED_NO_PRIOR_APPROVALS",
                    severity="info",
                    message="prior_approvals not supplied; LEVEL_4_APPROVAL_REPLAY skipped",
                )
            )
        else:
            # Keyed on receipt_hash, not receipt_id: the emitter chooses the
            # id, so an id match is no evidence this is the same receipt.
            used_by = prior_approvals.get(approval_fingerprint(approval))
            if used_by is not None and used_by != receipt.get("receipt_hash"):
                out.append(
                    ConformanceCheck(
                        level=4,
                        code="LEVEL_4_APPROVAL_REPLAY",
                        severity="fail",
                        message=(
                            f"this approval was already used by the receipt with "
                            f"receipt_hash {used_by!r}; an approval authorizes one action"
                        ),
                        field="approval",
                    )
                )

    # Approval-context checks
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
    elif approval is not None and refused:
        # The stale/unauthorized checks catch an action that RAN on a bad
        # approval. This receipt records that the action was refused, so the
        # bad approval it carries is the evidence of the refusal, not a
        # breach. Reported as info so a reader can see the checks did not run.
        out.append(
            ConformanceCheck(
                level=4,
                code="LEVEL_4_APPROVAL_CHECKS_NOT_APPLICABLE",
                severity="info",
                message=(
                    "receipt records a refusal with execution.status=blocked; "
                    "LEVEL_4_STALE_APPROVAL and LEVEL_4_UNAUTHORIZED_APPROVER "
                    "apply only to actions that ran"
                ),
            )
        )
    elif approval is not None:
        stale = _stale_approval_problem(approval, issued_at, policy_full)
        if stale is not None:
            out.append(
                ConformanceCheck(
                    level=4,
                    code="LEVEL_4_STALE_APPROVAL",
                    severity="fail",
                    message=stale,
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


def _stale_approval_problem(
    approval: Mapping[str, Any], issued_at: datetime | None, policy_full: Mapping[str, Any]
) -> str | None:
    """Why the approval is outside the policy's window, or None if it is inside.

    Written positively, so a window or timestamp the check cannot evaluate
    (NaN, negative, a string, an unparseable time) fails rather than passes.
    A forward-dated approval is reported separately
    (``LEVEL_4_FUTURE_DATED_APPROVAL``); here its age is negative, which is
    inside any window.
    """
    max_age = policy_full.get("approval_max_age_seconds")
    if max_age is None:
        return None
    usable = (type(max_age) is int and max_age >= 0) or (
        type(max_age) is float and math.isfinite(max_age) and max_age >= 0
    )
    if not usable:
        return f"policy.approval_max_age_seconds={max_age!r} is not a finite, non-negative number"
    approved_at = _parse_rfc3339(approval.get("approved_at"))
    if approved_at is None or issued_at is None:
        return "approval.approved_at or issued_at cannot be read, so the window cannot be checked"
    age = (issued_at - approved_at).total_seconds()
    if age <= max_age:
        return None
    return (
        f"approval.approved_at={approval.get('approved_at')!r} is {age:.0f}s before "
        f"issued_at; exceeds policy.approval_max_age_seconds={max_age}"
    )


_RFC3339 = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?"
    r"(?:([Zz])|([+-])(\d{2}):(\d{2}))"
)


def _parse_rfc3339(value: Any) -> datetime | None:
    """Parse an RFC 3339 date-time; return None if it is not one.

    Accepts every form RFC 3339 section 5.6 allows (lowercase ``t``/``z``,
    any number of fraction digits, any offset), which ``fromisoformat`` on
    Python 3.10 does not. Fractions beyond microseconds are truncated. A
    leap second (``:60``) is not representable and returns None, as does a
    non-string, so callers must treat None as "cannot evaluate".
    """
    if not isinstance(value, str):
        return None
    m = _RFC3339.fullmatch(value)
    if m is None:
        return None
    year, month, day, hour, minute, second = (int(g) for g in m.groups()[:6])
    micro = int((m.group(7) or "0")[:6].ljust(6, "0"))
    if m.group(8):
        tz = timezone.utc
    else:
        offset = timedelta(hours=int(m.group(10)), minutes=int(m.group(11)))
        if offset >= timedelta(hours=24):
            return None
        tz = timezone(-offset if m.group(9) == "-" else offset)
    try:
        return datetime(year, month, day, hour, minute, second, micro, tzinfo=tz)
    except ValueError:
        return None
