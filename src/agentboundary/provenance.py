"""Provenance and completeness_score helpers for AgentBoundary v0.2-alpha.

v0.2-alpha adds two optional top-level fields to the Action Receipt:

* ``provenance`` — a flat map of dotted path -> {"observed", "inferred",
  "synthesized"} declaring the emitter's first-hand knowledge of each
  field.
* ``completeness_score`` — a number in [0.0, 1.0] derived deterministically
  from the provenance map.

The score formula uses integer arithmetic with truncation so the result
is identical across every language a verifier might implement::

    weighted_sum = sum(weight[provenance[p]] for p in present_paths)
    score = floor(weighted_sum * 1000 / (2 * total)) / 1000.0

with ``weight = {"observed": 2, "inferred": 1, "synthesized": 0}``.

When a present path has no provenance entry, its weight is 0 — the
"synthesized" default. When a provenance entry references an absent
path, it is silently ignored. Both choices are documented in the spec.
"""

from __future__ import annotations

from typing import Any, Final, Literal

ProvenanceValue = Literal["observed", "inferred", "synthesized"]

# Normative provenance weights for v0.2-alpha. Changing these changes
# every receipt's score; any new ratio is a new spec version.
_WEIGHTS: Final[dict[str, int]] = {
    "observed": 2,
    "inferred": 1,
    "synthesized": 0,
}
_MAX_WEIGHT: Final[int] = 2

# Always-applicable paths: present in every conformant v0.2-alpha receipt.
_REQUIRED_PATHS: Final[tuple[str, ...]] = (
    "receipt_id",
    "issued_at",
    "actor.type",
    "actor.id",
    "agent.framework",
    "agent.framework_version",
    "agent.model",
    "tool.name",
    "tool.capability",
    "target.system",
    "target.environment",
    "arguments_hash",
    "policy.name",
    "policy.version",
    "policy.decision",
    "execution.status",
    "execution.completed_at",
)

# Conditional paths: counted only when the leaf is present in the receipt.
# Spec-defined; expanding the set requires a new schema version.
_CONDITIONAL_PATHS: Final[tuple[str, ...]] = (
    "actor.display_name",
    "agent.model_version",
    "tool.version",
    "target.resource_id",
    "approval.approver.id",
    "approval.approver.display_name",
    "approval.approver.role",
    "approval.approved_at",
    "approval.context",
    "execution.error_code",
    "execution.result_ref",
)

ALL_PROVENANCE_PATHS: Final[tuple[str, ...]] = _REQUIRED_PATHS + _CONDITIONAL_PATHS


def applicable_paths(receipt: dict[str, Any]) -> list[str]:
    """Return the subset of provenance paths that apply to ``receipt``.

    Always-required paths are included unconditionally (the receipt is
    expected to be schema-valid; absence at a required path will be
    flagged by the schema check before provenance ever runs).
    Conditional paths are included only when the corresponding receipt
    field is actually present.
    """
    out: list[str] = list(_REQUIRED_PATHS)
    for path in _CONDITIONAL_PATHS:
        if _path_present(receipt, path):
            out.append(path)
    return out


def compute_completeness_score(receipt: dict[str, Any]) -> float:
    """Recompute the completeness_score from a receipt's provenance block.

    A path that is applicable (per :func:`applicable_paths`) but has no
    entry in ``receipt['provenance']`` is weighted as ``synthesized`` (0).
    A provenance entry for a non-applicable path is ignored.

    Returns 0.0 for an empty applicable-path set (defensive; should never
    happen for a v0.2-alpha receipt since required paths are always
    applicable).
    """
    provenance = receipt.get("provenance", {})
    if not isinstance(provenance, dict):
        provenance = {}

    paths = applicable_paths(receipt)
    if not paths:
        return 0.0

    weighted_sum = 0
    for p in paths:
        value = provenance.get(p, "synthesized")
        if not isinstance(value, str):
            value = "synthesized"
        weighted_sum += _WEIGHTS.get(value, 0)

    total = len(paths)
    # Integer arithmetic with floor to 3 decimal places; identical across
    # every language a verifier might use.
    score_milli = (weighted_sum * 1000) // (_MAX_WEIGHT * total)
    return score_milli / 1000.0


def _path_present(receipt: dict[str, Any], dotted: str) -> bool:
    """True iff the leaf at ``dotted`` exists in ``receipt``."""
    cursor: Any = receipt
    for part in dotted.split("."):
        if not isinstance(cursor, dict) or part not in cursor:
            return False
        cursor = cursor[part]
    return True
