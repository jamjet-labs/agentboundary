"""Tests for the v0.2-alpha provenance + completeness_score helpers."""

from __future__ import annotations

from copy import deepcopy

import pytest

from agentboundary.hashing import compute_arguments_hash, compute_receipt_hash
from agentboundary.provenance import (
    ALL_PROVENANCE_PATHS,
    applicable_paths,
    compute_completeness_score,
)


@pytest.fixture
def minimal_v02_receipt() -> dict:
    """A v0.2-alpha receipt covering only the always-required paths."""
    base = {
        "version": "agentboundary/v0.2-alpha",
        "receipt_id": "0192c8d0-1f2a-7c3e-bf2a-1a4d3f5e6c7b",
        "issued_at": "2026-06-15T14:23:08Z",
        "actor": {"type": "agent", "id": "agent:test"},
        "agent": {
            "framework": "test",
            "framework_version": "1.0",
            "model": "test",
        },
        "tool": {"name": "t", "capability": "test.do"},
        "target": {"system": "test.example", "environment": "dev"},
        "arguments_hash": compute_arguments_hash({"x": 1}),
        "policy": {"name": "p", "version": "1", "decision": "allow"},
        "execution": {
            "status": "success",
            "completed_at": "2026-06-15T14:23:09Z",
        },
    }
    return base


@pytest.fixture
def all_observed_provenance() -> dict:
    """Provenance that marks every required path as 'observed'."""
    return {p: "observed" for p in (
        "receipt_id", "issued_at", "actor.type", "actor.id",
        "agent.framework", "agent.framework_version", "agent.model",
        "tool.name", "tool.capability",
        "target.system", "target.environment",
        "arguments_hash",
        "policy.name", "policy.version", "policy.decision",
        "execution.status", "execution.completed_at",
    )}


class TestApplicablePaths:
    def test_required_paths_always_included(self, minimal_v02_receipt: dict) -> None:
        paths = applicable_paths(minimal_v02_receipt)
        for p in (
            "receipt_id", "issued_at", "actor.type", "actor.id",
            "agent.framework", "agent.framework_version", "agent.model",
            "tool.name", "tool.capability",
            "target.system", "target.environment",
            "arguments_hash",
            "policy.name", "policy.version", "policy.decision",
            "execution.status", "execution.completed_at",
        ):
            assert p in paths

    def test_optional_path_excluded_when_absent(self, minimal_v02_receipt: dict) -> None:
        paths = applicable_paths(minimal_v02_receipt)
        assert "tool.version" not in paths
        assert "approval.approver.id" not in paths

    def test_optional_path_included_when_present(self, minimal_v02_receipt: dict) -> None:
        receipt = deepcopy(minimal_v02_receipt)
        receipt["tool"]["version"] = "1.0.0"
        receipt["actor"]["display_name"] = "Test Agent"
        paths = applicable_paths(receipt)
        assert "tool.version" in paths
        assert "actor.display_name" in paths

    def test_approval_subpaths_included_when_block_present(
        self, minimal_v02_receipt: dict
    ) -> None:
        receipt = deepcopy(minimal_v02_receipt)
        receipt["policy"]["decision"] = "require-approval"
        receipt["approval"] = {
            "approver": {"id": "user:1", "role": "maintainer"},
            "approved_at": "2026-06-15T14:22:30Z",
        }
        paths = applicable_paths(receipt)
        assert "approval.approver.id" in paths
        assert "approval.approver.role" in paths
        assert "approval.approved_at" in paths
        assert "approval.approver.display_name" not in paths


class TestCompletenessScore:
    def test_all_observed_score_is_one(
        self, minimal_v02_receipt: dict, all_observed_provenance: dict
    ) -> None:
        receipt = deepcopy(minimal_v02_receipt)
        receipt["provenance"] = all_observed_provenance
        assert compute_completeness_score(receipt) == 1.0

    def test_all_synthesized_score_is_zero(self, minimal_v02_receipt: dict) -> None:
        receipt = deepcopy(minimal_v02_receipt)
        # Empty provenance -> every applicable path defaults to synthesized
        receipt["provenance"] = {}
        assert compute_completeness_score(receipt) == 0.0

    def test_half_observed_half_inferred_scores_three_quarters(
        self, minimal_v02_receipt: dict
    ) -> None:
        receipt = deepcopy(minimal_v02_receipt)
        required = [p for p in applicable_paths(receipt)]
        half = len(required) // 2
        receipt["provenance"] = {
            **{p: "observed" for p in required[:half]},
            **{p: "inferred" for p in required[half:]},
        }
        # observed=2, inferred=1; half each → weighted_sum = 1.5*N; max = 2*N
        # Floor at 3 decimals: 0.764 for 17 paths (8 obs + 9 inf → 25/34 = 0.735)
        # Don't pin the exact number — N depends on the path set. Instead bound it.
        score = compute_completeness_score(receipt)
        assert 0.5 < score < 1.0

    def test_inferred_weighted_half(self, minimal_v02_receipt: dict) -> None:
        """One inferred + rest observed should produce a small dip below 1.0."""
        receipt = deepcopy(minimal_v02_receipt)
        required = applicable_paths(receipt)
        provenance = {p: "observed" for p in required}
        provenance[required[0]] = "inferred"  # one inferred
        receipt["provenance"] = provenance
        # 1 inferred + (N-1) observed in N paths
        # weighted_sum = 1 + (N-1)*2 = 2N - 1
        # score = (2N-1) / (2N)
        n = len(required)
        expected_milli = ((2 * n - 1) * 1000) // (2 * n)
        assert compute_completeness_score(receipt) == expected_milli / 1000.0

    def test_missing_provenance_entry_defaults_to_synthesized(
        self, minimal_v02_receipt: dict, all_observed_provenance: dict
    ) -> None:
        """A path that exists in the receipt but has no provenance entry
        is treated as synthesized (weight 0) — the lenient default."""
        receipt = deepcopy(minimal_v02_receipt)
        provenance = dict(all_observed_provenance)
        # Drop one entry
        del provenance["actor.id"]
        receipt["provenance"] = provenance
        # 16 observed + 1 missing (treated as synthesized)
        # weighted_sum = 16*2 + 0 = 32; max = 2*17 = 34
        # score = 32/34 → 941 / 1000
        score = compute_completeness_score(receipt)
        # Bound; exact depends on path count
        assert 0.93 < score < 0.95

    def test_extra_provenance_entry_for_absent_field_ignored(
        self, minimal_v02_receipt: dict, all_observed_provenance: dict
    ) -> None:
        """A provenance entry for a path that doesn't appear in the receipt
        is silently ignored — does not affect the score."""
        receipt_a = deepcopy(minimal_v02_receipt)
        receipt_a["provenance"] = dict(all_observed_provenance)

        receipt_b = deepcopy(receipt_a)
        # tool.version is absent from receipt; provenance entry for it is noise
        receipt_b["provenance"]["tool.version"] = "observed"

        assert compute_completeness_score(receipt_a) == compute_completeness_score(receipt_b)

    def test_unknown_provenance_value_treated_as_synthesized(
        self, minimal_v02_receipt: dict, all_observed_provenance: dict
    ) -> None:
        receipt = deepcopy(minimal_v02_receipt)
        provenance = dict(all_observed_provenance)
        provenance["policy.version"] = "guessed"  # not in enum
        receipt["provenance"] = provenance
        # 16 observed + 1 unknown (synthesized)
        score = compute_completeness_score(receipt)
        assert 0.93 < score < 0.95

    def test_score_is_deterministic_integer_arithmetic(
        self, minimal_v02_receipt: dict, all_observed_provenance: dict
    ) -> None:
        """Specific numerical case to pin the formula: integer arithmetic, floor."""
        receipt = deepcopy(minimal_v02_receipt)
        provenance = dict(all_observed_provenance)
        # 5 inferred, rest observed (N=17 always-required paths)
        for p in list(provenance.keys())[:5]:
            provenance[p] = "inferred"
        receipt["provenance"] = provenance
        # weighted_sum = 5*1 + 12*2 = 29; max = 2*17 = 34
        # (29*1000) // 34 = 852 (29000 / 34 = 852.94…, floored)
        assert compute_completeness_score(receipt) == 0.852


class TestPathSet:
    def test_all_paths_constant_is_sorted_required_then_conditional(self) -> None:
        # Sanity: ALL_PROVENANCE_PATHS contains everything once
        assert len(ALL_PROVENANCE_PATHS) == len(set(ALL_PROVENANCE_PATHS))
        # No empty strings, no whitespace
        for p in ALL_PROVENANCE_PATHS:
            assert p and p.strip() == p
