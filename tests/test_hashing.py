"""Tests for canonical JSON and hash helpers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentboundary.hashing import (
    canonical_json,
    compute_arguments_hash,
    compute_receipt_hash,
    sha256_hex,
)


class TestCanonicalJson:
    def test_keys_are_sorted_lexicographically(self) -> None:
        assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'

    def test_nested_objects_are_sorted_recursively(self) -> None:
        result = canonical_json({"outer": {"z": 1, "a": 2}})
        assert result == '{"outer":{"a":2,"z":1}}'

    def test_no_whitespace_between_tokens(self) -> None:
        result = canonical_json({"a": [1, 2, 3]})
        assert result == '{"a":[1,2,3]}'

    def test_non_ascii_preserved_unescaped(self) -> None:
        # Spec §4.12: canonical JSON is UTF-8 with non-ASCII preserved.
        assert canonical_json({"k": "café"}) == '{"k":"café"}'

    def test_deterministic_across_dict_insertion_order(self) -> None:
        a = canonical_json({"x": 1, "y": 2, "z": 3})
        b = canonical_json({"z": 3, "y": 2, "x": 1})
        assert a == b


class TestCanonicalJsonIsRFC8785:
    """Canonicalization MUST be RFC 8785 (JSON Canonicalization Scheme).

    Ad-hoc ``json.dumps(sort_keys=True)`` diverges from JCS on number
    formatting and non-BMP key ordering, so two spec-compliant verifiers can
    disagree on the same receipt's hash. See spec §4.8 / §4.12.
    """

    def test_integer_valued_float_drops_decimal_point(self) -> None:
        # RFC 8785 §3.2.2.3 serializes 50.0 as "50"; json.dumps emits "50.0".
        assert canonical_json({"amount": 50.0}) == '{"amount":50}'

    def test_lone_integer_valued_float(self) -> None:
        assert canonical_json({"x": 1.0}) == '{"x":1}'

    def test_matches_rfc8785_reference_vectors(self) -> None:
        import rfc8785

        for value in (
            {"amount": 50.0, "b": 1},
            {"x": 1.0},
            {"k": "café"},
            {"a": [1, 2, 3]},
            {"\U0001f600": 1, "a": 2},
        ):
            assert canonical_json(value) == rfc8785.dumps(value).decode("utf-8")


class TestSha256Hex:
    def test_known_vector_empty_string(self) -> None:
        assert sha256_hex("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_known_vector_abc(self) -> None:
        assert (
            sha256_hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )


class TestComputeArgumentsHash:
    def test_computes_canonical_json_sha256(self) -> None:
        args = {"ref": "refs/heads/main", "sha": "b1c2d3e4"}
        expected = sha256_hex('{"ref":"refs/heads/main","sha":"b1c2d3e4"}')
        assert compute_arguments_hash(args) == expected

    def test_insensitive_to_input_key_order(self) -> None:
        a = compute_arguments_hash({"a": 1, "b": 2})
        b = compute_arguments_hash({"b": 2, "a": 1})
        assert a == b


class TestComputeReceiptHash:
    def test_excludes_receipt_hash_field_from_input(self) -> None:
        # The receipt_hash field must not be included in the hash input
        # (otherwise the hash would depend on itself).
        with_hash = {"a": 1, "b": 2, "receipt_hash": "deadbeef"}
        without_hash = {"a": 1, "b": 2}
        assert compute_receipt_hash(with_hash) == compute_receipt_hash(without_hash)

    def test_deterministic_on_full_receipt_shape(self) -> None:
        receipt = {
            "version": "agentboundary/v0.1",
            "receipt_id": "0192c8d0-1f2a-7c3e-bf2a-1a4d3f5e6c7b",
            "issued_at": "2026-06-15T14:23:08Z",
            "actor": {"type": "agent", "id": "agent:x"},
        }
        expected = sha256_hex(canonical_json(receipt))
        assert compute_receipt_hash(receipt) == expected


@pytest.mark.parametrize(
    "slug",
    ["github-merge", "spring-service-mutation", "stripe-refund"],
)
def test_worked_example_receipt_hash_is_canonical(slug: str) -> None:
    # Worked examples ship in the wheel as evidence the spec is self-consistent.
    # Anyone who downloads one and recomputes the canonical hash MUST get a match,
    # otherwise the L3 verifiability claim in spec §5.1 is false on day one.
    path = Path(__file__).parent.parent / "docs" / "receipts" / f"{slug}.json"
    receipt = json.loads(path.read_text())
    assert receipt["receipt_hash"] == compute_receipt_hash(receipt), (
        f"{slug}.json receipt_hash does not match canonical SHA-256 of its body"
    )
