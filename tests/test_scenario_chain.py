"""The chain harness behind setup.chain scenarios (scenarios/chain.py)."""

from __future__ import annotations

from itertools import pairwise
from typing import Any

import pytest

from agentboundary.hashing import compute_receipt_hash
from agentboundary.runtime import ReferenceImplementation
from agentboundary.scenarios.chain import build_chain, chain_failure_codes

SETUP: dict[str, Any] = {
    "receipt_version": "agentboundary/v0.2-alpha",
    "now": "2026-06-15T14:23:00Z",
    "policies": [{"name": "p", "version": "1", "rule": "allow", "capabilities": ["c.x"]}],
}
ACTION: dict[str, Any] = {
    "actor": {"type": "agent", "id": "agent:a"},
    "agent": {"framework": "f", "framework_version": "1", "model": "m"},
    "tool": {"name": "t", "capability": "c.x"},
    "target": {"system": "s.example", "environment": "prod"},
    "arguments": {"a": 1},
}


def _receipt(setup: dict[str, Any] = SETUP) -> dict[str, Any]:
    out = ReferenceImplementation().attempt(ACTION, setup=setup)
    assert out.receipt is not None
    return out.receipt


def test_chain_links_each_receipt_to_the_one_before() -> None:
    chain = build_chain(_receipt(), 3)
    assert "prior_receipt" not in chain[0]
    for prev, cur in pairwise(chain):
        assert cur["prior_receipt"] == {
            "receipt_id": prev["receipt_id"],
            "receipt_hash": compute_receipt_hash(prev),
        }
    assert len({r["receipt_id"] for r in chain}) == 3


def test_intact_chain_has_no_failures() -> None:
    setup = {**SETUP, "chain": {"length": 3}}
    assert chain_failure_codes(setup, ACTION, _receipt()) == set()


def test_needs_v02_receipts() -> None:
    v01 = {k: v for k, v in SETUP.items() if k != "receipt_version"}
    with pytest.raises(ValueError, match=r"v0\.2-alpha"):
        chain_failure_codes({**v01, "chain": {"length": 2}}, ACTION, _receipt(v01))


def test_resign_needs_an_envelope() -> None:
    op = {"op": "resign", "index": 1, "kid": "k2", "seed_hex": "00" * 32}
    setup = {**SETUP, "chain": {"length": 2, "inject": [op]}}
    with pytest.raises(ValueError, match="envelope"):
        chain_failure_codes(setup, ACTION, _receipt())
