"""Scenario support for the COSE envelope: sign the emitted receipt, apply
envelope injects, verify offline, and return the failure codes.

A scenario opts in with ``setup.envelope``. The key in it is a fixed test
seed so the suite stays deterministic; it is not a key anyone should trust.
"""

from __future__ import annotations

import json
from typing import Any

from agentboundary.cose import (
    HDR_ALG,
    Keyring,
    KeyringEntry,
    build_protected_header,
    private_key_from_seed,
    sign_payload,
)
from agentboundary.hashing import canonical_json
from agentboundary.verify import load_items, verify_items


def envelope_failure_codes(
    setup: dict[str, Any], action: dict[str, Any], receipt: dict[str, Any]
) -> set[str]:
    """Return the verifier's failure codes for the scenario's envelope, or an empty set."""
    cfg = setup.get("envelope")
    if not cfg:
        return set()
    key = private_key_from_seed(bytes.fromhex(cfg["seed_hex"]))
    kid = cfg["kid"]
    protected = build_protected_header(kid, issuer=cfg.get("issuer"), subject=cfg.get("subject"))
    payload = canonical_json(receipt).encode("utf-8")

    ops = action.get("envelope_inject", [])
    for op in ops:
        if op["op"] == "resign_with_alg":
            protected[HDR_ALG] = op["alg"]
        elif op["op"] == "non_canonical_payload":
            payload = json.dumps(receipt, indent=2, sort_keys=True).encode("utf-8")
    envelope = sign_payload(protected, {}, payload, key)
    for op in ops:
        if op["op"] == "replace_in_payload":
            find, repl = op["find"].encode("utf-8"), op["replace"].encode("utf-8")
            if len(find) != len(repl) or envelope.count(find) != 1:
                raise ValueError("replace_in_payload needs a unique, same-length substitution")
            envelope = envelope.replace(find, repl)

    public = key.public_key().public_bytes_raw()
    keyring = Keyring((KeyringEntry(cfg.get("keyring_kid", kid), public),))
    report = verify_items(
        load_items([("envelope", envelope)]),
        keyring,
        as_signed_statement=bool(cfg.get("as_signed_statement", False)),
        require_signature=True,
    )
    return {
        c.code
        for c in [*report.chain, *(c for r in report.receipts for c in r.checks)]
        if c.status == "fail" and c.code is not None
    }
