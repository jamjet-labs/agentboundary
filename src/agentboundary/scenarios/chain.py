"""Scenario support for receipt chains: build a chain ending in the
scenario's receipt, tamper with it, verify it offline, return the failure
codes.

A scenario opts in with ``setup.chain``. Receipt ``i`` is a copy of the
scenario's receipt with its own receipt_id, linked to receipt ``i - 1``
through ``prior_receipt``; receipt 0 is the genesis. With ``setup.envelope``
every receipt is signed with that fixed TEST key, so the signer-continuity
check runs too. The injects are what someone with write access to a receipt
store can do:

* ``edit_and_rehash``: change a field of receipt ``index`` and recompute its
  ``receipt_hash`` (re-signing it if the chain is signed);
* ``drop``: remove receipt ``index``;
* ``unlink``: remove receipt ``index``'s ``prior_receipt`` and rehash it;
* ``relink``: point receipt ``index`` at receipt ``to`` (a fork presented as
  one chain) and rehash it;
* ``duplicate``: present receipt ``index`` a second time, at the end;
* ``corrupt``: replace receipt ``index`` with bytes that do not parse;
* ``resign``: sign receipt ``index`` with another key the keyring also
  trusts, under ``kid``.
"""

from __future__ import annotations

import copy
import json
import uuid
from typing import Any

from agentboundary.cose import Keyring, KeyringEntry, private_key_from_seed, sign_receipt
from agentboundary.hashing import compute_receipt_hash
from agentboundary.runtime import V02_ALPHA
from agentboundary.verify import load_items, verify_items

_NS = uuid.UUID("6f0e2a51-6b0c-4f3e-9a55-0a0b0c0d0e0f")  # fixed, so ids are deterministic


def _rehash(receipt: dict[str, Any]) -> None:
    receipt.pop("receipt_hash", None)
    receipt["receipt_hash"] = compute_receipt_hash(receipt)


def _set_path(receipt: dict[str, Any], path: str, value: Any) -> None:
    parts = path.split(".")
    cursor: Any = receipt
    for seg in parts[:-1]:
        cursor = cursor.setdefault(seg, {})
    cursor[parts[-1]] = value


def _link(receipt: dict[str, Any], prior: dict[str, Any]) -> None:
    receipt["prior_receipt"] = {
        "receipt_id": prior["receipt_id"],
        "receipt_hash": prior["receipt_hash"],
    }


def build_chain(receipt: dict[str, Any], length: int) -> list[dict[str, Any]]:
    """``length`` linked copies of ``receipt``; the last one is the newest."""
    chain: list[dict[str, Any]] = []
    for i in range(length):
        r = copy.deepcopy(receipt)
        r.pop("prior_receipt", None)
        r["receipt_id"] = str(uuid.uuid5(_NS, f"{receipt.get('receipt_id')}/{i}"))
        if chain:
            _link(r, chain[-1])
        _rehash(r)
        chain.append(r)
    return chain


def chain_failure_codes(
    setup: dict[str, Any], action: dict[str, Any], receipt: dict[str, Any]
) -> set[str]:
    """Return the offline verifier's failure codes for the scenario's chain, or an empty set."""
    cfg = setup.get("chain")
    if not cfg:
        return set()
    if receipt.get("version") != V02_ALPHA:
        raise ValueError("setup.chain needs v0.2-alpha receipts (receipt_version)")
    chain = build_chain(receipt, int(cfg["length"]))
    env_cfg = setup.get("envelope")
    signers: dict[int, tuple[Any, str]] = {}
    entries: list[KeyringEntry] = []
    if env_cfg:
        key = private_key_from_seed(bytes.fromhex(env_cfg["seed_hex"]))
        signers = dict.fromkeys(range(len(chain)), (key, env_cfg["kid"]))
        entries.append(KeyringEntry(env_cfg["kid"], key.public_key().public_bytes_raw()))

    presented: list[dict[str, Any] | bytes] = list(chain)
    for op in cfg.get("inject", []):
        kind, i = op["op"], op["index"]
        if kind == "edit_and_rehash":
            _set_path(chain[i], op["path"], op["value"])
            _rehash(chain[i])
        elif kind == "unlink":
            chain[i].pop("prior_receipt", None)
            _rehash(chain[i])
        elif kind == "relink":
            _link(chain[i], chain[op["to"]])
            _rehash(chain[i])
        elif kind == "resign":
            if not env_cfg:
                raise ValueError("chain inject 'resign' needs setup.envelope")
            other = private_key_from_seed(bytes.fromhex(op["seed_hex"]))
            signers[i] = (other, op["kid"])
            entries.append(KeyringEntry(op["kid"], other.public_key().public_bytes_raw()))
        elif kind == "drop":
            presented[i] = b""  # removed below, after every index is resolved
        elif kind == "duplicate":
            presented.append(chain[i])
        elif kind == "corrupt":
            presented[i] = b"{not a receipt"
        else:
            raise ValueError(f"unknown chain inject op: {kind}")

    sources: list[tuple[str, bytes]] = []
    for pos, item in enumerate(presented):
        if item == b"":
            continue
        if isinstance(item, bytes):
            sources.append((f"chain[{pos}].json", item))
            continue
        idx = next(j for j, r in enumerate(chain) if r is item)
        if idx in signers:
            key, kid = signers[idx]
            sources.append((f"chain[{pos}].cose", sign_receipt(item, key, kid)))
        else:
            sources.append((f"chain[{pos}].json", json.dumps(item).encode("utf-8")))

    keyring = Keyring(tuple(entries)) if entries else None
    report = verify_items(load_items(sources), keyring)
    return {
        c.code
        for c in [*report.chain, *(c for r in report.receipts for c in r.checks)]
        if c.status == "fail" and c.code is not None
    }
