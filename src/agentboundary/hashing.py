"""Canonical JSON + SHA-256 helpers for Action Receipt integrity.

Spec §4.12 defines canonical JSON as: keys sorted lexicographically,
no whitespace, UTF-8 encoded, non-ASCII characters preserved literally.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> str:
    """Serialize ``value`` to AgentBoundary canonical JSON form."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def sha256_hex(text: str) -> str:
    """Return the SHA-256 hex digest of ``text`` UTF-8 encoded."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def compute_arguments_hash(arguments: dict[str, Any]) -> str:
    """Compute the canonical SHA-256 of an action's arguments object."""
    return sha256_hex(canonical_json(arguments))


def compute_receipt_hash(receipt: dict[str, Any]) -> str:
    """Compute the SHA-256 over a receipt with ``receipt_hash`` removed.

    Removing the field prevents the hash from depending on itself.
    """
    payload = {k: v for k, v in receipt.items() if k != "receipt_hash"}
    return sha256_hex(canonical_json(payload))
