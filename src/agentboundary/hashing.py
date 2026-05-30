"""Canonical JSON + SHA-256 helpers for Action Receipt integrity.

Spec §4.8 mandates RFC 8785 (JSON Canonicalization Scheme) as the canonical
form for ``arguments_hash`` and ``receipt_hash``. JCS fixes the number
formatting (e.g. ``50.0`` → ``50``) and key-ordering (UTF-16 code-unit order)
rules that an ad-hoc ``json.dumps(sort_keys=True)`` gets wrong, so two
spec-compliant verifiers always compute the same hash for the same receipt.
"""

from __future__ import annotations

import hashlib
from typing import Any

import rfc8785


def canonical_json(value: Any) -> str:
    """Serialize ``value`` to AgentBoundary canonical JSON form (RFC 8785)."""
    return rfc8785.dumps(value).decode("utf-8")


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
