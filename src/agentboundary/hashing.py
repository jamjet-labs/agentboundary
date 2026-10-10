"""Canonical JSON + SHA-256 helpers for Action Receipt integrity.

Spec §4.8 mandates RFC 8785 (JSON Canonicalization Scheme) as the canonical
form for ``arguments_hash`` and ``receipt_hash``. JCS fixes the number
formatting (e.g. ``50.0`` → ``50``) and key-ordering (UTF-16 code-unit order)
rules that an ad-hoc ``json.dumps(sort_keys=True)`` gets wrong, so two
spec-compliant verifiers always compute the same hash for the same receipt.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any

import rfc8785


def canonical_json(value: Any) -> str:
    """Serialize ``value`` to AgentBoundary canonical JSON form (RFC 8785)."""
    # ``bytes(...)`` pins the type to a concrete ``bytes`` regardless of how
    # rfc8785 annotates ``dumps`` (older releases return ``Any``), so mypy
    # --strict does not flag ``no-any-return`` on the decode.
    return bytes(rfc8785.dumps(value)).decode("utf-8")


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


# Member names some host languages treat specially when materializing an
# object. draft-noa-scitt-ai-agent-receipt-01 section 3.2 rejects them at the
# parse boundary of every document a verifier reads; we do the same so a
# receipt or keyring that is safe here is safe for a JavaScript verifier too.
MAX_SAFE_INTEGER = 2**53 - 1

FORBIDDEN_MEMBER_NAMES = frozenset({"__proto__", "prototype", "constructor"})


class StrictJSONError(ValueError):
    """Raised when a document is valid JSON for ``json.loads`` but not for a verifier."""


def parse_json_strict(text: str | bytes) -> Any:
    """Parse JSON the way an offline verifier must.

    Rejects what ``json.loads`` silently accepts: duplicate member names
    (``json.loads`` keeps the last one, so two verifiers can read different
    values from one document), the non-finite literals ``NaN`` /
    ``Infinity`` (RFC 8785 cannot serialize them), unpaired UTF-16
    surrogates (they collapse onto one replacement character when hashed),
    and the forbidden member names above. Bytes must be UTF-8.
    """
    if isinstance(text, bytes):
        try:
            text = text.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise StrictJSONError(f"not UTF-8: {exc}") from exc

    def pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise StrictJSONError(f"duplicate member name {key!r}")
            if key in FORBIDDEN_MEMBER_NAMES:
                raise StrictJSONError(f"forbidden member name {key!r}")
            out[key] = value
        return out

    def reject_constant(name: str) -> Any:
        raise StrictJSONError(f"non-finite number {name} is not permitted")

    def parse_float(literal: str) -> float:
        value = float(literal)
        if not math.isfinite(value):
            raise StrictJSONError(f"non-finite number {literal[:20]} is not permitted")
        return value

    def parse_int(literal: str) -> int:
        # RFC 8785 serializes numbers as IEEE 754 doubles, so integers past
        # 2**53 - 1 cannot be canonicalized; reject them here, before
        # int() meets Python's digit limit on a hostile literal.
        digits = literal.lstrip("-")
        if len(digits) > 16 or int(literal) > MAX_SAFE_INTEGER or int(literal) < -MAX_SAFE_INTEGER:
            raise StrictJSONError(f"integer {literal[:20]} is outside the range JCS can represent")
        return int(literal)

    try:
        value = json.loads(
            text,
            object_pairs_hook=pairs_hook,
            parse_constant=reject_constant,
            parse_float=parse_float,
            parse_int=parse_int,
        )
    except json.JSONDecodeError as exc:
        raise StrictJSONError(f"invalid JSON: {exc}") from exc
    except RecursionError as exc:
        raise StrictJSONError("document nests too deeply") from exc
    _reject_lone_surrogates(value)
    return value


def _reject_lone_surrogates(value: Any) -> None:
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise StrictJSONError("string contains an unpaired surrogate") from exc
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
