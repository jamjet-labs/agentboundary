"""Offline verification of Action Receipts and receipt chains.

Everything here runs locally on the bytes it is given: no network, no
vendor service, no JamJet component. The report says what was checked,
what failed, and what was not checked and why, because a verifier that
reports a property it did not check is worse than none.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from agentboundary.conformance import check_conformance
from agentboundary.cose import Keyring, is_cose_sign1, verify_envelope
from agentboundary.hashing import (
    StrictJSONError,
    canonical_json,
    compute_receipt_hash,
    parse_json_strict,
)
from agentboundary.report import Check, failed, not_checked, passed
from agentboundary.validator import validate_receipt

# Statements about what this verifier never establishes, whatever the input.
# They are part of every report so a passing result cannot be read as more
# than it is.
NOT_CHECKED_STATEMENTS: tuple[str, ...] = (
    "What the receipt claims is the emitter's record. A valid receipt shows the "
    "record is intact and, if signed, that a key in the keyring signed it; not "
    "that it is true or that the action had the recorded effect.",
    "Signer identity: a passing signature means a key in the supplied keyring "
    "signed the envelope. Whether that key belongs to the party it is said to "
    "belong to is decided by whoever supplied the keyring.",
    "Timestamps are the emitter's own and are not checked against any clock.",
    "Truncation: receipts removed from the end of a stream cannot be detected "
    "from the receipts presented; that needs an external checkpoint.",
    "Equivocation: an emitter that signed two different histories cannot be "
    "detected from one presentation; that needs a transparency log, and no "
    "Transparency Service was consulted.",
    "Unicode normalization (NFC) of strings is not checked; strings are hashed as received.",
    "Ed25519 is verified by OpenSSL (through the cryptography package) plus "
    "this verifier's own checks on S and on the public key; which verification "
    "equation OpenSSL applies, cofactored or cofactorless, is not pinned.",
)

# Conformance codes the receipt-level checks already report under their own
# names, so they are not listed twice.
_REPORTED_ELSEWHERE = frozenset({"SCHEMA_INVALID", "LEVEL_3_RECEIPT_HASH_MISMATCH"})


@dataclass
class Item:
    """One input unit: a bare receipt (parsed) or an envelope (raw bytes)."""

    source: str
    form: str  # "bare" | "cose" | "unreadable"
    receipt: dict[str, Any] | None = None
    envelope: bytes | None = None
    error: str | None = None


@dataclass
class ReceiptReport:
    source: str
    form: str
    checks: list[Check] = field(default_factory=list)
    receipt: dict[str, Any] | None = None
    kid: str | None = None
    kid_bucket: str | None = None
    issuer: str | None = None
    subject: str | None = None
    signature_verified: bool = False

    @property
    def receipt_id(self) -> str | None:
        rid = (self.receipt or {}).get("receipt_id")
        return rid if isinstance(rid, str) else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "form": self.form,
            "receipt_id": self.receipt_id,
            "kid": self.kid,
            "kid_bucket": self.kid_bucket,
            "issuer": self.issuer,
            "subject": self.subject,
            "checks": [c.to_dict() for c in self.checks],
        }


@dataclass
class VerifyReport:
    receipts: list[ReceiptReport] = field(default_factory=list)
    chain: list[Check] = field(default_factory=list)
    not_checked: tuple[str, ...] = NOT_CHECKED_STATEMENTS

    @property
    def ok(self) -> bool:
        every = [*self.chain, *(c for r in self.receipts for c in r.checks)]
        return not any(c.status == "fail" for c in every)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "receipts": [r.to_dict() for r in self.receipts],
            "chain": [c.to_dict() for c in self.chain],
            "not_checked": list(self.not_checked),
        }


def load_items(sources: Iterable[tuple[str, bytes]]) -> list[Item]:
    """Turn ``(name, bytes)`` inputs into items, in presentation order.

    A COSE_Sign1 file is one item. A JSON file holding an object is one
    item; holding an array, one item per element (a chain). A ``.jsonl``
    file is one item per non-empty line. Parse failures become
    ``unreadable`` items so the report can say which input broke.
    """
    items: list[Item] = []
    for name, data in sources:
        if is_cose_sign1(data):
            items.append(Item(name, "cose", envelope=data))
            continue
        if name.endswith(".jsonl"):
            lines = [ln for ln in data.split(b"\n") if ln.strip()]
            for i, line in enumerate(lines):
                items.append(_parse_bare(f"{name}:{i + 1}", line))
            continue
        try:
            value = parse_json_strict(data)
        except StrictJSONError as exc:
            items.append(Item(name, "unreadable", error=str(exc)))
            continue
        if isinstance(value, list):
            for i, element in enumerate(value):
                items.append(_bare_item(f"{name}[{i}]", element))
        else:
            items.append(_bare_item(name, value))
    return items


def _parse_bare(source: str, data: bytes) -> Item:
    try:
        return _bare_item(source, parse_json_strict(data))
    except StrictJSONError as exc:
        return Item(source, "unreadable", error=str(exc))


def _bare_item(source: str, value: Any) -> Item:
    if not isinstance(value, dict):
        return Item(source, "unreadable", error="a receipt must be a JSON object")
    return Item(source, "bare", receipt=value)


def verify_items(
    items: list[Item],
    keyring: Keyring | None,
    *,
    as_signed_statement: bool = False,
    require_signature: bool = False,
) -> VerifyReport:
    """Verify each item, then the chain they form in presentation order."""
    report = VerifyReport()
    for item in items:
        report.receipts.append(_verify_one(item, keyring, as_signed_statement, require_signature))
    report.chain = _chain_checks(report.receipts)
    return report


def _verify_one(
    item: Item,
    keyring: Keyring | None,
    as_signed_statement: bool,
    require_signature: bool,
) -> ReceiptReport:
    rr = ReceiptReport(item.source, item.form)
    checks = rr.checks

    if item.form == "unreadable":
        checks.append(failed("json", "JSON_INVALID", item.error or "unreadable"))
        return rr

    if item.form == "cose":
        assert item.envelope is not None
        env = verify_envelope(item.envelope, keyring, as_signed_statement=as_signed_statement)
        checks.extend(env.checks)
        rr.kid, rr.kid_bucket = env.kid, env.kid_bucket
        rr.issuer, rr.subject = env.issuer, env.subject
        rr.signature_verified = any(
            c.name == "cose.signature" and c.status == "pass" for c in env.checks
        )
        if env.payload is None:
            return rr
        receipt = _receipt_from_payload(env.payload, checks)
        if receipt is None:
            return rr
    else:
        assert item.receipt is not None
        receipt = item.receipt
        checks.append(passed("json", "parsed with duplicate-member and surrogate checks"))
        checks.append(
            not_checked(
                "signature",
                "bare receipt: AgentBoundary receipts carry no in-payload signature; "
                "only a COSE envelope can be signature-checked",
            )
        )
        if as_signed_statement:
            checks.append(
                failed(
                    "scitt.statement",
                    "SCITT_NOT_A_STATEMENT",
                    "a bare receipt is not a Signed Statement; wrap it in a COSE envelope",
                )
            )

    rr.receipt = receipt
    if require_signature and not rr.signature_verified:
        checks.append(
            failed(
                "signature.required",
                "SIGNATURE_REQUIRED",
                "--require-signature was given and no signature was verified",
            )
        )
    checks.extend(_receipt_checks(receipt))
    return rr


def _receipt_from_payload(payload: bytes, checks: list[Check]) -> dict[str, Any] | None:
    try:
        value = parse_json_strict(payload)
    except StrictJSONError as exc:
        checks.append(failed("payload.json", "PAYLOAD_INVALID", f"payload is not a receipt: {exc}"))
        return None
    if not isinstance(value, dict):
        checks.append(failed("payload.json", "PAYLOAD_INVALID", "payload is not a JSON object"))
        return None
    if canonical_json(value).encode("utf-8") != payload:
        checks.append(
            failed(
                "payload.canonical",
                "PAYLOAD_NOT_CANONICAL",
                "payload bytes are not the RFC 8785 (JCS) serialization of the receipt",
            )
        )
    else:
        checks.append(passed("payload.canonical", "payload is exactly JCS(receipt)"))
    return value


def _receipt_checks(receipt: dict[str, Any]) -> list[Check]:
    out: list[Check] = []
    schema_errors = validate_receipt(receipt)
    version = receipt.get("version")
    if schema_errors:
        out.append(
            failed(
                "schema",
                "SCHEMA_INVALID",
                f"{len(schema_errors)} schema error(s); first: {schema_errors[0]}",
            )
        )
    else:
        out.append(passed("schema", f"valid against the {version} schema"))

    declared = receipt.get("receipt_hash")
    try:
        recomputed: str | None = compute_receipt_hash(receipt)
    except Exception as exc:  # rfc8785 refuses e.g. floats it cannot serialize
        recomputed = None
        out.append(failed("receipt_hash", "RECEIPT_HASH_MISMATCH", f"cannot canonicalize: {exc}"))
    if recomputed is not None:
        if declared == recomputed:
            out.append(passed("receipt_hash", "receipt_hash matches SHA-256 of JCS(receipt)"))
        else:
            out.append(
                failed(
                    "receipt_hash",
                    "RECEIPT_HASH_MISMATCH",
                    f"declared {declared!r}, recomputed {recomputed}",
                )
            )

    out.append(
        not_checked(
            "arguments_hash",
            "the action's arguments are not in the receipt, so arguments_hash "
            "cannot be recomputed here",
        )
    )

    if schema_errors:
        out.append(not_checked("conformance", "skipped: the receipt is not schema-valid"))
        return out
    conformance_failures = 0
    for c in check_conformance(receipt, 4):
        if c.code in _REPORTED_ELSEWHERE or c.code == "SKIPPED_NO_ARGUMENTS":
            continue
        if c.severity == "fail":
            conformance_failures += 1
            out.append(failed("conformance", c.code, c.message))
        else:
            out.append(not_checked(c.code, c.message))
    if conformance_failures == 0:
        out.append(
            passed(
                "conformance",
                "no Level 2-4 check that needs only the receipt itself failed",
            )
        )
    return out


def _chain_checks(reports: list[ReceiptReport]) -> list[Check]:
    if len(reports) < 2:
        detail = "one receipt presented; there is no chain to check"
        if reports and isinstance((reports[0].receipt or {}).get("prior_receipt"), dict):
            detail += " (its prior_receipt points at a receipt that was not presented)"
        return [not_checked("chain", detail)]

    out: list[Check] = []
    unreadable = [r.source for r in reports if r.receipt is None]
    if unreadable:
        out.append(
            failed(
                "chain",
                "CHAIN_INCOMPLETE",
                f"{len(unreadable)} item(s) could not be read ({', '.join(unreadable)}); "
                "links through them were not checked",
            )
        )
        return out

    receipts = [r.receipt for r in reports if r.receipt is not None]

    first_prior = receipts[0].get("prior_receipt")
    if first_prior is None:
        out.append(passed("chain.genesis", "the first receipt has no prior_receipt"))
    else:
        out.append(
            failed(
                "chain.genesis",
                "CHAIN_NOT_FROM_GENESIS",
                "the first receipt presented links to an earlier one; a chain must be "
                "presented from its first receipt",
            )
        )

    broken: list[str] = []
    for i in range(1, len(receipts)):
        prev, cur = receipts[i - 1], receipts[i]
        link = cur.get("prior_receipt")
        try:
            prev_hash: str | None = compute_receipt_hash(prev)
        except Exception:
            prev_hash = None
        if not isinstance(link, dict):
            broken.append(f"{reports[i].source}: no prior_receipt")
        elif link.get("receipt_id") != prev.get("receipt_id"):
            broken.append(
                f"{reports[i].source}: prior_receipt.receipt_id does not name its predecessor"
            )
        elif prev_hash is None or link.get("receipt_hash") != prev_hash:
            broken.append(
                f"{reports[i].source}: prior_receipt.receipt_hash does not match the "
                "recomputed hash of its predecessor"
            )
    if broken:
        out.append(failed("chain.links", "CHAIN_LINK_BROKEN", "; ".join(broken)))
    else:
        out.append(passed("chain.links", f"{len(receipts) - 1} link(s) match"))

    seen: dict[Any, dict[str, Any]] = {}
    dups: list[str] = []
    for r in receipts:
        rid = r.get("receipt_id")
        if rid in seen:
            same = canonical_json(seen[rid]) == canonical_json(r)
            dups.append(f"{rid!r} ({'byte-identical copy' if same else 'different content'})")
        else:
            seen[rid] = r
    if dups:
        out.append(failed("chain.unique_ids", "CHAIN_DUPLICATE_RECEIPT_ID", "; ".join(dups)))
    else:
        out.append(passed("chain.unique_ids", "no receipt_id repeats"))

    out.append(_signer_continuity(reports))
    return out


def _signer_continuity(reports: list[ReceiptReport]) -> Check:
    signed = [r for r in reports if r.form == "cose" and r.kid is not None]
    if len(signed) < 2:
        return not_checked("chain.signer", "fewer than two signed receipts; nothing to compare")
    kids_by_actor: dict[Any, set[str]] = {}
    for r in signed:
        actor_id = ((r.receipt or {}).get("actor") or {}).get("id")
        assert r.kid is not None
        kids_by_actor.setdefault(actor_id, set()).add(r.kid)
    split = {a: k for a, k in kids_by_actor.items() if len(k) > 1}
    if split:
        detail = "; ".join(f"actor {a!r} signed under {sorted(k)}" for a, k in split.items())
        return failed("chain.signer", "CHAIN_KEY_DISCONTINUITY", detail)
    return passed("chain.signer", "each actor's receipts are signed under one kid")
