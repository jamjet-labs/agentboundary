"""Offline verification of Action Receipts and receipt chains.

Everything here runs locally on the bytes it is given: no network, no
vendor service, no JamJet component. The report says what was checked,
what failed, and what was not checked and why, because a verifier that
reports a property it did not check is worse than none.

It also says which of three properties the input established:

* ``hash``: every ``receipt_hash`` matches its receipt. This catches
  accidental change only. Anyone who can edit a receipt can recompute its
  hash, so on its own it is not evidence that nobody edited the receipt.
* ``signed``: every receipt carries an Ed25519 signature that verified
  under a keyring key, and the keyring binds that key to the receipt's
  ``actor.id`` (and to the envelope's CWT ``iss``, when it names one).
* ``chained``: two or more receipts form one unbroken chain from a genesis
  receipt.

A caller can require any of them; one that is not established then fails.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from agentboundary.conformance import check_conformance
from agentboundary.cose import (
    ANY_IDENTITY,
    Keyring,
    KeyringEntry,
    binding_allows,
    is_cose_sign1,
    verify_envelope,
)
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
    "signed the envelope, and, where the keyring binds that key to actor ids or "
    "issuers, that the receipt's actor.id and the envelope's iss are among them. "
    "Whether the key is really held by that party is decided by whoever supplied "
    "the keyring.",
    "Timestamps are the emitter's own and are not checked against any clock.",
    "Truncation: receipts removed from the end of a stream cannot be detected "
    "from the receipts presented; that needs an external checkpoint.",
    "Equivocation: an emitter that signed two different histories cannot be "
    "detected from one presentation; that needs a transparency log, and no "
    "Transparency Service was consulted.",
    "Unicode normalization (NFC) of strings is not checked; strings are hashed as received.",
    "Ed25519 is verified by OpenSSL (through the cryptography package) plus "
    "this verifier's own checks on S and on the public key. The project's tests "
    "hold it to the cofactorless equation with one known vector; that is a test "
    "of the installed library, not a proof.",
)

# Conformance codes the receipt-level checks already report under their own
# names, so they are not listed twice.
_REPORTED_ELSEWHERE = frozenset({"SCHEMA_INVALID", "LEVEL_3_RECEIPT_HASH_MISMATCH"})

# Properties a caller can require (``verify --require``). See the module
# docstring for what each one does and does not show.
ASSURANCES: tuple[str, ...] = ("hash", "signed", "chained")


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
    key_fingerprint: str | None = None
    key: KeyringEntry | None = None
    signer_bound: bool = False  # the verifying key is bound to actor.id (and iss)

    @property
    def receipt_id(self) -> str | None:
        rid = (self.receipt or {}).get("receipt_id")
        return rid if isinstance(rid, str) else None

    @property
    def hash_ok(self) -> bool:
        return any(c.name == "receipt_hash" and c.status == "pass" for c in self.checks)

    @property
    def signed(self) -> bool:
        return self.signature_verified and self.signer_bound

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "form": self.form,
            "receipt_id": self.receipt_id,
            "kid": self.kid,
            "kid_bucket": self.kid_bucket,
            "issuer": self.issuer,
            "subject": self.subject,
            "established": {"hash": self.hash_ok, "signed": self.signed},
            "checks": [c.to_dict() for c in self.checks],
        }


@dataclass(frozen=True)
class Assurance:
    """Whether the whole input established one property, and why or why not."""

    name: str
    met: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"met": self.met, "detail": self.detail}


@dataclass
class VerifyReport:
    receipts: list[ReceiptReport] = field(default_factory=list)
    chain: list[Check] = field(default_factory=list)
    not_checked: tuple[str, ...] = NOT_CHECKED_STATEMENTS
    required: tuple[str, ...] = ("hash",)

    @property
    def ok(self) -> bool:
        every = [*self.chain, *(c for r in self.receipts for c in r.checks)]
        return not any(c.status == "fail" for c in every)

    def established(self) -> list[Assurance]:
        """What the input established, property by property (see ``ASSURANCES``)."""
        return [_hash_assurance(self), _signed_assurance(self), _chained_assurance(self)]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "required": list(self.required),
            "established": {a.name: a.to_dict() for a in self.established()},
            "receipts": [r.to_dict() for r in self.receipts],
            "chain": [c.to_dict() for c in self.chain],
            "not_checked": list(self.not_checked),
        }


def _hash_assurance(report: VerifyReport) -> Assurance:
    if not report.receipts:
        return Assurance("hash", False, "no receipts were presented")
    bad = [r.source for r in report.receipts if not r.hash_ok]
    if bad:
        return Assurance("hash", False, f"receipt_hash did not match for {', '.join(bad)}")
    return Assurance(
        "hash",
        True,
        "every receipt_hash matches its receipt. This catches accidental change only: "
        "anyone who can edit a receipt can recompute its hash, so it is not evidence "
        "that the receipt is unedited",
    )


def _why_not_signed(r: ReceiptReport) -> str:
    if r.form == "bare":
        return "bare receipt, no signature"
    if not r.signature_verified:
        return "signature not verified"
    if r.key is not None and r.key.actor_ids is None:
        return f"key {r.kid!r} is not bound to any actor in the keyring"
    if r.issuer is not None and r.key is not None and r.key.issuers is None:
        return f"key {r.kid!r} is not bound to any issuer in the keyring"
    return f"key {r.kid!r} may not sign for this receipt's actor or issuer"


def _signed_assurance(report: VerifyReport) -> Assurance:
    if not report.receipts:
        return Assurance("signed", False, "no receipts were presented")
    unsigned = [f"{r.source} ({_why_not_signed(r)})" for r in report.receipts if not r.signed]
    if unsigned:
        return Assurance("signed", False, "; ".join(unsigned))
    return Assurance(
        "signed",
        True,
        "every receipt carries a signature that verified under a keyring key bound to "
        "the receipt's actor",
    )


def _chain_complete(report: VerifyReport) -> str | None:
    """Why the receipts do not form a verified chain, or None if they do."""
    if len(report.receipts) < 2:
        return "fewer than two receipts were presented, so no link was checked"
    failures = {
        c.code
        for c in report.chain
        if c.status == "fail" and c.code is not None and c.code != "CHAIN_REQUIRED"
    }
    if failures:
        return f"chain checks failed ({', '.join(sorted(failures))})"
    names = {c.name for c in report.chain if c.status == "pass"}
    missing = {"chain.genesis", "chain.links", "chain.unique_ids"} - names
    if missing:
        return f"chain checks did not run ({', '.join(sorted(missing))})"
    return None


def _chained_assurance(report: VerifyReport) -> Assurance:
    why = _chain_complete(report)
    if why is not None:
        return Assurance("chained", False, why)
    return Assurance(
        "chained",
        True,
        f"{len(report.receipts)} receipts link in order from a genesis receipt, so none "
        "was removed, inserted or reordered between the first and the last. Someone who "
        "can rewrite every receipt can rebuild the chain, and a missing tail is not "
        "detected",
    )


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
    require: Iterable[str] = (),
) -> VerifyReport:
    """Verify each item, then the chain they form in presentation order.

    Supplying a keyring means the caller expects signed receipts, so it
    implies ``require_signature``: otherwise an unsigned receipt could be
    slipped into a signed chain and pass. An envelope's signature must
    verify whatever is required: a signature that is present but was not
    checked is not reported as passing.

    ``require`` names properties from ``ASSURANCES`` that must be
    established. ``"signed"`` is stricter than ``require_signature``: the
    verifying key must also be bound to the receipt's actor (and issuer).
    """
    required = tuple(dict.fromkeys(("hash", *require)))
    unknown = [r for r in required if r not in ASSURANCES]
    if unknown:
        raise ValueError(f"unknown requirement(s) {unknown}; choose from {list(ASSURANCES)}")
    require_signature = require_signature or keyring is not None or "signed" in required
    report = VerifyReport(required=required)
    for item in items:
        try:
            rr = _verify_one(
                item,
                keyring,
                as_signed_statement,
                require_signature,
                require_bound="signed" in required,
            )
        except Exception as exc:  # last line of defence: report, never crash
            rr = ReceiptReport(item.source, item.form)
            rr.checks.append(failed("internal", "VERIFIER_ERROR", f"{type(exc).__name__}: {exc}"))
        report.receipts.append(rr)
    try:
        report.chain = _chain_checks(report.receipts)
    except Exception as exc:
        report.chain = [failed("chain", "VERIFIER_ERROR", f"{type(exc).__name__}: {exc}")]
    if "chained" in required:
        why = _chain_complete(report)
        if why is not None:
            report.chain.append(
                failed("chain.required", "CHAIN_REQUIRED", f"a chain was required: {why}")
            )
    return report


def _verify_one(
    item: Item,
    keyring: Keyring | None,
    as_signed_statement: bool,
    require_signature: bool,
    *,
    require_bound: bool = False,
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
        rr.key_fingerprint = env.key_fingerprint
        rr.key = env.key if rr.signature_verified else None
        if env.payload is None:
            return rr
        receipt = _receipt_from_payload(env.payload, checks)
        if receipt is None:
            return rr
        # An envelope presents a signature. Left unchecked it must not pass:
        # without keys, an envelope whose payload or signature was altered
        # looks exactly like an intact one.
        require_signature = True
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
    if rr.key is not None:
        checks.extend(_binding_checks(rr, receipt))
    if require_signature and not rr.signature_verified:
        if item.form == "cose" and keyring is None:
            why = (
                "the envelope carries a signature that was not verified because no keys "
                "were supplied (--keys); an altered envelope looks the same without them"
            )
        elif item.form == "cose":
            why = "the envelope's signature did not verify under the supplied keys"
        else:
            why = (
                "a signature was required (--require signed, or --keys) and a bare "
                "receipt carries none"
            )
        checks.append(failed("signature.required", "SIGNATURE_REQUIRED", why))
    elif require_bound and not rr.signer_bound and not _has_binding_failure(checks):
        checks.append(
            failed(
                "signer.required",
                "SIGNER_UNBOUND",
                f"a signed receipt was required, and {_why_not_signed(rr)}; bind the key "
                "with actor_ids (and issuers) in the keyring",
            )
        )
    checks.extend(_receipt_checks(receipt))
    return rr


_BINDING_FAILURES = frozenset({"SIGNER_ACTOR_MISMATCH", "SIGNER_ISSUER_MISMATCH"})


def _has_binding_failure(checks: list[Check]) -> bool:
    return any(c.code in _BINDING_FAILURES for c in checks)


def _binding_checks(rr: ReceiptReport, receipt: dict[str, Any]) -> list[Check]:
    """Check the verifying key may sign for the receipt's actor and the envelope's iss.

    A key the keyring binds to identities may not vouch for any other; a key
    with no binding is reported as such, never as passing.
    """
    key = rr.key
    assert key is not None
    out: list[Check] = []
    actor = receipt.get("actor")
    actor_id = actor.get("id") if isinstance(actor, dict) else None
    actor_ok: bool | None = None
    if not isinstance(actor_id, str):
        out.append(not_checked("signer.actor", "the receipt has no string actor.id"))
    else:
        actor_ok = binding_allows(key.actor_ids, actor_id)
        if actor_ok is None:
            out.append(
                not_checked(
                    "signer.actor",
                    f"key {key.kid!r} declares no actor_ids, so which actors it may sign "
                    "for was not checked",
                )
            )
        elif actor_ok:
            scope = "any actor" if key.actor_ids == (ANY_IDENTITY,) else f"actor {actor_id!r}"
            out.append(passed("signer.actor", f"key {key.kid!r} is bound to {scope}"))
        else:
            out.append(
                failed(
                    "signer.actor",
                    "SIGNER_ACTOR_MISMATCH",
                    f"key {key.kid!r} is bound to actor_ids {list(key.actor_ids or ())}, "
                    f"not to actor.id {actor_id!r}",
                )
            )

    issuer_ok: bool | None = True
    if rr.issuer is not None:
        issuer_ok = binding_allows(key.issuers, rr.issuer)
        if issuer_ok is None:
            out.append(
                not_checked(
                    "signer.issuer",
                    f"iss {rr.issuer!r} is asserted by the signer; key {key.kid!r} "
                    "declares no issuers, so it was not checked",
                )
            )
        elif issuer_ok:
            out.append(passed("signer.issuer", f"key {key.kid!r} may sign for iss {rr.issuer!r}"))
        else:
            out.append(
                failed(
                    "signer.issuer",
                    "SIGNER_ISSUER_MISMATCH",
                    f"key {key.kid!r} is bound to issuers {list(key.issuers or ())}, "
                    f"not to iss {rr.issuer!r}",
                )
            )
    rr.signer_bound = actor_ok is True and issuer_ok is True
    return out


def _receipt_from_payload(payload: bytes, checks: list[Check]) -> dict[str, Any] | None:
    try:
        value = parse_json_strict(payload)
    except StrictJSONError as exc:
        checks.append(failed("payload.json", "PAYLOAD_INVALID", f"payload is not a receipt: {exc}"))
        return None
    if not isinstance(value, dict):
        checks.append(failed("payload.json", "PAYLOAD_INVALID", "payload is not a JSON object"))
        return None
    try:
        canonical = canonical_json(value).encode("utf-8")
    except Exception as exc:  # rfc8785 refuses e.g. integers beyond 2**53
        checks.append(
            failed("payload.json", "PAYLOAD_INVALID", f"payload cannot be canonicalized: {exc}")
        )
        return None
    if canonical != payload:
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
    if not reports:
        return [failed("chain", "NO_RECEIPTS", "the input held no receipts; nothing was verified")]
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

    seen: dict[str, dict[str, Any]] = {}
    dups: list[str] = []
    for r in receipts:
        rid = r.get("receipt_id")
        if not isinstance(rid, str):
            continue  # the schema check has already failed this receipt
        if rid in seen:
            same = seen[rid] == r
            dups.append(f"{rid!r} ({'identical copy' if same else 'different content'})")
        else:
            seen[rid] = r
    if dups:
        out.append(failed("chain.unique_ids", "CHAIN_DUPLICATE_RECEIPT_ID", "; ".join(dups)))
    else:
        out.append(passed("chain.unique_ids", "no receipt_id repeats"))

    out.append(_signer_continuity(reports))
    return out


def _signer_continuity(reports: list[ReceiptReport]) -> Check:
    """One signing key per actor, judged by the key that actually verified.

    Comparing kid strings is not enough: two keys can share a kid in the
    keyring, and an unverified envelope's kid is an attacker-chosen header.
    So only receipts with a verified signature count, keyed by fingerprint.
    """
    signed = [r for r in reports if r.signature_verified and r.key_fingerprint is not None]
    if len(signed) < 2:
        return not_checked(
            "chain.signer", "fewer than two receipts with a verified signature; nothing to compare"
        )
    keys_by_actor: dict[str, set[str]] = {}
    for r in signed:
        actor = (r.receipt or {}).get("actor")
        actor_id = actor.get("id") if isinstance(actor, dict) else None
        if not isinstance(actor_id, str) or r.key_fingerprint is None:
            continue  # the schema check has already failed this receipt
        keys_by_actor.setdefault(actor_id, set()).add(r.key_fingerprint)
    split = {a: k for a, k in keys_by_actor.items() if len(k) > 1}
    if split:
        detail = "; ".join(
            f"actor {a!r} signed by {len(k)} different keys "
            f"({', '.join('sha256:' + f[:16] for f in sorted(k))})"
            for a, k in split.items()
        )
        return failed("chain.signer", "CHAIN_KEY_DISCONTINUITY", detail)
    return passed("chain.signer", "each actor's receipts are signed by one key")
