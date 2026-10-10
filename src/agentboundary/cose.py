"""COSE_Sign1 envelope (Ed25519) for Action Receipts.

The envelope is OPTIONAL and sits alongside the bare JSON receipt; it does
not change the receipt's wire format. The choices follow the envelope
profile of draft-noa-scitt-ai-agent-receipt-01 section 4 (an individual
Internet-Draft, work in progress) where it applies to a receipt that, unlike
a noa receipt, carries no native in-payload signature:

* tagged COSE_Sign1 (CBOR tag 18, RFC 9052 section 4.2);
* protected header ``alg`` = -19, the fully-specified Ed25519 identifier
  (RFC 9864); every other value, including the deprecated polymorphic
  EdDSA -8, is rejected;
* ``kid`` in the protected header, a UTF-8 identifier resolved against a
  keyring the verifier is given out of band (a JWK Set, RFC 7517 / 8037);
* protected header in RFC 8949 section 4.2.1 core deterministic encoding;
* payload attached (no detached mode), and it is the RFC 8785 (JCS)
  serialization of the receipt, so the verifier can check
  JCS(parse(payload)) == payload before trusting any field;
* ``external_aad`` is the empty byte string;
* optionally, a CWT Claims header (label 15, RFC 9597) carrying ``iss`` (1)
  and ``sub`` (2), the protected-header shape RFC 9943 section 6 requires of
  a Signed Statement. Nothing here registers a statement with a
  Transparency Service.

Ed25519 verification is done by OpenSSL through ``cryptography``. On top of
it this module rejects a signature whose S is not reduced modulo the group
order, a public key whose y-coordinate is not a canonical field element,
and the eight small-order public key encodings. That last check matters:
``cryptography`` loads small-order keys, and with OpenSSL 4.0.3 it accepted
a forged signature (R = identity, S = 0) over an arbitrary message under the
identity key (see ``tests/test_cose.py``). Which Ed25519 verification
equation OpenSSL applies (cofactored or cofactorless) is not pinned here;
draft-noa-scitt-ai-agent-receipt-01 pins the cofactorless one.
"""

from __future__ import annotations

import base64
import io
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from agentboundary.hashing import canonical_json
from agentboundary.report import Check, failed, not_checked, passed

COSE_SIGN1_TAG: Final = 18
ALG_ED25519: Final = -19  # RFC 9864 section 2.2
HDR_ALG: Final = 1
HDR_CRIT: Final = 2
HDR_CONTENT_TYPE: Final = 3
HDR_KID: Final = 4
HDR_CWT_CLAIMS: Final = 15  # RFC 9597
CWT_ISS: Final = 1
CWT_SUB: Final = 2
SCITT_RECEIPTS: Final = 394  # RFC 9943 unprotected header carrying Transparency Receipts

# Not a registered media type. A Transparency Service that dispatches on
# content type needs to agree this value with the issuer.
CONTENT_TYPE: Final = "application/vnd.agentboundary.receipt+json"

_UNDERSTOOD_HEADERS: Final = frozenset(
    {HDR_ALG, HDR_CRIT, HDR_CONTENT_TYPE, HDR_KID, HDR_CWT_CLAIMS}
)

_P: Final = 2**255 - 19
_L: Final = 2**252 + 27742317777372353535851937790883648493

# The eight canonical encodings of the small-order points of edwards25519
# (identity, order 2, two of order 4, four of order 8). Each was checked to
# decode and to be annihilated by the cofactor using the RFC 8032 section 6
# reference arithmetic.
SMALL_ORDER_KEYS: Final = frozenset(
    bytes.fromhex(h)
    for h in (
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    )
)


class KeyringError(ValueError):
    """A key or keyring document is malformed or not acceptable."""


# --------------------------------------------------------------------------
# Deterministic CBOR (RFC 8949 section 4.2.1) for the subset we emit
# --------------------------------------------------------------------------


class NotEncodableError(ValueError):
    """The value holds a type outside the deterministic-encoding subset."""


def encode_deterministic(value: Any) -> bytes:
    """Encode ``value`` with shortest-form heads and bytewise-sorted map keys.

    Supports int, str, bytes, bool, None, sequences, mappings and tag 18.
    Floats and other tags are outside the subset and raise ``NotEncodableError``.
    """
    out = io.BytesIO()
    _encode(value, out)
    return out.getvalue()


def _head(major: int, arg: int) -> bytes:
    if arg < 24:
        return bytes([(major << 5) | arg])
    for extra, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if arg < 1 << (8 * size):
            return bytes([(major << 5) | extra]) + arg.to_bytes(size, "big")
    raise NotEncodableError(f"integer argument {arg} does not fit in 64 bits")


def _encode(value: Any, out: io.BytesIO) -> None:
    import cbor2

    if value is False:
        out.write(b"\xf4")
    elif value is True:
        out.write(b"\xf5")
    elif value is None:
        out.write(b"\xf6")
    elif isinstance(value, int):
        out.write(_head(0, value) if value >= 0 else _head(1, -1 - value))
    elif isinstance(value, bytes):
        out.write(_head(2, len(value)) + value)
    elif isinstance(value, str):
        raw = value.encode("utf-8")
        out.write(_head(3, len(raw)) + raw)
    elif isinstance(value, Mapping):
        items = sorted((encode_deterministic(k), v) for k, v in value.items())
        out.write(_head(5, len(items)))
        for key_bytes, v in items:
            out.write(key_bytes)
            _encode(v, out)
    elif isinstance(value, Sequence):
        out.write(_head(4, len(value)))
        for item in value:
            _encode(item, out)
    elif isinstance(value, cbor2.CBORTag) and value.tag == COSE_SIGN1_TAG:
        out.write(_head(6, value.tag))
        _encode(value.value, out)
    else:
        raise NotEncodableError(f"type {type(value).__name__} is outside the deterministic subset")


def sig_structure(protected: bytes, payload: bytes, external_aad: bytes = b"") -> bytes:
    """RFC 9052 section 4.4 Sig_structure for COSE_Sign1."""
    return encode_deterministic(["Signature1", protected, external_aad, payload])


# --------------------------------------------------------------------------
# Keys
# --------------------------------------------------------------------------


def _b64url_decode_canonical(text: Any, what: str) -> bytes:
    if not isinstance(text, str) or not text or "=" in text:
        raise KeyringError(f"{what} must be unpadded base64url text")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError) as exc:
        raise KeyringError(f"{what} is not base64url: {exc}") from exc
    if _b64url(raw) != text:
        raise KeyringError(f"{what} is not the canonical base64url spelling of its bytes")
    return raw


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def check_public_key(raw: bytes) -> str | None:
    """Return why ``raw`` is not an acceptable Ed25519 public key, or None."""
    if len(raw) != 32:
        return f"public key is {len(raw)} bytes, Ed25519 needs 32"
    y = int.from_bytes(raw, "little") & ((1 << 255) - 1)
    if not y < _P:
        return "public key y-coordinate is not a canonical field element"
    if raw in SMALL_ORDER_KEYS:
        return "public key is a small-order point"
    return None


@dataclass(frozen=True)
class KeyringEntry:
    kid: str
    public_key: bytes


@dataclass(frozen=True)
class Keyring:
    """Verification keys a verifier trusts for this run, addressed by kid."""

    entries: tuple[KeyringEntry, ...] = field(default_factory=tuple)

    def lookup(self, kid: str) -> list[KeyringEntry]:
        return [e for e in self.entries if e.kid == kid]


def _okp_ed25519(jwk: Any, where: str) -> tuple[str, bytes]:
    if not isinstance(jwk, Mapping):
        raise KeyringError(f"{where} is not a JSON object")
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise KeyringError(f"{where} must have kty=OKP and crv=Ed25519")
    kid = jwk.get("kid")
    if not isinstance(kid, str) or not kid:
        raise KeyringError(f"{where} needs a non-empty string kid")
    x = _b64url_decode_canonical(jwk.get("x"), f"{where}.x")
    problem = check_public_key(x)
    if problem is not None:
        raise KeyringError(f"{where}: {problem}")
    return kid, x


def load_keyring(jwks: Any) -> Keyring:
    """Build a keyring from a JWK Set of Ed25519 public keys."""
    if not isinstance(jwks, Mapping) or not isinstance(jwks.get("keys"), list):
        raise KeyringError('keyring must be a JWK Set: {"keys": [...]}')
    entries = []
    for i, jwk in enumerate(jwks["keys"]):
        where = f"keys[{i}]"
        if isinstance(jwk, Mapping) and "d" in jwk:
            raise KeyringError(
                f"{where} contains private key material; a keyring holds public keys"
            )
        kid, x = _okp_ed25519(jwk, where)
        entries.append(KeyringEntry(kid, x))
    return Keyring(tuple(entries))


def private_key_from_seed(seed: bytes) -> Any:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey.from_private_bytes(seed)


def _raw_public(private_key: Any) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    )


def _raw_private(private_key: Any) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return bytes(
        private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    )


def public_jwk(private_key: Any, kid: str) -> dict[str, str]:
    return {"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": _b64url(_raw_public(private_key))}


def private_jwk(private_key: Any, kid: str) -> dict[str, str]:
    return {**public_jwk(private_key, kid), "d": _b64url(_raw_private(private_key))}


def load_private_jwk(jwk: Any) -> tuple[Any, str]:
    """Return ``(private_key, kid)`` from an Ed25519 private JWK."""
    kid, x = _okp_ed25519(jwk, "private key")
    seed = _b64url_decode_canonical(jwk.get("d"), "private key.d")
    if len(seed) != 32:
        raise KeyringError("private key.d must decode to 32 bytes")
    key = private_key_from_seed(seed)
    if _raw_public(key) != x:
        raise KeyringError("private key.x does not match the public key derived from d")
    return key, kid


# --------------------------------------------------------------------------
# Signing
# --------------------------------------------------------------------------


def sign_payload(
    protected: Mapping[Any, Any],
    unprotected: Mapping[Any, Any],
    payload: bytes,
    private_key: Any,
) -> bytes:
    """Low-level COSE_Sign1 construction over arbitrary headers and payload.

    ``sign_receipt`` is the normal entry point. This one exists so tests and
    conformance scenarios can build deliberately wrong envelopes (another
    alg, a non-canonical payload) that still carry a valid signature.
    """
    import cbor2

    protected_bytes = encode_deterministic(dict(protected))
    signature = private_key.sign(sig_structure(protected_bytes, payload))
    return encode_deterministic(
        cbor2.CBORTag(COSE_SIGN1_TAG, [protected_bytes, dict(unprotected), payload, signature])
    )


def build_protected_header(
    kid: str,
    *,
    issuer: str | None = None,
    subject: str | None = None,
    content_type: str = CONTENT_TYPE,
) -> dict[int, Any]:
    if (issuer is None) != (subject is None):
        raise ValueError("a Signed Statement needs both issuer and subject, or neither")
    header: dict[int, Any] = {
        HDR_ALG: ALG_ED25519,
        HDR_CONTENT_TYPE: content_type,
        HDR_KID: kid.encode("utf-8"),
    }
    if issuer is not None and subject is not None:
        if not issuer or not subject:
            raise ValueError("issuer and subject must be non-empty")
        header[HDR_CWT_CLAIMS] = {CWT_ISS: issuer, CWT_SUB: subject}
    return header


def sign_receipt(
    receipt: Mapping[str, Any],
    private_key: Any,
    kid: str,
    *,
    issuer: str | None = None,
    subject: str | None = None,
) -> bytes:
    """Wrap ``receipt`` in a tagged COSE_Sign1 signed with Ed25519 (alg -19).

    The payload is the RFC 8785 serialization of the whole receipt,
    ``receipt_hash`` included. Passing ``issuer`` and ``subject`` adds the
    CWT Claims header so the envelope has the protected-header shape of an
    RFC 9943 Signed Statement.
    """
    if not kid:
        raise ValueError("kid must be non-empty")
    payload = canonical_json(dict(receipt)).encode("utf-8")
    protected = build_protected_header(kid, issuer=issuer, subject=subject)
    return sign_payload(protected, {}, payload, private_key)


# --------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------


@dataclass
class EnvelopeResult:
    """What ``verify_envelope`` established about one COSE_Sign1."""

    checks: list[Check] = field(default_factory=list)
    payload: bytes | None = None
    kid: str | None = None
    kid_bucket: str | None = None
    issuer: str | None = None
    subject: str | None = None

    @property
    def ok(self) -> bool:
        return not any(c.status == "fail" for c in self.checks)


def is_cose_sign1(data: bytes) -> bool:
    """True if ``data`` starts with the CBOR head of tag 18."""
    return data[:1] == b"\xd2"


def verify_envelope(
    data: bytes,
    keyring: Keyring | None,
    *,
    as_signed_statement: bool = False,
) -> EnvelopeResult:
    """Check one tagged COSE_Sign1 envelope; never raises on bad input.

    Reports each step in ``result.checks``. ``result.payload`` is set when
    the structure was sound enough to extract the payload, whether or not
    the signature verified, so the caller can still report on the receipt;
    callers must read ``result.ok`` before trusting it.
    """
    import cbor2

    res = EnvelopeResult()
    checks = res.checks

    try:
        fp = io.BytesIO(data)
        top = cbor2.CBORDecoder(fp).decode()
        trailing = fp.read()
    except Exception as exc:  # cbor2 raises several types on hostile input
        checks.append(failed("cose.structure", "COSE_STRUCTURE", f"not decodable CBOR: {exc}"))
        return res
    if trailing:
        checks.append(
            failed("cose.structure", "COSE_STRUCTURE", f"{len(trailing)} bytes after the envelope")
        )
        return res
    if not isinstance(top, cbor2.CBORTag) or top.tag != COSE_SIGN1_TAG:
        checks.append(
            failed("cose.structure", "COSE_STRUCTURE", "not a tagged COSE_Sign1 (CBOR tag 18)")
        )
        return res
    body = top.value
    if (
        not isinstance(body, Sequence)
        or isinstance(body, (bytes, str))
        or len(body) != 4
        or not isinstance(body[0], bytes)
        or not isinstance(body[1], Mapping)
        or not (body[2] is None or isinstance(body[2], bytes))
        or not isinstance(body[3], bytes)
    ):
        checks.append(
            failed(
                "cose.structure",
                "COSE_STRUCTURE",
                "COSE_Sign1 must be [protected bstr, unprotected map, payload, signature bstr]",
            )
        )
        return res
    protected_bytes, unprotected, payload, signature = body
    if payload is None:
        checks.append(
            failed(
                "cose.structure",
                "COSE_PAYLOAD_DETACHED",
                "payload is detached (nil); this profile requires it attached",
            )
        )
        return res
    checks.append(passed("cose.structure", "tagged COSE_Sign1 with attached payload"))
    res.payload = payload

    # Protected header: decodable map, deterministic encoding.
    try:
        protected = cbor2.loads(protected_bytes) if protected_bytes else {}
    except Exception as exc:
        checks.append(
            failed("cose.protected", "COSE_STRUCTURE", f"protected header not decodable: {exc}")
        )
        return res
    if not isinstance(protected, Mapping):
        checks.append(failed("cose.protected", "COSE_STRUCTURE", "protected header is not a map"))
        return res
    try:
        reencoded = encode_deterministic(protected)
    except NotEncodableError as exc:
        reencoded = None
        why = str(exc)
    if reencoded != protected_bytes:
        checks.append(
            failed(
                "cose.protected",
                "COSE_PROTECTED_NOT_DETERMINISTIC",
                "protected header is not in RFC 8949 core deterministic encoding"
                + (f" ({why})" if reencoded is None else "")
                + " (or repeats a key)",
            )
        )
        return res
    checks.append(passed("cose.protected", "protected header uses deterministic encoding"))

    # Algorithm: exactly -19 in the protected bucket.
    alg = protected.get(HDR_ALG)
    if type(alg) is not int or alg != ALG_ED25519:
        checks.append(
            failed(
                "cose.alg",
                "COSE_ALG_REJECTED",
                f"protected alg is {alg!r}; only {ALG_ED25519} (Ed25519, RFC 9864) is accepted",
            )
        )
        return res
    checks.append(passed("cose.alg", "alg -19 (Ed25519) in the protected header"))

    # crit: every listed label must be protected and understood here.
    if HDR_CRIT in unprotected:
        checks.append(
            failed("cose.crit", "COSE_CRIT_UNSUPPORTED", "crit must be in the protected header")
        )
        return res
    if HDR_CRIT in protected:
        crit = protected[HDR_CRIT]
        bad = (
            not isinstance(crit, Sequence)
            or isinstance(crit, (bytes, str))
            or not crit
            or any(
                not isinstance(label, (int, str))
                or label not in protected
                or label not in _UNDERSTOOD_HEADERS
                for label in crit
            )
        )
        if bad:
            checks.append(
                failed(
                    "cose.crit",
                    "COSE_CRIT_UNSUPPORTED",
                    f"crit lists {crit!r}; each label must be protected and one of "
                    f"{sorted(_UNDERSTOOD_HEADERS)}",
                )
            )
            return res

    if HDR_CWT_CLAIMS in protected and HDR_CWT_CLAIMS in unprotected:
        checks.append(
            failed(
                "cose.cwt_claims",
                "COSE_CWT_CLAIMS_DUPLICATED",
                "CWT Claims (label 15) appears in both header buckets (RFC 9597 section 2)",
            )
        )
        return res

    # kid: prefer the protected copy; report which bucket was used.
    if HDR_KID in protected:
        raw_kid, bucket = protected[HDR_KID], "protected"
    elif HDR_KID in unprotected:
        raw_kid, bucket = unprotected[HDR_KID], "unprotected"
    else:
        checks.append(failed("cose.kid", "COSE_KID_MISSING", "no kid in either header bucket"))
        return res
    if not isinstance(raw_kid, bytes) or not raw_kid:
        checks.append(failed("cose.kid", "COSE_KID_INVALID", "kid must be a non-empty bstr"))
        return res
    try:
        kid = raw_kid.decode("utf-8")
    except UnicodeDecodeError:
        checks.append(
            failed(
                "cose.kid",
                "COSE_KID_INVALID",
                "kid bytes are not UTF-8; refusing a lossy decode",
            )
        )
        return res
    res.kid, res.kid_bucket = kid, bucket
    note = "" if bucket == "protected" else " (unprotected: resolves a key, names nobody)"
    checks.append(passed("cose.kid", f"kid {kid!r} from the {bucket} header{note}"))

    content_type = protected.get(HDR_CONTENT_TYPE)
    if content_type is None:
        checks.append(not_checked("cose.content_type", "no protected content type"))
    else:
        checks.append(passed("cose.content_type", f"protected content type {content_type!r}"))

    checks.append(_check_signature(protected_bytes, payload, signature, kid, keyring))

    if as_signed_statement:
        checks.extend(_check_signed_statement(protected, unprotected, bucket, res))
    return res


def _check_signature(
    protected_bytes: bytes,
    payload: bytes,
    signature: bytes,
    kid: str,
    keyring: Keyring | None,
) -> Check:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    name = "cose.signature"
    if keyring is None:
        return not_checked(name, "no keyring supplied; the signature was not verified")
    candidates = keyring.lookup(kid)
    if not candidates:
        return failed(name, "COSE_KID_UNRESOLVED", f"kid {kid!r} is not in the keyring")
    if len(signature) != 64:
        return failed(name, "COSE_SIGNATURE_INVALID", "Ed25519 signature must be 64 bytes")
    if not int.from_bytes(signature[32:], "little") < _L:
        return failed(
            name, "COSE_SIGNATURE_INVALID", "signature S is not reduced modulo the group order"
        )
    message = sig_structure(protected_bytes, payload)
    verified = 0
    rejected_keys: list[str] = []
    for entry in candidates:
        problem = check_public_key(entry.public_key)
        if problem is not None:
            rejected_keys.append(problem)
            continue
        try:
            Ed25519PublicKey.from_public_bytes(entry.public_key).verify(signature, message)
        except InvalidSignature:
            continue
        verified += 1
    if rejected_keys and len(rejected_keys) == len(candidates):
        return failed(name, "COSE_KEY_REJECTED", "; ".join(rejected_keys))
    if verified == 0:
        return failed(
            name, "COSE_SIGNATURE_INVALID", f"Ed25519 signature does not verify under kid {kid!r}"
        )
    if verified > 1:
        return failed(
            name,
            "COSE_KID_AMBIGUOUS",
            f"kid {kid!r} matched {verified} keys that all verify; refusing to choose",
        )
    if len(candidates) > 1:
        return passed(
            name,
            f"verified under kid {kid!r}; kid is ambiguous in the keyring "
            f"({len(candidates)} keys tried, exactly one verified)",
        )
    return passed(name, f"Ed25519 signature verifies under kid {kid!r}")


def _check_signed_statement(
    protected: Mapping[Any, Any],
    unprotected: Mapping[Any, Any],
    kid_bucket: str,
    res: EnvelopeResult,
) -> list[Check]:
    out: list[Check] = []
    claims = protected.get(HDR_CWT_CLAIMS)
    iss = claims.get(CWT_ISS) if isinstance(claims, Mapping) else None
    sub = claims.get(CWT_SUB) if isinstance(claims, Mapping) else None
    if isinstance(iss, str) and iss and isinstance(sub, str) and sub:
        res.issuer, res.subject = iss, sub
        out.append(
            passed("scitt.cwt_claims", f"protected CWT Claims carry iss={iss!r} and sub={sub!r}")
        )
    else:
        out.append(
            failed(
                "scitt.cwt_claims",
                "SCITT_CWT_CLAIMS_MISSING",
                "a Signed Statement needs protected CWT Claims (label 15) with string "
                "iss (1) and sub (2) (RFC 9943 section 6)",
            )
        )
    if kid_bucket == "protected":
        out.append(passed("scitt.kid", "kid is in the protected header"))
    else:
        out.append(
            failed(
                "scitt.kid",
                "SCITT_KID_NOT_PROTECTED",
                "a Signed Statement without x5t/x5chain needs kid in the protected header",
            )
        )
    if SCITT_RECEIPTS in unprotected:
        out.append(
            not_checked(
                "scitt.transparency_receipt",
                "a Transparency Receipt (label 394) is attached; this verifier does not "
                "check inclusion proofs",
            )
        )
    else:
        out.append(
            not_checked(
                "scitt.registration",
                "statement shape only; it has not been registered with or checked "
                "against any Transparency Service",
            )
        )
    return out
