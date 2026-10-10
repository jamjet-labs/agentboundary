"""COSE_Sign1 (Ed25519) envelope: encoding, signing, and every verifier guard."""

from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any

import cbor2
import pytest

from agentboundary.cose import (
    ALG_ED25519,
    CONTENT_TYPE,
    HDR_ALG,
    HDR_CONTENT_TYPE,
    HDR_CRIT,
    HDR_CWT_CLAIMS,
    HDR_KID,
    SMALL_ORDER_KEYS,
    Keyring,
    KeyringEntry,
    KeyringError,
    build_protected_header,
    encode_deterministic,
    is_cose_sign1,
    load_keyring,
    load_private_jwk,
    private_jwk,
    private_key_from_seed,
    public_jwk,
    sig_structure,
    sign_payload,
    sign_receipt,
    verify_envelope,
)
from agentboundary.hashing import canonical_json

SEED = bytes(range(32))  # TEST KEY ONLY
OTHER_SEED = bytes(range(1, 33))  # TEST KEY ONLY
KID = "test-key-1"
L = 2**252 + 27742317777372353535851937790883648493


@pytest.fixture
def receipt() -> dict[str, Any]:
    path = Path(__file__).resolve().parent.parent / "docs" / "receipts" / "github-merge.json"
    return json.loads(path.read_text("utf-8"))


@pytest.fixture
def key() -> Any:
    return private_key_from_seed(SEED)


@pytest.fixture
def keyring(key: Any) -> Keyring:
    return load_keyring({"keys": [public_jwk(key, KID)]})


def _codes(result: Any) -> set[str]:
    return {c.code for c in result.checks if c.status == "fail"}


def _status(result: Any, name: str) -> str:
    return next(c.status for c in result.checks if c.name == name)


def _payload(receipt: dict[str, Any]) -> bytes:
    return canonical_json(receipt).encode("utf-8")


def _raw_envelope(protected_bytes: bytes, unprotected: dict, payload: Any, key: Any) -> bytes:
    """Build an envelope from pre-encoded protected bytes, signed validly."""
    sig = key.sign(sig_structure(protected_bytes, payload or b""))
    return cbor2.dumps(cbor2.CBORTag(18, [protected_bytes, unprotected, payload, sig]))


class TestDeterministicEncoding:
    @pytest.mark.parametrize(
        ("value", "hex_"),
        [
            # RFC 8949 Appendix A vectors
            (0, "00"),
            (23, "17"),
            (24, "1818"),
            (100, "1864"),
            (1000, "1903e8"),
            (1000000, "1a000f4240"),
            (1000000000000, "1b000000e8d4a51000"),
            (-1, "20"),
            (-10, "29"),
            (-100, "3863"),
            (-1000, "3903e7"),
            ("", "60"),
            ("a", "6161"),
            (b"", "40"),
            ([], "80"),
            ([1, 2, 3], "83010203"),
            ({}, "a0"),
            ({1: 2, 3: 4}, "a201020304"),
            (False, "f4"),
            (True, "f5"),
            (None, "f6"),
        ],
    )
    def test_rfc8949_vectors(self, value: Any, hex_: str) -> None:
        assert encode_deterministic(value).hex() == hex_

    def test_map_keys_sort_bytewise_not_length_first(self) -> None:
        # 24 encodes as 18 18 and -1 as 20: bytewise puts 24 first, the old
        # RFC 7049 length-first rule would put -1 first.
        assert encode_deterministic({-1: 0, 24: 0}).hex() == "a2181800" + "2000"

    def test_float_is_outside_the_subset(self) -> None:
        from agentboundary.cose import NotEncodableError

        with pytest.raises(NotEncodableError):
            encode_deterministic(1.5)

    def test_sig_structure_matches_an_independent_encoder(self) -> None:
        mine = sig_structure(b"\xa1\x01\x32", b'{"a":1}')
        assert mine == cbor2.dumps(["Signature1", b"\xa1\x01\x32", b"", b'{"a":1}'])


class TestSignAndVerify:
    def test_round_trip(self, receipt: dict, key: Any, keyring: Keyring) -> None:
        env = sign_receipt(receipt, key, KID)
        assert is_cose_sign1(env)
        res = verify_envelope(env, keyring)
        assert res.ok, res.checks
        assert _status(res, "cose.signature") == "pass"
        assert res.payload == _payload(receipt)
        assert (res.kid, res.kid_bucket) == (KID, "protected")

    def test_protected_header_shape(self, receipt: dict, key: Any) -> None:
        env = sign_receipt(receipt, key, KID)
        protected = cbor2.loads(cbor2.loads(env).value[0])
        assert protected == {
            HDR_ALG: ALG_ED25519,
            HDR_CONTENT_TYPE: CONTENT_TYPE,
            HDR_KID: KID.encode(),
        }

    def test_no_keyring_reports_not_checked(self, receipt: dict, key: Any) -> None:
        res = verify_envelope(sign_receipt(receipt, key, KID), None)
        assert _status(res, "cose.signature") == "not_checked"
        assert res.payload == _payload(receipt)

    def test_tampered_payload(self, receipt: dict, key: Any, keyring: Keyring) -> None:
        env = bytearray(sign_receipt(receipt, key, KID))
        idx = env.index(b'"allow"')
        env[idx + 1 : idx + 6] = b"denyy"
        assert _codes(verify_envelope(bytes(env), keyring)) == {"COSE_SIGNATURE_INVALID"}

    def test_tampered_signature(self, receipt: dict, key: Any, keyring: Keyring) -> None:
        env = bytearray(sign_receipt(receipt, key, KID))
        env[-1] ^= 0x01
        assert _codes(verify_envelope(bytes(env), keyring)) == {"COSE_SIGNATURE_INVALID"}

    def test_wrong_key_under_known_kid(self, receipt: dict, keyring: Keyring) -> None:
        env = sign_receipt(receipt, private_key_from_seed(OTHER_SEED), KID)
        assert _codes(verify_envelope(env, keyring)) == {"COSE_SIGNATURE_INVALID"}

    def test_unknown_kid(self, receipt: dict, key: Any, keyring: Keyring) -> None:
        env = sign_receipt(receipt, key, "someone-else")
        assert _codes(verify_envelope(env, keyring)) == {"COSE_KID_UNRESOLVED"}


class TestAlgorithm:
    def _with_alg(self, receipt: dict, key: Any, alg: Any) -> bytes:
        protected = build_protected_header(KID)
        protected[HDR_ALG] = alg
        return sign_payload(protected, {}, _payload(receipt), key)

    @pytest.mark.parametrize("alg", [-8, -7, 0, "-19", True])
    def test_other_algs_are_rejected(
        self, receipt: dict, key: Any, keyring: Keyring, alg: Any
    ) -> None:
        env = self._with_alg(receipt, key, alg)
        assert _codes(verify_envelope(env, keyring)) == {"COSE_ALG_REJECTED"}

    def test_alg_only_in_unprotected_is_rejected(
        self, receipt: dict, key: Any, keyring: Keyring
    ) -> None:
        protected = build_protected_header(KID)
        del protected[HDR_ALG]
        env = sign_payload(protected, {HDR_ALG: ALG_ED25519}, _payload(receipt), key)
        assert _codes(verify_envelope(env, keyring)) == {"COSE_ALG_REJECTED"}


class TestStructure:
    @pytest.mark.parametrize(
        "data",
        [
            b"",
            b"\x00\x01\x02",
            b"not cbor at all",
            cbor2.dumps([b"", {}, b"x", b"y"]),  # untagged
            cbor2.dumps(cbor2.CBORTag(98, [b"", {}, b"x", b"y"])),  # right shape, wrong tag
            cbor2.dumps(cbor2.CBORTag(18, [b"", {}, b"x"])),  # 3 elements
            cbor2.dumps(cbor2.CBORTag(18, [{}, {}, b"x", b"y"])),  # protected not bstr
            cbor2.dumps(cbor2.CBORTag(18, [b"", [], b"x", b"y"])),  # unprotected not map
            cbor2.dumps(cbor2.CBORTag(18, [b"", {}, "x", b"y"])),  # payload text
        ],
    )
    def test_malformed_envelopes(self, data: bytes, keyring: Keyring) -> None:
        assert _codes(verify_envelope(data, keyring)) == {"COSE_STRUCTURE"}

    def test_trailing_bytes(self, receipt: dict, key: Any, keyring: Keyring) -> None:
        env = sign_receipt(receipt, key, KID) + b"\x00"
        assert _codes(verify_envelope(env, keyring)) == {"COSE_STRUCTURE"}

    def test_detached_payload(self, key: Any, keyring: Keyring) -> None:
        protected = encode_deterministic(build_protected_header(KID))
        env = _raw_envelope(protected, {}, None, key)
        assert _codes(verify_envelope(env, keyring)) == {"COSE_PAYLOAD_DETACHED"}

    def test_never_raises_on_hostile_input(self, receipt: dict, key: Any, keyring: Keyring) -> None:
        rng = random.Random(1234)
        good = sign_receipt(receipt, key, KID)
        for _ in range(300):
            blob = bytearray(good)
            for _ in range(rng.randint(1, 4)):
                blob[rng.randrange(len(blob))] = rng.randrange(256)
            verify_envelope(bytes(blob), keyring)
            verify_envelope(bytes(rng.randrange(256) for _ in range(rng.randint(0, 64))), keyring)


class TestProtectedHeaderEncoding:
    def test_unsorted_keys(self, receipt: dict, key: Any, keyring: Keyring) -> None:
        kid = KID.encode()
        # {4: kid, 1: -19}: valid CBOR, keys out of order
        protected = b"\xa2\x04" + encode_deterministic(kid) + b"\x01\x32"
        env = _raw_envelope(protected, {}, _payload(receipt), key)
        assert _codes(verify_envelope(env, keyring)) == {"COSE_PROTECTED_NOT_DETERMINISTIC"}

    def test_non_shortest_integer(self, receipt: dict, key: Any, keyring: Keyring) -> None:
        # alg -19 written as 38 12 (one extra byte) instead of 32
        protected = b"\xa2\x01\x38\x12\x04" + encode_deterministic(KID.encode())
        env = _raw_envelope(protected, {}, _payload(receipt), key)
        assert _codes(verify_envelope(env, keyring)) == {"COSE_PROTECTED_NOT_DETERMINISTIC"}

    def test_duplicate_key(self, receipt: dict, key: Any, keyring: Keyring) -> None:
        protected = b"\xa3\x01\x26\x01\x32\x04" + encode_deterministic(KID.encode())
        env = _raw_envelope(protected, {}, _payload(receipt), key)
        assert _codes(verify_envelope(env, keyring)) == {"COSE_PROTECTED_NOT_DETERMINISTIC"}


class TestCrit:
    def _env(self, receipt: dict, key: Any, crit: Any, *, in_unprotected: bool = False) -> bytes:
        protected = build_protected_header(KID)
        if in_unprotected:
            return sign_payload(protected, {HDR_CRIT: crit}, _payload(receipt), key)
        protected[HDR_CRIT] = crit
        return sign_payload(protected, {}, _payload(receipt), key)

    def test_understood_protected_label_is_accepted(
        self, receipt: dict, key: Any, keyring: Keyring
    ) -> None:
        assert verify_envelope(self._env(receipt, key, [HDR_KID]), keyring).ok

    @pytest.mark.parametrize("crit", [[33], [HDR_CWT_CLAIMS], [], [[1]], "4"])
    def test_rejected_crit(self, receipt: dict, key: Any, keyring: Keyring, crit: Any) -> None:
        # 33 is not understood; 15 is understood but absent from the header
        env = self._env(receipt, key, crit)
        assert _codes(verify_envelope(env, keyring)) == {"COSE_CRIT_UNSUPPORTED"}

    def test_protected_but_not_understood_label(
        self, receipt: dict, key: Any, keyring: Keyring
    ) -> None:
        protected = build_protected_header(KID)
        protected[33] = b"cert"  # x5chain: present and protected, but not processed here
        protected[HDR_CRIT] = [33]
        env = sign_payload(protected, {}, _payload(receipt), key)
        assert _codes(verify_envelope(env, keyring)) == {"COSE_CRIT_UNSUPPORTED"}

    def test_crit_in_unprotected(self, receipt: dict, key: Any, keyring: Keyring) -> None:
        env = self._env(receipt, key, [HDR_KID], in_unprotected=True)
        assert _codes(verify_envelope(env, keyring)) == {"COSE_CRIT_UNSUPPORTED"}


class TestKid:
    def _env(self, receipt: dict, key: Any, protected_kid: Any, unprotected_kid: Any) -> bytes:
        protected = build_protected_header(KID)
        del protected[HDR_KID]
        if protected_kid is not None:
            protected[HDR_KID] = protected_kid
        unprotected = {} if unprotected_kid is None else {HDR_KID: unprotected_kid}
        return sign_payload(protected, unprotected, _payload(receipt), key)

    def test_missing(self, receipt: dict, key: Any, keyring: Keyring) -> None:
        env = self._env(receipt, key, None, None)
        assert _codes(verify_envelope(env, keyring)) == {"COSE_KID_MISSING"}

    @pytest.mark.parametrize("kid", [KID, b"", b"\xff\xfe"])
    def test_invalid(self, receipt: dict, key: Any, keyring: Keyring, kid: Any) -> None:
        env = self._env(receipt, key, kid, None)
        assert _codes(verify_envelope(env, keyring)) == {"COSE_KID_INVALID"}

    def test_unprotected_kid_resolves_and_is_reported(
        self, receipt: dict, key: Any, keyring: Keyring
    ) -> None:
        res = verify_envelope(self._env(receipt, key, None, KID.encode()), keyring)
        assert res.ok
        assert res.kid_bucket == "unprotected"

    def test_protected_copy_wins(self, receipt: dict, key: Any, keyring: Keyring) -> None:
        res = verify_envelope(self._env(receipt, key, KID.encode(), b"decoy"), keyring)
        assert res.ok
        assert (res.kid, res.kid_bucket) == (KID, "protected")

    def test_ambiguous_kid_one_verifies(self, receipt: dict, key: Any) -> None:
        other = private_key_from_seed(OTHER_SEED)
        ring = load_keyring({"keys": [public_jwk(other, KID), public_jwk(key, KID)]})
        res = verify_envelope(sign_receipt(receipt, key, KID), ring)
        assert res.ok
        sig = next(c for c in res.checks if c.name == "cose.signature")
        assert "ambiguous" in sig.detail

    def test_ambiguous_kid_both_verify(self, receipt: dict, key: Any) -> None:
        ring = load_keyring({"keys": [public_jwk(key, KID), public_jwk(key, KID)]})
        res = verify_envelope(sign_receipt(receipt, key, KID), ring)
        assert _codes(res) == {"COSE_KID_AMBIGUOUS"}


class TestEd25519Hardening:
    def test_non_canonical_s(self, receipt: dict, key: Any, keyring: Keyring) -> None:
        env = cbor2.loads(sign_receipt(receipt, key, KID))
        protected, unprotected, payload, sig = env.value
        s = int.from_bytes(sig[32:], "little") + L
        if s >= 2**256:  # pragma: no cover - depends on the fixed test key
            pytest.skip("S + L does not fit in 32 bytes for this signature")
        bad = sig[:32] + s.to_bytes(32, "little")
        forged = cbor2.dumps(cbor2.CBORTag(18, [protected, unprotected, payload, bad]))
        res = verify_envelope(forged, keyring)
        assert _codes(res) == {"COSE_SIGNATURE_INVALID"}
        assert "reduced" in next(c.detail for c in res.checks if c.name == "cose.signature")

    def test_small_order_key_forgery_is_refused(self, receipt: dict) -> None:
        """With the identity point as the public key, R = identity and S = 0
        satisfy [S]B = R + [k]A for every message. The keyring loader refuses
        such a key; a hand-built keyring holding one is refused at verify."""
        identity = bytes.fromhex("01" + "00" * 31)
        forged_sig = identity + bytes(32)
        protected = encode_deterministic(build_protected_header(KID))
        payload = _payload(receipt)
        env = cbor2.dumps(cbor2.CBORTag(18, [protected, {}, payload, forged_sig]))
        ring = Keyring((KeyringEntry(KID, identity),))
        assert _codes(verify_envelope(env, ring)) == {"COSE_KEY_REJECTED"}

    @pytest.mark.parametrize("raw", sorted(SMALL_ORDER_KEYS))
    def test_loader_refuses_small_order_keys(self, raw: bytes) -> None:
        import base64

        x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        with pytest.raises(KeyringError, match="small-order"):
            load_keyring({"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "k", "x": x}]})

    def test_loader_refuses_non_canonical_y(self) -> None:
        import base64

        p = 2**255 - 19
        x = base64.urlsafe_b64encode(p.to_bytes(32, "little")).rstrip(b"=").decode()
        with pytest.raises(KeyringError, match="canonical field element"):
            load_keyring({"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "k", "x": x}]})


class TestJwk:
    def test_private_round_trip(self, key: Any) -> None:
        loaded, kid = load_private_jwk(private_jwk(key, KID))
        assert kid == KID
        assert public_jwk(loaded, KID) == public_jwk(key, KID)

    def test_private_with_mismatched_x(self, key: Any) -> None:
        jwk = private_jwk(key, KID)
        jwk["x"] = public_jwk(private_key_from_seed(OTHER_SEED), KID)["x"]
        with pytest.raises(KeyringError, match="does not match"):
            load_private_jwk(jwk)

    @pytest.mark.parametrize(
        ("mutate", "match"),
        [
            (lambda j: j.update(kty="EC"), "kty=OKP"),
            (lambda j: j.update(crv="Ed448"), "crv=Ed25519"),
            (lambda j: j.pop("kid"), "kid"),
            (lambda j: j.update(kid=""), "kid"),
            (lambda j: j.update(x=j["x"] + "="), "unpadded"),
            (lambda j: j.update(x=j["x"][:-1] + chr(ord(j["x"][-1]) + 1)), "canonical"),
            (lambda j: j.update(x=j["x"][:-3]), "32"),  # 40 chars = 30 bytes
            (lambda j: j.update(d="AAAA"), "private key material"),
        ],
    )
    def test_keyring_rejects(self, key: Any, mutate: Any, match: str) -> None:
        jwk = public_jwk(key, KID)
        mutate(jwk)
        with pytest.raises(KeyringError, match=match):
            load_keyring({"keys": [jwk]})

    @pytest.mark.parametrize("doc", [[], {"keys": {}}, {"key": []}, "x"])
    def test_keyring_must_be_a_jwk_set(self, doc: Any) -> None:
        with pytest.raises(KeyringError, match="JWK Set"):
            load_keyring(doc)


class TestSignedStatement:
    def test_claims_present(self, receipt: dict, key: Any, keyring: Keyring) -> None:
        env = sign_receipt(receipt, key, KID, issuer="https://emitter.example", subject="stream-1")
        res = verify_envelope(env, keyring, as_signed_statement=True)
        assert res.ok, res.checks
        assert (res.issuer, res.subject) == ("https://emitter.example", "stream-1")
        protected = cbor2.loads(cbor2.loads(env).value[0])
        assert protected[HDR_CWT_CLAIMS] == {1: "https://emitter.example", 2: "stream-1"}
        assert _status(res, "scitt.registration") == "not_checked"

    def test_claims_missing(self, receipt: dict, key: Any, keyring: Keyring) -> None:
        res = verify_envelope(sign_receipt(receipt, key, KID), keyring, as_signed_statement=True)
        assert _codes(res) == {"SCITT_CWT_CLAIMS_MISSING"}

    def test_claims_not_checked_unless_asked(
        self, receipt: dict, key: Any, keyring: Keyring
    ) -> None:
        res = verify_envelope(sign_receipt(receipt, key, KID), keyring)
        assert res.ok
        assert not any(c.name.startswith("scitt.") for c in res.checks)

    @pytest.mark.parametrize("claims", [{1: "iss"}, {2: "sub"}, {1: 7, 2: "sub"}, {1: "", 2: "s"}])
    def test_incomplete_claims(
        self, receipt: dict, key: Any, keyring: Keyring, claims: dict
    ) -> None:
        protected = build_protected_header(KID)
        protected[HDR_CWT_CLAIMS] = claims
        env = sign_payload(protected, {}, _payload(receipt), key)
        res = verify_envelope(env, keyring, as_signed_statement=True)
        assert _codes(res) == {"SCITT_CWT_CLAIMS_MISSING"}

    def test_kid_must_be_protected(self, receipt: dict, key: Any, keyring: Keyring) -> None:
        protected = build_protected_header(KID, issuer="i", subject="s")
        del protected[HDR_KID]
        env = sign_payload(protected, {HDR_KID: KID.encode()}, _payload(receipt), key)
        res = verify_envelope(env, keyring, as_signed_statement=True)
        assert _codes(res) == {"SCITT_KID_NOT_PROTECTED"}

    def test_cwt_claims_in_both_buckets(self, receipt: dict, key: Any, keyring: Keyring) -> None:
        protected = build_protected_header(KID, issuer="i", subject="s")
        env = sign_payload(protected, {HDR_CWT_CLAIMS: {1: "i", 2: "s"}}, _payload(receipt), key)
        assert _codes(verify_envelope(env, keyring)) == {"COSE_CWT_CLAIMS_DUPLICATED"}

    @pytest.mark.parametrize("as_statement", [False, True])
    def test_attached_transparency_receipt_is_reported_not_checked(
        self, receipt: dict, key: Any, keyring: Keyring, as_statement: bool
    ) -> None:
        protected = build_protected_header(KID, issuer="i", subject="s")
        env = sign_payload(protected, {394: [b"\xd2\x84"]}, _payload(receipt), key)
        res = verify_envelope(env, keyring, as_signed_statement=as_statement)
        assert res.ok
        assert _status(res, "scitt.transparency_receipt") == "not_checked"

    def test_issuer_needs_subject(self) -> None:
        with pytest.raises(ValueError, match="both issuer and subject"):
            build_protected_header(KID, issuer="i")
