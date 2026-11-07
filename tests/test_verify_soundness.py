"""Soundness of ``agentboundary verify``: what a passing result may claim.

Three defects these tests pin:

* an envelope whose signature was never checked (no keys) passed;
* a signing key could vouch for any actor or issuer, with no way to bind it;
* a bare receipt edited and rehashed passed with nothing in the output saying
  that a matching ``receipt_hash`` is not evidence the receipt is unedited.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from agentboundary.cli import main
from agentboundary.cose import (
    KeyringError,
    load_keyring,
    private_jwk,
    private_key_from_seed,
    public_jwk,
    sign_receipt,
)
from agentboundary.hashing import compute_receipt_hash
from agentboundary.verify import load_items, verify_items

SEED = bytes(range(32))  # TEST KEY ONLY
ATTACKER_SEED = bytes(range(7, 39))  # TEST KEY ONLY
KID = "emitter-1"
EXAMPLE = Path(__file__).resolve().parent.parent / "docs" / "receipts" / "github-merge.json"
ACTOR = "agent:claude-code:session/789abc"  # actor.id of EXAMPLE


def _receipt() -> dict[str, Any]:
    return dict(json.loads(EXAMPLE.read_text("utf-8")))


def _edited_and_rehashed() -> dict[str, Any]:
    """What someone with write access to the receipt store can always produce."""
    r = _receipt()
    r["target"]["resource_id"] = "pull/999"
    r.pop("receipt_hash")
    r["receipt_hash"] = compute_receipt_hash(r)
    return r


def _codes(report: Any) -> set[str]:
    return {
        c.code
        for c in [*report.chain, *(c for r in report.receipts for c in r.checks)]
        if c.status == "fail"
    }


def _established(report: Any) -> dict[str, bool]:
    return {a.name: a.met for a in report.established()}


@pytest.fixture
def key() -> Any:
    return private_key_from_seed(SEED)


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


class TestUncheckedSignatureIsNotOk:
    def test_flipped_signature_byte_without_keys(self, key: Any) -> None:
        env = bytearray(sign_receipt(_receipt(), key, KID))
        env[-40] ^= 0x01  # inside R, so the encoding check alone cannot see it
        report = verify_items(load_items([("r.cose", bytes(env))]), None)
        assert not report.ok
        assert _codes(report) == {"SIGNATURE_REQUIRED"}

    def test_edited_receipt_resigned_by_another_key_without_keys(self) -> None:
        forged = sign_receipt(_edited_and_rehashed(), private_key_from_seed(ATTACKER_SEED), KID)
        report = verify_items(load_items([("r.cose", forged)]), None)
        assert not report.ok
        assert "SIGNATURE_REQUIRED" in _codes(report)
        assert not _established(report)["signed"]

    def test_cli_exits_nonzero_and_says_to_pass_keys(
        self, runner: CliRunner, tmp_path: Path, key: Any
    ) -> None:
        env = bytearray(sign_receipt(_receipt(), key, KID))
        env[-40] ^= 0x01
        path = tmp_path / "r.cose"
        path.write_bytes(bytes(env))
        result = runner.invoke(main, ["verify", str(path)])
        assert result.exit_code == 1, result.output
        assert "SIGNATURE_REQUIRED" in result.output
        assert "--keys" in result.output


class TestEstablishedIsReported:
    def test_bare_edited_receipt_passes_hash_only(self) -> None:
        items = load_items([("r.json", json.dumps(_edited_and_rehashed()).encode())])
        report = verify_items(items, None)
        assert report.ok  # hash-only is all that was asked for
        assert _established(report) == {"hash": True, "signed": False, "chained": False}
        hash_detail = next(a.detail for a in report.established() if a.name == "hash")
        assert "recompute" in hash_detail
        assert "not evidence" in hash_detail

    def test_cli_text_says_what_was_and_was_not_established(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        path = tmp_path / "r.json"
        path.write_text(json.dumps(_edited_and_rehashed()))
        result = runner.invoke(main, ["verify", str(path)])
        assert result.exit_code == 0, result.output
        out = result.output
        assert "Established" in out
        assert "hash      yes" in out
        assert "signed    no" in out
        assert "chained   no" in out
        assert "Tamper evidence: not established" in out

    def test_cli_json_carries_established_and_required(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        path = tmp_path / "r.json"
        path.write_text(json.dumps(_edited_and_rehashed()))
        result = runner.invoke(main, ["verify", "--json", str(path)])
        payload = json.loads(result.output)
        assert payload["required"] == ["hash"]
        assert payload["established"]["hash"]["met"] is True
        assert payload["established"]["signed"]["met"] is False
        assert payload["established"]["chained"]["met"] is False
        assert payload["receipts"][0]["established"] == {"hash": True, "signed": False}

    def test_require_signed_fails_a_bare_receipt(self, runner: CliRunner, tmp_path: Path) -> None:
        path = tmp_path / "r.json"
        path.write_text(json.dumps(_edited_and_rehashed()))
        result = runner.invoke(main, ["verify", "--require", "signed", str(path)])
        assert result.exit_code == 1, result.output
        assert "SIGNATURE_REQUIRED" in result.output

    def test_require_chained_fails_a_single_receipt(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        path = tmp_path / "r.json"
        path.write_text(json.dumps(_receipt()))
        result = runner.invoke(main, ["verify", "--require", "chained", str(path)])
        assert result.exit_code == 1, result.output
        assert "CHAIN_REQUIRED" in result.output

    def test_require_chained_passes_an_unbroken_chain(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        base = _receipt()
        base["version"] = "agentboundary/v0.2-alpha"
        chain: list[dict[str, Any]] = []
        for i in range(3):
            r = copy.deepcopy(base)
            r["receipt_id"] = f"0192c8d0-1f2a-7c3e-bf2a-{i:012x}"
            if chain:
                prev = chain[-1]
                r["prior_receipt"] = {
                    "receipt_id": prev["receipt_id"],
                    "receipt_hash": prev["receipt_hash"],
                }
            r.pop("receipt_hash")
            r["receipt_hash"] = compute_receipt_hash(r)
            chain.append(r)
        path = tmp_path / "c.json"
        path.write_text(json.dumps(chain))
        result = runner.invoke(main, ["verify", "--json", "--require", "chained", str(path)])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["established"]["chained"]["met"] is True
        assert payload["established"]["signed"]["met"] is False

    def test_unknown_requirement_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="unknown requirement"):
            verify_items([], None, require=("notarized",))


class TestKeyBinding:
    def _ring(self, key: Any, **binding: Any) -> Any:
        # Built by hand rather than through public_jwk(..., actor_ids=...) so
        # the same test runs, and fails, against a verifier that ignores
        # the binding members.
        jwk = public_jwk(key, KID)
        jwk.update(binding)
        return load_keyring({"keys": [jwk]})

    def _env(self, key: Any, **kw: Any) -> list[Any]:
        return load_items([("r.cose", sign_receipt(_receipt(), key, KID, **kw))])

    def test_key_bound_to_another_actor_cannot_vouch(self, key: Any) -> None:
        ring = self._ring(key, actor_ids=["agent:some-other-agent"])
        report = verify_items(self._env(key), ring)
        assert _codes(report) == {"SIGNER_ACTOR_MISMATCH"}
        assert not _established(report)["signed"]

    def test_key_bound_to_the_actor_establishes_signed(self, key: Any) -> None:
        report = verify_items(self._env(key), self._ring(key, actor_ids=[ACTOR]))
        assert report.ok, _codes(report)
        assert _established(report)["signed"]

    def test_wildcard_binding_is_explicit_and_accepted(self, key: Any) -> None:
        report = verify_items(self._env(key), self._ring(key, actor_ids=["*"]))
        assert report.ok
        assert _established(report)["signed"]
        detail = next(
            c.detail for r in report.receipts for c in r.checks if c.name == "signer.actor"
        )
        assert "any actor" in detail

    def test_unbound_key_verifies_but_does_not_establish_signed(self, key: Any) -> None:
        report = verify_items(self._env(key), self._ring(key))
        assert not report.ok  # a keyring means signed is required
        assert _codes(report) == {"SIGNER_UNBOUND"}
        assert not _established(report)["signed"]
        statuses = {c.name: c.status for r in report.receipts for c in r.checks}
        assert statuses["signer.actor"] == "not_checked"

    def test_unbound_key_fails_when_signed_is_required(self, key: Any) -> None:
        report = verify_items(self._env(key), self._ring(key), require=("signed",))
        assert _codes(report) == {"SIGNER_UNBOUND"}

    def test_issuer_outside_the_binding_fails(self, key: Any) -> None:
        ring = self._ring(key, actor_ids=[ACTOR], issuers=["https://emitter.example"])
        items = self._env(key, issuer="https://evil.example", subject="s")
        assert _codes(verify_items(items, ring)) == {"SIGNER_ISSUER_MISMATCH"}

    def test_issuer_inside_the_binding_passes(self, key: Any) -> None:
        ring = self._ring(key, actor_ids=[ACTOR], issuers=["https://emitter.example"])
        items = self._env(key, issuer="https://emitter.example", subject="s")
        report = verify_items(items, ring, require=("signed",))
        assert report.ok, _codes(report)
        assert _established(report)["signed"]

    def test_issuer_with_no_issuer_binding_is_not_signed(self, key: Any) -> None:
        ring = self._ring(key, actor_ids=[ACTOR])
        items = self._env(key, issuer="https://emitter.example", subject="s")
        assert _codes(verify_items(items, ring, require=("signed",))) == {"SIGNER_UNBOUND"}

    def test_actor_binding_applies_in_a_chain(self, key: Any) -> None:
        """Signer continuity alone accepts one key signing a forged actor's
        whole history; the binding does not."""
        other = _receipt()
        other["actor"]["id"] = "agent:impersonated"
        other.pop("receipt_hash")
        other["receipt_hash"] = compute_receipt_hash(other)
        ring = self._ring(key, actor_ids=[ACTOR])
        items = load_items([("o.cose", sign_receipt(other, key, KID))])
        assert "SIGNER_ACTOR_MISMATCH" in _codes(verify_items(items, ring))

    @pytest.mark.parametrize(
        "binding",
        [
            {"actor_ids": []},
            {"actor_ids": "agent:a"},
            {"actor_ids": ["agent:a", ""]},
            {"actor_ids": ["agent:a", 7]},
            {"actor_ids": ["*", "agent:a"]},
            {"actor_ids": ["agent:a", "agent:a"]},
            {"issuers": []},
            {"issuers": [None]},
        ],
    )
    def test_malformed_binding_is_a_keyring_error(self, key: Any, binding: Any) -> None:
        jwk = public_jwk(key, KID)
        jwk.update(binding)
        with pytest.raises(KeyringError):
            load_keyring({"keys": [jwk]})


class TestCliBinding:
    def _keygen(self, runner: CliRunner, tmp_path: Path, *extra: str) -> tuple[Path, Path, Any]:
        priv, pub = tmp_path / "k.jwk", tmp_path / "keys.jwks"
        args = ["keygen", "--kid", KID, "--private", str(priv), "--public", str(pub), *extra]
        return priv, pub, runner.invoke(main, args)

    def test_keygen_needs_a_binding(self, runner: CliRunner, tmp_path: Path) -> None:
        priv, pub, result = self._keygen(runner, tmp_path)
        assert result.exit_code == 2
        assert "--actor" in result.output
        assert not priv.exists()
        assert not pub.exists()

    def test_keygen_actor_sign_verify(self, runner: CliRunner, tmp_path: Path) -> None:
        priv, pub, result = self._keygen(runner, tmp_path, "--actor", ACTOR)
        assert result.exit_code == 0, result.output
        assert json.loads(pub.read_text())["keys"][0]["actor_ids"] == [ACTOR]
        out = tmp_path / "r.cose"
        signed = runner.invoke(main, ["sign", str(EXAMPLE), "--key", str(priv), "-o", str(out)])
        assert signed.exit_code == 0, signed.output
        result = runner.invoke(main, ["verify", "--keys", str(pub), str(out)])
        assert result.exit_code == 0, result.output
        assert "signed    yes" in result.output

    def test_sign_refuses_an_actor_the_key_is_not_bound_to(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        priv, _pub, result = self._keygen(runner, tmp_path, "--actor", "agent:someone-else")
        assert result.exit_code == 0, result.output
        out = tmp_path / "r.cose"
        signed = runner.invoke(main, ["sign", str(EXAMPLE), "--key", str(priv), "-o", str(out)])
        assert signed.exit_code == 1
        assert "actor" in signed.output
        assert not out.exists()

    def test_sign_refuses_an_issuer_the_key_is_not_bound_to(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        priv, _pub, result = self._keygen(
            runner, tmp_path, "--actor", ACTOR, "--issuer", "https://emitter.example"
        )
        assert result.exit_code == 0, result.output
        out = tmp_path / "r.cose"
        args = ["sign", str(EXAMPLE), "--key", str(priv), "-o", str(out)]
        args += ["--issuer", "https://evil.example", "--subject", "s"]
        signed = runner.invoke(main, args)
        assert signed.exit_code == 1
        assert not out.exists()

    def test_verify_with_unbound_keys_fails(
        self, runner: CliRunner, tmp_path: Path, key: Any
    ) -> None:
        pub = tmp_path / "keys.jwks"
        pub.write_text(json.dumps({"keys": [public_jwk(key, KID)]}))
        priv = tmp_path / "k.jwk"  # bound, so sign accepts it; the keyring is not
        priv.write_text(json.dumps(private_jwk(key, KID, actor_ids=[ACTOR])))
        out = tmp_path / "r.cose"
        assert (
            runner.invoke(main, ["sign", str(EXAMPLE), "--key", str(priv), "-o", str(out)])
        ).exit_code == 0
        result = runner.invoke(main, ["verify", "--keys", str(pub), str(out)])
        assert result.exit_code == 1, result.output
        assert "SIGNER_UNBOUND" in result.output


class TestReviewFindings:
    """Second-review findings on the first version of this change."""

    def test_verify_envelope_without_keys_is_not_ok(self, key: Any) -> None:
        from agentboundary.cose import verify_envelope

        env = bytearray(sign_receipt(_receipt(), key, KID))
        env[-40] ^= 0x01
        assert not verify_envelope(bytes(env), None).ok
        assert not verify_envelope(sign_receipt(_receipt(), key, KID), None).ok

    def test_malformed_iss_cannot_skip_the_issuer_binding(self, key: Any) -> None:
        from agentboundary.cose import (
            HDR_CWT_CLAIMS,
            build_protected_header,
            sign_payload,
        )
        from agentboundary.hashing import canonical_json

        jwk = public_jwk(key, KID)
        jwk.update(actor_ids=[ACTOR], issuers=["issuer-a"])
        ring = load_keyring({"keys": [jwk]})
        protected = build_protected_header(KID)
        protected[HDR_CWT_CLAIMS] = {1: b"issuer-b", 2: "s"}
        env = sign_payload(protected, {}, canonical_json(_receipt()).encode(), key)
        report = verify_items(load_items([("r.cose", env)]), ring, require=("signed",))
        assert not report.ok
        assert "COSE_CWT_CLAIMS_INVALID" in _codes(report)
        assert not _established(report)["signed"]

    def test_unprotected_kid_does_not_establish_signed(self, key: Any) -> None:
        from agentboundary.cose import HDR_KID, build_protected_header, sign_payload
        from agentboundary.hashing import canonical_json

        jwk = public_jwk(key, KID)
        jwk.update(actor_ids=[ACTOR])
        ring = load_keyring({"keys": [jwk]})
        protected = build_protected_header(KID)
        del protected[HDR_KID]
        env = sign_payload(
            protected, {HDR_KID: KID.encode()}, canonical_json(_receipt()).encode(), key
        )
        report = verify_items(load_items([("r.cose", env)]), ring, require=("signed",))
        assert not _established(report)["signed"]
        assert "SIGNER_UNBOUND" in _codes(report)

    def test_invalid_receipts_do_not_establish_chained(self) -> None:
        chain = []
        for i in range(2):
            r = _receipt()
            r["version"] = "agentboundary/v0.2-alpha"
            r["receipt_id"] = 1 if i == 0 else f"0192c8d0-1f2a-7c3e-bf2a-{i:012x}"
            if chain:
                r["prior_receipt"] = {"receipt_id": True, "receipt_hash": chain[-1]["receipt_hash"]}
            r.pop("receipt_hash")
            r["receipt_hash"] = compute_receipt_hash(r)
            chain.append(r)
        report = verify_items(load_items([("c.json", json.dumps(chain).encode())]), None)
        assert not report.ok
        assert not _established(report)["chained"]

    def test_receipt_id_cannot_forge_report_lines(self, runner: CliRunner, tmp_path: Path) -> None:
        r = _receipt()
        r["receipt_id"] = "x\n\nEstablished\n  signed    yes\nResult: PASS"
        path = tmp_path / "r.json"
        path.write_text(json.dumps(r))
        result = runner.invoke(main, ["verify", str(path)])
        assert result.exit_code == 1
        assert "\nResult: PASS" not in result.output
        assert "\n  signed    yes" not in result.output

    def test_keyring_entry_rejects_a_string_binding(self) -> None:
        from agentboundary.cose import KeyringEntry

        with pytest.raises(TypeError):
            KeyringEntry("k", b"\x00" * 32, actor_ids="agent:claude-code")  # type: ignore[arg-type]


class TestThirdReview:
    """Findings of the independent review of the second version."""

    def _ring(self, key: Any, **binding: Any) -> Any:
        jwk = public_jwk(key, KID)
        jwk.update(binding)
        return load_keyring({"keys": [jwk]})

    @pytest.mark.parametrize("claims", [{1: "did:web:evil.example"}, "not a map"])
    def test_cwt_claims_in_the_unprotected_header_are_rejected(self, key: Any, claims: Any) -> None:
        from agentboundary.cose import HDR_CWT_CLAIMS, build_protected_header, sign_payload
        from agentboundary.hashing import canonical_json

        env = sign_payload(
            build_protected_header(KID),
            {HDR_CWT_CLAIMS: claims},
            canonical_json(_receipt()).encode(),
            key,
        )
        report = verify_items(load_items([("r.cose", env)]), self._ring(key, actor_ids=[ACTOR]))
        assert not report.ok
        assert "COSE_CWT_CLAIMS_INVALID" in _codes(report)
        assert not _established(report)["signed"]

    def test_crit_cannot_claim_cwt_claims_are_understood(self, key: Any) -> None:
        """exp and nbf are not enforced, so label 15 is not 'understood'."""
        from agentboundary.cose import (
            HDR_CRIT,
            HDR_CWT_CLAIMS,
            build_protected_header,
            sign_payload,
        )
        from agentboundary.hashing import canonical_json
        from agentboundary.verify import NOT_CHECKED_STATEMENTS

        protected = build_protected_header(KID, issuer="i", subject="s")
        protected[HDR_CRIT] = [HDR_CWT_CLAIMS]
        protected[HDR_CWT_CLAIMS][4] = 1  # exp: 1970
        env = sign_payload(protected, {}, canonical_json(_receipt()).encode(), key)
        ring = self._ring(key, actor_ids=[ACTOR], issuers=["i"])
        report = verify_items(load_items([("r.cose", env)]), ring)
        assert "COSE_CRIT_UNSUPPORTED" in _codes(report)
        assert "exp" in " ".join(NOT_CHECKED_STATEMENTS)

    def test_signed_is_not_established_beside_a_failure(self, key: Any) -> None:
        env = sign_receipt(_receipt(), key, KID)  # no CWT claims
        ring = self._ring(key, actor_ids=[ACTOR])
        report = verify_items(load_items([("r.cose", env)]), ring, as_signed_statement=True)
        assert "SCITT_CWT_CLAIMS_MISSING" in _codes(report)
        assert not _established(report)["signed"]

    def test_library_keyring_requires_signed(self, key: Any) -> None:
        """Passing keys means the caller wants signed receipts, as in the CLI."""
        env = sign_receipt(_receipt(), key, KID)
        report = verify_items(load_items([("r.cose", env)]), self._ring(key))
        assert not report.ok
        assert "SIGNER_UNBOUND" in _codes(report)
        assert report.required == ("hash", "signed")


class TestThirdReviewCli:
    def _priv(self, tmp_path: Path, key: Any, **binding: Any) -> Path:
        jwk = private_jwk(key, KID)
        jwk.update(binding)
        path = tmp_path / "k.jwk"
        path.write_text(json.dumps(jwk))
        return path

    def test_sign_refuses_an_issuer_when_the_key_lists_none(
        self, runner: CliRunner, tmp_path: Path, key: Any
    ) -> None:
        priv = self._priv(tmp_path, key, actor_ids=[ACTOR])
        out = tmp_path / "r.cose"
        args = ["sign", str(EXAMPLE), "--key", str(priv), "-o", str(out)]
        result = runner.invoke(main, [*args, "--issuer", "https://e.example", "--subject", "s"])
        assert result.exit_code == 1
        assert not out.exists()

    def test_sign_refuses_a_key_bound_to_no_actor(
        self, runner: CliRunner, tmp_path: Path, key: Any
    ) -> None:
        priv = self._priv(tmp_path, key)
        out = tmp_path / "r.cose"
        result = runner.invoke(main, ["sign", str(EXAMPLE), "--key", str(priv), "-o", str(out)])
        assert result.exit_code == 1
        assert not out.exists()

    @pytest.mark.parametrize("flag", ["--actor", "--issuer"])
    def test_keygen_refuses_a_star_value(
        self, runner: CliRunner, tmp_path: Path, flag: str
    ) -> None:
        priv, pub = tmp_path / "k.jwk", tmp_path / "keys.jwks"
        args = ["keygen", "--kid", KID, "--private", str(priv), "--public", str(pub)]
        extra = ["--actor", ACTOR] if flag == "--issuer" else []
        result = runner.invoke(main, [*args, *extra, flag, "*"])
        assert result.exit_code == 2
        assert not priv.exists()

    def test_keygen_any_issuer(self, runner: CliRunner, tmp_path: Path) -> None:
        priv, pub = tmp_path / "k.jwk", tmp_path / "keys.jwks"
        args = ["keygen", "--kid", KID, "--private", str(priv), "--public", str(pub)]
        result = runner.invoke(main, [*args, "--actor", ACTOR, "--any-issuer"])
        assert result.exit_code == 0, result.output
        assert json.loads(pub.read_text())["keys"][0]["issuers"] == ["*"]
