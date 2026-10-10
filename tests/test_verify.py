"""Offline verifier: ``agentboundary.verify`` and the ``verify``/``sign``/``keygen`` CLI."""

from __future__ import annotations

import copy
import json
import os
import socket
import stat
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from agentboundary.cli import main
from agentboundary.cose import (
    load_keyring,
    private_jwk,
    private_key_from_seed,
    public_jwk,
    sign_receipt,
)
from agentboundary.hashing import canonical_json, compute_receipt_hash
from agentboundary.verify import load_items, verify_items

SEED = bytes(range(32))  # TEST KEY ONLY
OTHER_SEED = bytes(range(1, 33))  # TEST KEY ONLY
KID = "test-key-1"
EXAMPLE = Path(__file__).resolve().parent.parent / "docs" / "receipts" / "github-merge.json"


def _rehash(r: dict[str, Any]) -> dict[str, Any]:
    r.pop("receipt_hash", None)
    r["receipt_hash"] = compute_receipt_hash(r)
    return r


def _chain(n: int) -> list[dict[str, Any]]:
    base = json.loads(EXAMPLE.read_text("utf-8"))
    base["version"] = "agentboundary/v0.2-alpha"
    out: list[dict[str, Any]] = []
    for i in range(n):
        r = copy.deepcopy(base)
        r["receipt_id"] = f"0192c8d0-1f2a-7c3e-bf2a-{i:012x}"
        if out:
            r["prior_receipt"] = {
                "receipt_id": out[-1]["receipt_id"],
                "receipt_hash": out[-1]["receipt_hash"],
            }
        out.append(_rehash(r))
    return out


def _codes(report: Any) -> set[str]:
    return {
        c.code
        for c in [*report.chain, *(c for r in report.receipts for c in r.checks)]
        if c.status == "fail"
    }


def _status(checks: list[Any], name: str) -> str:
    return next(c.status for c in checks if c.name == name)


@pytest.fixture
def key() -> Any:
    return private_key_from_seed(SEED)


@pytest.fixture
def keyring(key: Any) -> Any:
    return load_keyring({"keys": [public_jwk(key, KID)]})


def _bare(r: dict[str, Any], name: str = "r.json") -> tuple[str, bytes]:
    return name, json.dumps(r, indent=2).encode()


def _cose(r: dict[str, Any], key: Any, name: str = "r.cose", **kw: Any) -> tuple[str, bytes]:
    return name, sign_receipt(r, key, KID, **kw)


class TestSingleReceipt:
    def test_bare_receipt(self) -> None:
        report = verify_items(load_items([_bare(json.loads(EXAMPLE.read_text()))]), None)
        assert report.ok
        (rr,) = report.receipts
        assert rr.form == "bare"
        assert _status(rr.checks, "schema") == "pass"
        assert _status(rr.checks, "receipt_hash") == "pass"
        assert _status(rr.checks, "signature") == "not_checked"
        assert _status(rr.checks, "arguments_hash") == "not_checked"

    def test_bare_receipt_hash_mismatch(self) -> None:
        r = json.loads(EXAMPLE.read_text())
        r["policy"]["decision"] = "deny"
        report = verify_items(load_items([_bare(r)]), None)
        assert not report.ok
        assert "RECEIPT_HASH_MISMATCH" in _codes(report)

    def test_bare_receipt_schema_invalid(self) -> None:
        r = json.loads(EXAMPLE.read_text())
        del r["actor"]
        report = verify_items(load_items([_bare(_rehash(r))]), None)
        assert "SCHEMA_INVALID" in _codes(report)

    def test_bare_receipt_conformance_failure_is_reported(self) -> None:
        r = json.loads(EXAMPLE.read_text())
        r["policy"]["decision"] = "deny"  # deny with execution.status=success
        report = verify_items(load_items([_bare(_rehash(r))]), None)
        assert "LEVEL_4_DENY_EXECUTED" in _codes(report)

    def test_context_dependent_checks_are_listed_as_not_checked(self) -> None:
        report = verify_items(load_items([_bare(json.loads(EXAMPLE.read_text()))]), None)
        names = {c.name for c in report.receipts[0].checks if c.status == "not_checked"}
        assert {"LEVEL_4_SKIPPED_NO_POLICY_STORE", "LEVEL_4_SKIPPED_NO_PRIOR_RECEIPTS"} <= names

    def test_require_signature_fails_a_bare_receipt(self) -> None:
        items = load_items([_bare(json.loads(EXAMPLE.read_text()))])
        report = verify_items(items, None, require_signature=True)
        assert _codes(report) == {"SIGNATURE_REQUIRED"}

    def test_enveloped_receipt(self, key: Any, keyring: Any) -> None:
        r = json.loads(EXAMPLE.read_text())
        report = verify_items(load_items([_cose(r, key)]), keyring, require_signature=True)
        assert report.ok, [c for rr in report.receipts for c in rr.checks]
        (rr,) = report.receipts
        assert rr.form == "cose"
        assert rr.kid == KID
        assert _status(rr.checks, "payload.canonical") == "pass"

    def test_envelope_without_keyring_and_require_signature(self, key: Any) -> None:
        items = load_items([_cose(json.loads(EXAMPLE.read_text()), key)])
        assert verify_items(items, None).ok
        assert _codes(verify_items(items, None, require_signature=True)) == {"SIGNATURE_REQUIRED"}

    def test_envelope_with_bad_signature_fails(self, keyring: Any) -> None:
        r = json.loads(EXAMPLE.read_text())
        items = load_items([_cose(r, private_key_from_seed(OTHER_SEED))])
        assert _codes(verify_items(items, keyring)) == {"COSE_SIGNATURE_INVALID"}

    def test_non_canonical_payload_is_rejected(self, key: Any, keyring: Any) -> None:
        from agentboundary.cose import build_protected_header, sign_payload

        r = json.loads(EXAMPLE.read_text())
        payload = json.dumps(r, indent=1).encode()
        env = sign_payload(build_protected_header(KID), {}, payload, key)
        report = verify_items(load_items([("x.cose", env)]), keyring)
        assert _codes(report) == {"PAYLOAD_NOT_CANONICAL"}

    @pytest.mark.parametrize(
        "payload",
        [b"not json", b'{"a":1,"a":2}', b"[1,2]", b'"text"'],
    )
    def test_payload_that_is_not_a_receipt_object(
        self, key: Any, keyring: Any, payload: bytes
    ) -> None:
        from agentboundary.cose import build_protected_header, sign_payload

        env = sign_payload(build_protected_header(KID), {}, payload, key)
        report = verify_items(load_items([("x.cose", env)]), keyring)
        assert "PAYLOAD_INVALID" in _codes(report)

    def test_signed_statement_mode(self, key: Any, keyring: Any) -> None:
        r = json.loads(EXAMPLE.read_text())
        plain = load_items([_cose(r, key)])
        assert "SCITT_CWT_CLAIMS_MISSING" in _codes(
            verify_items(plain, keyring, as_signed_statement=True)
        )
        stmt = load_items([_cose(r, key, issuer="https://e.example", subject="stream-1")])
        report = verify_items(stmt, keyring, as_signed_statement=True)
        assert report.ok
        assert report.receipts[0].issuer == "https://e.example"

    def test_signed_statement_mode_fails_bare_receipts(self) -> None:
        items = load_items([_bare(json.loads(EXAMPLE.read_text()))])
        report = verify_items(items, None, as_signed_statement=True)
        assert "SCITT_NOT_A_STATEMENT" in _codes(report)


class TestLoading:
    def test_json_array_is_a_chain(self) -> None:
        items = load_items([("c.json", json.dumps(_chain(3)).encode())])
        assert [i.source for i in items] == ["c.json[0]", "c.json[1]", "c.json[2]"]

    def test_jsonl(self) -> None:
        text = "\n".join(json.dumps(r) for r in _chain(2)) + "\n"
        items = load_items([("c.jsonl", text.encode())])
        assert len(items) == 2
        assert verify_items(items, None).ok

    def test_duplicate_member_is_a_failure_not_last_wins(self) -> None:
        text = EXAMPLE.read_text().replace(
            '"version": "agentboundary/v0.1",',
            '"version": "agentboundary/v0.1", "version": "agentboundary/v0.1",',
        )
        assert text != EXAMPLE.read_text()
        report = verify_items(load_items([("d.json", text.encode())]), None)
        assert _codes(report) == {"JSON_INVALID"}

    def test_not_an_object(self) -> None:
        report = verify_items(load_items([("n.json", b"42")]), None)
        assert _codes(report) == {"JSON_INVALID"}


class TestChain:
    def test_valid_chain(self) -> None:
        report = verify_items(load_items([("c.json", json.dumps(_chain(4)).encode())]), None)
        assert report.ok
        assert _status(report.chain, "chain.genesis") == "pass"
        assert _status(report.chain, "chain.links") == "pass"
        assert _status(report.chain, "chain.unique_ids") == "pass"

    def test_deleted_middle_receipt(self) -> None:
        chain = _chain(4)
        del chain[1]
        report = verify_items(load_items([("c.json", json.dumps(chain).encode())]), None)
        assert _codes(report) == {"CHAIN_LINK_BROKEN"}

    def test_reordered(self) -> None:
        chain = _chain(3)
        chain[1], chain[2] = chain[2], chain[1]
        report = verify_items(load_items([("c.json", json.dumps(chain).encode())]), None)
        assert "CHAIN_LINK_BROKEN" in _codes(report)

    def test_link_hash_must_match_the_recomputed_predecessor_hash(self) -> None:
        """A predecessor whose content changed keeps its declared hash only by
        lying; the link is checked against what its content hashes to."""
        chain = _chain(2)
        chain[0]["target"]["resource_id"] = "pull/99"  # declared hash now stale
        report = verify_items(load_items([("c.json", json.dumps(chain).encode())]), None)
        assert {"CHAIN_LINK_BROKEN", "RECEIPT_HASH_MISMATCH"} <= _codes(report)

    def test_link_id_mismatch(self) -> None:
        chain = _chain(2)
        chain[1]["prior_receipt"]["receipt_id"] = "0192c8d0-1f2a-7c3e-bf2a-ffffffffffff"
        _rehash(chain[1])
        report = verify_items(load_items([("c.json", json.dumps(chain).encode())]), None)
        assert _codes(report) == {"CHAIN_LINK_BROKEN"}

    def test_missing_link(self) -> None:
        chain = _chain(2)
        del chain[1]["prior_receipt"]
        _rehash(chain[1])
        report = verify_items(load_items([("c.json", json.dumps(chain).encode())]), None)
        assert _codes(report) == {"CHAIN_LINK_BROKEN"}

    def test_not_from_genesis(self) -> None:
        chain = _chain(3)[1:]
        report = verify_items(load_items([("c.json", json.dumps(chain).encode())]), None)
        assert _codes(report) == {"CHAIN_NOT_FROM_GENESIS"}

    def test_duplicate_receipt_id(self) -> None:
        chain = _chain(2)
        chain.append(copy.deepcopy(chain[1]))
        report = verify_items(load_items([("c.json", json.dumps(chain).encode())]), None)
        assert "CHAIN_DUPLICATE_RECEIPT_ID" in _codes(report)
        dup = next(c for c in report.chain if c.code == "CHAIN_DUPLICATE_RECEIPT_ID")
        assert "identical" in dup.detail

    def test_unreadable_item_breaks_the_chain(self) -> None:
        chain = _chain(3)
        items = load_items(
            [
                ("a.json", json.dumps(chain[0]).encode()),
                ("b.json", b"{not json"),
                ("c.json", json.dumps(chain[2]).encode()),
            ]
        )
        assert "CHAIN_INCOMPLETE" in _codes(verify_items(items, None))

    def test_single_receipt_has_no_chain_verdict(self) -> None:
        report = verify_items(load_items([_bare(_chain(1)[0])]), None)
        assert {c.status for c in report.chain} == {"not_checked"}

    def test_enveloped_chain(self, key: Any, keyring: Any) -> None:
        items = load_items([_cose(r, key, name=f"{i}.cose") for i, r in enumerate(_chain(3))])
        report = verify_items(items, keyring, require_signature=True)
        assert report.ok
        assert _status(report.chain, "chain.signer") == "pass"

    def test_key_discontinuity(self, key: Any) -> None:
        other = private_key_from_seed(OTHER_SEED)
        ring = load_keyring({"keys": [public_jwk(key, KID), public_jwk(other, "test-key-2")]})
        chain = _chain(2)
        items = load_items(
            [
                ("0.cose", sign_receipt(chain[0], key, KID)),
                ("1.cose", sign_receipt(chain[1], other, "test-key-2")),
            ]
        )
        assert _codes(verify_items(items, ring)) == {"CHAIN_KEY_DISCONTINUITY"}

    def test_signer_axis_not_checked_for_bare_chain(self) -> None:
        report = verify_items(load_items([("c.json", json.dumps(_chain(2)).encode())]), None)
        assert _status(report.chain, "chain.signer") == "not_checked"


class TestStatements:
    def test_report_always_says_what_it_did_not_check(self) -> None:
        report = verify_items(load_items([_bare(json.loads(EXAMPLE.read_text()))]), None)
        text = " ".join(report.not_checked).lower()
        for needle in ("truncat", "equivocat", "keyring", "timestamp", "nfc", "transparency"):
            assert needle in text


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


class TestCli:
    def _keys(self, tmp_path: Path, key: Any) -> Path:
        p = tmp_path / "keys.jwks"
        p.write_text(json.dumps({"keys": [public_jwk(key, KID)]}))
        return p

    def test_verify_bare_ok(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["verify", str(EXAMPLE)])
        assert result.exit_code == 0, result.output
        assert "PASS" in result.output
        assert "Not checked" in result.output

    def test_verify_json_output(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["verify", "--json", str(EXAMPLE)])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["ok"] is True
        assert payload["receipts"][0]["form"] == "bare"
        assert payload["not_checked"]

    def test_verify_failure_exit_code(self, runner: CliRunner, tmp_path: Path) -> None:
        r = json.loads(EXAMPLE.read_text())
        r["execution"]["status"] = "blocked"
        bad = tmp_path / "bad.json"
        bad.write_text(json.dumps(r))
        result = runner.invoke(main, ["verify", str(bad)])
        assert result.exit_code == 1
        assert "RECEIPT_HASH_MISMATCH" in result.output

    def test_sign_then_verify(self, runner: CliRunner, tmp_path: Path, key: Any) -> None:
        priv = tmp_path / "k.jwk"
        priv.write_text(json.dumps(private_jwk(key, KID)))
        out = tmp_path / "r.cose"
        result = runner.invoke(main, ["sign", str(EXAMPLE), "--key", str(priv), "-o", str(out)])
        assert result.exit_code == 0, result.output
        keys = self._keys(tmp_path, key)
        result = runner.invoke(
            main, ["verify", "--keys", str(keys), "--require-signature", str(out)]
        )
        assert result.exit_code == 0, result.output

    def test_sign_signed_statement(self, runner: CliRunner, tmp_path: Path, key: Any) -> None:
        priv = tmp_path / "k.jwk"
        priv.write_text(json.dumps(private_jwk(key, KID)))
        out = tmp_path / "r.cose"
        args = ["sign", str(EXAMPLE), "--key", str(priv), "-o", str(out)]
        args += ["--issuer", "https://e.example", "--subject", "stream-1"]
        assert runner.invoke(main, args).exit_code == 0
        keys = self._keys(tmp_path, key)
        result = runner.invoke(
            main, ["verify", "--keys", str(keys), "--signed-statement", str(out)]
        )
        assert result.exit_code == 0, result.output

    def test_sign_refuses_an_invalid_receipt(
        self, runner: CliRunner, tmp_path: Path, key: Any
    ) -> None:
        r = json.loads(EXAMPLE.read_text())
        r["policy"]["decision"] = "deny"  # stale receipt_hash
        src = tmp_path / "r.json"
        src.write_text(json.dumps(r))
        priv = tmp_path / "k.jwk"
        priv.write_text(json.dumps(private_jwk(key, KID)))
        result = runner.invoke(main, ["sign", str(src), "--key", str(priv)])
        assert result.exit_code == 1
        assert not (tmp_path / "r.json.cose").exists()

    def test_sign_issuer_needs_subject(self, runner: CliRunner, tmp_path: Path, key: Any) -> None:
        priv = tmp_path / "k.jwk"
        priv.write_text(json.dumps(private_jwk(key, KID)))
        result = runner.invoke(main, ["sign", str(EXAMPLE), "--key", str(priv), "--issuer", "i"])
        assert result.exit_code == 2

    def test_bad_keyring_is_a_usage_error(self, runner: CliRunner, tmp_path: Path) -> None:
        keys = tmp_path / "keys.jwks"
        keys.write_text('{"keys": [{"kty": "EC"}]}')
        result = runner.invoke(main, ["verify", "--keys", str(keys), str(EXAMPLE)])
        assert result.exit_code == 2

    def test_keygen(self, runner: CliRunner, tmp_path: Path) -> None:
        priv, pub = tmp_path / "k.jwk", tmp_path / "keys.jwks"
        result = runner.invoke(
            main, ["keygen", "--kid", "k1", "--private", str(priv), "--public", str(pub)]
        )
        assert result.exit_code == 0, result.output
        assert stat.S_IMODE(os.stat(priv).st_mode) == 0o600
        assert load_keyring(json.loads(pub.read_text())).lookup("k1")
        out = tmp_path / "r.cose"
        assert (
            runner.invoke(main, ["sign", str(EXAMPLE), "--key", str(priv), "-o", str(out)])
        ).exit_code == 0
        result = runner.invoke(main, ["verify", "--keys", str(pub), str(out)])
        assert result.exit_code == 0, result.output

    def test_keygen_refuses_to_overwrite(self, runner: CliRunner, tmp_path: Path) -> None:
        priv, pub = tmp_path / "k.jwk", tmp_path / "keys.jwks"
        priv.write_text("keep me")
        result = runner.invoke(
            main, ["keygen", "--kid", "k1", "--private", str(priv), "--public", str(pub)]
        )
        assert result.exit_code != 0
        assert priv.read_text() == "keep me"

    def test_keygen_refuses_to_overwrite_the_public_file(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        priv, pub = tmp_path / "k.jwk", tmp_path / "keys.jwks"
        pub.write_text("keep me")
        result = runner.invoke(
            main, ["keygen", "--kid", "k1", "--private", str(priv), "--public", str(pub)]
        )
        assert result.exit_code != 0
        assert pub.read_text() == "keep me"
        assert not priv.exists()

    def test_verify_opens_no_network_connection(
        self, runner: CliRunner, tmp_path: Path, key: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def refuse(*_: Any, **__: Any) -> None:
            raise AssertionError("verify tried to open a network connection")

        monkeypatch.setattr(socket.socket, "connect", refuse)
        monkeypatch.setattr(socket, "create_connection", refuse)
        out = tmp_path / "r.cose"
        out.write_bytes(sign_receipt(json.loads(EXAMPLE.read_text()), key, KID))
        keys = self._keys(tmp_path, key)
        result = runner.invoke(main, ["verify", "--keys", str(keys), str(out)])
        assert result.exit_code == 0, result.output
        result = runner.invoke(main, ["verify", str(EXAMPLE)])
        assert result.exit_code == 0, result.output


def test_canonical_payload_helper_matches_sign() -> None:
    r = json.loads(EXAMPLE.read_text())
    assert canonical_json(r).encode() == canonical_json(json.loads(canonical_json(r))).encode()
