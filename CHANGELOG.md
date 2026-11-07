# Changelog

Notable changes to the `agentboundary` package, the spec documents and the
conformance suite. Versions follow the git tags (`v0.2.0-alpha.1`, ...).

## Unreleased

### Offline verifier (`agentboundary verify`, `sign`, `keygen`)

- An envelope whose signature was not verified no longer passes. Without
  `--keys`, a COSE envelope now fails with `SIGNATURE_REQUIRED`; before, a
  tampered envelope reported `PASS` and exit 0.
- Signing keys can be bound to the identities they sign for. A JWK in the
  keyring may list `actor_ids` (receipt `actor.id` values) and `issuers`
  (CWT `iss` values); a receipt outside the binding fails with
  `SIGNER_ACTOR_MISMATCH` or `SIGNER_ISSUER_MISMATCH`.
- `keygen` now requires `--actor ID` (repeatable) or `--any-actor`, and takes
  `--issuer ID` or `--any-issuer`; a literal `*` is refused. `sign` refuses
  a receipt or issuer the private key is not bound to, including a key that
  declares no binding.
- `verify_items(items, keyring)` with a keyring now requires `signed`, as
  `verify --keys` does.
- A protected CWT Claims header with a malformed `iss` or `sub` (wrong type,
  empty, or spelled as text keys) now fails with `COSE_CWT_CLAIMS_INVALID`
  instead of reading as "no issuer". So does a CWT Claims header in the
  unprotected header, which the signature does not cover. `crit` may no
  longer list the CWT Claims header, since `exp` and `nbf` are not enforced. `verify_envelope(...).ok` is False
  unless the signature verified. A key selected by an unprotected `kid` does
  not count as bound. Text from the input is escaped in the report so it
  cannot add lines to it.
- The report says which of `hash`, `signed` and `chained` the input
  established, in text and in `--json` (`established`, `required`). A
  matching `receipt_hash` is reported as hash consistency only, not as
  evidence the receipt is unedited.
- New `--require hash|signed|chained` (repeatable). `--keys` and
  `--require-signature` imply `--require signed`, which now also needs the
  key to be bound to the receipt's actor (`SIGNER_UNBOUND`). `--require
  chained` fails with `CHAIN_REQUIRED` unless the receipts form one verified
  chain.
- Spec text: v0.1 section 4.12 and threat model T-05 no longer say a matching
  `receipt_hash` shows a receipt is untampered. v0.2-alpha sections 9 and 10
  describe key binding and the three properties.

#### Upgrading an existing keyring

A keyring made before this change has no bindings, so `verify --keys` now
fails its receipts with `SIGNER_UNBOUND`. Add the identities each key signs
for to its JWK in the JWK Set, for example:

```json
{"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "emitter-1", "x": "...",
           "actor_ids": ["agent:claude-code:session/789abc"],
           "issuers": ["https://emitter.example"]}]}
```

`issuers` is needed only if the envelopes carry a CWT `iss`. Use `["*"]` for
a key trusted for any actor or issuer, such as a gateway's. To keep using
`sign` with an existing private JWK, add the same members to it, or make a
new key with `keygen --actor ...`.

### CI

- The 45 adapter smoke tests (`adapters/*/test_adapter.py`) now run in CI,
  in a job of their own. They need nothing beyond the package itself. Each
  adapter runs in its own pytest process because every adapter's module is
  named `adapter`. The job fails if an adapter directory has no tests.
