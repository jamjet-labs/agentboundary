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
  `--issuer`. `sign` refuses a receipt or issuer outside the binding its
  private key declares. The verifier's keyring is what counts: a receipt
  signed for an issuer the keyring does not list is not `signed`.
- A protected CWT Claims header with a malformed `iss` or `sub` (wrong type,
  empty, or spelled as text keys) now fails with `COSE_CWT_CLAIMS_INVALID`
  instead of reading as "no issuer". `verify_envelope(...).ok` is False
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
