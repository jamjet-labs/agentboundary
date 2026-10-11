# AgentBoundary receipts and the SCITT agent-receipt draft

**Status:** informative. This document compares; it adds no requirement.

**What it compares:**

- AgentBoundary Action Receipts, `agentboundary/v0.1` (published) and `agentboundary/v0.2-alpha` (draft), with the optional COSE envelope described in [`v0.2-alpha.md`](v0.2-alpha.md) section 9.
- [draft-noa-scitt-ai-agent-receipt-01](https://datatracker.ietf.org/doc/draft-noa-scitt-ai-agent-receipt/), "A SCITT Profile for AI-Agent Action Receipts", T. Toraman, dated 15 August 2026, expires 16 February 2027. It is an individual Internet-Draft, not a SCITT working group document, and like every Internet-Draft it is work in progress. Revision -01 was the latest in the IETF archive when this was written (October 2026). Its payload is called `noa.receipt/0.1` below.
- The RFCs it builds on: [RFC 9943](https://www.rfc-editor.org/rfc/rfc9943) (SCITT architecture), [RFC 9942](https://www.rfc-editor.org/rfc/rfc9942) (COSE Receipts), [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052) (COSE), [RFC 9597](https://www.rfc-editor.org/rfc/rfc9597) (CWT Claims in COSE headers), [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864) (fully-specified algorithms), [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) (JCS).

Field names below are copied from the draft's section 3 figure and from the AgentBoundary JSON Schemas. Section numbers in "draft §" refer to the -01 text.

## The claim, stated exactly

AgentBoundary receipts are **aligned with the draft-noa-scitt-ai-agent-receipt-01 field set where a field has a counterpart**, and the optional AgentBoundary COSE envelope **follows the draft's envelope choices** (draft §4.1 to §4.3) for a receipt that carries no native signature.

AgentBoundary receipts are **not** `noa.receipt/0.1` receipts and do not conform to that profile. A verifier for the draft will reject them: the draft requires `spec` to be exactly `noa.receipt/0.1`, closes the object against unknown members, and requires a native `sig` member that AgentBoundary does not have. No translation between the two formats is implemented in this repository.

## 1. Field mapping

"Equivalent" means the two fields record the same thing, possibly in a different encoding. "Partial" means they overlap but one records something the other does not. "None" means there is no counterpart.

| draft-noa-01 (`noa.receipt/0.1`) | AgentBoundary | Relation | Notes |
|---|---|---|---|
| `spec` = `"noa.receipt/0.1"` | `version` = `"agentboundary/v0.1"` or `"agentboundary/v0.2-alpha"` | Equivalent role | Each side rejects the other's literal. |
| `id` (issuer-scoped, at most 128 code points) | `receipt_id` (UUID, RFC 4122) | Equivalent | AgentBoundary is stricter on syntax (a UUID); neither defines a cross-issuer namespace. |
| `ts` (when the issuer recorded the receipt) | `issued_at` | Equivalent | Both RFC 3339 and signer-chosen. The draft forbids a seconds value of 60; AgentBoundary's schema does not say. |
| `scope.tenant` | none | None | |
| `scope.chain` (chain identifier) | none | None | AgentBoundary has no chain id field; a chain is the sequence of `prior_receipt` links. The envelope's `sub` claim is supplied by the signer. |
| `agent.id` | `actor.id` | Partial | `actor` is whoever initiated the action (`human`, `system` or `agent`); the draft's `agent.id` is always the agent. |
| `agent.model` (optional, may be null) | `agent.model` (required) and `agent.model_version` | Equivalent | |
| `agent.principal` (`HUMAN`, `SERVICE`, `POLICY`, `SANDBOX_SIM`) | `actor.type` (`human`, `system`, `agent`) | Partial | Different questions: the draft records on whose behalf the action was taken; AgentBoundary records who initiated it. `HUMAN` is close to `human` and `SERVICE` to `system`. `POLICY` and `SANDBOX_SIM` have no counterpart, and `agent` has none in the draft. |
| `action.id` (tool or operation invoked) | `tool.name` | Equivalent | |
| `action.canonical` (key into the issuer's risk table) | `tool.capability` | Partial | Both are stable names for a kind of action. `tool.capability` is a dotted namespace that policies match on; the draft's key indexes a risk table. |
| `action.riskClass` (`LOW` ... `IRREVERSIBLE`) | none | None | |
| `action.paramsHash` (`sha256:<hex>` or `hmac-sha256:<hex>`) | `arguments_hash` (bare lowercase hex) | Equivalent role, different construction | AgentBoundary fixes the preimage: SHA-256 of JCS(arguments object), so two emitters given the same arguments compute the same value. The draft deliberately leaves the preimage to each producer and forbids comparing values across producers (draft §3). AgentBoundary has no keyed (HMAC) form. |
| `action.reversible`, `action.rollbackRef` | none | None | |
| none | `target.system`, `target.environment`, `target.resource_id` | AgentBoundary adds | Which system and environment the action touched. |
| `governance.mode` (`off`, `shadow`, `approvals_on`, `on`) | none | None | |
| `governance.verdict` (seven values) | `policy.decision`, `execution.status`, `refusal.verdict` | Partial | See section 2. |
| `governance.sandboxed` | none | None | `target.environment` (`prod`, `staging`, `dev`) is a different axis. |
| `governance.ruleId` (a label, not a commitment) | `policy.name` + `policy.version` (required) | Partial | Both are labels. AgentBoundary requires a named, versioned policy and checks it against a verifier's policy store at Level 4; neither format carries a content hash of the policy. |
| `governance.approval` `{by, at}` | `approval` `{approver {id, display_name?, role?}, approved_at, context?}` | Equivalent, AgentBoundary records more | The draft places no ordering rule on `approval.at` (a signer-chosen time cannot prove order). AgentBoundary's Level 4 checks approval age and approver against verifier-supplied policy context; that is a check on what the receipt claims, not proof of when approval happened. |
| `governance.compliance` `{policyHash, readSetHash, inputsHash, verdict?}` | none | None | AgentBoundary has no policy content commitment. |
| `chain.seq` | none | None | Order is carried by the links only. |
| `chain.prevHash` | `prior_receipt.receipt_hash` (v0.2-alpha) | Equivalent | AgentBoundary also carries `prior_receipt.receipt_id`. Hash encodings differ (`sha256:` prefix vs bare hex). |
| `chain.hash` | `receipt_hash` | Equivalent construction family | Both are SHA-256 over JCS of the receipt minus the hash itself. The draft also removes `sig.value`; AgentBoundary has no `sig`. |
| `sig` `{alg: "ed25519", kid, value}` (native, domain-separated) | none | AgentBoundary lacks | AgentBoundary's only signature is the optional COSE envelope (section 4). |
| none | `agent.framework`, `agent.framework_version` | AgentBoundary adds | |
| none | `execution` `{status, completed_at, error_code?, result_ref?}` | AgentBoundary adds | The draft keeps outcomes out of the base record and in separate artifacts (draft §8). |
| none | `provenance`, `completeness_score` (v0.2-alpha) | AgentBoundary adds | Per-field self-report and a score the verifier recomputes. |
| none | `refusal` `{verdict, reason_code?}` (v0.2-alpha) | AgentBoundary adds | Why a blocked action did not run. |

## 2. Verdicts

The draft has one lifecycle field, `governance.verdict`, with seven values. AgentBoundary splits the same ground across three fields: what the policy returned (`policy.decision`), what happened (`execution.status`), and, for a refused action, why it did not run (`refusal.verdict`, v0.2-alpha). AgentBoundary emits a receipt only at a terminal state (v0.1 §3.3); the draft also records non-terminal states.

| draft `governance.verdict` | Closest AgentBoundary record | Difference |
|---|---|---|
| `ALLOWED` (permitted, may still be consumed) | none | AgentBoundary does not emit a receipt for a permission that has not been used yet. |
| `BLOCKED` | `execution.status: blocked` with `refusal.verdict: deny` | |
| `DEFERRED` (no decision yet) | `execution.status: blocked` with `refusal.verdict: require-approval` | The AgentBoundary receipt is final for this attempt: approval did not come before the receipt was issued, and the action did not run. |
| `EXECUTED` (dispatched or attempted) | `execution.status: success` or `failure` | `success` claims more than `EXECUTED`: that the action had its intended effect. Neither format can prove the effect. |
| `FAILED` (failure at the governed boundary) | `execution.status: failure` | AgentBoundary's `failure` means the target system rejected or errored. |
| `ROLLED_BACK` | none | |
| `SIMULATED` | none | |
| none | `refusal.verdict: expired` | An approval, or an approval or escalation window, lapsed. |

## 3. Canonicalization and hashing

| Parameter | draft-noa-01 (§3.2) | AgentBoundary |
|---|---|---|
| Serialization | JCS (RFC 8785) | JCS (RFC 8785), mandatory since v0.1.1 |
| Numbers | Integers only; non-integers MUST be rejected | Non-integers allowed (`completeness_score` is a number in [0, 1]); serialized per RFC 8785 |
| Unicode normalization | None applied; producers MUST emit NFC; verifiers MUST NOT normalize | None applied; NFC not required; the verifier does not normalize and does not check NFC |
| Unpaired surrogates | Rejected | Rejected by `agentboundary verify` |
| Duplicate member names | Rejected at parse | Rejected by `agentboundary verify` |
| `__proto__`, `prototype`, `constructor` | Rejected at parse | Rejected by `agentboundary verify` |
| Digest | SHA-256, lowercase hex, `sha256:` prefix | SHA-256, lowercase hex, no prefix |
| Hash input | receipt minus `chain.hash` and `sig.value` | receipt minus `receipt_hash` |
| Signature domain separation | `NOA-Receipt-v0.1-sig:` tag on the native signature | Not applicable: no native signature. The COSE Sig_structure context string `Signature1` is the only separation. |

## 4. Signatures and the COSE envelope

The draft defines two presentations: a bare receipt (payload plus its native signature) and an enveloped one (a COSE_Sign1 whose payload already carries that native signature, so an enveloped receipt has two signatures). AgentBoundary has a bare receipt with no signature, and an optional COSE_Sign1 envelope that is its only signature.

| Envelope property | draft-noa-01 | AgentBoundary envelope |
|---|---|---|
| Structure | Tagged COSE_Sign1 (tag 18); untagged rejected | Same |
| Algorithm | Protected `alg` = -19 (Ed25519, RFC 9864); every other value rejected, including -8 | Same |
| Key identifier | `kid` required; SHOULD be protected; MAY be unprotected; verifier reports which bucket it used | Same. The signer puts `kid` in the protected header. An unprotected `kid` is used to find a key and is reported as such. |
| `kid` decoding | No lossy decode | `kid` must be UTF-8; anything else is refused |
| Several keys under one `kid` | Try each; accept only if exactly one verifies; report the ambiguity | Same. The chain signer check compares the fingerprint of the key that verified, so a shared `kid` cannot hide a second signer. |
| Protected header encoding | RFC 8949 §4.2.1 deterministic; others rejected | Same |
| `crit` | Unlisted unknown headers ignored; listed ones must be understood | Same |
| Payload | Attached; detached rejected | Same |
| Payload bytes | JCS(parse(payload)) == payload | Same |
| `external_aad` | Empty | Empty |
| Ed25519 key checks | Ed25519 key only; non-canonical y rejected; eight small-order keys rejected | Same |
| Signature encoding | Canonical; S reduced mod L | S reduced mod L is checked; the 64-byte signature is carried raw in COSE, so the base64 rules for `sig.value` do not apply |
| Verification equation | Pinned to cofactorless `[S]B = R + [k]A'` | Not implemented here: OpenSSL (through `cryptography`) verifies, plus the key and S checks above. A regression test rejects a signature valid only under the cofactored equation, which holds the installed library to cofactorless behaviour for that vector. |
| Content type | SHOULD be protected; no media type registered | `application/vnd.agentboundary.receipt+json`, protected. Not a registered media type. Any other value is reported, not passed. |

## 5. Signed Statements and registration

RFC 9943 §6 requires a Signed Statement's protected header to carry CWT Claims (label 15, RFC 9597) with `iss` (1) and `sub` (2), and a protected `kid` when there is no `x5t` or `x5chain`. The draft adopts that (§4.3) and maps `sub` to `scope.chain`.

`agentboundary sign --issuer ISS --subject SUB` produces that header shape, and `agentboundary verify --signed-statement` checks it. Because an AgentBoundary receipt has no `scope.chain`, `sub` is whatever the signer supplies; a stable identifier for the emitter's receipt stream fits RFC 9943's idea of a subject best.

What is **not** done:

- Nothing is submitted to, or checked against, a Transparency Service. The verifier reports registration as not checked.
- An attached Transparency Receipt (RFC 9943 unprotected header 394, the RFC 9942 object) is reported as present and not checked. Inclusion and consistency proofs are not verified.
- `iss` is reported as issuer-asserted. Binding it to the signing key is the Transparency Service's job (draft §7 item 1) and is not attempted.
- The draft's registration policy also requires the service to verify the payload's native signature (§7 item 4) and that `sub` equals `scope.chain` (§7 item 5). An AgentBoundary receipt has neither, so a service enforcing the draft's policy would refuse it.

## 6. Chains

| | draft-noa-01 (§5, §5.1) | AgentBoundary (`prior_receipt`, v0.2-alpha) |
|---|---|---|
| Link | `chain.prevHash` = previous `chain.hash` | `prior_receipt` = previous `{receipt_id, receipt_hash}` |
| Order | `chain.seq`, from 0 | Presentation order, checked through the links |
| Presentation must start at genesis | Yes | Yes (`CHAIN_NOT_FROM_GENESIS`) |
| Broken link | `chain-link-broken` | `CHAIN_LINK_BROKEN`; the link is compared with the hash the predecessor's content recomputes to, not the hash it declares |
| Repeated position | `chain-sequence-duplicate` | `CHAIN_DUPLICATE_RECEIPT_ID`, reporting whether the copies are byte-identical |
| Gap in sequence | `chain-sequence-gap` | Shows up as `CHAIN_LINK_BROKEN` (no sequence numbers) |
| Several chains mixed | `chain-scope-mismatch` | Not detectable separately (no chain id); shows up as broken links |
| Tenant split | `chain-tenant-split` | Not applicable (no tenant) |
| Signer change | `chain-key-discontinuity` (same `agent.id`, different `sig.kid`) | `CHAIN_KEY_DISCONTINUITY` (same `actor.id`, different envelope `kid`) |
| Tail truncation | Only against an authenticated checkpoint | Not detectable; there is no checkpoint object |
| Equivocation | Needs a transparency log | Not detectable |

## 7. What AgentBoundary adds

- A fixed preimage for the arguments hash, so `arguments_hash` values are comparable across emitters.
- The target system and environment.
- An execution outcome inside the receipt, kept separate from the policy decision, plus the conformance checks that tie them (for example `LEVEL_4_DENY_EXECUTED`, `LEVEL_2_REFUSAL_EXECUTED`).
- A refusal reason for blocked actions (`refusal`, v0.2-alpha), including `expired`.
- Self-reported field provenance with a recomputed completeness score.
- A conformance suite: 40 frozen v0.1 scenarios plus the v0.2-alpha scenarios in `scenarios-v0.2-alpha/`.

## 8. What AgentBoundary lacks

- A native in-payload signature. A bare AgentBoundary receipt is tamper-evident (`receipt_hash`) but not attributable; only the COSE envelope makes it attributable.
- Principal class, risk class, reversibility and rollback reference, governance mode, and a sandbox marker.
- A policy content commitment (the draft's optional `governance.compliance`).
- A chain identifier, tenant, and sequence number.
- Checkpoints, so no detection of a truncated tail.
- An Ed25519 verification equation pinned in its own code (it relies on OpenSSL, held to cofactorless behaviour by one test vector).
- Integer-only numbers and a required NFC form.
