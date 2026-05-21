# Microsoft AGT — 30-scenario conformance evaluation

Evaluation date: 2026-05-21 (v0.2-alpha re-run after prior_receipt
ships). AGT version: `microsoft/agent-governance-toolkit` main as of
that date. Methodology: docs-only mapping per [`mapping.md`](mapping.md).
Each row asks: *given AGT's normative emitted artifact, can a third-party
verifier check the property the scenario tests?*

**Adapter output (2026-05-21):** v0.2-alpha by default. Every receipt
the adapter produces carries:

- A populated `provenance` block with honest tags for the four AGT gap
  fields (`policy.version`, `target.environment`, `tool.version`,
  `execution.result_ref` when synthesized) and a recomputed
  `completeness_score`.
- A `prior_receipt` link when the caller supplies the prior `entry_id`,
  built from AGT's native `previous_hash`. AGT's audit log is structurally
  a hash-chain; the adapter exposes it as AgentBoundary's chain primitive.

A verifier reading an adapter-produced receipt sees exactly which fields
came from AGT directly and which the adapter synthesized. This is the
substantive response to the W7 evaluation's NOT COVERED column: the gaps
are still real, but they're now self-reported in-receipt rather than
hidden.

| Cell | Meaning |
|---|---|
| **PASS** | AGT's documented behaviour + the receipt the adapter produces from a normative AGT artifact survives this conformance check |
| **PARTIAL** | The lifecycle is handled by AGT but the emitted artifact is missing a field AgentBoundary requires at the relevant Level |
| **DOCS-ONLY** | AGT documentation claims the property but it cannot be observed without paid access / private deployment |
| **NOT COVERED** | The feature is absent from AGT's normative schema |
| **N/A** | Positive boundary scenario whose check has no equivalent semantics in AGT (e.g., approval-window when AGT doesn't model approval-time) |

## Summary

```
PASS         15  (+5 from v0.2-alpha integration: chain check + 4 positive
                  boundary scenarios via adapter)
PARTIAL       4
DOCS-ONLY     1
NOT COVERED   8
N/A           2
              ──
TOTAL        30
```

**Net change since W7 first run:** five additional PASS rows. Three from
v0.2-alpha provenance + completeness scenarios (the adapter populates
both honestly). Two from the new chain scenarios — AGT's `previous_hash`
maps cleanly to v0.2-alpha's `prior_receipt.receipt_hash`, so when the
adapter is told the prior `entry_id`, the chain check works end-to-end.
The eight NOT COVERED rows are unchanged: those reflect AGT-side schema
gaps (no `arguments_hash`, no approver identity, no policy version, no
issued-vs-completed split) that v0.2-alpha cannot retrofit because they
require AGT-side data the audit entry doesn't carry.

## Per-scenario results

| # | Scenario | Result | Structural reason |
|---|---|---|---|
| 01 | merge-allow | **PASS** | AGT records `decision: allow`, `agent_id`, `timestamp`, `matched_rule`; sufficient for L1 + L2 |
| 02 | mutation-require-approval | **PARTIAL** | AGT records `event_type: human_review_requested` and `decision: escalate`, but the approver identity + approved_at live in workflow systems external to the audit schema. A receipt-only verifier cannot confirm WHO approved WHEN |
| 03 | refund-under-limit | **PASS** | Standard allow-with-limit-check; AGT policy engine evaluates against rule fields |
| 04 | merge-deny | **PASS** | Explicit `decision: deny` recorded |
| 05 | refund-escalate | **PASS** | `decision: escalate` recorded; resolution downstream is external |
| 06 | missing-policy-block | **PARTIAL** | AGT schema requires `decision` and `event_type` but not a structured `policy {name, version, decision}` block. A receipt missing the rule reference does NOT trigger an AGT-side schema failure analogous to AgentBoundary's |
| 07 | bad-timestamp-format | **PASS** | AGT requires ISO-8601 UTC; same constraint |
| 08 | arguments-hash-mismatch | **NOT COVERED** | AGT has no normative `arguments_hash` field. Spec Appendix A.1 shows `tool_args_hash` as an example metadata key only. A verifier with the receipt + the arguments cannot reproduce the hash to detect mutation. **This is the single largest AgentBoundary→AGT gap.** |
| 09 | receipt-hash-mismatch | **PASS** | AGT's `entry_hash` is SHA-256 of the canonicalised entry; per-entry tamper detection works. Note: AGT's canonical form is the sorted-key dict over `{entry_id, timestamp, event_type, agent_did, action, resource, data, outcome, previous_hash}` — different from AgentBoundary's but functionally equivalent |
| 10 | claim-level-3-without-hash | **DOCS-ONLY** | AGT has its own 157-test conformance suite; mapping AgentBoundary Level claims to AGT's compliance levels requires running AGT's tests against the adapter output. Out of scope for the docs-only pass |
| 11 | stale-approval | **NOT COVERED** | Approval-time is not in `AuditEntry`. AGT doesn't model approval staleness |
| 12 | unauthorized-approver | **NOT COVERED** | Approver identity is not in `AuditEntry`. A receipt verifier has no field to check against |
| 13 | replay-receipt-id | **PASS** | The Merkle chain prevents replay structurally: inserting a duplicate `entry_id` requires rebuilding all subsequent `previous_hash` links. **AGT is stronger than AgentBoundary v0.1 here** — v0.1 requires an external receipt-id set |
| 14 | completed-before-issued | **NOT COVERED** | AGT has one `timestamp` per entry. No issued-vs-completed split |
| 15 | policy-version-downgrade | **NOT COVERED** | AGT records `matched_rule` but no policy version string. A verifier cannot confirm the receipt was decided against the current policy version |
| 16 | deny-with-execution-success | **PARTIAL** | AGT records `decision` and `outcome` as separate fields, so the contradictory `decision: deny + outcome: success` state is detectable in principle — but the spec doesn't normatively require AGT runtimes to reject such entries on emit. Catch is verifier-side only |
| 17 | approval-inside-window | **N/A** | Positive boundary for an approval-window check AGT doesn't model |
| 18 | known-policy-store-passes | **N/A** | Positive boundary for a policy-version check AGT doesn't model |
| 19 | actor-human-validates | **PARTIAL** | AGT uses W3C DIDs; a human can be expressed as `did:web:...` or `did:key:...`, but there is no normative `type: agent\|human` enum. A verifier reading an AGT entry cannot disambiguate without DID-method conventions |
| 20 | numeric-arguments-validate | **NOT COVERED** | Without a normative arguments-hash + canonical-JSON rule, numeric / boolean / null handling is implementation-defined per AGT deployment |
| 21 | multiline-arguments-validate | **NOT COVERED** | Same — no normative canonical-JSON for arguments |
| 22 | missing-execution-block | **PASS** | AGT requires `outcome` as a top-level field; absence triggers schema-level rejection |
| 23 | malformed-receipt-id | **PASS** | AGT requires `entry_id` to be a UUID; non-UUID rejected at parse |
| 24 | mutated-approver-no-rehash | **NOT COVERED** | Approval block is not part of `AuditEntry`, so there is nothing to mutate in the receipt; the verifier has no field to check |
| 25 | clean-receipt-id-passes-replay | **PASS** | Merkle chain accepts a new entry with a fresh `entry_id` cleanly |
| 26 | completeness-below-threshold | **PASS** | Adapter populates `provenance` + `completeness_score`; a verifier can set a minimum and reject low-quality translations |
| 27 | completeness-score-mismatch | **PASS** | Adapter recomputes the score from its own provenance; mismatch is impossible by construction |
| 28 | honest-completeness-passes | **PASS** | Adapter-emitted receipts always include `provenance` + `completeness_score`; positive boundary is met |
| 29 | valid-chain-passes | **PASS** | When the caller supplies `prior_entry_id`, AGT's native `previous_hash` populates `prior_receipt.receipt_hash`; verifier accepts the chain link |
| 30 | broken-chain-fires | **PASS** | An adapter-produced receipt with a tampered `prior_receipt.receipt_hash` is correctly rejected by the L4 check |

## Per-conformance-level rollup (after v0.2-alpha integration)

| Level | Of N applicable | PASS | PARTIAL | NOT COVERED |
|---|---|---|---|---|
| Level 1 (Logged) | 10 | 9 | 1 | 0 |
| Level 2 (Policy-Bound) | 6 | 4 | 2 | 0 |
| Level 3 (Portable Proof) | 5 | 1 | 0 | 4 |
| Level 4 (Tamper-Evident) | 12 | 7 | 1 | 4 |

The L4 row went from 2/7 PASS to 7/12 PASS after v0.2-alpha integration —
five new L4 scenarios all PASS because the adapter populates the new
fields. The AGT-side gaps (no `arguments_hash`, no approver identity,
no policy version) still drive the remaining NOT COVERED rows.

The pattern is unchanged: AGT is **strong at Levels 1-2** (recording
that an evaluation happened and which decision came out) and **weak at
Levels 3-4** for the properties AGT's own schema can't express. v0.2-alpha
extensions (provenance, completeness, prior_receipt) compensate by making
the *adapter's translation losses* visible in the receipt itself.

## Where the gaps might matter

For each NOT COVERED gap, a one-sentence concrete attack-vector or audit-failure scenario:

- **08, 20, 21 (no normative arguments_hash):** An agent or compromised middleware mutates the arguments between policy decision and tool invocation; the audit log records "approved" and the mutated execution, but the verifier cannot prove the mutation without the original arguments side-channelled in via metadata
- **11 (no approval staleness):** An old approval from a different change-window is replayed against a new action; AGT records the escalation and the eventual allow, but no timestamp delta between approval and execution is normative
- **12 (unauthorized approver):** Workflow integration uses a manager's identity to satisfy the escalation, but the actual click was from someone else who borrowed their session; AGT's audit entry records the escalation outcome without the approver identity, so the receipt alone can't catch it
- **14 (no completed-before-issued):** A receipt is forged with timestamps that imply the action finished before policy ever evaluated it; AGT has a single timestamp per entry, so the timeline is one point, not an interval
- **15 (policy-version-downgrade):** A receipt claims it was decided by `policy:foo:rule-23` but the live policy store now has different semantics for `rule-23`; AGT's `matched_rule` is just an ID, no version

## What AGT does that AgentBoundary v0.1 does NOT

- **Merkle chain across actions** — v0.1 hashes each receipt independently; AGT's chain detects entry-deletion and entry-reordering attacks v0.1 cannot. Candidate for v0.2 §6.2.
- **Completeness score on reconstructed decisions** — AGT's `DecisionBOM.completeness_score` self-honest signal has no v0.1 equivalent. Worth borrowing for v0.2.
- **OWASP Agentic Top 10 mapping at the runtime layer** — AGT addresses capability sandboxing, rogue detection, and SRE failure modes that AgentBoundary's spec deliberately scopes out (v0.1 §1: "AgentBoundary is not a policy engine, sandbox, or runtime").
- **CloudEvents SIEM export** — production-grade observability primitive AgentBoundary leaves to the implementer.

## How to reproduce these results

1. Read the AGT spec at `https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/specs/AUDIT-COMPLIANCE-1.0.md`
2. Run the AgentBoundary suite locally: `npx agentboundary run scenarios/`
3. For each scenario, check whether the property under test can be expressed in AGT's normative schema (see [`mapping.md`](mapping.md))
4. If yes → PASS or PARTIAL; if not → NOT COVERED
5. File a PR against `jamjet-labs/agentboundary/adapters/microsoft-agt/results.md` if any row is wrong

## Right-to-respond

A summary of these findings was filed as an issue on the AGT repository on 2026-05-21. Corrections received within 7 days are incorporated; later corrections appear inline with date stamps.
