# Cloudflare HITL Agents — 30-scenario conformance evaluation

Evaluation date: 2026-05-21. Cloudflare Agents SDK version: latest published as of that date (`@cloudflare/agents` v0.1.x, AI SDK v5 compatible). Methodology: docs-only mapping per [`mapping.md`](mapping.md). Each row asks: *given Cloudflare's recommended normative artifact (the `approval_audit` row), can a third-party verifier check the property the scenario tests?*

Note: "Cloudflare's normative artifact" is the **6-column `approval_audit` table** the docs recommend. The actual `needsApproval` SDK plumbing carries more in memory (tool name, arguments, agent state) but does not prescribe persistence of any of it. This evaluation is therefore strict — it grades what survives to a third-party verifier consulting the audit log alone.

| Cell | Meaning |
|---|---|
| **PASS** | Cloudflare's recommended audit row carries the field; adapter-translated receipt survives this check |
| **PARTIAL** | Lifecycle is supported by the SDK but the audit row is missing structure AgentBoundary requires |
| **DOCS-ONLY** | Docs describe the property but it cannot be verified without paid runtime access |
| **NOT COVERED** | Field has no Cloudflare-side equivalent; adapter synthesizes or omits |
| **N/A** | Positive boundary scenario whose check semantics don't apply to Cloudflare |

## Summary

```
PASS          4
PARTIAL       6
DOCS-ONLY     1
NOT COVERED  17
N/A           2
              ──
TOTAL        30
```

The 17 NOT COVERED count reflects the depth of the artifact gap: Cloudflare HITL gives you a workflow primitive (`needsApproval` + durable execution) and an audit-table suggestion, not an emitted-artifact format. Most AgentBoundary checks operate on fields Cloudflare's normative row simply doesn't carry.

## Per-scenario results

| # | Scenario | Result | Structural reason |
|---|---|---|---|
| 01 | merge-allow | **PARTIAL** | `decision: approved` maps to `policy.decision: allow`, but the surrounding context (tool name, target, args) is not in the audit row — must be threaded via `tool_call_context` |
| 02 | mutation-require-approval | **PASS** | The `needsApproval` flow IS exactly this pattern. `approval_audit` captures `decided_by` + `decided_at` + `reason` |
| 03 | refund-under-limit | **PARTIAL** | Same shape as 01 — context required externally |
| 04 | merge-deny | **PASS** | `decision: rejected` maps to `policy.decision: deny` cleanly |
| 05 | refund-escalate | **NOT COVERED** | Cloudflare's enum is 2-value (`approved` | `rejected`); there is no `escalate` decision. A receipt translating "agent escalated" loses fidelity |
| 06 | missing-policy-block | **NOT COVERED** | Cloudflare's row has no `policy` block at all; absence isn't a schema failure on Cloudflare's side |
| 07 | bad-timestamp-format | **PASS** | `decided_at INTEGER` (millis since epoch) is well-typed; adapter formats to RFC 3339 |
| 08 | arguments-hash-mismatch | **NOT COVERED** | Audit row carries no arguments and no hash. Mutation between decision and execute is structurally undetectable from the row |
| 09 | receipt-hash-mismatch | **NOT COVERED** | No receipt-level hash. Database-immutability convention only |
| 10 | claim-level-3-without-hash | **NOT COVERED** | Cloudflare doesn't claim Level 3; there's no hash to check |
| 11 | stale-approval | **NOT COVERED** | `decided_at` is captured but there's no policy-side `approval_max_age_seconds`; staleness is undetectable |
| 12 | unauthorized-approver | **PARTIAL** | `decided_by TEXT` records who approved, but there's no policy-side `approvers` list to check against. A verifier with separate access to the policy can correlate; from the row alone, no |
| 13 | replay-receipt-id | **NOT COVERED** | `id INTEGER AUTOINCREMENT` is local; no global receipt_id; no replay primitive |
| 14 | completed-before-issued | **NOT COVERED** | One timestamp per row. No issued-vs-completed split |
| 15 | policy-version-downgrade | **NOT COVERED** | No policy version field |
| 16 | deny-with-execution-success | **NOT COVERED** | Row records the decision but not the execution outcome. No way to detect a `rejected → executed-anyway` inconsistency from the row |
| 17 | approval-inside-window | **N/A** | Positive boundary for stale-approval; Cloudflare has no window concept |
| 18 | known-policy-store-passes | **N/A** | Positive boundary for policy-store; Cloudflare has no policy versioning |
| 19 | actor-human-validates | **PARTIAL** | `decided_by TEXT` can be a human identifier, but no `type: agent\|human` enum is normative |
| 20 | numeric-arguments-validate | **NOT COVERED** | No arguments hash; canonical-JSON handling for numerics not specified |
| 21 | multiline-arguments-validate | **NOT COVERED** | Same — no normative arguments handling |
| 22 | missing-execution-block | **NOT COVERED** | Audit row has no execution block at all |
| 23 | malformed-receipt-id | **PARTIAL** | `id INTEGER` is well-typed; UUID format is an AgentBoundary spec choice. Adapter generates UUIDs at translation |
| 24 | mutated-approver-no-rehash | **NOT COVERED** | No hash to tamper with |
| 25 | clean-receipt-id-passes-replay | **NOT COVERED** | No replay primitive |
| 26 | completeness-below-threshold | **PASS** | Adapter emits provenance + completeness_score; threshold check works against adapter output |
| 27 | completeness-score-mismatch | **PASS** | Adapter recomputes the score from its own provenance; mismatch is impossible by construction |
| 28 | honest-completeness-passes | **PARTIAL** | Adapter populates provenance honestly, but Cloudflare's normative row is so thin that most paths land at `synthesized`; the typical score is low (~0.4-0.6) |
| 29 | valid-chain-passes | **NOT COVERED** | No Cloudflare-side chain primitive. Adapter could maintain `prior_receipt` externally but it's not derivable from the row |
| 30 | broken-chain-fires | **DOCS-ONLY** | If the adapter does maintain external `prior_receipt` state, the L4 broken-chain check fires on tamper. But this is adapter-side discipline, not Cloudflare-side guarantee |

## Per-conformance-level rollup

| Level | Of N applicable | PASS | PARTIAL | NOT COVERED |
|---|---|---|---|---|
| Level 1 (Logged) | 10 | 3 | 4 | 2 |
| Level 2 (Policy-Bound) | 6 | 1 | 2 | 3 |
| Level 3 (Portable Proof) | 5 | 0 | 0 | 5 |
| Level 4 (Tamper-Evident) | 12 | 2 | 1 | 8 |

The pattern: Cloudflare's HITL passes Level 2 mostly because the **decision itself is recorded** (the central thing it does). It misses Level 3 entirely because there's no hash, no normative argument capture, no policy version. Level 4 is mostly NOT COVERED because Cloudflare relies on database-immutability conventions instead of cryptographic tamper-evidence.

## Where the gaps might matter (concrete attack/audit scenarios)

- **08, 20, 21 (no normative arguments hashing):** An agent or middleware mutates the tool arguments between the `needsApproval` decision and the `execute` call. Cloudflare's audit row records the approval and the workflow continues; the mutated execution is undetectable from the audit log.
- **15 (no policy versioning):** A team updates their `needsApproval` predicate logic. Existing audit rows reference the old semantics; rows emitted after the change reference the new semantics. There is no version flag separating them.
- **16 (no execution outcome correlation):** The audit row records that a tool was approved. Whether the tool actually executed, succeeded, or failed lives in a separate (developer-defined) system. A forger who never invokes the tool but inserts an audit row showing approval cannot be caught from the row alone.
- **13 (no replay primitive):** Audit rows can be replayed (re-inserted with new `id`) and downstream consumers correlating by `decided_at` cannot distinguish the duplicate.

## What Cloudflare does that AgentBoundary does NOT

- **`workflow_id`** — durable-execution context. AgentBoundary's receipt is single-action; multi-step orchestration is out of scope.
- **Multi-day approval windows** via `waitForApproval()`. AgentBoundary doesn't address durability.
- **Notification integration** (Knock and equivalents). External notification routing is solved at the Cloudflare layer.

These are excellent primitives for *running* an HITL workflow. They are orthogonal to the question AgentBoundary answers (the *artifact*).

## How to reproduce these results

1. Read `https://developers.cloudflare.com/agents/concepts/human-in-the-loop/` and `/guides/human-in-the-loop/`
2. Read the recommended `approval_audit` schema in the guide
3. For each AgentBoundary scenario, check whether the property under test can be expressed in the 6-column audit row + adapter-threaded context
4. If yes → PASS or PARTIAL; if not → NOT COVERED
5. File a PR against `jamjet-labs/agentboundary/adapters/cloudflare-hitl/results.md` if any row is wrong

## Right-to-respond

A summary of these findings will be filed against `cloudflare/agents` before the W12 comparative report publishes. Corrections received within 7 days are incorporated; later corrections appear inline with date stamps.
