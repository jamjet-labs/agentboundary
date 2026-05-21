# Anthropic permission_policy — 30-scenario conformance evaluation

Evaluation date: 2026-05-21. Sources: Claude Agent SDK permissions docs + Managed Agents overview. Methodology: docs-only mapping per [`mapping.md`](mapping.md). The adapter works against a **synthetic permission-decision event** captured at the SDK boundary by the integrating team — Anthropic does not publish an audit-log schema.

Each row asks: *given the Anthropic SDK's permission decision plus reasonable caller-supplied tool-call context, can a third-party verifier check the property the scenario tests?*

| Cell | Meaning |
|---|---|
| **PASS** | Anthropic's decision event + caller-supplied context covers the field; adapter receipt survives this check |
| **PARTIAL** | The data exists at the SDK boundary but Anthropic exposes no normative schema for it |
| **DOCS-ONLY** | Property described in docs but not verifiable from any portable artifact |
| **NOT COVERED** | No Anthropic-side equivalent; adapter synthesizes |
| **N/A** | Positive boundary scenario whose check semantics don't apply |

## Summary

```
PASS          5
PARTIAL       8
DOCS-ONLY     3
NOT COVERED  12
N/A           2
              ──
TOTAL        30
```

3 DOCS-ONLY is the highest of any vendor — Anthropic's Managed Agents Console maintains a comprehensive audit log per their launch announcement, but the schema is not publicly documented; we can confirm capability without being able to verify the artifact.

## Per-scenario results

| # | Scenario | Result | Structural reason |
|---|---|---|---|
| 01 | merge-allow | **PARTIAL** | Decision event has `decision: allow` and `tool_name`, but target/policy.name/agent.model require caller context |
| 02 | mutation-require-approval | **PASS** | `decision: ask` + `decided_via: canUseTool` + `decided_by` (caller-supplied) populate the approval block |
| 03 | refund-under-limit | **PARTIAL** | Same shape as 01 |
| 04 | merge-deny | **PASS** | `decision: deny` with `matched_rule` populates policy.name + decision cleanly |
| 05 | refund-escalate | **NOT COVERED** | Anthropic's enum is 3-value (allow/deny/ask); there's no `escalate` distinct from `ask` |
| 06 | missing-policy-block | **NOT COVERED** | Anthropic's policy concept is settings.json + permission_mode; there's no per-event policy block, so its absence isn't detectable from Anthropic-side |
| 07 | bad-timestamp-format | **DOCS-ONLY** | Managed Agents Console records timestamps — schema not public; adapter formats RFC 3339 |
| 08 | arguments-hash-mismatch | **PASS** | Adapter hashes `tool_input` (or `updated_input` if `canUseTool` modified it). Mutation between decision and execute is detectable when the adapter is on the execute path too |
| 09 | receipt-hash-mismatch | **NOT COVERED** | No receipt-level hash |
| 10 | claim-level-3-without-hash | **NOT COVERED** | Anthropic doesn't claim Level 3 |
| 11 | stale-approval | **NOT COVERED** | No approval-window primitive |
| 12 | unauthorized-approver | **PARTIAL** | `decided_by` is whoever the canUseTool callback identified; no policy-side approvers list to validate against |
| 13 | replay-receipt-id | **PASS** | Adapter generates UUID per decision event; replay detection works against verifier's prior_receipt_ids |
| 14 | completed-before-issued | **PARTIAL** | Decision event has one timestamp; execute timestamp comes from caller context. When both supplied, the check works |
| 15 | policy-version-downgrade | **NOT COVERED** | settings.json has no embedded version; rule strings have no version qualifier |
| 16 | deny-with-execution-success | **PARTIAL** | Anthropic's deny rules are absolute (the tool doesn't execute), so this contradiction shouldn't arise in practice. If an adapter is fed a deny event with a success execute outcome (a misconfiguration), the L4 check catches it |
| 17 | approval-inside-window | **N/A** | Positive boundary; no window concept |
| 18 | known-policy-store-passes | **N/A** | Positive boundary; no policy versioning |
| 19 | actor-human-validates | **NOT COVERED** | Anthropic SDK agents are always agent-typed; no human-actor variant in the SDK boundary |
| 20 | numeric-arguments-validate | **PASS** | `tool_input` is arbitrary JSON; adapter canonicalises and hashes |
| 21 | multiline-arguments-validate | **PASS** | Same — adapter handles raw JSON |
| 22 | missing-execution-block | **NOT COVERED** | Execution status is caller-supplied; absence isn't an Anthropic-side schema failure |
| 23 | malformed-receipt-id | **DOCS-ONLY** | Console audit log presumably uses UUIDs; schema not public |
| 24 | mutated-approver-no-rehash | **NOT COVERED** | No hash to tamper with |
| 25 | clean-receipt-id-passes-replay | **PASS** | Fresh UUID per emission; positive case works |
| 26 | completeness-below-threshold | **DOCS-ONLY** | Adapter emits provenance + completeness_score; works at adapter layer, not Anthropic-side |
| 27 | completeness-score-mismatch | **PARTIAL** | Same — adapter-layer property |
| 28 | honest-completeness-passes | **PARTIAL** | Adapter populates provenance honestly; bare event scores ~0.4, full context ~0.85 |
| 29 | valid-chain-passes | **NOT COVERED** | No chain primitive; events are independent |
| 30 | broken-chain-fires | **NOT COVERED** | Same |

## Per-conformance-level rollup

| Level | Of N applicable | PASS | PARTIAL | NOT COVERED |
|---|---|---|---|---|
| Level 1 (Logged) | 10 | 3 | 4 | 3 |
| Level 2 (Policy-Bound) | 6 | 2 | 3 | 1 |
| Level 3 (Portable Proof) | 5 | 3 | 0 | 2 |
| Level 4 (Tamper-Evident) | 12 | 1 | 2 | 6 |

The pattern: Anthropic does well at **Level 3** for hash recomputation (the adapter has the args). It does relatively well at **Level 2** because `policy.decision` maps cleanly. It does worst at **Level 4** because there's no chain, no tamper-evidence, and limited approval-window semantics.

## Where the gaps might matter

- **05 (no escalate):** A workflow that distinguishes "requires-approval" (ask a maintainer) from "escalate" (kick to a different system) collapses these to the same `ask` decision on Anthropic's side. Receipt loses the distinction.
- **15 (no policy versioning):** Two snapshots of settings.json with different `disallowed_tools` lists. A receipt referencing "the deny rule that fired" doesn't know which version was active.
- **22 (no execution block):** Anthropic's permission decision is *evaluation*, not *execution*. If a downstream MCP tool fails after `allow`, the adapter must be fed that outcome — Anthropic's SDK doesn't unify decision + execution in a single event.

## What Anthropic does that AgentBoundary does NOT

- **Permission modes** as global session state — `dontAsk`, `acceptEdits`, `bypassPermissions`, `plan`, `auto`
- **Scoped pattern matching** (`Bash(rm *)`) for tool + argument patterns in declarative rules
- **Layered evaluation pipeline** (hook → deny → mode → allow → callback)
- **canUseTool's `updatedInput`** — the callback can modify the args before execution; the adapter handles this by hashing the modified inputs
- **Managed Agents harness** — sandboxing, state persistence, error recovery, dreaming

The runtime mechanism is significantly richer than AGT or Cloudflare. The portable artifact is significantly thinner — there isn't one.

## Recommendation for the W12 §7.1 narrative

> Anthropic's permission_policy is the strongest *runtime permission primitive* in this comparison — layered evaluation, scoped patterns, multiple permission modes, programmatic hooks, interactive callbacks. The Managed Agents Console maintains a comprehensive audit log; that log's schema is not publicly documented. A team using Anthropic Managed Agents has excellent in-product audit visibility and no portable evidence to share with external verifiers. AgentBoundary v0.2-alpha is the export format for that gap — a team can wrap their `canUseTool` callback or `query()` invocation, capture the synthetic decision event documented here, and emit a v0.2-alpha receipt at the action boundary.

## Right-to-respond

Findings will be sent to Anthropic before W12 publication.
