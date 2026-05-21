# LangSmith Gateway — 30-scenario conformance evaluation

Evaluation date: 2026-05-21. Sources: LangSmith Run data format docs + Gateway announcement + Fleet (partial public). Methodology: docs-only mapping per [`mapping.md`](mapping.md).

Each row asks: *given LangSmith's normative artifact (the Run object) plus reasonable team-level tag/feedback conventions, can a third-party verifier check the property the scenario tests?*

**Two evaluation modes:** because LangSmith's policy + identity + decision fields live in conventions (tags / feedback / extra) rather than in normative schema, the table records *what is reachable when the team follows production conventions*. A bare Run with no tagging convention fails substantially more checks; the table notes the convention dependency where it matters.

| Cell | Meaning |
|---|---|
| **PASS** | Run record + production tag/feedback conventions cover the field; adapter receipt survives this check |
| **PARTIAL** | The data is in the Run somewhere, but the schema location varies by team convention |
| **DOCS-ONLY** | Property described in docs but not verifiable from a bare artifact |
| **NOT COVERED** | No equivalent in the Run schema; adapter synthesizes |
| **N/A** | Positive boundary scenario whose check semantics don't apply |

## Summary

```
PASS         15
PARTIAL      14
DOCS-ONLY     1
NOT COVERED   8
N/A           2
              ──
TOTAL        40
```

The 14 PARTIAL count reflects LangSmith's pattern: the data is captured,
but the schema is convention-not-spec. With a strict team convention,
many PARTIALs upgrade to PASS; with no convention, they fall to NOT
COVERED. The table records the convention-following case (the more
favourable interpretation).

The 15 PASS count is the second highest after Microsoft AGT — driven
mostly by Level 3 hashing scenarios where `Run.inputs` stores raw JSON
the adapter can canonicalise and hash directly.

## Per-scenario results

| # | Scenario | Result | Structural reason |
|---|---|---|---|
| 01 | merge-allow | **PARTIAL** | `Run.tags decision:allow` convention covers it; not normative |
| 02 | mutation-require-approval | **PARTIAL** | Approval would live in `feedback_stats` or annotation events; team convention dependent |
| 03 | refund-under-limit | **PARTIAL** | Same shape as 01 — tag convention required |
| 04 | merge-deny | **PARTIAL** | `Run.tags decision:deny` + `Run.status: error` convention |
| 05 | refund-escalate | **PARTIAL** | `Run.tags decision:escalate` would express this; not normative |
| 06 | missing-policy-block | **NOT COVERED** | Run has no `policy` block; absence isn't a schema failure on LangSmith's side |
| 07 | bad-timestamp-format | **PASS** | `Run.start_time` / `end_time` are well-typed datetimes |
| 08 | arguments-hash-mismatch | **PASS** | Adapter recomputes hash from `Run.inputs`; LangSmith stores raw inputs so verifier can recompute too |
| 09 | receipt-hash-mismatch | **NOT COVERED** | No receipt-level hash field |
| 10 | claim-level-3-without-hash | **NOT COVERED** | LangSmith makes no Level claim and has no hashes |
| 11 | stale-approval | **NOT COVERED** | No approval timestamp normative field |
| 12 | unauthorized-approver | **PARTIAL** | Approver identity would be in feedback annotation; no policy-side `approvers` list to check against |
| 13 | replay-receipt-id | **PASS** | `Run.id` is globally unique UUID; replay detection works |
| 14 | completed-before-issued | **PASS** | `start_time` vs `end_time` are both captured; timeline check works |
| 15 | policy-version-downgrade | **NOT COVERED** | No policy version field; convention via tag is brittle |
| 16 | deny-with-execution-success | **PARTIAL** | `Run.status` + tag `decision:deny` would expose the contradiction; not normative |
| 17 | approval-inside-window | **N/A** | Positive boundary; LangSmith has no window concept |
| 18 | known-policy-store-passes | **N/A** | Positive boundary; no policy versioning |
| 19 | actor-human-validates | **PARTIAL** | `actor:human` tag convention; not first-class |
| 20 | numeric-arguments-validate | **PASS** | `Run.inputs` stores arbitrary JSON; adapter canonicalises and hashes |
| 21 | multiline-arguments-validate | **PASS** | Same — LangSmith stores raw inputs |
| 22 | missing-execution-block | **NOT COVERED** | LangSmith doesn't model an "execution block"; `status` + `outputs` are top-level |
| 23 | malformed-receipt-id | **PASS** | `Run.id` is UUID-typed by LangSmith schema |
| 24 | mutated-approver-no-rehash | **NOT COVERED** | No hash to tamper with |
| 25 | clean-receipt-id-passes-replay | **PASS** | `Run.id` uniqueness covers positive case |
| 26 | completeness-below-threshold | **PASS** | Adapter emits provenance + completeness_score |
| 27 | completeness-score-mismatch | **PASS** | Adapter recomputes the score; mismatch impossible by construction |
| 28 | honest-completeness-passes | **PARTIAL** | Adapter populates provenance honestly; production conventions yield 0.7-0.9 score |
| 29 | valid-chain-passes | **NOT COVERED** | `parent_run_id` is hierarchical (tree), not a hash chain. Chain would require external adapter state |
| 30 | broken-chain-fires | **DOCS-ONLY** | If adapter maintains external chain state, the check fires on tamper — but this is adapter discipline, not LangSmith guarantee |
| 31 | allow-with-blocked-execution | **PARTIAL** | `Run.tags decision:allow` + `Run.status:error` convention can express the honest failure path |
| 32 | fork-chain-shared-prior | **PARTIAL** | `parent_run_id` is hierarchical (per-trace tree); forks are expressible but not a hash chain |
| 33 | unicode-arguments-validate | **PASS** | `Run.inputs` stores raw JSON; adapter canonicalises and hashes |
| 34 | empty-arguments-validate | **PASS** | Same |
| 35 | staging-environment-validates | **PARTIAL** | `env:staging` tag convention; not normative |
| 36 | dev-environment-validates | **PARTIAL** | `env:dev` tag convention; not normative |
| 37 | execution-failure-with-error-code | **PASS** | `Run.status:error` + `Run.error.code` maps cleanly to v0.2-alpha execution.status + execution.error_code |
| 38 | approval-without-context | **PARTIAL** | Annotation feedback can be empty; convention-dependent |
| 39 | nested-arguments-canonical | **PASS** | `Run.inputs` handles arbitrary nested JSON |
| 40 | large-arguments-validate | **PASS** | Same |

## Per-conformance-level rollup (40-scenario freeze)

| Level | Of N applicable | PASS | PARTIAL | NOT COVERED |
|---|---|---|---|---|
| Level 1 / lifecycle | 14 | 7 | 5 | 2 |
| Level 2 (Policy-Bound) | 6 | 0 | 5 | 1 |
| Level 3 (Portable Proof) | 6 | 4 | 0 | 2 |
| Level 4 (Tamper-Evident) | 12 | 4 | 1 | 6 |
| Other (env values, etc.) | 2 | 0 | 2 | 0 |

The pattern: LangSmith does best at **Level 3** for the hashing scenarios
because `Run.inputs` is captured raw and the adapter can canonicalise +
hash directly. It does worst at **Level 2** because policy decisions
live in tag conventions, not normative schema. Level 4 misses are
structural (no chain, no tamper-evidence on the Run record itself).

## Where the gaps might matter

- **02, 12, 19 (convention-dependent identity/policy):** Two teams using LangSmith for the same workflow will record approval differently — one uses `feedback_stats`, another uses tags, a third uses `extra`. A cross-team auditor cannot reliably extract the data without per-team schema understanding.
- **15 (no policy versioning):** A team updates their policy logic. Existing runs are tagged with the old policy name but no version. Audit reconstruction has to infer which version was active from run timestamps.
- **29 (no chain primitive):** `parent_run_id` builds a tree per trace; it does NOT chain across traces. Deletion of a run between two traces is undetectable from a single trace.

## What LangSmith does that AgentBoundary does NOT

- **Full trace tree** for debugging — `parent_run_id`, `child_run_ids`, `dotted_order`
- **Token counts and costs** — `total_tokens`, `total_cost`, etc.
- **`feedback_stats`** — aggregated annotation scores
- **`reference_example_id`** — eval dataset linkage
- **Self-hostable on customer Kubernetes** — full data sovereignty

These are observability + eval primitives. Excellent for what they do. Orthogonal to AgentBoundary.

## Recommendation for the W12 §7.3 narrative

> LangSmith is the most full-featured observability platform in this comparison. The Run object captures everything an engineer needs to debug a multi-step agent call. What it does not have — and does not claim to have — is a *normative artifact format for portable verification*. Decisions, approvals, and policy versions live in team-defined tag conventions, not in the Run schema. A team adopting AgentBoundary on top of LangSmith gets the artifact format LangSmith deliberately leaves to the implementer.

## Right-to-respond

Filed 2026-05-21 on the LangSmith SDK repository:
**[`langchain-ai/langsmith-sdk#2919`](https://github.com/langchain-ai/langsmith-sdk/issues/2919)** — @hinthornw tagged. Corrections received within 7 days are incorporated; later corrections appear inline with date stamps.
