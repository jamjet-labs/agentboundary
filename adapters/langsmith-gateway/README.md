# LangSmith Gateway — AgentBoundary v0.2-alpha adapter

This directory maps LangSmith's Run object (and Gateway policy events) onto AgentBoundary v0.2-alpha receipts so the conformance suite can grade what LangSmith's emitted artifacts let a third party verify.

**Scope:** docs-only evaluation against LangSmith documentation as of 2026-05-21:

- `https://docs.langchain.com/langsmith/run-data-format`
- `https://docs.smith.langchain.com/how_to_guides/human_feedback/annotate_traces_inline`
- `https://www.langchain.com/blog/introducing-llm-gateway`
- LangSmith Fleet (agent identity / ABAC) — private beta, partial public docs

**Right to respond:** an issue summarising these findings was filed against `langchain-ai/langsmith-sdk` ([#2919](https://github.com/langchain-ai/langsmith-sdk/issues/2919)) before publication of the comparative report. Corrections received during the 7-day window will be reflected in `results.md`; corrections received after publication are added inline with a date stamp.

## Files in this directory

- [`mapping.md`](mapping.md) — field-by-field map of LangSmith Run → AgentBoundary v0.2-alpha receipt
- [`results.md`](results.md) — per-scenario PASS / PARTIAL / DOCS-ONLY / NOT-COVERED table
- [`adapter.py`](adapter.py) — runtime mapping: given a LangSmith Run (with optional feedback + tags + session context), produce an AgentBoundary v0.2-alpha receipt

## Headline finding

LangSmith is **observability-first**. The Run object captures rich runtime data — `inputs`, `outputs`, `start_time`, `end_time`, `status`, `tags`, `feedback_stats` — but does NOT have a normative schema for policy decisions, approver identity, or tamper-evidence. The Gateway adds spend caps and PII redaction; LangSmith Fleet adds agent identity and ABAC. Neither addresses the *artifact*: there is no per-action receipt format that a third party can verify.

For AgentBoundary's purposes, LangSmith is closer than Cloudflare HITL but still missing the load-bearing fields:

| Property | LangSmith status |
|---|---|
| Per-action data captured | ✅ rich — `inputs`, `outputs`, `run_type`, `tags`, `feedback_stats`, `error` |
| Schema for policy decision | ❌ free-form `tags` and `feedback_stats` only |
| Cryptographic tamper-evidence | ❌ database row, no hash |
| Approval identity in record | ❌ would live in feedback or tags, not normative |
| Policy version in record | ❌ no normative field |
| Chain across actions | ⚠️ partial — `parent_run_id` / `trace_id` give run tree; not a hash chain |

The honest framing: LangSmith *captures* the data; AgentBoundary gives it a *target schema*. A LangSmith user who wants verifiable receipts could write AgentBoundary v0.2-alpha JSON into the Run's `extra` field, or emit receipts at the action boundary alongside the LangSmith trace.

## What LangSmith does well

- **Observability depth.** Full trace tree, intermediate runs, IO at every step. AgentBoundary's per-action receipt has nothing comparable for *debugging*.
- **Human-feedback workflows.** Tags + scores + comments at any run level. Best-in-class for evaluation iteration.
- **Eval harness integration.** Run-against-dataset, statistical comparison, replay.
- **Self-hosting.** Full deployment on customer Kubernetes; data sovereignty for regulated workloads.

These are orthogonal to AgentBoundary (which is about the artifact format) and complementary in practice.

## What's missing for portable verification

1. **No normative policy-decision field.** Decisions live in tags or feedback conventions; different teams use different shapes.
2. **No tamper-evidence on the run record.** Reliance on database immutability.
3. **No agent-identity primitive in the run schema.** Identity is per-session; Fleet adds RBAC but that's control-plane, not artifact-bound.
4. **No spec versioning on the run.** Schema evolution is undetectable from a single record.

See [`results.md`](results.md) for the per-scenario table.
