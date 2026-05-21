# Cloudflare HITL Agents — AgentBoundary v0.2-alpha adapter

This directory maps the Cloudflare Agents SDK's human-in-the-loop primitive onto AgentBoundary v0.2-alpha receipts so the conformance suite can grade what Cloudflare's recommended approach lets a third party verify.

**Scope:** docs-only evaluation against `cloudflare/agents` SDK and the Cloudflare Agents documentation as of 2026-05-21, principally:

- `https://developers.cloudflare.com/agents/concepts/human-in-the-loop/`
- `https://developers.cloudflare.com/agents/guides/human-in-the-loop/`
- `https://github.com/cloudflare/agents/blob/main/guides/human-in-the-loop/README.md`

**Right to respond:** a summary of these findings will be filed against `cloudflare/agents` before the W12 comparative report publishes. Corrections received during the 7-day window are reflected in `results.md`; later corrections appear inline with date stamps.

## Files in this directory

- [`mapping.md`](mapping.md) — field-by-field map of Cloudflare's recommended audit-row schema + the surrounding tool-call context → AgentBoundary v0.2-alpha receipt
- [`results.md`](results.md) — per-scenario PASS / PARTIAL / DOCS-ONLY / NOT-COVERED table, with the structural reason for each cell
- [`adapter.py`](adapter.py) — best-effort runtime mapping: given a Cloudflare HITL audit row + the tool-call context the agent had in scope, produce an AgentBoundary v0.2-alpha receipt

## Headline finding

Cloudflare's HITL is **a workflow primitive, not an emitted-artifact format**. The SDK provides `needsApproval` on tool definitions and `addToolApprovalResponse` for client-side handling, but does not prescribe a structured audit record. The documentation *recommends* developers build their own audit log via `this.sql`, and gives a 6-column suggested schema:

```sql
CREATE TABLE IF NOT EXISTS approval_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workflow_id TEXT NOT NULL,
  decision TEXT NOT NULL CHECK(decision IN ('approved', 'rejected')),
  decided_by TEXT NOT NULL,
  decided_at INTEGER NOT NULL,
  reason TEXT
)
```

That's the entire normative surface. No tool name, no arguments, no policy reference, no execution result, no tamper-evidence hash, no chain link, no agent identity. Everything downstream of "I approved this" lives in developer-written code.

The honest comparison: Cloudflare HITL **does not produce an audit artifact** that a third party can verify — it provides a primitive that developers can use to build one. AgentBoundary's role here is upstream: it gives Cloudflare-using developers a *target schema* their `this.sql` writes should land in.

## What Cloudflare does well

- **Durable execution.** Approval gates can wait hours, days, or weeks via Workflows + `waitForApproval()`. AgentBoundary doesn't speak to durability at all.
- **Client-server pattern.** The `addToolApprovalResponse` flow is clean and well-documented.
- **Integration with Knock.** Notification + approval routing through external systems is well-supported.

These are orthogonal to AgentBoundary's scope (the receipt artifact) and complementary in practice — a Cloudflare Agents workflow can durably gate an action and emit an AgentBoundary receipt at the boundary.

## What's missing for portable verification

Of the 30 conformance scenarios, the gaps are structural:

1. **No prescribed tool/argument capture.** The recommended schema records `workflow_id` + `decision` + `decided_by`. The tool name, the arguments, and any hash of the arguments are not normative.
2. **No actor identity beyond a string.** `decided_by TEXT` is a label, not a cryptographically verifiable identity.
3. **No policy reference.** The audit row doesn't name the policy the decision was made against.
4. **No tamper-evidence on the row.** Reliance on database immutability conventions; no `entry_hash` or `previous_hash`.
5. **No chain link.** Each `approval_audit` row stands alone; there's no formal mechanism for an auditor to detect deletion or reordering of rows.
6. **No spec versioning.** The recommended schema has no `version` field, so a downstream evolution is undetectable from the row.

See [`results.md`](results.md) for the per-scenario table.

## Bottom line for the comparative report

> Cloudflare's HITL is excellent at one thing AgentBoundary does not address: durable human-approval gates with multi-day windows and external notification integration. Cloudflare's HITL does not address what AgentBoundary is for: a portable, schema-versioned, tamper-evident audit artifact that a third party can verify without trusting the runtime. The two systems are complementary; a Cloudflare Agents workflow can durably gate an action AND emit an AgentBoundary receipt at the boundary. Existing Cloudflare HITL deployments could adopt AgentBoundary by writing v0.2-alpha receipts into `this.sql` instead of (or alongside) the suggested `approval_audit` schema.
