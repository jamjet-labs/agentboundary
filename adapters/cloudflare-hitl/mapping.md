# Cloudflare HITL → AgentBoundary v0.2-alpha field mapping

The recommended Cloudflare audit table has six columns. AgentBoundary v0.2-alpha receipts have ~22 paths. The mapping is therefore heavy on "synthesized" — most receipt fields come from the surrounding tool-call context, not the recommended audit row itself.

## Cloudflare-recommended audit row (the only normative artifact)

```sql
approval_audit (
  id            INTEGER     PRIMARY KEY AUTOINCREMENT,
  workflow_id   TEXT        NOT NULL,
  decision      TEXT        NOT NULL CHECK(decision IN ('approved', 'rejected')),
  decided_by    TEXT        NOT NULL,
  decided_at    INTEGER     NOT NULL,
  reason        TEXT
)
```

## Translation table

| AgentBoundary v0.2-alpha | Cloudflare source | Translation note |
|---|---|---|
| `version: "agentboundary/v0.2-alpha"` | constant | Adapter writes |
| `receipt_id` | adapter-generated UUID | Cloudflare's `id INTEGER AUTOINCREMENT` is local-only; not globally unique |
| `issued_at` | adapter clock at emit time | Cloudflare's `decided_at INTEGER` is millis-since-epoch; adapter formats as RFC 3339 |
| `actor.type` | constant `"agent"` for tool calls under `needsApproval` | Cloudflare doesn't distinguish agent vs human actor in the audit row |
| `actor.id` | from the surrounding `AIChatAgent` context (the agent instance) | Not in the audit row; adapter must be passed it |
| `actor.display_name` | not normative | Lost in translation |
| `agent.framework` | constant `"cloudflare-agents"` (or version-specific) | Not in any normative Cloudflare record |
| `agent.framework_version` | reading SDK version from `package.json` | Adapter-supplied |
| `agent.model` | from `AIChatAgent` configuration | Not in the audit row |
| `tool.name` | tool name from `addTool` registration | Not in the audit row; adapter must be passed it from the tool-call context |
| `tool.version` | not present | Lost — Cloudflare tools don't carry a version |
| `tool.capability` | adapter convention; e.g. `cloudflare.tool.<name>` | Synthesized from `tool.name` |
| `target.system` | from agent runtime configuration (worker URL, durable object class) | Not in the audit row |
| `target.environment` | adapter-supplied (defaults to `"prod"`) | Cloudflare doesn't model environment in the audit row |
| `target.resource_id` | from tool arguments where applicable | Synthesized from `inputSchema`-validated input |
| `arguments_hash` | adapter recomputes from `inputSchema`-validated input | Cloudflare has the args at decision time (inside `needsApproval` predicate or `execute`) but does NOT store them normatively — the adapter must be passed them |
| `policy.name` | constant or adapter-supplied (no Cloudflare-side policy primitive) | Synthesized — Cloudflare's needsApproval isn't a "policy" with a name |
| `policy.version` | `"unknown"` (no Cloudflare versioning) | Synthesized |
| `policy.decision` | mapped from `decision`: `approved → "allow"`, `rejected → "deny"` | Coarser than AgentBoundary's 4-value enum (no `escalate`, no `require-approval` at receipt time because Cloudflare emits the row only AFTER decision) |
| `approval.approver.id` | `decided_by TEXT` | Observed; string-only (no identity verification) |
| `approval.approver.role` | not present | Lost |
| `approval.approver.display_name` | not present | Lost |
| `approval.approved_at` | `decided_at INTEGER` (millis since epoch); adapter formats as RFC 3339 | Observed |
| `approval.context` | `reason TEXT` (optional) | Observed when present |
| `execution.status` | adapter-supplied from the tool's `execute` outcome | Cloudflare's audit row records the DECISION, not the EXECUTION |
| `execution.completed_at` | adapter clock at execute time | Not in the audit row |
| `execution.result_ref` | adapter-supplied (e.g. an opaque reference to the tool's return value) | Not in the audit row |
| `receipt_hash` | computed by AgentBoundary canonicaliser | Cloudflare has no equivalent |
| `prior_receipt` | not available — Cloudflare's `id AUTOINCREMENT` orders rows but doesn't pair the prior hash | Adapter must maintain external prior_receipt state across emissions |
| `provenance` | adapter populates honestly from translation | Most fields are `synthesized` because the audit row has so few |
| `completeness_score` | computed from provenance | Typical Cloudflare-adapter score is low (~0.4-0.6) reflecting the artifact gap |

## Translation losses (one-way: Cloudflare → AgentBoundary)

When `adapter.py` ingests an `approval_audit` row, these v0.2-alpha receipt fields cannot be populated from the row alone:

- `tool.name`, `tool.capability`, `tool.version`
- `actor.id`, `actor.display_name`, `actor.type`
- `agent.framework`, `agent.framework_version`, `agent.model`
- `target.system`, `target.environment`, `target.resource_id`
- `arguments_hash` (the args aren't stored in the row)
- `policy.name`, `policy.version`
- `execution.status`, `execution.completed_at`, `execution.result_ref`
- `prior_receipt`

The adapter therefore takes a separate `tool_call_context` parameter capturing what the agent had in scope at decision time. A Cloudflare-using team that wants verifiable receipts can populate this context via their own `this.sql` writes (denormalising what the audit row should have carried) or by emitting AgentBoundary receipts directly at the tool call site and skipping the recommended `approval_audit` schema entirely.

## Translation losses (one-way: AgentBoundary → Cloudflare)

These AgentBoundary v0.2-alpha properties have no normative Cloudflare-side field:

- `version` (receipt format version)
- The split between `target.system` / `target.environment` / `target.resource_id`
- Per-action `arguments_hash`
- Schema-validated decision enum (Cloudflare uses 2-value approved/rejected; AgentBoundary uses 4-value with explicit escalate + require-approval)
- `receipt_hash` and the chain
- `provenance` + `completeness_score`

## What Cloudflare carries that AgentBoundary does NOT

- **`workflow_id`** — durable-execution context. AgentBoundary's receipt is single-action; durable multi-step orchestration is out of scope.
- **`decided_at INTEGER`** — millis-since-epoch. Both formats encode time; Cloudflare's is cheaper to store and order.
- **Workflow waitForApproval semantics** — multi-day pause primitive. AgentBoundary has no equivalent.
