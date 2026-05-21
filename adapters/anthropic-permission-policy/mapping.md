# Anthropic Permission Policy → AgentBoundary v0.2-alpha field mapping

Anthropic doesn't publish an audit-log schema — the Managed Agents Console maintains one internally. The adapter therefore works against a **synthetic permission-decision event** captured at the SDK boundary (typically inside a `canUseTool` callback, a hook, or a wrapper around `query()`/`ClaudeSDKClient`).

## Anthropic SDK constructs (the building blocks)

```
permission_mode:        "default" | "dontAsk" | "acceptEdits" | "bypassPermissions" | "plan" | "auto"
allowed_tools:          list[str]   # e.g. ["Read", "Grep", "Bash(ls *)"]
disallowed_tools:       list[str]   # e.g. ["Bash(rm *)"]
hook:                   callback     # runs early in evaluation
canUseTool:             callback     # invoked when no rule resolves

# canUseTool receives:
#   tool_name: str
#   tool_input: dict
# canUseTool returns one of:
#   {"behavior": "allow", "updatedInput": dict | None}
#   {"behavior": "deny", "message": str}
```

## Synthetic permission-decision event (adapter input)

The adapter takes a structured representation of what Anthropic's SDK evaluated, captured by the integrating team at the SDK boundary:

```python
{
    "session_id": str,
    "tool_name": str,            # the tool Claude requested
    "tool_input": dict,           # the arguments Claude proposed
    "decision": str,              # "allow" | "deny" | "ask" -> AgentBoundary decision
    "decided_via": str,           # "hook" | "deny_rule" | "permission_mode" | "allow_rule" | "canUseTool"
    "matched_rule": str | None,   # e.g. "Bash(rm *)" when decided by a rule
    "permission_mode": str,       # active mode at decision time
    "decided_at": str,            # RFC 3339
    "decided_by": str | None,     # only present for canUseTool-resolved decisions
    "reason": str | None,         # canUseTool's deny message, or hook's reason
    "updated_input": dict | None, # when canUseTool returned modified input
}
```

This is **not** a normative Anthropic schema — it's a recommended capture shape for teams that want to emit AgentBoundary receipts from their Anthropic agents.

## Translation table

| AgentBoundary v0.2-alpha | Anthropic source | Translation note |
|---|---|---|
| `version: "agentboundary/v0.2-alpha"` | constant | Adapter writes |
| `receipt_id` | adapter-generated UUID | Anthropic doesn't expose a portable decision-event ID |
| `issued_at` | event `decided_at` | Direct map |
| `actor.type` | constant `"agent"` for SDK tool calls | Anthropic agents are always `agent`-typed at the SDK boundary |
| `actor.id` | derived from `session_id` (e.g. `anthropic:session:<id>`) | Anthropic identity is per-API-key, server-side; no public agent identifier |
| `actor.display_name` | not normative | Lost |
| `agent.framework` | constant `"claude-agent-sdk"` | Adapter convention |
| `agent.framework_version` | from caller-supplied context (e.g. `package.json` of `@anthropic-ai/claude-agent-sdk`) | Not in the event |
| `agent.model` | from the SDK session (Claude model in use) | Caller must supply; not in the permission event |
| `tool.name` | event `tool_name` | Direct map |
| `tool.version` | not present | Lost — Anthropic tools don't carry a version |
| `tool.capability` | derived from `tool_name` (e.g. `anthropic.tool.Bash`) | Synthesized |
| `target.system` | from caller context (the system the tool acts on) | Not in the event; depends on which tool |
| `target.environment` | from caller context | Not in the event |
| `target.resource_id` | from `tool_input` when it contains a resource identifier | Inferred from inputs |
| `arguments_hash` | adapter recomputes from `tool_input` (using `updated_input` if present, as that's what actually executes) | Anthropic has the args at decision time; adapter canonicalises and hashes |
| `policy.name` | constant `"anthropic.permission_policy"` (or caller-supplied) | Anthropic doesn't use named policies; settings.json is the "policy" |
| `policy.version` | from settings.json git commit (caller-supplied) | Not in the event; out-of-band |
| `policy.decision` | event `decision`, with the Anthropic 3-value enum (allow/deny/ask) mapped to AgentBoundary's 4-value enum: `allow→allow`, `deny→deny`, `ask→require-approval` | Coarser on Anthropic's side (no `escalate`) |
| `approval.approver.id` | event `decided_by` when `decided_via == "canUseTool"` | The callback runs in the integrating team's code; the team identifies the approver |
| `approval.approver.role` | not normative | Lost |
| `approval.approver.display_name` | not normative | Lost |
| `approval.approved_at` | `decided_at` | Same value as issued_at when adapter emits at decision time |
| `approval.context` | event `reason` (canUseTool's message or hook's reason) | Optional |
| `execution.status` | from caller context — Anthropic's SDK doesn't emit a separate "the tool ran" event in this synthesized model | Adapter must be told the execute outcome |
| `execution.completed_at` | caller context | Same |
| `execution.result_ref` | from caller context | Same |
| `receipt_hash` | computed by AgentBoundary canonicaliser | No Anthropic equivalent |
| `prior_receipt` | not directly available; adapter caller maintains chain state externally | Anthropic doesn't expose decision-event sequence numbers in a portable form |
| `provenance` | adapter populates honestly | Mostly synthesized + inferred; only the `decision`, `tool_name`, and `matched_rule` are observed from the event |
| `completeness_score` | computed from provenance | Typical 0.4-0.6 with bare event; 0.8+ with full caller context |

## Strong PASS candidates

- `tool.name` — direct from event
- `arguments_hash` — adapter has the args
- `policy.decision` — Anthropic's 3-value enum maps to AgentBoundary's first three
- `policy.name` — synthesized constant, but stable across receipts
- The L3 scenarios where the verifier has the args (because adapter canonicalises raw `tool_input`)

## NOT COVERED structural gaps

- No agent-identity primitive in the SDK
- No portable policy-version field (settings.json is out-of-band)
- No tamper-evidence in the synthesized event
- No chain primitive
- The Console-side audit log has a schema, but it's not public

## What Anthropic carries that AgentBoundary does NOT

- **Permission modes** as global state (`dontAsk`, `acceptEdits`, `bypassPermissions`, `plan`, `auto`)
- **Scoped pattern matching** (`Bash(rm *)`) for tool+args combinations in declarative rules
- **canUseTool's `updatedInput`** — the callback can return a modified version of the args, which then executes instead of Claude's original proposal. AgentBoundary's `arguments_hash` would need to cover whichever args actually ran (the adapter uses `updated_input` when present)
- **Layered evaluation order** (hook → deny → mode → allow → callback) — Anthropic exposes this as a documented evaluation pipeline; AgentBoundary doesn't model the pipeline, only the outcome
