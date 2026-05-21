# LangSmith → AgentBoundary v0.2-alpha field mapping

LangSmith Run objects are rich; AgentBoundary v0.2-alpha receipts are stricter-schema. Most receipt fields can be populated from a Run when the team has followed a tag/feedback convention; many fall to `synthesized` because there's no normative schema in LangSmith's data format.

## LangSmith Run shape (from docs)

```
Run {
  id                  uuid
  name                string
  run_type            "llm" | "tool" | "chain" | ...
  inputs              object
  outputs             object | null
  error               object | null
  start_time          datetime
  end_time            datetime
  status              "success" | "error" | ...
  tags                string[]
  trace_id            uuid
  parent_run_id       uuid | null
  parent_run_ids      uuid[]
  child_run_ids       uuid[]
  session_id          uuid
  feedback_stats      object  // { <key>: { n, avg, ... } }
  extra               object
  reference_example_id uuid | null
  // token counts, costs, etc.
}
```

## Translation table

| AgentBoundary v0.2-alpha | LangSmith source | Translation note |
|---|---|---|
| `version: "agentboundary/v0.2-alpha"` | constant | Adapter writes |
| `receipt_id` | `Run.id` | Both UUIDs; direct map |
| `issued_at` | `Run.end_time` (or `start_time` for blocked runs) | RFC 3339 format |
| `actor.type` | inferred from `Run.tags` (look for `actor:agent` or `actor:human`) | No normative actor.type field; tag convention |
| `actor.id` | from `Run.extra.user_id` or `Run.tags` `user:*` | Tag/extra convention; not normative |
| `actor.display_name` | from `Run.tags` `display_name:*` | Optional, tag-based |
| `agent.framework` | constant `"langchain"` (or from `Run.extra.framework`) | Implementer convention |
| `agent.framework_version` | from `Run.extra.framework_version` | Conventional |
| `agent.model` | from the run's LLM child or `Run.extra.model` | LangSmith traces include the model in LLM-run children |
| `tool.name` | `Run.name` (when `run_type == "tool"`) | Direct map for tool-typed runs |
| `tool.version` | `Run.extra.tool_version` | Conventional; not normative |
| `tool.capability` | `Run.tags` `capability:*` or synthesized from `Run.name` | Conventional |
| `target.system` | from `Run.tags` `target:*` or `Run.extra.target` | Conventional |
| `target.environment` | from `Run.tags` `env:prod\|staging\|dev` | Conventional |
| `target.resource_id` | from `Run.inputs` (e.g., a `resource_id` key) | Convention; varies per implementation |
| `arguments_hash` | adapter recomputes from `Run.inputs` | LangSmith stores raw inputs; adapter canonicalises and hashes |
| `policy.name` | from `Run.tags` `policy:*` | Tag convention |
| `policy.version` | from `Run.tags` `policy_version:*` | Tag convention |
| `policy.decision` | from `Run.tags` `decision:allow\|deny\|escalate\|require-approval` or from `Run.feedback_stats.decision` | Tag/feedback convention |
| `approval.approver.id` | from `Run.feedback_stats` or annotation events | Conventional; annotation-based |
| `approval.approver.role` | not normative | Lost |
| `approval.approver.display_name` | not normative | Lost |
| `approval.approved_at` | from annotation timestamp | Inferred |
| `approval.context` | from annotation comment | Optional |
| `execution.status` | mapped from `Run.status`: `success → success`, `error → failure`, plus blocked when policy decision was deny/escalate without approval | Direct map for success/failure; blocked is inferred from policy outcome |
| `execution.completed_at` | `Run.end_time` | Direct map |
| `execution.result_ref` | from `Run.outputs` (e.g., a `result_ref` key) or `Run.extra.result_ref` | Convention |
| `execution.error_code` | from `Run.error.code` when present | Direct map |
| `receipt_hash` | computed by AgentBoundary canonicaliser | LangSmith has no equivalent |
| `prior_receipt` | not directly available — `Run.parent_run_id` is hierarchical, not a chain in the AgentBoundary sense | Adapter caller can construct a chain externally |
| `provenance` | adapter populates honestly | Most fields are `observed` when tag/feedback conventions are followed; `synthesized` when defaulted |
| `completeness_score` | computed from provenance | Typical score with full tag conventions: 0.7-0.9; bare run: 0.3-0.5 |

## What LangSmith carries that AgentBoundary does NOT

- **Full trace tree** (`parent_run_id`, `child_run_ids`, `dotted_order`) — hierarchical context across many runs in a single call
- **Token counts and costs** — `prompt_tokens`, `completion_tokens`, `total_cost`
- **`feedback_stats`** — aggregated annotation scores with count and average
- **`reference_example_id`** — links to an eval dataset row
- **`session_id` / tracing project** — workspace-level grouping

These are observability and eval primitives. AgentBoundary deliberately doesn't address them.

## Translation losses (one-way: LangSmith → AgentBoundary)

When the team hasn't followed any tag convention, these v0.2-alpha receipt fields cannot be populated from a bare Run:

- `actor.type`, `actor.id`, `actor.display_name`
- `agent.framework`, `agent.framework_version`, `agent.model`
- `policy.name`, `policy.version`, `policy.decision`
- `approval.*` (entire block)
- `target.system`, `target.environment`, `target.resource_id`

When the team HAS followed conventions (the typical "production-grade observability" case), most of these become `observed` via the tag/feedback paths described above.

## Recommendation for LangSmith users

The clean adoption pattern is to emit AgentBoundary v0.2-alpha receipts at the action boundary AND continue using LangSmith for observability. The two artifacts serve different audiences: LangSmith's run tree is for engineers debugging; the AgentBoundary receipt is for third-party verifiers (auditors, regulators, insurers). They reference each other via `Run.extra.agentboundary_receipt_id` ↔ `Receipt.execution.result_ref`.
