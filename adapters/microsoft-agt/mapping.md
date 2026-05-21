# AGT → AgentBoundary v0.1 field mapping

Field-by-field translation. Sources: `microsoft/agent-governance-toolkit` `docs/specs/AUDIT-COMPLIANCE-1.0.md` §4.2 (`AuditEntry`), §11.7 (`DecisionBOM`), §4.4 (hash canonicalisation), §9.2-3 (Merkle chain).

| AgentBoundary v0.1 | AGT source | Notes |
|---|---|---|
| `version: "agentboundary/v0.1"` | constant | Adapter writes this; AGT has no equivalent receipt-format version field |
| `receipt_id` | `AuditEntry.entry_id` | Both UUIDs; direct map |
| `issued_at` | `AuditEntry.timestamp` | Both ISO-8601 UTC; direct map |
| `actor.type` | inferred from `agent_id` DID method | AGT uses `did:web:` / `did:key:` etc.; no normative `type: agent\|human\|service` enum |
| `actor.id` | `AuditEntry.agent_id` | DID string; AGT identity model |
| `actor.display_name` | not present | Lost in translation |
| `agent.framework` | `AuditEntry.metadata.framework` (custom) | Not normative in AGT schema |
| `agent.framework_version` | `AuditEntry.metadata.framework_version` (custom) | Not normative |
| `agent.model` | `AuditEntry.metadata.model` (custom) | Not normative; some teams put it in `data` |
| `tool.name` | `AuditEntry.data.tool` (sample shape) | Implementation-defined; sample payload puts it here |
| `tool.version` | not present | Lost in translation |
| `tool.capability` | `AuditEntry.event_type` partial | `tool_invocation` is the closest analogue but coarser |
| `target.system` | `AuditEntry.resource` partial | AGT collapses system+environment+resource into one `resource` URL/path |
| `target.environment` | not present | Inferred from resource path conventions |
| `target.resource_id` | `AuditEntry.resource` partial | Same field |
| `arguments_hash` | `AuditEntry.metadata.tool_args_hash` (sample only) | **Not normative in AGT spec.** Sample appendix shows it as custom metadata. The adapter computes it from `data` arguments at translation time so the produced AgentBoundary receipt is verifiable. |
| `policy.name` | derived from `AuditEntry.matched_rule` (policy file + rule reference) | AGT's `matched_rule` is a rule ID; the policy name lives in the YAML/Rego/Cedar file |
| `policy.version` | not present | **Not normative in AGT.** Adapter writes `"unknown"`. |
| `policy.decision` | `AuditEntry.decision` | AGT decision enum: `allow`, `deny`, `audit`, `quarantine`, `warning`. AgentBoundary enum: `allow`, `deny`, `require-approval`, `escalate`. Mapping: `allow→allow`, `deny→deny`, `audit→allow` (with note), `quarantine→deny` (with reason), `warning→allow` (with reason). `escalate` is implicit when AGT emits `event_type: human_review_requested` |
| `approval.approver.id` | not in AuditEntry — adapter pulls from associated workflow event (impl-defined) | **Not normative.** AGT documents approvals as "external to the audit schema" |
| `approval.approver.role` | not present | Lost in translation |
| `approval.approver.display_name` | not present | Lost in translation |
| `approval.approved_at` | not in AuditEntry — separate workflow event timestamp | Same as above |
| `approval.context` | not present | Lost |
| `execution.status` | `AuditEntry.outcome` | AGT: `success`, `failure`, `denied`, `error`. AgentBoundary: `success`, `blocked`, `pending`. Mapping: `success→success`, `failure→blocked`, `denied→blocked`, `error→blocked` |
| `execution.completed_at` | `AuditEntry.timestamp` | AGT uses one timestamp per entry; adapter copies it. Loses precision: AgentBoundary distinguishes issued_at vs completed_at |
| `execution.result_ref` | `AuditEntry.metadata.result_ref` (custom) | Not normative |
| `receipt_hash` | `AuditEntry.entry_hash` | Both SHA-256. AGT canonicalisation: sorted-key dict of `entry_id, timestamp, event_type, agent_did, action, resource, data, outcome, previous_hash`. AgentBoundary canonicalisation: every field except `receipt_hash` itself. Hashes are NOT byte-equivalent across the two formats. |

## Translation losses (one-way: AGT → AgentBoundary)

When `adapter.py` ingests an AGT `AuditEntry`, these v0.1 receipt fields cannot be populated without consulting external sources:

- `actor.display_name`
- `tool.version`
- `policy.name` (the named-policy string, not the rule ID)
- `policy.version`
- `approval.*` (the entire block, unless the adapter is also handed the workflow event log)
- `execution.result_ref` (unless put in custom metadata)
- `arguments_hash` is computable on the fly *if* `AuditEntry.data` contains the full arguments; AGT does NOT require this — implementations may store only an opaque reference.

## Translation losses (one-way: AgentBoundary → AGT)

These v0.1 receipt properties have no normative AGT field:

- `version` (receipt format version)
- The split between `target.system` / `target.environment` / `target.resource_id`
- `agent.framework_version` / `agent.model` / `agent.framework`
- Distinction between `policy.decision` and `policy_decision` reason string

## What AGT carries that v0.1 does NOT

- `previous_hash` — chain link to the prior entry. v0.2 candidate.
- `event_type` enum richer than AgentBoundary's tool/capability split (`tool_invocation`, `tool_blocked`, `policy_evaluation`, `human_review_requested`, etc.).
- `DecisionBOM.completeness_score` — self-reported reconstruction confidence.
- `DecisionBOM.sources_queried` — provenance of evidence used to make the decision.
- `latency_ms` — useful for SRE, not for evidence.
