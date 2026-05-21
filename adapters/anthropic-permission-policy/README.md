# Anthropic Managed Agents `permission_policy` — AgentBoundary v0.2-alpha adapter

This directory maps Anthropic's Claude Agent SDK permission system onto AgentBoundary v0.2-alpha receipts so the conformance suite can grade what Anthropic's emitted artifacts let a third party verify.

**Scope:** docs-only evaluation against Anthropic's public docs as of 2026-05-21:

- `https://code.claude.com/docs/en/agent-sdk/permissions` (Configure permissions)
- `https://code.claude.com/docs/en/agent-sdk/user-input` (Approvals and user input)
- `https://platform.claude.com/docs/en/managed-agents/overview` (Managed Agents overview)
- Managed Agents beta header: `managed-agents-2026-04-01`

**Right to respond:** findings will be filed to Anthropic before the W12 comparative report publishes.

## Files in this directory

- [`mapping.md`](mapping.md) — map of Anthropic's SDK permission constructs → AgentBoundary v0.2-alpha receipt
- [`results.md`](results.md) — per-scenario PASS / PARTIAL / DOCS-ONLY / NOT-COVERED table
- [`adapter.py`](adapter.py) — runtime mapping: given a synthetic permission-decision event captured at the SDK boundary, produce an AgentBoundary v0.2-alpha receipt

## Headline finding

Anthropic's `permission_policy` is the **most direct competitor to AgentBoundary v0.1's `policy.decision` primitive** of the four vendors evaluated — it has scoped rules, a multi-value decision enum, programmatic hooks, and interactive approval callbacks. It is also the most clearly **runtime-only**: the SDK provides decision *evaluation* but does not expose a portable artifact a third party can verify.

The Managed Agents Console maintains an audit log (per Anthropic's April 2026 launch announcement) where "compliance and engineering teams can inspect every tool call and decision." That log is **not exposed as a portable schema** — it lives behind the Console UI and the Managed Agents API doesn't document a schema for extracting it.

## What Anthropic does well

- **Layered permission evaluation.** Hooks → deny rules → permission mode → allow rules → canUseTool callback. Most flexible of any vendor in this comparison.
- **Scoped patterns.** `Bash(rm *)` matches a tool + argument pattern, not just the tool name. AGT comes closest with `matched_rule`, but Anthropic's patterns are expressed in the same vocabulary as the tool definitions.
- **Multiple permission modes** for different trust contexts (`default`, `dontAsk`, `acceptEdits`, `bypassPermissions`, `plan`, `auto`).
- **Managed Agents harness.** End-to-end agent runtime with sandboxing, state persistence, and Console-side audit log (closed-source schema).
- **Bypass-resistant deny.** `disallowed_tools` deny rules override even `bypassPermissions` mode — a meaningful safety primitive.

## What's missing for portable verification

The same gap as Cloudflare HITL and LangSmith Gateway, in this category: Anthropic gives you the *runtime mechanism*, not an *emitted artifact*.

1. **No public schema for the Console audit log.** Teams adopting Anthropic Managed Agents cannot extract the audit data as portable evidence.
2. **No tamper-evidence.** The audit log is database state, not a cryptographically signed artifact.
3. **No agent-identity primitive in any portable form.** Identity is per-API-key, server-side.
4. **No arguments-hash binding.** When a decision is `allow`, the action proceeds; if the args mutate during execution (e.g., MCP server-side mutation), the audit log doesn't carry a hash to detect it.
5. **No policy versioning.** Allow/deny rules are settings.json strings; their version is the git commit of settings.json (out-of-band).

See [`results.md`](results.md) for the per-scenario table.

## The honest framing for the W12 report

> Anthropic's Managed Agents permission system is the strongest *runtime* permission primitive in this comparison. It supports the richest policy expressiveness: scoped tool patterns, layered evaluation, programmatic hooks, interactive callbacks. The Console-side audit log records decisions for compliance review. What it does not expose is a portable artifact format: the audit log is a closed schema accessible only through the Console UI. Teams that need verifiable evidence outside Anthropic's environment — for an auditor, regulator, insurer, or external compliance system — need to emit their own. AgentBoundary v0.2-alpha is that emit format.
