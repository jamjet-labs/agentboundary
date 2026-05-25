# Microsoft Agent Governance Toolkit (AGT) — AgentBoundary v0.1 adapter

This directory maps Microsoft AGT's governance event model onto AgentBoundary v0.1 receipts so the conformance suite can grade what AGT's emitted artifacts let a third party verify.

**Scope:** docs-only evaluation against the AGT v1.0 specification (`microsoft/agent-governance-toolkit` main branch, `docs/specs/AUDIT-COMPLIANCE-1.0.md`, fetched 2026-05-21). No runtime account was provisioned; results reflect what AGT's own published schema and example payloads document, not whether a particular AGT deployment chooses to populate non-required metadata.

**Right to respond:** an issue was filed against `microsoft/agent-governance-toolkit` ([#2449](https://github.com/microsoft/agent-governance-toolkit/issues/2449)) before publication of the comparative report. The maintainer acknowledged five schema gaps as legitimate; companion PRs [#2473](https://github.com/microsoft/agent-governance-toolkit/pull/2473) (merged) and [#2532](https://github.com/microsoft/agent-governance-toolkit/pull/2532) (open) add the missing fields. Corrections received after publication are added inline with a date stamp.

## Files in this directory

- [`mapping.md`](mapping.md) — field-by-field map of AGT `AuditEntry` / `DecisionBOM` → AgentBoundary v0.1 receipt
- [`results.md`](results.md) — per-scenario PASS / PARTIAL / DOCS-ONLY / NOT-COVERED table, with the structural reason for each cell
- [`adapter.py`](adapter.py) — best-effort runtime mapping: given an AGT `AuditEntry` dict and an associated `DecisionBOM`, produce an AgentBoundary v0.1 receipt for the same action

## What this evaluation is NOT

- Not a verdict on whether AGT is good software (it is).
- Not a feature-by-feature audit. AGT covers OWASP Agentic Top 10 in ways AgentBoundary specifically does not (capability sandboxing, rogue detection, SRE primitives).
- Not a leaderboard. AGT and AgentBoundary measure different things: AGT *enforces* policy at runtime; AgentBoundary makes *the resulting evidence* portable and verifiable.

This evaluation answers exactly one question: *given AGT's emitted audit log, can a verifier with no access to the runtime check the same properties the AgentBoundary conformance suite checks?*

## Headline finding

AGT's structural Merkle-chained audit is **stronger** than AgentBoundary's per-receipt SHA-256 for tamper-evidence within a single audit log instance. AGT's per-entry payload is **weaker** for portable verification because four properties AgentBoundary mandates are not normative in AGT:

1. **No arguments hash.** AGT stores tool arguments in a `data` / `metadata` dict; canonicalisation is implementation-defined. A verifier cannot recompute a hash from the receipt alone to detect post-policy argument mutation. The AGT spec shows `tool_args_hash` as a sample metadata key in Appendix A.1; it is not required.
2. **No approval identity.** Approvals surface as `decision: escalate` in the audit log. The actual approver, approval timestamp, and approval context live in workflow systems external to the AGT audit schema.
3. **No policy version.** AGT records `matched_rule` (a rule ID) but no policy version string. A receipt cannot be checked against a "policy was version N at decision time" claim.
4. **Single timestamp per entry.** AGT entries have one `timestamp`; there is no separate issued-at vs completed-at, so the timeline-consistency check (LEVEL_4_COMPLETED_BEFORE_ISSUED) doesn't apply.

What AGT does better than v0.1:

1. **Chain-of-custody across actions.** The Merkle chain commits every entry to every preceding entry; reordering or selectively deleting entries is detectable. AgentBoundary v0.1 hashes each receipt independently. v0.2 candidate: receipt linkage.
2. **Decision BOM completeness score.** AGT reconstructs the decision lineage with a `completeness_score` field signalling reconstruction confidence. AgentBoundary has no equivalent self-honesty primitive.
3. **CloudEvents export to SIEM.** AGT ships a documented export path. AgentBoundary leaves this to the implementer.

See [`results.md`](results.md) for the per-scenario table.
