# AgentBoundary v0.1 → OWASP LLM Top 10 mapping

> **Companion to [`v0.1.md`](v0.1.md) and [`threat-model.md`](threat-model.md).** This document maps each OWASP LLM Top 10 risk to the AgentBoundary conformance level (or threat mitigation) that addresses it. Borrowed credibility: when implementers cite AgentBoundary in compliance contexts, they can point at an OWASP-aligned coverage table.

## OWASP LLM Top 10 (current edition)

The mapping below references the [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/). Confirm the current edition before citing in compliance documents.

| OWASP risk | What it is | AgentBoundary coverage | Conformance level |
|---|---|---|---|
| **LLM01: Prompt Injection** | An attacker manipulates LLM input to alter behavior. | Out of scope — receipt records what actually happened; doesn't prevent jailbreak. | N/A |
| **LLM02: Insecure Output Handling** | Downstream systems trust LLM output without validation. | Partial — AgentBoundary's policy layer evaluates LLM-proposed Actions before they reach production systems. Policy decisions are recorded. Doesn't validate LLM output sent to non-Action consumers. | Level 2 (policy-bound) |
| **LLM03: Training Data Poisoning** | Adversarial data in training corpus. | Out of scope — operates at inference time, not training. | N/A |
| **LLM04: Model Denial of Service** | Resource exhaustion via crafted prompts. | Out of scope — runtime concern, not receipt format. | N/A |
| **LLM05: Supply Chain Vulnerabilities** | Compromised model, framework, or dependency. | Partial — `agent.framework`, `agent.framework_version`, `agent.model`, `agent.model_version` are recorded in every receipt, supporting downstream forensics and SBOM-style audit. | Level 1 (logged) |
| **LLM06: Sensitive Information Disclosure** | LLM leaks confidential data. | Out of scope for Actions; AgentBoundary covers Action-taking, not reading. Operators handling sensitive read-only Actions should not classify them as Actions under this spec. | N/A |
| **LLM07: Insecure Plugin Design** | Tool/plugin lacks authorization checks. | Direct coverage — every controlled tool capability MUST be policy-governed. Unauthorized invocations produce `deny` receipts. T-03 (unauthorized approver) is mitigated at Level 4. | Level 2 + Level 4 (T-03) |
| **LLM08: Excessive Agency** | Agent has more permissions than necessary. | Direct coverage — AgentBoundary's policy layer is the primary control point. Policies declare per-capability per-target permissions. Receipt-level evidence proves only authorized capabilities were exercised. | Level 2 (policy-bound), strengthened at Level 4 |
| **LLM09: Overreliance** | Operators trust LLM output without verification. | Partial — receipts enable post-hoc audit, but the receipt format doesn't enforce human review. Policies with `require-approval` shift trust to humans where appropriate. | Level 2 (when `require-approval` policies are used) |
| **LLM10: Model Theft** | Adversaries exfiltrate proprietary models. | Out of scope — receipt format doesn't address model protection. | N/A |

## How to use this mapping

Two use cases:

### 1. Implementor self-assessment

If you build an AgentBoundary-conformant runtime at Level N, you can claim coverage of the OWASP risks marked at Level N or below in the table above.

Example: a runtime at Level 4 conformance covers LLM02 (Insecure Output Handling) at Level 2, LLM05 (Supply Chain Vulnerabilities) at Level 1, LLM07 (Insecure Plugin Design) at Level 2 + Level 4, and LLM08 (Excessive Agency) at Level 4. It does NOT cover LLM01, LLM03, LLM04, LLM06, LLM10.

### 2. Compliance reviewer evaluation

When evaluating an agent governance tool, ask:

- "Which OWASP LLM Top 10 risks does your tool cover?"
- "At what AgentBoundary conformance level?"
- "Can you produce an Action Receipt that I can verify independently?"

A tool that can't answer these questions is not making testable compliance claims.

## What this mapping is NOT

- **Not a substitute for OWASP testing.** AgentBoundary covers Action-taking; OWASP covers the broader LLM application surface. A complete security posture needs both.
- **Not a certification.** AgentBoundary v0.1 has no certification body. Vendors self-declare conformance.
- **Not stable across OWASP editions.** The OWASP LLM Top 10 changes annually. v0.2 of this mapping will re-baseline against the then-current OWASP edition.

## Versioning

This mapping document is versioned alongside the spec. A v0.2 mapping will be issued when:

- The OWASP LLM Top 10 issues a new edition
- AgentBoundary v0.2 adds new conformance levels
- Significant misalignments are reported by users

Report mapping issues at the [agentboundary issue tracker](https://github.com/jamjet-labs/agentboundary/issues) tagged `owasp-mapping`.
