# AgentBoundary v0.1 Threat Model

> **Companion to [`v0.1.md`](v0.1.md).** Conformance Level 4 implementations defend against the threats documented here. Level 1–3 implementations cover progressively fewer.

## 1. Scope and assumptions

This threat model covers the receipt-emission and receipt-verification path. It does NOT cover the agent runtime itself (LLM jailbreaks, prompt injection that produces a malicious-but-policy-permitted Action are agent-runtime threats, not receipt threats).

**Trust assumptions:**

- The runtime that emits receipts is **partially trusted**: it correctly implements the lifecycle and emits receipts, but it MAY be compromised by an attacker with code execution.
- The receipt store is **untrusted**: receipts MAY be modified, deleted, or forged by an attacker with write access.
- The policy store is **partially trusted**: policies MAY be modified, but old policy versions MUST be retained for receipt verification (a removed policy version invalidates all receipts referencing it).
- The auditor has **read-only access** to the receipt store and policy store at verification time.

## 2. Adversaries

Three adversaries:

### 2.1 Malicious agent

An agent (or the LLM driving it) attempts to take an Action it shouldn't. May try to:
- Bypass policy by misrepresenting arguments
- Forge approval (claim a human approved when one didn't)
- Replay a previous approval for a new Action
- Mutate arguments after approval

### 2.2 Compromised runtime

An attacker has gained code execution on the runtime emitting receipts. May try to:
- Emit fake receipts (Actions that never happened) to mask real malicious activity
- Suppress real receipts to hide malicious Actions
- Backdate receipts to predate detection windows
- Forge `receipt_hash` to mask tampering

### 2.3 Compromised receipt store

An attacker has write access to where receipts are stored. May try to:
- Modify existing receipts to whitewash bad Actions
- Insert fake receipts to manufacture compliance evidence
- Delete receipts to hide bad Actions
- Roll back the receipt store to a prior state

## 3. Threats and mitigations

Each threat is rated by its conformance-level coverage. Level 4 implementations defend against all listed threats.

### 3.1 T-01: Argument mutation after approval

**Description:** An agent obtains approval for arguments `A`, then submits arguments `A'` at execution time.

**Mitigation:** `arguments_hash` MUST be computed at policy-evaluation time and compared against arguments at execution time. Mismatch MUST cause the runtime to refuse execution and emit a `blocked` receipt.

**Defends at:** Level 4 (mutation defense is Level 4-specific).

### 3.2 T-02: Approval replay

**Description:** An attacker captures a valid `approval` block from one receipt and reuses it on a different Action.

**Mitigation:** The approval block MUST be cryptographically bound to the specific Action it approves. v0.1 binds via `arguments_hash` + `policy.name` + `policy.version` — the same approval cannot validly appear on two Actions with different argument hashes or policies. v0.2 candidate: explicit `approval.binding` field with a hash of the Action it approves.

**Defends at:** Level 4.

### 3.3 T-03: Unauthorized approver

**Description:** A user without authority to approve a given Action's capability submits an approval that the runtime accepts.

**Mitigation:** The policy MUST declare which approver identities (by `id` or `role`) are authorized to approve which capabilities. The runtime MUST verify `approval.approver.id` against the policy's authorized-approvers list at approval time. A receipt with an unauthorized approver MUST be rejected.

**Defends at:** Level 4.

### 3.4 T-04: Policy downgrade

**Description:** An attacker modifies the runtime to claim a more permissive policy decided an Action than actually did, or claims a policy version that doesn't exist.

**Mitigation:** The named, versioned policy referenced by `policy.name` + `policy.version` MUST exist in the policy store at receipt-verification time. An auditor MUST be able to retrieve the policy text and re-evaluate it against the Action's arguments. A receipt referencing a non-existent or modified policy MUST be invalid.

**Defends at:** Level 4.

### 3.5 T-05: Receipt tampering

**Description:** An attacker modifies a stored receipt to change recorded Action details.

**Mitigation:** `receipt_hash` MUST be SHA-256 of the canonicalized receipt content. Any field modification produces a hash mismatch that an auditor detects.

**Defends at:** Level 3 (receipt-hash verification is Level 3).

### 3.6 T-06: Receipt suppression

**Description:** A compromised runtime emits no receipt for a real Action, hiding it from audit.

**Mitigation:** This is partially out-of-scope for the receipt format itself — it's a runtime-integrity concern. However, the runtime MUST emit receipts for ALL Actions reaching the production action boundary (including denied ones), and the receipt store SHOULD support detection of gaps in receipt sequences (e.g., monotonic `receipt_id` ordering via UUID v7 or a separate sequence). Out-of-band monitoring (e.g., comparing tool-call counts in observability vs receipt counts in the store) MAY detect suppression.

**Defends at:** Implementation-defined; the spec provides receipt-emission requirements but cannot enforce them on a compromised runtime.

### 3.7 T-07: Receipt forgery (fake Action)

**Description:** An attacker with write access to the receipt store inserts receipts for Actions that never happened, to manufacture compliance evidence.

**Mitigation:** Receipts SHOULD be cryptographically signed by the runtime emitting them, with the runtime's signing key registered with the receipt store. Verifiers MUST reject receipts with invalid or missing signatures. v0.1 does NOT specify signing (deferred to v0.2); v0.1 implementations MAY add signatures as an extension.

**Defends at:** Implementation-defined for v0.1; v0.2 candidate.

### 3.8 T-08: Receipt deletion

**Description:** An attacker with write access deletes receipts to hide Actions.

**Mitigation:** Receipts SHOULD be stored in an append-only store. Detection of deletion requires out-of-band integrity mechanisms (e.g., periodic anchoring of receipt-store state to an external log). v0.1 does NOT specify deletion defenses; v0.2 candidate: integrate with append-only logging primitives.

**Defends at:** Implementation-defined; out-of-scope for receipt format.

### 3.9 T-09: Stale approval

**Description:** A long-running Action is approved, then waits beyond the approval's intended validity window, then executes.

**Mitigation:** The runtime MUST enforce a maximum lifetime for approvals (declared in the policy). A receipt with `approval.approved_at` more than the policy's stale-approval window before `execution.completed_at` MUST be rejected. The spec does not prescribe a specific window; the policy declares it.

**Defends at:** Level 4.

### 3.10 Summary

| Threat | Level 1 | Level 2 | Level 3 | Level 4 |
|---|---|---|---|---|
| T-01 Argument mutation | — | — | — | ✓ |
| T-02 Approval replay | — | — | — | ✓ |
| T-03 Unauthorized approver | — | — | — | ✓ |
| T-04 Policy downgrade | — | — | — | ✓ |
| T-05 Receipt tampering | — | — | ✓ | ✓ |
| T-06 Receipt suppression | — | — | — | impl-defined |
| T-07 Receipt forgery | — | — | — | v0.2 candidate |
| T-08 Receipt deletion | — | — | — | impl-defined |
| T-09 Stale approval | — | — | — | ✓ |

## 4. Out of scope

_Drafted in Task 9._
