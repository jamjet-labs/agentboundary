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

_Drafted in Task 8._

## 4. Out of scope

_Drafted in Task 9._
