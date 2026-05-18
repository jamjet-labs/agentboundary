# Worked example Action Receipts

These are real-shaped Action Receipts you can read top-to-bottom to understand the v0.1 spec. Each one is also loaded by the test suite as a positive-path validation case, so they are guaranteed to round-trip cleanly against the schema at `docs/schemas/action-receipt-v0.1.json`.

| File | Capability | Policy decision | Why it's here |
|---|---|---|---|
| `github-merge.json` | `github.merge` | `allow` | An agent merging a PR under a permissive policy. Demonstrates the minimum receipt shape. |
| `spring-service-mutation.json` | `spring.service.mutation` | `require-approval` | An internal copilot updating an insurance claim. Demonstrates the `approval` block with approver identity + context. |
| `stripe-refund.json` | `stripe.refund` | `allow` | A support bot issuing a refund within an auto-approve limit. Demonstrates a different framework (OpenAI Agents SDK) and a different target system shape. |

## How to read a receipt

Every Action Receipt is independently verifiable. Given just the JSON file, an auditor can answer:

- **Who initiated the action?** Read `actor`. Was it a human, a system, or an agent?
- **Which agent ran?** Read `agent.framework` + `agent.model` + versions.
- **What did the action do?** Read `tool.capability` and `target.system` + `target.environment`.
- **What were the arguments?** Read `arguments_hash`. Compare against the canonicalized arguments stored in the system of record; if the hashes diverge, the executed action differs from what was approved.
- **What policy decided?** Read `policy.name` + `policy.version` + `policy.decision`.
- **If approval was required, who approved?** Read `approval.approver` + `approval.approved_at` + `approval.context`.
- **What was the outcome?** Read `execution.status` + `execution.completed_at`.
- **Is the receipt itself untampered?** Recompute `receipt_hash` over the canonicalized preceding fields; compare.

## How to add a new example

1. Write the receipt JSON to `docs/receipts/<short-name>.json`.
2. Add a corresponding positive-path test in `tests/test_validator_positive.py` that loads and validates it.
3. Add a row to the table above.
4. `hatch test` should pass.
5. Update `pyproject.toml`'s `[tool.hatch.build.targets.wheel.force-include]` block so the example ships in the wheel.
6. Commit with DCO sign-off (`git commit -s`).
