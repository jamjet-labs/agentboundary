# AgentBoundary

> An open spec and conformance suite for proving AI-initiated production actions.

**Status:** v0.0.1 — pre-launch. The full v0.1 specification, runner, and conformance test suite are under active development. This repo will be public at the W4 launch (planned 2026-06-15). Until then, the README intentionally does not pitch the project — the v4 operating memo at `jamjet-business/PM-MEMO-2026-05-18-v4.md` describes the launch surface.

## What's here today

- `docs/schemas/action-receipt-v0.1.json` — the Action Receipt JSON Schema (the spec authority)
- `docs/receipts/` — three worked example receipts (GitHub merge, Spring service mutation, Stripe refund)
- `src/agentboundary/` — Python package skeleton + validator
- `tests/` — pytest suite

## Run the tests

```bash
pip install hatch
hatch test
```

## Roadmap (this repo, next 12 weeks)

- W1 (this plan): schema + worked examples + validator
- W2: full spec text in `docs/spec/v0.1.md` + threat model + OWASP mapping
- W3: `agentboundary` CLI runner + first 10 conformance tests
- W4: public launch
- W5-W12: reference implementation + comparative runs vs Microsoft AGT, Statis, Cloudflare HITL, LangSmith Gateway, Anthropic Managed Agents

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All commits require DCO sign-off.
