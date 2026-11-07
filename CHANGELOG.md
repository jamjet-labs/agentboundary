# Changelog

Notable changes to the `agentboundary` package, the spec documents and the
conformance suite. Versions follow the git tags (`v0.2.0-alpha.1`, ...).

## Unreleased

### Conformance checks and suite

- Two Level 4 requirements of spec v0.1 section 5.4 had no check behind
  them. `check_conformance` now takes `executed_arguments` and reports
  `LEVEL_4_ARGUMENT_MUTATION` when the action ran with arguments other than
  the ones `arguments_hash` commits to, and takes `prior_approvals` (from
  the new `approval_fingerprint` to the `receipt_hash` that used it) and
  reports `LEVEL_4_APPROVAL_REPLAY` when an approval already used by another
  receipt appears again. An approval is identified by `approver.id`, the
  approval instant in UTC and `context`, so re-spelling the timestamp or
  adding a display name does not hide reuse. Each check has a
  `LEVEL_4_SKIPPED_*` marker when its context is missing.
- The stale-approval check passed an approval dated after the receipt.
  `LEVEL_4_FUTURE_DATED_APPROVAL` now fails an approval more than 60 seconds
  after `issued_at`, or one whose time cannot be read, and the window check
  fails closed on a window or timestamp it cannot evaluate. Timestamps are
  parsed as RFC 3339 allows (lowercase `t`/`z`, any fraction length), which
  `fromisoformat` on Python 3.10 did not.
- The reference runtime, in v0.2-alpha mode, refuses arguments that changed
  after policy evaluation (`action.executed_arguments` in a scenario;
  reason `arguments-mutated`) and refuses a forward-dated approval even when
  the policy has no approval window. `RuntimeOutcome` gains
  `executed_arguments`.
- `LEVEL_2_APPROVAL_REQUIRED` and `LEVEL_2_DECISION_INVALID` could never
  fire: the schema rejected the receipt first and the level codes were
  dropped. They are now reported next to `SCHEMA_INVALID`, as the Level 3
  hash codes already were.
- 21 new v0.2-alpha scenarios (55 to 75): receipt chains verified offline
  (`setup.chain`: intact, edited and rehashed, not from genesis, signer
  switch, deleted receipt, removed link, fork, duplicate, unreadable member,
  wrong receipt named), forward-dated approval, arguments changed after
  approval (run and refused), forward-dated approval refused by the
  runtime, approval reused and first use, approval
  removed, decision outside the enum, escalation that ran, link to an
  unknown receipt, and an omitted `receipt_hash`.
- Scenario 32 ("fork") was the same test as scenario 29. The verifier now
  also holds a sibling receipt newer than the shared ancestor, so a verifier
  that accepts a link only to its newest receipt fails it.
- `scripts/mutation_check.py` disables each conformance rule and each chain
  check in turn and runs both scenario directories; a CI job fails if any
  rule can be disabled without a scenario failing. On the previous main, 15
  of 30 mutants survived; now none do.
- The CLI runner and the test harness build the verifier context in one
  place (`agentboundary.scenarios.context`).
- README: the comparative matrix is described as what it is, a hand-written
  docs-only evaluation per vendor. `run --implementation` only runs the
  reference implementation.

### CI

- The 45 adapter smoke tests (`adapters/*/test_adapter.py`) now run in CI,
  in a job of their own. They need nothing beyond the package itself. Each
  adapter runs in its own pytest process because every adapter's module is
  named `adapter`. The job fails if an adapter directory has no tests.
