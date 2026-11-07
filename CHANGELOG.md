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
  approval instant in UTC (microsecond precision) and `context`, defined in
  v0.2-alpha section 5.6 with its limits, so re-spelling the timestamp or
  adding a display name does not hide reuse. Each check has a
  `LEVEL_4_SKIPPED_*` marker when its context is missing.
- The stale-approval check passed an approval dated after the receipt.
  `LEVEL_4_APPROVAL_AFTER_COMPLETION` now enforces v0.1 sections 2.7 and
  3.4: `approval.approved_at` must be strictly before
  `execution.completed_at`, with no skew allowance, and an unreadable time
  fails. The stale window is measured to `execution.completed_at` (threat
  T-09) instead of `issued_at`, and fails closed on a window or timestamp it
  cannot evaluate. Timestamps are parsed as strict ASCII RFC 3339
  (lowercase `t`/`z` and any fraction length accepted; a space separator,
  non-ASCII digits and out-of-range offsets refused).
- `agentboundary verify` runs these Level 4 checks too, so a receipt whose
  approval is dated at or after its completion now fails `verify`.
- The reference runtime, in v0.2-alpha mode, refuses arguments that changed
  after policy evaluation (`action.executed_arguments` in a scenario;
  reason `arguments-mutated`) and refuses an approval dated at or after its
  clock, window or not (it used to allow 60 seconds). `RuntimeOutcome` gains
  `executed_arguments`.
- `LEVEL_2_APPROVAL_REQUIRED` and `LEVEL_2_DECISION_INVALID` could never
  fire: the schema rejected the receipt first and the level codes were
  dropped. They are now reported next to `SCHEMA_INVALID`, as the Level 3
  hash codes already were.
- 21 new v0.2-alpha scenarios (55 to 75): receipt chains verified offline
  (`setup.chain`: intact, edited and rehashed, not from genesis, signer
  switch, deleted receipt, removed link, fork, duplicate, unreadable member,
  wrong receipt named), approval dated after completion, arguments changed
  after approval (run and refused), a future approval refused by the
  runtime, approval reused and first use, approval removed, decision outside
  the enum, escalation that ran, link to an unknown receipt, and an omitted
  `receipt_hash`.
- Scenario 32 ("fork") was the same test as scenario 29. The verifier now
  also holds a sibling receipt newer than the shared ancestor, so a verifier
  that accepts a link only to its newest receipt fails it.
- `scripts/mutation_check.py` disables each conformance rule and each chain
  check in turn and runs both scenario directories; a CI job fails if any
  rule can be disabled without a scenario failing. On the previous main, 15
  of 30 mutants survived; now none do. It also weakens conditions (moved
  boundaries, a narrower status scope, fail-open paths, a field dropped from
  the approval fingerprint, runtime refusals) and requires a scenario or a
  unit test to catch each: 44 mutants, all caught.
- `agentboundary run` shows the checks each scenario skipped (text and
  `--json`). A scenario's verifier treats records its setup does not list
  as empty rather than missing, so the replay and receipt-id checks run in
  every scenario. A Level 4 scenario that expects no failure fails on any
  skip it does not list in the new `expect.allowed_skips`.
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
