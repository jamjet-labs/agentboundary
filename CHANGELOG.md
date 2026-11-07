# Changelog

Notable changes to the `agentboundary` package, the spec documents and the
conformance suite. Versions follow the git tags (`v0.2.0-alpha.1`, ...).

## Unreleased

### CI

- The 45 adapter smoke tests (`adapters/*/test_adapter.py`) now run in CI,
  in a job of their own. They need nothing beyond the package itself. Each
  adapter runs in its own pytest process because every adapter's module is
  named `adapter`. The job fails if an adapter directory has no tests.
