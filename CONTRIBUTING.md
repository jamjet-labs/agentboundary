# Contributing to AgentBoundary

Thanks for your interest. AgentBoundary is an open spec + conformance suite for controlling AI-initiated production actions. Contributions of any size welcome.

## Developer Certificate of Origin (DCO)

Every commit must include a `Signed-off-by` line. This is the [Developer Certificate of Origin](https://developercertificate.org/) — a lightweight alternative to a CLA. By signing off, you certify the contribution is yours to submit under this project's license.

To sign off a commit, use `git commit -s`. It appends:

```
Signed-off-by: Your Name <your.email@example.com>
```

The `Name` and `Email` must match your git config.

If you forgot to sign off, amend the most recent commit with `git commit --amend -s --no-edit`.

## License

By contributing you agree that your work will be released under the [Apache License 2.0](LICENSE).

## Development setup

Install [hatch](https://hatch.pypa.io/):

```bash
pip install hatch
```

Run the test suite:

```bash
hatch test
```

Run lint + types (matches CI):

```bash
hatch run lint:style
hatch run lint:fmt --check
hatch run lint:type
```

## Reporting bad mappings or test errors

If you ran the conformance suite against a vendor and the result looks wrong, please open an issue with:

- Vendor + version
- The exact `agentboundary` command you ran
- Expected vs actual output
- Your environment (`uname -a`, `python --version`)

If you maintain a vendor product and disagree with a conformance mapping, please open an issue tagged `conformance-mapping-dispute`. We respond within 7 days. We will publish a correction if the mapping is wrong, or add a note if it depends on configuration we missed.
