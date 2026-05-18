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

## Reporting issues

For schema or validator bugs in this release (v0.x), please open an issue with:

- The `agentboundary` version (`pip show agentboundary`)
- A minimal Action Receipt JSON that reproduces the bug
- Expected vs actual validator output
- Your environment (`uname -a`, `python --version`)

The CLI conformance runner and vendor-comparison mappings ship in a later release. Once they're available, this section will describe how to report bad mappings and how vendor maintainers can open `conformance-mapping-dispute` issues; for now those processes do not yet exist.
