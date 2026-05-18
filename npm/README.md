# agentboundary (npm)

Thin Node wrapper for the AgentBoundary conformance suite.

```bash
npx agentboundary run scenarios/
```

This package contains no conformance logic. It dispatches to the Python
implementation via the first runner it finds on PATH:

1. `uvx` (preferred — `curl -LsSf https://astral.sh/uv/install.sh | sh`)
2. `pipx`
3. `python3 -m agentboundary` (if installed in the active environment)

If none is available, you get an install hint pointing at `uv`.

The canonical implementation lives on PyPI as
[`agentboundary`](https://pypi.org/project/agentboundary/). Source code,
issue tracker, and documentation:
<https://github.com/jamjet-labs/agentboundary>.

License: Apache-2.0.
