"""Smoke test that the package imports and exposes a version."""

import agentboundary


def test_package_imports() -> None:
    assert agentboundary is not None


def test_package_exposes_version() -> None:
    assert hasattr(agentboundary, "__version__")
    assert isinstance(agentboundary.__version__, str)
    assert agentboundary.__version__ == "0.0.1"
