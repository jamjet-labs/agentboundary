"""Smoke test that the package imports and exposes a version."""

import agentboundary


def test_package_imports() -> None:
    assert agentboundary is not None


def test_package_exposes_version() -> None:
    assert hasattr(agentboundary, "__version__")
    assert isinstance(agentboundary.__version__, str)
    assert agentboundary.__version__ == "0.0.1"


def test_validate_receipt_is_importable_from_top_level() -> None:
    from agentboundary import validate_receipt
    assert callable(validate_receipt)


def test_load_action_receipt_schema_is_importable_from_top_level() -> None:
    from agentboundary import load_action_receipt_schema
    assert callable(load_action_receipt_schema)
