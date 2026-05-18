"""Tests for the schema loader. The loader's job is exactly one thing:
locate and return the bundled Action Receipt v0.1 JSON Schema."""

from agentboundary._schema import load_action_receipt_schema


def test_load_action_receipt_schema_returns_dict() -> None:
    schema = load_action_receipt_schema()
    assert isinstance(schema, dict)


def test_schema_has_expected_id() -> None:
    schema = load_action_receipt_schema()
    assert schema["$id"] == "https://agentboundary.dev/schemas/action-receipt-v0.1.json"


def test_schema_has_expected_title() -> None:
    schema = load_action_receipt_schema()
    assert schema["title"] == "AgentBoundary Action Receipt v0.1"


def test_schema_is_idempotent_across_calls() -> None:
    """Two calls return the same content (loader may cache or re-read; both fine)."""
    first = load_action_receipt_schema()
    second = load_action_receipt_schema()
    assert first == second
