"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def minimal_receipt() -> dict[str, object]:
    """A receipt that should pass validation with no optional fields."""
    return {
        "version": "agentboundary/v0.1",
        "receipt_id": "11111111-2222-4333-8444-555555555555",
        "issued_at": "2026-06-15T12:00:00Z",
        "actor": {"type": "human", "id": "u_alice"},
        "agent": {
            "framework": "jamjet",
            "framework_version": "0.8.5",
            "model": "claude-opus-4-7",
        },
        "tool": {"name": "github-mcp", "capability": "github.merge"},
        "target": {"system": "github.com/jamjet-labs/agentboundary", "environment": "prod"},
        "arguments_hash": "a" * 64,
        "policy": {"name": "prod-merges-require-approval", "version": "1", "decision": "allow"},
        "execution": {"status": "success", "completed_at": "2026-06-15T12:00:01Z"},
        "receipt_hash": "b" * 64,
    }


@pytest.fixture
def examples_dir() -> Path:
    """Path to the worked-example receipts shipped in docs/receipts/."""
    return Path(__file__).parent.parent / "docs" / "receipts"
