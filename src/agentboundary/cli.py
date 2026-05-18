"""agentboundary console-script entry point."""

from __future__ import annotations

import json as _json
import sys
from pathlib import Path

import click

from agentboundary import __version__
from agentboundary.validator import validate_receipt


@click.group()
def main() -> None:
    """AgentBoundary v0.1 conformance runner.

    Run a single scenario:
        agentboundary run examples/github-merge.yaml

    Run a directory of scenarios:
        agentboundary run scenarios/

    Validate an existing receipt JSON:
        agentboundary validate path/to/receipt.json
    """


@main.command()
def version() -> None:
    """Print the AgentBoundary version."""
    click.echo(f"agentboundary {__version__}")


@main.command()
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON.")
def validate(path: Path, as_json: bool) -> None:
    """Validate an Action Receipt JSON file against the v0.1 schema."""
    try:
        receipt = _json.loads(path.read_text("utf-8"))
    except _json.JSONDecodeError as exc:
        if as_json:
            click.echo(_json.dumps({"valid": False, "errors": [f"invalid JSON: {exc}"]}))
        else:
            click.echo(f"Invalid JSON: {exc}", err=True)
        sys.exit(1)

    errors = validate_receipt(receipt)
    if as_json:
        click.echo(_json.dumps({"valid": not errors, "errors": errors}))
    else:
        if errors:
            plural = "s" if len(errors) != 1 else ""
            click.echo(f"Receipt is INVALID ({len(errors)} error{plural}):")
            for e in errors:
                click.echo(f"  - {e}")
        else:
            click.echo("Receipt is valid against agentboundary/v0.1.")
    sys.exit(0 if not errors else 1)
