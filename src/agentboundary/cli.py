"""agentboundary console-script entry point."""

from __future__ import annotations

import json as _json
import sys
import time
from pathlib import Path
from typing import Any

import click

from agentboundary import __version__
from agentboundary.conformance import check_conformance
from agentboundary.runtime import ReferenceImplementation, RuntimeOutcome
from agentboundary.scenarios import Scenario, load_scenario, load_scenarios_dir
from agentboundary.validator import validate_receipt


@click.group()
def main() -> None:
    """AgentBoundary v0.1 conformance runner.

    Run a single scenario:
        agentboundary run scenarios/01-merge-allow.yaml

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


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON.")
@click.option(
    "--implementation",
    default="reference",
    show_default=True,
    help="Implementation to test against (W3 only supports 'reference').",
)
def run(path: Path, as_json: bool, implementation: str) -> None:
    """Run one scenario file or every scenario in a directory."""
    if implementation != "reference":
        raise click.BadParameter(
            f"unknown implementation {implementation!r}; only 'reference' is supported in W3"
        )

    scenarios = load_scenarios_dir(path) if path.is_dir() else [load_scenario(path)]

    impl = ReferenceImplementation()
    results = [_run_one(s, impl) for s in scenarios]

    if as_json:
        click.echo(_json.dumps(_summarise(results)))
    else:
        click.echo(_format_matrix(results))

    sys.exit(0 if all(r["passed"] for r in results) else 1)


def _run_one(scenario: Scenario, impl: ReferenceImplementation) -> dict[str, Any]:
    start = time.perf_counter()
    failures: list[str] = []
    try:
        outcome: RuntimeOutcome = impl.attempt(scenario.action, setup=scenario.setup)
    except Exception as exc:
        # One misbehaving scenario must not kill the batch — surface it as a
        # per-scenario InternalError and let the rest run.
        return {
            "scenario": scenario.name,
            "passed": False,
            "failures": [f"InternalError: {exc}"],
            "duration_ms": int((time.perf_counter() - start) * 1000),
        }

    expect = scenario.expect

    # Always schema-validate so SCHEMA_INVALID can show up in actual_fail_codes
    # whether or not the scenario sets a conformance_level.
    schema_errors = validate_receipt(outcome.receipt or {})

    # Schema validation expectation
    if (
        expect.get("receipt_must_validate", True)
        and schema_errors
        and "SCHEMA_INVALID" not in expect.get("failures_must_include", [])
    ):
        failures.extend(f"unexpected schema error: {e}" for e in schema_errors)

    # Conformance expectation
    level = expect.get("conformance_level")
    checks: list[Any] = []
    if level is not None and outcome.receipt is not None:
        # Level 4 reads the matching policy and the prior-receipt set out of
        # setup so adversarial context lives next to the action. For L<=3 the
        # extras are inert.
        capability = scenario.action.get("tool", {}).get("capability")
        policy_full = next(
            (
                p
                for p in scenario.setup.get("policies", [])
                if capability in p.get("capabilities", [])
            ),
            None,
        )
        prior_receipt_ids = (
            set(scenario.setup["prior_receipt_ids"])
            if "prior_receipt_ids" in scenario.setup
            else None
        )
        policy_store = {
            (p["name"], p["version"]) for p in scenario.setup.get("policies", [])
        } or None
        checks = check_conformance(
            outcome.receipt,
            level=level,
            arguments=outcome.arguments,
            policy_full=policy_full,
            prior_receipt_ids=prior_receipt_ids,
            policy_store=policy_store,
        )

    required_codes = set(expect.get("failures_must_include", []))
    actual_fail_codes = {c.code for c in checks if c.severity == "fail"}
    if schema_errors:
        actual_fail_codes.add("SCHEMA_INVALID")

    # If receipt_must_validate is False, schema failure is expected behaviour.
    if not expect.get("receipt_must_validate", True) and "SCHEMA_INVALID" in required_codes:
        if "SCHEMA_INVALID" not in actual_fail_codes:
            failures.append("expected SCHEMA_INVALID but receipt validated")
        required_codes.discard("SCHEMA_INVALID")
        actual_fail_codes.discard("SCHEMA_INVALID")

    # Every required code must appear in actual failures.
    missing = required_codes - actual_fail_codes
    for code in sorted(missing):
        failures.append(f"expected failure code missing: {code}")

    # Codes that fired but weren't expected are surprises only when
    # failures_must_include is empty (positive scenario). For negative
    # scenarios that DID match their expected codes, extra codes are noise.
    if not required_codes:
        unexpected = actual_fail_codes
        for code in sorted(unexpected):
            failures.append(f"unexpected failure code: {code}")

    # Decision assertion
    if "decision" in expect and outcome.decision != expect["decision"]:
        failures.append(
            f"decision mismatch: expected {expect['decision']!r}, got {outcome.decision!r}"
        )

    # Field assertions
    for assertion in expect.get("assertions", []):
        value = _resolve_field(outcome.receipt or {}, assertion["field"])
        if value != assertion["equals"]:
            failures.append(
                f"assertion failed: {assertion['field']}={value!r} != {assertion['equals']!r}"
            )

    return {
        "scenario": scenario.name,
        "passed": not failures,
        "failures": failures,
        "duration_ms": int((time.perf_counter() - start) * 1000),
    }


def _resolve_field(obj: dict[str, Any], path: str) -> Any:
    cur: Any = obj
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _summarise(results: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "passed": sum(1 for r in results if r["passed"]),
        "failed": sum(1 for r in results if not r["passed"]),
        "results": results,
    }


def _format_matrix(results: list[dict[str, Any]]) -> str:
    lines = [
        f"AgentBoundary v0.1 conformance suite — {len(results)} scenarios",
        "",
    ]
    for r in results:
        status = "PASS" if r["passed"] else "FAIL"
        lines.append(f"  {status}  {r['scenario']:<40s}  {r['duration_ms']:>4d}ms")
        for f in r["failures"]:
            lines.append(f"        · {f}")
    passed = sum(1 for r in results if r["passed"])
    failed = sum(1 for r in results if not r["passed"])
    total = sum(r["duration_ms"] for r in results)
    lines.append("")
    lines.append(f"  {passed} passed · {failed} failed · {total}ms total")
    return "\n".join(lines)
