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
from agentboundary.scenarios.envelope import envelope_failure_codes
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

    Verify receipts, envelopes or a chain offline:
        agentboundary verify receipt.json
        agentboundary verify --keys keys.jwks r1.cose r2.cose r3.cose
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
        minimum_completeness = scenario.setup.get("minimum_completeness")
        prior_receipt_hashes = scenario.setup.get("prior_receipt_hashes")
        checks = check_conformance(
            outcome.receipt,
            level=level,
            arguments=outcome.arguments,
            policy_full=policy_full,
            prior_receipt_ids=prior_receipt_ids,
            policy_store=policy_store,
            minimum_completeness=minimum_completeness,
            prior_receipt_hashes=prior_receipt_hashes,
        )

    required_codes = set(expect.get("failures_must_include", []))
    actual_fail_codes = {c.code for c in checks if c.severity == "fail"}
    if outcome.receipt is not None:
        actual_fail_codes |= envelope_failure_codes(
            scenario.setup, scenario.action, outcome.receipt
        )
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
        f"AgentBoundary conformance suite — {len(results)} scenarios",
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


@main.command()
@click.argument(
    "paths", nargs=-1, required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path)
)
@click.option(
    "--keys",
    "keys_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help=(
        "JWK Set of trusted Ed25519 public keys. Implies --require-signature. "
        "Without it, signatures are not checked."
    ),
)
@click.option(
    "--signed-statement",
    is_flag=True,
    help="Also require the RFC 9943 Signed Statement header shape (CWT iss/sub, protected kid).",
)
@click.option(
    "--require-signature",
    is_flag=True,
    help="Fail any receipt whose signature was not verified.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON.")
def verify(
    paths: tuple[Path, ...],
    keys_path: Path | None,
    signed_statement: bool,
    require_signature: bool,
    as_json: bool,
) -> None:
    """Verify receipts offline: hashes, canonical form, signatures, chain.

    Each PATH is a receipt JSON file, a JSON array of receipts, a .jsonl file,
    or a COSE_Sign1 envelope. Several receipts are checked as one chain in
    the order given. No network access; nothing is sent anywhere.

    Exit status: 0 when every check that ran passed, 1 when one failed,
    2 on a usage error (such as an unusable keyring).
    """
    from agentboundary.cose import KeyringError, load_keyring
    from agentboundary.hashing import StrictJSONError, parse_json_strict
    from agentboundary.verify import load_items, verify_items

    keyring = None
    if keys_path is not None:
        try:
            keyring = load_keyring(parse_json_strict(keys_path.read_bytes()))
        except (KeyringError, StrictJSONError) as exc:
            raise click.UsageError(f"--keys {keys_path}: {exc}") from exc

    items = load_items((str(p), p.read_bytes()) for p in paths)
    report = verify_items(
        items,
        keyring,
        as_signed_statement=signed_statement,
        require_signature=require_signature,
    )
    if as_json:
        click.echo(_json.dumps(report.to_dict(), indent=2))
    else:
        click.echo(_format_verify(report, keyring is not None))
    sys.exit(0 if report.ok else 1)


def _format_verify(report: Any, have_keys: bool) -> str:
    marks = {"pass": "PASS", "fail": "FAIL", "not_checked": "----"}
    lines = ["AgentBoundary offline verifier (no network access)", ""]
    if not have_keys:
        lines += ["No --keys given: signatures are reported as not checked.", ""]
    for r in report.receipts:
        rid = f"  receipt_id {r.receipt_id}" if r.receipt_id else ""
        lines.append(f"{r.source}  [{r.form}]{rid}")
        for c in r.checks:
            code = f"{c.code}: " if c.code else ""
            lines.append(f"  {marks[c.status]}  {c.name:<34s} {code}{c.detail}")
        lines.append("")
    lines.append(f"chain ({len(report.receipts)} item(s), in the order given)")
    for c in report.chain:
        code = f"{c.code}: " if c.code else ""
        lines.append(f"  {marks[c.status]}  {c.name:<34s} {code}{c.detail}")
    lines += ["", "Not checked by this verifier, whatever the input:"]
    lines += [f"  - {s}" for s in report.not_checked]
    failures = sum(
        1
        for c in [*report.chain, *(c for r in report.receipts for c in r.checks)]
        if c.status == "fail"
    )
    lines.append("")
    if report.ok:
        lines.append("Result: PASS (every check that ran passed; read 'not checked' above)")
    else:
        lines.append(f"Result: FAIL ({failures} failed check(s))")
    return "\n".join(lines)


@main.command()
@click.argument("receipt_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--key",
    "key_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Ed25519 private key as a JWK (from 'agentboundary keygen').",
)
@click.option(
    "-o",
    "--out",
    "out_path",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Where to write the envelope (default: RECEIPT_PATH + '.cose').",
)
@click.option("--issuer", help="CWT iss claim; with --subject, makes a Signed Statement shape.")
@click.option("--subject", help="CWT sub claim, e.g. the emitter's receipt stream id.")
def sign(
    receipt_path: Path,
    key_path: Path,
    out_path: Path | None,
    issuer: str | None,
    subject: str | None,
) -> None:
    """Wrap a receipt in a COSE_Sign1 envelope signed with Ed25519.

    Refuses a receipt that is not schema-valid or whose receipt_hash does
    not match, so a signature never vouches for a broken record.
    """
    from agentboundary.cose import KeyringError, load_private_jwk, sign_receipt
    from agentboundary.hashing import StrictJSONError, compute_receipt_hash, parse_json_strict

    if (issuer is None) != (subject is None):
        raise click.UsageError("--issuer and --subject go together")
    try:
        private_key, kid = load_private_jwk(parse_json_strict(key_path.read_bytes()))
    except (KeyringError, StrictJSONError) as exc:
        raise click.UsageError(f"--key {key_path}: {exc}") from exc
    try:
        receipt = parse_json_strict(receipt_path.read_bytes())
    except StrictJSONError as exc:
        click.echo(f"{receipt_path}: {exc}", err=True)
        sys.exit(1)
    if not isinstance(receipt, dict):
        click.echo(f"{receipt_path}: a receipt must be a JSON object", err=True)
        sys.exit(1)
    errors = validate_receipt(receipt)
    if errors:
        click.echo(f"{receipt_path}: not schema-valid, refusing to sign: {errors[0]}", err=True)
        sys.exit(1)
    if compute_receipt_hash(receipt) != receipt.get("receipt_hash"):
        click.echo(f"{receipt_path}: receipt_hash does not match, refusing to sign", err=True)
        sys.exit(1)
    envelope = sign_receipt(receipt, private_key, kid, issuer=issuer, subject=subject)
    target = out_path or receipt_path.with_name(receipt_path.name + ".cose")
    target.write_bytes(envelope)
    click.echo(f"wrote {target} ({len(envelope)} bytes, kid {kid!r})")


@main.command()
@click.option("--kid", required=True, help="Key identifier to embed in envelopes.")
@click.option(
    "--private",
    "private_path",
    required=True,
    type=click.Path(dir_okay=False, path_type=Path),
    help="Where to write the private JWK (created with mode 0600).",
)
@click.option(
    "--public",
    "public_path",
    required=True,
    type=click.Path(dir_okay=False, path_type=Path),
    help="Where to write the public JWK Set to hand to verifiers.",
)
def keygen(kid: str, private_path: Path, public_path: Path) -> None:
    """Generate an Ed25519 signing key (private JWK + public JWK Set)."""
    import os

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from agentboundary.cose import private_jwk, public_jwk

    if not kid:
        raise click.UsageError("--kid must be non-empty")
    if private_path.resolve() == public_path.resolve():
        raise click.UsageError("--private and --public must be different files")
    for p in (private_path, public_path):
        if p.exists():
            raise click.UsageError(f"{p} exists; refusing to overwrite")
    key = Ed25519PrivateKey.generate()
    # O_EXCL on both files: neither write may replace a file that appeared
    # after the checks above. If the public write fails, remove the private
    # key so no half-made key pair is left behind.
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(_json.dumps(private_jwk(key, kid), indent=2) + "\n")
    try:
        fd = os.open(public_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(_json.dumps({"keys": [public_jwk(key, kid)]}, indent=2) + "\n")
    except OSError as exc:
        private_path.unlink(missing_ok=True)
        raise click.ClickException(f"could not write {public_path}: {exc}") from exc
    click.echo(f"wrote {private_path} (private, keep it secret) and {public_path} (public)")
