#!/usr/bin/env python3
"""Mutation check for the conformance suite.

For every rule, disable it in a copy of the package and run both scenario
directories with that copy. A rule no scenario notices is a rule the suite
does not test. The script exits 1 if any mutant survives, if the unmutated
copy fails a scenario (the control), or if a rule has no mutant.

Rule mutants (each must be caught by a scenario):

* every failing check site in ``conformance.py``, found by parsing the
  source, disabled by turning its severity from "fail" into "info";
* the chain checks of the offline verifier (``verify.py``), each disabled by
  an explicit edit below;
* the schema (``SCHEMA_INVALID``), disabled by making the validator accept
  everything, since the runner validates the schema itself as well;
* one over-strict mutant: a chain check that accepts a link only to the
  newest receipt the verifier holds (scenario 32, the fork case).

Condition mutants (each must be caught by a scenario or by the unit tests in
``UNIT_TESTS``): a rule that still runs but with a weakened condition, such
as a moved boundary, a narrower status scope, a fail-open path for an
unreadable value, or a field dropped from the approval fingerprint.

Usage::

    python scripts/mutation_check.py          # run, print a table
    python scripts/mutation_check.py --list   # list mutants without running

Runs on the source tree; nothing is installed or written outside a
temporary directory.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "src" / "agentboundary"
SCENARIO_DIRS = ("scenarios", "scenarios-v0.2-alpha")
UNIT_TESTS = (
    "tests/test_conformance.py",
    "tests/test_conformance_soundness.py",
    "tests/test_refusal.py",
    "tests/test_scenario_skips.py",
)
CRASHED = "<runner crashed> "


@dataclass(frozen=True)
class Mutant:
    id: str
    rule: str
    file: str  # path relative to src/agentboundary
    find: str
    replace: str
    kind: str = "rule"  # "rule": scenarios must catch it; "condition": scenarios or unit tests

    def apply(self, source: str) -> str:
        count = source.count(self.find)
        if count != 1:
            raise SystemExit(
                f"mutant {self.id}: expected the edit text exactly once in {self.file}, "
                f"found it {count} times; update scripts/mutation_check.py"
            )
        return source.replace(self.find, self.replace)


# Offline-verifier chain rules (verify.py). Each edit removes one rule.
CHAIN_MUTANTS: tuple[Mutant, ...] = (
    Mutant(
        "chain-genesis",
        "CHAIN_NOT_FROM_GENESIS",
        "verify.py",
        "    if first_prior is None:\n",
        "    if True:\n",
    ),
    Mutant(
        "chain-link-missing",
        "CHAIN_LINK_BROKEN",
        "verify.py",
        '            broken.append(f"{reports[i].source}: no prior_receipt")\n',
        "            pass\n",
    ),
    Mutant(
        "chain-link-id",
        "CHAIN_LINK_BROKEN",
        "verify.py",
        '        elif link.get("receipt_id") != prev.get("receipt_id"):\n',
        "        elif False:\n",
    ),
    Mutant(
        "chain-link-hash",
        "CHAIN_LINK_BROKEN",
        "verify.py",
        '        elif prev_hash is None or link.get("receipt_hash") != prev_hash:\n',
        "        elif False:\n",
    ),
    Mutant(
        "chain-unique-ids",
        "CHAIN_DUPLICATE_RECEIPT_ID",
        "verify.py",
        "    if dups:\n",
        "    if False:\n",
    ),
    Mutant(
        "chain-incomplete",
        "CHAIN_INCOMPLETE",
        "verify.py",
        "    if unreadable:\n",
        "    if False:\n",
    ),
    Mutant(
        "chain-signer-continuity",
        "CHAIN_KEY_DISCONTINUITY",
        "verify.py",
        "    if split:\n",
        "    if False:\n",
    ),
)

# Codes in verify.py that are not chain-integrity rules a scenario can reach.
CHAIN_EXEMPT = {
    "NO_RECEIPTS": "empty input; a scenario always presents a receipt (unit-tested)",
    "CHAIN_REQUIRED": "a --require outcome, not a chain rule; scenarios never set require",
}

SCHEMA_MUTANT = Mutant(
    "schema",
    "SCHEMA_INVALID",
    "validator.py",
    "    return [_format_error(err) for err in iter_schema_errors(receipt)]\n",
    "    return []\n",
)

# Over-strict: accept a link only to the newest receipt the verifier holds.
# A verifier built like a single "previous hash" log behaves this way and
# cannot accept a fork, which spec v0.2-alpha section 2.0 permits.
FORK_MUTANT = Mutant(
    "chain-fork-rejected",
    "fork tolerance (scenario 32)",
    "conformance.py",
    "                prior_receipt_hashes.get(claimed_id)"
    " if isinstance(claimed_id, str) else None\n",
    "                prior_receipt_hashes.get(claimed_id)\n"
    "                if claimed_id == list(prior_receipt_hashes)[-1]\n"
    "                else None\n",
)


def _cond(id: str, rule: str, file: str, find: str, replace: str) -> Mutant:
    return Mutant(id, rule, file, find, replace, kind="condition")


CONDITION_MUTANTS: tuple[Mutant, ...] = (
    _cond(
        "after-completion-boundary",
        "LEVEL_4_APPROVAL_AFTER_COMPLETION",
        "conformance.py",
        "    return _fraction(earlier) < _fraction(later)\n",
        "    return _fraction(earlier) <= _fraction(later)\n",
    ),
    _cond(
        "after-completion-ignores-sub-microsecond",
        "LEVEL_4_APPROVAL_AFTER_COMPLETION",
        "conformance.py",
        "    return _fraction(earlier) < _fraction(later)\n",
        "    return False\n",
    ),
    _cond(
        "after-completion-fails-open",
        "LEVEL_4_APPROVAL_AFTER_COMPLETION",
        "conformance.py",
        "        if before is not True:\n",
        "        if before is False:\n",
    ),
    _cond(
        "mutation-success-only",
        "LEVEL_4_ARGUMENT_MUTATION",
        "conformance.py",
        '    proceeded = execution_status in ("success", "failure")\n',
        '    proceeded = execution_status == "success"\n',
    ),
    _cond(
        "replay-exempt-by-id",
        "LEVEL_4_APPROVAL_REPLAY",
        "conformance.py",
        'used_by != receipt.get("receipt_hash")',
        'used_by != receipt.get("receipt_id")',
    ),
    _cond(
        "fingerprint-drops-context",
        "LEVEL_4_APPROVAL_REPLAY",
        "conformance.py",
        '        "context": approval.get("context"),\n',
        '        "context": None,\n',
    ),
    _cond(
        "fingerprint-raw-time",
        "LEVEL_4_APPROVAL_REPLAY",
        "conformance.py",
        '            stamp = instant.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")\n',
        "            stamp = raw_time\n",
    ),
    _cond(
        "window-fails-open",
        "LEVEL_4_STALE_APPROVAL",
        "conformance.py",
        '        return f"policy.approval_max_age_seconds={max_age!r} is not a finite, '
        'non-negative number"\n',
        "        return None\n",
    ),
    _cond(
        "window-boundary",
        "LEVEL_4_STALE_APPROVAL",
        "conformance.py",
        "    if age <= max_age:\n",
        "    if age < max_age:\n",
    ),
    _cond(
        "rfc3339-space-separator",
        "RFC 3339 parsing",
        "conformance.py",
        "([0-9]{2})[Tt]([0-9]{2})",
        "([0-9]{2})[Tt ]([0-9]{2})",
    ),
    _cond(
        "runtime-approval-at-now",
        "runtime approval-postdates-action",
        "runtime.py",
        "    if not age > 0:\n",
        "    if not age >= 0:\n",
    ),
    _cond(
        "runtime-postdates-disabled",
        "runtime approval-postdates-action",
        "runtime.py",
        "    if not age > 0:\n",
        "    if False:\n",
    ),
    _cond(
        "runtime-runs-changed-arguments",
        "runtime arguments-mutated",
        "runtime.py",
        "        if executed and mutated and emit_v02:\n",
        "        if False:\n",
    ),
    _cond(
        "skips-never-fail",
        "scenario skip rule",
        "scenarios/context.py",
        '    allowed = set(scenario.expect.get("allowed_skips", []))\n',
        "    return []\n",
    ),
)


def conformance_site_mutants() -> list[Mutant]:
    """One mutant per failing ConformanceCheck site in conformance.py."""
    path = PKG / "conformance.py"
    source = path.read_text("utf-8")
    lines = source.splitlines(keepends=True)
    mutants: list[Mutant] = []
    for node in ast.walk(ast.parse(source)):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "ConformanceCheck"
        ):
            continue
        kw = {k.arg: k.value for k in node.keywords}
        sev, code = kw.get("severity"), kw.get("code")
        if not (isinstance(sev, ast.Constant) and sev.value == "fail"):
            continue
        if not (isinstance(code, ast.Constant) and isinstance(code.value, str)):
            raise SystemExit(f"conformance.py:{node.lineno}: failing check with a non-literal code")
        if code.value == "SCHEMA_INVALID":
            continue  # the runner validates the schema too; see SCHEMA_MUTANT
        # The whole call (message and field included) is unique to its site.
        find = "".join(lines[node.lineno - 1 : node.end_lineno])
        if find.count('"fail"') != 1:
            raise SystemExit(f"conformance.py:{sev.lineno}: cannot isolate the severity")
        mutants.append(
            Mutant(
                f"{code.value}@{sev.lineno}",
                code.value,
                "conformance.py",
                find,
                find.replace('"fail"', '"info"'),
            )
        )
    return mutants


def all_mutants() -> list[Mutant]:
    return [
        SCHEMA_MUTANT,
        *conformance_site_mutants(),
        *CHAIN_MUTANTS,
        FORK_MUTANT,
        *CONDITION_MUTANTS,
    ]


def check_coverage(mutants: list[Mutant]) -> list[str]:
    """Rules with no mutant. Empty when every rule is covered."""
    covered = {m.rule for m in mutants if m.kind == "rule"}
    problems = []
    conformance = (PKG / "conformance.py").read_text("utf-8")
    for code in sorted(set(re.findall(r'code="([A-Z0-9_]+)"', conformance))):
        if "SKIPPED" in code or "NOT_APPLICABLE" in code:
            continue  # info markers, not rules
        if code not in covered:
            problems.append(f"conformance.py rule {code} has no mutant")
    verify = (PKG / "verify.py").read_text("utf-8")
    for code in sorted(set(re.findall(r'"(CHAIN_[A-Z_]+|NO_RECEIPTS)"', verify))):
        if code not in covered and code not in CHAIN_EXEMPT:
            problems.append(f"verify.py rule {code} has no mutant")
    return problems


def _copy_tree(dest: Path, mutant: Mutant | None) -> Path:
    src = dest / "src"
    shutil.copytree(PKG, src / "agentboundary", ignore=shutil.ignore_patterns("__pycache__"))
    # _schema.py falls back to <src>/../docs/schemas when the package is not
    # installed from a wheel.
    (dest / "docs").symlink_to(ROOT / "docs", target_is_directory=True)
    if mutant is not None:
        target = src / "agentboundary" / mutant.file
        target.write_text(mutant.apply(target.read_text("utf-8")), "utf-8")
    return src


def run_scenarios(mutant: Mutant | None, *, unit_tests: bool = False) -> list[str]:
    """What fails against the (mutated) copy: scenario names, then, when
    ``unit_tests`` is set and no scenario failed, ``unit tests`` if any of
    UNIT_TESTS fails."""
    with tempfile.TemporaryDirectory(prefix="ab-mutant-") as tmp:
        src = _copy_tree(Path(tmp), mutant)
        env = {**os.environ, "PYTHONPATH": str(src), "PYTHONDONTWRITEBYTECODE": "1"}
        proc = subprocess.run(
            [sys.executable, __file__, "--worker", str(src)],
            capture_output=True,
            text=True,
            env=env,
            cwd=ROOT,
            timeout=300,
        )
        if proc.returncode != 0:
            # A crash is not a scenario catching the mutant; reported apart.
            tail = proc.stderr.strip().splitlines()[-1:] or ["no output"]
            return [f"{CRASHED}{tail[0]}"]
        failed = list(json.loads(proc.stdout))
        if failed or not unit_tests:
            return failed
        tests = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", *UNIT_TESTS],
            capture_output=True,
            text=True,
            env=env,
            cwd=ROOT,
            timeout=300,
        )
        # pytest exit 1 means tests failed; anything else (2-5) is a usage
        # or collection problem, which must not count as a kill.
        if tests.returncode == 1:
            return ["unit tests"]
        if tests.returncode != 0:
            return [f"{CRASHED}pytest exited {tests.returncode}"]
        return []


def worker(src: str) -> int:
    import agentboundary
    from agentboundary.cli import _run_one
    from agentboundary.runtime import ReferenceImplementation
    from agentboundary.scenarios import load_scenarios_dir

    if not Path(agentboundary.__file__).resolve().is_relative_to(Path(src).resolve()):
        print(f"imported {agentboundary.__file__}, not the copy in {src}", file=sys.stderr)
        return 2
    impl = ReferenceImplementation()
    failed = []
    for d in SCENARIO_DIRS:
        for scenario in load_scenarios_dir(ROOT / d):
            if not _run_one(scenario, impl)["passed"]:
                failed.append(scenario.name)
    print(json.dumps(failed))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--worker", metavar="SRC", help=argparse.SUPPRESS)
    parser.add_argument("--list", action="store_true", help="list mutants and exit")
    args = parser.parse_args()
    if args.worker:
        return worker(args.worker)

    mutants = all_mutants()
    if args.list:
        for m in mutants:
            print(f"{m.id:<45s} {m.rule}")
        return 0

    problems = check_coverage(mutants)
    for p in problems:
        print(f"UNCOVERED  {p}")

    control = run_scenarios(None, unit_tests=True)
    if control:
        print(f"CONTROL FAILED: the unmutated copy fails {control}")
        return 1
    print("control: every scenario and unit test passes on the unmutated copy")

    def run(m: Mutant) -> list[str]:
        return run_scenarios(m, unit_tests=m.kind == "condition")

    with ThreadPoolExecutor(max_workers=os.cpu_count() or 2) as pool:
        results = list(pool.map(run, mutants))

    survivors = crashed = 0
    print()
    print(f"{'mutant':<45s} {'result':<9s} killed by")
    for m, failed in zip(mutants, results, strict=True):
        if failed and failed[0].startswith(CRASHED):
            crashed += 1
            print(f"{m.id:<45s} {'CRASHED':<9s} {failed[0][len(CRASHED) :]}")
        elif failed:
            shown = ", ".join(failed[:3]) + (f" (+{len(failed) - 3})" if len(failed) > 3 else "")
            print(f"{m.id:<45s} {'killed':<9s} {shown}")
        else:
            survivors += 1
            print(f"{m.id:<45s} {'SURVIVED':<9s} no scenario noticed rule {m.rule}")
    killed = len(mutants) - survivors - crashed
    print()
    print(
        f"{len(mutants)} mutants, {killed} killed, {survivors} survived, "
        f"{crashed} crashed the runner"
    )
    return 1 if survivors or crashed or problems else 0


if __name__ == "__main__":
    sys.exit(main())
