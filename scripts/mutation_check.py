#!/usr/bin/env python3
"""Mutation check for the conformance suite.

For every rule, disable it in a copy of the package and run both scenario
directories with that copy. A rule no scenario notices is a rule the suite
does not test. The script exits 1 if any mutant survives, if the unmutated
copy fails a scenario (the control), or if a rule has no mutant.

Rules covered:

* every failing check site in ``conformance.py``, found by parsing the
  source, disabled by turning its severity from "fail" into "info";
* the chain checks of the offline verifier (``verify.py``), each disabled by
  an explicit edit below;
* the schema (``SCHEMA_INVALID``), disabled by making the validator accept
  everything, since the runner validates the schema itself as well;
* one over-strict mutant: a chain check that accepts a link only to the
  newest receipt the verifier holds (scenario 32, the fork case).

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


@dataclass(frozen=True)
class Mutant:
    id: str
    rule: str
    file: str  # path relative to src/agentboundary
    find: str
    replace: str

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
    return [SCHEMA_MUTANT, *conformance_site_mutants(), *CHAIN_MUTANTS, FORK_MUTANT]


def check_coverage(mutants: list[Mutant]) -> list[str]:
    """Rules with no mutant. Empty when every rule is covered."""
    covered = {m.rule for m in mutants}
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


def run_scenarios(mutant: Mutant | None) -> list[str]:
    """Names of the scenarios that fail against the (mutated) copy."""
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
            # A mutant that crashes the runner is noticed; report it as such.
            return [f"<runner crashed: {proc.stderr.strip().splitlines()[-1:]}>"]
        return list(json.loads(proc.stdout))


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

    control = run_scenarios(None)
    if control:
        print(f"CONTROL FAILED: the unmutated copy fails {control}")
        return 1
    print("control: every scenario passes on the unmutated copy")

    with ThreadPoolExecutor(max_workers=os.cpu_count() or 2) as pool:
        results = list(pool.map(run_scenarios, mutants))

    survivors = 0
    print()
    print(f"{'mutant':<45s} {'result':<9s} killed by")
    for m, failed in zip(mutants, results, strict=True):
        if failed:
            shown = ", ".join(failed[:3]) + (f" (+{len(failed) - 3})" if len(failed) > 3 else "")
            print(f"{m.id:<45s} {'killed':<9s} {shown}")
        else:
            survivors += 1
            print(f"{m.id:<45s} {'SURVIVED':<9s} no scenario noticed rule {m.rule}")
    print()
    print(f"{len(mutants)} mutants, {len(mutants) - survivors} killed, {survivors} survived")
    return 1 if survivors or problems else 0


if __name__ == "__main__":
    sys.exit(main())
