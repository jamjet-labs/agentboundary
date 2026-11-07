"""The mutation check (scripts/mutation_check.py) must know every rule.

Running the mutants is a CI job of its own; this only checks, quickly, that
a rule added to conformance.py or to the chain checks gets a mutant.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "mutation_check.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("mutation_check", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["mutation_check"] = module
    spec.loader.exec_module(module)
    return module


def test_every_rule_has_a_mutant() -> None:
    mc = _load()
    assert mc.check_coverage(mc.all_mutants()) == []


def test_every_mutant_edit_applies_exactly_once() -> None:
    mc = _load()
    for m in mc.all_mutants():
        source = (mc.PKG / m.file).read_text("utf-8")
        assert m.apply(source) != source, m.id


def test_new_rules_are_in_the_mutant_set() -> None:
    rules = {m.rule for m in _load().all_mutants()}
    assert {
        "LEVEL_4_ARGUMENT_MUTATION",
        "LEVEL_4_APPROVAL_REPLAY",
        "LEVEL_4_FUTURE_DATED_APPROVAL",
        "CHAIN_NOT_FROM_GENESIS",
        "CHAIN_KEY_DISCONTINUITY",
    } <= rules
