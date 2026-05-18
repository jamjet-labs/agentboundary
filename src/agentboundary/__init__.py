"""AgentBoundary — open spec and conformance suite for AI action control.

v0.0.1 ships the Action Receipt schema and validator. The CLI runner,
conformance test suite, and comparative report against major vendors are
on the project roadmap.

Top-level public API:

    >>> from agentboundary import validate_receipt, load_action_receipt_schema
    >>> errors = validate_receipt(receipt_dict)
    >>> schema = load_action_receipt_schema()
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

from agentboundary._schema import load_action_receipt_schema
from agentboundary.conformance import ConformanceCheck, check_conformance
from agentboundary.runtime import (
    Implementation,
    ReferenceImplementation,
    RuntimeOutcome,
)
from agentboundary.scenarios import Scenario, load_scenario, load_scenarios_dir
from agentboundary.validator import validate_receipt

try:
    __version__ = _pkg_version("agentboundary")
except PackageNotFoundError:  # editable/source tree before install
    __version__ = "0.0.0+unknown"

__all__ = [
    "ConformanceCheck",
    "Implementation",
    "ReferenceImplementation",
    "RuntimeOutcome",
    "Scenario",
    "__version__",
    "check_conformance",
    "load_action_receipt_schema",
    "load_scenario",
    "load_scenarios_dir",
    "validate_receipt",
]
