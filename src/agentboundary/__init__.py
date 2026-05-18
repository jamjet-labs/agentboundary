"""AgentBoundary — open spec and conformance suite for AI action control.

v0.0.1 ships the Action Receipt schema and validator. The CLI runner,
conformance test suite, and comparative report against major vendors are
on the project roadmap.

Top-level public API:

    >>> from agentboundary import validate_receipt, load_action_receipt_schema
    >>> errors = validate_receipt(receipt_dict)
    >>> schema = load_action_receipt_schema()
"""

from agentboundary._schema import load_action_receipt_schema
from agentboundary.validator import validate_receipt

__version__ = "0.0.2"

__all__ = [
    "__version__",
    "load_action_receipt_schema",
    "validate_receipt",
]
