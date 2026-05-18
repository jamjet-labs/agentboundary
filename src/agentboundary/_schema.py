"""Locate and load the bundled Action Receipt JSON Schema.

The schema file is the single source of truth for what an Action Receipt
must contain. It is bundled into the wheel via pyproject.toml's
`force-include` so installing the package always provides the schema.

During local development (when the package is installed in editable mode),
the schema is read from the repo's `docs/schemas/` directory.
"""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

_BUNDLED_RESOURCE = "agentboundary._data"
_BUNDLED_FILENAME = "action-receipt-v0.1.json"
# Three parent traversals assume `_schema.py` lives at exactly
# `src/agentboundary/_schema.py`. If the package layout changes,
# update this traversal count.
_REPO_RELATIVE_PATH = Path(__file__).parent.parent.parent / "docs" / "schemas" / _BUNDLED_FILENAME


@lru_cache(maxsize=1)
def load_action_receipt_schema() -> dict[str, Any]:
    """Return the Action Receipt v0.1 JSON Schema as a dict.

    Tries the installed wheel resource first; falls back to the repo path
    so the loader works in editable-install development.
    """
    try:
        resource = resources.files(_BUNDLED_RESOURCE).joinpath(_BUNDLED_FILENAME)
        with resources.as_file(resource) as path:
            return _read_json(path)
    except (FileNotFoundError, ModuleNotFoundError):
        return _read_json(_REPO_RELATIVE_PATH)


def _read_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise TypeError(f"Schema at {path} is not a JSON object")
    return data
