"""Locate and load the bundled Action Receipt JSON Schemas.

Schema files are the single source of truth for what an Action Receipt
must contain. They are bundled into the wheel via pyproject.toml's
`force-include` so installing the package always provides the schemas.

During local development (when the package is installed in editable mode),
the schemas are read from the repo's `docs/schemas/` directory.

Multiple schema versions are supported. ``load_action_receipt_schema()``
returns v0.1 (the stable default; preserved for backward compatibility).
``load_schema_for_version(version)`` routes by the receipt's ``version``
field so the validator can grade v0.1 and v0.2-alpha receipts side-by-side.
"""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

_BUNDLED_RESOURCE = "agentboundary._data"

# Map from receipt's `version` field literal -> bundled schema filename.
# Each entry MUST be a $id-matched JSON Schema document under docs/schemas/.
_SCHEMA_FILES: dict[str, str] = {
    "agentboundary/v0.1": "action-receipt-v0.1.json",
    "agentboundary/v0.2-alpha": "action-receipt-v0.2-alpha.json",
}

# Three parent traversals assume `_schema.py` lives at exactly
# `src/agentboundary/_schema.py`. If the package layout changes,
# update this traversal count.
_REPO_SCHEMAS_DIR = Path(__file__).parent.parent.parent / "docs" / "schemas"


@lru_cache(maxsize=1)
def load_action_receipt_schema() -> dict[str, Any]:
    """Return the v0.1 schema (backward-compatible default).

    Preserved as a top-level export because existing callers and external
    consumers reference it directly. For version-routed validation use
    ``load_schema_for_version``.
    """
    return load_schema_for_version("agentboundary/v0.1")


@lru_cache(maxsize=8)
def load_schema_for_version(version: str) -> dict[str, Any]:
    """Return the JSON Schema for the given receipt ``version`` literal.

    Raises ``ValueError`` if ``version`` is not a known schema version.
    Tries the installed wheel resource first; falls back to the repo path
    so the loader works in editable-install development.
    """
    filename = _SCHEMA_FILES.get(version)
    if filename is None:
        raise ValueError(
            f"Unknown receipt schema version {version!r}; known versions: {sorted(_SCHEMA_FILES)}"
        )
    try:
        resource = resources.files(_BUNDLED_RESOURCE).joinpath(filename)
        with resources.as_file(resource) as path:
            return _read_json(path)
    except (FileNotFoundError, ModuleNotFoundError):
        return _read_json(_REPO_SCHEMAS_DIR / filename)


def known_schema_versions() -> tuple[str, ...]:
    """All receipt schema versions this build of agentboundary recognises."""
    return tuple(sorted(_SCHEMA_FILES))


def _read_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise TypeError(f"Schema at {path} is not a JSON object")
    return data
