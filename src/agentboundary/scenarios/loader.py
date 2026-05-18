"""YAML scenario loader with meta-schema validation."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any, cast

import yaml
from jsonschema import Draft202012Validator

_META_SCHEMA_FILENAME = "_meta-schema.json"


def _load_meta_schema() -> dict[str, Any]:
    """Read the bundled scenario meta-schema as JSON."""
    pkg = resources.files("agentboundary.scenarios")
    return cast(
        dict[str, Any],
        json.loads(pkg.joinpath(_META_SCHEMA_FILENAME).read_text("utf-8")),
    )


_META_VALIDATOR = Draft202012Validator(
    _load_meta_schema(),
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)


@dataclass(frozen=True)
class Scenario:
    """A loaded scenario file ready to be executed."""

    name: str
    description: str
    setup: dict[str, Any]
    action: dict[str, Any]
    expect: dict[str, Any]
    path: Path = field(compare=False)


def load_scenario(path: Path) -> Scenario:
    """Load and meta-validate one scenario file."""
    try:
        raw = yaml.safe_load(Path(path).read_text("utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(f"{path}: invalid YAML: {exc}") from exc

    if not isinstance(raw, dict):
        raise ValueError(f"{path}: top level must be a mapping")

    errors = sorted(_META_VALIDATOR.iter_errors(raw), key=lambda e: e.path)
    if errors:
        bullets = "\n  - ".join(
            f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}" for e in errors
        )
        raise ValueError(f"{path}: scenario fails meta-schema:\n  - {bullets}")

    return Scenario(
        name=raw["name"],
        description=raw.get("description", ""),
        setup=raw["setup"],
        action=raw["action"],
        expect=raw["expect"],
        path=Path(path),
    )


def load_scenarios_dir(path: Path) -> list[Scenario]:
    """Load every ``*.yaml`` in ``path`` (recursive). Skips underscore-prefixed files."""
    base = Path(path)
    files = sorted(f for f in base.rglob("*.yaml") if not f.name.startswith("_"))
    return [load_scenario(f) for f in files]
