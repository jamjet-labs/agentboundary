"""Verify the built wheel correctly bundles the schema and that an installed
package (NOT editable mode) can load the schema from the bundled resource path.

This test guards against silent regressions where pyproject.toml's
`force-include` block gets edited and the wheel ships without the
schema — `hatch test` (editable install) wouldn't catch it because the
loader falls back to the repo path.

Marked `slow`: skipped by default. Run explicitly with `hatch test -m slow`."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent


@pytest.mark.slow
def test_installed_wheel_loads_schema_from_bundled_resource(tmp_path: Path) -> None:
    """Build wheel -> install into clean venv -> import agentboundary -> load schema."""

    # 1. Build a fresh wheel into a temp outdir so we control exactly one .whl
    wheel_outdir = tmp_path / "wheel_build"
    wheel_outdir.mkdir()
    subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(wheel_outdir)],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
    )
    wheels = list(wheel_outdir.glob("*.whl"))
    assert len(wheels) == 1, f"Expected exactly one wheel; got {wheels}"
    wheel = wheels[0]

    # 2. Create a clean venv
    venv_dir = tmp_path / "venv"
    subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], check=True)
    venv_python = venv_dir / "bin" / "python"
    if not venv_python.exists():
        # Windows path
        venv_python = venv_dir / "Scripts" / "python.exe"

    # 3. Install the wheel into the venv (with extras so jsonschema format checkers are present)
    subprocess.run(
        [str(venv_python), "-m", "pip", "install", "--quiet", str(wheel)],
        check=True,
    )

    # 4. Run a subprocess that imports agentboundary, loads the schema, and prints the $id
    result = subprocess.run(
        [
            str(venv_python),
            "-c",
            "from agentboundary import load_action_receipt_schema; "
            "s = load_action_receipt_schema(); "
            "import json; print(json.dumps({'id': s['$id'], 'title': s['title']}))",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    output = json.loads(result.stdout)
    assert output["id"] == "https://agentboundary.dev/schemas/action-receipt-v0.1.json"
    assert output["title"] == "AgentBoundary Action Receipt v0.1"


@pytest.mark.slow
def test_installed_wheel_validates_a_receipt(tmp_path: Path) -> None:
    """Same setup as above, but also calls validate_receipt to confirm the full
    public API works from an installed wheel."""

    # Build wheel into a temp outdir
    wheel_outdir = tmp_path / "wheel_build"
    wheel_outdir.mkdir()
    subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(wheel_outdir)],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
    )
    wheels = list(wheel_outdir.glob("*.whl"))
    wheel = wheels[0]

    venv_dir = tmp_path / "venv"
    subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], check=True)
    venv_python = venv_dir / "bin" / "python"
    if not venv_python.exists():
        venv_python = venv_dir / "Scripts" / "python.exe"
    subprocess.run(
        [str(venv_python), "-m", "pip", "install", "--quiet", str(wheel)],
        check=True,
    )

    # Load the GitHub merge example from the bundled resource and validate
    result = subprocess.run(
        [
            str(venv_python),
            "-c",
            "import json\n"
            "from importlib import resources\n"
            "from agentboundary import validate_receipt\n"
            "receipt_text = resources.files('agentboundary._data.examples')"
            ".joinpath('github-merge.json').read_text()\n"
            "errors = validate_receipt(json.loads(receipt_text))\n"
            "print('errors:', errors)",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert "errors: []" in result.stdout, f"Expected no errors. Output: {result.stdout}"
