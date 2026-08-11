"""Tests for the standalone installed-distribution release smoke check."""

from importlib.metadata import version
from pathlib import Path
import subprocess
import sys


def test_distribution_smoke_script_exercises_installed_public_api(tmp_path: Path) -> None:
    script = Path(__file__).parents[2] / "scripts" / "verify_python_distribution.py"

    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--expected-version",
            version("agent-manifest"),
            "--forbidden-source-root",
            str(tmp_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert "verified agent-manifest" in completed.stdout
