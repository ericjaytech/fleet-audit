from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[2]


def run_cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(PROJECT_ROOT / "src")
    return subprocess.run(
        [sys.executable, "-m", "fleet_audit", *arguments],
        check=False,
        capture_output=True,
        env=environment,
        text=True,
    )


def test_version_reports_program_name_and_release() -> None:
    result = run_cli("--version")

    assert result.returncode == 0
    assert result.stdout == "fleet-audit 0.1.0\n"
    assert result.stderr == ""


def test_help_describes_the_read_only_tool() -> None:
    result = run_cli("--help")

    assert result.returncode == 0
    assert "Read-only Linux inventory and configuration drift reporting." in result.stdout
    assert "--version" in result.stdout
    assert result.stderr == ""
