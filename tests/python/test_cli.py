from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from fleet_audit import cli

PROJECT_ROOT = Path(__file__).parents[2]
FIXTURES = PROJECT_ROOT / "tests" / "fixtures"


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


def test_collect_help_documents_policy_input() -> None:
    result = run_cli("collect", "--help")

    assert result.returncode == 0
    assert "--policy POLICY" in result.stdout


def test_invalid_policy_fails_before_collection(tmp_path: Path) -> None:
    policy_path = tmp_path / "invalid.toml"
    policy_path.write_text("version = [", encoding="utf-8")
    output_path = tmp_path / "snapshot.json"

    result = run_cli(
        "collect",
        "--policy",
        str(policy_path),
        "--output",
        str(output_path),
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert "invalid TOML policy" in result.stderr
    assert not output_path.exists()


def test_collect_attaches_policy_results_before_writing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = FIXTURES / "snapshots" / "complete.json"
    snapshot: dict[str, Any] = json.loads(fixture.read_text(encoding="utf-8"))
    policy_path = tmp_path / "policy.toml"
    policy_path.write_text(
        """
version = 1
[[checks]]
id = "updates.pending"
type = "pending_updates"
warn_count = 1
fail_count = 20
""",
        encoding="utf-8",
    )
    output_path = tmp_path / "snapshot.json"
    monkeypatch.setattr(cli, "collect_snapshot", lambda *, label: snapshot)

    exit_code = cli.main(
        [
            "collect",
            "--policy",
            str(policy_path),
            "--output",
            str(output_path),
        ]
    )

    written_snapshot = json.loads(output_path.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert written_snapshot["checks"] == [
        {
            "evidence": "3 pending; warning threshold 1; failure threshold 20.",
            "id": "updates.pending",
            "status": "WARN",
            "summary": "Pending updates reached the warning threshold.",
        }
    ]
