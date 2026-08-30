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


def test_compare_json_reports_material_changes(tmp_path: Path) -> None:
    fixture = FIXTURES / "snapshots" / "complete.json"
    current: dict[str, Any] = json.loads(fixture.read_text(encoding="utf-8"))
    current["software"]["pending_updates"] = 0
    current_path = tmp_path / "current.json"
    current_path.write_text(json.dumps(current), encoding="utf-8")

    result = run_cli("compare", str(fixture), str(current_path), "--format", "json")

    document = json.loads(result.stdout)
    assert result.returncode == 0
    assert result.stderr == ""
    assert document["status"] == "changed"
    assert document["change_count"] == 1
    assert document["changes"][0] == {
        "after": 0,
        "before": 3,
        "category": "software",
        "key": "pending_updates",
        "kind": "changed",
    }


def test_compare_text_is_the_default_format(tmp_path: Path) -> None:
    fixture = FIXTURES / "snapshots" / "complete.json"
    current: dict[str, Any] = json.loads(fixture.read_text(encoding="utf-8"))
    current["software"]["enabled_services"].append("cron.service")
    current_path = tmp_path / "current.json"
    current_path.write_text(json.dumps(current), encoding="utf-8")

    result = run_cli("compare", str(fixture), str(current_path))

    assert result.returncode == 0
    assert "Snapshot comparison: changed (1 material change)" in result.stdout
    assert '[services] added "cron.service": null -> "enabled"' in result.stdout
    assert result.stderr == ""


@pytest.mark.parametrize(
    ("changed", "expected_exit_code"),
    [(False, 0), (True, 1)],
)
def test_compare_fail_on_changed_controls_exit_status(
    tmp_path: Path,
    changed: bool,
    expected_exit_code: int,
) -> None:
    fixture = FIXTURES / "snapshots" / "complete.json"
    current: dict[str, Any] = json.loads(fixture.read_text(encoding="utf-8"))
    if changed:
        current["software"]["reboot_required"] = True
    current_path = tmp_path / "current.json"
    current_path.write_text(json.dumps(current), encoding="utf-8")

    result = run_cli(
        "compare",
        str(fixture),
        str(current_path),
        "--fail-on",
        "changed",
    )

    assert result.returncode == expected_exit_code


def test_compare_host_mismatch_requires_cli_acknowledgement(tmp_path: Path) -> None:
    fixture = FIXTURES / "snapshots" / "complete.json"
    current: dict[str, Any] = json.loads(fixture.read_text(encoding="utf-8"))
    current["host"]["label"] = "demo-web-02"
    current_path = tmp_path / "current.json"
    current_path.write_text(json.dumps(current), encoding="utf-8")

    rejected = run_cli("compare", str(fixture), str(current_path))
    accepted = run_cli(
        "compare",
        str(fixture),
        str(current_path),
        "--allow-host-label-mismatch",
    )

    assert rejected.returncode == 2
    assert "host labels differ" in rejected.stderr
    assert accepted.returncode == 0
    assert "Snapshot comparison: unchanged" in accepted.stdout
