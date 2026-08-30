from __future__ import annotations

import json
import os
import shlex
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from fleet_audit.collection import collect_snapshot
from fleet_audit.collection.runner import CollectorStatus, run_collector
from fleet_audit.collection.workspace import secure_workspace
from fleet_audit.validation import validate_snapshot

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


def write_collector(directory: Path, body: str, filename: str = "collector.sh") -> Path:
    collector = directory / filename
    collector.write_text("#!/usr/bin/env bash\nset -u\n" + body, encoding="utf-8")
    return collector


def test_workspace_is_private_and_removed_after_success(tmp_path: Path) -> None:
    with secure_workspace(parent=tmp_path) as workspace:
        workspace_path = workspace
        mode = stat.S_IMODE(workspace.stat().st_mode)

        assert mode == 0o700
        assert workspace.parent == tmp_path

    assert not workspace_path.exists()


def test_workspace_is_removed_after_exception(tmp_path: Path) -> None:
    workspace_path: Path | None = None

    with pytest.raises(RuntimeError, match="parser failed"):
        with secure_workspace(parent=tmp_path) as workspace:
            workspace_path = workspace
            raise RuntimeError("parser failed")

    assert workspace_path is not None
    assert not workspace_path.exists()


@pytest.mark.parametrize(
    ("exit_code", "expected_status"),
    [
        (0, CollectorStatus.AVAILABLE),
        (10, CollectorStatus.UNAVAILABLE),
        (7, CollectorStatus.ERROR),
    ],
)
def test_collector_exit_codes_have_distinct_states(
    tmp_path: Path,
    exit_code: int,
    expected_status: CollectorStatus,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    collector = write_collector(tmp_path, f"exit {exit_code}\n")

    result = run_collector("stub", collector, workspace, timeout_seconds=1)

    assert result.name == "stub"
    assert result.status is expected_status
    assert result.exit_code == exit_code


def test_collector_timeout_is_an_error(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    collector = write_collector(tmp_path, "sleep 1\n")

    result = run_collector("stub", collector, workspace, timeout_seconds=0.01)

    assert result.status is CollectorStatus.ERROR
    assert result.exit_code is None
    assert result.detail == "Collector exceeded its 0.01 second timeout."


def test_collector_timeout_terminates_background_children(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    marker = tmp_path / "late-write"
    collector = write_collector(
        tmp_path,
        f"(sleep 0.1; printf late > {shlex.quote(str(marker))}) &\nwait\n",
    )

    result = run_collector("stub", collector, workspace, timeout_seconds=0.01)
    time.sleep(0.2)

    assert result.status is CollectorStatus.ERROR
    assert not marker.exists()


def test_timeout_snapshot_preserves_error_and_removes_workspace(tmp_path: Path) -> None:
    collector = write_collector(tmp_path, "sleep 1\n")

    snapshot = collect_snapshot(
        label="test-host",
        collector_paths={"platform": collector},
        timeout_seconds=0.01,
        workspace_parent=tmp_path,
    )

    assert snapshot["collection"]["capabilities"] == [
        {
            "name": "platform",
            "status": "error",
            "detail": "Collector exceeded its 0.01 second timeout.",
        }
    ]
    assert list(tmp_path.glob("fleet-audit-*")) == []


def test_parser_failure_removes_collection_workspace(tmp_path: Path) -> None:
    collector = write_collector(
        tmp_path,
        'printf "not-an-assignment\\n" > "${1}/os-release"\n'
        'printf "6.8.0\\n" > "${1}/kernel"\n'
        'printf "x86_64\\n" > "${1}/architecture"\n'
        'printf "1.0 2.0\\n" > "${1}/uptime"\n',
    )

    snapshot = collect_snapshot(
        label="test-host",
        collector_paths={"platform": collector},
        workspace_parent=tmp_path,
    )

    assert snapshot["platform"] == {"status": "unavailable"}
    assert snapshot["collection"]["capabilities"] == [
        {
            "name": "platform",
            "status": "error",
            "detail": "Collector output was invalid: invalid os-release assignment at line 1.",
        }
    ]
    assert snapshot["collection"]["warnings"][0]["code"] == "COLLECTOR_OUTPUT_INVALID"
    assert list(tmp_path.glob("fleet-audit-*")) == []


def test_hardware_parser_failure_preserves_successful_platform_data(tmp_path: Path) -> None:
    platform_collector = write_collector(
        tmp_path,
        'printf \'ID=test\\nVERSION_ID="1"\\nPRETTY_NAME="Test Linux"\\n\' > "${1}/os-release"\n'
        'printf "6.8.0\\n" > "${1}/kernel"\n'
        'printf "x86_64\\n" > "${1}/architecture"\n'
        'printf "1.0 2.0\\n" > "${1}/uptime"\n',
        "platform.sh",
    )
    hardware_collector = write_collector(
        tmp_path,
        'printf "processor : 0\\nmodel name : Test CPU\\n" > "${1}/cpuinfo"\n'
        'printf "MemTotal: invalid\\n" > "${1}/meminfo"\n'
        'printf "1\\n" > "${1}/logical-processors"\n',
        "hardware.sh",
    )

    snapshot = collect_snapshot(
        label="test-host",
        collector_paths={
            "platform": platform_collector,
            "hardware": hardware_collector,
        },
        workspace_parent=tmp_path,
    )

    assert snapshot["platform"]["status"] == "complete"
    assert snapshot["hardware"] == {"status": "unavailable"}
    assert snapshot["collection"]["capabilities"] == [
        {"name": "platform", "status": "available"},
        {
            "name": "hardware",
            "status": "error",
            "detail": "Collector output was invalid: invalid MemTotal value; expected kB.",
        },
    ]
    assert snapshot["collection"]["warnings"] == [
        {
            "collector": "hardware",
            "code": "COLLECTOR_OUTPUT_INVALID",
            "message": "Collector output was invalid: invalid MemTotal value; expected kB.",
        }
    ]


def test_collect_command_writes_valid_owner_only_snapshot(tmp_path: Path) -> None:
    output = tmp_path / "snapshot.json"

    result = run_cli("collect", "--label", "demo-host", "--output", str(output))

    assert result.returncode == 0
    assert result.stdout == f"Snapshot written to {output}\n"
    assert result.stderr == ""
    assert stat.S_IMODE(output.stat().st_mode) == 0o600

    snapshot = json.loads(output.read_text(encoding="utf-8"))
    validate_snapshot(snapshot)
    assert snapshot["host"] == {"label": "demo-host"}
    assert snapshot["platform"]["status"] == "complete"
    assert snapshot["platform"]["os"]["id"]
    assert snapshot["platform"]["kernel"]
    assert snapshot["platform"]["architecture"]
    assert snapshot["platform"]["uptime_seconds"] >= 0
    assert snapshot["hardware"]["status"] in {"complete", "partial"}
    assert snapshot["hardware"]["cpu"]["logical_processors"] >= 1
    assert snapshot["hardware"]["memory_bytes"] > 0
    assert snapshot["collection"]["capabilities"] == [
        {"name": "platform", "status": "available"},
        {"name": "hardware", "status": "available"},
    ]


def test_collect_command_does_not_overwrite_existing_file(tmp_path: Path) -> None:
    output = tmp_path / "snapshot.json"
    output.write_text("keep me", encoding="utf-8")

    result = run_cli("collect", "--output", str(output))

    assert result.returncode == 2
    assert result.stdout == ""
    assert "already exists" in result.stderr
    assert output.read_text(encoding="utf-8") == "keep me"


def test_collect_command_does_not_follow_output_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("keep target", encoding="utf-8")
    output = tmp_path / "snapshot.json"
    output.symlink_to(target)

    result = run_cli("collect", "--output", str(output))

    assert result.returncode == 2
    assert "already exists" in result.stderr
    assert target.read_text(encoding="utf-8") == "keep target"


def test_validate_command_accepts_valid_snapshot() -> None:
    fixture = PROJECT_ROOT / "tests" / "fixtures" / "snapshots" / "complete.json"

    result = run_cli("validate", str(fixture))

    assert result.returncode == 0
    assert result.stdout == f"Snapshot is valid: {fixture}\n"
    assert result.stderr == ""


def test_validate_command_rejects_invalid_snapshot() -> None:
    fixture = PROJECT_ROOT / "tests" / "fixtures" / "snapshots" / "invalid.json"

    result = run_cli("validate", str(fixture))

    assert result.returncode == 2
    assert result.stdout == ""
    assert "hostname" in result.stderr
