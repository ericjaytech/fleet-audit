from __future__ import annotations

import time
from pathlib import Path

import pytest

from fleet_audit.collection import CollectionError, collect_snapshot
from fleet_audit.collection.runner import CollectorStatus, run_collector


def write_collector(directory: Path, body: str, filename: str = "collector.sh") -> Path:
    collector = directory / filename
    collector.write_text("#!/usr/bin/env bash\nset -u\n" + body, encoding="utf-8")
    return collector


def test_timeout_has_a_structured_issue_code(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    collector = write_collector(tmp_path, "sleep 1\n")

    result = run_collector("platform", collector, workspace, timeout_seconds=0.01)

    assert result.status is CollectorStatus.ERROR
    assert result.issue_code == "COLLECTOR_TIMEOUT"


def test_nonzero_exit_has_a_structured_issue_code(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    collector = write_collector(tmp_path, "exit 13\n")

    result = run_collector("platform", collector, workspace, timeout_seconds=1)

    assert result.status is CollectorStatus.ERROR
    assert result.issue_code == "COLLECTOR_EXIT_ERROR"
    assert result.detail == "Collector exited with code 13."


def test_oversized_collector_artifact_is_rejected(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    collector = write_collector(
        tmp_path,
        'head -c 4194305 /dev/zero > "${1}/oversized"\n',
    )

    result = run_collector("platform", collector, workspace, timeout_seconds=1)

    assert result.status is CollectorStatus.ERROR
    assert result.issue_code == "COLLECTOR_OUTPUT_LIMIT"
    assert result.detail == "Collector output exceeded the 4 MiB per-file limit."


def test_collector_cannot_replace_an_existing_workspace_artifact(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    protected_artifact = workspace / "existing"
    protected_artifact.write_text("keep\n", encoding="utf-8")
    collector = write_collector(
        tmp_path,
        'printf "changed\\n" > "${1}/existing"\n',
    )

    result = run_collector("platform", collector, workspace, timeout_seconds=1)

    assert result.status is CollectorStatus.ERROR
    assert result.issue_code == "COLLECTOR_WORKSPACE_VIOLATION"


def test_successful_collector_cannot_leave_background_children(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    late_artifact = workspace / "late"
    collector = write_collector(
        tmp_path,
        '(sleep 0.1; printf "late\\n" > "${1}/late") &\nexit 0\n',
    )

    result = run_collector("platform", collector, workspace, timeout_seconds=1)
    time.sleep(0.2)

    assert result.status is CollectorStatus.AVAILABLE
    assert not late_artifact.exists()


@pytest.mark.parametrize("path_kind", ["missing", "symlink"])
def test_invalid_override_collector_path_prevents_collection(
    tmp_path: Path,
    path_kind: str,
) -> None:
    collector = tmp_path / "collector.sh"
    if path_kind == "symlink":
        target = write_collector(tmp_path, "exit 0\n", "target.sh")
        collector.symlink_to(target)

    with pytest.raises(CollectionError, match="invalid collector path"):
        collect_snapshot(
            collector_paths={"platform": collector},
            workspace_parent=tmp_path,
        )


def test_output_limit_appears_in_snapshot_diagnostics(tmp_path: Path) -> None:
    collector = write_collector(
        tmp_path,
        'head -c 4194305 /dev/zero > "${1}/oversized"\n',
    )

    snapshot = collect_snapshot(
        collector_paths={"platform": collector},
        workspace_parent=tmp_path,
    )

    assert snapshot["collection"]["warnings"] == [
        {
            "collector": "platform",
            "code": "COLLECTOR_OUTPUT_LIMIT",
            "message": "Collector output exceeded the 4 MiB per-file limit.",
        }
    ]
