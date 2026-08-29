from __future__ import annotations

import os
from datetime import UTC, datetime
from importlib.resources import as_file, files
from pathlib import Path
from time import monotonic
from typing import Any

from fleet_audit import __version__
from fleet_audit.collection.runner import CollectorResult, CollectorStatus, run_collector
from fleet_audit.collection.workspace import secure_workspace
from fleet_audit.validation import validate_snapshot


class CollectionError(RuntimeError):
    """Raised when a snapshot cannot be collected safely."""


def collect_snapshot(
    *,
    label: str = "host",
    collector_path: Path | None = None,
    timeout_seconds: float = 5,
    workspace_parent: Path | None = None,
) -> dict[str, Any]:
    started_at = monotonic()

    with secure_workspace(parent=workspace_parent) as workspace:
        result = _run_stub_collector(collector_path, workspace, timeout_seconds)
        if result.status is CollectorStatus.AVAILABLE:
            _parse_stub_result(workspace)

    snapshot = _minimal_snapshot(label, result, started_at)
    validate_snapshot(snapshot)
    return snapshot


def _run_stub_collector(
    collector_path: Path | None,
    workspace: Path,
    timeout_seconds: float,
) -> CollectorResult:
    if collector_path is not None:
        return run_collector("stub", collector_path, workspace, timeout_seconds=timeout_seconds)

    collector_resource = files("fleet_audit.collectors").joinpath("stub.sh")
    with as_file(collector_resource) as packaged_collector:
        return run_collector(
            "stub",
            packaged_collector,
            workspace,
            timeout_seconds=timeout_seconds,
        )


def _parse_stub_result(workspace: Path) -> None:
    status_path = workspace / "stub.status"
    try:
        status = status_path.read_text(encoding="utf-8")
    except OSError as error:
        raise CollectionError("stub collector did not produce its expected output") from error

    if status != "ready\n":
        raise CollectionError("unexpected stub output")


def _minimal_snapshot(
    label: str,
    result: CollectorResult,
    started_at: float,
) -> dict[str, Any]:
    capability = {"name": result.name, "status": result.status.value}
    if result.detail is not None:
        capability["detail"] = result.detail

    warnings: list[dict[str, str]] = []
    if result.status is not CollectorStatus.AVAILABLE:
        warnings.append(
            {
                "collector": result.name,
                "code": (
                    "CAPABILITY_UNAVAILABLE"
                    if result.status is CollectorStatus.UNAVAILABLE
                    else "COLLECTOR_ERROR"
                ),
                "message": result.detail or "Collector did not complete.",
            }
        )

    return {
        "schema_version": "1.0",
        "tool": {"name": "fleet-audit", "version": __version__},
        "collected_at": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "host": {"label": label},
        "platform": {"status": "unavailable"},
        "hardware": {"status": "unavailable"},
        "storage": {"status": "unavailable", "devices": [], "filesystems": []},
        "network": {"status": "unavailable", "interfaces": [], "listening_sockets": []},
        "software": {
            "status": "unavailable",
            "package_manager": None,
            "installed_packages": [],
            "enabled_services": [],
            "pending_updates": None,
            "reboot_required": None,
        },
        "checks": [],
        "collection": {
            "status": "partial",
            "privilege_level": "root" if os.geteuid() == 0 else "non-root",
            "duration_ms": max(0, int((monotonic() - started_at) * 1000)),
            "capabilities": [capability],
            "warnings": warnings,
        },
    }
