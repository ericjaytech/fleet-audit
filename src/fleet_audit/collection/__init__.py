from __future__ import annotations

import os
from datetime import UTC, datetime
from importlib.resources import as_file, files
from pathlib import Path
from time import monotonic
from typing import Any

from fleet_audit import __version__
from fleet_audit.collection.os_parser import PlatformParseError, parse_platform
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
        result = _run_platform_collector(collector_path, workspace, timeout_seconds)
        platform: dict[str, Any] = {"status": "unavailable"}
        warning_code: str | None = None
        if result.status is CollectorStatus.AVAILABLE:
            try:
                platform = parse_platform(workspace)
            except PlatformParseError as error:
                result = CollectorResult(
                    name="platform",
                    status=CollectorStatus.ERROR,
                    exit_code=result.exit_code,
                    detail=f"Collector output was invalid: {error}.",
                )
                warning_code = "COLLECTOR_OUTPUT_INVALID"

    snapshot = _snapshot(label, platform, result, started_at, warning_code)
    validate_snapshot(snapshot)
    return snapshot


def _run_platform_collector(
    collector_path: Path | None,
    workspace: Path,
    timeout_seconds: float,
) -> CollectorResult:
    if collector_path is not None:
        return run_collector("platform", collector_path, workspace, timeout_seconds=timeout_seconds)

    collector_resource = files("fleet_audit.collectors").joinpath("os.sh")
    with as_file(collector_resource) as packaged_collector:
        return run_collector(
            "platform",
            packaged_collector,
            workspace,
            timeout_seconds=timeout_seconds,
        )


def _snapshot(
    label: str,
    platform: dict[str, Any],
    result: CollectorResult,
    started_at: float,
    warning_code: str | None,
) -> dict[str, Any]:
    capability = {"name": result.name, "status": result.status.value}
    if result.detail is not None:
        capability["detail"] = result.detail

    warnings: list[dict[str, str]] = []
    if result.status is not CollectorStatus.AVAILABLE:
        warnings.append(
            {
                "collector": result.name,
                "code": warning_code
                or (
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
        "platform": platform,
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
