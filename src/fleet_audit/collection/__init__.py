from __future__ import annotations

import os
from collections.abc import Mapping
from datetime import UTC, datetime
from importlib.resources import as_file, files
from pathlib import Path
from time import monotonic
from typing import Any

from fleet_audit import __version__
from fleet_audit.collection.hardware_parser import HardwareParseError, parse_hardware
from fleet_audit.collection.network_parser import (
    NetworkParseError,
    NetworkWarning,
    parse_network,
)
from fleet_audit.collection.os_parser import PlatformParseError, parse_platform
from fleet_audit.collection.runner import CollectorResult, CollectorStatus, run_collector
from fleet_audit.collection.software_parser import (
    SoftwareParseError,
    SoftwareWarning,
    parse_software,
)
from fleet_audit.collection.storage_parser import (
    StorageParseError,
    StorageWarning,
    parse_storage,
)
from fleet_audit.collection.workspace import secure_workspace
from fleet_audit.validation import validate_snapshot


class CollectionError(RuntimeError):
    """Raised when a snapshot cannot be collected safely."""


_COLLECTOR_RESOURCES = {
    "platform": "os.sh",
    "hardware": "hardware.sh",
    "storage": "storage.sh",
    "network": "network.sh",
    "software": "software.sh",
}


def collect_snapshot(
    *,
    label: str = "host",
    collector_paths: Mapping[str, Path] | None = None,
    timeout_seconds: float = 5,
    workspace_parent: Path | None = None,
) -> dict[str, Any]:
    started_at = monotonic()
    selected_collectors = (
        tuple(_COLLECTOR_RESOURCES) if collector_paths is None else tuple(collector_paths)
    )
    unknown_collectors = set(selected_collectors) - set(_COLLECTOR_RESOURCES)
    if unknown_collectors:
        names = ", ".join(sorted(unknown_collectors))
        raise CollectionError(f"unknown collector: {names}")
    if collector_paths is not None:
        _validate_override_paths(collector_paths)

    domains: dict[str, dict[str, Any]] = {
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
    }
    outcomes: list[tuple[CollectorResult, str | None]] = []
    domain_warnings: list[dict[str, str]] = []

    with secure_workspace(parent=workspace_parent) as workspace:
        for name in selected_collectors:
            collector_workspace = workspace / name
            collector_workspace.mkdir(mode=0o700)
            override_path = None if collector_paths is None else collector_paths[name]
            result = _run_named_collector(
                name,
                override_path,
                collector_workspace,
                timeout_seconds,
            )
            warning_code = result.issue_code
            if result.status is CollectorStatus.AVAILABLE:
                domain, result, warning_code, parser_warnings = _parse_collector_output(
                    name,
                    result,
                    collector_workspace,
                )
                domains[name] = domain
                domain_warnings.extend(
                    {
                        "collector": name,
                        "code": warning.code,
                        "message": warning.message,
                    }
                    for warning in parser_warnings
                )
            outcomes.append((result, warning_code))

    snapshot = _snapshot(label, domains, outcomes, domain_warnings, started_at)
    validate_snapshot(snapshot)
    return snapshot


def _validate_override_paths(collector_paths: Mapping[str, Path]) -> None:
    for name, collector_path in collector_paths.items():
        try:
            valid = (
                not collector_path.is_symlink()
                and collector_path.is_file()
                and os.access(collector_path, os.R_OK)
            )
        except OSError:
            valid = False
        if not valid:
            raise CollectionError(f"invalid collector path for {name}: {collector_path}")


def _run_named_collector(
    name: str,
    collector_path: Path | None,
    workspace: Path,
    timeout_seconds: float,
) -> CollectorResult:
    if collector_path is not None:
        return run_collector(name, collector_path, workspace, timeout_seconds=timeout_seconds)

    collector_resource = files("fleet_audit.collectors").joinpath(_COLLECTOR_RESOURCES[name])
    with as_file(collector_resource) as packaged_collector:
        return run_collector(
            name,
            packaged_collector,
            workspace,
            timeout_seconds=timeout_seconds,
        )


def _parse_collector_output(
    name: str,
    result: CollectorResult,
    workspace: Path,
) -> tuple[
    dict[str, Any],
    CollectorResult,
    str | None,
    tuple[StorageWarning | NetworkWarning | SoftwareWarning, ...],
]:
    try:
        if name == "platform":
            return parse_platform(workspace), result, None, ()
        if name == "hardware":
            return parse_hardware(workspace), result, None, ()
        if name == "storage":
            storage_result = parse_storage(workspace)
            return storage_result.storage, result, None, storage_result.warnings
        if name == "software":
            software_result = parse_software(workspace)
            return software_result.software, result, None, software_result.warnings

        network_result = parse_network(workspace)
        return network_result.network, result, None, network_result.warnings
    except (
        PlatformParseError,
        HardwareParseError,
        StorageParseError,
        NetworkParseError,
        SoftwareParseError,
    ) as error:
        return (
            _unavailable_domain(name),
            CollectorResult(
                name=name,
                status=CollectorStatus.ERROR,
                exit_code=result.exit_code,
                detail=f"Collector output was invalid: {error}.",
                issue_code="COLLECTOR_OUTPUT_INVALID",
            ),
            "COLLECTOR_OUTPUT_INVALID",
            (),
        )


def _unavailable_domain(name: str) -> dict[str, Any]:
    if name == "storage":
        return {"status": "unavailable", "devices": [], "filesystems": []}
    if name == "network":
        return {"status": "unavailable", "interfaces": [], "listening_sockets": []}
    if name == "software":
        return {
            "status": "unavailable",
            "package_manager": None,
            "installed_packages": [],
            "enabled_services": [],
            "pending_updates": None,
            "reboot_required": None,
        }
    return {"status": "unavailable"}


def _snapshot(
    label: str,
    domains: dict[str, dict[str, Any]],
    outcomes: list[tuple[CollectorResult, str | None]],
    domain_warnings: list[dict[str, str]],
    started_at: float,
) -> dict[str, Any]:
    capabilities: list[dict[str, str]] = []
    warnings = list(domain_warnings)
    for result, warning_code in outcomes:
        capability = {"name": result.name, "status": result.status.value}
        if result.detail is not None:
            capability["detail"] = result.detail
        capabilities.append(capability)

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
        "platform": domains["platform"],
        "hardware": domains["hardware"],
        "storage": domains["storage"],
        "network": domains["network"],
        "software": domains["software"],
        "checks": [],
        "collection": {
            "status": _collection_status(domains),
            "privilege_level": "root" if os.geteuid() == 0 else "non-root",
            "duration_ms": max(0, int((monotonic() - started_at) * 1000)),
            "capabilities": capabilities,
            "warnings": warnings,
        },
    }


def _collection_status(domains: dict[str, dict[str, Any]]) -> str:
    statuses = {domain["status"] for domain in domains.values()}
    if statuses == {"complete"}:
        return "complete"
    if statuses == {"unavailable"}:
        return "failed"
    return "partial"
