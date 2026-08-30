from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fleet_audit.validation import validate_snapshot

ChangeValue = str | int | bool | tuple[str, ...] | None


class ComparisonError(ValueError):
    """Raised when two snapshots cannot be compared safely."""


@dataclass(frozen=True)
class SnapshotChange:
    category: str
    kind: str
    key: str
    before: ChangeValue
    after: ChangeValue

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "kind": self.kind,
            "key": self.key,
            "before": _json_value(self.before),
            "after": _json_value(self.after),
        }


@dataclass(frozen=True)
class SnapshotComparison:
    baseline_label: str
    current_label: str
    baseline_collected_at: str
    current_collected_at: str
    changes: tuple[SnapshotChange, ...]

    @property
    def status(self) -> str:
        return "changed" if self.changes else "unchanged"

    @property
    def change_count(self) -> int:
        return len(self.changes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "change_count": self.change_count,
            "baseline": {
                "label": self.baseline_label,
                "collected_at": self.baseline_collected_at,
            },
            "current": {
                "label": self.current_label,
                "collected_at": self.current_collected_at,
            },
            "changes": [change.to_dict() for change in self.changes],
        }


def compare_snapshots(
    baseline: dict[str, Any],
    current: dict[str, Any],
    *,
    allow_host_label_mismatch: bool = False,
) -> SnapshotComparison:
    _check_schema_compatibility(baseline, current)
    validate_snapshot(baseline)
    validate_snapshot(current)

    baseline_label = baseline["host"]["label"]
    current_label = current["host"]["label"]
    if baseline_label != current_label and not allow_host_label_mismatch:
        raise ComparisonError(
            "host labels differ; use --allow-host-label-mismatch to acknowledge this comparison"
        )

    changes: list[SnapshotChange] = []
    changes.extend(_compare_mappings("platform", _platform(baseline), _platform(current)))
    changes.extend(_compare_mappings("packages", _packages(baseline), _packages(current)))
    changes.extend(_compare_mappings("services", _services(baseline), _services(current)))
    changes.extend(_compare_mappings("ports", _ports(baseline), _ports(current)))
    changes.extend(
        _compare_mappings("software", _software_facts(baseline), _software_facts(current))
    )
    changes.extend(_compare_mappings("checks", _checks(baseline), _checks(current)))
    changes.extend(
        _compare_mappings("capabilities", _capabilities(baseline), _capabilities(current))
    )

    return SnapshotComparison(
        baseline_label=baseline_label,
        current_label=current_label,
        baseline_collected_at=baseline["collected_at"],
        current_collected_at=current["collected_at"],
        changes=tuple(changes),
    )


def _check_schema_compatibility(
    baseline: dict[str, Any],
    current: dict[str, Any],
) -> None:
    baseline_version = baseline.get("schema_version")
    current_version = current.get("schema_version")
    if baseline_version != current_version:
        raise ComparisonError(
            "incompatible schema versions: "
            f"baseline {baseline_version!r}, current {current_version!r}"
        )
    if baseline_version != "1.0":
        raise ComparisonError(f"unsupported schema version: {baseline_version!r}")


def _compare_mappings(
    category: str,
    baseline: dict[str, ChangeValue],
    current: dict[str, ChangeValue],
) -> list[SnapshotChange]:
    changes: list[SnapshotChange] = []
    for key in sorted(baseline.keys() | current.keys()):
        if key not in baseline:
            changes.append(SnapshotChange(category, "added", key, None, current[key]))
        elif key not in current:
            changes.append(SnapshotChange(category, "removed", key, baseline[key], None))
        elif baseline[key] != current[key]:
            changes.append(SnapshotChange(category, "changed", key, baseline[key], current[key]))
    return changes


def _platform(snapshot: dict[str, Any]) -> dict[str, ChangeValue]:
    platform = snapshot["platform"]
    values: dict[str, ChangeValue] = {}
    operating_system = platform.get("os")
    if isinstance(operating_system, dict):
        for field in ("id", "pretty_name", "version_id"):
            if field in operating_system:
                values[f"os.{field}"] = operating_system[field]
    for field in ("architecture", "kernel"):
        if field in platform:
            values[field] = platform[field]
    return values


def _packages(snapshot: dict[str, Any]) -> dict[str, ChangeValue]:
    packages: dict[str, ChangeValue] = {}
    for package in snapshot["software"]["installed_packages"]:
        key = f"{package['name']}:{package['architecture']}"
        if key in packages:
            raise ComparisonError(f"duplicate package identity: {key}")
        packages[key] = package["version"]
    return packages


def _services(snapshot: dict[str, Any]) -> dict[str, ChangeValue]:
    return {service: "enabled" for service in set(snapshot["software"]["enabled_services"])}


def _ports(snapshot: dict[str, Any]) -> dict[str, ChangeValue]:
    scopes_by_port: dict[str, set[str]] = {}
    for socket in snapshot["network"]["listening_sockets"]:
        key = f"{socket['protocol']}/{socket['port']}"
        scopes_by_port.setdefault(key, set()).add(socket["bind_scope"])
    return {key: tuple(sorted(scopes)) for key, scopes in scopes_by_port.items()}


def _software_facts(snapshot: dict[str, Any]) -> dict[str, ChangeValue]:
    software = snapshot["software"]
    return {
        "pending_updates": software["pending_updates"],
        "reboot_required": software["reboot_required"],
    }


def _checks(snapshot: dict[str, Any]) -> dict[str, ChangeValue]:
    checks: dict[str, ChangeValue] = {}
    for check in snapshot["checks"]:
        key = check["id"]
        if key in checks:
            raise ComparisonError(f"duplicate policy check identity: {key}")
        checks[key] = check["status"]
    return checks


def _capabilities(snapshot: dict[str, Any]) -> dict[str, ChangeValue]:
    capabilities: dict[str, ChangeValue] = {}
    for capability in snapshot["collection"]["capabilities"]:
        key = capability["name"]
        if key in capabilities:
            raise ComparisonError(f"duplicate capability identity: {key}")
        capabilities[key] = capability["status"]
    return capabilities


def _json_value(value: ChangeValue) -> str | int | bool | list[str] | None:
    if isinstance(value, tuple):
        return list(value)
    return value
