from __future__ import annotations

import copy
import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from fleet_audit.compare import ComparisonError, SnapshotComparison, compare_snapshots

FIXTURES = Path(__file__).parents[1] / "fixtures" / "snapshots"


def complete_snapshot() -> dict[str, Any]:
    return json.loads((FIXTURES / "complete.json").read_text(encoding="utf-8"))


def change_tuples(comparison: SnapshotComparison) -> list[tuple[object, ...]]:
    return [
        (change.category, change.kind, change.key, change.before, change.after)
        for change in comparison.changes
    ]


def test_volatile_metadata_reordering_and_evidence_changes_are_not_material() -> None:
    baseline = complete_snapshot()
    current = copy.deepcopy(baseline)
    current["collected_at"] = "2026-08-30T18:00:00Z"
    current["platform"]["uptime_seconds"] = 999_999
    current["collection"]["duration_ms"] = 9_999
    current["collection"]["status"] = "partial"
    current["collection"]["privilege_level"] = "root"
    current["collection"]["warnings"] = [
        {
            "collector": "software",
            "code": "APT_INDEX_NOT_REFRESHED",
            "message": "Local package indexes may be stale.",
        }
    ]
    current["software"]["installed_packages"].reverse()
    current["network"]["listening_sockets"].reverse()
    current["checks"].reverse()
    current["checks"][0]["summary"] = "Different wording with the same status."
    current["checks"][0]["evidence"] = "Different evidence with the same status."

    comparison = compare_snapshots(baseline, current)

    assert comparison.status == "unchanged"
    assert comparison.change_count == 0
    assert comparison.changes == ()


def test_packages_are_classified_as_added_removed_or_version_changed() -> None:
    baseline = complete_snapshot()
    current = copy.deepcopy(baseline)
    current["software"]["installed_packages"] = [
        {"name": "bash", "version": "5.3", "architecture": "amd64"},
        {"name": "curl", "version": "8.5", "architecture": "amd64"},
    ]

    comparison = compare_snapshots(baseline, current)

    assert change_tuples(comparison) == [
        ("packages", "changed", "bash:amd64", "5.2.21-example", "5.3"),
        ("packages", "added", "curl:amd64", None, "8.5"),
        ("packages", "removed", "openssh-server:amd64", "1:9.6p1-example", None),
    ]


def test_services_are_classified_as_enabled_or_disabled() -> None:
    baseline = complete_snapshot()
    current = copy.deepcopy(baseline)
    baseline["software"]["enabled_services"] = ["cron.service", "ssh.service"]
    current["software"]["enabled_services"] = ["nginx.service", "ssh.service"]

    comparison = compare_snapshots(baseline, current)

    assert change_tuples(comparison) == [
        ("services", "removed", "cron.service", "enabled", None),
        ("services", "added", "nginx.service", None, "enabled"),
    ]


def test_ports_are_classified_by_protocol_port_and_bind_scope() -> None:
    baseline = complete_snapshot()
    current = copy.deepcopy(baseline)
    current["network"]["listening_sockets"] = [
        {"protocol": "tcp", "port": 22, "bind_scope": "loopback"},
        {"protocol": "tcp", "port": 8080, "bind_scope": "wildcard"},
    ]

    comparison = compare_snapshots(baseline, current)

    assert change_tuples(comparison) == [
        ("ports", "changed", "tcp/22", ("external",), ("loopback",)),
        ("ports", "removed", "tcp/5432", ("loopback",), None),
        ("ports", "added", "tcp/8080", None, ("wildcard",)),
    ]


def test_capabilities_are_classified_by_availability_status() -> None:
    baseline = complete_snapshot()
    current = copy.deepcopy(baseline)
    current["collection"]["capabilities"] = [
        {"name": "hardware", "status": "available"},
        {"name": "platform", "status": "error", "detail": "Synthetic error."},
    ]

    comparison = compare_snapshots(baseline, current)

    assert change_tuples(comparison) == [
        ("capabilities", "added", "hardware", None, "available"),
        ("capabilities", "changed", "platform", "available", "error"),
        ("capabilities", "removed", "software", "available", None),
    ]


def test_policy_results_compare_status_crossings_not_message_text() -> None:
    baseline = complete_snapshot()
    current = copy.deepcopy(baseline)
    current["checks"] = [
        {
            "id": "disk.root.utilisation",
            "status": "WARN",
            "summary": "Threshold crossed.",
            "evidence": "85% used.",
        },
        {
            "id": "service.ssh.required",
            "status": "PASS",
            "summary": "Required service is enabled.",
        },
    ]

    comparison = compare_snapshots(baseline, current)

    assert change_tuples(comparison) == [
        ("checks", "changed", "disk.root.utilisation", "PASS", "WARN"),
        ("checks", "added", "service.ssh.required", None, "PASS"),
        ("checks", "removed", "updates.pending", "WARN", None),
    ]


def test_platform_update_and_reboot_facts_are_material() -> None:
    baseline = complete_snapshot()
    current = copy.deepcopy(baseline)
    current["platform"]["kernel"] = "6.9.0-example-generic"
    current["platform"]["os"]["version_id"] = "26.04"
    current["software"]["pending_updates"] = 0
    current["software"]["reboot_required"] = True

    comparison = compare_snapshots(baseline, current)

    assert change_tuples(comparison) == [
        ("platform", "changed", "kernel", "6.8.0-example-generic", "6.9.0-example-generic"),
        ("platform", "changed", "os.version_id", "24.04", "26.04"),
        ("software", "changed", "pending_updates", 3, 0),
        ("software", "changed", "reboot_required", False, True),
    ]


def test_comparison_serialises_context_and_deterministic_changes() -> None:
    baseline = complete_snapshot()
    current = copy.deepcopy(baseline)
    current["software"]["enabled_services"].append("cron.service")

    result = compare_snapshots(baseline, current).to_dict()

    assert result == {
        "status": "changed",
        "change_count": 1,
        "baseline": {
            "label": "demo-web-01",
            "collected_at": "2026-08-29T12:00:00Z",
        },
        "current": {
            "label": "demo-web-01",
            "collected_at": "2026-08-29T12:00:00Z",
        },
        "changes": [
            {
                "category": "services",
                "kind": "added",
                "key": "cron.service",
                "before": None,
                "after": "enabled",
            }
        ],
    }


def test_incompatible_schema_versions_fail_clearly() -> None:
    baseline = complete_snapshot()
    current = copy.deepcopy(baseline)
    current["schema_version"] = "2.0"

    with pytest.raises(ComparisonError, match="incompatible schema versions"):
        compare_snapshots(baseline, current)


def test_host_label_mismatch_requires_explicit_acknowledgement() -> None:
    baseline = complete_snapshot()
    current = copy.deepcopy(baseline)
    current["host"]["label"] = "demo-web-02"

    with pytest.raises(ComparisonError, match="host labels differ"):
        compare_snapshots(baseline, current)

    comparison = compare_snapshots(baseline, current, allow_host_label_mismatch=True)
    assert comparison.status == "unchanged"
    assert comparison.baseline_label == "demo-web-01"
    assert comparison.current_label == "demo-web-02"


def test_changed_fixture_exercises_each_initial_comparison_category() -> None:
    baseline = complete_snapshot()
    current = json.loads((FIXTURES / "changed.json").read_text(encoding="utf-8"))

    comparison = compare_snapshots(baseline, current)

    assert comparison.change_count == 13
    assert Counter(change.category for change in comparison.changes) == {
        "platform": 1,
        "packages": 3,
        "services": 1,
        "ports": 3,
        "software": 2,
        "checks": 2,
        "capabilities": 1,
    }


def test_duplicate_identity_error_does_not_echo_snapshot_control_characters() -> None:
    baseline = complete_snapshot()
    current = copy.deepcopy(baseline)
    unsafe_name = "\x1b[31mduplicate"
    current["software"]["installed_packages"].extend(
        [
            {"name": unsafe_name, "version": "1", "architecture": "amd64"},
            {"name": unsafe_name, "version": "1", "architecture": "amd64"},
        ]
    )

    with pytest.raises(ComparisonError, match="duplicate package identity") as error:
        compare_snapshots(baseline, current)

    assert unsafe_name not in str(error.value)
