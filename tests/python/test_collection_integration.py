from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from fleet_audit.collection import CollectionError, collect_snapshot
from fleet_audit.validation import SnapshotValidationError


def write_collector(directory: Path, filename: str, body: str) -> Path:
    collector = directory / filename
    collector.write_text("#!/usr/bin/env bash\nset -u\n" + body, encoding="utf-8")
    return collector


def test_all_complete_domains_produce_a_complete_collection(tmp_path: Path) -> None:
    collectors = {
        "platform": write_collector(
            tmp_path,
            "platform.sh",
            'printf \'ID=test\\nVERSION_ID="1"\\nPRETTY_NAME="Test Linux"\\n\' '
            '> "${1}/os-release"\n'
            'printf "6.8.0\\n" > "${1}/kernel"\n'
            'printf "x86_64\\n" > "${1}/architecture"\n'
            'printf "1.0 2.0\\n" > "${1}/uptime"\n',
        ),
        "hardware": write_collector(
            tmp_path,
            "hardware.sh",
            'printf "processor : 0\\nmodel name : Test CPU\\n" > "${1}/cpuinfo"\n'
            'printf "MemTotal: 1024 kB\\n" > "${1}/meminfo"\n'
            'printf "1\\n" > "${1}/logical-processors"\n',
        ),
        "storage": write_collector(
            tmp_path,
            "storage.sh",
            "printf '%s\\n' '{\"blockdevices\": []}' > \"${1}/lsblk.json\"\n"
            "printf '%s\\n' '{\"filesystems\": []}' > \"${1}/findmnt.json\"\n",
        ),
        "network": write_collector(
            tmp_path,
            "network.sh",
            'printf "eth0\\tup\\n" > "${1}/interfaces.tsv"\n'
            'printf "tcp\\t22\\texternal\\n" > "${1}/sockets.tsv"\n',
        ),
        "software": write_collector(
            tmp_path,
            "software.sh",
            'printf "bash\\t5.2\\tamd64\\n" > "${1}/packages.tsv"\n'
            'printf "ssh.service\\n" > "${1}/services.txt"\n'
            'printf "0\\n" > "${1}/pending-updates.txt"\n'
            'printf "false\\n" > "${1}/reboot-required.txt"\n',
        ),
    }

    snapshot = collect_snapshot(collector_paths=collectors, workspace_parent=tmp_path)

    assert snapshot["collection"]["status"] == "complete"
    assert all(domain["status"] == "complete" for domain in _domains(snapshot))
    assert all(
        capability["status"] == "available" for capability in snapshot["collection"]["capabilities"]
    )


def test_one_failed_collector_preserves_successful_data_and_is_partial(
    tmp_path: Path,
) -> None:
    platform = write_collector(
        tmp_path,
        "platform.sh",
        'printf \'ID=test\\nVERSION_ID="1"\\nPRETTY_NAME="Test Linux"\\n\' '
        '> "${1}/os-release"\n'
        'printf "6.8.0\\n" > "${1}/kernel"\n'
        'printf "x86_64\\n" > "${1}/architecture"\n'
        'printf "1.0 2.0\\n" > "${1}/uptime"\n',
    )
    hardware = write_collector(tmp_path, "hardware.sh", "exit 13\n")

    snapshot = collect_snapshot(
        collector_paths={"platform": platform, "hardware": hardware},
        workspace_parent=tmp_path,
    )

    assert snapshot["platform"]["status"] == "complete"
    assert snapshot["hardware"]["status"] == "unavailable"
    assert snapshot["collection"]["status"] == "partial"
    assert snapshot["collection"]["warnings"] == [
        {
            "collector": "hardware",
            "code": "COLLECTOR_EXIT_ERROR",
            "message": "Collector exited with code 13.",
        }
    ]


def test_no_successful_domain_produces_a_failed_collection(tmp_path: Path) -> None:
    collector = write_collector(tmp_path, "platform.sh", "exit 10\n")

    snapshot = collect_snapshot(
        collector_paths={"platform": collector},
        workspace_parent=tmp_path,
    )

    assert snapshot["collection"]["status"] == "failed"
    assert all(domain["status"] == "unavailable" for domain in _domains(snapshot))
    assert snapshot["collection"]["warnings"][0]["code"] == "CAPABILITY_UNAVAILABLE"


def test_final_validation_failure_prevents_snapshot_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collector = write_collector(tmp_path, "platform.sh", "exit 10\n")

    def reject_snapshot(snapshot: object) -> None:
        raise SnapshotValidationError("synthetic validation failure")

    monkeypatch.setattr("fleet_audit.collection.validate_snapshot", reject_snapshot)

    with pytest.raises(CollectionError, match="generated snapshot failed validation"):
        collect_snapshot(
            collector_paths={"platform": collector},
            workspace_parent=tmp_path,
        )

    assert list(tmp_path.glob("fleet-audit-*")) == []


def _domains(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    return [snapshot[name] for name in ("platform", "hardware", "storage", "network", "software")]
