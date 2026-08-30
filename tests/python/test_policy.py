from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from fleet_audit.policy import (
    FilesystemUsageCheck,
    MaximumUptimeCheck,
    PendingUpdatesCheck,
    Policy,
    PolicyCheck,
    PolicyError,
    ProhibitedPortCheck,
    RequiredServiceCheck,
    evaluate_policy,
    load_policy,
)
from fleet_audit.validation import validate_snapshot

FIXTURES = Path(__file__).parents[1] / "fixtures"
PROJECT_ROOT = Path(__file__).parents[2]


def write_policy(tmp_path: Path, content: str) -> Path:
    policy_path = tmp_path / "policy.toml"
    policy_path.write_text(content, encoding="utf-8")
    return policy_path


def complete_snapshot() -> dict[str, Any]:
    fixture = FIXTURES / "snapshots" / "complete.json"
    return json.loads(fixture.read_text(encoding="utf-8"))


def test_example_policy_covers_all_supported_check_types() -> None:
    policy = load_policy(PROJECT_ROOT / "config" / "example-policy.toml")

    assert {type(check) for check in policy.checks} == {
        FilesystemUsageCheck,
        PendingUpdatesCheck,
        MaximumUptimeCheck,
        RequiredServiceCheck,
        ProhibitedPortCheck,
    }


def test_load_policy_parses_all_supported_check_types(tmp_path: Path) -> None:
    policy_path = write_policy(
        tmp_path,
        """
version = 1

[[checks]]
id = "disk.root.utilisation"
type = "filesystem_usage"
mountpoint = "/"
warn_percent = 80
fail_percent = 90

[[checks]]
id = "updates.pending"
type = "pending_updates"
warn_count = 1
fail_count = 20

[[checks]]
id = "uptime.maximum"
type = "maximum_uptime"
max_days = 30

[[checks]]
id = "service.ssh.required"
type = "required_service"
service = "ssh.service"

[[checks]]
id = "port.telnet.prohibited"
type = "prohibited_port"
protocol = "tcp"
port = 23
""",
    )

    policy = load_policy(policy_path)

    assert policy.version == 1
    assert [check.id for check in policy.checks] == [
        "disk.root.utilisation",
        "updates.pending",
        "uptime.maximum",
        "service.ssh.required",
        "port.telnet.prohibited",
    ]


def test_load_policy_rejects_malformed_toml(tmp_path: Path) -> None:
    policy_path = write_policy(tmp_path, "version = [")

    with pytest.raises(PolicyError, match="invalid TOML"):
        load_policy(policy_path)


def test_load_policy_rejects_unknown_fields(tmp_path: Path) -> None:
    policy_path = write_policy(
        tmp_path,
        """
version = 1

[[checks]]
id = "updates.pending"
type = "pending_updates"
warn_count = 1
fail_count = 20
warning_count = 2
""",
    )

    with pytest.raises(PolicyError, match=r"checks\[0\].*unknown field: warning_count"):
        load_policy(policy_path)


def test_load_policy_rejects_duplicate_check_ids(tmp_path: Path) -> None:
    policy_path = write_policy(
        tmp_path,
        """
version = 1

[[checks]]
id = "updates.pending"
type = "pending_updates"
warn_count = 1
fail_count = 20

[[checks]]
id = "updates.pending"
type = "maximum_uptime"
max_days = 30
""",
    )

    with pytest.raises(PolicyError, match="duplicate check id"):
        load_policy(policy_path)


@pytest.mark.parametrize(
    "content",
    [
        """
version = 1
[[checks]]
id = "disk.root.utilisation"
type = "filesystem_usage"
mountpoint = "/"
warn_percent = 90
fail_percent = 90
""",
        """
version = 1
[[checks]]
id = "updates.pending"
type = "pending_updates"
warn_count = 20
fail_count = 10
""",
    ],
)
def test_load_policy_rejects_inconsistent_thresholds(tmp_path: Path, content: str) -> None:
    policy_path = write_policy(tmp_path, content)

    with pytest.raises(PolicyError, match="warning threshold must be less than failure threshold"):
        load_policy(policy_path)


@pytest.mark.parametrize(
    "content",
    [
        "version = 2\nchecks = []\n",
        "version = 1\nchecks = []\n",
        """
version = 1
[[checks]]
id = "uptime.maximum"
type = "maximum_uptime"
max_days = 0
""",
        """
version = 1
[[checks]]
id = "port.invalid.prohibited"
type = "prohibited_port"
protocol = "tcp"
port = 65536
""",
        """
version = 1
[[checks]]
id = "disk.invalid"
type = "filesystem_usage"
mountpoint = "relative/path"
warn_percent = 80
fail_percent = 90
""",
        """
version = 1
[[checks]]
id = "service.invalid"
type = "required_service"
service = "ssh"
""",
    ],
)
def test_load_policy_rejects_invalid_boundaries(tmp_path: Path, content: str) -> None:
    policy_path = write_policy(tmp_path, content)

    with pytest.raises(PolicyError):
        load_policy(policy_path)


@pytest.mark.parametrize(
    ("used_percent", "expected_status"),
    [(79.9, "PASS"), (80, "WARN"), (89.9, "WARN"), (90, "FAIL")],
)
def test_filesystem_usage_applies_inclusive_thresholds(
    used_percent: float,
    expected_status: str,
) -> None:
    snapshot = complete_snapshot()
    snapshot["storage"]["filesystems"][0]["used_percent"] = used_percent
    policy = Policy(
        version=1,
        checks=(FilesystemUsageCheck("disk.root", "/", 80, 90),),
    )

    result = evaluate_policy(policy, snapshot)[0]

    assert result["status"] == expected_status
    assert "80%" in result["evidence"]
    assert "90%" in result["evidence"]


@pytest.mark.parametrize(
    ("pending_updates", "expected_status"),
    [(0, "PASS"), (1, "WARN"), (19, "WARN"), (20, "FAIL")],
)
def test_pending_updates_applies_inclusive_thresholds(
    pending_updates: int,
    expected_status: str,
) -> None:
    snapshot = complete_snapshot()
    snapshot["software"]["pending_updates"] = pending_updates
    policy = Policy(
        version=1,
        checks=(PendingUpdatesCheck("updates.pending", 1, 20),),
    )

    result = evaluate_policy(policy, snapshot)[0]

    assert result["status"] == expected_status


@pytest.mark.parametrize(
    ("uptime_seconds", "expected_status"),
    [(2_592_000, "PASS"), (2_592_001, "FAIL")],
)
def test_maximum_uptime_allows_the_exact_limit(
    uptime_seconds: int,
    expected_status: str,
) -> None:
    snapshot = complete_snapshot()
    snapshot["platform"]["uptime_seconds"] = uptime_seconds
    policy = Policy(
        version=1,
        checks=(MaximumUptimeCheck("uptime.maximum", 30),),
    )

    result = evaluate_policy(policy, snapshot)[0]

    assert result["status"] == expected_status


@pytest.mark.parametrize(
    ("service", "expected_status"),
    [("ssh.service", "PASS"), ("chrony.service", "FAIL")],
)
def test_required_service_checks_enabled_service_inventory(
    service: str,
    expected_status: str,
) -> None:
    policy = Policy(
        version=1,
        checks=(RequiredServiceCheck("service.required", service),),
    )

    result = evaluate_policy(policy, complete_snapshot())[0]

    assert result["status"] == expected_status


@pytest.mark.parametrize(
    ("protocol", "port", "expected_status"),
    [("tcp", 22, "FAIL"), ("udp", 22, "PASS"), ("tcp", 23, "PASS")],
)
def test_prohibited_port_matches_protocol_and_port(
    protocol: str,
    port: int,
    expected_status: str,
) -> None:
    policy = Policy(
        version=1,
        checks=(ProhibitedPortCheck("port.prohibited", protocol, port),),
    )

    result = evaluate_policy(policy, complete_snapshot())[0]

    assert result["status"] == expected_status


def test_unavailable_sources_produce_skip_results() -> None:
    snapshot = complete_snapshot()
    snapshot["storage"] = {"status": "unavailable", "devices": [], "filesystems": []}
    snapshot["platform"] = {"status": "unavailable"}
    snapshot["software"] = {
        "status": "unavailable",
        "package_manager": None,
        "installed_packages": [],
        "enabled_services": [],
        "pending_updates": None,
        "reboot_required": None,
    }
    snapshot["network"] = {
        "status": "unavailable",
        "interfaces": [],
        "listening_sockets": [],
    }
    policy = Policy(
        version=1,
        checks=(
            FilesystemUsageCheck("disk.root", "/", 80, 90),
            PendingUpdatesCheck("updates.pending", 1, 20),
            MaximumUptimeCheck("uptime.maximum", 30),
            RequiredServiceCheck("service.required", "ssh.service"),
            ProhibitedPortCheck("port.prohibited", "tcp", 22),
        ),
    )

    results = evaluate_policy(policy, snapshot)

    assert [result["status"] for result in results] == ["SKIP"] * 5


def test_invalid_collected_values_produce_error_results() -> None:
    snapshot = complete_snapshot()
    snapshot["storage"]["filesystems"][0]["used_percent"] = "nearly full"
    snapshot["platform"]["uptime_seconds"] = -1
    snapshot["software"]["pending_updates"] = True
    snapshot["software"]["enabled_services"] = [17]
    snapshot["network"]["listening_sockets"] = [{"protocol": "tcp", "port": "22"}]
    policy = Policy(
        version=1,
        checks=(
            FilesystemUsageCheck("disk.root", "/", 80, 90),
            PendingUpdatesCheck("updates.pending", 1, 20),
            MaximumUptimeCheck("uptime.maximum", 30),
            RequiredServiceCheck("service.required", "ssh.service"),
            ProhibitedPortCheck("port.prohibited", "tcp", 22),
        ),
    )

    results = evaluate_policy(policy, snapshot)

    assert [result["status"] for result in results] == ["ERROR"] * 5


@pytest.mark.parametrize(
    ("warning_code", "check", "expected_status"),
    [
        ("FILESYSTEMS_UNAVAILABLE", FilesystemUsageCheck("disk.root", "/", 80, 90), "SKIP"),
        ("FILESYSTEMS_INVALID", FilesystemUsageCheck("disk.root", "/", 80, 90), "ERROR"),
        ("PENDING_UPDATES_UNAVAILABLE", PendingUpdatesCheck("updates", 1, 20), "SKIP"),
        ("PENDING_UPDATES_INVALID", PendingUpdatesCheck("updates", 1, 20), "ERROR"),
        ("SERVICES_UNAVAILABLE", RequiredServiceCheck("service", "ssh.service"), "SKIP"),
        ("SERVICES_INVALID", RequiredServiceCheck("service", "ssh.service"), "ERROR"),
        ("SOCKETS_UNAVAILABLE", ProhibitedPortCheck("port", "tcp", 22), "SKIP"),
        ("SOCKETS_INVALID", ProhibitedPortCheck("port", "tcp", 22), "ERROR"),
    ],
)
def test_partial_source_warnings_determine_skip_or_error(
    warning_code: str,
    check: PolicyCheck,
    expected_status: str,
) -> None:
    snapshot = complete_snapshot()
    collector = "storage" if warning_code.startswith("FILESYSTEMS") else "software"
    if warning_code.startswith("SOCKETS"):
        collector = "network"
    snapshot[collector]["status"] = "partial"
    snapshot["collection"]["warnings"] = [
        {"collector": collector, "code": warning_code, "message": "Synthetic warning."}
    ]
    policy = Policy(version=1, checks=(check,))

    result = evaluate_policy(policy, snapshot)[0]

    assert result["status"] == expected_status


def test_results_are_schema_valid_and_do_not_echo_sensitive_policy_targets() -> None:
    snapshot = complete_snapshot()
    policy = Policy(
        version=1,
        checks=(
            FilesystemUsageCheck("disk.private", "/home/alice/private", 80, 90),
            RequiredServiceCheck("service.private", "alice-private.service"),
        ),
    )

    snapshot["checks"] = evaluate_policy(policy, snapshot)
    validate_snapshot(snapshot)

    evidence = " ".join(result["evidence"] for result in snapshot["checks"])
    assert "alice" not in evidence
    assert "/home" not in evidence
