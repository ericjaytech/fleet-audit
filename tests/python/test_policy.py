from __future__ import annotations

from pathlib import Path

import pytest

from fleet_audit.policy import PolicyError, load_policy


def write_policy(tmp_path: Path, content: str) -> Path:
    policy_path = tmp_path / "policy.toml"
    policy_path.write_text(content, encoding="utf-8")
    return policy_path


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
    ],
)
def test_load_policy_rejects_invalid_boundaries(tmp_path: Path, content: str) -> None:
    policy_path = write_policy(tmp_path, content)

    with pytest.raises(PolicyError):
        load_policy(policy_path)
