from __future__ import annotations

from pathlib import Path

import pytest

from fleet_audit.collection.software_parser import (
    SoftwareParseError,
    SoftwareWarning,
    parse_software,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "raw" / "software"


def test_software_fixture_is_normalised_deduplicated_and_sorted() -> None:
    result = parse_software(FIXTURES / "complete")

    assert result.software == {
        "status": "complete",
        "package_manager": "dpkg",
        "installed_packages": [
            {"name": "acl", "version": "2.3.1-3", "architecture": "amd64"},
            {
                "name": "python3-minimal",
                "version": "3.11.2-1+b1",
                "architecture": "amd64",
            },
            {"name": "zlib1g", "version": "1:1.2.13.dfsg-1", "architecture": "amd64"},
        ],
        "enabled_services": ["cron.service", "ssh.service"],
        "pending_updates": 7,
        "reboot_required": True,
    }
    assert result.warnings == (
        SoftwareWarning(
            code="APT_INDEX_NOT_REFRESHED",
            message=(
                "Pending-update count uses local package indexes, which may be stale; "
                "no index refresh was performed."
            ),
        ),
    )


def test_unavailable_packages_preserve_other_software_facts(tmp_path: Path) -> None:
    (tmp_path / "packages.error").write_text("unavailable\n", encoding="utf-8")
    _copy_fixture_files(tmp_path, "services.txt", "pending-updates.txt", "reboot-required.txt")

    result = parse_software(tmp_path)

    assert result.software == {
        "status": "partial",
        "package_manager": None,
        "installed_packages": [],
        "enabled_services": ["cron.service", "ssh.service"],
        "pending_updates": 7,
        "reboot_required": True,
    }
    assert [warning.code for warning in result.warnings] == [
        "PACKAGES_UNAVAILABLE",
        "APT_INDEX_NOT_REFRESHED",
    ]


def test_empty_enabled_service_list_is_valid(tmp_path: Path) -> None:
    _copy_fixture_files(tmp_path, "packages.tsv", "pending-updates.txt", "reboot-required.txt")
    (tmp_path / "services.txt").write_text("", encoding="utf-8")

    result = parse_software(tmp_path)

    assert result.software["status"] == "complete"
    assert result.software["enabled_services"] == []


@pytest.mark.parametrize(
    ("filename", "content", "warning_code"),
    [
        ("packages.tsv", "broken\tpackage\n", "PACKAGES_INVALID"),
        ("services.txt", "not-a-service\n", "SERVICES_INVALID"),
        ("pending-updates.txt", "-1\n", "PENDING_UPDATES_INVALID"),
        ("reboot-required.txt", "maybe\n", "REBOOT_STATE_INVALID"),
    ],
)
def test_malformed_source_preserves_other_software_inventory(
    tmp_path: Path,
    filename: str,
    content: str,
    warning_code: str,
) -> None:
    _copy_fixture_files(
        tmp_path,
        "packages.tsv",
        "services.txt",
        "pending-updates.txt",
        "reboot-required.txt",
    )
    (tmp_path / filename).write_text(content, encoding="utf-8")

    result = parse_software(tmp_path)

    assert result.software["status"] == "partial"
    assert warning_code in [warning.code for warning in result.warnings]


def test_conflicting_package_versions_are_invalid(tmp_path: Path) -> None:
    _copy_fixture_files(tmp_path, "services.txt", "pending-updates.txt", "reboot-required.txt")
    (tmp_path / "packages.tsv").write_text(
        "acl\t2.3.1-3\tamd64\nacl\t2.3.1-4\tamd64\n",
        encoding="utf-8",
    )

    result = parse_software(tmp_path)

    assert result.software["status"] == "partial"
    assert result.software["installed_packages"] == []
    assert result.software["package_manager"] is None
    assert result.warnings[0].code == "PACKAGES_INVALID"


def test_no_valid_software_source_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(SoftwareParseError, match="no valid software inventory"):
        parse_software(tmp_path)


def _copy_fixture_files(target: Path, *filenames: str) -> None:
    for filename in filenames:
        (target / filename).write_bytes((FIXTURES / "complete" / filename).read_bytes())
