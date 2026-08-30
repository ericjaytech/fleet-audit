from __future__ import annotations

from pathlib import Path

import pytest

from fleet_audit.collection.storage_parser import (
    StorageParseError,
    StorageWarning,
    parse_storage,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "raw" / "storage"


def test_storage_fixture_is_normalised_and_sorted_without_identifiers() -> None:
    result = parse_storage(FIXTURES / "complete")

    assert result.storage == {
        "status": "complete",
        "devices": [
            {"name": "loop0", "type": "loop", "size_bytes": 1_048_576},
            {"name": "nvme0n1", "type": "disk", "size_bytes": 100_000_000_000},
            {"name": "nvme0n1p1", "type": "part", "size_bytes": 99_900_000_000},
            {"name": "sdb", "type": "disk", "size_bytes": 200_000_000_000},
        ],
        "filesystems": [
            {
                "mountpoint": "/",
                "filesystem_type": "ext4",
                "size_bytes": 50_000_000_000,
                "used_bytes": 20_000_000_000,
                "used_percent": 40,
            },
            {
                "mountpoint": "/run",
                "filesystem_type": "tmpfs",
                "size_bytes": 2_000_000_000,
                "used_bytes": 100_000_000,
                "used_percent": 5,
            },
            {
                "mountpoint": "/srv/team files",
                "filesystem_type": "xfs",
                "size_bytes": 1_000_000_000,
                "used_bytes": 425_000_000,
                "used_percent": 42.5,
            },
        ],
    }
    assert result.warnings == ()
    rendered = repr(result.storage)
    assert "excluded-uuid" not in rendered
    assert "excluded-serial" not in rendered


def test_filesystems_without_capacity_are_skipped() -> None:
    result = parse_storage(FIXTURES / "complete")

    mountpoints = {item["mountpoint"] for item in result.storage["filesystems"]}

    assert "/proc" not in mountpoints
    assert "/run/user/1000/doc" not in mountpoints


def test_unavailable_block_devices_preserve_filesystems(tmp_path: Path) -> None:
    (tmp_path / "lsblk.error").write_text("unavailable\n", encoding="utf-8")
    (tmp_path / "findmnt.json").write_bytes((FIXTURES / "complete" / "findmnt.json").read_bytes())

    result = parse_storage(tmp_path)

    assert result.storage["status"] == "partial"
    assert result.storage["devices"] == []
    assert len(result.storage["filesystems"]) == 3
    assert result.warnings == (
        StorageWarning(
            code="BLOCK_DEVICES_UNAVAILABLE",
            message="Block-device inventory is unavailable on this host.",
        ),
    )


def test_malformed_filesystems_preserve_block_devices(tmp_path: Path) -> None:
    (tmp_path / "lsblk.json").write_bytes((FIXTURES / "complete" / "lsblk.json").read_bytes())
    (tmp_path / "findmnt.json").write_text("not JSON\n", encoding="utf-8")

    result = parse_storage(tmp_path)

    assert result.storage["status"] == "partial"
    assert len(result.storage["devices"]) == 4
    assert result.storage["filesystems"] == []
    assert result.warnings == (
        StorageWarning(
            code="FILESYSTEMS_INVALID",
            message="Filesystem inventory output was invalid.",
        ),
    )


@pytest.mark.parametrize(
    ("lsblk_content", "findmnt_content"),
    [
        ('{"blockdevices": [{"name": "sda", "type": "disk", "size": -1}]}', "not JSON"),
        ('{"blockdevices": "not-a-list"}', '{"filesystems": "not-a-list"}'),
    ],
)
def test_no_valid_storage_source_is_an_error(
    tmp_path: Path,
    lsblk_content: str,
    findmnt_content: str,
) -> None:
    (tmp_path / "lsblk.json").write_text(lsblk_content, encoding="utf-8")
    (tmp_path / "findmnt.json").write_text(findmnt_content, encoding="utf-8")

    with pytest.raises(StorageParseError, match="no valid storage"):
        parse_storage(tmp_path)


def test_missing_storage_inputs_are_an_error(tmp_path: Path) -> None:
    with pytest.raises(StorageParseError, match="no valid storage"):
        parse_storage(tmp_path)
