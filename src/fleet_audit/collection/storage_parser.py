from __future__ import annotations

import json
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

_MAX_INPUT_BYTES = 4_194_304
_MAX_ITEMS = 10_000
_NONNEGATIVE_INTEGER = re.compile(r"^[0-9]+$")
_PERCENTAGE = re.compile(r"^([0-9]+(?:\.[0-9]+)?)%$")


class StorageParseError(ValueError):
    """Raised when no usable storage collector output remains."""


@dataclass(frozen=True)
class StorageWarning:
    code: str
    message: str


@dataclass(frozen=True)
class StorageParseResult:
    storage: dict[str, Any]
    warnings: tuple[StorageWarning, ...]


def parse_storage(workspace: Path) -> StorageParseResult:
    """Normalise independent block-device and filesystem JSON outputs."""
    warnings: list[StorageWarning] = []
    devices: list[dict[str, Any]] | None = None
    filesystems: list[dict[str, Any]] | None = None

    if _is_regular_file(workspace / "lsblk.error"):
        warnings.append(
            StorageWarning(
                code="BLOCK_DEVICES_UNAVAILABLE",
                message="Block-device inventory is unavailable on this host.",
            )
        )
    else:
        try:
            devices = _parse_devices(_load_json(workspace / "lsblk.json"))
        except StorageParseError:
            warnings.append(
                StorageWarning(
                    code="BLOCK_DEVICES_INVALID",
                    message="Block-device inventory output was invalid.",
                )
            )

    if _is_regular_file(workspace / "findmnt.error"):
        warnings.append(
            StorageWarning(
                code="FILESYSTEMS_UNAVAILABLE",
                message="Filesystem inventory is unavailable on this host.",
            )
        )
    else:
        try:
            filesystems = _parse_filesystems(_load_json(workspace / "findmnt.json"))
        except StorageParseError:
            warnings.append(
                StorageWarning(
                    code="FILESYSTEMS_INVALID",
                    message="Filesystem inventory output was invalid.",
                )
            )

    if devices is None and filesystems is None:
        raise StorageParseError("no valid storage inventory source remains")

    return StorageParseResult(
        storage={
            "status": "complete" if devices is not None and filesystems is not None else "partial",
            "devices": devices or [],
            "filesystems": filesystems or [],
        },
        warnings=tuple(warnings),
    )


def _is_regular_file(path: Path) -> bool:
    return not path.is_symlink() and path.is_file()


def _load_json(path: Path) -> object:
    try:
        if not _is_regular_file(path):
            raise StorageParseError(f"required storage input is missing: {path.name}")
        with path.open("rb") as input_file:
            raw = input_file.read(_MAX_INPUT_BYTES + 1)
    except OSError as error:
        raise StorageParseError(f"could not read storage input {path.name}") from error

    if len(raw) > _MAX_INPUT_BYTES:
        raise StorageParseError(f"storage input is too large: {path.name}")
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StorageParseError(f"storage input is not valid JSON: {path.name}") from error
    return document


def _parse_devices(document: object) -> list[dict[str, Any]]:
    items = _document_items(document, "blockdevices")
    devices: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            raise StorageParseError("invalid block-device entry")
        devices.append(
            {
                "name": _text(item.get("name"), "device name", maximum_length=255),
                "type": _text(item.get("type"), "device type", maximum_length=100),
                "size_bytes": _nonnegative_integer(item.get("size"), "device size"),
            }
        )
    return sorted(devices, key=lambda item: (item["name"], item["type"], item["size_bytes"]))


def _parse_filesystems(document: object) -> list[dict[str, Any]]:
    items = _document_items(document, "filesystems")
    filesystems: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            raise StorageParseError("invalid filesystem entry")
        used_percent = _percentage(item.get("use%"))
        if used_percent is None:
            continue

        size_bytes = _nonnegative_integer(item.get("size"), "filesystem size")
        used_bytes = _nonnegative_integer(item.get("used"), "filesystem used size")
        if used_bytes > size_bytes:
            raise StorageParseError("filesystem used size exceeds total size")
        filesystems.append(
            {
                "mountpoint": _text(item.get("target"), "mountpoint", maximum_length=4_096),
                "filesystem_type": _text(
                    item.get("fstype"),
                    "filesystem type",
                    maximum_length=100,
                ),
                "size_bytes": size_bytes,
                "used_bytes": used_bytes,
                "used_percent": used_percent,
            }
        )
    return sorted(
        filesystems,
        key=lambda item: (item["mountpoint"], item["filesystem_type"]),
    )


def _document_items(document: object, key: str) -> list[object]:
    if not isinstance(document, dict):
        raise StorageParseError("storage JSON root is not an object")
    items = document.get(key)
    if not isinstance(items, list) or len(items) > _MAX_ITEMS:
        raise StorageParseError(f"storage JSON field is not a bounded list: {key}")
    return items


def _text(value: object, field: str, *, maximum_length: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum_length
        or not value.isprintable()
    ):
        raise StorageParseError(f"invalid {field}")
    return value


def _nonnegative_integer(value: object, field: str) -> int:
    if isinstance(value, bool):
        raise StorageParseError(f"invalid {field}")
    if isinstance(value, int) and value >= 0:
        return value
    if isinstance(value, str) and _NONNEGATIVE_INTEGER.fullmatch(value):
        return int(value)
    raise StorageParseError(f"invalid {field}")


def _percentage(value: object) -> int | float | None:
    if value is None or value == "-":
        return None
    if not isinstance(value, str) or len(value) > 32:
        raise StorageParseError("invalid filesystem utilisation percentage")
    match = _PERCENTAGE.fullmatch(value)
    if match is None:
        raise StorageParseError("invalid filesystem utilisation percentage")
    try:
        percentage = Decimal(match.group(1))
    except InvalidOperation as error:
        raise StorageParseError("invalid filesystem utilisation percentage") from error
    if percentage > 100:
        raise StorageParseError("filesystem utilisation percentage exceeds 100")
    if percentage == percentage.to_integral_value():
        return int(percentage)
    return float(percentage)
