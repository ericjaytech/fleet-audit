"""Normalise independent block-device and filesystem JSON outputs from the storage collector."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from fleet_audit.collection._parsing import ParsingError, is_regular_file, read_required_file, text

_MAX_INPUT_BYTES = 4_194_304
_MAX_ITEMS = 10_000
_NONNEGATIVE_INTEGER = re.compile(r"^[0-9]+$")
_PERCENTAGE = re.compile(r"^([0-9]+(?:\.[0-9]+)?)%$")


class StorageParseError(ParsingError):
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

    if is_regular_file(workspace / "lsblk.error"):
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

    if is_regular_file(workspace / "findmnt.error"):
        warnings.append(
            StorageWarning(
                code="FILESYSTEMS_UNAVAILABLE",
                message="Filesystem inventory is unavailable on this host.",
            )
        )
    else:
        try:
            filesystems, omitted_filesystems = _parse_filesystems(
                _load_json(workspace / "findmnt.json")
            )
            if omitted_filesystems:
                warnings.append(
                    StorageWarning(
                        code="FILESYSTEMS_INCOMPLETE",
                        message=(
                            "Some mounted filesystems did not expose capacity data and "
                            "were omitted."
                        ),
                    )
                )
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
            "status": (
                "complete"
                if devices is not None and filesystems is not None and not warnings
                else "partial"
            ),
            "devices": devices or [],
            "filesystems": filesystems or [],
        },
        warnings=tuple(warnings),
    )


def _load_json(path: Path) -> object:
    raw = read_required_file(
        path, max_bytes=_MAX_INPUT_BYTES, error_cls=StorageParseError, label=path.name
    )
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise StorageParseError(f"storage input is not valid JSON: {path.name}") from exc
    return document


def _parse_devices(document: object) -> list[dict[str, Any]]:
    items = _document_items(document, "blockdevices")
    devices: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            raise StorageParseError("invalid block-device entry")
        devices.append(
            {
                "name": text(
                    item.get("name"), "device name", maximum_length=255, error_cls=StorageParseError
                ),
                "type": text(
                    item.get("type"), "device type", maximum_length=100, error_cls=StorageParseError
                ),
                "size_bytes": _nonnegative_integer(item.get("size"), "device size"),
            }
        )
    return sorted(devices, key=lambda item: (item["name"], item["type"], item["size_bytes"]))


def _parse_filesystems(document: object) -> tuple[list[dict[str, Any]], bool]:
    items = _document_items(document, "filesystems")
    filesystems: list[dict[str, Any]] = []
    omitted_filesystems = False
    for item in items:
        if not isinstance(item, dict):
            raise StorageParseError("invalid filesystem entry")
        raw_percentage = item.get("use%")
        if raw_percentage is None:
            omitted_filesystems = True
            continue
        used_percent = _percentage(raw_percentage)
        if used_percent is None:
            continue

        size_bytes = _nonnegative_integer(item.get("size"), "filesystem size")
        used_bytes = _nonnegative_integer(item.get("used"), "filesystem used size")
        if used_bytes > size_bytes:
            raise StorageParseError("filesystem used size exceeds total size")
        filesystems.append(
            {
                "mountpoint": text(
                    item.get("target"),
                    "mountpoint",
                    maximum_length=4_096,
                    error_cls=StorageParseError,
                ),
                "filesystem_type": text(
                    item.get("fstype"),
                    "filesystem type",
                    maximum_length=100,
                    error_cls=StorageParseError,
                ),
                "size_bytes": size_bytes,
                "used_bytes": used_bytes,
                "used_percent": used_percent,
            }
        )
    return (
        sorted(
            filesystems,
            key=lambda item: (item["mountpoint"], item["filesystem_type"]),
        ),
        omitted_filesystems,
    )


def _document_items(document: object, key: str) -> list[object]:
    if not isinstance(document, dict):
        raise StorageParseError("storage JSON root is not an object")
    items = document.get(key)
    if not isinstance(items, list) or len(items) > _MAX_ITEMS:
        raise StorageParseError(f"storage JSON field is not a bounded list: {key}")
    return items


def _nonnegative_integer(value: object, field: str) -> int:
    if isinstance(value, bool):
        raise StorageParseError(f"invalid {field}")
    if isinstance(value, int) and value >= 0:
        return value
    if isinstance(value, str) and _NONNEGATIVE_INTEGER.fullmatch(value):
        return int(value)
    raise StorageParseError(f"invalid {field}")


def _percentage(value: object) -> int | float | None:
    if value == "-":
        return None
    if not isinstance(value, str) or len(value) > 32:
        raise StorageParseError("invalid filesystem utilisation percentage")
    match = _PERCENTAGE.fullmatch(value)
    if match is None:
        raise StorageParseError("invalid filesystem utilisation percentage")
    try:
        percentage = Decimal(match.group(1))
    except InvalidOperation as exc:
        raise StorageParseError("invalid filesystem utilisation percentage") from exc
    if percentage > 100:
        raise StorageParseError("filesystem utilisation percentage exceeds 100")
    if percentage == percentage.to_integral_value():
        return int(percentage)
    return float(percentage)
