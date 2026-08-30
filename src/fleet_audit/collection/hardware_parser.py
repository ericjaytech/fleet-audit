"""Normalise raw hardware collector files into the snapshot schema."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from fleet_audit.collection._parsing import ParsingError, read_required_file

_CPUINFO_MAX_BYTES = 1_048_576
_MEMINFO_MAX_BYTES = 262_144
_SMALL_INPUT_MAX_BYTES = 64
_CPU_MODEL_FIELDS = ("model name", "Model Name", "Processor", "cpu", "CPU")
_POSITIVE_INTEGER = re.compile(r"^[1-9][0-9]*$")
_MEMTOTAL = re.compile(r"^\s*([0-9]+)\s+kB\s*$")


class HardwareParseError(ParsingError):
    """Raised when raw hardware output is missing or malformed."""


def parse_hardware(workspace: Path) -> dict[str, Any]:
    """Normalise raw hardware collector files into the snapshot schema."""
    cpuinfo = read_required_file(
        workspace / "cpuinfo", max_bytes=_CPUINFO_MAX_BYTES, error_cls=HardwareParseError
    )
    meminfo = read_required_file(
        workspace / "meminfo", max_bytes=_MEMINFO_MAX_BYTES, error_cls=HardwareParseError
    )
    logical_raw = read_required_file(
        workspace / "logical-processors",
        max_bytes=_SMALL_INPUT_MAX_BYTES,
        error_cls=HardwareParseError,
    )

    logical_processors = _parse_logical_processors(logical_raw)
    memory_bytes = _parse_memory_bytes(meminfo)
    cpu_model = _parse_cpu_model(cpuinfo)

    cpu: dict[str, Any] = {"logical_processors": logical_processors}
    status = "partial"
    if cpu_model is not None:
        cpu["model"] = cpu_model
        status = "complete"

    return {
        "status": status,
        "cpu": cpu,
        "memory_bytes": memory_bytes,
    }


def _parse_logical_processors(content: str) -> int:
    value = content.strip()
    if _POSITIVE_INTEGER.fullmatch(value) is None:
        raise HardwareParseError("invalid logical processor count")
    return int(value)


def _parse_memory_bytes(content: str) -> int:
    memtotal_value: str | None = None
    for line in content.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", maxsplit=1)
        if key != "MemTotal":
            continue
        if memtotal_value is not None:
            raise HardwareParseError("duplicate MemTotal field")
        memtotal_value = value

    if memtotal_value is None:
        raise HardwareParseError("required MemTotal field is missing")
    match = _MEMTOTAL.fullmatch(memtotal_value)
    if match is None:
        raise HardwareParseError("invalid MemTotal value; expected kB")
    return int(match.group(1)) * 1024


def _parse_cpu_model(content: str) -> str | None:
    descriptions: dict[str, set[str]] = {}
    for line in content.splitlines():
        if ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", maxsplit=1))
        if key not in _CPU_MODEL_FIELDS or not value:
            continue
        if len(value) > 1_024 or not value.isprintable():
            raise HardwareParseError(f"invalid CPU description in field {key}")
        descriptions.setdefault(key, set()).add(value)

    for field in _CPU_MODEL_FIELDS:
        values = descriptions.get(field)
        if values is None:
            continue
        if len(values) == 1:
            return next(iter(values))
        return None
    return None
