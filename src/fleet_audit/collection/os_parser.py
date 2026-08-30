"""Normalise raw platform collector files into the snapshot schema."""

from __future__ import annotations

import re
import shlex
from decimal import ROUND_FLOOR, Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from fleet_audit.collection._parsing import ParsingError, read_required_file

_MAX_INPUT_BYTES = 65_536
_OS_KEY = re.compile(r"^[A-Z][A-Z0-9_]*$")
_OS_ID = re.compile(r"^[a-z0-9._-]+$")
_PROC_SECONDS = re.compile(r"^[0-9]+(?:\.[0-9]+)?$")
_REQUIRED_OS_FIELDS = ("ID", "VERSION_ID", "PRETTY_NAME")


class PlatformParseError(ParsingError):
    """Raised when raw platform output is missing or malformed."""


def parse_platform(workspace: Path) -> dict[str, Any]:
    """Normalise raw platform collector files into the snapshot schema."""
    os_release = _parse_os_release(
        read_required_file(
            workspace / "os-release", max_bytes=_MAX_INPUT_BYTES, error_cls=PlatformParseError
        )
    )
    kernel = _parse_single_line(
        "kernel",
        read_required_file(
            workspace / "kernel", max_bytes=_MAX_INPUT_BYTES, error_cls=PlatformParseError
        ),
    )
    architecture = _parse_single_line(
        "architecture",
        read_required_file(
            workspace / "architecture", max_bytes=_MAX_INPUT_BYTES, error_cls=PlatformParseError
        ),
    )
    uptime_seconds = _parse_uptime(
        read_required_file(
            workspace / "uptime", max_bytes=_MAX_INPUT_BYTES, error_cls=PlatformParseError
        )
    )

    return {
        "status": "complete",
        "os": {
            "id": os_release["ID"],
            "version_id": os_release["VERSION_ID"],
            "pretty_name": os_release["PRETTY_NAME"],
        },
        "kernel": kernel,
        "architecture": architecture,
        "uptime_seconds": uptime_seconds,
    }


def _parse_os_release(content: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in line:
            raise PlatformParseError(f"invalid os-release assignment at line {line_number}")

        key, raw_value = line.split("=", maxsplit=1)
        if not _OS_KEY.fullmatch(key):
            raise PlatformParseError(f"invalid os-release key at line {line_number}")
        if key in values:
            raise PlatformParseError(f"duplicate os-release key: {key}")

        try:
            decoded = (
                [""] if raw_value == "" else shlex.split(raw_value, comments=False, posix=True)
            )
        except ValueError as error:
            raise PlatformParseError(f"invalid os-release value for {key}") from error
        if len(decoded) != 1:
            raise PlatformParseError(f"invalid os-release value for {key}")
        values[key] = decoded[0]

    for field in _REQUIRED_OS_FIELDS:
        if not values.get(field):
            raise PlatformParseError(f"required os-release field is missing: {field}")

    if not _OS_ID.fullmatch(values["ID"]):
        raise PlatformParseError("invalid os-release value for ID")
    for field in _REQUIRED_OS_FIELDS:
        _require_printable(field, values[field])
    return values


def _parse_single_line(field: str, content: str) -> str:
    lines = content.splitlines()
    if len(lines) != 1 or not lines[0]:
        raise PlatformParseError(f"invalid {field} value")
    _require_printable(field, lines[0])
    return lines[0]


def _parse_uptime(content: str) -> int:
    fields = content.split()
    if len(fields) != 2 or any(_PROC_SECONDS.fullmatch(field) is None for field in fields):
        raise PlatformParseError("invalid uptime value")

    try:
        uptime = Decimal(fields[0])
    except InvalidOperation as error:
        raise PlatformParseError("invalid uptime value") from error
    if not uptime.is_finite() or uptime < 0:
        raise PlatformParseError("invalid uptime value")
    return int(uptime.to_integral_value(rounding=ROUND_FLOOR))


def _require_printable(field: str, value: str) -> None:
    if len(value) > 1_024 or not value.isprintable():
        raise PlatformParseError(f"invalid {field} value")
