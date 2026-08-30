"""Normalise independent package, service, update and reboot facts from the software collector."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar

from fleet_audit.collection._parsing import ParsingError, is_regular_file, read_lines, text

_MAX_INPUT_BYTES = 4_194_304
_MAX_LINES = 100_000
_MAX_INTEGER_DIGITS = 20


class SoftwareParseError(ParsingError):
    """Raised when no usable software collector output remains."""


@dataclass(frozen=True)
class SoftwareWarning:
    code: str
    message: str


@dataclass(frozen=True)
class SoftwareParseResult:
    software: dict[str, Any]
    warnings: tuple[SoftwareWarning, ...]


_ParsedValue = TypeVar("_ParsedValue")


def parse_software(workspace: Path) -> SoftwareParseResult:
    """Normalise independent package, service, update, and reboot facts."""
    warnings: list[SoftwareWarning] = []

    packages = _parse_source(
        workspace,
        data_filename="packages.tsv",
        error_filename="packages.error",
        parser=_parse_packages,
        unavailable_warning=SoftwareWarning(
            code="PACKAGES_UNAVAILABLE",
            message="Installed-package inventory is unavailable on this host.",
        ),
        invalid_warning=SoftwareWarning(
            code="PACKAGES_INVALID",
            message="Installed-package inventory output was invalid.",
        ),
        warnings=warnings,
    )
    services = _parse_source(
        workspace,
        data_filename="services.txt",
        error_filename="services.error",
        parser=_parse_services,
        unavailable_warning=SoftwareWarning(
            code="SERVICES_UNAVAILABLE",
            message="Enabled-service inventory is unavailable on this host.",
        ),
        invalid_warning=SoftwareWarning(
            code="SERVICES_INVALID",
            message="Enabled-service inventory output was invalid.",
        ),
        warnings=warnings,
    )
    pending_updates = _parse_source(
        workspace,
        data_filename="pending-updates.txt",
        error_filename="pending-updates.error",
        parser=_parse_pending_updates,
        unavailable_warning=SoftwareWarning(
            code="PENDING_UPDATES_UNAVAILABLE",
            message="Pending-update count is unavailable on this host.",
        ),
        invalid_warning=SoftwareWarning(
            code="PENDING_UPDATES_INVALID",
            message="Pending-update count output was invalid.",
        ),
        warnings=warnings,
    )
    if pending_updates is not None:
        warnings.append(
            SoftwareWarning(
                code="APT_INDEX_NOT_REFRESHED",
                message=(
                    "Pending-update count uses local package indexes, which may be stale; "
                    "no index refresh was performed."
                ),
            )
        )
    reboot_required = _parse_source(
        workspace,
        data_filename="reboot-required.txt",
        error_filename="reboot-required.error",
        parser=_parse_reboot_required,
        unavailable_warning=SoftwareWarning(
            code="REBOOT_STATE_UNAVAILABLE",
            message="Reboot-required state is unavailable on this host.",
        ),
        invalid_warning=SoftwareWarning(
            code="REBOOT_STATE_INVALID",
            message="Reboot-required state output was invalid.",
        ),
        warnings=warnings,
    )

    available_sources = (packages, services, pending_updates, reboot_required)
    if all(source is None for source in available_sources):
        raise SoftwareParseError("no valid software inventory source remains")

    return SoftwareParseResult(
        software={
            "status": (
                "complete" if all(source is not None for source in available_sources) else "partial"
            ),
            "package_manager": "dpkg" if packages is not None else None,
            "installed_packages": packages or [],
            "enabled_services": services or [],
            "pending_updates": pending_updates,
            "reboot_required": reboot_required,
        },
        warnings=tuple(warnings),
    )


def _parse_source(
    workspace: Path,
    *,
    data_filename: str,
    error_filename: str,
    parser: Callable[[list[str]], _ParsedValue],
    unavailable_warning: SoftwareWarning,
    invalid_warning: SoftwareWarning,
    warnings: list[SoftwareWarning],
) -> _ParsedValue | None:
    if is_regular_file(workspace / error_filename):
        warnings.append(unavailable_warning)
        return None
    try:
        return parser(
            read_lines(
                workspace / data_filename,
                max_bytes=_MAX_INPUT_BYTES,
                max_lines=_MAX_LINES,
                error_cls=SoftwareParseError,
            )
        )
    except SoftwareParseError:
        warnings.append(invalid_warning)
        return None


def _parse_packages(lines: list[str]) -> list[dict[str, str]]:
    packages: dict[tuple[str, str], str] = {}
    for line in lines:
        fields = line.split("\t")
        if len(fields) != 3:
            raise SoftwareParseError("invalid installed-package entry")
        name = text(fields[0], "package name", maximum_length=255, error_cls=SoftwareParseError)
        version = text(
            fields[1], "package version", maximum_length=1_024, error_cls=SoftwareParseError
        )
        architecture = text(
            fields[2], "package architecture", maximum_length=100, error_cls=SoftwareParseError
        )
        key = (name, architecture)
        previous_version = packages.get(key)
        if previous_version is not None and previous_version != version:
            raise SoftwareParseError("conflicting installed-package versions")
        packages[key] = version
    if not packages:
        raise SoftwareParseError("installed-package inventory is empty")
    return [
        {"name": name, "version": version, "architecture": architecture}
        for (name, architecture), version in sorted(packages.items())
    ]


def _parse_services(lines: list[str]) -> list[str]:
    services: set[str] = set()
    for line in lines:
        service = text(line, "service name", maximum_length=255, error_cls=SoftwareParseError)
        if not service.endswith(".service"):
            raise SoftwareParseError("invalid service name")
        services.add(service)
    return sorted(services)


def _parse_pending_updates(lines: list[str]) -> int:
    if (
        len(lines) != 1
        or len(lines[0]) > _MAX_INTEGER_DIGITS
        or not lines[0].isascii()
        or not lines[0].isdecimal()
    ):
        raise SoftwareParseError("invalid pending-update count")
    return int(lines[0])


def _parse_reboot_required(lines: list[str]) -> bool:
    if lines == ["true"]:
        return True
    if lines == ["false"]:
        return False
    raise SoftwareParseError("invalid reboot-required state")
