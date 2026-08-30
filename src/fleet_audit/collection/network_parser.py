"""Normalise independently reduced interface and socket facts from the network collector."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fleet_audit.collection._parsing import ParsingError, is_regular_file, read_lines, text

_MAX_INPUT_BYTES = 4_194_304
_MAX_LINES = 10_000
_INTERFACE_STATES = {"up", "down", "unknown"}
_PROTOCOLS = {"tcp", "udp"}
_BIND_SCOPES = {"loopback", "external", "wildcard", "unknown"}


class NetworkParseError(ParsingError):
    """Raised when no usable network collector output remains."""


@dataclass(frozen=True)
class NetworkWarning:
    code: str
    message: str


@dataclass(frozen=True)
class NetworkParseResult:
    network: dict[str, Any]
    warnings: tuple[NetworkWarning, ...]


def parse_network(workspace: Path) -> NetworkParseResult:
    """Normalise independently reduced interface and socket facts."""
    warnings: list[NetworkWarning] = []
    interfaces: list[dict[str, str]] | None = None
    sockets: list[dict[str, Any]] | None = None

    if is_regular_file(workspace / "interfaces.error"):
        warnings.append(
            NetworkWarning(
                code="INTERFACES_UNAVAILABLE",
                message="Network-interface inventory is unavailable on this host.",
            )
        )
    else:
        try:
            interfaces = _parse_interfaces(
                read_lines(
                    workspace / "interfaces.tsv",
                    max_bytes=_MAX_INPUT_BYTES,
                    max_lines=_MAX_LINES,
                    error_cls=NetworkParseError,
                )
            )
        except NetworkParseError:
            warnings.append(
                NetworkWarning(
                    code="INTERFACES_INVALID",
                    message="Network-interface inventory output was invalid.",
                )
            )

    if is_regular_file(workspace / "sockets.error"):
        warnings.append(
            NetworkWarning(
                code="SOCKETS_UNAVAILABLE",
                message="Listening-socket inventory is unavailable on this host.",
            )
        )
    else:
        try:
            sockets = _parse_sockets(
                read_lines(
                    workspace / "sockets.tsv",
                    max_bytes=_MAX_INPUT_BYTES,
                    max_lines=_MAX_LINES,
                    error_cls=NetworkParseError,
                )
            )
        except NetworkParseError:
            warnings.append(
                NetworkWarning(
                    code="SOCKETS_INVALID",
                    message="Listening-socket inventory output was invalid.",
                )
            )

    if interfaces is None and sockets is None:
        raise NetworkParseError("no valid network inventory source remains")

    return NetworkParseResult(
        network={
            "status": "complete" if interfaces is not None and sockets is not None else "partial",
            "interfaces": interfaces or [],
            "listening_sockets": sockets or [],
        },
        warnings=tuple(warnings),
    )


def _parse_interfaces(lines: list[str]) -> list[dict[str, str]]:
    interfaces: dict[str, str] = {}
    for line in lines:
        fields = line.split("\t")
        if len(fields) != 2:
            raise NetworkParseError("invalid interface entry")
        name = text(fields[0], "interface name", maximum_length=255, error_cls=NetworkParseError)
        state = fields[1]
        if state not in _INTERFACE_STATES:
            raise NetworkParseError("invalid interface state")
        previous_state = interfaces.get(name)
        if previous_state is not None and previous_state != state:
            raise NetworkParseError("conflicting interface states")
        interfaces[name] = state
    return [
        {"name": name, "state": state}
        for name, state in sorted(interfaces.items(), key=lambda item: item[0])
    ]


def _parse_sockets(lines: list[str]) -> list[dict[str, Any]]:
    sockets: set[tuple[str, int, str]] = set()
    for line in lines:
        fields = line.split("\t")
        if len(fields) != 3:
            raise NetworkParseError("invalid listening-socket entry")
        protocol, raw_port, bind_scope = fields
        if protocol not in _PROTOCOLS:
            raise NetworkParseError("invalid listening-socket protocol")
        if not raw_port.isascii() or not raw_port.isdecimal():
            raise NetworkParseError("invalid listening-socket port")
        port = int(raw_port)
        if not 1 <= port <= 65_535:
            raise NetworkParseError("listening-socket port is outside 1-65535")
        if bind_scope not in _BIND_SCOPES:
            raise NetworkParseError("invalid listening-socket bind scope")
        sockets.add((protocol, port, bind_scope))
    return [
        {"protocol": protocol, "port": port, "bind_scope": bind_scope}
        for protocol, port, bind_scope in sorted(sockets)
    ]
