from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

_MAX_INPUT_BYTES = 4_194_304
_MAX_LINES = 10_000
_INTERFACE_STATES = {"up", "down", "unknown"}
_PROTOCOLS = {"tcp", "udp"}
_BIND_SCOPES = {"loopback", "external", "wildcard", "unknown"}


class NetworkParseError(ValueError):
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

    if _is_regular_file(workspace / "interfaces.error"):
        warnings.append(
            NetworkWarning(
                code="INTERFACES_UNAVAILABLE",
                message="Network-interface inventory is unavailable on this host.",
            )
        )
    else:
        try:
            interfaces = _parse_interfaces(_read_lines(workspace / "interfaces.tsv"))
        except NetworkParseError:
            warnings.append(
                NetworkWarning(
                    code="INTERFACES_INVALID",
                    message="Network-interface inventory output was invalid.",
                )
            )

    if _is_regular_file(workspace / "sockets.error"):
        warnings.append(
            NetworkWarning(
                code="SOCKETS_UNAVAILABLE",
                message="Listening-socket inventory is unavailable on this host.",
            )
        )
    else:
        try:
            sockets = _parse_sockets(_read_lines(workspace / "sockets.tsv"))
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


def _is_regular_file(path: Path) -> bool:
    return not path.is_symlink() and path.is_file()


def _read_lines(path: Path) -> list[str]:
    try:
        if not _is_regular_file(path):
            raise NetworkParseError(f"required network input is missing: {path.name}")
        with path.open("rb") as input_file:
            raw = input_file.read(_MAX_INPUT_BYTES + 1)
    except OSError as error:
        raise NetworkParseError(f"could not read network input {path.name}") from error

    if len(raw) > _MAX_INPUT_BYTES:
        raise NetworkParseError(f"network input is too large: {path.name}")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise NetworkParseError(f"network input is not UTF-8: {path.name}") from error
    if len(lines) > _MAX_LINES:
        raise NetworkParseError(f"network input has too many lines: {path.name}")
    return lines


def _parse_interfaces(lines: list[str]) -> list[dict[str, str]]:
    interfaces: dict[str, str] = {}
    for line in lines:
        fields = line.split("\t")
        if len(fields) != 2:
            raise NetworkParseError("invalid interface entry")
        name = _text(fields[0], "interface name", maximum_length=255)
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


def _text(value: str, field: str, *, maximum_length: int) -> str:
    if not value or len(value) > maximum_length or not value.isprintable():
        raise NetworkParseError(f"invalid {field}")
    return value
