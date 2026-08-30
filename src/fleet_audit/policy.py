from __future__ import annotations

import math
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_MAX_POLICY_BYTES = 1_048_576
_CHECK_ID = re.compile(r"^[a-z][a-z0-9_.-]*$")


class PolicyError(ValueError):
    """Raised when a policy file is unreadable or invalid."""


@dataclass(frozen=True)
class FilesystemUsageCheck:
    id: str
    mountpoint: str
    warn_percent: float
    fail_percent: float


@dataclass(frozen=True)
class PendingUpdatesCheck:
    id: str
    warn_count: int
    fail_count: int


@dataclass(frozen=True)
class MaximumUptimeCheck:
    id: str
    max_days: float


@dataclass(frozen=True)
class RequiredServiceCheck:
    id: str
    service: str


@dataclass(frozen=True)
class ProhibitedPortCheck:
    id: str
    protocol: str
    port: int


PolicyCheck = (
    FilesystemUsageCheck
    | PendingUpdatesCheck
    | MaximumUptimeCheck
    | RequiredServiceCheck
    | ProhibitedPortCheck
)


@dataclass(frozen=True)
class Policy:
    version: int
    checks: tuple[PolicyCheck, ...]


def load_policy(path: Path) -> Policy:
    try:
        with path.open("rb") as policy_file:
            raw_policy = policy_file.read(_MAX_POLICY_BYTES + 1)
    except OSError as error:
        raise PolicyError(f"could not read policy: {error.strerror}") from error

    if len(raw_policy) > _MAX_POLICY_BYTES:
        raise PolicyError("policy exceeds the 1 MiB size limit")
    try:
        document = tomllib.loads(raw_policy.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise PolicyError("invalid TOML policy") from error

    return _parse_policy(document)


def _parse_policy(document: dict[str, Any]) -> Policy:
    _reject_unknown_fields(document, {"version", "checks"}, "policy")
    if "version" not in document:
        raise PolicyError("policy: missing field: version")
    if "checks" not in document:
        raise PolicyError("policy: missing field: checks")

    version = _integer(document["version"], "policy.version")
    if version != 1:
        raise PolicyError("policy.version: only version 1 is supported")

    raw_checks = document["checks"]
    if not isinstance(raw_checks, list) or not raw_checks:
        raise PolicyError("policy.checks: expected a non-empty array of tables")

    checks: list[PolicyCheck] = []
    seen_ids: set[str] = set()
    for index, raw_check in enumerate(raw_checks):
        location = f"checks[{index}]"
        if not isinstance(raw_check, dict):
            raise PolicyError(f"{location}: expected a table")
        check = _parse_check(raw_check, location)
        if check.id in seen_ids:
            raise PolicyError(f"{location}: duplicate check id")
        seen_ids.add(check.id)
        checks.append(check)

    return Policy(version=version, checks=tuple(checks))


def _parse_check(raw_check: dict[str, Any], location: str) -> PolicyCheck:
    check_id = _check_id(raw_check.get("id"), f"{location}.id")
    check_type = _text(raw_check.get("type"), f"{location}.type")

    if check_type == "filesystem_usage":
        _require_fields(
            raw_check,
            {"id", "type", "mountpoint", "warn_percent", "fail_percent"},
            location,
        )
        warning = _percentage(raw_check["warn_percent"], f"{location}.warn_percent")
        failure = _percentage(raw_check["fail_percent"], f"{location}.fail_percent")
        _validate_threshold_order(warning, failure, location)
        return FilesystemUsageCheck(
            id=check_id,
            mountpoint=_text(raw_check["mountpoint"], f"{location}.mountpoint"),
            warn_percent=warning,
            fail_percent=failure,
        )

    if check_type == "pending_updates":
        _require_fields(raw_check, {"id", "type", "warn_count", "fail_count"}, location)
        warning = _non_negative_integer(raw_check["warn_count"], f"{location}.warn_count")
        failure = _non_negative_integer(raw_check["fail_count"], f"{location}.fail_count")
        _validate_threshold_order(warning, failure, location)
        return PendingUpdatesCheck(
            id=check_id,
            warn_count=warning,
            fail_count=failure,
        )

    if check_type == "maximum_uptime":
        _require_fields(raw_check, {"id", "type", "max_days"}, location)
        max_days = _finite_number(raw_check["max_days"], f"{location}.max_days")
        if max_days <= 0:
            raise PolicyError(f"{location}.max_days: expected a value greater than zero")
        return MaximumUptimeCheck(id=check_id, max_days=max_days)

    if check_type == "required_service":
        _require_fields(raw_check, {"id", "type", "service"}, location)
        return RequiredServiceCheck(
            id=check_id,
            service=_text(raw_check["service"], f"{location}.service"),
        )

    if check_type == "prohibited_port":
        _require_fields(raw_check, {"id", "type", "protocol", "port"}, location)
        protocol = _text(raw_check["protocol"], f"{location}.protocol")
        if protocol not in {"tcp", "udp"}:
            raise PolicyError(f"{location}.protocol: expected tcp or udp")
        port = _integer(raw_check["port"], f"{location}.port")
        if not 1 <= port <= 65_535:
            raise PolicyError(f"{location}.port: expected a value from 1 to 65535")
        return ProhibitedPortCheck(id=check_id, protocol=protocol, port=port)

    raise PolicyError(f"{location}.type: unsupported check type")


def _require_fields(raw_check: dict[str, Any], expected: set[str], location: str) -> None:
    _reject_unknown_fields(raw_check, expected, location)
    missing = sorted(expected - raw_check.keys())
    if missing:
        raise PolicyError(f"{location}: missing field: {missing[0]}")


def _reject_unknown_fields(
    document: dict[str, Any], expected: set[str], location: str
) -> None:
    unknown = sorted(document.keys() - expected)
    if unknown:
        raise PolicyError(f"{location}: unknown field: {unknown[0]}")


def _check_id(value: object, location: str) -> str:
    check_id = _text(value, location)
    if _CHECK_ID.fullmatch(check_id) is None:
        raise PolicyError(f"{location}: expected a lowercase policy check identifier")
    return check_id


def _text(value: object, location: str) -> str:
    if not isinstance(value, str) or not value or not value.isprintable():
        raise PolicyError(f"{location}: expected non-empty printable text")
    return value


def _integer(value: object, location: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PolicyError(f"{location}: expected an integer")
    return value


def _non_negative_integer(value: object, location: str) -> int:
    integer = _integer(value, location)
    if integer < 0:
        raise PolicyError(f"{location}: expected a non-negative integer")
    return integer


def _finite_number(value: object, location: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PolicyError(f"{location}: expected a number")
    number = float(value)
    if not math.isfinite(number):
        raise PolicyError(f"{location}: expected a finite number")
    return number


def _percentage(value: object, location: str) -> float:
    percentage = _finite_number(value, location)
    if not 0 <= percentage <= 100:
        raise PolicyError(f"{location}: expected a percentage from 0 to 100")
    return percentage


def _validate_threshold_order(warning: float, failure: float, location: str) -> None:
    if warning >= failure:
        raise PolicyError(
            f"{location}: warning threshold must be less than failure threshold"
        )
