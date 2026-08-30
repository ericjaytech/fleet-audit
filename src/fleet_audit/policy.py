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


def evaluate_policy(policy: Policy, snapshot: dict[str, Any]) -> list[dict[str, str]]:
    if policy.version != 1:
        raise PolicyError("only policy version 1 can be evaluated")

    results: list[dict[str, str]] = []
    for check in policy.checks:
        if isinstance(check, FilesystemUsageCheck):
            results.append(_evaluate_filesystem_usage(check, snapshot))
        elif isinstance(check, PendingUpdatesCheck):
            results.append(_evaluate_pending_updates(check, snapshot))
        elif isinstance(check, MaximumUptimeCheck):
            results.append(_evaluate_maximum_uptime(check, snapshot))
        elif isinstance(check, RequiredServiceCheck):
            results.append(_evaluate_required_service(check, snapshot))
        elif isinstance(check, ProhibitedPortCheck):
            results.append(_evaluate_prohibited_port(check, snapshot))
        else:
            raise PolicyError("policy contains an unsupported check model")
    return results


def _evaluate_filesystem_usage(
    check: FilesystemUsageCheck,
    snapshot: dict[str, Any],
) -> dict[str, str]:
    source_state = _source_state(
        snapshot,
        "storage",
        invalid_codes={"FILESYSTEMS_INVALID", "COLLECTOR_OUTPUT_INVALID"},
        unavailable_codes={"FILESYSTEMS_UNAVAILABLE"},
    )
    if source_state != "available":
        return _source_result(check.id, "Filesystem utilisation", source_state)

    storage = snapshot.get("storage")
    filesystems = storage.get("filesystems") if isinstance(storage, dict) else None
    if not isinstance(filesystems, list):
        return _source_result(check.id, "Filesystem utilisation", "error")

    matches: list[dict[str, Any]] = []
    for filesystem in filesystems:
        if not isinstance(filesystem, dict) or not isinstance(filesystem.get("mountpoint"), str):
            return _source_result(check.id, "Filesystem utilisation", "error")
        if filesystem["mountpoint"] == check.mountpoint:
            matches.append(filesystem)
    if not matches:
        return _result(
            check.id,
            "SKIP",
            "Filesystem utilisation check was skipped.",
            "The configured filesystem was absent from the collected data.",
        )
    if len(matches) != 1:
        return _source_result(check.id, "Filesystem utilisation", "error")

    used_percent = matches[0].get("used_percent")
    if not _valid_number(used_percent, minimum=0, maximum=100):
        return _source_result(check.id, "Filesystem utilisation", "error")

    value = float(used_percent)
    if value >= check.fail_percent:
        status = "FAIL"
        summary = "Filesystem utilisation reached the failure threshold."
    elif value >= check.warn_percent:
        status = "WARN"
        summary = "Filesystem utilisation reached the warning threshold."
    else:
        status = "PASS"
        summary = "Filesystem utilisation is within policy."
    return _result(
        check.id,
        status,
        summary,
        (
            f"{_format_number(value)}% used; warning threshold "
            f"{_format_number(check.warn_percent)}%; failure threshold "
            f"{_format_number(check.fail_percent)}%."
        ),
    )


def _evaluate_pending_updates(
    check: PendingUpdatesCheck,
    snapshot: dict[str, Any],
) -> dict[str, str]:
    source_state = _source_state(
        snapshot,
        "software",
        invalid_codes={"PENDING_UPDATES_INVALID", "COLLECTOR_OUTPUT_INVALID"},
        unavailable_codes={"PENDING_UPDATES_UNAVAILABLE"},
    )
    if source_state != "available":
        return _source_result(check.id, "Pending-update", source_state)

    software = snapshot.get("software")
    pending_updates = software.get("pending_updates") if isinstance(software, dict) else None
    if (
        isinstance(pending_updates, bool)
        or not isinstance(pending_updates, int)
        or pending_updates < 0
    ):
        if pending_updates is None:
            return _source_result(check.id, "Pending-update", "skip")
        return _source_result(check.id, "Pending-update", "error")

    if pending_updates >= check.fail_count:
        status = "FAIL"
        summary = "Pending updates reached the failure threshold."
    elif pending_updates >= check.warn_count:
        status = "WARN"
        summary = "Pending updates reached the warning threshold."
    else:
        status = "PASS"
        summary = "Pending updates are within policy."
    return _result(
        check.id,
        status,
        summary,
        (
            f"{pending_updates} pending; warning threshold {check.warn_count}; "
            f"failure threshold {check.fail_count}."
        ),
    )


def _evaluate_maximum_uptime(
    check: MaximumUptimeCheck,
    snapshot: dict[str, Any],
) -> dict[str, str]:
    source_state = _source_state(
        snapshot,
        "platform",
        invalid_codes={"COLLECTOR_OUTPUT_INVALID"},
        unavailable_codes=set(),
    )
    if source_state != "available":
        return _source_result(check.id, "Maximum-uptime", source_state)

    platform = snapshot.get("platform")
    uptime_seconds = platform.get("uptime_seconds") if isinstance(platform, dict) else None
    if (
        isinstance(uptime_seconds, bool)
        or not isinstance(uptime_seconds, int)
        or uptime_seconds < 0
    ):
        if uptime_seconds is None:
            return _source_result(check.id, "Maximum-uptime", "skip")
        return _source_result(check.id, "Maximum-uptime", "error")

    uptime_days = uptime_seconds / 86_400
    if uptime_days > check.max_days:
        status = "FAIL"
        summary = "Uptime exceeds the configured maximum."
    else:
        status = "PASS"
        summary = "Uptime is within policy."
    return _result(
        check.id,
        status,
        summary,
        (
            f"Uptime {_format_number(uptime_days)} days; maximum "
            f"{_format_number(check.max_days)} days."
        ),
    )


def _evaluate_required_service(
    check: RequiredServiceCheck,
    snapshot: dict[str, Any],
) -> dict[str, str]:
    source_state = _source_state(
        snapshot,
        "software",
        invalid_codes={"SERVICES_INVALID", "COLLECTOR_OUTPUT_INVALID"},
        unavailable_codes={"SERVICES_UNAVAILABLE"},
    )
    if source_state != "available":
        return _source_result(check.id, "Required-service", source_state)

    software = snapshot.get("software")
    enabled_services = software.get("enabled_services") if isinstance(software, dict) else None
    if not isinstance(enabled_services, list) or any(
        not isinstance(service, str) for service in enabled_services
    ):
        return _source_result(check.id, "Required-service", "error")

    if check.service in enabled_services:
        return _result(
            check.id,
            "PASS",
            "The required service is enabled.",
            "The required service appears in the enabled-service inventory.",
        )
    return _result(
        check.id,
        "FAIL",
        "The required service is not enabled.",
        "The required service is absent from the enabled-service inventory.",
    )


def _evaluate_prohibited_port(
    check: ProhibitedPortCheck,
    snapshot: dict[str, Any],
) -> dict[str, str]:
    source_state = _source_state(
        snapshot,
        "network",
        invalid_codes={"SOCKETS_INVALID", "COLLECTOR_OUTPUT_INVALID"},
        unavailable_codes={"SOCKETS_UNAVAILABLE"},
    )
    if source_state != "available":
        return _source_result(check.id, "Prohibited-port", source_state)

    network = snapshot.get("network")
    sockets = network.get("listening_sockets") if isinstance(network, dict) else None
    if not isinstance(sockets, list):
        return _source_result(check.id, "Prohibited-port", "error")

    matching_scopes: list[str] = []
    for socket in sockets:
        if not _valid_socket(socket):
            return _source_result(check.id, "Prohibited-port", "error")
        if socket["protocol"] == check.protocol and socket["port"] == check.port:
            matching_scopes.append(socket["bind_scope"])

    safe_protocol = check.protocol.upper()
    if matching_scopes:
        scopes = ", ".join(sorted(set(matching_scopes)))
        return _result(
            check.id,
            "FAIL",
            "A prohibited port is listening.",
            f"{safe_protocol} port {check.port} is listening with scope: {scopes}.",
        )
    return _result(
        check.id,
        "PASS",
        "No prohibited listener was found.",
        f"No listener matched {safe_protocol} port {check.port}.",
    )


def _source_state(
    snapshot: dict[str, Any],
    collector: str,
    *,
    invalid_codes: set[str],
    unavailable_codes: set[str],
) -> str:
    warning_codes = _warning_codes(snapshot, collector)
    if warning_codes & invalid_codes:
        return "error"

    capability_status = _capability_status(snapshot, collector)
    if capability_status == "error":
        return "error"
    if capability_status == "unavailable":
        return "skip"
    if warning_codes & unavailable_codes:
        return "skip"

    domain = snapshot.get(collector)
    if not isinstance(domain, dict):
        return "error"
    domain_status = domain.get("status")
    if domain_status == "unavailable":
        return "skip"
    if domain_status not in {"complete", "partial"}:
        return "error"
    return "available"


def _warning_codes(snapshot: dict[str, Any], collector: str) -> set[str]:
    collection = snapshot.get("collection")
    warnings = collection.get("warnings") if isinstance(collection, dict) else None
    if not isinstance(warnings, list):
        return set()
    return {
        warning["code"]
        for warning in warnings
        if isinstance(warning, dict)
        and warning.get("collector") == collector
        and isinstance(warning.get("code"), str)
    }


def _capability_status(snapshot: dict[str, Any], collector: str) -> str | None:
    collection = snapshot.get("collection")
    capabilities = collection.get("capabilities") if isinstance(collection, dict) else None
    if not isinstance(capabilities, list):
        return None
    statuses = {
        capability["status"]
        for capability in capabilities
        if isinstance(capability, dict)
        and capability.get("name") == collector
        and capability.get("status") in {"available", "unavailable", "error"}
    }
    if len(statuses) != 1:
        return None
    return statuses.pop()


def _valid_number(value: object, *, minimum: float, maximum: float) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(float(value))
        and minimum <= float(value) <= maximum
    )


def _valid_socket(socket: object) -> bool:
    if not isinstance(socket, dict):
        return False
    protocol = socket.get("protocol")
    port = socket.get("port")
    bind_scope = socket.get("bind_scope")
    return (
        protocol in {"tcp", "udp"}
        and not isinstance(port, bool)
        and isinstance(port, int)
        and 1 <= port <= 65_535
        and bind_scope in {"loopback", "external", "wildcard", "unknown"}
    )


def _source_result(check_id: str, label: str, source_state: str) -> dict[str, str]:
    if source_state == "skip":
        return _result(
            check_id,
            "SKIP",
            f"{label} check was skipped.",
            "The required collected data was unavailable.",
        )
    return _result(
        check_id,
        "ERROR",
        f"{label} check could not be evaluated.",
        "The required collected data was invalid.",
    )


def _result(
    check_id: str,
    status: str,
    summary: str,
    evidence: str,
) -> dict[str, str]:
    return {"id": check_id, "status": status, "summary": summary, "evidence": evidence}


def _format_number(value: float) -> str:
    return f"{value:.2f}".rstrip("0").rstrip(".")


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
