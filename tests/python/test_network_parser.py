from __future__ import annotations

from pathlib import Path

import pytest

from fleet_audit.collection.network_parser import (
    NetworkParseError,
    NetworkWarning,
    parse_network,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "raw" / "network"


def test_network_fixture_is_normalised_deduplicated_and_sorted() -> None:
    result = parse_network(FIXTURES / "complete")

    assert result.network == {
        "status": "complete",
        "interfaces": [
            {"name": "ens5", "state": "up"},
            {"name": "lo", "state": "unknown"},
            {"name": "wlan0", "state": "down"},
        ],
        "listening_sockets": [
            {"protocol": "tcp", "port": 443, "bind_scope": "wildcard"},
            {"protocol": "tcp", "port": 631, "bind_scope": "loopback"},
            {"protocol": "tcp", "port": 8080, "bind_scope": "external"},
            {"protocol": "udp", "port": 53, "bind_scope": "loopback"},
            {"protocol": "udp", "port": 5353, "bind_scope": "wildcard"},
        ],
    }
    assert result.warnings == ()


def test_unavailable_ip_preserves_listening_sockets(tmp_path: Path) -> None:
    (tmp_path / "interfaces.error").write_text("unavailable\n", encoding="utf-8")
    (tmp_path / "sockets.tsv").write_bytes((FIXTURES / "complete" / "sockets.tsv").read_bytes())

    result = parse_network(tmp_path)

    assert result.network["status"] == "partial"
    assert result.network["interfaces"] == []
    assert len(result.network["listening_sockets"]) == 5
    assert result.warnings == (
        NetworkWarning(
            code="INTERFACES_UNAVAILABLE",
            message="Network-interface inventory is unavailable on this host.",
        ),
    )


def test_unavailable_ss_preserves_interfaces(tmp_path: Path) -> None:
    (tmp_path / "interfaces.tsv").write_bytes(
        (FIXTURES / "complete" / "interfaces.tsv").read_bytes()
    )
    (tmp_path / "sockets.error").write_text("unavailable\n", encoding="utf-8")

    result = parse_network(tmp_path)

    assert result.network["status"] == "partial"
    assert len(result.network["interfaces"]) == 3
    assert result.network["listening_sockets"] == []
    assert result.warnings == (
        NetworkWarning(
            code="SOCKETS_UNAVAILABLE",
            message="Listening-socket inventory is unavailable on this host.",
        ),
    )


@pytest.mark.parametrize(
    ("filename", "content", "warning_code"),
    [
        ("interfaces.tsv", "eth0\tnot-a-state\n", "INTERFACES_INVALID"),
        ("sockets.tsv", "tcp\t70000\texternal\n", "SOCKETS_INVALID"),
        ("sockets.tsv", "tcp\t22\texternal\textra\n", "SOCKETS_INVALID"),
    ],
)
def test_malformed_source_preserves_other_network_inventory(
    tmp_path: Path,
    filename: str,
    content: str,
    warning_code: str,
) -> None:
    (tmp_path / "interfaces.tsv").write_bytes(
        (FIXTURES / "complete" / "interfaces.tsv").read_bytes()
    )
    (tmp_path / "sockets.tsv").write_bytes((FIXTURES / "complete" / "sockets.tsv").read_bytes())
    (tmp_path / filename).write_text(content, encoding="utf-8")

    result = parse_network(tmp_path)

    assert result.network["status"] == "partial"
    assert [warning.code for warning in result.warnings] == [warning_code]
    if filename == "interfaces.tsv":
        assert result.network["interfaces"] == []
        assert len(result.network["listening_sockets"]) == 5
    else:
        assert len(result.network["interfaces"]) == 3
        assert result.network["listening_sockets"] == []


def test_no_valid_network_source_is_an_error(tmp_path: Path) -> None:
    (tmp_path / "interfaces.tsv").write_text("eth0\tinvalid\n", encoding="utf-8")
    (tmp_path / "sockets.tsv").write_text("tcp\tnot-a-port\texternal\n", encoding="utf-8")

    with pytest.raises(NetworkParseError, match="no valid network inventory"):
        parse_network(tmp_path)


def test_missing_network_inputs_are_an_error(tmp_path: Path) -> None:
    with pytest.raises(NetworkParseError, match="no valid network inventory"):
        parse_network(tmp_path)
