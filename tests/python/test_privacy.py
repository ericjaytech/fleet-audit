from __future__ import annotations

import json
from pathlib import Path

import pytest

from fleet_audit.collection.network_parser import parse_network
from fleet_audit.validation import SnapshotValidationError, validate_snapshot

FIXTURES = Path(__file__).parents[1] / "fixtures"


def test_published_network_domain_contains_only_reduced_fields() -> None:
    result = parse_network(FIXTURES / "raw" / "network" / "complete")

    assert set(result.network) == {"status", "interfaces", "listening_sockets"}
    assert all(set(item) == {"name", "state"} for item in result.network["interfaces"])
    assert all(
        set(item) == {"protocol", "port", "bind_scope"}
        for item in result.network["listening_sockets"]
    )


@pytest.mark.parametrize(
    ("section", "prohibited_field", "value"),
    [
        ("interface", "address", "192.0.2.10"),
        ("interface", "mac_address", "02:00:00:00:00:01"),
        ("socket", "local_address", "2001:db8::10"),
        ("socket", "process", "private-service --credential secret"),
    ],
)
def test_schema_rejects_network_identifier_and_process_fields(
    section: str,
    prohibited_field: str,
    value: str,
) -> None:
    fixture = FIXTURES / "snapshots" / "complete.json"
    snapshot = json.loads(fixture.read_text(encoding="utf-8"))
    if section == "interface":
        snapshot["network"]["interfaces"][0][prohibited_field] = value
    else:
        snapshot["network"]["listening_sockets"][0][prohibited_field] = value

    with pytest.raises(SnapshotValidationError, match=prohibited_field):
        validate_snapshot(snapshot)
