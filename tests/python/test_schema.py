from __future__ import annotations

import json
from pathlib import Path

import pytest

from fleet_audit.validation import SnapshotValidationError, load_schema, validate_snapshot

FIXTURES = Path(__file__).parents[1] / "fixtures" / "snapshots"


def read_fixture(name: str) -> object:
    with (FIXTURES / name).open(encoding="utf-8") as fixture_file:
        return json.load(fixture_file)


@pytest.mark.parametrize("fixture_name", ["complete.json", "partial.json"])
def test_valid_snapshot_fixtures_conform_to_schema(fixture_name: str) -> None:
    validate_snapshot(read_fixture(fixture_name))


def test_schema_is_valid_draft_2020_12() -> None:
    schema = load_schema()

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["properties"]["schema_version"]["const"] == "1.0"


def test_snapshot_rejects_prohibited_hostname_field() -> None:
    with pytest.raises(SnapshotValidationError, match=r"host.*hostname"):
        validate_snapshot(read_fixture("invalid.json"))


def test_snapshot_rejects_invalid_timestamp_format() -> None:
    snapshot = read_fixture("complete.json")
    assert isinstance(snapshot, dict)
    snapshot["collected_at"] = "29 August 2026"

    with pytest.raises(SnapshotValidationError, match="collected_at"):
        validate_snapshot(snapshot)
