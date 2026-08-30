from __future__ import annotations

from pathlib import Path

import pytest

from fleet_audit.collection.hardware_parser import HardwareParseError, parse_hardware

FIXTURES = Path(__file__).parents[1] / "fixtures" / "raw" / "hardware"


def test_x86_fixture_is_normalised_to_stable_numeric_units() -> None:
    hardware = parse_hardware(FIXTURES / "x86")

    assert hardware == {
        "status": "complete",
        "cpu": {
            "model": "Example Xeon CPU",
            "logical_processors": 2,
        },
        "memory_bytes": 8_589_934_592,
    }


def test_arm_description_is_supported_without_exposing_board_identifiers() -> None:
    hardware = parse_hardware(FIXTURES / "arm")

    assert hardware == {
        "status": "complete",
        "cpu": {
            "model": "ARMv7 Processor rev 3 (v7l)",
            "logical_processors": 2,
        },
        "memory_bytes": 1_992_142_848,
    }
    rendered = repr(hardware)
    assert "Example Board" not in rendered
    assert "0000000000000001" not in rendered


def test_missing_cpu_model_produces_partial_hardware_without_guessing() -> None:
    hardware = parse_hardware(FIXTURES / "missing-model")

    assert hardware == {
        "status": "partial",
        "cpu": {"logical_processors": 2},
        "memory_bytes": 4_294_967_296,
    }


@pytest.mark.parametrize(
    ("filename", "content", "message"),
    [
        ("logical-processors", "0\n", "logical processor"),
        ("logical-processors", "two\n", "logical processor"),
        ("meminfo", "MemTotal: 8192 MB\n", "MemTotal"),
        ("meminfo", "MemFree: 8192 kB\n", "MemTotal"),
    ],
)
def test_malformed_required_values_are_explicit(
    tmp_path: Path,
    filename: str,
    content: str,
    message: str,
) -> None:
    for source_name in ("cpuinfo", "meminfo", "logical-processors"):
        (tmp_path / source_name).write_bytes((FIXTURES / "x86" / source_name).read_bytes())
    (tmp_path / filename).write_text(content, encoding="utf-8")

    with pytest.raises(HardwareParseError, match=message):
        parse_hardware(tmp_path)


def test_missing_raw_input_is_reported() -> None:
    with pytest.raises(HardwareParseError, match="cpuinfo"):
        parse_hardware(FIXTURES / "missing")
