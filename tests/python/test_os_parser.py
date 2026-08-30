from __future__ import annotations

from pathlib import Path

import pytest

from fleet_audit.collection.os_parser import PlatformParseError, parse_platform

FIXTURES = Path(__file__).parents[1] / "fixtures" / "raw"


def test_ubuntu_fixture_is_normalised() -> None:
    platform = parse_platform(FIXTURES / "ubuntu-24.04")

    assert platform == {
        "status": "complete",
        "os": {
            "id": "ubuntu",
            "version_id": "24.04",
            "pretty_name": "Ubuntu 24.04.3 LTS",
        },
        "kernel": "6.8.0-79-generic",
        "architecture": "x86_64",
        "uptime_seconds": 12345,
    }


def test_os_release_quoted_escapes_are_decoded_without_expansion(tmp_path: Path) -> None:
    (tmp_path / "os-release").write_text(
        'ID=test\nVERSION_ID="1.0"\nPRETTY_NAME="Test \\"Stable\\" $HOME"\n',
        encoding="utf-8",
    )
    (tmp_path / "kernel").write_text("6.8.0\n", encoding="utf-8")
    (tmp_path / "architecture").write_text("aarch64\n", encoding="utf-8")
    (tmp_path / "uptime").write_text("0.99 4.25\n", encoding="utf-8")

    platform = parse_platform(tmp_path)

    assert platform["os"]["pretty_name"] == 'Test "Stable" $HOME'
    assert platform["uptime_seconds"] == 0


@pytest.mark.parametrize(
    ("fixture_name", "message"),
    [
        ("malformed-os", "VERSION_ID"),
        ("missing", "os-release"),
    ],
)
def test_missing_platform_inputs_are_reported_without_guesses(
    fixture_name: str,
    message: str,
) -> None:
    with pytest.raises(PlatformParseError, match=message):
        parse_platform(FIXTURES / fixture_name)


def test_invalid_uptime_is_reported(tmp_path: Path) -> None:
    for name in ("os-release", "kernel", "architecture"):
        source = FIXTURES / "malformed-os" / name
        (tmp_path / name).write_bytes(source.read_bytes())
    (tmp_path / "os-release").write_text(
        'ID=test\nVERSION_ID="1"\nPRETTY_NAME="Test Linux"\n',
        encoding="utf-8",
    )
    (tmp_path / "uptime").write_text("not-a-number 10.0\n", encoding="utf-8")

    with pytest.raises(PlatformParseError, match="uptime"):
        parse_platform(tmp_path)
