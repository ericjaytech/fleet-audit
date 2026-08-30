"""Shared input validation helpers for collector output parsers."""

from __future__ import annotations

from pathlib import Path


class ParsingError(ValueError):
    """Base class for parser-level errors.

    All parser-specific error types (HardwareParseError, PlatformParseError,
    NetworkParseError, StorageParseError, SoftwareParseError) inherit from
    this class so that shared helpers can raise a single catchable type.
    """


def is_regular_file(path: Path) -> bool:
    """Return True when *path* is a regular file and not a symlink."""
    return not path.is_symlink() and path.is_file()


def text(
    value: object,
    field: str,
    *,
    maximum_length: int,
    error_cls: type[ParsingError] = ParsingError,
) -> str:
    """Validate and return a non-empty, printable string under *maximum_length*."""
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum_length
        or not value.isprintable()
    ):
        raise error_cls(f"invalid {field}")
    return value


def read_required_file(
    path: Path,
    *,
    max_bytes: int,
    label: str | None = None,
    error_cls: type[ParsingError] = ParsingError,
) -> str:
    """Read *path* as a UTF-8 text file, enforcing a size limit.

    Raises *error_cls* when the file is missing, too large or not valid UTF-8.
    """
    file_label = label or path.name
    try:
        if not is_regular_file(path):
            raise error_cls(f"required input is missing: {file_label}")
        with path.open("rb") as input_file:
            raw = input_file.read(max_bytes + 1)
    except OSError as exc:
        raise error_cls(f"could not read input {file_label}") from exc

    if len(raw) > max_bytes:
        raise error_cls(f"input is too large: {file_label}")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise error_cls(f"input is not UTF-8: {file_label}") from exc


def read_lines(
    path: Path,
    *,
    max_bytes: int,
    max_lines: int,
    label: str | None = None,
    error_cls: type[ParsingError] = ParsingError,
) -> list[str]:
    """Read *path* as UTF-8 text and split into lines, enforcing size and line-count limits."""
    content = read_required_file(path, max_bytes=max_bytes, label=label, error_cls=error_cls)
    lines = content.splitlines()
    if len(lines) > max_lines:
        raise error_cls(f"input has too many lines: {label or path.name}")
    return lines
