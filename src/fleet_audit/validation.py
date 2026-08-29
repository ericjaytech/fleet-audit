from __future__ import annotations

import json
from collections.abc import Iterable
from functools import lru_cache
from importlib.resources import files
from typing import Any, cast

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError


class SnapshotValidationError(ValueError):
    """Raised when a Fleet Audit snapshot does not match its schema."""


@lru_cache(maxsize=1)
def load_schema() -> dict[str, Any]:
    schema_resource = files("fleet_audit.schemas").joinpath("snapshot-v1.schema.json")
    with schema_resource.open(encoding="utf-8") as schema_file:
        schema = json.load(schema_file)

    Draft202012Validator.check_schema(schema)
    return cast(dict[str, Any], schema)


def validate_snapshot(snapshot: object) -> None:
    validator = Draft202012Validator(load_schema(), format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(snapshot), key=_error_sort_key)
    if not errors:
        return

    messages = [_format_error(error.absolute_path, error.message) for error in errors]
    raise SnapshotValidationError("; ".join(messages))


def _error_sort_key(error: ValidationError) -> tuple[str, str]:
    path = ".".join(str(part) for part in error.absolute_path)
    return path, error.message


def _format_error(path_parts: Iterable[object], message: str) -> str:
    path = ".".join(str(part) for part in path_parts)
    return f"{path or '$'}: {message}"
