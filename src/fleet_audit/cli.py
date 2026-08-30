from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from fleet_audit import __version__
from fleet_audit.collection import CollectionError, collect_snapshot
from fleet_audit.policy import PolicyError, evaluate_policy, load_policy
from fleet_audit.validation import SnapshotValidationError, load_snapshot, validate_snapshot


class OutputExistsError(ValueError):
    """Raised when an operation would overwrite an existing file."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fleet-audit",
        description="Read-only Linux inventory and configuration drift reporting.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    commands = parser.add_subparsers(dest="command")

    collect_parser = commands.add_parser("collect", help="Collect a local inventory snapshot.")
    collect_parser.add_argument("--output", required=True, type=Path, help="Snapshot JSON path.")
    collect_parser.add_argument(
        "--label",
        default="host",
        help="Non-sensitive label used to distinguish this host (default: host).",
    )
    collect_parser.add_argument(
        "--policy",
        type=Path,
        help="TOML policy whose checks are attached to the snapshot.",
    )
    collect_parser.set_defaults(handler=_collect_command)

    validate_parser = commands.add_parser("validate", help="Validate a snapshot JSON file.")
    validate_parser.add_argument("snapshot", type=Path, help="Snapshot JSON path.")
    validate_parser.set_defaults(handler=_validate_command)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    parser = build_parser()
    parsed = parser.parse_args(arguments)
    handler = getattr(parsed, "handler", None)
    if handler is None:
        parser.print_help()
        return 0

    try:
        return handler(parsed)
    except (OutputExistsError, PolicyError, SnapshotValidationError) as error:
        print(f"fleet-audit: {error}", file=sys.stderr)
        return 2
    except (CollectionError, OSError) as error:
        print(f"fleet-audit: collection failed: {error}", file=sys.stderr)
        return 3


def _collect_command(arguments: argparse.Namespace) -> int:
    policy = load_policy(arguments.policy) if arguments.policy is not None else None
    snapshot = collect_snapshot(label=arguments.label)
    if policy is not None:
        snapshot["checks"] = evaluate_policy(policy, snapshot)
        validate_snapshot(snapshot)
    _write_json_exclusive(arguments.output, snapshot)
    print(f"Snapshot written to {arguments.output}")
    return 0


def _validate_command(arguments: argparse.Namespace) -> int:
    load_snapshot(arguments.snapshot)
    print(f"Snapshot is valid: {arguments.snapshot}")
    return 0


def _write_json_exclusive(path: Path, document: dict[str, Any]) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as error:
        raise OutputExistsError(f"output file already exists: {path}") from error

    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output_file:
            json.dump(document, output_file, indent=2, sort_keys=True)
            output_file.write("\n")
            output_file.flush()
            os.fsync(output_file.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
