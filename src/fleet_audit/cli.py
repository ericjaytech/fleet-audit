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
from fleet_audit.compare import ComparisonError, SnapshotComparison, compare_snapshots
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
    publication = collect_parser.add_mutually_exclusive_group(required=True)
    publication.add_argument("--output", type=Path, help="Snapshot JSON path.")
    publication.add_argument(
        "--dry-run",
        action="store_true",
        help="Collect and validate without writing a snapshot.",
    )
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

    compare_parser = commands.add_parser(
        "compare",
        help="Compare two snapshots for material changes.",
    )
    compare_parser.add_argument("baseline", type=Path, help="Baseline snapshot JSON path.")
    compare_parser.add_argument("current", type=Path, help="Current snapshot JSON path.")
    compare_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text).",
    )
    compare_parser.add_argument(
        "--fail-on",
        choices=("changed",),
        help="Return exit code 1 when material changes are detected.",
    )
    compare_parser.add_argument(
        "--allow-host-label-mismatch",
        action="store_true",
        help="Acknowledge that the snapshots have different host labels.",
    )
    compare_parser.set_defaults(handler=_compare_command)
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
    except (
        ComparisonError,
        OutputExistsError,
        PolicyError,
        SnapshotValidationError,
    ) as error:
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
    if arguments.dry_run:
        capabilities = snapshot["collection"]["capabilities"]
        available = sum(item["status"] == "available" for item in capabilities)
        unavailable = len(capabilities) - available
        warnings = len(snapshot["collection"]["warnings"])
        print(
            f"Dry run complete: {available} capabilities available, "
            f"{unavailable} unavailable, {warnings} warnings. No snapshot was written."
        )
        return 0
    _write_json_exclusive(arguments.output, snapshot)
    print(f"Snapshot written to {arguments.output}")
    return 0


def _validate_command(arguments: argparse.Namespace) -> int:
    load_snapshot(arguments.snapshot)
    print(f"Snapshot is valid: {arguments.snapshot}")
    return 0


def _compare_command(arguments: argparse.Namespace) -> int:
    baseline = load_snapshot(arguments.baseline)
    current = load_snapshot(arguments.current)
    comparison = compare_snapshots(
        baseline,
        current,
        allow_host_label_mismatch=arguments.allow_host_label_mismatch,
    )
    if arguments.format == "json":
        json.dump(comparison.to_dict(), sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        print(_format_comparison_text(comparison))

    if arguments.fail_on == "changed" and comparison.status == "changed":
        return 1
    return 0


def _format_comparison_text(comparison: SnapshotComparison) -> str:
    count = comparison.change_count
    noun = "change" if count == 1 else "changes"
    lines = [
        f"Snapshot comparison: {comparison.status} ({count} material {noun})",
        (
            f"Baseline: {json.dumps(comparison.baseline_label)} "
            f"at {comparison.baseline_collected_at}"
        ),
        (f"Current: {json.dumps(comparison.current_label)} at {comparison.current_collected_at}"),
    ]
    for change in comparison.changes:
        document = change.to_dict()
        key = json.dumps(change.key, ensure_ascii=True)
        before = json.dumps(document["before"], ensure_ascii=True, sort_keys=True)
        after = json.dumps(document["after"], ensure_ascii=True, sort_keys=True)
        lines.append(f"- [{change.category}] {change.kind} {key}: {before} -> {after}")
    return "\n".join(lines)


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
