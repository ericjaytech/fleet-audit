from __future__ import annotations

import argparse
from collections.abc import Sequence

from fleet_audit import __version__


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
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    parser = build_parser()
    parser.parse_args(arguments)
    return 0
