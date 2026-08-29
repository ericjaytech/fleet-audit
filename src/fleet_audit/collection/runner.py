from __future__ import annotations

import os
import signal
import subprocess
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class CollectorStatus(StrEnum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


@dataclass(frozen=True)
class CollectorResult:
    name: str
    status: CollectorStatus
    exit_code: int | None
    detail: str | None = None


def run_collector(
    name: str,
    collector_path: Path,
    workspace: Path,
    *,
    timeout_seconds: float,
) -> CollectorResult:
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    }

    try:
        process = subprocess.Popen(
            ["/bin/bash", str(collector_path), str(workspace)],
            env=environment,
            start_new_session=True,
            stderr=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
        )
    except OSError as error:
        return CollectorResult(
            name=name,
            status=CollectorStatus.ERROR,
            exit_code=None,
            detail=f"Collector could not start: {error.strerror or type(error).__name__}.",
        )

    try:
        exit_code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        return CollectorResult(
            name=name,
            status=CollectorStatus.ERROR,
            exit_code=None,
            detail=f"Collector exceeded its {timeout_seconds:g} second timeout.",
        )

    if exit_code == 0:
        return CollectorResult(name, CollectorStatus.AVAILABLE, exit_code)
    if exit_code == 10:
        return CollectorResult(
            name,
            CollectorStatus.UNAVAILABLE,
            exit_code,
            "Collector reported that the capability is unavailable.",
        )
    return CollectorResult(
        name,
        CollectorStatus.ERROR,
        exit_code,
        f"Collector exited with code {exit_code}.",
    )
