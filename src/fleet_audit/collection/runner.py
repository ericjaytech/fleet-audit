from __future__ import annotations

import os
import signal
import stat
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
    issue_code: str | None = None


_MAX_ARTIFACT_BYTES = 4_194_304
_MAX_ARTIFACTS = 16
_MAX_TOTAL_BYTES = 16_777_216


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
        existing_artifacts = _artifact_fingerprints(workspace)
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
            issue_code="COLLECTOR_START_FAILED",
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
            issue_code="COLLECTOR_TIMEOUT",
        )

    if exit_code == 0:
        output_issue = _validate_collector_output(workspace, existing_artifacts)
        if output_issue is not None:
            issue_code, detail = output_issue
            return CollectorResult(
                name=name,
                status=CollectorStatus.ERROR,
                exit_code=exit_code,
                detail=detail,
                issue_code=issue_code,
            )
        return CollectorResult(name, CollectorStatus.AVAILABLE, exit_code)
    if exit_code == 10:
        return CollectorResult(
            name,
            CollectorStatus.UNAVAILABLE,
            exit_code,
            "Collector reported that the capability is unavailable.",
            "CAPABILITY_UNAVAILABLE",
        )
    return CollectorResult(
        name,
        CollectorStatus.ERROR,
        exit_code,
        f"Collector exited with code {exit_code}.",
        "COLLECTOR_EXIT_ERROR",
    )


def _artifact_fingerprints(workspace: Path) -> dict[str, tuple[int, int, int, int]]:
    return {entry.name: _fingerprint(entry) for entry in workspace.iterdir()}


def _fingerprint(path: Path) -> tuple[int, int, int, int]:
    metadata = path.lstat()
    return (
        metadata.st_mode,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _validate_collector_output(
    workspace: Path,
    existing_artifacts: dict[str, tuple[int, int, int, int]],
) -> tuple[str, str] | None:
    try:
        artifacts = list(workspace.iterdir())
        current_names = {artifact.name for artifact in artifacts}
        if current_names & existing_artifacts.keys():
            for artifact in artifacts:
                previous = existing_artifacts.get(artifact.name)
                if previous is not None and _fingerprint(artifact) != previous:
                    return (
                        "COLLECTOR_WORKSPACE_VIOLATION",
                        "Collector modified an existing workspace artifact.",
                    )
        if existing_artifacts.keys() - current_names:
            return (
                "COLLECTOR_WORKSPACE_VIOLATION",
                "Collector removed an existing workspace artifact.",
            )

        new_artifacts = [
            artifact for artifact in artifacts if artifact.name not in existing_artifacts
        ]
        if len(new_artifacts) > _MAX_ARTIFACTS:
            return (
                "COLLECTOR_OUTPUT_LIMIT",
                f"Collector output exceeded the {_MAX_ARTIFACTS} artifact limit.",
            )

        total_bytes = 0
        for artifact in new_artifacts:
            metadata = artifact.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                return (
                    "COLLECTOR_WORKSPACE_VIOLATION",
                    "Collector output contained a non-regular artifact.",
                )
            if metadata.st_size > _MAX_ARTIFACT_BYTES:
                return (
                    "COLLECTOR_OUTPUT_LIMIT",
                    "Collector output exceeded the 4 MiB per-file limit.",
                )
            total_bytes += metadata.st_size
        if total_bytes > _MAX_TOTAL_BYTES:
            return (
                "COLLECTOR_OUTPUT_LIMIT",
                "Collector output exceeded the 16 MiB total limit.",
            )
    except OSError:
        return (
            "COLLECTOR_WORKSPACE_VIOLATION",
            "Collector output could not be inspected safely.",
        )
    return None
