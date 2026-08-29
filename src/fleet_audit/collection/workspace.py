from __future__ import annotations

import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def secure_workspace(*, parent: Path | None = None) -> Iterator[Path]:
    parent_path = None if parent is None else parent.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="fleet-audit-", dir=parent_path) as directory:
        workspace = Path(directory)
        workspace.chmod(0o700)
        yield workspace
