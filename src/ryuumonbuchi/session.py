"""Runtime workspace: one private root with projects, runs, logs, and a lock."""

from __future__ import annotations

import fcntl
import os
import shutil
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO


class WorkspaceError(RuntimeError):
    """Raised when a workspace operation is invalid."""


@dataclass(slots=True)
class RuntimeWorkspace:
    """One private, mode-0700 root owned by one MCP process."""

    root: Path
    projects: Path
    runs: Path
    worker_log: Path
    _lock_handle: BinaryIO | None = None
    _closed: bool = False

    @classmethod
    def create(cls, base: Path | None = None) -> RuntimeWorkspace:
        """Create a fresh private workspace under the system temp dir."""
        base_dir = base or Path(tempfile.gettempdir())
        root = base_dir / f"ryuumonbuchi-{uuid.uuid4().hex}"
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        projects = root / "projects"
        projects.mkdir(mode=0o700)
        runs = root / "runs"
        runs.mkdir(mode=0o700)
        worker_log = root / "worker.log"
        ws = cls(root=root, projects=projects, runs=runs, worker_log=worker_log)
        ws._acquire_lock()
        return ws

    def _acquire_lock(self) -> None:
        lock_path = self.root / ".owner.lock"
        lock_path.touch(mode=0o600)
        handle = lock_path.open("rb+")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            handle.close()
            msg = f"workspace lock contention: {exc}"
            raise WorkspaceError(msg) from exc
        self._lock_handle = handle

    def new_run_file(self, prefix: str = "run-", suffix: str = ".json") -> Path:
        """Create a mode-0600 spill/log file under runs/."""
        path = self.runs / f"{prefix}{uuid.uuid4().hex}{suffix}"
        fd = os.open(str(path), os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
        os.close(fd)
        return path

    def managed_project_root(self, name: str) -> Path:
        """Allocate a mode-0700 managed project root under projects/."""
        safe = name.replace("/", "_").replace("\\", "_")
        path = self.projects / f"{safe}-{uuid.uuid4().hex[:8]}"
        path.mkdir(mode=0o700)
        return path

    def close(self) -> None:
        """Remove the entire workspace tree."""
        if self._closed:
            return
        self._closed = True
        if self._lock_handle is not None:
            with __import__("contextlib").suppress(OSError):
                fcntl.flock(self._lock_handle.fileno(), fcntl.LOCK_UN)
            self._lock_handle.close()
        shutil.rmtree(self.root, ignore_errors=True)


def try_cleanup_workspace(root: Path) -> bool:
    """Remove an explicitly supplied stale root only when its owner lock is free."""
    lock_path = root / ".owner.lock"
    if not lock_path.exists():
        return False
    try:
        handle = lock_path.open("rb")
    except OSError:
        return False
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        return False
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()
    shutil.rmtree(root, ignore_errors=True)
    return True
