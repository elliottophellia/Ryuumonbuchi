"""Backend runtime state, records, and error types."""

from __future__ import annotations

import time
from collections.abc import Callable
from concurrent.futures import Future
from dataclasses import dataclass, field
from typing import Any

MAX_MEMORY_READ_BYTES = 64 * 1024
DEFAULT_ANALYSIS_TIMEOUT = 60 * 60


@dataclass(frozen=True, slots=True)
class BackendConfig:
    """Immutable backend startup configuration."""

    install_dir: str | None
    max_heap_mb: int = 1024
    max_cpu: int = 2
    vm_args: tuple[str, ...] = ()
    classpaths: tuple[str, ...] = ()
    class_files: tuple[str, ...] = ()
    deterministic: bool = True
    workspace_root: str = ""
    max_import_bytes: int = 67_108_864
    max_response_bytes: int = 4_194_304
    max_log_tail_bytes: int = 65_536
    allow_export: bool = False
    allow_import_bytes: bool = False


class GhidraBackendError(RuntimeError):
    """Raised when a backend operation fails."""


@dataclass
class SessionRecord:
    """Tracks an open Ghidra program session."""

    session_id: str
    project: Any
    program: Any
    flat_api: Any
    program_name: str
    program_path: str
    project_location: str
    project_name: str
    source_path: str | None = None
    read_only: bool = True
    managed_project: bool = False
    managed_project_root: str | None = None
    temp_source_path: str | None = None
    program_consumer: Any = None
    decompiler: Any = None
    active_transaction_id: int | None = None
    active_transaction_description: str | None = None
    last_analysis_status: str = "idle"
    last_analysis_started_at: float | None = None
    last_analysis_completed_at: float | None = None
    last_analysis_log: str | None = None
    last_analysis_error: str | None = None
    last_analysis_task_id: str | None = None


@dataclass
class TaskRecord:
    """Tracks an asynchronous backend task."""

    task_id: str
    kind: str
    future: Future[Any]
    session_id: str | None
    cancel_hook: Callable[[], None] | None = None
    cancel_requested: bool = False
    monitor: Any = None
    created_at: float = field(default_factory=time.time)
