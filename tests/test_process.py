# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors

"""Process: PersistentWorker generation, lock, status, shutdown, error taxonomy."""

from __future__ import annotations

# pyright: reportPrivateUsage=false, reportUnknownMemberType=false, reportUnknownVariableType=false
from pathlib import Path

import pytest

from ryuumonbuchi.config import AppConfig
from ryuumonbuchi.process import (
    PersistentWorker,
    WorkerCancelledError,
    WorkerFailedError,
    WorkerOperationError,
    WorkerRunError,
    WorkerTimeoutError,
)
from ryuumonbuchi.session import RuntimeWorkspace


@pytest.fixture
def config(fake_ghidra: Path) -> AppConfig:
    return AppConfig(
        ghidra_install_dir=fake_ghidra,
        max_heap_mb=256,
        max_cpu=1,
        operation_timeout_seconds=30,
    )


@pytest.fixture
def worker(workspace: RuntimeWorkspace, config: AppConfig) -> PersistentWorker:
    return PersistentWorker(config=config, workspace=workspace)


def test_worker_generation_is_string(worker: PersistentWorker) -> None:
    gen = worker.generation
    assert isinstance(gen, str)
    assert len(gen) == 36 or len(gen) == 32  # UUID format


def test_worker_generation_changes_on_reset(worker: PersistentWorker) -> None:
    gen1 = worker.generation
    import asyncio

    asyncio.run(worker._handle_failure("test"))  # noqa: SLF001
    gen2 = worker.generation
    assert gen1 != gen2


def test_worker_not_started(worker: PersistentWorker) -> None:
    assert not worker.is_started
    assert not worker.jvm_started
    assert worker.child_pid() is None


def test_worker_status_before_start(worker: PersistentWorker) -> None:
    import asyncio

    status = asyncio.run(worker.status())
    assert status["jvm_started"] is False
    assert status["child_pid"] is None
    assert status["session_count"] == 0
    assert status["task_count"] == 0


def test_worker_shutdown_before_start(worker: PersistentWorker) -> None:
    import asyncio

    asyncio.run(worker.shutdown())
    assert not worker.is_started


def test_worker_error_taxonomy_inheritance() -> None:
    assert issubclass(WorkerTimeoutError, WorkerRunError)
    assert issubclass(WorkerCancelledError, WorkerRunError)
    assert issubclass(WorkerFailedError, WorkerRunError)
    assert issubclass(WorkerOperationError, WorkerRunError)


def test_worker_failed_error_has_log_tail() -> None:
    err = WorkerFailedError("crash", log_tail="log lines")
    assert err.log_tail == "log lines"


def test_worker_operation_error_has_code() -> None:
    err = WorkerOperationError("ghidra_error", "bad address")
    assert err.code == "ghidra_error"
    assert "ghidra_error" in str(err)


def test_worker_handle_failure_resets_state(worker: PersistentWorker) -> None:
    import asyncio

    asyncio.run(worker._handle_failure("test"))  # noqa: SLF001
    assert not worker.is_started
    assert not worker.jvm_started
    assert worker.child_pid() is None
