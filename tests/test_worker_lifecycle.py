# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors

"""Real child-worker lifecycle over the inherited-socket FD protocol.

Spawns the actual ``ryuumonbuchi.worker`` entrypoint as a child process and
drives status/shutdown/restart. The worker imports pyghidra but does not start
the JVM until the first backend call, so this test needs no Ghidra install.
It catches descriptor and bootstrap-envelope drift against the versioned model
contract.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import asyncio
from pathlib import Path

from ryuumonbuchi.config import AppConfig
from ryuumonbuchi.process import PersistentWorker
from ryuumonbuchi.session import RuntimeWorkspace


def _config(fake_ghidra: Path) -> AppConfig:
    return AppConfig(
        ghidra_install_dir=fake_ghidra,
        max_heap_mb=256,
        max_cpu=1,
        operation_timeout_seconds=30,
    )


def test_worker_spawn_status_shutdown_restart(
    fake_ghidra: Path, tmp_path: Path
) -> None:
    async def run() -> None:
        workspace = RuntimeWorkspace.create(base=tmp_path)
        try:
            worker = PersistentWorker(_config(fake_ghidra), workspace)
            # Status before start does not spawn the child.
            status = await worker.status()
            assert status["jvm_started"] is False
            assert worker.child_pid() is None
            # Spawn the real child over the inherited-socket FD, then query
            # status (which does not start the JVM in the child).
            await worker._ensure_started()  # noqa: SLF001
            assert worker.child_pid() is not None
            status = await worker.status()
            assert status["child_pid"] is not None
            assert isinstance(status["generation"], str) and status["generation"]

            # Shutdown reaps the child and closes the socket.
            await worker.shutdown()
            assert worker.child_pid() is None
            assert not worker.is_started

            # Restart advances the parent generation and starts a clean child.
            gen_before = worker.generation
            await worker._ensure_started()  # noqa: SLF001
            assert worker.generation != gen_before
            status = await worker.status()
            assert status["child_pid"] is not None

            await worker.shutdown()
        finally:
            workspace.close()

    asyncio.run(run())