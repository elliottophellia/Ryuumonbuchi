# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors

from __future__ import annotations

from mcp.client import Client

from ryuumonbuchi.config import build_config
from ryuumonbuchi.server import create_server


def test_in_process_health_and_session_clear(fake_ghidra: object) -> None:
    import asyncio

    async def run() -> None:
        server = create_server(build_config(ghidra_install_dir=fake_ghidra, max_cpu=1))  # type: ignore[arg-type]
        async with Client(server, raise_exceptions=True) as client:
            health = await client.call_tool("health", {})
            assert health.structured_content["worker_running"] is False
            assert health.structured_content["project_open"] is False
            before = health.structured_content["session_id"]
            status = await client.call_tool("session_status", {})
            assert status.structured_content["active_worker_pid"] is None
            cleared = await client.call_tool("session_clear", {})
            assert cleared.structured_content["old_session_id"] == before
            assert cleared.structured_content["new_session_id"] != before
            programs = await client.call_tool("program_list", {})
            assert programs.structured_content == {"programs": []}

    asyncio.run(run())
