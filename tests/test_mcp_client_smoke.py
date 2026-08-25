# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors

"""In-process low-level MCP client smoke test over the real wire protocol.

Exercises tools/list and tools/call against the actual ``Server`` object using
in-memory MCP streams, without spawning a JVM (``health.ping`` is JVM-lazy and
``mcp.response_format`` is server-native).
"""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportAttributeAccessIssue=false, reportUnknownArgumentType=false

from __future__ import annotations

from pathlib import Path

import anyio
from mcp.client.session import ClientSession
from mcp.shared.memory import create_client_server_memory_streams

from ryuumonbuchi.config import AppConfig
from ryuumonbuchi.server import create_server


async def _run_smoke(config: AppConfig) -> None:
    server = create_server(config)
    init_options = server.create_initialization_options()

    async with create_client_server_memory_streams() as (client_streams, server_streams):
        client_read, client_write = client_streams
        server_read, server_write = server_streams

        client = ClientSession(client_read, client_write)
        async with anyio.create_task_group() as tg:
            tg.start_soon(server.run, server_read, server_write, init_options, False)
            async with client:
                result = await client.initialize()
                assert result.server_info.name == "ryuumonbuchi"

                tools = await client.list_tools()
                names = {tool.name for tool in tools.tools}
                assert "health.ping" in names
                assert "mcp.response_format" in names
                assert len(names) == 216

                ping = await client.call_tool("health.ping", {})
                assert not ping.is_error
                text = ping.content[0].text
                assert "health.ping" in text

                fmt = await client.call_tool("mcp.response_format", {})
                assert not fmt.is_error

            tg.cancel_scope.cancel()


def test_in_process_mcp_client_smoke(fake_ghidra: Path) -> None:
    config = AppConfig(
        ghidra_install_dir=fake_ghidra,
        max_heap_mb=256,
        max_cpu=1,
        operation_timeout_seconds=30,
    )
    anyio.run(_run_smoke, config)
