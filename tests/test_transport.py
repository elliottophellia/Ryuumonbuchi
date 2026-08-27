"""Streamable HTTP transport: in-process ASGI smoke test and transport config wiring.

Drives the real streamable-HTTP ASGI app returned by ``Server.streamable_http_app``
through an in-process ``httpx2.ASGITransport``, so the MCP wire protocol is
exercised without binding a socket or spawning a JVM.
"""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportAttributeAccessIssue=false, reportUnknownArgumentType=false, reportPrivateUsage=false

from __future__ import annotations

from pathlib import Path

import anyio
import httpx2
import pytest
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client

from ryuumonbuchi.config import AppConfig, ConfigError
from ryuumonbuchi.server import create_server

# The port is mandatory: loopback DNS-rebinding protection rejects Host headers
# without one.
_BASE_URL = "http://127.0.0.1:8000"


async def _run_http_smoke(config: AppConfig) -> None:
    server = create_server(config)
    app = server.streamable_http_app(streamable_http_path="/mcp", host="127.0.0.1")

    async with app.router.lifespan_context(app):
        transport = httpx2.ASGITransport(app=app)
        async with (
            httpx2.AsyncClient(transport=transport, base_url=_BASE_URL) as http_client,
            streamable_http_client(f"{_BASE_URL}/mcp", http_client=http_client) as streams,
        ):
            read_stream, write_stream = streams[0], streams[1]
            async with ClientSession(read_stream, write_stream) as client:
                result = await client.initialize()
                assert result.server_info.name == "ryuumonbuchi"

                tools = await client.list_tools()
                names = {tool.name for tool in tools.tools}
                assert "health.ping" in names
                assert len(names) == 217

                ping = await client.call_tool("health.ping", {})
                assert ping.is_error is False
                assert "health.ping" in ping.content[0].text


def test_streamable_http_transport_smoke(fake_ghidra: Path) -> None:
    config = AppConfig(
        ghidra_install_dir=fake_ghidra,
        max_heap_mb=256,
        max_cpu=1,
        operation_timeout_seconds=30,
        transport="http",
    )
    anyio.run(_run_http_smoke, config)


def test_transport_defaults_to_stdio(fake_ghidra: Path) -> None:
    config = AppConfig(ghidra_install_dir=fake_ghidra)
    assert config.transport == "stdio"
    assert config.http_host == "127.0.0.1"
    assert config.http_port == 8765
    assert config.http_path == "/mcp"


def test_transport_rejects_unknown_value(fake_ghidra: Path) -> None:
    with pytest.raises(ConfigError, match="transport must be"):
        AppConfig(ghidra_install_dir=fake_ghidra, transport="grpc")


def test_http_port_out_of_range(fake_ghidra: Path) -> None:
    with pytest.raises(ConfigError, match="http_port must be"):
        AppConfig(ghidra_install_dir=fake_ghidra, http_port=0)


def test_http_port_rejects_non_integer(fake_ghidra: Path) -> None:
    with pytest.raises(ConfigError, match="http_port must be"):
        AppConfig(ghidra_install_dir=fake_ghidra, http_port="8765")  # type: ignore[arg-type]


def test_http_path_must_be_absolute(fake_ghidra: Path) -> None:
    with pytest.raises(ConfigError, match="http_path must start"):
        AppConfig(ghidra_install_dir=fake_ghidra, http_path="mcp")
