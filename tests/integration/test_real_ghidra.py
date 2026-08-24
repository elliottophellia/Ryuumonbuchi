# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors

from __future__ import annotations

import asyncio
import os
import subprocess
from pathlib import Path

import pytest
from mcp.client import Client

from ryuumonbuchi.config import build_config
from ryuumonbuchi.server import create_server

pytestmark = pytest.mark.live


def test_real_ghidra_import_read_and_cleanup(tmp_path: Path) -> None:
    ghidra = os.environ.get("GHIDRA_INSTALL_DIR", "/usr/share/ghidra")
    if not Path(ghidra).is_dir():
        pytest.skip("real Ghidra installation is unavailable")
    source = tmp_path / "hello.c"
    binary = tmp_path / "hello"
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    subprocess.run(["cc", "-O0", "-g", "-o", str(binary), str(source)], check=True)  # noqa: S603, S607

    async def run() -> None:
        server = create_server(build_config(ghidra_install_dir=ghidra, max_cpu=1, max_heap_mb=512))
        async with Client(server, raise_exceptions=True) as client:
            imported = await client.call_tool(
                "program_import",
                {"source_path": str(binary), "program_name": "hello", "analyze": True},
            )
            assert imported.structured_content["program_name"] == "hello"
            functions = await client.call_tool("function_list", {"program_name": "hello"})
            assert functions.structured_content["items"]
            status = await client.call_tool("session_status", {})
            assert status.structured_content["active_worker_pid"] is None
            assert status.structured_content["project_open"] is False

    asyncio.run(run())
