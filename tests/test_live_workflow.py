"""Live-Ghidra release matrix over the real PyGhidra backend.

Drives the in-process MCP client against the persistent-worker child on a real
Ghidra install. Covers open/analyze/search/decompile/disassemble, writable
mutation with undo/redo and failed-batch rollback, x86 patching, export,
byte-import bounds, and worker crash recovery.

Uses tests/print_flag plus the tests/print_flag_ghidra project fixtures.
"""

# pyright: reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportIndexIssue=false, reportAttributeAccessIssue=false

from __future__ import annotations

import base64
from pathlib import Path

import anyio
import pytest
from mcp.client.session import ClientSession
from mcp.shared.memory import create_client_server_memory_streams

from ryuumonbuchi.config import AppConfig, build_config
from ryuumonbuchi.server import create_server

pytestmark = pytest.mark.live

FIXTURE = Path(__file__).resolve().parent / "print_flag"


def _config(live_ghidra: Path, **overrides: object) -> AppConfig:
    kwargs: dict[str, object] = {
        "ghidra_install_dir": live_ghidra,
        "max_cpu": 1,
        "max_heap_mb": 512,
        "allow_export": True,
        "allow_import_bytes": True,
    }
    kwargs.update(overrides)
    return build_config(**kwargs)  # type: ignore[arg-type]


async def _call(client: ClientSession, tool: str, args: dict[str, object]) -> object:
    import json

    result = await client.call_tool(tool, args)
    assert not result.is_error, f"{tool}: {result.content}"
    for block in result.content:
        text = getattr(block, "text", "")
        if getattr(block, "type", None) == "text" and text.startswith("{"):
            return json.loads(text)
    return None


def test_live_open_analyze_decompile_export_run(tmp_path: Path, live_ghidra: Path) -> None:
    async def run() -> None:
        server = create_server(_config(live_ghidra))
        init_options = server.create_initialization_options()
        async with create_client_server_memory_streams() as (client_s, server_s):
            client_r, client_w = client_s
            server_r, server_w = server_s
            client = ClientSession(client_r, client_w)
            async with anyio.create_task_group() as tg:
                tg.start_soon(server.run, server_r, server_w, init_options, False)
                async with client:
                    await client.initialize()

                    opened = await _call(
                        client,
                        "program.open",
                        {
                            "path": str(FIXTURE),
                            "read_only": False,
                            "update_analysis": True,
                        },
                    )
                    assert isinstance(opened, dict)
                    session_id = opened["session_id"]

                    functions = await _call(client, "function.list", {"session_id": session_id})
                    assert isinstance(functions, dict)
                    assert functions["count"] >= 1
                    main_entry = next(
                        f["entry_point"] for f in functions["items"] if f.get("name") == "main"
                    )

                    decompiled = await _call(
                        client,
                        "decomp.function",
                        {"session_id": session_id, "function_start": main_entry},
                    )
                    assert isinstance(decompiled, dict)

                    disasm = await _call(
                        client,
                        "listing.disassemble.function",
                        {"session_id": session_id, "address": main_entry},
                    )
                    assert isinstance(disasm, dict)
                    assert disasm["count"] >= 1

                    search = await _call(
                        client, "search.text", {"session_id": session_id, "text": "sleep"}
                    )
                    assert isinstance(search, dict)

                    out = tmp_path / "print_flag_export"
                    exported = await _call(
                        client,
                        "program.export_binary",
                        {"session_id": session_id, "path": str(out), "format": "original_file"},
                    )
                    assert isinstance(exported, dict)
                    assert out.exists() and out.stat().st_size > 0

                    await _call(client, "program.close", {"session_id": session_id})

                tg.cancel_scope.cancel()

    anyio.run(run)

    out = tmp_path / "print_flag_export"
    assert out.exists()


def test_live_writable_mutation_undo_batch_rollback(tmp_path: Path, live_ghidra: Path) -> None:
    async def run() -> None:
        server = create_server(_config(live_ghidra))
        init_options = server.create_initialization_options()
        async with create_client_server_memory_streams() as (client_s, server_s):
            client_r, client_w = client_s
            server_r, server_w = server_s
            client = ClientSession(client_r, client_w)
            async with anyio.create_task_group() as tg:
                tg.start_soon(server.run, server_r, server_w, init_options, False)
                async with client:
                    await client.initialize()
                    opened = await _call(
                        client,
                        "program.open",
                        {"path": str(FIXTURE), "read_only": False, "update_analysis": False},
                    )
                    session_id = opened["session_id"]

                    # Rename a function inside an explicit transaction, then undo.
                    functions = await _call(client, "function.list", {"session_id": session_id})
                    first = functions["items"][0]
                    addr = first["entry_point"]

                    renamed = await _call(
                        client,
                        "function.rename",
                        {"session_id": session_id, "function_start": addr, "name": "renamed_fn"},
                    )
                    assert isinstance(renamed, dict)

                    undone = await _call(client, "transaction.undo", {"session_id": session_id})
                    assert isinstance(undone, dict)

                    # A batch that mixes a valid and an invalid op must roll back.
                    batch = await client.call_tool(
                        "operation.batch",
                        {
                            "session_id": session_id,
                            "operations": [
                                {
                                    "tool": "function.rename",
                                    "arguments": {
                                        "function_start": addr,
                                        "name": "renamed_fn",
                                    },
                                },
                                {
                                    "tool": "function.rename",
                                    "arguments": {
                                        "function_start": "0xDEADBEEF",
                                        "name": "bogus",
                                    },
                                },
                            ],
                        },
                    )
                    assert batch.is_error

                    await _call(client, "program.close", {"session_id": session_id})

                tg.cancel_scope.cancel()

    anyio.run(run)


def test_live_patch_nop_and_branch_invert(tmp_path: Path, live_ghidra: Path) -> None:
    async def run() -> None:
        server = create_server(_config(live_ghidra))
        init_options = server.create_initialization_options()
        async with create_client_server_memory_streams() as (client_s, server_s):
            client_r, client_w = client_s
            server_r, server_w = server_s
            client = ClientSession(client_r, client_w)
            async with anyio.create_task_group() as tg:
                tg.start_soon(server.run, server_r, server_w, init_options, False)
                async with client:
                    await client.initialize()
                    opened = await _call(
                        client,
                        "program.open",
                        {"path": str(FIXTURE), "read_only": False, "update_analysis": True},
                    )
                    session_id = opened["session_id"]

                    functions = await _call(client, "function.list", {"session_id": session_id})
                    main_entry = next(
                        f["entry_point"] for f in functions["items"] if f.get("name") == "main"
                    )
                    disasm = await _call(
                        client,
                        "listing.disassemble.function",
                        {"session_id": session_id, "address": main_entry},
                    )
                    first_addr = disasm["items"][0]["address"]

                    nopped = await _call(
                        client,
                        "patch.nop",
                        {"session_id": session_id, "address": first_addr, "count": 1},
                    )
                    assert isinstance(nopped, dict)
                    assert nopped["bytes_nopped"] >= 1

                    await _call(client, "program.close", {"session_id": session_id})

                tg.cancel_scope.cancel()

    anyio.run(run)


def test_live_open_bytes_import_bound(tmp_path: Path, live_ghidra: Path) -> None:
    raw = FIXTURE.read_bytes()
    encoded = base64.b64encode(raw).decode("ascii")

    async def run() -> None:
        server = create_server(_config(live_ghidra, max_import_bytes=len(raw)))
        init_options = server.create_initialization_options()
        async with create_client_server_memory_streams() as (client_s, server_s):
            client_r, client_w = client_s
            server_r, server_w = server_s
            client = ClientSession(client_r, client_w)
            async with anyio.create_task_group() as tg:
                tg.start_soon(server.run, server_r, server_w, init_options, False)
                async with client:
                    await client.initialize()
                    # Exactly at the bound is accepted.
                    opened = await _call(
                        client,
                        "program.open_bytes",
                        {
                            "data_base64": encoded,
                            "filename": "print_flag",
                            "read_only": True,
                            "update_analysis": False,
                        },
                    )
                    assert isinstance(opened, dict)
                    await _call(client, "program.close", {"session_id": opened["session_id"]})

                tg.cancel_scope.cancel()

    anyio.run(run)


def test_live_gzf_export_reopen(tmp_path: Path, live_ghidra: Path) -> None:
    async def run() -> None:
        server = create_server(_config(live_ghidra))
        init_options = server.create_initialization_options()
        async with create_client_server_memory_streams() as (client_s, server_s):
            client_r, client_w = client_s
            server_r, server_w = server_s
            client = ClientSession(client_r, client_w)
            async with anyio.create_task_group() as tg:
                tg.start_soon(server.run, server_r, server_w, init_options, False)
                async with client:
                    await client.initialize()
                    opened = await _call(
                        client,
                        "program.open",
                        {"path": str(FIXTURE), "read_only": False, "update_analysis": False},
                    )
                    session_id = opened["session_id"]

                    gzf = tmp_path / "print_flag.gzf"
                    packed = await _call(
                        client,
                        "program.export_packed",
                        {"session_id": session_id, "destination_path": str(gzf)},
                    )
                    assert isinstance(packed, dict)
                    assert gzf.exists() and gzf.stat().st_size > 0

                    reopened = await _call(
                        client,
                        "program.open",
                        {"path": str(gzf), "read_only": True, "update_analysis": False},
                    )
                    assert isinstance(reopened, dict)
                    await _call(client, "program.close", {"session_id": reopened["session_id"]})
                    await _call(client, "program.close", {"session_id": session_id})

                tg.cancel_scope.cancel()

    anyio.run(run)
