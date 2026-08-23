# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors
# pyright: reportUnknownParameterType=false, reportMissingParameterType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownMemberType=false

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from mcp.client import Client

from ryuumonbuchi.config import AppConfig
from ryuumonbuchi.models import (
    CallGraph,
    CallGraphNode,
    DecompileResult,
    FunctionDetail,
    MemoryBlock,
    MemoryReadResult,
    MutationResult,
)
from ryuumonbuchi.process import WorkerCall, WorkerRunner
from ryuumonbuchi.server import create_server
from ryuumonbuchi.session import ProgramRecord, SessionWorkspace, stream_sha256


def test_complete_catalog_handlers_with_fake_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = SessionWorkspace.create("12.0.4", temp_dir=tmp_path)
    source = tmp_path / "source.bin"
    source.write_bytes(b"source")
    workspace.update_program(
        ProgramRecord(
            "hello", str(source), stream_sha256(source), workspace.created_at.isoformat(), True
        )
    )
    monkeypatch.setattr(
        SessionWorkspace,
        "create",
        staticmethod(lambda _version: workspace),  # type: ignore[reportUnknownLambdaType]
    )

    async def fake_run(
        self: WorkerRunner,
        operations: list[dict[str, object]],
        *,
        read_only: bool,
        timeout_seconds: int | None = None,
        program_name: str | None = None,
    ) -> WorkerCall:
        action = str(operations[0]["action"])
        page = {"items": [], "offset": 0, "limit": 100, "has_more": False}
        if action == "function_get":
            result: object = FunctionDetail(
                name="main", address="1000", entry_address="1000", size=1
            ).model_dump()
        elif action == "function_decompile":
            result = DecompileResult(
                function_name="main", address="1000", c_code="return 0;"
            ).model_dump()
        elif action == "memory_read":
            result = MemoryReadResult(
                address="1000", requested_length=1, actual_length=1, bytes_hex="90"
            ).model_dump()
        elif action == "memory_blocks":
            result = [
                MemoryBlock(
                    name=".text",
                    start="1000",
                    end="1001",
                    size=2,
                    read=True,
                    write=False,
                    execute=True,
                ).model_dump()
            ]
        elif action == "call_graph":
            result = CallGraph(
                root=CallGraphNode(address="1000", name="main", depth=0),
                nodes=[],
                edges=[],
            ).model_dump()
        elif action == "analysis_run":
            result = {"analyzed": True, "log": ""}
        elif action in {"analysis_options_get", "analysis_options_set"}:
            result = {}
        elif len(operations) > 1:
            result = {
                "results": [{"action": item["action"], "result": page} for item in operations]
            }
        elif action in {
            "edit_rename_function",
            "edit_rename_variable",
            "edit_set_comment",
            "edit_set_prototype",
            "edit_patch_bytes",
            "edit_undo",
            "edit_redo",
        }:
            result = MutationResult(
                changed=True, program_name=program_name or "hello", description=action
            ).model_dump()
        elif action == "program_import":
            result = {"program_name": "imported", "analyzed": True}
        elif action == "program_delete":
            result = {"program_name": str(operations[0]["program_name"]), "deleted": True}
        else:
            result = page
        return WorkerCall("fake", result)

    monkeypatch.setattr(WorkerRunner, "run", fake_run)

    async def run() -> None:
        config = AppConfig(
            Path("/usr/share/ghidra"), max_heap_mb=256, max_cpu=1, operation_timeout_seconds=30
        )
        server = create_server(config)
        async with Client(server, raise_exceptions=True) as client:
            health = await client.call_tool("health", {})
            assert health.structured_content["worker_running"] is False
            read_calls = [
                ("function_list", {"program_name": "hello"}),
                ("function_get", {"program_name": "hello", "name": "main"}),
                ("function_decompile", {"program_name": "hello", "name": "main"}),
                ("listing_disassemble", {"program_name": "hello"}),
                ("listing_data", {"program_name": "hello"}),
                ("memory_blocks", {"program_name": "hello"}),
                ("memory_read", {"program_name": "hello", "address": "1000", "length": 1}),
                ("search_strings", {"program_name": "hello"}),
                ("search_symbols", {"program_name": "hello", "query": "main"}),
                ("list_imports", {"program_name": "hello"}),
                ("list_exports", {"program_name": "hello"}),
                ("references", {"program_name": "hello", "address": "1000"}),
                ("call_graph", {"program_name": "hello", "name": "main"}),
                ("byte_search", {"program_name": "hello", "pattern": "90"}),
                ("text_search", {"program_name": "hello", "query": "hello"}),
                ("analysis_run", {"program_name": "hello"}),
                ("analysis_options_get", {"program_name": "hello"}),
            ]
            for name, arguments in read_calls:
                result = await client.call_tool(name, arguments)
                assert not result.is_error, (name, result)
            mutations = [
                ("analysis_options_set", {"program_name": "hello", "values": {}}),
                (
                    "edit_rename_function",
                    {"program_name": "hello", "name": "main", "new_name": "renamed"},
                ),
                (
                    "edit_rename_variable",
                    {
                        "program_name": "hello",
                        "function_address": "1000",
                        "old_name": "x",
                        "new_name": "y",
                    },
                ),
                ("edit_set_comment", {"program_name": "hello", "address": "1000", "comment": "x"}),
                (
                    "edit_set_prototype",
                    {"program_name": "hello", "name": "main", "prototype": "int main(void)"},
                ),
                (
                    "edit_patch_bytes",
                    {"program_name": "hello", "address": "1000", "bytes_hex": "90"},
                ),
                ("edit_undo", {"program_name": "hello"}),
                ("edit_redo", {"program_name": "hello"}),
                (
                    "batch",
                    {
                        "program_name": "hello",
                        "operations": [{"action": "function_list"}, {"action": "memory_blocks"}],
                    },
                ),
            ]
            for name, arguments in mutations:
                result = await client.call_tool(name, arguments)
                assert not result.is_error, (name, result)
            imported = await client.call_tool(
                "program_import", {"source_path": str(source), "program_name": "imported"}
            )
            assert not imported.is_error
            deleted = await client.call_tool("program_delete", {"program_name": "imported"})
            assert not deleted.is_error

    try:
        asyncio.run(run())
    finally:
        if not workspace.closed:
            asyncio.run(workspace.close())
