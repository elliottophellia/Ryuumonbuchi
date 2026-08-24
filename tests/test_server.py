# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors
# pyright: reportUnknownParameterType=false, reportMissingParameterType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportPrivateUsage=false

from __future__ import annotations

import asyncio
import base64
import hashlib
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
        elif action == "analysis_list_analyzers":
            result = {"items": [], "offset": 0, "limit": 100, "has_more": False}
        elif action in {"program_export", "program_save"}:
            result = {
                "program_name": program_name or "hello",
                "destination_path": str(operations[0].get("destination_path", "")),
                "bytes_written": 1,
                "overwritten": False,
            }
        elif len(operations) > 1:
            result = {
                "results": [{"action": item["action"], "result": page} for item in operations]
            }
        elif action in {
            "edit_rename_function",
            "edit_rename_variable",
            "edit_set_comment",
            "edit_set_data_type",
            "edit_set_prototype",
            "edit_patch_bytes",
            "edit_undo",
            "edit_redo",
        }:
            result = MutationResult(
                changed=True, program_name=program_name or "hello", description=action
            ).model_dump()
        elif action in {"program_import", "program_import_bytes"}:
            result = {
                "program_name": program_name or str(operations[0]["program_name"]),
                "analyzed": bool(operations[0].get("analyze", True)),
                "language_id": "x86:LE:64:default",
                "processor": "x86",
            }
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
                ("analysis_list_analyzers", {"program_name": "hello"}),
                ("program_info", {"program_name": "hello"}),
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
                (
                    "edit_set_data_type",
                    {"program_name": "hello", "address": "1000", "data_type": "dword"},
                ),
                (
                    "program_export",
                    {"program_name": "hello", "destination_path": "/tmp/export.bin"},
                ),
                ("program_save", {"program_name": "hello", "destination_path": "/tmp/save.gzf"}),
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
            imported_bytes = await client.call_tool(
                "program_import_bytes",
                {
                    "program_name": "bytesy",
                    "data": base64.b64encode(b"bytes").decode(),
                },
            )
            assert not imported_bytes.is_error
            info = await client.call_tool("program_info", {"program_name": "bytesy"})
            assert (
                info.structured_content["source_path"]
                == f"bytes:{hashlib.sha256(b'bytes').hexdigest()}"
            )

    try:
        asyncio.run(run())
    finally:
        if not workspace.closed:
            asyncio.run(workspace.close())


def test_server_import_and_save_success_paths(tmp_path, monkeypatch):
    from ryuumonbuchi.config import GhidraInstallation
    from ryuumonbuchi.process import WorkerCall, WorkerFailedError, WorkerRunner
    from ryuumonbuchi.server import (  # pyright: ignore[reportPrivateUsage]
        ServerState,
        _program_import,
        _program_import_bytes,
        _program_save,
    )
    from ryuumonbuchi.session import SessionWorkspace, stream_sha256

    source = tmp_path / "source.bin"
    source.write_bytes(b"source")
    workspace = SessionWorkspace.create("12.0.4", temp_dir=tmp_path / "ws")
    try:
        installation = GhidraInstallation(Path("/usr/share/ghidra"), "12.0.4", 21, ("3.13",))
        config = AppConfig(
            Path("/usr/share/ghidra"), max_heap_mb=256, max_cpu=1, operation_timeout_seconds=30
        )
        from ryuumonbuchi.server import _SessionState

        runner = WorkerRunner(config, workspace)
        state = ServerState(config, installation, _SessionState(workspace, runner))

        async def fake_run(operations, **kwargs):
            action = operations[0]["action"]
            requested_name = str(kwargs.get("program_name") or operations[0].get("program_name"))
            if action == "program_save":
                return WorkerCall(
                    "r",
                    {
                        "program_name": requested_name,
                        "destination_path": operations[0]["destination_path"],
                        "bytes_written": 4,
                        "overwritten": False,
                    },
                )
            if action in {"program_import", "program_import_bytes"}:
                return WorkerCall(
                    "r",
                    {
                        "program_name": requested_name,
                        "analyzed": operations[0]["analyze"],
                        "language_id": "x86:LE:64:default",
                        "processor": "x86",
                    },
                )
            return WorkerCall("r", {"program_name": requested_name, "deleted": True})

        monkeypatch.setattr(state.session.runner, "run", fake_run)
        imported = asyncio.run(_program_import(state, str(source), "source", True))
        assert imported.source_sha256 == stream_sha256(source)
        saved = asyncio.run(_program_save(state, "source", str(tmp_path / "snap.gzf"), False))
        assert saved.bytes_written == 4
        data = base64.b64encode(b"bytes").decode()
        imported_bytes = asyncio.run(_program_import_bytes(state, "bytes", data, b"bytes", False))
        assert imported_bytes.source_sha256 == hashlib.sha256(b"bytes").hexdigest()

        async def certain(*args, **kwargs):
            message = "certain"
            raise WorkerFailedError(message, request_id="r", uncertain=False)

        monkeypatch.setattr(state.session.runner, "run", certain)
        with pytest.raises(WorkerFailedError):
            asyncio.run(_program_import(state, str(source), "certain", False))
        with pytest.raises(WorkerFailedError):
            asyncio.run(_program_import_bytes(state, "certain_bytes", data, b"bytes", False))
    finally:
        asyncio.run(workspace.close())


def test_server_save_uncertain_transition(tmp_path, monkeypatch):
    from ryuumonbuchi.config import GhidraInstallation
    from ryuumonbuchi.process import WorkerFailedError, WorkerRunner
    from ryuumonbuchi.server import ServerState, _program_save
    from ryuumonbuchi.session import SessionError, SessionWorkspace

    workspace = SessionWorkspace.create("12.0.4", temp_dir=tmp_path / "ws")
    try:
        config = AppConfig(
            Path("/usr/share/ghidra"), max_heap_mb=256, max_cpu=1, operation_timeout_seconds=30
        )
        installation = GhidraInstallation(Path("/usr/share/ghidra"), "12.0.4", 21, ("3.13",))
        runner = WorkerRunner(config, workspace)
        from ryuumonbuchi.server import _SessionState

        state = ServerState(config, installation, _SessionState(workspace, runner))
        workspace.update_program(
            ProgramRecord("hello", "source", "hash", workspace.created_at.isoformat(), False)
        )

        async def replace(self):
            return "old", "new"

        monkeypatch.setattr(ServerState, "_replace_session_locked", replace)

        async def uncertain(*args, **kwargs):
            message = "save"
            raise WorkerFailedError(message, request_id="r", uncertain=True)

        monkeypatch.setattr(runner, "run", uncertain)
        with pytest.raises(SessionError, match="program save"):
            asyncio.run(_program_save(state, "hello", str(tmp_path / "snap.gzf"), False))
    finally:
        asyncio.run(workspace.close())


def test_selector_tool_schemas_encode_exactly_one() -> None:
    config = AppConfig(
        Path("/usr/share/ghidra"), max_heap_mb=256, max_cpu=1, operation_timeout_seconds=30
    )
    server = create_server(config)

    async def run() -> None:
        async with Client(server, raise_exceptions=True) as client:
            result = await client.list_tools()
        tools = {tool.name: tool for tool in next(e for e in result if e[0] == "tools")[1]}
        constraint = [
            {"required": ["address"], "not": {"required": ["name"]}},
            {"required": ["name"], "not": {"required": ["address"]}},
        ]
        for name in (
            "function_get",
            "function_decompile",
            "call_graph",
            "edit_rename_function",
            "edit_set_prototype",
        ):
            assert tools[name].input_schema.get("oneOf") == constraint, name
        assert "oneOf" not in tools["memory_read"].input_schema

    asyncio.run(run())


def test_selector_schema_enforcement_missing_tool() -> None:
    from unittest.mock import MagicMock

    from ryuumonbuchi.server import _enforce_selector_schemas  # pyright: ignore[reportPrivateUsage]

    manager = MagicMock()
    manager.get_tool.return_value = None
    mcp = MagicMock()
    mcp._tool_manager = manager
    with pytest.raises(RuntimeError, match="selector tool not registered"):
        _enforce_selector_schemas(mcp)


def test_program_export_disabled_by_config() -> None:
    config = AppConfig(
        Path("/usr/share/ghidra"),
        max_heap_mb=256,
        max_cpu=1,
        operation_timeout_seconds=30,
        allow_export=False,
    )
    server = create_server(config)

    async def run() -> None:
        async with Client(server, raise_exceptions=False) as client:
            result = await client.call_tool(
                "program_export",
                {"program_name": "hello", "destination_path": "/tmp/out.bin"},
            )
            assert result.is_error
            assert "export_disabled" in str(result)
            snapshot = await client.call_tool(
                "program_save", {"program_name": "hello", "destination_path": "/tmp/save.gzf"}
            )
            assert snapshot.is_error
            assert "export_disabled" in str(snapshot)

    asyncio.run(run())


def test_program_import_bytes_gate_and_validation() -> None:
    config = AppConfig(
        Path("/usr/share/ghidra"), max_heap_mb=256, max_cpu=1, operation_timeout_seconds=30
    )
    server = create_server(config)

    async def run() -> None:
        async with Client(server, raise_exceptions=False) as client:
            bad = await client.call_tool(
                "program_import_bytes", {"program_name": "x", "data": "!!!not-base64!!!"}
            )
            assert bad.is_error
            assert "invalid_params" in str(bad)
            big = await client.call_tool(
                "program_import_bytes",
                {
                    "program_name": "x",
                    "data": base64.b64encode(b"\x00" * (config.max_import_bytes + 1)).decode(),
                },
            )
            assert big.is_error
            assert "import_too_large" in str(big)

    asyncio.run(run())


def test_program_import_bytes_disabled_by_config() -> None:
    config = AppConfig(
        Path("/usr/share/ghidra"),
        max_heap_mb=256,
        max_cpu=1,
        operation_timeout_seconds=30,
        allow_import_bytes=False,
    )
    server = create_server(config)

    async def run() -> None:
        async with Client(server, raise_exceptions=False) as client:
            result = await client.call_tool(
                "program_import_bytes",
                {"program_name": "x", "data": base64.b64encode(b"bytes").decode()},
            )
        assert result.is_error
        assert "import_bytes_disabled" in str(result)

    asyncio.run(run())


def test_server_rejects_malformed_lifecycle_results(tmp_path: Path, monkeypatch) -> None:
    from ryuumonbuchi.config import GhidraInstallation
    from ryuumonbuchi.process import WorkerCall
    from ryuumonbuchi.server import (
        ServerState,
        _program_delete,
        _program_import,
        _program_import_bytes,
        _program_save,
        _SessionState,
    )

    source = tmp_path / "source.bin"
    source.write_bytes(b"source")
    workspace = SessionWorkspace.create("12.0.4", temp_dir=tmp_path / "workspace")
    config = AppConfig(
        Path("/usr/share/ghidra"), max_heap_mb=256, max_cpu=1, operation_timeout_seconds=30
    )
    state = ServerState(
        config,
        GhidraInstallation(Path("/usr/share/ghidra"), "12.0.4", 21, ("3.13",)),
        _SessionState(workspace, WorkerRunner(config, workspace)),
    )
    workspace.update_program(
        ProgramRecord("hello", "source", "hash", workspace.created_at.isoformat(), False)
    )
    replacements: list[tuple[str, str]] = []

    async def replace(self):
        replacements.append((self.session.workspace.session_id, "replacement"))
        return "old", "replacement"

    monkeypatch.setattr(ServerState, "_replace_session_locked", replace)

    async def malformed_import(*args, **kwargs):
        return WorkerCall(
            "import",
            {"program_name": "other", "analyzed": True, "language_id": "x", "processor": "x"},
        )

    async def malformed_import_analyzed(*args, **kwargs):
        return WorkerCall(
            "import2",
            {"program_name": "new2", "analyzed": True, "language_id": "x", "processor": "x"},
        )

    async def malformed_import_bytes_analyzed(*args, **kwargs):
        return WorkerCall(
            "import-bytes",
            {"program_name": "new3", "analyzed": True, "language_id": "x", "processor": "x"},
        )

    async def malformed_save(*args, **kwargs):
        return WorkerCall(
            "save",
            {
                "program_name": "hello",
                "destination_path": str(tmp_path / "save.gzf"),
                "bytes_written": True,
                "overwritten": False,
            },
        )

    async def malformed_save_name(*args, **kwargs):
        return WorkerCall(
            "save2",
            {
                "program_name": "other",
                "destination_path": str(tmp_path / "save.gzf"),
                "bytes_written": 1,
                "overwritten": False,
            },
        )

    async def malformed_save_destination(*args, **kwargs):
        return WorkerCall(
            "save3",
            {
                "program_name": "hello",
                "destination_path": str(tmp_path / "other.gzf"),
                "bytes_written": 1,
                "overwritten": False,
            },
        )

    async def malformed_delete(*args, **kwargs):
        return WorkerCall("delete", {"program_name": "other", "deleted": True})

    monkeypatch.setattr(state.session.runner, "run", malformed_import)
    with pytest.raises(Exception, match="replacement"):
        asyncio.run(_program_import(state, str(source), "new", False))
    monkeypatch.setattr(state.session.runner, "run", malformed_import_analyzed)
    with pytest.raises(Exception, match="replacement"):
        asyncio.run(_program_import(state, str(source), "new2", False))
    monkeypatch.setattr(state.session.runner, "run", malformed_import_bytes_analyzed)
    with pytest.raises(Exception, match="replacement"):
        asyncio.run(_program_import_bytes(state, "new3", "Ynl0ZXM=", b"bytes", False))
    monkeypatch.setattr(state.session.runner, "run", malformed_save)
    with pytest.raises(Exception, match="replacement"):
        asyncio.run(_program_save(state, "hello", str(tmp_path / "save.gzf"), False))
    monkeypatch.setattr(state.session.runner, "run", malformed_save_name)
    with pytest.raises(Exception, match="replacement"):
        asyncio.run(_program_save(state, "hello", str(tmp_path / "save.gzf"), False))
    monkeypatch.setattr(state.session.runner, "run", malformed_save_destination)
    with pytest.raises(Exception, match="replacement"):
        asyncio.run(_program_save(state, "hello", str(tmp_path / "save.gzf"), False))
    monkeypatch.setattr(state.session.runner, "run", malformed_delete)
    with pytest.raises(Exception, match="replacement"):
        asyncio.run(_program_delete(state, "hello"))
    assert len(replacements) == 7
    asyncio.run(workspace.close())


def test_server_rejects_byte_import_name_mismatch(tmp_path: Path, monkeypatch) -> None:
    from ryuumonbuchi.config import GhidraInstallation
    from ryuumonbuchi.process import WorkerCall
    from ryuumonbuchi.server import ServerState, _program_import_bytes, _SessionState

    workspace = SessionWorkspace.create("12.0.4", temp_dir=tmp_path / "workspace")
    config = AppConfig(
        Path("/usr/share/ghidra"), max_heap_mb=256, max_cpu=1, operation_timeout_seconds=30
    )
    state = ServerState(
        config,
        GhidraInstallation(Path("/usr/share/ghidra"), "12.0.4", 21, ("3.13",)),
        _SessionState(workspace, WorkerRunner(config, workspace)),
    )
    replacements = 0

    async def replace(self):
        nonlocal replacements
        replacements += 1
        return "old", "new"

    async def mismatch(*args, **kwargs):
        return WorkerCall(
            "import",
            {"program_name": "other", "analyzed": False, "language_id": "x", "processor": "x"},
        )

    monkeypatch.setattr(ServerState, "_replace_session_locked", replace)
    monkeypatch.setattr(state.session.runner, "run", mismatch)
    with pytest.raises(Exception, match="replacement"):
        asyncio.run(_program_import_bytes(state, "bytes", "Ynl0ZXM=", b"bytes", False))
    assert replacements == 1
    asyncio.run(workspace.close())
