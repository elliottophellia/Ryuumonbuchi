# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors

"""Server: catalog listing, tool dispatch, health.ping, response_format."""

from __future__ import annotations

# pyright: reportPrivateUsage=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportAttributeAccessIssue=false, reportUndefinedVariable=false

import asyncio
import json
from pathlib import Path


from ryuumonbuchi.catalog import TOOL_BY_NAME, TOOL_SPECS
from ryuumonbuchi.config import AppConfig
from ryuumonbuchi.native import NativeRunner
from ryuumonbuchi.process import PersistentWorker
from ryuumonbuchi.server import (
    ServerState,
    _dispatch_tool,
    _error_result,
    _summarize,
    _success_result,
    _to_jsonable,
    create_server,
    main,
)
from ryuumonbuchi.session import RuntimeWorkspace


def _make_state(workspace: RuntimeWorkspace, fake_ghidra: Path) -> ServerState:
    config = AppConfig(
        ghidra_install_dir=fake_ghidra,
        max_heap_mb=256,
        max_cpu=1,
        operation_timeout_seconds=30,
    )
    worker = PersistentWorker(config=config, workspace=workspace)
    native = NativeRunner(config=config, workspace=workspace)
    return ServerState(config=config, workspace=workspace, worker=worker, native=native)


def test_create_server_returns_server(fake_ghidra: Path) -> None:
    config = AppConfig(
        ghidra_install_dir=fake_ghidra,
        max_heap_mb=256, max_cpu=1, operation_timeout_seconds=30,
    )
    server = create_server(config)
    assert server is not None
    assert server.name == "ryuumonbuchi"


def test_success_result_returns_two_content_blocks() -> None:
    result = _success_result("function.list", {"count": 5})
    assert len(result) == 2


def test_success_result_summary() -> None:
    result = _success_result("function.list", {"count": 5})
    assert "5" in result[0].text  # type: ignore[union-attr]


def test_error_result_has_code_prefix() -> None:
    result = _error_result("ghidra_error", "bad address")
    assert "ghidra_error" in result[0].text  # type: ignore[union-attr]
    assert "bad address" in result[0].text  # type: ignore[union-attr]


def test_error_result_with_log_tail() -> None:
    result = _error_result("worker_failed", "crash", log_tail="traceback")
    assert "traceback" in result[0].text  # type: ignore[union-attr]


def test_summarize_count() -> None:
    assert "5" in _summarize("function.list", {"count": 5})


def test_summarize_session_id() -> None:
    assert "s1" in _summarize("program.open", {"session_id": "s1"})


def test_summarize_keys() -> None:
    summary = _summarize("memory.read", {"address": "0x1000", "bytes_hex": "ab"})
    assert "memory.read" in summary


def test_summarize_non_dict() -> None:
    assert "str" in _summarize("test", "hello")


def test_to_jsonable_none() -> None:
    assert _to_jsonable(None) is None


def test_to_jsonable_primitives() -> None:
    assert _to_jsonable(42) == 42
    assert _to_jsonable("hello") == "hello"
    assert _to_jsonable(True) is True
    assert _to_jsonable(3.14) == 3.14


def test_to_jsonable_list() -> None:
    assert _to_jsonable([1, "a"]) == [1, "a"]


def test_to_jsonable_dict() -> None:
    assert _to_jsonable({"k": "v"}) == {"k": "v"}


def test_to_jsonable_object() -> None:
    class Foo:
        pass

    assert isinstance(_to_jsonable(Foo()), str)


def test_dispatch_unknown_tool(workspace: RuntimeWorkspace, fake_ghidra: Path) -> None:
    state = _make_state(workspace, fake_ghidra)
    result = asyncio.run(_dispatch_tool(state, "nonexistent.tool", {}))
    assert "invalid_params" in result[0].text  # type: ignore[union-attr]


def test_dispatch_health_ping(workspace: RuntimeWorkspace, fake_ghidra: Path) -> None:
    state = _make_state(workspace, fake_ghidra)
    result = asyncio.run(_dispatch_tool(state, "health.ping", {}))
    text = result[1].text if len(result) > 1 else result[0].text
    data = json.loads(text)  # type: ignore[arg-type]
    assert data["status"] == "ok"
    assert data["package_version"] == "0.3.0"


def test_dispatch_response_format(workspace: RuntimeWorkspace, fake_ghidra: Path) -> None:
    state = _make_state(workspace, fake_ghidra)
    result = asyncio.run(_dispatch_tool(state, "mcp.response_format", {}))
    assert len(result) >= 1


def test_main_callable() -> None:
    assert callable(main)


def test_all_tools_have_dispatch_path() -> None:
    assert "health.ping" in TOOL_BY_NAME
    assert "mcp.response_format" in TOOL_BY_NAME
    assert "headless.run" in TOOL_BY_NAME
    assert "operation.batch" in TOOL_BY_NAME
    backend_tools = [s for s in TOOL_SPECS if s.backend_method is not None]
    assert len(backend_tools) == 212
