# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors

"""Low-level MCP server with the 216-tool dynamic registry."""

# pyright: reportUnusedFunction=false, reportDeprecated=false, reportPrivateUsage=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations

import asyncio
import base64
import binascii
import json
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import anyio
import jsonschema
from mcp import types as mcp_types
from mcp.server.lowlevel.server import NotificationOptions, Server

from . import __version__
from .catalog import TOOL_BY_NAME, TOOL_SPECS
from .config import AppConfig, current_python_version, validate_ghidra_installation
from .native import NativeRunError, NativeRunner, NativeSpawnError, NativeTimeoutError
from .process import (
    PersistentWorker,
    WorkerCancelledError,
    WorkerFailedError,
    WorkerOperationError,
    WorkerTimeoutError,
)
from .session import RuntimeWorkspace

_EXPORT_TOOLS: frozenset[str] = frozenset(
    {
        "program.export",
        "program.export_binary",
        "program.export_packed",
        "program.save",
        "program.save_as",
        "project.export",
    }
)


def _is_export_tool(tool_name: str) -> bool:
    return tool_name in _EXPORT_TOOLS


@dataclass(slots=True)
class ServerState:
    """Mutable process state scoped to one MCP lifespan."""

    config: AppConfig
    workspace: RuntimeWorkspace
    worker: PersistentWorker
    native: NativeRunner
    native_running: int = 0
    cached_status: dict[str, Any] = field(default_factory=dict)


@asynccontextmanager
async def server_lifespan(
    _server: Server[ServerState], config: AppConfig
) -> AsyncGenerator[ServerState]:
    """Create one private workspace and persistent worker."""
    workspace = RuntimeWorkspace.create()
    worker = PersistentWorker(config, workspace)
    native = NativeRunner(config, workspace)
    state = ServerState(config=config, workspace=workspace, worker=worker, native=native)
    try:
        yield state
    finally:
        await state.worker.shutdown()
        state.workspace.close()


def create_server(config: AppConfig) -> Server[ServerState]:
    """Build a fresh MCP server with the 216-tool dynamic registry."""

    async def on_list_tools(ctx: Any, params: Any | None) -> mcp_types.ListToolsResult:
        tools: list[mcp_types.Tool] = []
        for spec in TOOL_SPECS:
            annotations = mcp_types.ToolAnnotations(
                read_only_hint=spec.read_only,
                destructive_hint=spec.destructive,
                open_world_hint=spec.open_world,
            )
            tools.append(
                mcp_types.Tool(
                    name=spec.name,
                    description=spec.description,
                    input_schema=spec.input_schema,
                    annotations=annotations,
                )
            )
        tools.sort(key=lambda t: t.name)
        return mcp_types.ListToolsResult(tools=tools)

    async def on_call_tool(
        ctx: Any, params: mcp_types.CallToolRequestParams
    ) -> mcp_types.CallToolResult:
        state: ServerState = ctx.lifespan_context
        name = params.name
        arguments = dict(params.arguments) if params.arguments else {}
        content = await _dispatch_tool(state, name, arguments)
        is_error = any(
            isinstance(c, mcp_types.TextContent)
            and c.text.startswith(
                ("invalid_params:", "ghidra_error:", "worker_", "native_spawn_failed:")
            )
            for c in content
        )
        return mcp_types.CallToolResult(content=content, is_error=is_error)

    server: Server[ServerState] = Server(
        name="ryuumonbuchi",
        version=__version__,
        lifespan=lambda s: server_lifespan(s, config),
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )
    return server


async def _dispatch_tool(
    state: ServerState, tool_name: str, arguments: dict[str, Any]
) -> list[mcp_types.ContentBlock]:
    spec = TOOL_BY_NAME.get(tool_name)
    if spec is None:
        return _error_result("invalid_params", f"unknown tool: {tool_name}")

    # Validate every tool (including special/native/batch dispatch) against
    # the authoritative catalog schema immediately after lookup.
    try:
        jsonschema.validate(arguments, spec.input_schema, cls=jsonschema.Draft202012Validator)
    except jsonschema.ValidationError as exc:
        return _error_result("invalid_params", f"argument validation failed: {exc.message}")

    # Default-deny export and byte-import policy gates (goal 4).
    if _is_export_tool(tool_name) and not state.config.allow_export:
        return _error_result(
            "invalid_params",
            f"{tool_name} is disabled; set RYUUMONBUCHI_ALLOW_EXPORT=1 to enable",
        )
    if tool_name == "program.open_bytes" and not state.config.allow_import_bytes:
        return _error_result(
            "invalid_params",
            "program.open_bytes is disabled; set RYUUMONBUCHI_ALLOW_IMPORT_BYTES=1 to enable",
        )

    # Preflight decoded base64 size in the parent before worker dispatch.
    if tool_name == "program.open_bytes":
        data_base64 = arguments.get("data_base64", "")
        try:
            decoded = base64.b64decode(data_base64, validate=True)
        except (ValueError, binascii.Error):
            decoded = b""
        else:
            if len(decoded) > state.config.max_import_bytes:
                return _error_result(
                    "invalid_params",
                    f"import payload {len(decoded)} bytes exceeds "
                    f"max_import_bytes {state.config.max_import_bytes}",
                )

    # Server-side tools that don't go through the worker
    if tool_name == "health.ping":
        return await _handle_health_ping(state)
    if tool_name == "mcp.response_format":
        return _handle_response_format()

    # Native tool
    if tool_name == "headless.run":
        return await _handle_headless_run(state, arguments)

    # Batch tool
    if tool_name == "operation.batch":
        return await _handle_batch(state, arguments)

    # Dispatch to worker
    try:
        call = await state.worker.call(tool_name, arguments)
        return _success_result(tool_name, call.result)
    except WorkerOperationError as exc:
        return _error_result(exc.code, str(exc))
    except WorkerTimeoutError as exc:
        return _error_result("worker_timeout", str(exc))
    except WorkerCancelledError as exc:
        return _error_result("worker_cancelled", str(exc))
    except WorkerFailedError as exc:
        return _error_result("worker_failed", str(exc), log_tail=exc.log_tail)


def _success_result(tool_name: str, result: Any) -> list[mcp_types.ContentBlock]:
    """Build a success response with structured content and text summary."""
    text = _summarize(tool_name, result)
    structured = _to_jsonable(result)
    return [
        mcp_types.TextContent(type="text", text=text),
        mcp_types.TextContent(
            type="text", text=json.dumps(structured, default=str, ensure_ascii=False)
        ),
    ]


def _error_result(code: str, message: str, *, log_tail: str = "") -> list[mcp_types.ContentBlock]:
    """Build an error response."""
    text = f"{code}: {message}"
    if log_tail:
        text += f"\n\nWorker log tail:\n{log_tail}"
    return [mcp_types.TextContent(type="text", text=text)]


def _summarize(tool_name: str, result: Any) -> str:
    """Produce a compact deterministic text summary."""
    if isinstance(result, dict):
        if "count" in result:
            return f"{tool_name}: {result['count']} items"
        if "session_id" in result:
            return f"{tool_name}: session {result['session_id']}"
        keys = list(result.keys())[:5]
        return f"{tool_name}: {', '.join(keys)}"
    return f"{tool_name}: {type(result).__name__}"


def _to_jsonable(obj: Any) -> Any:
    """Convert to JSON-serializable form."""
    if obj is None:
        return None
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, (list, tuple)):
        return [_to_jsonable(item) for item in obj]
    if isinstance(obj, dict):
        return {str(k): _to_jsonable(v) for k, v in obj.items()}
    return str(obj)


async def _handle_health_ping(state: ServerState) -> list[mcp_types.ContentBlock]:
    """Health ping: never spawns the JVM."""
    installation = validate_ghidra_installation(state.config.ghidra_install_dir)
    status = await state.worker.status()
    result = {
        "status": "ok",
        "package_version": __version__,
        "python_version": current_python_version(),
        "ghidra_version": installation.version,
        "ghidra_install_dir": str(state.config.ghidra_install_dir),
        "jvm_started": status.get("jvm_started", False),
        "child_pid": status.get("child_pid"),
        "backend_generation": status.get("generation", state.worker.generation),
        "session_count": status.get("session_count", 0),
        "task_count": status.get("task_count", 0),
        "active_task_ids": status.get("active_task_ids", []),
        "native_running": state.native_running,
        "max_heap_mb": state.config.max_heap_mb,
        "max_cpu": state.config.max_cpu,
        "operation_timeout_seconds": state.config.operation_timeout_seconds,
        "max_response_bytes": state.config.max_response_bytes,
        "max_log_tail_bytes": state.config.max_log_tail_bytes,
        "vm_args": list(state.config.vm_args),
        "classpaths": list(state.config.classpaths),
        "class_files": list(state.config.class_files),
    }
    return _success_result("health.ping", result)


def _handle_response_format() -> list[mcp_types.ContentBlock]:
    """Explain the text/structured split and spill paths."""
    result = {
        "format": (
            "Each tool returns a TextContent with a compact summary and a second "
            "TextContent with the full JSON result. When a result exceeds "
            "max_response_bytes, the worker writes it to a spill file under the "
            "runtime workspace runs/ directory and returns a spill envelope with "
            "result_path, preview, and total_bytes."
        ),
    }
    return _success_result("mcp.response_format", result)


async def _handle_headless_run(
    state: ServerState, arguments: dict[str, Any]
) -> list[mcp_types.ContentBlock]:
    """Execute analyzeHeadless with exact argv."""
    state.native_running += 1
    try:
        result = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: state.native.run(
                arguments=arguments.get("arguments", []),
                working_directory=arguments.get("working_directory"),
                environment=arguments.get("environment"),
                stdin_text=arguments.get("stdin_text"),
                terminal=arguments.get("terminal", False),
                timeout_seconds=arguments.get("timeout_seconds"),
            ),
        )
        return _success_result("headless.run", result.to_dict())
    except NativeSpawnError as exc:
        return _error_result("native_spawn_failed", str(exc))
    except NativeTimeoutError as exc:
        return _error_result("worker_timeout", str(exc))
    except NativeRunError as exc:
        return _error_result("ghidra_error", str(exc))
    finally:
        state.native_running -= 1


async def _handle_batch(
    state: ServerState, arguments: dict[str, Any]
) -> list[mcp_types.ContentBlock]:
    """Execute an atomic batch through the worker."""
    session_id = arguments.get("session_id", "")
    operations = arguments.get("operations", [])

    # Validate each batch item against its referenced ToolSpec before dispatch.
    for op in operations:
        tool = op.get("tool", "")
        item_spec = TOOL_BY_NAME.get(tool)
        if item_spec is None:
            return _error_result("invalid_params", f"unknown tool in batch: {tool}")
        if not item_spec.batch_allowed:
            return _error_result("invalid_params", f"tool {tool} is not batchable")
        item_args = dict(op.get("arguments", {}))
        if "session_id" not in item_args:
            item_args["session_id"] = session_id
        try:
            jsonschema.validate(
                item_args, item_spec.input_schema, cls=jsonschema.Draft202012Validator
            )
        except jsonschema.ValidationError as exc:
            return _error_result(
                "invalid_params", f"argument validation failed for {tool}: {exc.message}"
            )
    try:
        call = await state.worker.batch(session_id, operations)
        return _success_result("operation.batch", call.result)
    except WorkerOperationError as exc:
        return _error_result(exc.code, str(exc))
    except WorkerTimeoutError as exc:
        return _error_result("worker_timeout", str(exc))
    except WorkerCancelledError as exc:
        return _error_result("worker_cancelled", str(exc))
    except WorkerFailedError as exc:
        return _error_result("worker_failed", str(exc), log_tail=exc.log_tail)


def main(config: AppConfig) -> None:
    """Run the MCP server over stdio."""
    server = create_server(config)

    async def run() -> None:
        from mcp.server.stdio import stdio_server

        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(notification_options=NotificationOptions()),
            )

    anyio.run(run)
