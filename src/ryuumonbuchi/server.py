# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors

"""MCP server factory, lifespan state, and finite typed tool catalog."""

# pyright: reportUnusedFunction=false, reportDeprecated=false

from __future__ import annotations

import base64
import hashlib
from collections.abc import AsyncGenerator, Awaitable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, TypeVar

from mcp.server import MCPServer
from mcp.server.mcpserver import Context
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import BaseModel

from . import __version__
from .config import AppConfig, GhidraInstallation, current_python_version, validate_config
from .models import (
    READ_ACTIONS,
    AddressMatch,
    AnalysisOptions,
    AnalysisOptionsGetOperation,
    AnalysisOptionsSetOperation,
    AnalysisResult,
    AnalysisRunOperation,
    BatchOperation,
    BatchResult,
    ByteSearchOperation,
    CallGraph,
    CallGraphOperation,
    DecompileResult,
    DefinedData,
    ExportSymbol,
    FunctionDecompileOperation,
    FunctionDetail,
    FunctionGetOperation,
    FunctionListOperation,
    FunctionSummary,
    HealthResult,
    ImportSymbol,
    Instruction,
    ListExportsOperation,
    ListImportsOperation,
    ListingDataOperation,
    ListingDisassembleOperation,
    MemoryBlock,
    MemoryBlocksOperation,
    MemoryReadOperation,
    MemoryReadResult,
    MutationResult,
    Page,
    PatchBytesOperation,
    ProgramDeleteResult,
    ProgramExportOperation,
    ProgramExportResult,
    ProgramImportResult,
    ProgramInfo,
    ProgramListResult,
    RedoOperation,
    Reference,
    ReferencesOperation,
    RenameFunctionOperation,
    RenameVariableOperation,
    SearchStringsOperation,
    SearchSymbolsOperation,
    SessionClearResult,
    SessionStatus,
    SetCommentOperation,
    SetPrototypeOperation,
    StringMatch,
    SymbolMatch,
    TextSearchOperation,
    UndoOperation,
)
from .process import (
    WorkerCancelledError,
    WorkerFailedError,
    WorkerOperationError,
    WorkerRunError,
    WorkerRunner,
    WorkerTimeoutError,
)
from .session import (
    ProgramExistsError,
    ProgramNotFoundError,
    ProgramNotSelectedError,
    ProgramRecord,
    SessionError,
    SessionWorkspace,
    stream_sha256,
    validate_program_name,
)

T = TypeVar("T", bound=BaseModel)


@dataclass(slots=True)
class ServerState:
    """Mutable process state scoped to one MCP lifespan."""

    config: AppConfig
    installation: GhidraInstallation
    workspace: SessionWorkspace
    runner: WorkerRunner

    @classmethod
    def create(cls, config: AppConfig, installation: GhidraInstallation) -> ServerState:
        workspace = SessionWorkspace.create(installation.version)
        return cls(config, installation, workspace, WorkerRunner(config, workspace))

    async def clear_session(self) -> tuple[str, str]:
        old = self.workspace
        old_id = old.session_id
        await old.close()
        new = SessionWorkspace.create(self.installation.version, temp_dir=old.root.parent)
        self.workspace = new
        self.runner = WorkerRunner(self.config, new)
        return old_id, new.session_id

    async def close(self) -> None:
        await self.workspace.close()


@asynccontextmanager
async def server_lifespan(
    _: MCPServer[ServerState], config: AppConfig
) -> AsyncGenerator[ServerState]:
    """Create one private workspace and always remove it on MCP shutdown."""

    installation = validate_config(config)
    state = ServerState.create(config, installation)
    try:
        yield state
    finally:
        await state.close()


def _state(ctx: Context[ServerState, Any]) -> ServerState:
    return ctx.request_context.lifespan_context


def _raise_tool(code: str, message: str) -> ToolError:
    return ToolError(f"{code}: {message}")


async def _guard(awaitable: Awaitable[T]) -> T:
    """Map domain failures to stable MCP tool error prefixes."""

    try:
        return await awaitable
    except WorkerOperationError as exc:
        raise _raise_tool(exc.code, str(exc)) from exc
    except WorkerTimeoutError as exc:
        raise _raise_tool("worker_timeout", str(exc)) from exc
    except WorkerCancelledError as exc:
        raise _raise_tool("worker_cancelled", str(exc)) from exc
    except WorkerFailedError as exc:
        raise _raise_tool("worker_failed", str(exc)) from exc
    except ProgramNotSelectedError as exc:
        raise _raise_tool("program_not_selected", str(exc)) from exc
    except ProgramNotFoundError as exc:
        raise _raise_tool("program_not_found", str(exc)) from exc
    except ProgramExistsError as exc:
        raise _raise_tool("invalid_params", str(exc)) from exc
    except SessionError as exc:
        raise _raise_tool("configuration", str(exc)) from exc
    except (ValueError, TypeError) as exc:
        raise _raise_tool("invalid_params", str(exc)) from exc


async def _run_program(
    state: ServerState,
    program_name: str,
    operation: BaseModel,
    *,
    read_only: bool,
    timeout_seconds: int | None = None,
) -> Any:
    name = validate_program_name(program_name)
    state.workspace.require_program(name)
    raw = operation.model_dump(mode="json")
    try:
        async with state.workspace.operation():
            call = await state.runner.run(
                [raw], read_only=read_only, timeout_seconds=timeout_seconds, program_name=name
            )
        return call.result
    except WorkerRunError as exc:
        if exc.uncertain:
            new_id = await state.clear_session()
            raise SessionError(
                f"worker state was uncertain; replacement session created: {new_id}"
            ) from exc
        raise


async def _run_batch(
    state: ServerState, program_name: str, operations: tuple[BatchOperation, ...]
) -> Any:
    name = validate_program_name(program_name)
    state.workspace.require_program(name)
    if not 1 <= len(operations) <= 32:
        raise ValueError("batch operations must contain 1..32 items")
    raw_operations = [operation.model_dump(mode="json") for operation in operations]
    read_only = all(operation.action in READ_ACTIONS for operation in operations)
    try:
        async with state.workspace.operation():
            call = await state.runner.run(raw_operations, read_only=read_only, program_name=name)
        return call.result
    except WorkerRunError as exc:
        if exc.uncertain:
            new_id = await state.clear_session()
            raise SessionError(
                f"worker state was uncertain; replacement session created: {new_id}"
            ) from exc
        raise


def _program_info(record: ProgramRecord, version: str) -> ProgramInfo:
    return ProgramInfo(
        program_name=record.program_name,
        source_path=record.source_path,
        source_sha256=record.source_sha256,
        imported_at=datetime.fromisoformat(record.imported_at),
        analyzed=record.analyzed,
        ghidra_version=version,
    )


def create_server(config: AppConfig) -> MCPServer[ServerState]:
    """Build a fresh MCP server instance with the complete finite catalog."""

    validate_config(config)
    mcp: MCPServer[ServerState] = MCPServer(
        "ryuumonbuchi",
        version=__version__,
        description="Headless Ghidra analysis with one-shot worker isolation.",
        lifespan=lambda server: server_lifespan(server, config),
    )

    @mcp.tool()
    async def health(ctx: Context[ServerState, Any]) -> HealthResult:
        """Return configuration and session health without starting a worker."""

        state = _state(ctx)
        return HealthResult(
            package_version=__version__,
            python_version=current_python_version(),
            ghidra_path=str(state.installation.path),
            ghidra_version=state.installation.version,
            max_heap_mb=state.config.max_heap_mb,
            max_cpu=state.config.max_cpu,
            operation_timeout_seconds=state.config.operation_timeout_seconds,
            session_id=state.workspace.session_id,
            tracked_program_count=len(state.workspace.read_manifest().programs),
        )

    @mcp.tool()
    async def session_status(ctx: Context[ServerState, Any]) -> SessionStatus:
        """Return session ownership and worker lifecycle state."""

        state = _state(ctx)
        manifest = state.workspace.read_manifest()
        return SessionStatus(
            session_id=manifest.session_id,
            root_created_at=datetime.fromisoformat(manifest.created_at),
            programs=list(manifest.programs),
            active_worker_pid=state.runner.active_worker_pid,
            last_worker_pid=state.runner.last_worker_pid,
        )

    @mcp.tool()
    async def session_clear(ctx: Context[ServerState, Any]) -> SessionClearResult:
        """Close the current private workspace and create a new empty session."""

        old_id, new_id = await _state(ctx).clear_session()
        return SessionClearResult(old_session_id=old_id, new_session_id=new_id)

    @mcp.tool()
    async def program_import(
        source_path: str,
        program_name: str,
        analyze: bool = True,
        *,
        ctx: Context[ServerState, Any],
    ) -> ProgramImportResult:
        """Import caller-selected bytes under an explicit root-level program name."""

        return await _guard(_program_import(_state(ctx), source_path, program_name, analyze))

    @mcp.tool()
    async def program_delete(
        program_name: str, *, ctx: Context[ServerState, Any]
    ) -> ProgramDeleteResult:
        """Delete exactly one imported root-level program."""

        return await _guard(_program_delete(_state(ctx), program_name))

    @mcp.tool()
    async def program_import_bytes(
        program_name: str,
        data: str,
        analyze: bool = True,
        *,
        ctx: Context[ServerState, Any],
    ) -> ProgramImportResult:
        """Import caller-selected base64-encoded bytes under an explicit program name."""

        state = _state(ctx)
        if not state.config.allow_import_bytes:
            raise _raise_tool("import_bytes_disabled", "byte import is disabled by configuration")
        try:
            payload = base64.b64decode(data, validate=True)
        except ValueError as exc:
            raise _raise_tool("invalid_params", f"data must be valid base64: {exc}") from exc
        if len(payload) > state.config.max_import_bytes:
            message = f"decoded import exceeds {state.config.max_import_bytes} bytes"
            raise _raise_tool("import_too_large", message)
        result = await _guard(_program_import_bytes(state, program_name, data, payload, analyze))
        return ProgramImportResult.model_validate(result)

    @mcp.tool()
    async def program_export(
        program_name: str,
        destination_path: str,
        overwrite: bool = False,
        *,
        ctx: Context[ServerState, Any],
    ) -> ProgramExportResult:
        """Write the current program bytes, including patches, to a destination file.

        The original imported file is copied and every initialized file-backed
        memory block is overlaid at its source file offset, so edits made with
        edit_patch_bytes are reflected in the exported image. Disabled when
        RYUUMONBUCHI_ALLOW_EXPORT is set to a false value.
        """

        state = _state(ctx)
        if not state.config.allow_export:
            raise _raise_tool("export_disabled", "program export is disabled by configuration")
        result = await _guard(
            _run_program(
                state,
                program_name,
                ProgramExportOperation(destination_path=destination_path, overwrite=overwrite),
                read_only=False,
            )
        )
        return ProgramExportResult.model_validate(result)

    @mcp.tool()
    async def program_list(ctx: Context[ServerState, Any]) -> ProgramListResult:
        """List imported programs from the authoritative manifest without a worker."""

        state = _state(ctx)
        return ProgramListResult(
            programs=[
                _program_info(record, state.installation.version)
                for record in state.workspace.read_manifest().programs.values()
            ]
        )

    @mcp.tool()
    async def program_info(program_name: str, *, ctx: Context[ServerState, Any]) -> ProgramInfo:
        """Return manifest metadata for one explicitly selected program."""

        return await _guard(_program_info_async(_state(ctx), program_name))

    @mcp.tool()
    async def function_list(
        program_name: str,
        query: str | None = None,
        offset: int = 0,
        page_size: int = 100,
        *,
        ctx: Context[ServerState, Any],
    ) -> Page[FunctionSummary]:
        """List bounded function summaries."""

        result = await _guard(
            _run_program(
                _state(ctx),
                program_name,
                FunctionListOperation(query=query, offset=offset, page_size=page_size),
                read_only=True,
            )
        )
        return Page[FunctionSummary].model_validate(result)

    @mcp.tool()
    async def function_get(
        program_name: str,
        address: str | None = None,
        name: str | None = None,
        *,
        ctx: Context[ServerState, Any],
    ) -> FunctionDetail:
        """Return one function selected by exactly one address or full name."""

        result = await _guard(
            _run_program(
                _state(ctx),
                program_name,
                FunctionGetOperation(address=address, name=name),
                read_only=True,
            )
        )
        return FunctionDetail.model_validate(result)

    @mcp.tool()
    async def function_decompile(
        program_name: str,
        address: str | None = None,
        name: str | None = None,
        timeout_seconds: int = 60,
        *,
        ctx: Context[ServerState, Any],
    ) -> DecompileResult:
        """Decompile one function with a bounded timeout and UTF-8 result cap."""

        result = await _guard(
            _run_program(
                _state(ctx),
                program_name,
                FunctionDecompileOperation(
                    address=address, name=name, timeout_seconds=timeout_seconds
                ),
                read_only=True,
                timeout_seconds=timeout_seconds,
            )
        )
        return DecompileResult.model_validate(result)

    @mcp.tool()
    async def listing_disassemble(
        program_name: str,
        address: str | None = None,
        offset: int = 0,
        page_size: int = 100,
        *,
        ctx: Context[ServerState, Any],
    ) -> Page[Instruction]:
        """Return a bounded instruction page."""

        result = await _guard(
            _run_program(
                _state(ctx),
                program_name,
                ListingDisassembleOperation(address=address, offset=offset, page_size=page_size),
                read_only=True,
            )
        )
        return Page[Instruction].model_validate(result)

    @mcp.tool()
    async def listing_data(
        program_name: str,
        offset: int = 0,
        page_size: int = 100,
        *,
        ctx: Context[ServerState, Any],
    ) -> Page[DefinedData]:
        """Return a bounded page of defined data."""

        result = await _guard(
            _run_program(
                _state(ctx),
                program_name,
                ListingDataOperation(offset=offset, page_size=page_size),
                read_only=True,
            )
        )
        return Page[DefinedData].model_validate(result)

    @mcp.tool()
    async def memory_blocks(
        program_name: str, *, ctx: Context[ServerState, Any]
    ) -> list[MemoryBlock]:
        """Return memory block permissions and ranges."""

        result = await _guard(
            _run_program(_state(ctx), program_name, MemoryBlocksOperation(), read_only=True)
        )
        return [MemoryBlock.model_validate(item) for item in result]

    @mcp.tool()
    async def memory_read(
        program_name: str, address: str, length: int, *, ctx: Context[ServerState, Any]
    ) -> MemoryReadResult:
        """Read at most 65,536 bytes and return lowercase hexadecimal bytes."""

        result = await _guard(
            _run_program(
                _state(ctx),
                program_name,
                MemoryReadOperation(address=address, length=length),
                read_only=True,
            )
        )
        return MemoryReadResult.model_validate(result)

    @mcp.tool()
    async def search_strings(
        program_name: str,
        query: str | None = None,
        min_length: int = 4,
        offset: int = 0,
        page_size: int = 100,
        *,
        ctx: Context[ServerState, Any],
    ) -> Page[StringMatch]:
        """Search bounded printable strings.

        Matches are maximal printable runs: overlapping substrings are
        deduplicated and only runs of at least min_length bytes are returned.
        """

        result = await _guard(
            _run_program(
                _state(ctx),
                program_name,
                SearchStringsOperation(
                    query=query, min_length=min_length, offset=offset, page_size=page_size
                ),
                read_only=True,
            )
        )
        return Page[StringMatch].model_validate(result)

    @mcp.tool()
    async def search_symbols(
        program_name: str,
        query: str,
        offset: int = 0,
        page_size: int = 100,
        *,
        ctx: Context[ServerState, Any],
    ) -> Page[SymbolMatch]:
        """Search bounded fully qualified symbol names."""

        result = await _guard(
            _run_program(
                _state(ctx),
                program_name,
                SearchSymbolsOperation(query=query, offset=offset, page_size=page_size),
                read_only=True,
            )
        )
        return Page[SymbolMatch].model_validate(result)

    @mcp.tool()
    async def list_imports(
        program_name: str,
        offset: int = 0,
        page_size: int = 100,
        *,
        ctx: Context[ServerState, Any],
    ) -> Page[ImportSymbol]:
        """List bounded external import symbols."""

        result = await _guard(
            _run_program(
                _state(ctx),
                program_name,
                ListImportsOperation(offset=offset, page_size=page_size),
                read_only=True,
            )
        )
        return Page[ImportSymbol].model_validate(result)

    @mcp.tool()
    async def list_exports(
        program_name: str,
        offset: int = 0,
        page_size: int = 100,
        *,
        ctx: Context[ServerState, Any],
    ) -> Page[ExportSymbol]:
        """List bounded export symbols."""

        result = await _guard(
            _run_program(
                _state(ctx),
                program_name,
                ListExportsOperation(offset=offset, page_size=page_size),
                read_only=True,
            )
        )
        return Page[ExportSymbol].model_validate(result)

    @mcp.tool()
    async def references(
        program_name: str,
        address: str,
        direction: Literal["to", "from"] = "to",
        offset: int = 0,
        page_size: int = 100,
        *,
        ctx: Context[ServerState, Any],
    ) -> Page[Reference]:
        """List bounded references to or from an address."""

        result = await _guard(
            _run_program(
                _state(ctx),
                program_name,
                ReferencesOperation(
                    address=address, direction=direction, offset=offset, page_size=page_size
                ),
                read_only=True,
            )
        )
        return Page[Reference].model_validate(result)

    @mcp.tool()
    async def call_graph(
        program_name: str,
        address: str | None = None,
        name: str | None = None,
        depth: int = 2,
        max_nodes: int = 500,
        *,
        ctx: Context[ServerState, Any],
    ) -> CallGraph:
        """Traverse a bounded function call graph."""

        result = await _guard(
            _run_program(
                _state(ctx),
                program_name,
                CallGraphOperation(address=address, name=name, depth=depth, max_nodes=max_nodes),
                read_only=True,
            )
        )
        return CallGraph.model_validate(result)

    @mcp.tool()
    async def byte_search(
        program_name: str,
        pattern: str,
        mask: str | None = None,
        offset: int = 0,
        page_size: int = 100,
        *,
        ctx: Context[ServerState, Any],
    ) -> Page[AddressMatch]:
        """Search bounded whitespace-separated hexadecimal byte patterns."""

        result = await _guard(
            _run_program(
                _state(ctx),
                program_name,
                ByteSearchOperation(pattern=pattern, mask=mask, offset=offset, page_size=page_size),
                read_only=True,
            )
        )
        return Page[AddressMatch].model_validate(result)

    @mcp.tool()
    async def text_search(
        program_name: str,
        query: str,
        offset: int = 0,
        page_size: int = 100,
        *,
        ctx: Context[ServerState, Any],
    ) -> Page[AddressMatch]:
        """Search bounded memory input for UTF-8 text."""

        result = await _guard(
            _run_program(
                _state(ctx),
                program_name,
                TextSearchOperation(query=query, offset=offset, page_size=page_size),
                read_only=True,
            )
        )
        return Page[AddressMatch].model_validate(result)

    @mcp.tool()
    async def analysis_run(
        program_name: str,
        timeout_seconds: int = 900,
        *,
        ctx: Context[ServerState, Any],
    ) -> AnalysisResult:
        """Run bounded auto-analysis and save only on success."""

        result = await _guard(
            _run_program(
                _state(ctx),
                program_name,
                AnalysisRunOperation(timeout_seconds=timeout_seconds),
                read_only=False,
                timeout_seconds=timeout_seconds,
            )
        )
        return AnalysisResult.model_validate(result)

    @mcp.tool()
    async def analysis_options_get(
        program_name: str, *, ctx: Context[ServerState, Any]
    ) -> AnalysisOptions:
        """Return existing analysis option values."""

        result = await _guard(
            _run_program(_state(ctx), program_name, AnalysisOptionsGetOperation(), read_only=True)
        )
        return AnalysisOptions(values=result)

    @mcp.tool()
    async def analysis_options_set(
        program_name: str,
        values: dict[str, bool | int | float | str],
        *,
        ctx: Context[ServerState, Any],
    ) -> AnalysisOptions:
        """Set only existing analysis options in one transaction."""

        result = await _guard(
            _run_program(
                _state(ctx),
                program_name,
                AnalysisOptionsSetOperation(values=values),
                read_only=False,
            )
        )
        return AnalysisOptions(values=result)

    @mcp.tool()
    async def edit_rename_function(
        program_name: str,
        address: str | None = None,
        name: str | None = None,
        new_name: str = "",
        *,
        ctx: Context[ServerState, Any],
    ) -> MutationResult:
        """Rename one explicitly selected function."""

        result = await _guard(
            _run_program(
                _state(ctx),
                program_name,
                RenameFunctionOperation(address=address, name=name, new_name=new_name),
                read_only=False,
            )
        )
        return MutationResult.model_validate(result)

    @mcp.tool()
    async def edit_rename_variable(
        program_name: str,
        function_address: str,
        old_name: str,
        new_name: str,
        *,
        ctx: Context[ServerState, Any],
    ) -> MutationResult:
        """Rename one local variable in an explicitly selected function."""

        result = await _guard(
            _run_program(
                _state(ctx),
                program_name,
                RenameVariableOperation(
                    function_address=function_address, old_name=old_name, new_name=new_name
                ),
                read_only=False,
            )
        )
        return MutationResult.model_validate(result)

    @mcp.tool()
    async def edit_set_comment(
        program_name: str,
        address: str,
        comment: str,
        comment_type: Literal["plate", "pre", "post", "eol", "repeatable"] = "plate",
        *,
        ctx: Context[ServerState, Any],
    ) -> MutationResult:
        """Set one typed address comment."""

        result = await _guard(
            _run_program(
                _state(ctx),
                program_name,
                SetCommentOperation(address=address, comment=comment, comment_type=comment_type),
                read_only=False,
            )
        )
        return MutationResult.model_validate(result)

    @mcp.tool()
    async def edit_set_prototype(
        program_name: str,
        address: str | None = None,
        name: str | None = None,
        prototype: str = "",
        *,
        ctx: Context[ServerState, Any],
    ) -> MutationResult:
        """Replace one function prototype using Ghidra's signature parser."""

        result = await _guard(
            _run_program(
                _state(ctx),
                program_name,
                SetPrototypeOperation(address=address, name=name, prototype=prototype),
                read_only=False,
            )
        )
        return MutationResult.model_validate(result)

    @mcp.tool()
    async def edit_patch_bytes(
        program_name: str, address: str, bytes_hex: str, *, ctx: Context[ServerState, Any]
    ) -> MutationResult:
        """Patch bounded bytes, clear overlapping code units, and disassemble."""

        result = await _guard(
            _run_program(
                _state(ctx),
                program_name,
                PatchBytesOperation(address=address, bytes_hex=bytes_hex),
                read_only=False,
            )
        )
        return MutationResult.model_validate(result)

    @mcp.tool()
    async def edit_undo(
        program_name: str, count: int = 1, *, ctx: Context[ServerState, Any]
    ) -> MutationResult:
        """Undo up to 100 available changes."""

        result = await _guard(
            _run_program(_state(ctx), program_name, UndoOperation(count=count), read_only=False)
        )
        return MutationResult.model_validate(result)

    @mcp.tool()
    async def edit_redo(
        program_name: str, count: int = 1, *, ctx: Context[ServerState, Any]
    ) -> MutationResult:
        """Redo up to 100 available changes."""

        result = await _guard(
            _run_program(_state(ctx), program_name, RedoOperation(count=count), read_only=False)
        )
        return MutationResult.model_validate(result)

    @mcp.tool()
    async def batch(
        program_name: str,
        operations: tuple[BatchOperation, ...],
        *,
        ctx: Context[ServerState, Any],
    ) -> BatchResult:
        """Execute up to 32 ordered reads or one atomic mixed batch."""

        result = await _guard(_run_batch(_state(ctx), program_name, operations))
        return BatchResult.model_validate(result)

    _enforce_selector_schemas(mcp)
    return mcp


SELECTOR_TOOL_NAMES = frozenset(
    {
        "function_get",
        "function_decompile",
        "call_graph",
        "edit_rename_function",
        "edit_set_prototype",
    }
)


def _enforce_selector_schemas(mcp: MCPServer[ServerState]) -> None:
    """Embed the exactly-one selector constraint in tool parameter schemas.

    Tool schemas are derived from the flat function signature, which cannot
    express the XOR between ``address`` and ``name``. The operation models
    validate it at call time; this makes the contract visible to clients
    before they call.
    """

    for name in SELECTOR_TOOL_NAMES:
        tool = mcp._tool_manager.get_tool(name)  # pyright: ignore[reportPrivateUsage]
        if tool is None:
            raise RuntimeError(f"selector tool not registered: {name}")
        tool.parameters["oneOf"] = [
            {"required": ["address"], "not": {"required": ["name"]}},
            {"required": ["name"], "not": {"required": ["address"]}},
        ]


async def _program_info_async(state: ServerState, program_name: str) -> ProgramInfo:
    name = validate_program_name(program_name)
    return _program_info(state.workspace.require_program(name), state.installation.version)


async def _program_import(
    state: ServerState, source_path: str, program_name: str, analyze: bool
) -> ProgramImportResult:
    name = validate_program_name(program_name)
    source = Path(source_path).expanduser().resolve()
    source_hash = stream_sha256(source)
    state.workspace.ensure_program_absent(name)
    raw = {
        "action": "program_import",
        "source_path": str(source),
        "program_name": name,
        "analyze": analyze,
    }
    try:
        async with state.workspace.operation():
            await state.runner.run([raw], read_only=False, program_name=name)
    except WorkerRunError as exc:
        if exc.uncertain:
            new_id = await state.clear_session()
            message = f"program import uncertain; replacement session created: {new_id}"
            raise SessionError(message) from exc
        raise
    state.workspace.update_program(
        ProgramRecord(name, str(source), source_hash, datetime.now(UTC).isoformat(), analyze)
    )
    return ProgramImportResult(
        program_name=name,
        source_sha256=source_hash,
        ghidra_version=state.installation.version,
        analyzed=analyze,
    )


async def _program_import_bytes(
    state: ServerState,
    program_name: str,
    data: str,
    payload: bytes,
    analyze: bool,
) -> ProgramImportResult:
    name = validate_program_name(program_name)
    source_hash = hashlib.sha256(payload).hexdigest()
    state.workspace.ensure_program_absent(name)
    raw = {
        "action": "program_import_bytes",
        "data": data,
        "program_name": name,
        "analyze": analyze,
    }
    try:
        async with state.workspace.operation():
            await state.runner.run([raw], read_only=False, program_name=name)
    except WorkerRunError as exc:
        if exc.uncertain:
            new_id = await state.clear_session()
            message = f"program import uncertain; replacement session created: {new_id}"
            raise SessionError(message) from exc
        raise
    state.workspace.update_program(
        ProgramRecord(
            name, f"bytes:{source_hash}", source_hash, datetime.now(UTC).isoformat(), analyze
        )
    )
    return ProgramImportResult(
        program_name=name,
        source_sha256=source_hash,
        ghidra_version=state.installation.version,
        analyzed=analyze,
    )


async def _program_delete(state: ServerState, program_name: str) -> ProgramDeleteResult:
    name = validate_program_name(program_name)
    state.workspace.require_program(name)
    raw = {"action": "program_delete", "program_name": name}
    try:
        async with state.workspace.operation():
            await state.runner.run([raw], read_only=False, program_name=name)
    except WorkerRunError as exc:
        if exc.uncertain:
            new_id = await state.clear_session()
            message = f"program deletion uncertain; replacement session created: {new_id}"
            raise SessionError(message) from exc
        raise
    state.workspace.remove_program(name)
    return ProgramDeleteResult(program_name=name)


def main(config: AppConfig) -> None:
    """Validate startup before opening MCP stdio and run one server instance."""

    validate_config(config)
    create_server(config).run("stdio")
