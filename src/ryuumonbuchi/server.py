# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors

"""MCP server factory, lifespan state, and finite typed tool catalog."""

# pyright: reportUnusedFunction=false, reportDeprecated=false, reportPrivateUsage=false

from __future__ import annotations

import asyncio
import base64
import hashlib
from collections.abc import AsyncGenerator, Awaitable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Never, TypeVar

from mcp.server import MCPServer
from mcp.server.mcpserver import Context
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from . import __version__
from .config import AppConfig, GhidraInstallation, current_python_version, validate_config
from .models import (
    READ_ACTIONS,
    AddressMatch,
    AnalysisListAnalyzersOperation,
    AnalysisOptions,
    AnalysisOptionsGetOperation,
    AnalysisOptionsSetOperation,
    AnalysisResult,
    AnalysisRunOperation,
    AnalyzerSummary,
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
    ProgramSaveResult,
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
    SetDataTypeOperation,
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


class _WorkerImportResult(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    program_name: str
    analyzed: bool
    language_id: str
    processor: str


class _WorkerSaveResult(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    program_name: str
    destination_path: str
    bytes_written: int = Field(ge=0)
    overwritten: bool


class _WorkerDeleteResult(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    program_name: str
    deleted: Literal[True]


@dataclass(frozen=True, slots=True)
class _SessionState:
    workspace: SessionWorkspace
    runner: WorkerRunner


@dataclass(slots=True)
class ServerState:
    """Mutable process state scoped to one MCP lifespan."""

    config: AppConfig
    installation: GhidraInstallation
    session: _SessionState
    session_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    @classmethod
    def create(cls, config: AppConfig, installation: GhidraInstallation) -> ServerState:
        workspace = SessionWorkspace.create(installation.version)
        return cls(config, installation, _SessionState(workspace, WorkerRunner(config, workspace)))

    async def _replace_session_locked(self) -> tuple[str, str]:
        """Install a replacement before closing the old workspace.

        The caller must hold ``session_lock`` and must not hold a workspace lock.
        """

        old = self.session
        replacement_workspace = SessionWorkspace.create(
            self.installation.version, temp_dir=old.workspace.root.parent
        )
        replacement = _SessionState(
            replacement_workspace, WorkerRunner(self.config, replacement_workspace)
        )
        self.session = replacement
        await old.workspace.close()
        return old.workspace.session_id, replacement_workspace.session_id

    async def clear_session(self) -> tuple[str, str]:
        async with self.session_lock:
            return await self._replace_session_locked()

    async def close(self) -> None:
        async with self.session_lock:
            await self.session.workspace.close()


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


async def _raise_worker_failure_locked(
    state: ServerState, exc: WorkerRunError, operation: str
) -> Never:
    """Replace uncertain state while ``session_lock`` is held, without a workspace lock."""

    if not exc.uncertain:
        raise exc
    _old_id, new_id = await state._replace_session_locked()
    raise SessionError(f"{operation} uncertain; replacement session created: {new_id}") from exc


async def _run_program(
    state: ServerState,
    program_name: str,
    operation: BaseModel,
    *,
    read_only: bool,
    timeout_seconds: int | None = None,
) -> Any:
    name = validate_program_name(program_name)
    raw = operation.model_dump(mode="json")
    async with state.session_lock:
        session = state.session
        session.workspace.require_program(name)
        try:
            async with session.workspace.operation():
                call = await session.runner.run(
                    [raw], read_only=read_only, timeout_seconds=timeout_seconds, program_name=name
                )
        except WorkerRunError as exc:
            await _raise_worker_failure_locked(state, exc, "worker state was")
        return call.result


async def _run_batch(
    state: ServerState, program_name: str, operations: tuple[BatchOperation, ...]
) -> Any:
    name = validate_program_name(program_name)
    if not 1 <= len(operations) <= 32:
        raise ValueError("batch operations must contain 1..32 items")
    raw_operations = [operation.model_dump(mode="json") for operation in operations]
    read_only = all(operation.action in READ_ACTIONS for operation in operations)
    async with state.session_lock:
        session = state.session
        session.workspace.require_program(name)
        try:
            async with session.workspace.operation():
                call = await session.runner.run(
                    raw_operations, read_only=read_only, program_name=name
                )
        except WorkerRunError as exc:
            await _raise_worker_failure_locked(state, exc, "worker state was")
        return call.result


def _program_info(record: ProgramRecord, version: str) -> ProgramInfo:
    return ProgramInfo(
        program_name=record.program_name,
        source_path=record.source_path,
        source_sha256=record.source_sha256,
        imported_at=datetime.fromisoformat(record.imported_at),
        analyzed=record.analyzed,
        ghidra_version=version,
        language_id=record.language_id,
        processor=record.processor,
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
        session = state.session
        return HealthResult(
            package_version=__version__,
            python_version=current_python_version(),
            ghidra_path=str(state.installation.path),
            ghidra_version=state.installation.version,
            max_heap_mb=state.config.max_heap_mb,
            max_cpu=state.config.max_cpu,
            operation_timeout_seconds=state.config.operation_timeout_seconds,
            max_response_bytes=state.config.max_response_bytes,
            max_log_tail_bytes=state.config.max_log_tail_bytes,
            session_id=session.workspace.session_id,
            tracked_program_count=len(session.workspace.read_manifest().programs),
        )

    @mcp.tool()
    async def session_status(ctx: Context[ServerState, Any]) -> SessionStatus:
        """Return session ownership and worker lifecycle state."""

        state = _state(ctx)
        session = state.session
        manifest = session.workspace.read_manifest()
        return SessionStatus(
            session_id=manifest.session_id,
            root_created_at=datetime.fromisoformat(manifest.created_at),
            programs=list(manifest.programs),
            active_worker_pid=session.runner.active_worker_pid,
            last_worker_pid=session.runner.last_worker_pid,
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
        canonical_destination = str(Path(destination_path).expanduser().resolve())
        result = await _guard(
            _run_program(
                state,
                program_name,
                ProgramExportOperation(destination_path=canonical_destination, overwrite=overwrite),
                read_only=False,
            )
        )
        return ProgramExportResult.model_validate(result)

    @mcp.tool()
    async def program_save(
        program_name: str,
        destination_path: str,
        overwrite: bool = False,
        *,
        ctx: Context[ServerState, Any],
    ) -> ProgramSaveResult:
        """Write a lossless GZF snapshot of the program to a destination file.

        The snapshot includes analysis, types, symbols, comments, and patches.
        Re-import it later with program_import to restore full session state.
        Disabled when RYUUMONBUCHI_ALLOW_EXPORT is set to a false value.
        """

        state = _state(ctx)
        if not state.config.allow_export:
            raise _raise_tool("export_disabled", "program snapshot is disabled by configuration")
        result = await _guard(_program_save(state, program_name, destination_path, overwrite))
        return ProgramSaveResult.model_validate(result)

    @mcp.tool()
    async def program_list(ctx: Context[ServerState, Any]) -> ProgramListResult:
        """List imported programs from the authoritative manifest without a worker."""

        state = _state(ctx)
        async with state.session_lock:
            session = state.session
            manifest = session.workspace.read_manifest()
            return ProgramListResult(
                programs=[
                    _program_info(record, state.installation.version)
                    for record in manifest.programs.values()
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
        defined_only: bool = False,
        offset: int = 0,
        page_size: int = 100,
        *,
        ctx: Context[ServerState, Any],
    ) -> Page[StringMatch]:
        """Search bounded printable strings.

        Matches are maximal printable runs: overlapping substrings are
        deduplicated and only runs of at least min_length bytes are returned.
        When defined_only is set, only strings defined as data by analysis
        are returned.
        """

        result = await _guard(
            _run_program(
                _state(ctx),
                program_name,
                SearchStringsOperation(
                    query=query,
                    min_length=min_length,
                    defined_only=defined_only,
                    offset=offset,
                    page_size=page_size,
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
    async def analysis_list_analyzers(
        program_name: str,
        query: str | None = None,
        offset: int = 0,
        page_size: int = 100,
        *,
        ctx: Context[ServerState, Any],
    ) -> Page[AnalyzerSummary]:
        """List bounded analysis engine analyzers."""

        result = await _guard(
            _run_program(
                _state(ctx),
                program_name,
                AnalysisListAnalyzersOperation(query=query, offset=offset, page_size=page_size),
                read_only=True,
            )
        )
        return Page[AnalyzerSummary].model_validate(result)

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
    async def edit_set_data_type(
        program_name: str,
        address: str,
        data_type: str,
        length: int | None = None,
        *,
        ctx: Context[ServerState, Any],
    ) -> MutationResult:
        """Define one data type at an address."""

        result = await _guard(
            _run_program(
                _state(ctx),
                program_name,
                SetDataTypeOperation(address=address, data_type=data_type, length=length),
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
    async with state.session_lock:
        session = state.session
        return _program_info(session.workspace.require_program(name), state.installation.version)


async def _program_import(
    state: ServerState, source_path: str, program_name: str, analyze: bool
) -> ProgramImportResult:
    name = validate_program_name(program_name)
    source = Path(source_path).expanduser().resolve()
    source_hash = stream_sha256(source)
    raw = {
        "action": "program_import",
        "source_path": str(source),
        "program_name": name,
        "analyze": analyze,
    }
    async with state.session_lock:
        session = state.session
        session.workspace.ensure_program_absent(name)
        try:
            async with session.workspace.operation():
                call = await session.runner.run([raw], read_only=False, program_name=name)
                try:
                    worker_result = _WorkerImportResult.model_validate(call.result)
                    if worker_result.program_name != name:
                        raise ValueError("program_name mismatch")
                    if worker_result.analyzed is not analyze:
                        raise ValueError("analyzed mismatch")
                except (ValidationError, ValueError) as exc:
                    message = f"worker returned invalid program import result: {call.request_id}"
                    raise WorkerFailedError(
                        message, request_id=call.request_id, uncertain=True
                    ) from exc
                session.workspace.update_program(
                    ProgramRecord(
                        name,
                        str(source),
                        source_hash,
                        datetime.now(UTC).isoformat(),
                        analyze,
                        language_id=worker_result.language_id,
                        processor=worker_result.processor,
                    )
                )
        except WorkerRunError as exc:
            await _raise_worker_failure_locked(state, exc, "program import")
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
    raw = {
        "action": "program_import_bytes",
        "data": data,
        "program_name": name,
        "analyze": analyze,
    }
    async with state.session_lock:
        session = state.session
        session.workspace.ensure_program_absent(name)
        try:
            async with session.workspace.operation():
                call = await session.runner.run([raw], read_only=False, program_name=name)
                try:
                    worker_result = _WorkerImportResult.model_validate(call.result)
                    if worker_result.program_name != name:
                        raise ValueError("program_name mismatch")
                    if worker_result.analyzed is not analyze:
                        raise ValueError("analyzed mismatch")
                except (ValidationError, ValueError) as exc:
                    message = f"worker returned invalid program import result: {call.request_id}"
                    raise WorkerFailedError(
                        message, request_id=call.request_id, uncertain=True
                    ) from exc
                session.workspace.update_program(
                    ProgramRecord(
                        name,
                        f"bytes:{source_hash}",
                        source_hash,
                        datetime.now(UTC).isoformat(),
                        analyze,
                        language_id=worker_result.language_id,
                        processor=worker_result.processor,
                    )
                )
        except WorkerRunError as exc:
            await _raise_worker_failure_locked(state, exc, "program import")
    return ProgramImportResult(
        program_name=name,
        source_sha256=source_hash,
        ghidra_version=state.installation.version,
        analyzed=analyze,
    )


async def _program_save(
    state: ServerState, program_name: str, destination_path: str, overwrite: bool
) -> ProgramSaveResult:
    name = validate_program_name(program_name)
    canonical_destination = str(Path(destination_path).expanduser().resolve())
    raw = {
        "action": "program_save",
        "destination_path": canonical_destination,
        "overwrite": overwrite,
    }
    async with state.session_lock:
        session = state.session
        session.workspace.require_program(name)
        try:
            async with session.workspace.operation():
                call = await session.runner.run([raw], read_only=False, program_name=name)
                try:
                    worker_result = _WorkerSaveResult.model_validate(call.result)
                    if worker_result.program_name != name:
                        raise ValueError("program_name mismatch")
                    if worker_result.destination_path != canonical_destination:
                        raise ValueError("destination_path mismatch")
                except (ValidationError, ValueError) as exc:
                    message = f"worker returned invalid program save result: {call.request_id}"
                    raise WorkerFailedError(
                        message, request_id=call.request_id, uncertain=True
                    ) from exc
        except WorkerRunError as exc:
            await _raise_worker_failure_locked(state, exc, "program save")
    return ProgramSaveResult(
        program_name=worker_result.program_name,
        destination_path=worker_result.destination_path,
        bytes_written=worker_result.bytes_written,
        overwritten=worker_result.overwritten,
    )


async def _program_delete(state: ServerState, program_name: str) -> ProgramDeleteResult:
    name = validate_program_name(program_name)
    raw = {"action": "program_delete", "program_name": name}
    async with state.session_lock:
        session = state.session
        session.workspace.require_program(name)
        try:
            async with session.workspace.operation():
                call = await session.runner.run([raw], read_only=False, program_name=name)
                try:
                    worker_result = _WorkerDeleteResult.model_validate(call.result)
                    if worker_result.program_name != name:
                        raise ValueError("program_name mismatch")
                except (ValidationError, ValueError) as exc:
                    message = f"worker returned invalid program deletion result: {call.request_id}"
                    raise WorkerFailedError(
                        message, request_id=call.request_id, uncertain=True
                    ) from exc
                session.workspace.remove_program(name)
        except WorkerRunError as exc:
            await _raise_worker_failure_locked(state, exc, "program deletion")
    return ProgramDeleteResult(
        program_name=worker_result.program_name, deleted=worker_result.deleted
    )


def main(config: AppConfig) -> None:
    """Validate startup before opening MCP stdio and run one server instance."""

    validate_config(config)
    create_server(config).run("stdio")
