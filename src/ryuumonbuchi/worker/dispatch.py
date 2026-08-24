# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors

"""Typed operation parsing and dispatch inside one Ghidra worker."""

from __future__ import annotations

from typing import Any, cast

from pydantic import TypeAdapter

from ..models import (
    AnalysisListAnalyzersOperation,
    AnalysisOptionsGetOperation,
    AnalysisOptionsSetOperation,
    AnalysisRunOperation,
    BatchOperation,
    ByteSearchOperation,
    CallGraphOperation,
    FunctionDecompileOperation,
    FunctionGetOperation,
    FunctionListOperation,
    ListExportsOperation,
    ListImportsOperation,
    ListingDataOperation,
    ListingDisassembleOperation,
    MemoryBlocksOperation,
    MemoryReadOperation,
    PatchBytesOperation,
    ProgramExportOperation,
    ReferencesOperation,
    RenameFunctionOperation,
    RenameVariableOperation,
    SearchStringsOperation,
    SearchSymbolsOperation,
    SetCommentOperation,
    SetDataTypeOperation,
    SetPrototypeOperation,
    TextSearchOperation,
    UndoOperation,
    WorkerOperation,
)
from . import operations
from .context import WorkerContext

_WORKER_ADAPTER: TypeAdapter[Any] = TypeAdapter(WorkerOperation)


def parse_operation(raw: dict[str, Any]) -> WorkerOperation:
    """Validate one discriminated operation without allowing arbitrary calls."""

    return cast(WorkerOperation, _WORKER_ADAPTER.validate_python(raw))


def execute_operation(
    context: WorkerContext,
    program: Any,
    operation: BatchOperation,
    monitor: Any,
) -> Any:
    """Dispatch a validated analysis or editing operation."""
    if isinstance(operation, FunctionListOperation):
        return operations.function_list(program, operation, monitor)
    if isinstance(operation, FunctionGetOperation):
        return operations.function_get(program, operation, monitor)
    if isinstance(operation, FunctionDecompileOperation):
        return operations.function_decompile(context, program, operation, monitor)
    if isinstance(operation, ListingDisassembleOperation):
        return operations.listing_disassemble(program, operation, monitor)
    if isinstance(operation, ListingDataOperation):
        return operations.listing_data(program, operation, monitor)
    if isinstance(operation, MemoryBlocksOperation):
        return operations.memory_blocks(program, operation, monitor)
    if isinstance(operation, MemoryReadOperation):
        return operations.memory_read(program, operation, monitor)
    if isinstance(operation, SearchStringsOperation):
        return operations.search_strings(program, operation, monitor)
    if isinstance(operation, SearchSymbolsOperation):
        return operations.search_symbols(program, operation, monitor)
    if isinstance(operation, ListImportsOperation):
        return operations.list_imports(program, operation, monitor)
    if isinstance(operation, ListExportsOperation):
        return operations.list_exports(program, operation, monitor)
    if isinstance(operation, ReferencesOperation):
        return operations.references(program, operation, monitor)
    if isinstance(operation, CallGraphOperation):
        return operations.call_graph(program, operation, monitor)
    if isinstance(operation, ByteSearchOperation):
        return operations.byte_search(program, operation, monitor)
    if isinstance(operation, TextSearchOperation):
        return operations.text_search(program, operation, monitor)
    if isinstance(operation, AnalysisRunOperation):
        return operations.analysis_run(program, operation, monitor)
    if isinstance(operation, AnalysisOptionsGetOperation):
        return operations.analysis_options_get(program, operation, monitor)
    if isinstance(operation, AnalysisListAnalyzersOperation):
        return operations.analysis_list_analyzers(program, operation, monitor)
    if isinstance(operation, AnalysisOptionsSetOperation):
        return operations.analysis_options_set(program, operation, monitor)
    if isinstance(operation, RenameFunctionOperation):
        return operations.rename_function(program, operation, monitor)
    if isinstance(operation, RenameVariableOperation):
        return operations.rename_variable(program, operation, monitor)
    if isinstance(operation, SetCommentOperation):
        return operations.set_comment(program, operation, monitor)
    if isinstance(operation, SetDataTypeOperation):
        return operations.set_data_type(program, operation, monitor)
    if isinstance(operation, SetPrototypeOperation):
        return operations.set_prototype(program, operation, monitor)
    if isinstance(operation, PatchBytesOperation):
        return operations.patch_bytes(program, operation, monitor)
    if isinstance(operation, ProgramExportOperation):
        return operations.program_export(program, operation, monitor)
    if isinstance(operation, UndoOperation):
        return operations.undo(program, operation, monitor)
    return operations.redo(program, operation, monitor)
