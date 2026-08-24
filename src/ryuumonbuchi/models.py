# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors

"""Pydantic wire models and bounded operation payloads."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

PageSize = Annotated[int, Field(ge=1, le=500)]
Offset = Annotated[int, Field(ge=0)]
TimeoutSeconds = Annotated[int, Field(ge=1, le=600)]
AnalysisTimeoutSeconds = Annotated[int, Field(ge=1, le=3600)]
Count = Annotated[int, Field(ge=1, le=100)]
GraphDepth = Annotated[int, Field(ge=1, le=5)]
GraphNodes = Annotated[int, Field(ge=1, le=500)]
ProgramName = Annotated[str, StringConstraints(min_length=1, max_length=128)]
HexPattern = Annotated[str, StringConstraints(min_length=1, max_length=4096)]
CommentText = Annotated[str, StringConstraints(max_length=1_048_576)]
MinStringLength = Annotated[int, Field(ge=1, le=4096)]


class WireModel(BaseModel):
    """Reject fields that are not part of the wire contract."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class Page[T](WireModel):
    """One bounded page of results."""

    items: list[T]
    offset: int = Field(ge=0)
    limit: int = Field(ge=1, le=500)
    has_more: bool


class HealthResult(WireModel):
    package_version: str
    python_version: str
    ghidra_path: str
    ghidra_version: str
    max_heap_mb: int
    max_cpu: int
    operation_timeout_seconds: int
    session_id: str
    tracked_program_count: int = Field(ge=0)
    worker_running: Literal[False] = False
    project_open: Literal[False] = False


class SessionStatus(WireModel):
    session_id: str
    root_created_at: datetime
    programs: list[str]
    active_worker_pid: int | None
    last_worker_pid: int | None
    project_open: Literal[False] = False


class SessionClearResult(WireModel):
    old_session_id: str
    new_session_id: str


class ProgramImportResult(WireModel):
    program_name: str
    source_sha256: str
    ghidra_version: str
    analyzed: bool


class ProgramDeleteResult(WireModel):
    program_name: str
    deleted: bool = True


class ProgramInfo(WireModel):
    program_name: str
    source_path: str
    source_sha256: str
    imported_at: datetime
    analyzed: bool
    ghidra_version: str


class ProgramListResult(WireModel):
    programs: list[ProgramInfo]


class FunctionSummary(WireModel):
    name: str
    address: str
    entry_address: str
    size: int | None = Field(default=None, ge=0)
    namespace: str | None = None


class FunctionDetail(FunctionSummary):
    signature: str | None = None
    calling_convention: str | None = None
    comment: str | None = None
    parameters: list[str] = Field(default_factory=list)
    return_type: str | None = None


class DecompileResult(WireModel):
    function_name: str
    address: str
    c_code: str
    truncated: bool = False


class Instruction(WireModel):
    address: str
    mnemonic: str
    operands: str
    text: str
    length: int = Field(ge=0)
    bytes_hex: str


class DefinedData(WireModel):
    address: str
    data_type: str
    value: str | None = None
    length: int = Field(ge=0)


class MemoryBlock(WireModel):
    name: str
    start: str
    end: str
    size: int = Field(ge=0)
    read: bool
    write: bool
    execute: bool


class MemoryReadResult(WireModel):
    address: str
    requested_length: int = Field(ge=1, le=65_536)
    actual_length: int = Field(ge=0, le=65_536)
    bytes_hex: str


class StringMatch(WireModel):
    address: str
    value: str
    length: int = Field(ge=0)


class SymbolMatch(WireModel):
    name: str
    address: str
    symbol_type: str
    namespace: str | None = None


class ImportSymbol(WireModel):
    name: str
    address: str | None = None
    library: str | None = None


class ExportSymbol(WireModel):
    name: str
    address: str
    ordinal: int | None = None


class Reference(WireModel):
    from_address: str
    to_address: str
    reference_type: str
    operand_index: int | None = None


class CallGraphNode(WireModel):
    address: str
    name: str
    depth: int = Field(ge=0, le=5)


class CallGraphEdge(WireModel):
    from_address: str
    to_address: str


class CallGraph(WireModel):
    root: CallGraphNode
    nodes: list[CallGraphNode]
    edges: list[CallGraphEdge]
    truncated: bool = False


class AddressMatch(WireModel):
    address: str


class AnalysisResult(WireModel):
    analyzed: bool
    log: str = ""


class AnalysisOptions(WireModel):
    values: dict[str, bool | int | float | str]


class MutationResult(WireModel):
    changed: bool
    program_name: str
    description: str


class BatchItem(WireModel):
    action: str
    result: Any


class BatchResult(WireModel):
    results: list[BatchItem]


class SelectorOperation(WireModel):
    """Operation base requiring exactly one function selector."""

    address: str | None = None
    name: str | None = None

    @model_validator(mode="after")
    def exactly_one_selector(self) -> Self:
        if (self.address is None) == (self.name is None):
            message = "exactly one of address or name is required"
            raise ValueError(message)
        return self


class FunctionListOperation(WireModel):
    action: Literal["function_list"] = "function_list"
    query: str | None = None
    offset: Offset = 0
    page_size: PageSize = 100


class FunctionGetOperation(SelectorOperation):
    action: Literal["function_get"] = "function_get"


class FunctionDecompileOperation(SelectorOperation):
    action: Literal["function_decompile"] = "function_decompile"
    timeout_seconds: TimeoutSeconds = 60


class ListingDisassembleOperation(WireModel):
    action: Literal["listing_disassemble"] = "listing_disassemble"
    address: str | None = None
    offset: Offset = 0
    page_size: PageSize = 100


class ListingDataOperation(WireModel):
    action: Literal["listing_data"] = "listing_data"
    offset: Offset = 0
    page_size: PageSize = 100


class MemoryBlocksOperation(WireModel):
    action: Literal["memory_blocks"] = "memory_blocks"


class MemoryReadOperation(WireModel):
    action: Literal["memory_read"] = "memory_read"
    address: str
    length: int = Field(ge=1, le=65_536)


class SearchStringsOperation(WireModel):
    action: Literal["search_strings"] = "search_strings"
    query: str | None = None
    min_length: MinStringLength = 4
    offset: Offset = 0
    page_size: PageSize = 100


class SearchSymbolsOperation(WireModel):
    action: Literal["search_symbols"] = "search_symbols"
    query: str
    offset: Offset = 0
    page_size: PageSize = 100


class ListImportsOperation(WireModel):
    action: Literal["list_imports"] = "list_imports"
    offset: Offset = 0
    page_size: PageSize = 100


class ListExportsOperation(WireModel):
    action: Literal["list_exports"] = "list_exports"
    offset: Offset = 0
    page_size: PageSize = 100


class ReferencesOperation(WireModel):
    action: Literal["references"] = "references"
    address: str
    direction: Literal["to", "from"] = "to"
    offset: Offset = 0
    page_size: PageSize = 100


class CallGraphOperation(SelectorOperation):
    action: Literal["call_graph"] = "call_graph"
    depth: GraphDepth = 2
    max_nodes: GraphNodes = 500


class ByteSearchOperation(WireModel):
    action: Literal["byte_search"] = "byte_search"
    pattern: HexPattern
    mask: str | None = None
    offset: Offset = 0
    page_size: PageSize = 100


class TextSearchOperation(WireModel):
    action: Literal["text_search"] = "text_search"
    query: str
    offset: Offset = 0
    page_size: PageSize = 100


class AnalysisRunOperation(WireModel):
    action: Literal["analysis_run"] = "analysis_run"
    timeout_seconds: AnalysisTimeoutSeconds = 900


class AnalysisOptionsGetOperation(WireModel):
    action: Literal["analysis_options_get"] = "analysis_options_get"


class AnalysisOptionsSetOperation(WireModel):
    action: Literal["analysis_options_set"] = "analysis_options_set"
    values: dict[str, bool | int | float | str]


class RenameFunctionOperation(SelectorOperation):
    action: Literal["edit_rename_function"] = "edit_rename_function"
    new_name: ProgramName


class RenameVariableOperation(WireModel):
    action: Literal["edit_rename_variable"] = "edit_rename_variable"
    function_address: str
    old_name: str
    new_name: ProgramName


class SetCommentOperation(WireModel):
    action: Literal["edit_set_comment"] = "edit_set_comment"
    address: str
    comment: CommentText
    comment_type: Literal["plate", "pre", "post", "eol", "repeatable"] = "plate"


class SetPrototypeOperation(SelectorOperation):
    action: Literal["edit_set_prototype"] = "edit_set_prototype"
    prototype: str = Field(min_length=1, max_length=65_536)


class PatchBytesOperation(WireModel):
    action: Literal["edit_patch_bytes"] = "edit_patch_bytes"
    address: str
    bytes_hex: str = Field(min_length=2, max_length=131_072)

    @field_validator("bytes_hex")
    @classmethod
    def validate_hex_payload(cls, value: str) -> str:
        if len(value) % 2 or any(char not in "0123456789abcdefABCDEF" for char in value):
            message = "bytes_hex must be an even-length hexadecimal string"
            raise ValueError(message)
        return value


class UndoOperation(WireModel):
    action: Literal["edit_undo"] = "edit_undo"
    count: Count = 1


class RedoOperation(WireModel):
    action: Literal["edit_redo"] = "edit_redo"
    count: Count = 1


class ProgramImportOperation(WireModel):
    action: Literal["program_import"] = "program_import"
    source_path: str
    program_name: ProgramName
    analyze: bool = True


class ProgramDeleteOperation(WireModel):
    action: Literal["program_delete"] = "program_delete"
    program_name: ProgramName


class ProgramExportOperation(WireModel):
    action: Literal["program_export"] = "program_export"
    destination_path: str = Field(min_length=1, max_length=4096)
    overwrite: bool = False


class ProgramExportResult(WireModel):
    program_name: str
    destination_path: str
    bytes_written: int = Field(ge=0)
    overwritten: bool = False


class ProgramImportBytesOperation(WireModel):
    action: Literal["program_import_bytes"] = "program_import_bytes"
    data: str = Field(min_length=1, max_length=100_663_296)
    program_name: ProgramName
    analyze: bool = True


type BatchOperation = Annotated[
    FunctionListOperation
    | FunctionGetOperation
    | FunctionDecompileOperation
    | ListingDisassembleOperation
    | ListingDataOperation
    | MemoryBlocksOperation
    | MemoryReadOperation
    | SearchStringsOperation
    | SearchSymbolsOperation
    | ListImportsOperation
    | ListExportsOperation
    | ReferencesOperation
    | CallGraphOperation
    | ByteSearchOperation
    | TextSearchOperation
    | AnalysisRunOperation
    | AnalysisOptionsGetOperation
    | AnalysisOptionsSetOperation
    | RenameFunctionOperation
    | RenameVariableOperation
    | SetCommentOperation
    | SetPrototypeOperation
    | PatchBytesOperation
    | ProgramExportOperation
    | UndoOperation
    | RedoOperation,
    Field(discriminator="action"),
]
type WorkerOperation = Annotated[
    BatchOperation | ProgramImportOperation | ProgramImportBytesOperation | ProgramDeleteOperation,
    Field(discriminator="action"),
]

READ_ACTIONS = frozenset(
    {
        "function_list",
        "function_get",
        "function_decompile",
        "listing_disassemble",
        "listing_data",
        "memory_blocks",
        "memory_read",
        "search_strings",
        "search_symbols",
        "list_imports",
        "list_exports",
        "references",
        "call_graph",
        "byte_search",
        "text_search",
        "analysis_options_get",
    }
)


class WorkerRequest(WireModel):
    """Versioned parent-to-worker request envelope."""

    schema_version: Literal[1] = Field(default=1, alias="schema")
    request_id: str
    session_id: str
    project_dir: str
    project_name: Literal["ryuumonbuchi"] = "ryuumonbuchi"
    ghidra_install_dir: str
    max_heap_mb: int
    max_cpu: int
    max_response_bytes: int
    read_only: bool
    program_name: ProgramName | None = None
    operations: list[dict[str, Any]] = Field(min_length=1, max_length=32)


class WorkerError(WireModel):
    code: str
    message: str


class WorkerSuccess(WireModel):
    schema_version: Literal[1] = Field(default=1, alias="schema")
    request_id: str
    ok: Literal[True] = True
    result: Any


class WorkerFailure(WireModel):
    schema_version: Literal[1] = Field(default=1, alias="schema")
    request_id: str
    ok: Literal[False] = False
    error: WorkerError


type WorkerResponse = WorkerSuccess | WorkerFailure
