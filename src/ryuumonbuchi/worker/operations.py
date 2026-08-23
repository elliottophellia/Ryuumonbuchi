# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors

"""Small, bounded operation functions over a request-local Ghidra Program."""

# pyright: reportMissingImports=false, reportMissingModuleSource=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportMissingTypeStubs=false, reportCallIssue=false

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, cast

import pyghidra

from ..models import (
    AddressMatch,
    AnalysisOptionsGetOperation,
    AnalysisOptionsSetOperation,
    AnalysisResult,
    AnalysisRunOperation,
    ByteSearchOperation,
    CallGraph,
    CallGraphEdge,
    CallGraphNode,
    CallGraphOperation,
    DecompileResult,
    DefinedData,
    FunctionDecompileOperation,
    FunctionDetail,
    FunctionGetOperation,
    FunctionListOperation,
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
    RedoOperation,
    Reference,
    ReferencesOperation,
    RenameFunctionOperation,
    RenameVariableOperation,
    SearchStringsOperation,
    SearchSymbolsOperation,
    SetCommentOperation,
    SetPrototypeOperation,
    StringMatch,
    SymbolMatch,
    TextSearchOperation,
    UndoOperation,
)
from .context import WorkerContext, WorkerGhidraError

MAX_DECOMPILE_BYTES = 1_048_576
MAX_TEXT_SCAN_BYTES = 64 * 1024 * 1024
MAX_PATTERN_TOKENS = 256
MAX_CSTRING_BYTES = 4096


class OperationError(WorkerGhidraError):
    """Raised for invalid or unsupported Ghidra operation input."""


def _canonical_address(address: Any) -> str:
    return str(address.toString()).upper().removeprefix("0X")


def _page[T](items: Iterable[T], offset: int, limit: int) -> Page[T]:
    bounded: list[T] = []
    skipped = 0
    has_more = False
    for item in items:
        if skipped < offset:
            skipped += 1
            continue
        if len(bounded) >= limit:
            has_more = True
            break
        bounded.append(item)
    return Page(items=bounded, offset=offset, limit=limit, has_more=has_more)


def _parse_address(program: Any, value: str) -> Any:
    candidates = program.parseAddress(value, True)
    if len(candidates) != 1:
        raise OperationError(f"address is invalid or ambiguous: {value}")
    return candidates[0]


def _function_name(function: Any) -> str:
    symbol = function.getSymbol()
    return str(symbol.getName(True)) if symbol is not None else str(function.getName())


def _resolve_function(program: Any, address: str | None, name: str | None) -> Any:
    if (address is None) == (name is None):
        raise OperationError("exactly one of address or name is required")
    manager = program.getFunctionManager()
    if address is not None:
        function = manager.getFunctionAt(_parse_address(program, address))
        if function is None:
            raise OperationError(f"function is not found at address: {address}")
        return function
    matches = [
        function for function in manager.getFunctions(True) if _function_name(function) == name
    ]
    if len(matches) != 1:
        raise OperationError(f"function name is missing or ambiguous: {name}")
    return matches[0]


def _function_summary(function: Any) -> dict[str, Any]:
    entry = function.getEntryPoint()
    body = function.getBody()
    parent = function.getParentNamespace()
    return {
        "name": _function_name(function),
        "address": _canonical_address(entry),
        "entry_address": _canonical_address(entry),
        "size": int(body.getNumAddresses()) if body is not None else None,
        "namespace": str(parent.getName(True)) if parent is not None else None,
    }


def function_list(
    program: Any, operation: FunctionListOperation, monitor: Any
) -> Page[dict[str, Any]]:
    query = operation.query.casefold() if operation.query else None

    def values() -> Iterable[dict[str, Any]]:
        for function in program.getFunctionManager().getFunctions(True):
            if monitor.isCancelled():
                break
            summary = _function_summary(function)
            if query is None or query in summary["name"].casefold():
                yield summary

    return _page(values(), operation.offset, operation.page_size)


def function_get(program: Any, operation: FunctionGetOperation, _: Any) -> FunctionDetail:
    function = _resolve_function(program, operation.address, operation.name)
    summary = _function_summary(function)
    signature = function.getSignature(False)
    return FunctionDetail(
        **summary,
        signature=str(function.getPrototypeString(False, True)),
        calling_convention=str(function.getCallingConventionName()),
        comment=function.getComment(),
        parameters=[str(parameter.getName()) for parameter in function.getParameters()],
        return_type=str(signature.getReturnType().getDisplayName()) if signature else None,
    )


def function_decompile(
    context: WorkerContext,
    program: Any,
    operation: FunctionDecompileOperation,
    monitor: Any,
) -> DecompileResult:
    function = _resolve_function(program, operation.address, operation.name)
    results = context.decompiler(program).decompileFunction(
        function, operation.timeout_seconds, monitor
    )
    if not results.decompileCompleted() or not results.isValid():
        raise OperationError(results.getErrorMessage() or "decompilation did not complete")
    code_bytes = str(results.getDecompiledFunction().getC()).encode("utf-8")
    truncated = len(code_bytes) > MAX_DECOMPILE_BYTES
    code = code_bytes[:MAX_DECOMPILE_BYTES].decode("utf-8", errors="ignore")
    return DecompileResult(
        function_name=_function_name(function),
        address=_canonical_address(function.getEntryPoint()),
        c_code=code,
        truncated=truncated,
    )


def listing_disassemble(
    program: Any, operation: ListingDisassembleOperation, monitor: Any
) -> Page[Instruction]:
    listing = program.getListing()
    iterator = (
        listing.getInstructions(_parse_address(program, operation.address), True)
        if operation.address is not None
        else listing.getInstructions(True)
    )

    def values() -> Iterable[Instruction]:
        for instruction in iterator:
            if monitor.isCancelled():
                break
            operands = " ".join(
                str(instruction.getDefaultOperandRepresentation(index))
                for index in range(int(instruction.getNumOperands()))
            )
            raw = bytes(int(value) & 0xFF for value in instruction.getBytes())
            yield Instruction(
                address=_canonical_address(instruction.getAddress()),
                mnemonic=str(instruction.getMnemonicString()),
                operands=operands,
                text=str(instruction),
                length=int(instruction.getLength()),
                bytes_hex=raw.hex(),
            )

    return _page(values(), operation.offset, operation.page_size)


def listing_data(program: Any, operation: ListingDataOperation, monitor: Any) -> Page[DefinedData]:
    iterator = program.getListing().getDefinedData(True)

    def values() -> Iterable[DefinedData]:
        for data in iterator:
            if monitor.isCancelled():
                break
            value = data.getValue()
            yield DefinedData(
                address=_canonical_address(data.getAddress()),
                data_type=str(data.getDataType().getDisplayName()),
                value=str(value) if value is not None else None,
                length=int(data.getLength()),
            )

    return _page(values(), operation.offset, operation.page_size)


def memory_blocks(program: Any, _: MemoryBlocksOperation, __: Any) -> list[MemoryBlock]:
    return [
        MemoryBlock(
            name=str(block.getName()),
            start=_canonical_address(block.getStart()),
            end=_canonical_address(block.getEnd()),
            size=int(block.getSize()),
            read=bool(block.isRead()),
            write=bool(block.isWrite()),
            execute=bool(block.isExecute()),
        )
        for block in program.getMemory().getBlocks()
    ]


def memory_read(program: Any, operation: MemoryReadOperation, _: Any) -> MemoryReadResult:
    import jpype  # type: ignore[import-not-found]

    address = _parse_address(program, operation.address)
    buffer = jpype.JArray(jpype.JByte)(operation.length)  # type: ignore[operator]
    actual = int(program.getMemory().getBytes(address, buffer))
    raw = bytes(int(value) & 0xFF for value in buffer[:actual])
    return MemoryReadResult(
        address=_canonical_address(address),
        requested_length=operation.length,
        actual_length=actual,
        bytes_hex=raw.hex(),
    )


def search_strings(
    program: Any, operation: SearchStringsOperation, monitor: Any
) -> Page[StringMatch]:
    query = operation.query.casefold() if operation.query else None

    def values() -> Iterable[StringMatch]:
        for block in program.getMemory().getBlocks():
            if monitor.isCancelled():
                break
            size = min(int(block.getSize()), MAX_CSTRING_BYTES)
            for offset in range(size):
                if monitor.isCancelled():
                    break
                address = block.getStart().add(offset)
                chars: list[int] = []
                for index in range(MAX_CSTRING_BYTES):
                    try:
                        value = int(program.getMemory().getByte(address.add(index))) & 0xFF
                    except Exception:
                        break
                    if value < 0x20 or value > 0x7E:
                        break
                    chars.append(value)
                if len(chars) >= 4:
                    text = bytes(chars).decode("ascii")
                    if query is None or query in text.casefold():
                        yield StringMatch(
                            address=_canonical_address(address), value=text, length=len(text)
                        )

    return _page(values(), operation.offset, operation.page_size)


def search_symbols(
    program: Any, operation: SearchSymbolsOperation, monitor: Any
) -> Page[SymbolMatch]:
    query = operation.query.casefold()

    def values() -> Iterable[SymbolMatch]:
        for symbol in program.getSymbolTable().getAllSymbols(False):
            if monitor.isCancelled():
                break
            name = str(symbol.getName(True))
            if query in name.casefold():
                parent = symbol.getParentNamespace()
                yield SymbolMatch(
                    name=name,
                    address=_canonical_address(symbol.getAddress()),
                    symbol_type=str(symbol.getSymbolType()),
                    namespace=str(parent.getName(True)) if parent is not None else None,
                )

    return _page(values(), operation.offset, operation.page_size)


def list_imports(program: Any, operation: ListImportsOperation, _: Any) -> Page[dict[str, Any]]:
    symbols = program.getSymbolTable().getExternalSymbols()
    return _page(
        (
            {
                "name": str(symbol.getName(True)),
                "address": _canonical_address(symbol.getAddress()),
                "library": str(symbol.getParentNamespace().getName(True)),
            }
            for symbol in symbols
        ),
        operation.offset,
        operation.page_size,
    )


def list_exports(program: Any, operation: ListExportsOperation, _: Any) -> Page[dict[str, Any]]:
    symbols = (
        symbol
        for symbol in program.getSymbolTable().getPrimarySymbolIterator(True)
        if symbol.isExternalEntryPoint()
    )
    return _page(
        (
            {
                "name": str(symbol.getName(True)),
                "address": _canonical_address(symbol.getAddress()),
                "ordinal": None,
            }
            for symbol in symbols
        ),
        operation.offset,
        operation.page_size,
    )


def references(program: Any, operation: ReferencesOperation, monitor: Any) -> Page[Reference]:
    address = _parse_address(program, operation.address)
    manager = program.getReferenceManager()
    iterator = (
        manager.getReferencesTo(address)
        if operation.direction == "to"
        else manager.getReferencesFrom(address)
    )

    def values() -> Iterable[Reference]:
        for reference in iterator:
            if monitor.isCancelled():
                break
            index = int(reference.getOperandIndex())
            yield Reference(
                from_address=_canonical_address(reference.getFromAddress()),
                to_address=_canonical_address(reference.getToAddress()),
                reference_type=str(reference.getReferenceType()),
                operand_index=index if index >= 0 else None,
            )

    return _page(values(), operation.offset, operation.page_size)


def call_graph(program: Any, operation: CallGraphOperation, monitor: Any) -> CallGraph:
    root_function = _resolve_function(program, operation.address, operation.name)
    root = CallGraphNode(
        address=_canonical_address(root_function.getEntryPoint()),
        name=_function_name(root_function),
        depth=0,
    )
    nodes = [root]
    edges: list[CallGraphEdge] = []
    queue: list[tuple[Any, int]] = [(root_function, 0)]
    seen = {root.address}
    while queue and len(nodes) < operation.max_nodes:
        function, depth = queue.pop(0)
        if depth >= operation.depth or monitor.isCancelled():
            continue
        for called in function.getCalledFunctions(monitor):
            target = _canonical_address(called.getEntryPoint())
            edges.append(
                CallGraphEdge(
                    from_address=_canonical_address(function.getEntryPoint()), to_address=target
                )
            )
            if target not in seen and len(nodes) < operation.max_nodes:
                seen.add(target)
                nodes.append(
                    CallGraphNode(address=target, name=_function_name(called), depth=depth + 1)
                )
                queue.append((called, depth + 1))
    return CallGraph(root=root, nodes=nodes, edges=edges, truncated=bool(queue))


def _pattern_arrays(operation: ByteSearchOperation) -> tuple[list[int], list[int]]:
    tokens = operation.pattern.split()
    if not 1 <= len(tokens) <= MAX_PATTERN_TOKENS:
        raise OperationError("byte pattern must contain 1..256 tokens")
    mask_tokens = operation.mask.split() if operation.mask else ["ff"] * len(tokens)
    if len(mask_tokens) != len(tokens):
        raise OperationError("byte pattern mask length must match pattern length")
    values: list[int] = []
    masks: list[int] = []
    for pattern_token, mask_token in zip(tokens, mask_tokens, strict=True):
        values.append(0 if pattern_token == "??" else int(pattern_token, 16))  # noqa: S105
        masks.append(0 if pattern_token == "??" else int(mask_token, 16))  # noqa: S105
    return values, masks


def byte_search(program: Any, operation: ByteSearchOperation, monitor: Any) -> Page[AddressMatch]:
    import jpype  # type: ignore[import-not-found]

    values, masks = _pattern_arrays(operation)
    pattern = jpype.JArray(jpype.JByte)(values)  # type: ignore[operator]
    mask = jpype.JArray(jpype.JByte)(masks)  # type: ignore[operator]
    address = program.getMinAddress()
    matches: list[AddressMatch] = []
    while address is not None and not monitor.isCancelled():
        found = program.getMemory().findBytes(address, pattern, mask, True, monitor)
        if found is None:
            break
        matches.append(AddressMatch(address=_canonical_address(found)))
        address = found.add(len(values))
    return _page(matches, operation.offset, operation.page_size)


def text_search(program: Any, operation: TextSearchOperation, monitor: Any) -> Page[AddressMatch]:
    needle = operation.query.encode("utf-8")
    matches: list[AddressMatch] = []
    scanned = 0
    for block in program.getMemory().getBlocks():
        if monitor.isCancelled() or scanned >= MAX_TEXT_SCAN_BYTES:
            break
        size = min(int(block.getSize()), MAX_TEXT_SCAN_BYTES - scanned)
        import jpype  # type: ignore[import-not-found]

        buffer = jpype.JArray(jpype.JByte)(size)  # type: ignore[operator]
        actual = int(block.getBytes(block.getStart(), buffer))
        raw = bytes(int(value) & 0xFF for value in buffer[:actual])
        scanned += actual
        start = 0
        while (index := raw.find(needle, start)) >= 0:
            matches.append(AddressMatch(address=_canonical_address(block.getStart().add(index))))
            start = index + 1
    return _page(matches, operation.offset, operation.page_size)


def analysis_run(program: Any, operation: AnalysisRunOperation, monitor: Any) -> AnalysisResult:
    log = pyghidra.analyze(program, monitor)
    return AnalysisResult(analyzed=not monitor.isCancelled(), log=str(log))


def analysis_options_get(program: Any, _: AnalysisOptionsGetOperation, __: Any) -> dict[str, Any]:
    options = pyghidra.analysis_properties(program)
    return {str(name): str(options.getValueAsString(name)) for name in options.getOptionNames()}


def analysis_options_set(
    program: Any, operation: AnalysisOptionsSetOperation, _: Any
) -> dict[str, Any]:
    options = pyghidra.analysis_properties(program)
    with pyghidra.transaction(program, "Set analysis options"):
        for name, value in operation.values.items():
            if not options.contains(name):
                raise OperationError(f"analysis option does not exist: {name}")
            if isinstance(value, bool):
                options.setBoolean(name, value)
            elif isinstance(value, int):
                options.setInt(name, value)
            elif isinstance(value, float):
                options.setDouble(name, value)
            else:
                options.setString(name, value)
    return {str(name): str(options.getValueAsString(name)) for name in options.getOptionNames()}


def rename_function(program: Any, operation: RenameFunctionOperation, _: Any) -> MutationResult:
    from ghidra.program.model.symbol import SourceType

    function = _resolve_function(program, operation.address, operation.name)
    with pyghidra.transaction(program, "Rename function"):
        function.setName(operation.new_name, SourceType.USER_DEFINED)
    return MutationResult(
        changed=True,
        program_name=str(program.getDomainFile().getName()),
        description="function renamed",
    )


def rename_variable(program: Any, operation: RenameVariableOperation, _: Any) -> MutationResult:
    from ghidra.program.model.symbol import SourceType

    function = _resolve_function(program, operation.function_address, None)
    variables = [
        variable
        for variable in function.getLocalVariables()
        if variable.getName() == operation.old_name
    ]
    if len(variables) != 1:
        raise OperationError(f"variable is missing or ambiguous: {operation.old_name}")
    with pyghidra.transaction(program, "Rename variable"):
        variables[0].setName(operation.new_name, SourceType.USER_DEFINED)
    return MutationResult(
        changed=True,
        program_name=str(program.getDomainFile().getName()),
        description="variable renamed",
    )


def set_comment(program: Any, operation: SetCommentOperation, _: Any) -> MutationResult:
    from ghidra.program.model.listing import CommentType

    address = _parse_address(program, operation.address)
    with pyghidra.transaction(program, "Set comment"):
        program.getListing().setComment(
            address, CommentType.valueOf(operation.comment_type.upper()), operation.comment
        )
    return MutationResult(
        changed=True, program_name=str(program.getDomainFile().getName()), description="comment set"
    )


def set_prototype(program: Any, operation: SetPrototypeOperation, _: Any) -> MutationResult:
    from ghidra.app.util.parser import FunctionSignatureParser  # type: ignore[import-not-found]
    from ghidra.program.model.symbol import SourceType  # type: ignore[import-not-found]

    function = _resolve_function(program, operation.address, operation.name)
    parser = FunctionSignatureParser(program.getDataTypeManager(), None)  # type: ignore[arg-type]
    signature = parser.parse(function.getSignature(False), operation.prototype)
    with pyghidra.transaction(program, "Set function prototype"):
        function.updateFunction(
            signature.getCallingConventionName(),
            None,
            signature.getArguments(),
            function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,  # type: ignore[attr-defined]
            True,
            SourceType.USER_DEFINED,
        )
    return MutationResult(
        changed=True,
        program_name=str(program.getDomainFile().getName()),
        description="prototype set",
    )


def patch_bytes(program: Any, operation: PatchBytesOperation, _: Any) -> MutationResult:
    import jpype  # type: ignore[import-not-found]
    from ghidra.program.disassemble import Disassembler

    address = _parse_address(program, operation.address)
    payload = bytes.fromhex(operation.bytes_hex)
    array = jpype.JArray(jpype.JByte)(payload)  # type: ignore[operator]
    end = address.add(len(payload) - 1)
    with pyghidra.transaction(program, "Patch bytes"):
        program.getListing().clearCodeUnits(address, end, True)
        program.getMemory().setBytes(address, array)
        disassembler = Disassembler.getDisassembler(  # type: ignore[arg-type]
            program, pyghidra.task_monitor(), cast(Any, None)
        )
        disassembler.disassemble(
            address, program.getAddressFactory().getAddressSet(address, end), False
        )
    return MutationResult(
        changed=True,
        program_name=str(program.getDomainFile().getName()),
        description="bytes patched",
    )


def undo(program: Any, operation: UndoOperation, _: Any) -> MutationResult:
    completed = 0
    for _ in range(operation.count):
        if not program.canUndo():
            break
        program.undo()
        completed += 1
    return MutationResult(
        changed=completed > 0,
        program_name=str(program.getDomainFile().getName()),
        description=f"undid {completed} operation(s)",
    )


def redo(program: Any, operation: RedoOperation, _: Any) -> MutationResult:
    completed = 0
    for _ in range(operation.count):
        if not program.canRedo():
            break
        program.redo()
        completed += 1
    return MutationResult(
        changed=completed > 0,
        program_name=str(program.getDomainFile().getName()),
        description=f"redid {completed} operation(s)",
    )
