# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors
# pyright: reportPrivateUsage=false, reportUnknownParameterType=false, reportMissingParameterType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportAttributeAccessIssue=false, reportAssignmentType=false, reportArgumentType=false, reportUnknownLambdaType=false

from __future__ import annotations

import sys
import types
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from ryuumonbuchi.models import *  # noqa: F403, F405
from ryuumonbuchi.worker import operations as ops


class _JArrayFactory:
    def __call__(self, _type, _value=None):
        if _value is None:
            return lambda value: [0] * value if isinstance(value, int) else list(value)
        if isinstance(_value, int):
            return [0] * _value
        return list(_value)


class FakeAnalyzer:
    def __init__(self, name="Demangler", class_name="ghidra.app.analyzers.DemanglerAnalyzer"):
        self.name = name
        self.class_name = class_name

    def getName(self):
        return self.name

    def getClass(self):
        return SimpleNamespace(getName=lambda: self.class_name)

    def getAnalysisType(self):
        return "ONE_SHOT"

    def getDefaultEnablement(self, program):
        return True

    def canAnalyze(self, program):
        return True

    def isPrototype(self):
        return False


_FAKE_ANALYZERS = [
    FakeAnalyzer(),
    FakeAnalyzer("ASCII Strings", "ghidra.app.analyzers.StringsAnalyzer"),
]


def install_ghidra_modules(monkeypatch):
    jpype = types.ModuleType("jpype")
    jpype.JByte = int
    jpype.JArray = _JArrayFactory()
    monkeypatch.setitem(sys.modules, "jpype", jpype)
    modules = {
        "ghidra": types.ModuleType("ghidra"),
        "ghidra.program": types.ModuleType("ghidra.program"),
        "ghidra.program.model": types.ModuleType("ghidra.program.model"),
        "ghidra.program.model.symbol": types.ModuleType("ghidra.program.model.symbol"),
        "ghidra.program.model.listing": types.ModuleType("ghidra.program.model.listing"),
        "ghidra.program.model.data": types.ModuleType("ghidra.program.model.data"),
        "ghidra.app": types.ModuleType("ghidra.app"),
        "ghidra.app.util": types.ModuleType("ghidra.app.util"),
        "ghidra.app.util.parser": types.ModuleType("ghidra.app.util.parser"),
        "ghidra.app.services": types.ModuleType("ghidra.app.services"),
        "ghidra.program.disassemble": types.ModuleType("ghidra.program.disassemble"),
        "ghidra.app.script": types.ModuleType("ghidra.app.script"),
        "ghidra.program.util": types.ModuleType("ghidra.program.util"),
        "ghidra.util": types.ModuleType("ghidra.util"),
        "ghidra.util.classfinder": types.ModuleType("ghidra.util.classfinder"),
        "ghidra.util.task": types.ModuleType("ghidra.util.task"),
        "ghidra.pyghidra": types.ModuleType("ghidra.pyghidra"),
        "ghidra.app.plugin": types.ModuleType("ghidra.app.plugin"),
        "ghidra.app.plugin.core": types.ModuleType("ghidra.app.plugin.core"),
        "ghidra.app.plugin.core.analysis": types.ModuleType("ghidra.app.plugin.core.analysis"),
    }
    modules["ghidra.app.services"].Analyzer = SimpleNamespace(class_="ghidra.app.services.Analyzer")
    modules["ghidra.util.classfinder"].ClassSearcher = SimpleNamespace(
        getInstances=lambda cls: _FAKE_ANALYZERS
    )
    modules["ghidra.app.script"].GhidraScriptUtil = SimpleNamespace(
        acquireBundleHostReference=lambda: None, releaseBundleHostReference=lambda: None
    )
    modules["ghidra.program.model.data"].CategoryPath = lambda path: path
    modules["ghidra.program.model.data"].BuiltInDataTypeManager = SimpleNamespace(
        getDataTypeManager=lambda: SimpleNamespace(
            getDataType=lambda path, name: name if name == "string" else None
        )
    )
    modules["ghidra.program.util"].GhidraProgramUtilities = SimpleNamespace(
        markProgramAnalyzed=lambda program: None
    )
    modules["ghidra.util.task"].TaskMonitor = SimpleNamespace(DUMMY=SimpleNamespace())
    modules["ghidra.pyghidra"].PyGhidraTaskMonitor = lambda *args: SimpleNamespace()
    modules["ghidra.program.model.symbol"].SourceType = SimpleNamespace(USER_DEFINED="user")
    modules["ghidra.program.model.listing"].CommentType = SimpleNamespace(valueOf=lambda name: name)
    modules["ghidra.app.util.parser"].FunctionSignatureParser = lambda *args: SimpleNamespace(
        parse=lambda *args: Signature()
    )
    modules["ghidra.program.disassemble"].Disassembler = SimpleNamespace(
        getDisassembler=lambda *args: SimpleNamespace(disassemble=lambda *args: None)
    )
    modules["ghidra.app.plugin.core.analysis"].AutoAnalysisManager = SimpleNamespace(
        getAnalysisManager=lambda program: SimpleNamespace(
            initializeOptions=lambda: None,
            reAnalyzeAll=lambda arg: None,
            addListener=lambda listener: None,
            getMessageLog=lambda: SimpleNamespace(toString=lambda: ""),
            startAnalysis=lambda monitor, times: None,
        )
    )
    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)


class Addr:
    def __init__(self, value: int):
        self.value = value

    def toString(self):
        return f"{self.value:04X}"

    def add(self, amount: int):
        return Addr(self.value + amount)

    def subtract(self, amount: int):
        return Addr(self.value - amount)

    def __hash__(self):
        return hash(self.value)

    def __eq__(self, other):
        return isinstance(other, Addr) and self.value == other.value


class Namespace:
    def __init__(self, name="Global"):
        self._name = name

    def getName(self, include=True):
        return self._name


class Symbol:
    def __init__(self, name="main", address=None, parent=None, external=False):
        self._name = name
        self._address = address or Addr(0x1000)
        self._parent = parent
        self._external = external

    def getName(self, include=True):
        return self._name if include else self._name.rsplit("::", 1)[-1]

    def getAddress(self):
        return self._address

    def getParentNamespace(self):
        return self._parent

    def getSymbolType(self):
        return "FUNCTION"

    def isExternalEntryPoint(self):
        return self._external


class Body:
    def __init__(self, count=1):
        self.count = count

    def getNumAddresses(self):
        return self.count


class DataType:
    def getDisplayName(self):
        return "int"


class Signature:
    def getReturnType(self):
        return DataType()

    def getCallingConventionName(self):
        return "default"

    def getArguments(self):
        return []


class Variable:
    def __init__(self, name):
        self.name = name

    def getName(self):
        return self.name

    def setName(self, name, source):
        self.name = name


class Fn:
    class FunctionUpdateType:
        DYNAMIC_STORAGE_FORMAL_PARAMS = "dynamic"

    def __init__(self, name="main", address=0x1000, parent=None, body=True, symbol=True):
        self.address = Addr(address)
        self.name = name
        self.parent = parent
        self.body = Body(4) if body else None
        self.symbol = Symbol(name, self.address, parent) if symbol else None
        self.params = [Variable("arg")]
        self.locals = [Variable("local")]
        self.called = []
        self.comment = None
        self.updated = False

    def getEntryPoint(self):
        return self.address

    def getBody(self):
        return self.body

    def getParentNamespace(self):
        return self.parent

    def getSymbol(self):
        return self.symbol

    def getName(self):
        return self.name

    def getSignature(self, formal=False):
        return Signature()

    def getPrototypeString(self, formal=False, convention=True):
        return f"int {self.name}(void)"

    def getCallingConventionName(self):
        return "default"

    def getComment(self):
        return self.comment

    def getParameters(self):
        return self.params

    def getLocalVariables(self):
        return self.locals

    def getCalledFunctions(self, monitor):
        return self.called

    def setName(self, name, source):
        self.name = name

    def updateFunction(self, *args):
        self.updated = True


class FunctionManager:
    def __init__(self, functions):
        self.functions = functions

    def getFunctions(self, forward=True):
        return iter(self.functions)

    def getFunctionAt(self, address):
        return next((f for f in self.functions if f.address == address), None)


class Instruction:
    def __init__(self, address=0x1000):
        self.address = Addr(address)

    def getAddress(self):
        return self.address

    def getLength(self):
        return 1

    def getBytes(self):
        return [0x90]

    def getMnemonicString(self):
        return "NOP"

    def getNumOperands(self):
        return 1

    def getDefaultOperandRepresentation(self, index):
        return "RAX"

    def __str__(self):
        return "NOP RAX"


class Data:
    def __init__(self, address=0x1000, value="x"):
        self.address = Addr(address)
        self.value = value

    def getAddress(self):
        return self.address

    def getDataType(self):
        return DataType()

    def getValue(self):
        return self.value

    def getLength(self):
        return 1


class Listing:
    def __init__(self):
        self.instructions = [Instruction(), Instruction(0x1001)]
        self.data = [Data()]

    def getInstructions(self, *args):
        return iter(self.instructions)

    def getDefinedData(self, *args):
        return iter(self.data)

    def setComment(self, *args):
        self.comment = args

    def clearCodeUnits(self, *args):
        self.cleared = args

    def createData(self, *args):
        self.created = args
        return Data()


class Block:
    def __init__(self, start=0x1000, payload=b"hello world\x00"):
        self.start = Addr(start)
        self.payload = payload
        self.source_infos: list[object] = []

    def getName(self):
        return ".text"

    def isInitialized(self):
        return True

    def getSourceInfos(self):
        return self.source_infos

    def getStart(self):
        return self.start

    def getEnd(self):
        return self.start.add(len(self.payload) - 1)

    def getSize(self):
        return len(self.payload)

    def isRead(self):
        return True

    def isWrite(self):
        return False

    def isExecute(self):
        return True

    def getBytes(self, address, target):
        for index, value in enumerate(self.payload[: len(target)]):
            target[index] = value
        return min(len(target), len(self.payload))


class Memory:
    def __init__(self):
        self.blocks = [Block()]

    def getBlocks(self):
        return self.blocks

    def getBytes(self, address, target):
        return self.blocks[0].getBytes(address, target)

    def getByte(self, address):
        return self.blocks[0].payload[address.value - 0x1000]

    def findBytes(self, address, pattern, mask, forward, monitor):
        return Addr(0x1000) if address.value <= 0x1000 else None

    def setBytes(self, address, array):
        self.written = (address, array)


class FakeFileBytes:
    def __init__(self, filename):
        self.filename = filename

    def getFilename(self):
        return self.filename


class MappedRange:
    def __init__(self, start=0x1000, length=14):
        self.start = Addr(start)
        self.length = length

    def getMinAddress(self):
        return self.start

    def getLength(self):
        return self.length


class SourceInfo:
    def __init__(self, filename="source.bin", offset=0, length=14, start=0x1000):
        self.file_bytes = FakeFileBytes(filename)
        self.offset = offset
        self.length = length
        self.mapped = MappedRange(start=start, length=length)

    def getFileBytes(self):
        return self.file_bytes

    def getMappedRange(self):
        return self.mapped

    def getByteMappingScheme(self):
        return None

    def getMinAddress(self):
        return self.mapped.getMinAddress()

    def getLength(self):
        return self.mapped.getLength()

    def getFileBytesOffset(self, address):
        return self.offset


class SymbolTable:
    def __init__(self):
        self.symbols = [
            Symbol("main", Addr(0x1000), Namespace("Global")),
            Symbol("lib::puts", Addr(0x2000), Namespace("lib"), True),
        ]

    def getAllSymbols(self, dynamic=False):
        return iter(self.symbols)

    def getExternalSymbols(self):
        return iter([self.symbols[1]])

    def getPrimarySymbolIterator(self, forward=True):
        return iter(self.symbols)


class Reference:
    def __init__(self, source=0x1000, target=0x2000, index=0):
        self.source = Addr(source)
        self.target = Addr(target)
        self.index = index

    def getFromAddress(self):
        return self.source

    def getToAddress(self):
        return self.target

    def getReferenceType(self):
        return "CALL"

    def getOperandIndex(self):
        return self.index


class ReferenceManager:
    def getReferencesTo(self, address):
        return iter([Reference(index=0), Reference(index=-1)])

    def getReferencesFrom(self, address):
        return iter([Reference(index=0)])


class AddressFactory:
    def getAddressSet(self, start, end):
        return SimpleNamespace(start=start, end=end)


class Program:
    def __init__(self):
        self.functions = [Fn(), Fn("other", 0x1100)]
        self.fm = FunctionManager(self.functions)
        self.listing = Listing()
        self.memory = Memory()
        self.symbols = SymbolTable()
        self.references = ReferenceManager()
        self.domain = SimpleNamespace(getName=lambda: "hello")
        self.executable_path = ""
        self.undoes = 0
        self.redoes = 0

    def getExecutablePath(self):
        return self.executable_path

    def parseAddress(self, value, case=True):
        return [] if value == "bad" else [Addr(int(value, 16))]

    def getFunctionManager(self):
        return self.fm

    def getListing(self):
        return self.listing

    def getMemory(self):
        return self.memory

    def getSymbolTable(self):
        return self.symbols

    def getReferenceManager(self):
        return self.references

    def getDataTypeManager(self):
        return SimpleNamespace()

    def getMinAddress(self):
        return Addr(0x1000)

    def getAddressFactory(self):
        return AddressFactory()

    def getDomainFile(self):
        return self.domain

    def getName(self):
        return "wrong-project-name"

    def startTransaction(self, description):
        return 1

    def endTransaction(self, identifier, commit):
        return True

    def save(self, comment, monitor):
        self.saved = comment

    def canUndo(self):
        return self.undoes < 1

    def canRedo(self):
        return self.redoes < 1

    def undo(self):
        self.undoes += 1

    def redo(self):
        self.redoes += 1


class Monitor:
    def __init__(self, cancelled=False):
        self.cancelled = cancelled

    def isCancelled(self):
        return self.cancelled

    def cancel(self):
        self.cancelled = True


class Decompiler:
    def __init__(self, complete=True, code="return 0;", valid=True):
        self.complete = complete
        self.code = code
        self.valid = valid

    def decompileFunction(self, *args):
        return SimpleNamespace(
            decompileCompleted=lambda: self.complete,
            isValid=lambda: self.valid,
            getErrorMessage=lambda: "bad",
            getDecompiledFunction=lambda: SimpleNamespace(getC=lambda: self.code),
        )


class Context:
    def __init__(self, decompiler=None):
        self._decompiler = decompiler or Decompiler()

    def decompiler(self, program):
        return self._decompiler


def fake_transaction(monkeypatch):
    @contextmanager
    def transaction(program, description):
        yield 1

    monkeypatch.setattr(ops.pyghidra, "transaction", transaction)


def test_operation_reads_and_selectors(monkeypatch):
    install_ghidra_modules(monkeypatch)
    program = Program()
    monitor = Monitor()
    context = Context()
    assert ops._canonical_address(Addr(0x10)) == "0010"
    assert ops.function_list(program, FunctionListOperation(), monitor).items
    assert ops.function_list(program, FunctionListOperation(query="main"), monitor).items
    assert ops.function_get(program, FunctionGetOperation(name="main"), monitor).name == "main"
    assert (
        ops.function_get(program, FunctionGetOperation(address="1000"), monitor).address == "1000"
    )
    assert ops.listing_disassemble(program, ListingDisassembleOperation(), monitor).items
    assert ops.listing_data(program, ListingDataOperation(), monitor).items
    assert ops.memory_blocks(program, MemoryBlocksOperation(), monitor)
    assert (
        ops.memory_read(program, MemoryReadOperation(address="1000", length=1), monitor).bytes_hex
        == "68"
    )
    assert ops.search_strings(program, SearchStringsOperation(query="hello"), monitor).items
    assert ops.search_symbols(program, SearchSymbolsOperation(query="main"), monitor).items
    assert ops.list_imports(program, ListImportsOperation(), monitor).items
    assert ops.list_exports(program, ListExportsOperation(), monitor).items
    assert ops.references(program, ReferencesOperation(address="1000"), monitor).items
    assert ops.references(
        program, ReferencesOperation(address="1000", direction="from"), monitor
    ).items
    assert ops.call_graph(program, CallGraphOperation(name="main"), monitor).root.name == "main"
    assert ops.byte_search(program, ByteSearchOperation(pattern="68"), monitor).items
    assert ops.text_search(program, TextSearchOperation(query="hello"), monitor).items
    assert ops.analysis_run(program, AnalysisRunOperation(), monitor).analyzed in {True, False}
    assert ops.function_decompile(
        context, program, FunctionDecompileOperation(name="main"), monitor
    ).c_code


def test_operation_error_and_branch_paths(monkeypatch):
    program = Program()
    monitor = Monitor()
    fake_transaction(monkeypatch)
    install_ghidra_modules(monkeypatch)
    with pytest.raises(ops.OperationError):
        ops._parse_address(program, "bad")
    with pytest.raises(ops.OperationError):
        ops._resolve_function(program, None, None)
    with pytest.raises(ops.OperationError):
        ops._resolve_function(program, None, "missing")
    program.fm.functions.append(Fn("main", 0x1200))
    with pytest.raises(ops.OperationError):
        ops._resolve_function(program, None, "main")
    with pytest.raises(ops.OperationError):
        ops._resolve_function(program, "9999", None)
    assert ops.rename_function(
        program, RenameFunctionOperation(name="other", new_name="renamed"), monitor
    ).changed
    assert ops.rename_variable(
        program,
        RenameVariableOperation(function_address="1000", old_name="local", new_name="new"),
        monitor,
    ).changed
    assert ops.set_comment(
        program, SetCommentOperation(address="1000", comment="comment"), monitor
    ).changed
    assert ops.set_prototype(
        program, SetPrototypeOperation(name="other", prototype="int other(void)"), monitor
    ).changed
    assert ops.patch_bytes(
        program, PatchBytesOperation(address="1000", bytes_hex="90"), monitor
    ).changed
    assert ops.undo(program, UndoOperation(count=1), monitor).changed
    assert ops.redo(program, RedoOperation(count=1), monitor).changed
    with pytest.raises(ops.OperationError):
        ops._pattern_arrays(SimpleNamespace(pattern="", mask=None))
    with pytest.raises(ops.OperationError):
        ops._pattern_arrays(SimpleNamespace(pattern="90", mask="ff ff"))
    failed = Context(Decompiler(complete=False))
    with pytest.raises(ops.OperationError):
        ops.function_decompile(failed, program, FunctionDecompileOperation(name="renamed"), monitor)


def test_operation_cancellation_graph_options_and_noop_edges(monkeypatch):
    install_ghidra_modules(monkeypatch)
    fake_transaction(monkeypatch)
    program = Program()

    class CancelAfter:
        def __init__(self, after=1):
            self.calls = 0
            self.after = after

        def isCancelled(self):
            self.calls += 1
            return self.calls > self.after

    cancelled = Monitor(cancelled=True)
    assert not ops.function_list(program, FunctionListOperation(), cancelled).items
    assert not ops.listing_disassemble(program, ListingDisassembleOperation(), cancelled).items
    assert not ops.listing_data(program, ListingDataOperation(), cancelled).items
    assert not ops.search_symbols(program, SearchSymbolsOperation(query="main"), cancelled).items
    assert not ops.references(program, ReferencesOperation(address="1000"), cancelled).items
    assert not ops.text_search(program, TextSearchOperation(query="hello"), cancelled).items
    assert not ops.byte_search(program, ByteSearchOperation(pattern="68"), cancelled).items

    after_one = CancelAfter()
    ops.function_list(program, FunctionListOperation(), after_one)
    after_one = CancelAfter()
    ops.listing_disassemble(program, ListingDisassembleOperation(), after_one)
    after_one = CancelAfter()
    ops.listing_data(program, ListingDataOperation(), after_one)
    after_one = CancelAfter()
    ops.search_symbols(program, SearchSymbolsOperation(query="main"), after_one)
    after_one = CancelAfter()
    ops.references(program, ReferencesOperation(address="1000"), after_one)
    after_one = CancelAfter()
    ops.search_strings(program, SearchStringsOperation(), after_one)

    failed = Context(Decompiler(complete=True, valid=False))
    with pytest.raises(ops.OperationError):
        ops.function_decompile(failed, program, FunctionDecompileOperation(name="main"), Monitor())

    child = Fn("child", 0x1200)
    grandchild = Fn("grandchild", 0x1300)
    program.functions[0].called = [child, program.functions[0]]
    child.called = [grandchild]
    graph = ops.call_graph(
        program, CallGraphOperation(name="main", depth=2, max_nodes=10), Monitor()
    )
    assert {node.name for node in graph.nodes} == {"main", "child", "grandchild"}
    limited = ops.call_graph(
        program, CallGraphOperation(name="main", depth=2, max_nodes=1), Monitor()
    )
    assert limited.nodes == [limited.root]
    assert not ops.call_graph(
        program, CallGraphOperation(name="main", depth=2, max_nodes=10), Monitor(cancelled=True)
    ).edges

    class Options:
        def __init__(self):
            self.values = {"flag": "false", "count": "0", "ratio": "0.0", "text": ""}

        def getOptionNames(self):
            return self.values.keys()

        def getValueAsString(self, name):
            return self.values[name]

        def contains(self, name):
            return name in self.values

        def setBoolean(self, name, value):
            self.values[name] = str(value)

        def setInt(self, name, value):
            self.values[name] = str(value)

        def setDouble(self, name, value):
            self.values[name] = str(value)

        def setString(self, name, value):
            self.values[name] = value

    options = Options()
    monkeypatch.setattr(ops.pyghidra, "analysis_properties", lambda program: options)
    assert ops.analysis_options_get(program, AnalysisOptionsGetOperation(), Monitor())
    updated = ops.analysis_options_set(
        program,
        AnalysisOptionsSetOperation(
            values={"flag": True, "count": 3, "ratio": 1.5, "text": "value"}
        ),
        Monitor(),
    )
    assert updated["text"] == "value"
    with pytest.raises(ops.OperationError, match="does not exist"):
        ops.analysis_options_set(
            program, AnalysisOptionsSetOperation(values={"missing": True}), Monitor()
        )
    assert ops.rename_variable(
        program,
        RenameVariableOperation(function_address="1000", old_name="local", new_name="new"),
        Monitor(),
    ).changed
    program.functions[0].locals = []
    with pytest.raises(ops.OperationError, match="missing or ambiguous"):
        ops.rename_variable(
            program,
            RenameVariableOperation(function_address="1000", old_name="local", new_name="new"),
            Monitor(),
        )
    program.undoes = 1
    program.redoes = 1
    assert not ops.undo(program, UndoOperation(count=1), Monitor()).changed
    assert not ops.redo(program, RedoOperation(count=1), Monitor()).changed


def test_search_strings_exception_and_full_scan_edges(monkeypatch):
    install_ghidra_modules(monkeypatch)
    program = Program()
    assert not ops.search_strings(program, SearchStringsOperation(), Monitor(cancelled=True)).items

    class RaisingMemory(Memory):
        def getByte(self, address):
            raise IndexError(address.value)

    program.memory = RaisingMemory()
    assert not ops.search_strings(program, SearchStringsOperation(), Monitor()).items

    class FullMemory(Memory):
        def getByte(self, address):
            return 65

    program.memory = FullMemory()
    result = ops.search_strings(program, SearchStringsOperation(), Monitor())
    assert result.items and result.items[0].length == 4096


def test_search_strings_deduplicates_overlapping_runs(monkeypatch):
    install_ghidra_modules(monkeypatch)
    program = Program()
    program.memory = Memory()
    program.memory.blocks = [Block(payload=b"alpha beta!\x00\x00gap")]
    result = ops.search_strings(program, SearchStringsOperation(), Monitor())
    assert [item.value for item in result.items] == ["alpha beta!"]


def test_search_strings_min_length_filters_short_runs(monkeypatch):
    install_ghidra_modules(monkeypatch)
    program = Program()
    program.memory = Memory()
    program.memory.blocks = [Block(payload=b"alpha beta!\x00\x00gap")]
    result = ops.search_strings(program, SearchStringsOperation(min_length=4), Monitor())
    assert [item.value for item in result.items] == ["alpha beta!"]
    tiny = ops.search_strings(program, SearchStringsOperation(min_length=20), Monitor())
    assert not tiny.items
    gap = ops.search_strings(program, SearchStringsOperation(min_length=3), Monitor())
    assert [item.value for item in gap.items] == ["alpha beta!", "gap"]


def _export_program(tmp_path, *, patched=b"XXXX_BBBB_CCCC", original=b"AAAA_BBBB_CCCC"):
    source = tmp_path / "source.bin"
    source.write_bytes(original)
    program = Program()
    program.executable_path = str(source)
    block = Block(payload=patched)
    block.source_infos = [SourceInfo(filename="source.bin", offset=0, length=len(original))]
    program.memory = Memory()
    program.memory.blocks = [block]
    return program


def test_program_export_overlays_patched_blocks(tmp_path, monkeypatch):
    install_ghidra_modules(monkeypatch)
    program = _export_program(tmp_path)
    destination = tmp_path / "out.bin"
    result = ops.program_export(
        program, ProgramExportOperation(destination_path=str(destination)), Monitor()
    )
    assert result.bytes_written == 14
    assert not result.overwritten
    assert destination.read_bytes() == b"XXXX_BBBB_CCCC"


def test_program_export_requires_overwrite_for_existing(tmp_path, monkeypatch):
    install_ghidra_modules(monkeypatch)
    program = _export_program(tmp_path)
    destination = tmp_path / "out.bin"
    destination.write_bytes(b"existing")
    with pytest.raises(ops.OperationError, match="destination already exists"):
        ops.program_export(
            program, ProgramExportOperation(destination_path=str(destination)), Monitor()
        )
    result = ops.program_export(
        program,
        ProgramExportOperation(destination_path=str(destination), overwrite=True),
        Monitor(),
    )
    assert result.overwritten
    assert destination.read_bytes() == b"XXXX_BBBB_CCCC"


def test_program_export_requires_original_file(tmp_path, monkeypatch):
    install_ghidra_modules(monkeypatch)
    program = _export_program(tmp_path)
    program.executable_path = str(tmp_path / "missing.bin")
    with pytest.raises(ops.OperationError, match="original program file is unavailable"):
        ops.program_export(
            program, ProgramExportOperation(destination_path=str(tmp_path / "out.bin")), Monitor()
        )


def test_program_export_skips_foreign_and_non_file_blocks(tmp_path, monkeypatch):
    install_ghidra_modules(monkeypatch)
    program = _export_program(tmp_path)
    block = program.memory.blocks[0]
    block.source_infos = [
        SourceInfo(filename="other.bin", offset=0, length=14),
        SourceInfo(filename="source.bin", offset=0, length=0),
    ]
    ops.program_export(
        program, ProgramExportOperation(destination_path=str(tmp_path / "out.bin")), Monitor()
    )
    assert (tmp_path / "out.bin").read_bytes() == b"AAAA_BBBB_CCCC"


def test_program_export_cancelled(tmp_path, monkeypatch):
    install_ghidra_modules(monkeypatch)
    program = _export_program(tmp_path)
    with pytest.raises(ops.OperationError, match="program export cancelled"):
        ops.program_export(
            program,
            ProgramExportOperation(destination_path=str(tmp_path / "out.bin")),
            Monitor(cancelled=True),
        )


def test_analysis_list_analyzers_filters_and_pages(monkeypatch):
    install_ghidra_modules(monkeypatch)
    program = Program()
    result = ops.analysis_list_analyzers(program, AnalysisListAnalyzersOperation(), Monitor())
    assert [item.name for item in result.items] == ["Demangler", "ASCII Strings"]
    filtered = ops.analysis_list_analyzers(
        program, AnalysisListAnalyzersOperation(query="strings"), Monitor()
    )
    assert [item.name for item in filtered.items] == ["ASCII Strings"]
    cancelled = ops.analysis_list_analyzers(
        program, AnalysisListAnalyzersOperation(), Monitor(cancelled=True)
    )
    assert not cancelled.items


def test_set_data_type_applies_and_rejects_unknown(monkeypatch):
    install_ghidra_modules(monkeypatch)
    program = Program()

    class RejectingManager:
        def getDataType(self, path, name):
            return None

    program._dtm = RejectingManager()

    def getDataTypeManager(self):
        return self._dtm

    Program.getDataTypeManager = getDataTypeManager
    with pytest.raises(ops.OperationError, match="unknown data type"):
        ops.set_data_type(
            program,
            SetDataTypeOperation(address="1000", data_type="nope"),
            Monitor(),
        )

    class AcceptingManager:
        def getDataType(self, path, name):
            return name if name == "string" else None

    program._dtm = AcceptingManager()
    result = ops.set_data_type(
        program, SetDataTypeOperation(address="1000", data_type="string"), Monitor()
    )
    assert result.changed
    assert program.listing.created[0].value == 0x1000
    sized = ops.set_data_type(
        program,
        SetDataTypeOperation(address="1000", data_type="string", length=16),
        Monitor(),
    )
    assert sized.changed
    assert program.listing.created[2] == 16
