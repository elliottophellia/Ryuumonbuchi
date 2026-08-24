# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors
# pyright: reportPrivateUsage=false, reportUnknownParameterType=false, reportMissingParameterType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportAttributeAccessIssue=false, reportAssignmentType=false, reportArgumentType=false, reportUnknownLambdaType=false, reportIndexIssue=false

from __future__ import annotations

import json
import runpy
import sys
import types
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from ryuumonbuchi.models import (
    AnalysisOptionsGetOperation,
    AnalysisOptionsSetOperation,
    AnalysisRunOperation,
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
    RedoOperation,
    ReferencesOperation,
    RenameFunctionOperation,
    RenameVariableOperation,
    SearchStringsOperation,
    SearchSymbolsOperation,
    SetCommentOperation,
    SetPrototypeOperation,
    TextSearchOperation,
    UndoOperation,
    WorkerRequest,
)
from ryuumonbuchi.worker import __main__ as worker_entry
from ryuumonbuchi.worker import context as context_module
from ryuumonbuchi.worker import dispatch
from ryuumonbuchi.worker.context import WorkerContext, WorkerGhidraError
from ryuumonbuchi.worker.operations import OperationError


class _FakeLauncher:
    instances: list[_FakeLauncher] = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.vmargs: tuple[str, ...] = ()
        self.started = False
        self.__class__.instances.append(self)

    def add_vmargs(self, *args):
        self.vmargs = args

    def start(self):
        self.started = True


class _FakeInterface:
    next_open = True
    instances: list[_FakeInterface] = []

    def __init__(self):
        self.opened = False
        self.disposed = False
        self.closed = False
        self.__class__.instances.append(self)

    def toggleCCode(self, enabled):
        self.c_code = enabled

    def openProgram(self, program):
        self.opened = self.__class__.next_open
        return self.opened

    def closeProgram(self):
        if getattr(self, "close_error", None) is not None:
            raise self.close_error
        self.closed = True

    def dispose(self):
        if getattr(self, "dispose_error", None) is not None:
            raise self.dispose_error
        self.disposed = True


class _FakeDomainProgram:
    def __init__(self, valid=True, release_error=None):
        self.valid = valid
        self.release_error = release_error
        self.released = False

    def getClass(self):
        return object

    def release(self, consumer):
        if self.release_error is not None:
            raise self.release_error
        self.released = True


class _FakeDomainFile:
    DEFAULT_VERSION = 7

    def __init__(self, program=None, error=None):
        self.program = program
        self.error = error
        self.deleted = False

    def getReadOnlyDomainObject(self, consumer, version, monitor):
        if self.error is not None:
            raise self.error
        return self.program

    def delete(self):
        self.deleted = True


class _FakeProjectData:
    def __init__(self, domain_file=None):
        self.domain_file = domain_file

    def getFile(self, path):
        return self.domain_file


class _FakeProject:
    def __init__(self, domain_file=None):
        self.data = _FakeProjectData(domain_file)
        self.closed = False
        self.close_error = None

    def getProjectData(self):
        return self.data

    def close(self):
        if self.close_error is not None:
            raise self.close_error
        self.closed = True


class _FakeDomain:
    def __init__(self, pathname="/hello"):
        self.pathname = pathname

    def getPathname(self):
        return self.pathname


class _FakeProgram:
    def __init__(self):
        self.domain = _FakeDomain()
        self.transactions: list[tuple[str, object]] = []
        self.saved: list[str] = []

    def getDomainFile(self):
        return self.domain

    def startTransaction(self, name):
        self.transactions.append(("start", name))
        return 9

    def endTransaction(self, identifier, commit):
        self.transactions.append(("end", commit))
        return True

    def save(self, comment, monitor):
        self.saved.append(comment)


class _FakeWorkerContext:
    def __init__(self, request):
        self.request = request
        self.project = SimpleNamespace()
        self.started = False
        self.closed = False
        self.close_error = None

    def start(self):
        self.started = True

    def close(self):
        if self.close_error is not None:
            raise self.close_error
        self.closed = True


class _FakeLoader:
    def __init__(self, results):
        self.results = results
        self.calls: list[tuple[str, object]] = []

    def source(self, value):
        self.calls.append(("source", value))
        return self

    def project(self, value):
        self.calls.append(("project", value))
        return self

    def projectFolderPath(self, value):
        self.calls.append(("folder", value))
        return self

    def name(self, value):
        self.calls.append(("name", value))
        return self

    def monitor(self, value):
        self.calls.append(("monitor", value))
        return self

    def load(self):
        return self.results


class _FakeLoadResults:
    def __init__(self, domain_file):
        self.domain_file = domain_file
        self.saved = False
        self.closed = False

    def save(self, monitor):
        self.saved = True

    def getPrimary(self):
        return SimpleNamespace(getSavedDomainFile=lambda: self.domain_file)

    def close(self):
        self.closed = True


def _request(
    tmp_path: Path, *, read_only=True, operations=None, program_name="hello"
) -> WorkerRequest:
    return WorkerRequest(
        request_id="request",
        session_id="session",
        project_dir=str(tmp_path / "project"),
        ghidra_install_dir="/usr/share/ghidra",
        max_heap_mb=256,
        max_cpu=1,
        max_response_bytes=4096,
        read_only=read_only,
        program_name=program_name,
        operations=operations or [{"action": "function_list"}],
    )


def _install_context_modules(monkeypatch, *, valid=True, release_error=None, read_error=None):
    framework = types.ModuleType("ghidra.framework")
    framework_model = types.ModuleType("ghidra.framework.model")
    listing = types.ModuleType("ghidra.program.model.listing")
    java = types.ModuleType("java")
    java_lang = types.ModuleType("java.lang")
    decompiler = types.ModuleType("ghidra.app.decompiler")
    domain_program = _FakeDomainProgram(valid=valid, release_error=release_error)
    domain_file = _FakeDomainFile(domain_program, read_error)
    framework_model.DomainFile = _FakeDomainFile
    listing.Program = SimpleNamespace(class_=SimpleNamespace(isAssignableFrom=lambda value: valid))
    java_lang.Object = object
    decompiler.DecompInterface = _FakeInterface
    for name, module in {
        "ghidra.framework": framework,
        "ghidra.framework.model": framework_model,
        "ghidra.program.model.listing": listing,
        "java": java,
        "java.lang": java_lang,
        "ghidra.app.decompiler": decompiler,
    }.items():
        monkeypatch.setitem(sys.modules, name, module)
    return domain_file, domain_program


def test_worker_context_start_program_modes_and_decompiler_lifecycle(tmp_path, monkeypatch):
    request = _request(tmp_path)
    project = _FakeProject()
    monkeypatch.setattr(context_module.pyghidra, "HeadlessPyGhidraLauncher", _FakeLauncher)
    monkeypatch.setattr(context_module.pyghidra, "open_project", lambda *args, **kwargs: project)
    context = WorkerContext(request)
    context.start()
    assert context.project is project
    assert _FakeLauncher.instances[-1].started
    assert "-Xmx256m" in _FakeLauncher.instances[-1].vmargs

    program = object()

    @contextmanager
    def program_context(project_value, path):
        assert project_value is project
        assert path == "/hello"
        yield program

    monkeypatch.setattr(context_module.pyghidra, "program_context", program_context)
    with context.writable_program("hello") as selected:
        assert selected is program
    monkeypatch.setattr(
        context_module.pyghidra,
        "program_context",
        lambda *args: (_ for _ in ()).throw(FileNotFoundError()),
    )
    with pytest.raises(WorkerGhidraError, match="not found"):
        context.writable_program("missing").__enter__()
    monkeypatch.setattr(context_module.pyghidra, "program_context", program_context)
    domain_file, domain_program = _install_context_modules(monkeypatch)
    project.data.domain_file = domain_file
    monkeypatch.setattr(context_module.pyghidra, "task_monitor", lambda: "monitor")
    with context.readonly_program("hello") as selected:
        assert selected is domain_program
    assert domain_program.released
    with context.program("hello", read_only=True) as selected:
        assert selected is domain_program
    with context.program("hello", read_only=False) as selected:
        assert selected is program

    fake_program = SimpleNamespace(getDomainFile=lambda: _FakeDomain("/hello"))
    _FakeInterface.next_open = True
    first = context.decompiler(fake_program)
    assert context.decompiler(fake_program) is first
    context.close()
    context.close()
    assert first.closed and first.disposed


def test_worker_context_error_paths_and_cleanup_first_error(tmp_path, monkeypatch):
    request = _request(tmp_path)
    context = WorkerContext(request)
    with pytest.raises(WorkerGhidraError, match="not open"):
        context.writable_program("hello").__enter__()
    with pytest.raises(WorkerGhidraError, match="not open"):
        context.readonly_program("hello").__enter__()

    project = _FakeProject(None)
    context.project = project
    _install_context_modules(monkeypatch)
    with pytest.raises(WorkerGhidraError, match="not found"):
        context.readonly_program("missing").__enter__()

    domain_file, _ = _install_context_modules(monkeypatch, valid=False)
    project.data.domain_file = domain_file
    with pytest.raises(WorkerGhidraError, match="Cannot open program read-only"):
        context.readonly_program("bad").__enter__()

    domain_file, _ = _install_context_modules(monkeypatch, read_error=RuntimeError("boom"))
    project.data.domain_file = domain_file
    with pytest.raises(WorkerGhidraError, match="read-only"):
        context.readonly_program("broken").__enter__()

    monkeypatch.setattr(context_module.pyghidra, "task_monitor", lambda: "monitor")
    domain_file, _ = _install_context_modules(monkeypatch, release_error=RuntimeError("release"))
    project.data.domain_file = domain_file
    with context.readonly_program("release"):
        pass

    _FakeInterface.next_open = False
    interface_program = SimpleNamespace(getDomainFile=lambda: _FakeDomain("/fail"))
    with pytest.raises(WorkerGhidraError, match="could not open"):
        context.decompiler(interface_program)
    failed = _FakeInterface.instances[-1]
    assert failed.disposed

    bad_interface = SimpleNamespace(
        closeProgram=lambda: (_ for _ in ()).throw(RuntimeError("close")),
        dispose=lambda: None,
    )
    context._decompilers = {"bad": bad_interface}
    project.close_error = RuntimeError("project")
    with pytest.raises(WorkerGhidraError, match="cleanup failed"):
        context.close()
    assert context._closed


def test_dispatch_parses_read_only_and_routes_every_operation(monkeypatch):
    operations = [
        FunctionListOperation(),
        FunctionGetOperation(name="main"),
        FunctionDecompileOperation(name="main"),
        ListingDisassembleOperation(),
        ListingDataOperation(),
        MemoryBlocksOperation(),
        MemoryReadOperation(address="1000", length=1),
        SearchStringsOperation(),
        SearchSymbolsOperation(query="main"),
        ListImportsOperation(),
        ListExportsOperation(),
        ReferencesOperation(address="1000"),
        CallGraphOperation(name="main"),
        ByteSearchOperation(pattern="90"),
        TextSearchOperation(query="hello"),
        AnalysisRunOperation(),
        AnalysisOptionsGetOperation(),
        AnalysisOptionsSetOperation(values={}),
        RenameFunctionOperation(name="main", new_name="renamed"),
        RenameVariableOperation(function_address="1000", old_name="x", new_name="y"),
        SetCommentOperation(address="1000", comment="x"),
        SetPrototypeOperation(name="main", prototype="int main(void)"),
        PatchBytesOperation(address="1000", bytes_hex="90"),
        UndoOperation(),
        RedoOperation(),
    ]
    names = {
        "function_list": "function_list",
        "function_get": "function_get",
        "function_decompile": "function_decompile",
        "listing_disassemble": "listing_disassemble",
        "listing_data": "listing_data",
        "memory_blocks": "memory_blocks",
        "memory_read": "memory_read",
        "search_strings": "search_strings",
        "search_symbols": "search_symbols",
        "list_imports": "list_imports",
        "list_exports": "list_exports",
        "references": "references",
        "call_graph": "call_graph",
        "byte_search": "byte_search",
        "text_search": "text_search",
        "analysis_run": "analysis_run",
        "analysis_options_get": "analysis_options_get",
        "analysis_options_set": "analysis_options_set",
        "edit_rename_function": "rename_function",
        "edit_rename_variable": "rename_variable",
        "edit_set_comment": "set_comment",
        "edit_set_prototype": "set_prototype",
        "edit_patch_bytes": "patch_bytes",
        "edit_undo": "undo",
        "edit_redo": "redo",
    }
    for operation in operations:
        parsed = dispatch.parse_operation(operation.model_dump(mode="json"))
        assert parsed.action == operation.action
        monkeypatch.setattr(
            dispatch.operations,
            names[operation.action],
            lambda *args, _action=operation.action: _action,
        )
        assert (
            dispatch.execute_operation(
                SimpleNamespace(), SimpleNamespace(), operation, SimpleNamespace()
            )
            == operation.action
        )
    assert dispatch.is_read_only("function_list")
    assert not dispatch.is_read_only("edit_patch_bytes")
    with pytest.raises(ValidationError):
        dispatch.parse_operation({"action": "not-an-operation"})


def test_worker_entry_response_import_delete_and_batch_paths(tmp_path, monkeypatch):
    response = tmp_path / "response.json"
    worker_entry._write_response(response, "r", max_response_bytes=4096, result={"ok": True})
    assert json.loads(response.read_text())["ok"] is True
    worker_entry._write_response(response, "r", max_response_bytes=4096, error=("bad", "message"))
    assert json.loads(response.read_text())["error"]["code"] == "bad"
    worker_entry._write_response(response, "r", max_response_bytes=150, result="x" * 100)
    assert json.loads(response.read_text())["error"]["code"] == "response_too_large"
    with pytest.raises(WorkerGhidraError, match="response_too_large"):
        worker_entry._write_response(response, "r", max_response_bytes=1, error=("bad", "message"))

    monitor = object()
    monkeypatch.setattr(worker_entry.pyghidra, "task_monitor", lambda: monitor)
    saved_file = _FakeDomainFile()
    results = _FakeLoadResults(saved_file)
    loader = _FakeLoader(results)
    monkeypatch.setattr(worker_entry.pyghidra, "program_loader", lambda: loader)
    monkeypatch.setattr(worker_entry.pyghidra, "analyze", lambda *args: None)
    program = _FakeProgram()

    class ImportContext:
        project = "project"

        @contextmanager
        def writable_program(self, name):
            yield program

    imported = worker_entry._import_program(
        ImportContext(),
        __import__(
            "ryuumonbuchi.models", fromlist=["ProgramImportOperation"]
        ).ProgramImportOperation(source_path="source", program_name="hello", analyze=True),
    )
    assert imported == {"program_name": "hello", "analyzed": True}
    assert results.saved and results.closed and program.saved

    results_no_analysis = _FakeLoadResults(_FakeDomainFile())
    monkeypatch.setattr(
        worker_entry.pyghidra, "program_loader", lambda: _FakeLoader(results_no_analysis)
    )
    imported = worker_entry._import_program(
        ImportContext(),
        __import__(
            "ryuumonbuchi.models", fromlist=["ProgramImportOperation"]
        ).ProgramImportOperation(source_path="source", program_name="hello", analyze=False),
    )
    assert imported["analyzed"] is False

    cleanup_file = _FakeDomainFile()
    cleanup_results = _FakeLoadResults(cleanup_file)
    monkeypatch.setattr(
        worker_entry.pyghidra, "program_loader", lambda: _FakeLoader(cleanup_results)
    )

    class FailingImportContext(ImportContext):
        @contextmanager
        def writable_program(self, name):
            message = "save failed"
            raise RuntimeError(message)
            yield program

    with pytest.raises(RuntimeError):
        worker_entry._import_program(
            FailingImportContext(),
            __import__(
                "ryuumonbuchi.models", fromlist=["ProgramImportOperation"]
            ).ProgramImportOperation(source_path="source", program_name="hello", analyze=False),
        )
    assert cleanup_file.deleted

    with pytest.raises(WorkerGhidraError, match="not open"):
        worker_entry._delete_program(
            SimpleNamespace(project=None), SimpleNamespace(program_name="x")
        )
    project = _FakeProject(None)
    with pytest.raises(WorkerGhidraError, match="not found"):
        worker_entry._delete_program(
            SimpleNamespace(project=project), SimpleNamespace(program_name="x")
        )
    domain_file = _FakeDomainFile()
    project = _FakeProject(domain_file)
    assert worker_entry._delete_program(
        SimpleNamespace(project=project), SimpleNamespace(program_name="x")
    )["deleted"]
    assert domain_file.deleted


def test_worker_entry_batch_and_worker_main_paths(tmp_path, monkeypatch):
    request = _request(tmp_path, read_only=True)
    context = SimpleNamespace()
    program = _FakeProgram()

    @contextmanager
    def selected(name, read_only):
        yield program

    context.program = selected
    monkeypatch.setattr(worker_entry.pyghidra, "task_monitor", lambda: "monitor")
    monkeypatch.setattr(
        worker_entry,
        "execute_operation",
        lambda context, program, operation, monitor: {"action": operation.action},
    )
    parsed = [FunctionListOperation()]
    assert worker_entry._execute_batch(context, request, parsed) == {"action": "function_list"}

    mutable = _request(
        tmp_path,
        read_only=False,
        operations=[{"action": "function_list"}, {"action": "memory_blocks"}],
    )
    parsed_mutable = [FunctionListOperation(), MemoryBlocksOperation()]
    result = worker_entry._execute_batch(context, mutable, parsed_mutable)
    assert len(result["results"]) == 2
    assert program.transactions[-2:] == [
        ("start", "Ryuumonbuchi batch"),
        ("end", True),
    ]
    assert program.saved
    with pytest.raises(OperationError, match="program_name"):
        worker_entry._execute_batch(
            context, mutable.model_copy(update={"program_name": None}), parsed_mutable
        )

    monkeypatch.setattr(
        worker_entry,
        "execute_operation",
        lambda *args: (_ for _ in ()).throw(RuntimeError("operation")),
    )
    with pytest.raises(RuntimeError):
        worker_entry._execute_batch(context, mutable, parsed_mutable)
    assert ("end", False) in program.transactions

    def write_request(path: Path, value: WorkerRequest):
        path.write_text(value.model_dump_json(by_alias=True), encoding="utf-8")

    monkeypatch.setattr(worker_entry, "WorkerContext", _FakeWorkerContext)
    monkeypatch.setattr(worker_entry, "_execute_batch", lambda *args: {"value": True})
    request_path = tmp_path / "request.json"
    response_path = tmp_path / "worker-response.json"
    write_request(request_path, request)
    assert worker_entry.worker_main(request_path, response_path) == 0
    assert json.loads(response_path.read_text())["ok"] is True

    invalid_path = tmp_path / "invalid.json"
    invalid_path.write_text("{}", encoding="utf-8")
    assert worker_entry.worker_main(invalid_path, response_path) == 0
    assert json.loads(response_path.read_text())["error"]["code"] == "invalid_params"

    too_many_request = SimpleNamespace(
        request_id="request",
        max_response_bytes=4096,
        operations=[{"action": "function_list"}] * 33,
    )
    with monkeypatch.context() as local:
        local.setattr(
            worker_entry.WorkerRequest,
            "model_validate_json",
            staticmethod(lambda raw: too_many_request),
        )
        assert worker_entry.worker_main(request_path, response_path) == 0
        assert json.loads(response_path.read_text())["error"]["code"] == "ghidra_error"

    import_op = _request(
        tmp_path,
        operations=[{"action": "program_import", "source_path": "x", "program_name": "new"}],
        program_name=None,
    )
    write_request(request_path, import_op)
    monkeypatch.setattr(worker_entry, "_import_program", lambda *args: {"program_name": "new"})
    assert worker_entry.worker_main(request_path, response_path) == 0

    delete_op = _request(
        tmp_path,
        operations=[{"action": "program_delete", "program_name": "new"}],
        program_name=None,
    )
    write_request(request_path, delete_op)
    monkeypatch.setattr(worker_entry, "_delete_program", lambda *args: {"deleted": True})
    assert worker_entry.worker_main(request_path, response_path) == 0

    monkeypatch.setattr(
        worker_entry, "_execute_batch", lambda *args: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    write_request(request_path, request)
    assert worker_entry.worker_main(request_path, response_path) == 1
    assert json.loads(response_path.read_text())["error"]["code"] == "worker_failed"

    class CleanupFailure(_FakeWorkerContext):
        def close(self):
            message = "cleanup"
            raise RuntimeError(message)

    monkeypatch.setattr(worker_entry, "WorkerContext", CleanupFailure)
    monkeypatch.setattr(worker_entry, "_execute_batch", lambda *args: {"ok": True})
    assert worker_entry.worker_main(request_path, response_path) == 1
    assert json.loads(response_path.read_text())["error"]["code"] == "worker_cleanup_failed"
    monkeypatch.setattr(worker_entry, "WorkerContext", _FakeWorkerContext)
    monkeypatch.setattr(worker_entry, "_execute_batch", lambda *args: {"ok": True})
    monkeypatch.setattr(
        worker_entry,
        "_write_response",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("write")),
    )
    assert worker_entry.worker_main(request_path, response_path) == 0


def test_worker_entry_main_argument_contract(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["worker"])
    assert worker_entry.main() == 2
    monkeypatch.setattr(sys, "argv", ["worker", "request", "response"])
    monkeypatch.setattr(worker_entry, "worker_main", lambda request, response: 7)
    assert worker_entry.main() == 7
    monkeypatch.setattr(sys, "argv", ["worker"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("ryuumonbuchi.worker.__main__", run_name="__main__")
    assert exc.value.code == 2


def test_worker_context_invalid_project_and_close_after_project_error(tmp_path, monkeypatch):
    request = _request(tmp_path)
    context = WorkerContext(request)
    project = _FakeProject()
    context.project = project
    domain_file, _ = _install_context_modules(monkeypatch, valid=False)
    project.data.domain_file = domain_file
    monkeypatch.setattr(context_module.pyghidra, "task_monitor", lambda: "monitor")
    with pytest.raises(WorkerGhidraError, match="not a Program"):
        context.readonly_program("bad").__enter__()
    context._decompilers = {}
    project.close_error = RuntimeError("close")
    with pytest.raises(WorkerGhidraError, match="cleanup failed"):
        context.close()
    assert context._closed


def test_worker_lifecycle_batch_and_rollback_cleanup_branches(tmp_path, monkeypatch):
    request = _request(tmp_path, read_only=False)
    response = tmp_path / "response.json"
    request_path = tmp_path / "request.json"
    request_path.write_text(request.model_dump_json(by_alias=True), encoding="utf-8")
    monkeypatch.setattr(worker_entry, "WorkerContext", _FakeWorkerContext)
    with monkeypatch.context() as local:
        mixed = SimpleNamespace(
            request_id="request",
            max_response_bytes=4096,
            operations=[
                {"action": "program_import", "source_path": "x", "program_name": "new"},
                {"action": "function_list"},
            ],
        )
        local.setattr(
            worker_entry.WorkerRequest,
            "model_validate_json",
            staticmethod(lambda raw: mixed),
        )
        assert worker_entry.worker_main(request_path, response) == 0
        assert json.loads(response.read_text())["error"]["code"] == "ghidra_error"

    program = _FakeProgram()
    context = SimpleNamespace()

    @contextmanager
    def selected(name, read_only):
        yield program

    context.program = selected
    monkeypatch.setattr(worker_entry.pyghidra, "task_monitor", lambda: "monitor")
    monkeypatch.setattr(
        worker_entry,
        "execute_operation",
        lambda *args: (_ for _ in ()).throw(RuntimeError("operation")),
    )
    original_end = program.endTransaction

    def rollback_failure(identifier, commit):
        if not commit:
            message = "rollback"
            raise RuntimeError(message)
        return original_end(identifier, commit)

    program.endTransaction = rollback_failure
    with pytest.raises(RuntimeError, match="operation"):
        worker_entry._execute_batch(context, request, [FunctionListOperation()])

    cleanup_results = _FakeLoadResults(None)
    monkeypatch.setattr(
        worker_entry.pyghidra,
        "program_loader",
        lambda: _FakeLoader(cleanup_results),
    )

    class FailingImportContext:
        project = "project"

        @contextmanager
        def writable_program(self, name):
            message = "save failed"
            raise RuntimeError(message)
            yield program

    with pytest.raises(RuntimeError, match="save failed"):
        worker_entry._import_program(
            FailingImportContext(),
            __import__(
                "ryuumonbuchi.models", fromlist=["ProgramImportOperation"]
            ).ProgramImportOperation(source_path="source", program_name="hello", analyze=False),
        )


def test_worker_context_project_only_cleanup_error(tmp_path):
    context = WorkerContext(_request(tmp_path))
    project = _FakeProject()
    project.close_error = RuntimeError("project close")
    context.project = project
    with pytest.raises(WorkerGhidraError, match="cleanup failed"):
        context.close()
    assert context._closed


def test_worker_context_close_without_project(tmp_path):
    context = WorkerContext(_request(tmp_path))
    context.close()
    assert context._closed


def test_worker_batch_read_only_failure_skips_rollback(tmp_path, monkeypatch):
    request = _request(tmp_path, read_only=True)
    program = _FakeProgram()
    context = SimpleNamespace()

    @contextmanager
    def selected(name, read_only):
        yield program

    context.program = selected
    message = "read failure"
    monkeypatch.setattr(worker_entry.pyghidra, "task_monitor", lambda: "monitor")
    monkeypatch.setattr(
        worker_entry,
        "execute_operation",
        lambda *args: (_ for _ in ()).throw(RuntimeError(message)),
    )
    with pytest.raises(RuntimeError, match="read failure"):
        worker_entry._execute_batch(context, request, [FunctionListOperation()])
