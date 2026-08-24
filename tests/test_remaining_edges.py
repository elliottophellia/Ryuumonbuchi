# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors
# pyright: reportPrivateUsage=false, reportUnknownParameterType=false, reportMissingParameterType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportArgumentType=false, reportUnknownLambdaType=false, reportAttributeAccessIssue=false

from __future__ import annotations

import asyncio
import hashlib
import importlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import ValidationError

from ryuumonbuchi import __main__ as package_main
from ryuumonbuchi import config as cfg
from ryuumonbuchi.config import AppConfig
from ryuumonbuchi.models import FunctionGetOperation, PatchBytesOperation
from ryuumonbuchi.process import (
    WorkerCancelledError,
    WorkerFailedError,
    WorkerOperationError,
    WorkerRunner,
    WorkerTimeoutError,
)
from ryuumonbuchi.server import (
    ServerState,
    _guard,
    _program_delete,
    _program_import,
    _program_import_bytes,
    _program_info_async,
    _program_save,
    _run_batch,
    _run_program,
)
from ryuumonbuchi.server import (
    main as server_main,
)
from ryuumonbuchi.session import (
    ProgramExistsError,
    ProgramNotFoundError,
    ProgramNotSelectedError,
    ProgramRecord,
    SessionError,
    SessionWorkspace,
    stream_sha256,
    validate_workspace_path,
)


async def _raise(value: BaseException) -> None:
    raise value


def test_package_main_import_covers_non_script_branch() -> None:
    assert importlib.import_module("ryuumonbuchi.__main__") is package_main


def test_config_parser_skips_comments_and_non_properties(fake_ghidra: Path) -> None:
    path = fake_ghidra / "Ghidra/application.properties"
    path.write_text("\n# comment\nignored\nkey = value = still-value\n", encoding="utf-8")
    assert cfg._parse_properties(path) == {"key": "value = still-value"}


def test_model_hex_validator_rejects_non_hex() -> None:
    with pytest.raises(ValidationError):
        PatchBytesOperation(address="100", bytes_hex="zz")


def test_session_manifest_object_duplicate_and_cleanup_edges(tmp_path: Path, monkeypatch) -> None:
    workspace = SessionWorkspace.create("12.0.4", temp_dir=tmp_path)
    try:
        workspace.manifest_path.write_text("[]", encoding="utf-8")
        with pytest.raises(SessionError, match="object"):
            workspace.read_manifest()
        record = {
            "program_name": "hello",
            "source_path": "source",
            "source_sha256": "hash",
            "imported_at": "now",
            "analyzed": False,
        }
        payload = {
            "schema": 1,
            "session_id": workspace.session_id,
            "created_at": "now",
            "ghidra_version": "12.0.4",
            "programs": [record, record],
        }
        workspace.manifest_path.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.raises(SessionError, match="Duplicate"):
            workspace.read_manifest()
        workspace.manifest_path.write_text(
            json.dumps({**payload, "programs": [[]]}), encoding="utf-8"
        )
        with pytest.raises(SessionError, match="invalid record"):
            workspace.read_manifest()
        with pytest.raises(SessionError, match="outside"):
            validate_workspace_path(workspace.root, workspace)
        assert validate_workspace_path(workspace.project_dir, workspace) == workspace.project_dir
        monkeypatch.setattr(os, "name", "nt")
        from ryuumonbuchi import session as session_module

        with pytest.raises(SessionError, match="POSIX"):
            session_module._lock_exclusive(workspace._lock_file)
    finally:
        if not workspace.closed:
            asyncio.run(workspace.close())


def test_session_close_idempotence_and_lock_release_edges(tmp_path: Path, monkeypatch) -> None:
    workspace = SessionWorkspace.create("12.0.4", temp_dir=tmp_path)
    asyncio.run(workspace.close())
    asyncio.run(workspace.close())
    assert workspace.closed
    monkeypatch.setattr(os, "name", "nt")
    from ryuumonbuchi import session as session_module

    session_module._unlock(workspace._lock_file)


def test_process_validation_timeout_response_size_and_termination_edges(
    app_config: AppConfig, workspace: SessionWorkspace, tmp_path: Path, monkeypatch
) -> None:
    runner = WorkerRunner(app_config, workspace)
    with pytest.raises(ValueError, match="between 1 and 32"):
        asyncio.run(runner.run([], read_only=True, program_name="hello"))
    workspace.runs_dir = workspace.root.parent
    with pytest.raises(WorkerFailedError, match="escaped"):
        asyncio.run(
            runner.run([{"action": "function_list"}], read_only=False, program_name="hello")
        )

    class Running:
        pid = 99
        returncode = None

        def poll(self):
            return None

        def wait(self, timeout=None):
            return 0

    process = Running()
    monkeypatch.setattr(runner, "_clock", lambda: 10.0)
    with pytest.raises(WorkerTimeoutError, match="timed out"):
        asyncio.run(runner._wait(process, 5.0, "request", True, tmp_path / "missing.log"))

    response = tmp_path / "response.json"
    response.write_text(
        json.dumps({"ok": True, "request_id": "r", "result": "x" * 100}), encoding="utf-8"
    )
    small_config = AppConfig(
        app_config.ghidra_install_dir,
        max_heap_mb=256,
        max_cpu=1,
        operation_timeout_seconds=30,
        max_response_bytes=1,
    )
    small_runner = WorkerRunner(small_config, workspace)
    with pytest.raises(WorkerFailedError, match="malformed"):
        small_runner._read_response(response, "r", True, tmp_path / "missing.log", tmp_path)

    class StopsOnTerm:
        pid = 101
        returncode = 0
        stopped = False

        def poll(self):
            return None if not self.stopped else 0

        def wait(self, timeout=None):
            self.stopped = True
            return 0

    stopped = StopsOnTerm()
    monkeypatch.setattr(os, "killpg", lambda pid, sig: setattr(stopped, "stopped", True))
    monkeypatch.setattr(runner, "_clock", lambda: 0.0)
    asyncio.run(runner._terminate(stopped))

    class Polling:
        returncode = None
        calls = 0

        def poll(self):
            self.calls += 1
            if self.calls >= 2:
                self.returncode = 0
            return self.returncode

    polling = Polling()
    monkeypatch.setattr(runner, "_clock", lambda: 0.0)
    asyncio.run(runner._wait(polling, 5.0, "poll", False, tmp_path / "missing.log"))


def _state_for_server(app_config: AppConfig, workspace: SessionWorkspace) -> ServerState:
    from ryuumonbuchi.config import GhidraInstallation
    from ryuumonbuchi.process import WorkerRunner

    installation = GhidraInstallation(app_config.ghidra_install_dir, "12.0.4", 21, ("3.13",))
    return ServerState(app_config, installation, workspace, WorkerRunner(app_config, workspace))


def test_server_guard_maps_all_domain_errors() -> None:
    errors = [
        WorkerOperationError("known", "known message", request_id="r"),
        WorkerTimeoutError("timeout", request_id="r", uncertain=True),
        WorkerCancelledError("cancelled", request_id="r", uncertain=True),
        WorkerFailedError("failed", request_id="r", uncertain=True),
        ProgramNotSelectedError("not selected"),
        ProgramNotFoundError("not found"),
        ProgramExistsError("exists"),
        SessionError("session"),
        ValueError("value"),
        TypeError("type"),
    ]
    for error in errors:
        with pytest.raises(ToolError):
            asyncio.run(_guard(_raise(error)))


def test_server_program_and_batch_uncertain_transitions(
    app_config: AppConfig, workspace: SessionWorkspace, tmp_path: Path, monkeypatch
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"source")
    state = _state_for_server(app_config, workspace)
    workspace.update_program(
        ProgramRecord(
            "hello", str(source), stream_sha256(source), workspace.created_at.isoformat(), False
        )
    )

    async def clear_session(self):
        return "old", "new"

    monkeypatch.setattr(ServerState, "clear_session", clear_session)
    operation = FunctionGetOperation(name="main")

    async def uncertain(*args, **kwargs):
        message = "uncertain"
        raise WorkerFailedError(message, request_id="r", uncertain=True)

    monkeypatch.setattr(state.runner, "run", uncertain)
    with pytest.raises(SessionError, match="replacement"):
        asyncio.run(_run_program(state, "hello", operation, read_only=True))
    with pytest.raises(SessionError, match="replacement"):
        asyncio.run(_run_batch(state, "hello", (operation,)))
    with pytest.raises(ValueError, match="1..32"):
        asyncio.run(_run_batch(state, "hello", ()))

    async def certain(*args, **kwargs):
        message = "certain"
        raise WorkerFailedError(message, request_id="r", uncertain=False)

    monkeypatch.setattr(state.runner, "run", certain)
    with pytest.raises(WorkerFailedError):
        asyncio.run(_run_program(state, "hello", operation, read_only=True))
    with pytest.raises(WorkerFailedError):
        asyncio.run(_run_batch(state, "hello", (operation,)))

    assert asyncio.run(_program_info_async(state, "hello")).program_name == "hello"
    with pytest.raises(ProgramNotSelectedError):
        asyncio.run(_program_info_async(state, "missing"))

    async def import_uncertain(*args, **kwargs):
        message = "import"
        raise WorkerFailedError(message, request_id="r", uncertain=True)

    monkeypatch.setattr(state.runner, "run", import_uncertain)
    with pytest.raises(SessionError, match="program import"):
        asyncio.run(_program_import(state, str(source), "new", False))

    async def successful(*args, **kwargs):
        return SimpleNamespace(result={"language_id": "x86:LE:64:default", "processor": "x86"})

    monkeypatch.setattr(state.runner, "run", successful)
    imported = asyncio.run(_program_import(state, str(source), "new", False))
    assert imported.analyzed is False
    imported_bytes = asyncio.run(_program_import_bytes(state, "bytes", "Ynl0ZXM=", b"bytes", True))
    assert imported_bytes.source_sha256 == hashlib.sha256(b"bytes").hexdigest()
    saved = asyncio.run(_program_save(state, "new", str(tmp_path / "save.gzf"), False))
    assert saved.program_name == "new"

    async def non_dict(*args, **kwargs):
        return SimpleNamespace(result="not-a-dict")

    monkeypatch.setattr(state.runner, "run", non_dict)
    imported_non_dict = asyncio.run(_program_import(state, str(source), "non_dict", False))
    assert imported_non_dict.analyzed is False
    imported_bytes_non_dict = asyncio.run(
        _program_import_bytes(state, "non_dict_bytes", "Ynl0ZXM=", b"bytes", True)
    )
    assert imported_bytes_non_dict.analyzed is True

    async def import_certain(*args, **kwargs):
        message = "import certain"
        raise WorkerFailedError(message, request_id="r", uncertain=False)

    monkeypatch.setattr(state.runner, "run", import_certain)
    with pytest.raises(WorkerFailedError):
        asyncio.run(_program_import(state, str(source), "certain", False))
    with pytest.raises(WorkerFailedError):
        asyncio.run(_program_import_bytes(state, "certain_bytes", "Ynl0ZXM=", b"bytes", False))

    async def import_bytes_uncertain(*args, **kwargs):
        message = "import bytes uncertain"
        raise WorkerFailedError(message, request_id="r", uncertain=True)

    monkeypatch.setattr(state.runner, "run", import_bytes_uncertain)
    with pytest.raises(SessionError, match="program import uncertain"):
        asyncio.run(_program_import_bytes(state, "uncertain_bytes", "Ynl0ZXM=", b"bytes", False))

    async def save_uncertain(*args, **kwargs):
        message = "save uncertain"
        raise WorkerFailedError(message, request_id="r", uncertain=True)

    monkeypatch.setattr(state.runner, "run", save_uncertain)
    with pytest.raises(SessionError, match="program save"):
        asyncio.run(_program_save(state, "new", str(tmp_path / "save2.gzf"), False))

    async def save_certain(*args, **kwargs):
        message = "save certain"
        raise WorkerFailedError(message, request_id="r", uncertain=False)

    monkeypatch.setattr(state.runner, "run", save_certain)
    with pytest.raises(WorkerFailedError):
        asyncio.run(_program_save(state, "new", str(tmp_path / "save3.gzf"), False))

    async def delete_uncertain(*args, **kwargs):
        message = "delete"
        raise WorkerFailedError(message, request_id="r", uncertain=True)

    monkeypatch.setattr(state.runner, "run", delete_uncertain)
    with pytest.raises(SessionError, match="program deletion"):
        asyncio.run(_program_delete(state, "hello"))

    asyncio.run(workspace.close())


def test_server_main_validates_then_runs(app_config: AppConfig, monkeypatch) -> None:
    called = []
    monkeypatch.setattr("ryuumonbuchi.server.validate_config", lambda config: None)
    monkeypatch.setattr(
        "ryuumonbuchi.server.create_server",
        lambda config: SimpleNamespace(run=lambda mode: called.append(mode)),
    )
    server_main(app_config)
    assert called == ["stdio"]


def test_process_runner_timeout_cleanup_and_running_property(
    app_config: AppConfig, workspace: SessionWorkspace, monkeypatch
) -> None:
    runner = WorkerRunner(app_config, workspace)
    assert runner.worker_running is False
    runner.active_worker_pid = 44
    assert runner.worker_running is True
    runner.active_worker_pid = None

    class Process:
        pid = 55
        returncode = None
        terminated = False

        def poll(self):
            return None if not self.terminated else 0

    process = Process()
    terminated: list[object] = []

    async def terminate(value):
        terminated.append(value)
        value.terminated = True

    async def timeout(*args, **kwargs):
        message = "timeout"
        raise WorkerTimeoutError(message, request_id="request", uncertain=True)

    monkeypatch.setattr(runner, "_spawn", lambda *args: process)
    monkeypatch.setattr(runner, "_terminate", terminate)
    monkeypatch.setattr(runner, "_wait", timeout)
    with pytest.raises(WorkerTimeoutError):
        asyncio.run(
            runner.run([{"action": "function_list"}], read_only=False, program_name="hello")
        )
    assert terminated == [process]

    process = Process()
    monkeypatch.setattr(runner, "_spawn", lambda *args: process)
    monkeypatch.setattr(runner, "_wait", lambda *args: _completed())
    monkeypatch.setattr(
        runner, "_read_response", lambda *args: SimpleNamespace(result={"ok": True})
    )
    result = asyncio.run(
        runner.run([{"action": "function_list"}], read_only=True, program_name="hello")
    )
    assert result.result == {"ok": True}
    assert process.terminated


async def _completed() -> None:
    return None


def test_server_program_certain_worker_failures(
    app_config: AppConfig, workspace: SessionWorkspace, tmp_path: Path, monkeypatch
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"source")
    state = _state_for_server(app_config, workspace)
    workspace.update_program(
        ProgramRecord(
            "hello", str(source), stream_sha256(source), workspace.created_at.isoformat(), False
        )
    )

    async def certain(*args, **kwargs):
        message = "certain"
        raise WorkerFailedError(message, request_id="request", uncertain=False)

    monkeypatch.setattr(state.runner, "run", certain)
    with pytest.raises(WorkerFailedError):
        asyncio.run(_program_import(state, str(source), "new", False))
    with pytest.raises(WorkerFailedError):
        asyncio.run(_program_delete(state, "hello"))
    asyncio.run(workspace.close())


def test_session_create_properties_lock_and_permission_edges(tmp_path: Path, monkeypatch) -> None:
    from ryuumonbuchi import session as session_module

    original_lock = session_module._lock_exclusive

    def fail_lock(handle):
        message = "lock failed"
        raise SessionError(message)

    monkeypatch.setattr(session_module, "_lock_exclusive", fail_lock)
    with pytest.raises(SessionError, match="lock failed"):
        SessionWorkspace.create("12.0.4", temp_dir=tmp_path)
    monkeypatch.setattr(session_module, "_lock_exclusive", original_lock)
    workspace = SessionWorkspace.create("12.0.4", temp_dir=tmp_path)
    try:
        assert workspace.project_path.name == "ryuumonbuchi.gpr"
        assert workspace.project_repository_path.name == "ryuumonbuchi.rep"
        with (
            workspace.owner_lock_path.open("a+b") as second_lock,
            pytest.raises(SessionError, match="already held"),
        ):
            session_module._lock_exclusive(second_lock)
        original_lock = session_module._lock_exclusive

        def busy_lock(handle):
            message = "already held"
            raise SessionError(message)

        monkeypatch.setattr(session_module, "_lock_exclusive", busy_lock)
        assert not session_module.try_cleanup_workspace(workspace.root)
        monkeypatch.setattr(session_module, "_lock_exclusive", original_lock)

        class SessionValueError(SessionError, ValueError):
            pass

        def fail_name(value):
            message = "invalid name"
            raise SessionValueError(message)

        payload = {
            "schema": 1,
            "session_id": workspace.session_id,
            "created_at": "now",
            "ghidra_version": "12.0.4",
            "programs": [{"program_name": "hello"}],
        }
        workspace.manifest_path.write_text(json.dumps(payload), encoding="utf-8")
        monkeypatch.setattr(session_module, "validate_program_name", fail_name)
        with pytest.raises(SessionValueError, match="invalid name"):
            workspace.read_manifest()
    finally:
        if not workspace.closed:
            asyncio.run(workspace.close())

    source = tmp_path / "readable"
    source.write_bytes(b"source")
    monkeypatch.setattr(session_module.os, "access", lambda path, mode: False)
    with pytest.raises(PermissionError, match="not readable"):
        session_module.stream_sha256(source)


def test_session_close_serializes_two_waiters(tmp_path: Path) -> None:
    workspace = SessionWorkspace.create("12.0.4", temp_dir=tmp_path)

    class YieldingLock:
        def __init__(self):
            self.lock = asyncio.Lock()

        async def __aenter__(self):
            await self.lock.acquire()
            await asyncio.sleep(0)

        async def __aexit__(self, *_args):
            self.lock.release()

    workspace.operation_lock = YieldingLock()

    async def close_both():
        await asyncio.gather(workspace.close(), workspace.close())

    asyncio.run(close_both())
    assert workspace.closed
