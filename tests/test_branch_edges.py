# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors
# pyright: reportPrivateUsage=false, reportUnknownParameterType=false, reportMissingParameterType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownLambdaType=false

from __future__ import annotations

import asyncio
import json
import os
import signal
from pathlib import Path

import pytest

from ryuumonbuchi import config as cfg
from ryuumonbuchi.config import AppConfig, ConfigError, build_config, validate_ghidra_installation
from ryuumonbuchi.models import WorkerFailure, WorkerSuccess
from ryuumonbuchi.process import (
    WorkerCancelledError,
    WorkerFailedError,
    WorkerRunner,
)
from ryuumonbuchi.session import (
    ProgramExistsError,
    ProgramNotSelectedError,
    ProgramRecord,
    SessionError,
    SessionWorkspace,
    stream_sha256,
    try_cleanup_workspace,
)


def _write_metadata(
    root: Path, version: str = "12.0.4", java: str = "21", python: str = "3.13"
) -> None:
    (root / "Ghidra/application.properties").write_text(
        f"application.version={version}\napplication.java.min={java}\napplication.python.supported={python}\n",
        encoding="utf-8",
    )


def test_config_all_metadata_missing_branches(fake_ghidra: Path) -> None:
    prop = fake_ghidra / "Ghidra/application.properties"
    for content, pattern in (
        ("application.java.min=21\napplication.python.supported=3.13\n", "application.version"),
        ("application.version=12.0.4\napplication.python.supported=3.13\n", "java.min"),
        ("application.version=12.0.4\napplication.java.min=21\n", "python.supported"),
    ):
        prop.write_text(content, encoding="utf-8")
        with pytest.raises(ConfigError, match=pattern):
            validate_ghidra_installation(fake_ghidra)


def test_config_required_files_and_directory(tmp_path: Path) -> None:
    file_path = tmp_path / "file"
    file_path.write_text("x", encoding="utf-8")
    with pytest.raises(ConfigError, match="not a directory"):
        validate_ghidra_installation(file_path)
    root = tmp_path / "root"
    (root / "Ghidra/Features/PyGhidra/lib").mkdir(parents=True)
    (root / "support").mkdir()
    _write_metadata(root)
    for required in (
        root / "Ghidra/Features/PyGhidra/lib/PyGhidra.jar",
        root / "support/analyzeHeadless",
    ):
        with pytest.raises(ConfigError, match="missing required"):
            validate_ghidra_installation(root)
        required.touch()


def test_config_limit_type_and_precedence_errors(fake_ghidra: Path) -> None:
    with pytest.raises(ConfigError, match="max_heap_mb"):
        AppConfig(fake_ghidra, max_heap_mb=True, max_cpu=1, operation_timeout_seconds=30)
    with pytest.raises(ConfigError, match="max_cpu"):
        AppConfig(fake_ghidra, max_heap_mb=256, max_cpu=True, operation_timeout_seconds=30)
    with pytest.raises(ConfigError, match="operation_timeout_seconds"):
        AppConfig(fake_ghidra, max_heap_mb=256, max_cpu=1, operation_timeout_seconds=True)
    with pytest.raises(ConfigError, match="integer"):
        build_config(ghidra_install_dir=fake_ghidra, environ={"RYUUMONBUCHI_MAX_HEAP_MB": "bad"})


def test_session_manifest_record_error_branches(workspace: SessionWorkspace) -> None:
    cases = [
        {
            "schema": 1,
            "session_id": workspace.session_id,
            "created_at": "x",
            "ghidra_version": "x",
            "programs": ["bad"],
        },
        {
            "schema": 1,
            "session_id": workspace.session_id,
            "created_at": "x",
            "ghidra_version": "x",
            "programs": [
                {
                    "program_name": "bad",
                    "source_path": "x",
                    "source_sha256": "x",
                    "imported_at": "x",
                    "analyzed": False,
                }
            ],
        },
        {
            "schema": 1,
            "session_id": "other",
            "created_at": "x",
            "ghidra_version": "x",
            "programs": [],
        },
    ]
    for index, case in enumerate(cases):
        workspace.manifest_path.write_text(json.dumps(case), encoding="utf-8")
        if index == 1:
            assert workspace.read_manifest().programs["bad"].program_name == "bad"
        else:
            with pytest.raises(SessionError):
                workspace.read_manifest()


def test_session_program_exists_and_lock_errors(tmp_path: Path) -> None:
    workspace = SessionWorkspace.create("12.0.4", temp_dir=tmp_path)
    source = tmp_path / "source"
    source.write_bytes(b"x")
    workspace.update_program(
        ProgramRecord(
            "hello", str(source), stream_sha256(source), workspace.created_at.isoformat(), False
        )
    )
    with pytest.raises(ProgramExistsError):
        workspace.ensure_program_absent("hello")
    workspace._lock_file.close()  # noqa: SLF001
    assert try_cleanup_workspace(workspace.root)
    assert not workspace.root.exists()


def test_session_path_and_name_edges(workspace: SessionWorkspace, tmp_path: Path) -> None:
    assert not cfg.safe_descendant(tmp_path / "x", workspace.root)
    with pytest.raises(ProgramNotSelectedError):
        workspace.require_program(None)
    with pytest.raises(FileNotFoundError):
        stream_sha256(tmp_path)


class _FakeProcess:
    pid = 4444

    def __init__(self, returncode: int | None = 0, running: bool = False) -> None:
        self.returncode = returncode
        self.running = running

    def poll(self) -> int | None:
        return None if self.running else self.returncode

    def wait(self, timeout: float | None = None) -> int | None:
        self.running = False
        return self.returncode


def test_process_wait_response_failure_edges(
    app_config, workspace: SessionWorkspace, tmp_path: Path, monkeypatch
) -> None:
    runner = WorkerRunner(app_config, workspace)
    log = tmp_path / "log"
    log.write_bytes(b"log")
    with pytest.raises(WorkerFailedError, match="missing"):
        runner._read_response(tmp_path / "missing", "r", True, log, tmp_path)
    response = tmp_path / "response"
    response.write_text("[]", encoding="utf-8")
    with pytest.raises(WorkerFailedError, match="schema"):
        runner._read_response(response, "r", True, log, tmp_path)
    response.write_text(
        WorkerSuccess(request_id="other", result={}).model_dump_json(by_alias=True),
        encoding="utf-8",
    )
    with pytest.raises(WorkerFailedError, match="schema"):
        runner._read_response(response, "r", True, log, tmp_path)
    response.write_text(
        WorkerFailure(
            request_id="other",
            error={"code": "x", "message": "x"},  # type: ignore[arg-type]
        ).model_dump_json(by_alias=True),
        encoding="utf-8",
    )
    with pytest.raises(WorkerFailedError, match="schema"):
        runner._read_response(response, "r", True, log, tmp_path)
    with pytest.raises(WorkerFailedError, match="status"):
        asyncio.run(runner._wait(_FakeProcess(7), 9_999_999_999, "r", True, log))  # type: ignore[arg-type]


def test_process_run_cancel_and_timeout(
    app_config, workspace: SessionWorkspace, monkeypatch
) -> None:
    runner = WorkerRunner(app_config, workspace)
    process = _FakeProcess(running=True)
    monkeypatch.setattr(runner, "_spawn", lambda *args: process)  # type: ignore[reportUnknownLambdaType]

    async def cancelled(*args):
        raise asyncio.CancelledError

    monkeypatch.setattr(runner, "_wait", cancelled)
    with pytest.raises(WorkerCancelledError):
        asyncio.run(runner.run([{"action": "function_list"}], read_only=True, program_name="hello"))
    assert runner.active_worker_pid is None


def test_process_terminate_kill_escalation(
    app_config, workspace: SessionWorkspace, monkeypatch
) -> None:
    runner = WorkerRunner(app_config, workspace)
    process = _FakeProcess(running=True)
    clock = iter([0, 0, 6])
    monkeypatch.setattr(runner, "_clock", lambda: next(clock))
    signals: list[tuple[int, int]] = []

    def killpg(pid: int, sig: int) -> None:
        signals.append((pid, sig))
        if sig == signal.SIGKILL:
            process.running = False

    monkeypatch.setattr(os, "killpg", killpg)
    asyncio.run(runner._terminate(process))  # type: ignore[arg-type]
    assert signals == [(4444, signal.SIGTERM), (4444, signal.SIGKILL)]
