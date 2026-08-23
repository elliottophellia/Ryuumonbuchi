# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors
# pyright: reportPrivateUsage=false, reportUnknownParameterType=false, reportMissingParameterType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownMemberType=false

from __future__ import annotations

import asyncio
import json
import runpy
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from ryuumonbuchi import cli
from ryuumonbuchi import config as config_module
from ryuumonbuchi.config import AppConfig, ConfigError, build_config, validate_ghidra_installation
from ryuumonbuchi.models import WorkerFailure, WorkerSuccess
from ryuumonbuchi.process import (
    WorkerFailedError,
    WorkerOperationError,
    WorkerRunner,
)
from ryuumonbuchi.session import (
    ProgramNotFoundError,
    SessionError,
    SessionWorkspace,
    stream_sha256,
    try_cleanup_workspace,
)


def test_config_invalid_metadata_variants(fake_ghidra: Path) -> None:
    properties = fake_ghidra / "Ghidra/application.properties"
    variants = [
        (
            "application.version=bad\napplication.java.min=21\napplication.python.supported=3.13\n",
            "version",
        ),
        (
            "application.version=11.0.0\napplication.java.min=21\napplication.python.supported=3.13\n",
            "unsupported",
        ),
        (
            "application.version=12.0.4\napplication.java.min=x\napplication.python.supported=3.13\n",
            "java.min",
        ),
        (
            "application.version=12.0.4\napplication.java.min=20\napplication.python.supported=3.13\n",
            "Java",
        ),
        (
            "application.version=12.0.4\napplication.java.min=21\napplication.python.supported=3.12\n",
            "Python 3.13",
        ),
    ]
    original = properties.read_text(encoding="utf-8")
    try:
        for content, message in variants:
            properties.write_text(content, encoding="utf-8")
            with pytest.raises(ConfigError, match=message):
                validate_ghidra_installation(fake_ghidra)
    finally:
        properties.write_text(original, encoding="utf-8")


def test_config_missing_layout_and_platform(fake_ghidra: Path, monkeypatch) -> None:
    required = fake_ghidra / "support/analyzeHeadless"
    required.unlink()
    with pytest.raises(ConfigError, match="missing required path"):
        validate_ghidra_installation(fake_ghidra)
    monkeypatch.setattr(config_module.platform, "system", lambda: "Windows")
    with pytest.raises(ConfigError, match="POSIX/Linux"):
        validate_ghidra_installation(fake_ghidra)


def test_config_env_and_positive_limit_errors(fake_ghidra: Path) -> None:
    with pytest.raises(ConfigError, match="must be an integer"):
        build_config(ghidra_install_dir=fake_ghidra, environ={"RYUUMONBUCHI_MAX_CPU": "x"})
    with pytest.raises(ConfigError, match="positive"):
        AppConfig(fake_ghidra, max_response_bytes=0)
    with pytest.raises(ConfigError, match="positive"):
        AppConfig(fake_ghidra, max_log_tail_bytes=0)


def test_config_private_parser_errors(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="Cannot read"):
        config_module._parse_properties(tmp_path / "missing")
    with pytest.raises(ConfigError, match="invalid"):
        config_module._parse_version("invalid")


def test_cli_version_and_validation(fake_ghidra: Path, capsys, monkeypatch) -> None:
    cli.main(["--version"])
    assert capsys.readouterr().out.strip() == "0.1.0"
    with pytest.raises(SystemExit):
        cli.main(["--ghidra-install-dir", str(fake_ghidra / "missing")])
    called: list[AppConfig] = []
    monkeypatch.setattr(cli, "run_server", lambda config: called.append(config))  # type: ignore[reportUnknownLambdaType]
    cli.main(
        [
            "--ghidra-install-dir",
            str(fake_ghidra),
            "--max-heap-mb",
            "256",
            "--max-cpu",
            "1",
            "--operation-timeout-seconds",
            "30",
        ]
    )
    assert called[0].ghidra_install_dir == fake_ghidra.resolve()


def test_module_entrypoint_version(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "argv", ["ryuumonbuchi", "--version"])
    runpy.run_module("ryuumonbuchi.__main__", run_name="__main__")
    assert capsys.readouterr().out.strip() == "0.1.0"


def test_session_manifest_corruption_and_transitions(tmp_path: Path) -> None:
    workspace = SessionWorkspace.create("12.0.4", temp_dir=tmp_path)
    try:
        workspace.manifest_path.write_text("not-json", encoding="utf-8")
        with pytest.raises(SessionError, match="unreadable"):
            workspace.read_manifest()
        workspace.manifest_path.write_text(json.dumps({"schema": 99}), encoding="utf-8")
        with pytest.raises(SessionError, match="schema"):
            workspace.read_manifest()
        workspace.manifest_path.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "session_id": workspace.session_id,
                    "created_at": "now",
                    "ghidra_version": "12",
                    "programs": "bad",
                }
            ),
            encoding="utf-8",
        )
        with pytest.raises(SessionError, match="programs"):
            workspace.read_manifest()
        valid_manifest = {
            "schema": 1,
            "session_id": workspace.session_id,
            "created_at": "now",
            "ghidra_version": "12",
            "programs": [],
        }
        workspace.manifest_path.write_text(json.dumps(valid_manifest), encoding="utf-8")
        with pytest.raises(ProgramNotFoundError):
            workspace.remove_program("missing")
        replacement_id, replacement = asyncio.run(workspace.replace("12.0.4"))
        assert replacement_id != replacement.session_id
        asyncio.run(replacement.close())
    except BaseException:
        if not workspace.closed:
            asyncio.run(workspace.close())
        raise


def test_session_cleanup_and_sha_errors(tmp_path: Path) -> None:
    assert not try_cleanup_workspace(tmp_path / "missing")
    with pytest.raises(FileNotFoundError):
        stream_sha256(tmp_path / "missing")
    directory = tmp_path / "directory"
    directory.mkdir()
    with pytest.raises(FileNotFoundError):
        stream_sha256(directory)


def test_worker_response_variants(
    app_config: AppConfig, workspace: SessionWorkspace, tmp_path: Path
) -> None:
    runner = WorkerRunner(app_config, workspace)
    run_dir = workspace.runs_dir / "request"
    run_dir.mkdir()
    response = run_dir / "response.json"
    log = run_dir / "worker.log"
    log.write_bytes(b"0123456789")
    response.write_text(
        WorkerSuccess(request_id="request", result={"ok": True}).model_dump_json(by_alias=True),
        encoding="utf-8",
    )
    assert runner._read_response(response, "request", True, log, run_dir).result == {"ok": True}
    run_dir.mkdir()
    response = run_dir / "response.json"
    response.write_text(
        WorkerFailure(
            request_id="request",
            error={"code": "known", "message": "bad"},  # type: ignore[arg-type]
        ).model_dump_json(by_alias=True),
        encoding="utf-8",
    )
    with pytest.raises(WorkerOperationError, match="bad"):
        runner._read_response(response, "request", True, log, run_dir)


def test_worker_wait_timeout_and_nonzero(
    app_config: AppConfig, workspace: SessionWorkspace, tmp_path: Path
) -> None:
    runner = WorkerRunner(app_config, workspace)
    process = SimpleNamespace(returncode=7, poll=lambda: 7)
    with pytest.raises(WorkerFailedError, match="status 7"):
        asyncio.run(
            runner._wait(process, 9_999_999_999, "request", True, tmp_path / "missing.log")  # type: ignore[arg-type]
        )
