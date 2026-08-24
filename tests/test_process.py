# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors
# pyright: reportPrivateUsage=false, reportUnknownParameterType=false, reportMissingParameterType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportIndexIssue=false
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import cast

import pytest

from ryuumonbuchi.config import AppConfig
from ryuumonbuchi.process import WorkerFailedError, WorkerRunner
from ryuumonbuchi.session import SessionWorkspace


class FakeProcess:
    pid = 1234
    returncode = 0

    def poll(self) -> int:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        return self.returncode


@pytest.mark.parametrize("read_only", [True, False])
def test_worker_runner_writes_request_and_cleans_success(
    app_config: object, workspace: SessionWorkspace, monkeypatch: object, read_only: bool
) -> None:
    runner = WorkerRunner(cast(AppConfig, app_config), workspace)
    process = FakeProcess()
    response_holder: dict[str, Path] = {}

    def spawn(request_path: Path, response_path: Path, log_path: Path) -> FakeProcess:
        payload = json.loads(request_path.read_text(encoding="utf-8"))
        assert payload["schema"] == 1
        assert payload["project_name"] == "ryuumonbuchi"
        assert payload["read_only"] is read_only
        response_path.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "request_id": payload["request_id"],
                    "ok": True,
                    "result": {"ok": 1},
                }
            ),
            encoding="utf-8",
        )
        response_holder["run"] = request_path.parent
        return process

    monkeypatch.setattr(runner, "_spawn", spawn)  # type: ignore[union-attr]
    result = asyncio.run(
        runner.run([{"action": "function_list"}], read_only=read_only, program_name="hello")
    )
    assert result.result == {"ok": 1}
    assert runner.active_worker_pid is None
    assert runner.last_worker_pid == 1234
    assert not response_holder["run"].exists()


def test_worker_runner_spawn_builds_sanitized_environment(
    app_config: AppConfig, workspace: SessionWorkspace, tmp_path: Path, monkeypatch
) -> None:
    runner = WorkerRunner(app_config, workspace)
    request = tmp_path / "request.json"
    response = tmp_path / "response.json"
    log = tmp_path / "worker.log"
    captured: dict[str, object] = {}

    class Process:
        pid = 12

    def fake_popen(args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return Process()

    monkeypatch.setattr("ryuumonbuchi.process.subprocess.Popen", fake_popen)
    process = runner._spawn(request, response, log)
    assert process.pid == 12
    assert captured["args"][1:3] == ["-m", "ryuumonbuchi.worker"]
    assert captured["kwargs"]["env"]["GHIDRA_INSTALL_DIR"] == str(app_config.ghidra_install_dir)


def test_worker_runner_rejects_malformed_response(
    app_config: object, workspace: SessionWorkspace, monkeypatch: object
) -> None:
    runner = WorkerRunner(cast(AppConfig, app_config), workspace)

    def spawn(request_path: Path, response_path: Path, log_path: Path) -> FakeProcess:
        response_path.write_text("{}", encoding="utf-8")
        return FakeProcess()

    monkeypatch.setattr(runner, "_spawn", spawn)  # type: ignore[union-attr]
    with pytest.raises(WorkerFailedError, match="schema mismatch"):
        asyncio.run(runner.run([{"action": "function_list"}], read_only=True, program_name="hello"))
    assert runner.active_worker_pid is None
