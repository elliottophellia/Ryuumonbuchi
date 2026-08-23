# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors

"""One-shot Ghidra worker process lifecycle and response validation."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from .config import AppConfig, safe_descendant
from .models import WorkerFailure, WorkerRequest, WorkerSuccess
from .session import PROJECT_NAME, SessionWorkspace


class WorkerRunError(RuntimeError):
    """Base class for parent-side worker lifecycle failures."""

    def __init__(
        self, message: str, *, request_id: str, uncertain: bool, log_tail: bytes = b""
    ) -> None:
        super().__init__(message)
        self.request_id = request_id
        self.uncertain = uncertain
        self.log_tail = log_tail


class WorkerTimeoutError(WorkerRunError):
    """Raised when a worker exceeds its wall-clock deadline."""


class WorkerCancelledError(WorkerRunError):
    """Raised when the MCP request is cancelled while a worker runs."""


class WorkerFailedError(WorkerRunError):
    """Raised when a worker exits or responds with an invalid envelope."""


class WorkerOperationError(WorkerRunError):
    """Raised for a valid, known operation error from a clean worker."""

    def __init__(self, code: str, message: str, *, request_id: str) -> None:
        super().__init__(message, request_id=request_id, uncertain=False)
        self.code = code


@dataclass(frozen=True, slots=True)
class WorkerCall:
    """Successful worker result plus request identity."""

    request_id: str
    result: Any


class WorkerRunner:
    """Launch exactly one isolated worker for each request."""

    def __init__(self, config: AppConfig, workspace: SessionWorkspace) -> None:
        self.config = config
        self.workspace = workspace
        self._clock = time.monotonic
        self.active_worker_pid: int | None = None
        self.last_worker_pid: int | None = None

    @property
    def worker_running(self) -> bool:
        return self.active_worker_pid is not None

    async def run(
        self,
        operations: list[dict[str, Any]],
        *,
        read_only: bool,
        timeout_seconds: int | None = None,
        program_name: str | None = None,
    ) -> WorkerCall:
        """Run a bounded operation envelope and return only structured Python data."""

        if not operations or len(operations) > 32:
            message = "worker operation count must be between 1 and 32"
            raise ValueError(message)
        request_id = str(uuid.uuid4())
        run_dir = (self.workspace.runs_dir / request_id).resolve()
        if not safe_descendant(run_dir, self.workspace.root):
            message = "worker run path escaped the session workspace"
            raise WorkerFailedError(
                message,
                request_id=request_id,
                uncertain=not read_only,
            )
        run_dir.mkdir(mode=0o700)
        request_path = run_dir / "request.json"
        response_path = run_dir / "response.json"
        log_path = run_dir / "worker.log"
        request = WorkerRequest(
            request_id=request_id,
            session_id=self.workspace.session_id,
            project_dir=str(self.workspace.project_dir.resolve()),
            project_name=PROJECT_NAME,
            ghidra_install_dir=str(self.config.ghidra_install_dir),
            max_heap_mb=self.config.max_heap_mb,
            max_cpu=self.config.max_cpu,
            max_response_bytes=self.config.max_response_bytes,
            read_only=read_only,
            program_name=program_name,
            operations=operations,
        )
        self._write_json(request_path, request.model_dump(mode="json", by_alias=True))
        process: subprocess.Popen[bytes] | None = None
        try:
            process = self._spawn(request_path, response_path, log_path)
            self.last_worker_pid = process.pid
            self.active_worker_pid = process.pid
            deadline = self._clock() + min(
                self.config.operation_timeout_seconds,
                timeout_seconds
                if timeout_seconds is not None
                else self.config.operation_timeout_seconds,
            )
            try:
                await self._wait(process, deadline, request_id, not read_only, log_path)
            except asyncio.CancelledError as exc:
                await self._terminate(process)
                message = f"worker request was cancelled: {request_id}"
                raise WorkerCancelledError(
                    message,
                    request_id=request_id,
                    uncertain=not read_only,
                    log_tail=self._read_log_tail(log_path),
                ) from exc
            except WorkerTimeoutError:
                await self._terminate(process)
                raise
            return self._read_response(response_path, request_id, read_only, log_path, run_dir)
        finally:
            self.active_worker_pid = None
            if process is not None and process.poll() is None:
                await self._terminate(process)

    def _spawn(
        self,
        request_path: Path,
        response_path: Path,
        log_path: Path,
    ) -> subprocess.Popen[bytes]:
        environment = {
            key: value
            for key, value in os.environ.items()
            if key in {"PATH", "HOME", "JAVA_HOME", "TMPDIR", "LANG", "LC_ALL", "PYTHONPATH"}
        }
        environment["GHIDRA_INSTALL_DIR"] = str(self.config.ghidra_install_dir)
        log_handle = log_path.open("wb")
        try:
            return subprocess.Popen(  # noqa: S603
                [
                    sys.executable,
                    "-m",
                    "ryuumonbuchi.worker",
                    str(request_path),
                    str(response_path),
                ],
                cwd=str(request_path.parent),
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=log_handle,
                stderr=log_handle,
                start_new_session=True,
            )
        finally:
            log_handle.close()

    async def _wait(
        self,
        process: subprocess.Popen[bytes],
        deadline: float,
        request_id: str,
        uncertain: bool,
        log_path: Path,
    ) -> None:
        while process.poll() is None:
            if self._clock() >= deadline:
                message = f"worker request timed out: {request_id}"
                raise WorkerTimeoutError(
                    message,
                    request_id=request_id,
                    uncertain=uncertain,
                    log_tail=self._read_log_tail(log_path),
                )
            await asyncio.sleep(0.05)
        if process.returncode != 0:
            message = f"worker exited with status {process.returncode}: {request_id}"
            raise WorkerFailedError(
                message,
                request_id=request_id,
                uncertain=uncertain,
                log_tail=self._read_log_tail(log_path),
            )

    def _read_response(
        self,
        response_path: Path,
        request_id: str,
        read_only: bool,
        log_path: Path,
        run_dir: Path,
    ) -> WorkerCall:
        try:
            if not response_path.is_file():
                raise FileNotFoundError(response_path)
            if response_path.stat().st_size > self.config.max_response_bytes:
                message = "response exceeds configured size"
                raise ValueError(message)
            payload = json.loads(response_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            message = f"worker response is missing or malformed: {request_id}"
            raise WorkerFailedError(
                message,
                request_id=request_id,
                uncertain=not read_only,
                log_tail=self._read_log_tail(log_path),
            ) from exc
        try:
            if not isinstance(payload, dict):
                message = "response envelope is not an object"
                raise ValueError(message)
            payload_dict = cast(dict[str, Any], payload)
            if payload_dict.get("ok") is True:
                response = WorkerSuccess.model_validate(payload_dict)
                if response.request_id != request_id:
                    message = "response request ID mismatch"
                    raise ValueError(message)
                shutil.rmtree(run_dir)
                return WorkerCall(request_id, response.result)
            if payload_dict.get("ok") is False:
                response = WorkerFailure.model_validate(payload_dict)
                if response.request_id != request_id:
                    message = "response request ID mismatch"
                    raise ValueError(message)
                shutil.rmtree(run_dir)
                raise WorkerOperationError(
                    response.error.code,
                    response.error.message,
                    request_id=request_id,
                )
            message = "response envelope is not a success or failure"
            raise ValueError(message)
        except WorkerOperationError:
            raise
        except Exception as exc:
            message = f"worker response schema mismatch: {request_id}"
            raise WorkerFailedError(
                message,
                request_id=request_id,
                uncertain=not read_only,
                log_tail=self._read_log_tail(log_path),
            ) from exc

    @staticmethod
    def _write_json(path: Path, payload: dict[str, Any]) -> None:
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        try:
            with temporary.open("w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)

    def _read_log_tail(self, path: Path) -> bytes:
        try:
            with path.open("rb") as handle:
                handle.seek(0, os.SEEK_END)
                size = handle.tell()
                handle.seek(max(0, size - self.config.max_log_tail_bytes))
                return handle.read(self.config.max_log_tail_bytes)
        except OSError:
            return b""

    async def _terminate(self, process: subprocess.Popen[bytes]) -> None:
        pid = process.pid
        with contextlib.suppress(ProcessLookupError):
            os.killpg(pid, signal.SIGTERM)
        deadline = self._clock() + 5.0
        while process.poll() is None and self._clock() < deadline:
            await asyncio.sleep(0.05)
        if process.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(pid, signal.SIGKILL)
        with contextlib.suppress(subprocess.TimeoutExpired, ChildProcessError):
            process.wait(timeout=1)
