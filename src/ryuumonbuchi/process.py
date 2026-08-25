# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors

"""Persistent isolated backend child with socket-framed IPC."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportPrivateUsage=false

import asyncio
import json
import os
import signal
import struct
import subprocess
import sys
import uuid
from dataclasses import dataclass
from typing import Any

from .config import AppConfig
from .models import (
    SCHEMA_VERSION,
    async_read_frame,
    async_send_frame,
    new_request_id,
    parse_message,
    read_exact,
)
from .session import RuntimeWorkspace


class WorkerRunError(RuntimeError):
    """Base class for parent-side worker lifecycle failures."""


class WorkerTimeoutError(WorkerRunError):
    """Raised when a worker exceeds its wall-clock deadline."""


class WorkerCancelledError(WorkerRunError):
    """Raised when the MCP request is cancelled while a worker runs."""


class WorkerFailedError(WorkerRunError):
    """Raised when a worker exits or responds with an invalid envelope."""

    def __init__(self, message: str, log_tail: str = "") -> None:
        super().__init__(message)
        self.log_tail = log_tail


class WorkerOperationError(WorkerRunError):
    """Raised for a valid, known operation error from a clean worker."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


@dataclass(frozen=True, slots=True)
class WorkerCall:
    """Successful worker result plus request identity."""

    request_id: str
    result: Any


_MAX_FRAME_BYTES = 512 * 1024 * 1024

_INHERITED_ENV_KEYS: tuple[str, ...] = (
    "PATH",
    "HOME",
    "JAVA_HOME",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "PYTHONPATH",
    "GHIDRA_INSTALL_DIR",
)


class PersistentWorker:
    """Launch exactly one isolated worker for the MCP process lifetime."""

    def __init__(self, config: AppConfig, workspace: RuntimeWorkspace) -> None:
        self._config = config
        self._workspace = workspace
        self._lock = asyncio.Lock()
        self._process: subprocess.Popen[bytes] | None = None
        self._child_sock: Any = None
        self._parent_sock: Any = None
        self._generation: str = str(uuid.uuid4())
        self._started = False
        self._jvm_started = False
        self._session_count = 0
        self._task_count = 0
        self._active_task_ids: list[str] = []
        self._log_tail: str = ""

    @property
    def generation(self) -> str:
        return self._generation

    @property
    def is_started(self) -> bool:
        return self._process is not None and self._process.poll() is None

    @property
    def jvm_started(self) -> bool:
        return self._jvm_started

    @property
    def log_tail(self) -> str:
        return self._log_tail

    def child_pid(self) -> int | None:
        if self._process is not None and self._process.poll() is None:
            return self._process.pid
        return None

    async def _ensure_started(self) -> None:
        if self._process is not None and self._process.poll() is None:
            return
        await self._spawn()

    async def _spawn(self) -> None:
        import socket

        parent_sock, child_sock = socket.socketpair()
        parent_sock.setblocking(False)
        child_sock.setblocking(True)

        env: dict[str, str] = {}
        for key in _INHERITED_ENV_KEYS:
            val = os.environ.get(key)
            if val is not None:
                env[key] = val

        child_fd = child_sock.fileno()
        log_fd = os.open(str(self._workspace.worker_log), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)

        self._process = subprocess.Popen(  # noqa: S603
            [sys.executable, "-m", "ryuumonbuchi.worker"],
            env={
                **env,
                # Tell the worker which inherited fd carries its IPC socket;
                # pass_fds preserves the parent fd number verbatim (no remap),
                # so the worker must read it dynamically rather than hardcode fd 3.
                "RYUUMONBUCHI_WORKER_FD": str(child_fd),
            },
            stdin=subprocess.DEVNULL,
            stdout=log_fd,
            stderr=log_fd,
            pass_fds=(child_fd,),
            start_new_session=True,
        )
        os.close(log_fd)
        child_sock.close()

        self._parent_sock = parent_sock
        loop = asyncio.get_event_loop()

        # Send bootstrap
        bootstrap = {
            "schema": SCHEMA_VERSION,
            "config": {
                "install_dir": str(self._config.ghidra_install_dir),
                "max_heap_mb": self._config.max_heap_mb,
                "max_cpu": self._config.max_cpu,
                "vm_args": list(self._config.vm_args),
                "classpaths": list(self._config.classpaths),
                "class_files": list(self._config.class_files),
                "deterministic": True,
                "workspace_root": str(self._workspace.root),
                "max_import_bytes": self._config.max_import_bytes,
                "max_response_bytes": self._config.max_response_bytes,
                "max_log_tail_bytes": self._config.max_log_tail_bytes,
                "allow_export": self._config.allow_export,
                "allow_import_bytes": self._config.allow_import_bytes,
            },
        }
        await async_send_frame(loop, self._parent_sock, bootstrap)
        self._started = True
        self._generation = str(uuid.uuid4())
        self._jvm_started = False

    async def call(
        self,
        tool: str,
        arguments: dict[str, Any],
        *,
        timeout: int | None = None,
    ) -> WorkerCall:
        """Execute one tool through the persistent child."""
        deadline = (
            timeout if timeout is not None
            else self._config.operation_timeout_seconds
        )
        request_id = new_request_id()
        request = {
            "schema": SCHEMA_VERSION,
            "request_id": request_id,
            "kind": "call",
            "tool": tool,
            "arguments": arguments,
        }
        return await self._request(request_id, request, deadline)

    async def batch(
        self,
        session_id: str,
        operations: list[dict[str, Any]],
        *,
        timeout: int | None = None,
    ) -> WorkerCall:
        """Execute an atomic batch through the persistent child."""
        deadline = (
            timeout if timeout is not None
            else self._config.operation_timeout_seconds
        )
        request_id = new_request_id()
        request = {
            "schema": SCHEMA_VERSION,
            "request_id": request_id,
            "kind": "batch",
            "session_id": session_id,
            "operations": operations,
        }
        return await self._request(request_id, request, deadline)

    async def status(self) -> dict[str, Any]:
        """Query backend status without starting the JVM."""
        if self._process is None or self._process.poll() is not None:
            return {
                "generation": self._generation,
                "jvm_started": False,
                "child_pid": None,
                "session_count": self._session_count,
                "task_count": self._task_count,
                "active_task_ids": list(self._active_task_ids),
            }
        request_id = new_request_id()
        request = {
            "schema": SCHEMA_VERSION,
            "request_id": request_id,
            "kind": "status",
        }
        try:
            call = await self._request(request_id, request, 10)
            result = call.result
            if isinstance(result, dict):
                self._jvm_started = result.get("jvm_started", False)
                self._session_count = result.get("session_count", 0)
                self._task_count = result.get("task_count", 0)
                self._active_task_ids = result.get("active_task_ids", [])
            return result if isinstance(result, dict) else {}
        except WorkerRunError:
            return {
                "generation": self._generation,
                "jvm_started": False,
                "child_pid": None,
                "session_count": self._session_count,
                "task_count": self._task_count,
                "active_task_ids": list(self._active_task_ids),
            }

    async def shutdown(self) -> None:
        """Gracefully shut down the persistent child."""
        if self._process is None:
            return
        proc = self._process
        if proc.poll() is None:
            try:
                request_id = new_request_id()
                request = {
                    "schema": SCHEMA_VERSION,
                    "request_id": request_id,
                    "kind": "shutdown",
                }
                loop = asyncio.get_event_loop()
                if self._parent_sock is not None:
                    await async_send_frame(loop, self._parent_sock, request)
                    try:
                        await asyncio.wait_for(
                            loop.sock_recv(self._parent_sock, 8), timeout=5
                        )
                    except (OSError, asyncio.TimeoutError):
                        pass
            except (OSError, WorkerRunError):
                pass
            with __import__("contextlib").suppress(ProcessLookupError):
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                with __import__("contextlib").suppress(ProcessLookupError):
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                proc.wait(timeout=5)
        self._parent_sock = None
        self._process = None
        self._started = False
        self._jvm_started = False

    async def _request(
        self, request_id: str, request: dict[str, Any], deadline: int
    ) -> WorkerCall:
        async with self._lock:
            await self._ensure_started()
            loop = asyncio.get_event_loop()
            assert self._parent_sock is not None

            try:
                await async_send_frame(loop, self._parent_sock, request)
                response = await asyncio.wait_for(
                    async_read_frame(loop, self._parent_sock), timeout=deadline
                )
            except asyncio.TimeoutError as exc:
                await self._handle_failure("worker_timeout")
                msg = f"worker timed out after {deadline}s"
                raise WorkerTimeoutError(msg) from exc
            except (ConnectionError, OSError) as exc:
                await self._handle_failure("worker_failed")
                msg = f"worker connection error: {exc}"
                raise WorkerFailedError(msg, self._log_tail) from exc
            except asyncio.CancelledError:
                await self._handle_failure("worker_cancelled")
                raise

            if response is None:
                await self._handle_failure("worker_failed")
                msg = "worker closed connection"
                raise WorkerFailedError(msg, self._log_tail)

            if response.get("request_id") != request_id:
                await self._handle_failure("worker_failed")
                msg = f"request ID mismatch: expected {request_id}, got {response.get('request_id')}"
                raise WorkerFailedError(msg, self._log_tail)

            if not response.get("ok", False):
                error = response.get("error", {})
                code = error.get("code", "ghidra_error")
                message = error.get("message", "unknown error")
                if code in ("worker_timeout", "worker_cancelled", "worker_failed"):
                    await self._handle_failure(code)
                    if code == "worker_timeout":
                        raise WorkerTimeoutError(message) from None
                    if code == "worker_cancelled":
                        raise WorkerCancelledError(message) from None
                    raise WorkerFailedError(message, self._log_tail) from None
                raise WorkerOperationError(code, message) from None

            result = response.get("result")
            if response.get("spilled"):
                result_path = response.get("result_path")
                if result_path:
                    try:
                        with open(result_path) as f:
                            result = json.load(f)
                    except (OSError, json.JSONDecodeError) as exc:
                        msg = f"failed to read spilled result: {exc}"
                        raise WorkerFailedError(msg, self._log_tail) from exc

            return WorkerCall(request_id=request_id, result=result)

    async def _handle_failure(self, code: str) -> None:
        """Terminate the process group and reset generation."""
        proc = self._process
        self._parent_sock = None
        self._process = None
        self._started = False
        self._jvm_started = False
        self._session_count = 0
        self._task_count = 0
        self._active_task_ids = []
        self._generation = str(uuid.uuid4())

        if proc is not None and proc.poll() is None:
            with __import__("contextlib").suppress(ProcessLookupError):
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                with __import__("contextlib").suppress(ProcessLookupError):
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                proc.wait(timeout=5)

        # Read log tail
        try:
            log_data = self._workspace.worker_log.read_bytes()
            bound = self._config.max_log_tail_bytes
            self._log_tail = log_data[-bound:].decode("utf-8", errors="replace")
        except OSError:
            pass

    def _read_exact_sync(self, sock: Any, n: int) -> bytes | None:
        return read_exact(sock, n)

    def _read_frame_sync(self, sock: Any) -> dict[str, Any] | None:
        header = read_exact(sock, 8)
        if header is None or len(header) < 8:
            return None
        (length,) = struct.unpack(">Q", header)
        if length > _MAX_FRAME_BYTES:
            raise ValueError("frame too large")
        if length == 0:
            return {}
        body = read_exact(sock, length)
        if body is None or len(body) < length:
            return None
        return parse_message(body)
