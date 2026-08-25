# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors

"""Protocol-v2 wire models for persistent child IPC."""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false

from __future__ import annotations
import json
import struct
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING
from typing import Any
if TYPE_CHECKING:
    import asyncio
    from socket import socket

SCHEMA_VERSION = 2

# Frame format: 8-byte big-endian unsigned length + UTF-8 JSON payload
_MAX_FRAME_BYTES = 512 * 1024 * 1024  # 512 MiB hard limit per frame


@dataclass(frozen=True, slots=True)
class BackendConfig:
    """Immutable backend startup configuration passed to the persistent child."""

    install_dir: str | None
    max_heap_mb: int
    max_cpu: int
    vm_args: tuple[str, ...] = ()
    classpaths: tuple[str, ...] = ()
    class_files: tuple[str, ...] = ()
    deterministic: bool = True
    workspace_root: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "install_dir": self.install_dir,
            "max_heap_mb": self.max_heap_mb,
            "max_cpu": self.max_cpu,
            "vm_args": list(self.vm_args),
            "classpaths": list(self.classpaths),
            "class_files": list(self.class_files),
            "deterministic": self.deterministic,
            "workspace_root": self.workspace_root,
        }


@dataclass(frozen=True, slots=True)
class BootstrapMessage:
    """Initial parent-to-child message with runtime configuration."""

    schema: int
    config: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"schema": SCHEMA_VERSION, "config": self.config}

    def to_bytes(self) -> bytes:
        return frame_message(self.to_dict())


@dataclass(frozen=True, slots=True)
class CallRequest:
    """Parent-to-child: execute one tool."""

    schema: int
    request_id: str
    kind: str  # always "call"
    tool: str
    arguments: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_VERSION,
            "request_id": self.request_id,
            "kind": "call",
            "tool": self.tool,
            "arguments": self.arguments,
        }


@dataclass(frozen=True, slots=True)
class BatchRequest:
    """Parent-to-child: execute an atomic batch of operations."""

    schema: int
    request_id: str
    kind: str  # always "batch"
    session_id: str
    operations: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_VERSION,
            "request_id": self.request_id,
            "kind": "batch",
            "session_id": self.session_id,
            "operations": self.operations,
        }


@dataclass(frozen=True, slots=True)
class StatusRequest:
    """Parent-to-child: query backend status without starting the JVM."""

    schema: int
    request_id: str
    kind: str  # always "status"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_VERSION,
            "request_id": self.request_id,
            "kind": "status",
        }


@dataclass(frozen=True, slots=True)
class ShutdownRequest:
    """Parent-to-child: gracefully shut down the backend."""

    schema: int
    request_id: str
    kind: str  # always "shutdown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_VERSION,
            "request_id": self.request_id,
            "kind": "shutdown",
        }


@dataclass(frozen=True, slots=True)
class SuccessResponse:
    """Child-to-parent: successful result, possibly spilled to a file."""

    schema: int
    request_id: str
    ok: bool  # always True
    result: Any
    spilled: bool = False
    result_path: str | None = None
    preview: str | None = None
    total_bytes: int | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "schema": SCHEMA_VERSION,
            "request_id": self.request_id,
            "ok": True,
            "result": self.result,
        }
        if self.spilled:
            d["spilled"] = True
            d["result_path"] = self.result_path
            d["preview"] = self.preview
            d["total_bytes"] = self.total_bytes
        return d


@dataclass(frozen=True, slots=True)
class ErrorResponse:
    """Child-to-parent: failure with a stable error code and message."""

    schema: int
    request_id: str
    ok: bool  # always False
    error: dict[str, Any]  # {"code": str, "message": str, ...}

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_VERSION,
            "request_id": self.request_id,
            "ok": False,
            "error": self.error,
        }


def new_request_id() -> str:
    return uuid.uuid4().hex


def frame_message(payload: dict[str, Any]) -> bytes:
    """Encode a message as 8-byte big-endian length + UTF-8 JSON."""
    data = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
    if len(data) > _MAX_FRAME_BYTES:
        msg = f"frame too large: {len(data)} bytes"
        raise ValueError(msg)
    return struct.pack(">Q", len(data)) + data


def parse_message(data: bytes) -> dict[str, Any]:
    """Parse a JSON message payload, validating schema version."""
    payload = json.loads(data.decode("utf-8"))
    if not isinstance(payload, dict):
        msg = "message is not a JSON object"
        raise ValueError(msg)
    schema = payload.get("schema")
    if schema != SCHEMA_VERSION:
        msg = f"unsupported schema version: {schema}, expected {SCHEMA_VERSION}"
        raise ValueError(msg)
    return payload


def read_exact(sock: socket, n: int) -> bytes | None:
    """Read exactly n bytes from a socket; return None on clean EOF."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None if not buf else bytes(buf)
        buf.extend(chunk)
    return bytes(buf)


def read_frame(sock: socket) -> dict[str, Any] | None:
    """Read one complete framed message; return None on clean EOF."""
    header = read_exact(sock, 8)
    if header is None:
        return None
    if len(header) < 8:
        msg = "truncated frame header"
        raise ValueError(msg)
    (length,) = struct.unpack(">Q", header)
    if length > _MAX_FRAME_BYTES:
        msg = f"frame too large: {length} bytes"
        raise ValueError(msg)
    if length == 0:
        return {}
    body = read_exact(sock, length)
    if body is None or len(body) < length:
        msg = "truncated frame body"
        raise ValueError(msg)
    return parse_message(body)


async def async_read_exact(loop: asyncio.AbstractEventLoop, sock: socket, n: int) -> bytes | None:
    """Async read exactly n bytes from a socket using the event loop."""
    import asyncio as _asyncio
    buf = bytearray()
    while len(buf) < n:
        remaining = n - len(buf)
        chunk = await _asyncio.wait_for(loop.sock_recv(sock, remaining), timeout=300)
        if not chunk:
            return None if not buf else bytes(buf)
        buf.extend(chunk)
    return bytes(buf)


async def async_read_frame(loop: asyncio.AbstractEventLoop, sock: socket) -> dict[str, Any] | None:
    """Async read one complete framed message."""
    header = await async_read_exact(loop, sock, 8)
    if header is None:
        return None
    if len(header) < 8:
        msg = "truncated frame header"
        raise ValueError(msg)
    (length,) = struct.unpack(">Q", header)
    if length > _MAX_FRAME_BYTES:
        msg = f"frame too large: {length} bytes"
        raise ValueError(msg)
    if length == 0:
        return {}
    body = await async_read_exact(loop, sock, length)
    if body is None or len(body) < length:
        msg = "truncated frame body"
        raise ValueError(msg)
    return parse_message(body)


async def async_send_frame(loop: asyncio.AbstractEventLoop, sock: socket, payload: dict[str, Any]) -> None:
    """Async send one complete framed message."""
    import asyncio as _asyncio
    data = frame_message(payload)
    await _asyncio.wait_for(loop.sock_sendall(sock, data), timeout=60)
