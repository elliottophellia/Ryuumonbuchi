# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors

"""Models: frame encoding, decoding, schema validation, roundtrips."""

from __future__ import annotations

# pyright: reportUnknownVariableType=false, reportUnknownMemberType=false

import json
import struct

import pytest

from ryuumonbuchi.models import (
    SCHEMA_VERSION,
    BackendConfig,
    BatchRequest,
    BootstrapMessage,
    CallRequest,
    ErrorResponse,
    ShutdownRequest,
    StatusRequest,
    SuccessResponse,
    async_read_frame,
    async_send_frame,
    frame_message,
    new_request_id,
    parse_message,
    read_exact,
    read_frame,
)


def test_schema_version() -> None:
    assert SCHEMA_VERSION == 2


def test_new_request_id_unique() -> None:
    a, b = new_request_id(), new_request_id()
    assert a != b
    assert len(a) == 32


def test_backend_config_to_dict() -> None:
    config = BackendConfig(
        install_dir="/usr/share/ghidra",
        max_heap_mb=512,
        max_cpu=2,
        vm_args=("-Dfoo=bar",),
        classpaths=("/lib",),
        class_files=("/Test.class",),
    )
    d = config.to_dict()
    assert d["install_dir"] == "/usr/share/ghidra"
    assert d["max_heap_mb"] == 512
    assert d["vm_args"] == ["-Dfoo=bar"]
    assert d["classpaths"] == ["/lib"]
    assert d["class_files"] == ["/Test.class"]


    config = BackendConfig(install_dir=None, max_heap_mb=1024, max_cpu=2)
    assert config.max_heap_mb == 1024
    assert config.max_cpu == 2
    assert config.vm_args == ()
    assert config.deterministic is True


def test_bootstrap_message_to_bytes() -> None:
    msg = BootstrapMessage(schema=SCHEMA_VERSION, config={"install_dir": "/test"})
    data = msg.to_bytes()
    assert len(data) > 8
    (length,) = struct.unpack(">Q", data[:8])
    assert length == len(data) - 8


def test_call_request_to_dict() -> None:
    req = CallRequest(
        schema=SCHEMA_VERSION,
        request_id="abc",
        kind="call",
        tool="function.list",
        arguments={"session_id": "s1"},
    )
    d = req.to_dict()
    assert d["kind"] == "call"
    assert d["tool"] == "function.list"
    assert d["request_id"] == "abc"


def test_batch_request_to_dict() -> None:
    req = BatchRequest(
        schema=SCHEMA_VERSION,
        request_id="abc",
        kind="batch",
        session_id="s1",
        operations=[{"tool": "function.list", "arguments": {}}],
    )
    d = req.to_dict()
    assert d["kind"] == "batch"
    assert len(d["operations"]) == 1


def test_status_request_to_dict() -> None:
    req = StatusRequest(schema=SCHEMA_VERSION, request_id="abc", kind="status")
    d = req.to_dict()
    assert d["kind"] == "status"


def test_shutdown_request_to_dict() -> None:
    req = ShutdownRequest(schema=SCHEMA_VERSION, request_id="abc", kind="shutdown")
    d = req.to_dict()
    assert d["kind"] == "shutdown"


def test_success_response_inline_to_dict() -> None:
    resp = SuccessResponse(schema=SCHEMA_VERSION, request_id="abc", ok=True, result={"x": 1})
    d = resp.to_dict()
    assert d["ok"] is True
    assert d["result"] == {"x": 1}
    assert "spilled" not in d


def test_success_response_spilled_to_dict() -> None:
    resp = SuccessResponse(
        schema=SCHEMA_VERSION,
        request_id="abc",
        ok=True,
        result=None,
        spilled=True,
        result_path="/tmp/spill.json",
        preview="...",
        total_bytes=1000,
    )
    d = resp.to_dict()
    assert d["spilled"] is True
    assert d["result_path"] == "/tmp/spill.json"
    assert d["total_bytes"] == 1000


def test_error_response_to_dict() -> None:
    resp = ErrorResponse(
        schema=SCHEMA_VERSION,
        request_id="abc",
        ok=False,
        error={"code": "ghidra_error", "message": "fail"},
    )
    d = resp.to_dict()
    assert d["ok"] is False
    assert d["error"]["code"] == "ghidra_error"


def test_frame_message_roundtrip() -> None:
    payload = {"schema": SCHEMA_VERSION, "test": True}
    data = frame_message(payload)
    assert len(data) > 8
    (length,) = struct.unpack(">Q", data[:8])
    assert length == len(data) - 8
    parsed = parse_message(data[8:])
    assert parsed["test"] is True


def test_parse_message_rejects_non_dict() -> None:
    data = json.dumps([1, 2, 3]).encode("utf-8")
    with pytest.raises(ValueError):
        parse_message(data)


def test_parse_message_rejects_wrong_schema() -> None:
    data = json.dumps({"schema": 1, "test": True}).encode("utf-8")
    with pytest.raises(ValueError):
        parse_message(data)


def test_read_exact_eof() -> None:
    import socket

    a, b = socket.socketpair()
    b.close()
    result = read_exact(a, 8)
    assert result is None
    a.close()


def test_read_exact_partial_eof() -> None:
    import socket

    a, b = socket.socketpair()
    b.send(b"abc")
    b.close()
    result = read_exact(a, 8)
    assert result == b"abc"
    a.close()


def test_read_frame_clean_eof() -> None:
    import socket

    a, b = socket.socketpair()
    b.close()
    result = read_frame(a)
    assert result is None
    a.close()


def test_read_frame_success() -> None:
    import socket

    a, b = socket.socketpair()
    payload = frame_message({"schema": SCHEMA_VERSION, "test": True})
    b.send(payload)
    result = read_frame(a)
    assert result is not None
    assert result["test"] is True
    a.close()
    b.close()


def test_read_frame_truncated_header() -> None:
    import socket

    a, b = socket.socketpair()
    b.send(b"\x00")
    b.close()
    with pytest.raises(ValueError):
        read_frame(a)
    a.close()


def test_read_frame_truncated_body() -> None:
    import socket

    a, b = socket.socketpair()
    header = struct.pack(">Q", 100)
    b.send(header + b"short")
    b.close()
    with pytest.raises(ValueError):
        read_frame(a)
    a.close()


def test_read_frame_zero_length() -> None:
    import socket

    a, b = socket.socketpair()
    header = struct.pack(">Q", 0)
    b.send(header)
    result = read_frame(a)
    assert result == {}
    a.close()
    b.close()
def test_async_send_read_frame_roundtrip() -> None:
    import asyncio
    import socket

    async def _run() -> None:
        loop = asyncio.get_event_loop()
        a, b = socket.socketpair()
        a.setblocking(False)
        b.setblocking(False)
        await async_send_frame(loop, a, {"schema": SCHEMA_VERSION, "async": True})
        result = await async_read_frame(loop, b)
        assert result is not None
        assert result["async"] is True
        a.close()
        b.close()

    asyncio.run(_run())


def test_async_read_frame_eof() -> None:
    import asyncio
    import socket

    async def _run() -> None:
        loop = asyncio.get_event_loop()
        a, b = socket.socketpair()
        a.setblocking(False)
        b.close()
        result = await async_read_frame(loop, a)
        assert result is None
        a.close()

    asyncio.run(_run())


def test_async_read_exact_eof() -> None:
    import asyncio
    import socket

    async def _run() -> None:
        loop = asyncio.get_event_loop()
        a, b = socket.socketpair()
        a.setblocking(False)
        b.close()
        from ryuumonbuchi.models import async_read_exact

        result = await async_read_exact(loop, a, 8)
        assert result is None
        a.close()

    asyncio.run(_run())
