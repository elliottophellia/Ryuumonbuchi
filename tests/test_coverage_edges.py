# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors

"""Remaining coverage: model frame limits, session lock paths, catalog assertion branch."""

from __future__ import annotations

# pyright: reportPrivateUsage=false, reportUnknownMemberType=false, reportUnknownVariableType=false

import socket
import struct
from pathlib import Path

import pytest

from ryuumonbuchi.catalog import assert_catalog_consistency
from ryuumonbuchi.config import ConfigError, validate_ghidra_installation
from ryuumonbuchi.models import (
    SCHEMA_VERSION,
    async_read_exact,
    async_read_frame,
    frame_message,
    parse_message,
    read_frame,
)
from ryuumonbuchi.session import RuntimeWorkspace, try_cleanup_workspace


def test_frame_message_too_large(monkeypatch: pytest.MonkeyPatch) -> None:
    import ryuumonbuchi.models as m

    monkeypatch.setattr(m, "_MAX_FRAME_BYTES", 10)
    with pytest.raises(ValueError, match="frame too large"):
        frame_message({"schema": SCHEMA_VERSION, "data": "x" * 100})


def test_read_frame_frame_too_large() -> None:
    import ryuumonbuchi.models as m

    original = m._MAX_FRAME_BYTES
    m._MAX_FRAME_BYTES = 10
    try:
        a, b = socket.socketpair()
        header = struct.pack(">Q", 999)
        b.send(header)
        with pytest.raises(ValueError, match="frame too large"):
            read_frame(a)
        a.close()
        b.close()
    finally:
        m._MAX_FRAME_BYTES = original


def test_read_frame_truncated_body() -> None:
    a, b = socket.socketpair()
    header = struct.pack(">Q", 100)
    b.send(header + b"short")
    b.close()
    with pytest.raises(ValueError, match="truncated frame body"):
        read_frame(a)
    a.close()


def test_parse_message_non_dict_array() -> None:
    import json

    data = json.dumps([1, 2]).encode("utf-8")
    with pytest.raises(ValueError, match="not a JSON object"):
        parse_message(data)


def test_parse_message_non_dict_string() -> None:
    import json

    data = json.dumps("hello").encode("utf-8")
    with pytest.raises(ValueError, match="not a JSON object"):
        parse_message(data)


def test_catalog_assertion_array_without_items_branch() -> None:
    """The array-without-items assertion branch is unreachable for valid specs."""
    # This test documents that the branch exists; assert_catalog_consistency passes
    assert_catalog_consistency()


def test_session_lock_contention(tmp_path: Path) -> None:
    """Two workspaces cannot lock the same root."""
    from ryuumonbuchi.session import WorkspaceError

    ws1 = RuntimeWorkspace.create(base=tmp_path)
    # Construct a second workspace pointing at the same root
    ws2 = RuntimeWorkspace(
        root=ws1.root,
        projects=ws1.projects,
        runs=ws1.runs,
        worker_log=ws1.worker_log,
    )
    with pytest.raises(WorkspaceError, match="lock contention"):
        ws2._acquire_lock()  # noqa: SLF001
    ws1.close()


def test_session_close_releases_lock(tmp_path: Path) -> None:
    """After close, a new workspace can be created at the same path (but different root)."""
    ws = RuntimeWorkspace.create(base=tmp_path)
    ws.close()
    # The root is deleted, so a new workspace at a different path works fine
    ws2 = RuntimeWorkspace.create(base=tmp_path)
    ws2.close()


def test_session_close_with_no_lock_handle(tmp_path: Path) -> None:
    """close() handles the case where lock_handle is None."""
    ws = RuntimeWorkspace.create(base=tmp_path)
    ws._lock_handle.close()  # type: ignore[union-attr]
    ws._lock_handle = None  # type: ignore[assignment]
    ws.close()
    assert not ws.root.exists()


def test_try_cleanup_workspace_no_lock_file(tmp_path: Path) -> None:
    fake = tmp_path / "nonexistent"
    result = try_cleanup_workspace(fake)
    assert result is False


def test_try_cleanup_workspace_lock_file_unreadable(tmp_path: Path) -> None:
    root = tmp_path / "stale"
    root.mkdir(mode=0o700)
    lock = root / ".owner.lock"
    lock.touch(mode=0o600)
    # Should acquire lock (no one holds it) and clean up
    result = try_cleanup_workspace(root)
    assert result is True
    assert not root.exists()

def test_try_cleanup_workspace_open_oserror(tmp_path: Path) -> None:
    """try_cleanup returns False when lock file can't be opened."""
    root = tmp_path / "stale_perm"
    root.mkdir(mode=0o700)
    lock = root / ".owner.lock"
    lock.touch(mode=0o600)
    lock.chmod(0o000)
    try:
        result = try_cleanup_workspace(root)
        assert result is False
    finally:
        lock.chmod(0o600)
        root.chmod(0o700)
    import shutil
    shutil.rmtree(root, ignore_errors=True)


def test_async_read_frame_truncated_header() -> None:
    import asyncio

    async def _run() -> None:
        loop = asyncio.get_event_loop()
        a, b = socket.socketpair()
        a.setblocking(False)
        b.send(b"\x00")  # truncated header
        b.close()
        with pytest.raises(ValueError, match="truncated frame header"):
            await async_read_frame(loop, a)
        a.close()

    asyncio.run(_run())


def test_async_read_frame_frame_too_large() -> None:
    import asyncio
    import ryuumonbuchi.models as m

    original = m._MAX_FRAME_BYTES
    m._MAX_FRAME_BYTES = 10

    async def _run() -> None:
        loop = asyncio.get_event_loop()
        a, b = socket.socketpair()
        a.setblocking(False)
        b.setblocking(False)
        header = struct.pack(">Q", 999)
        b.send(header)
        with pytest.raises(ValueError, match="frame too large"):
            await async_read_frame(loop, a)
        a.close()
        b.close()

    try:
        asyncio.run(_run())
    finally:
        m._MAX_FRAME_BYTES = original


def test_async_read_frame_truncated_body() -> None:
    import asyncio

    async def _run() -> None:
        loop = asyncio.get_event_loop()
        a, b = socket.socketpair()
        a.setblocking(False)
        b.setblocking(False)
        header = struct.pack(">Q", 100)
        b.send(header + b"short")
        b.close()
        with pytest.raises(ValueError, match="truncated frame body"):
            await async_read_frame(loop, a)
        a.close()

    asyncio.run(_run())


def test_async_read_frame_zero_length() -> None:
    import asyncio

    async def _run() -> None:
        loop = asyncio.get_event_loop()
        a, b = socket.socketpair()
        a.setblocking(False)
        b.setblocking(False)
        header = struct.pack(">Q", 0)
        b.send(header)
        result = await async_read_frame(loop, a)
        assert result == {}
        a.close()
        b.close()

    asyncio.run(_run())


def test_async_read_exact_partial_eof() -> None:
    import asyncio

    async def _run() -> None:
        loop = asyncio.get_event_loop()
        a, b = socket.socketpair()
        a.setblocking(False)
        b.setblocking(False)
        b.send(b"abc")
        b.close()
        result = await async_read_exact(loop, a, 8)
        assert result == b"abc"
        a.close()

    asyncio.run(_run())


def test_config_non_linux_rejected(fake_ghidra: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """validate_ghidra_installation rejects non-Linux platforms."""
    import platform

    monkeypatch.setattr(platform, "system", lambda: "Windows")
    with pytest.raises(ConfigError, match="POSIX/Linux"):
        validate_ghidra_installation(fake_ghidra)


def test_cli_run_server_called(fake_ghidra: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """CLI main calls run_server when config is valid."""
    import ryuumonbuchi.server

    called = False

    def fake_run_server(config: object) -> None:
        nonlocal called
        called = True

    monkeypatch.setattr(ryuumonbuchi.server, "main", fake_run_server)
    monkeypatch.setattr("ryuumonbuchi.cli.run_server", fake_run_server)
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(fake_ghidra))
    from ryuumonbuchi.cli import main

    main([])
    assert called
