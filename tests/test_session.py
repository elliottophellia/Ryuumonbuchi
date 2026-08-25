# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors

"""Session: RuntimeWorkspace creation, lock, cleanup, run files."""

# pyright: reportPrivateUsage=false

import stat
from pathlib import Path

from ryuumonbuchi.session import RuntimeWorkspace, try_cleanup_workspace


def test_workspace_create(tmp_path: Path) -> None:
    ws = RuntimeWorkspace.create(base=tmp_path)
    assert ws.root.exists()
    assert ws.projects.exists()
    assert ws.runs.exists()
    mode = stat.S_IMODE(ws.root.stat().st_mode)
    assert mode == 0o700
    ws.close()
    assert not ws.root.exists()


def test_workspace_lock_acquired(tmp_path: Path) -> None:
    ws = RuntimeWorkspace.create(base=tmp_path)
    assert ws._lock_handle is not None
    ws.close()


def test_workspace_close_idempotent(tmp_path: Path) -> None:
    ws = RuntimeWorkspace.create(base=tmp_path)
    ws.close()
    ws.close()
    assert not ws.root.exists()


def test_workspace_new_run_file(tmp_path: Path) -> None:
    ws = RuntimeWorkspace.create(base=tmp_path)
    path = ws.new_run_file(prefix="test-", suffix=".log")
    assert path.exists()
    assert path.parent == ws.runs
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600
    ws.close()


def test_workspace_new_run_file_unique(tmp_path: Path) -> None:
    ws = RuntimeWorkspace.create(base=tmp_path)
    p1 = ws.new_run_file()
    p2 = ws.new_run_file()
    assert p1 != p2
    ws.close()


def test_workspace_managed_project_root(tmp_path: Path) -> None:
    ws = RuntimeWorkspace.create(base=tmp_path)
    root = ws.managed_project_root("test_project")
    assert root.exists()
    assert root.parent == ws.projects
    mode = stat.S_IMODE(root.stat().st_mode)
    assert mode == 0o700
    ws.close()


def test_workspace_managed_project_root_sanitizes_name(tmp_path: Path) -> None:
    ws = RuntimeWorkspace.create(base=tmp_path)
    root = ws.managed_project_root("test/project\\name")
    assert "/" not in root.name
    assert "\\" not in root.name
    ws.close()


def test_try_cleanup_workspace_removes_stale(tmp_path: Path) -> None:
    ws = RuntimeWorkspace.create(base=tmp_path)
    root = ws.root
    ws._lock_handle.close()  # type: ignore[union-attr]
    ws._lock_handle = None  # simulate stale
    ws._closed = True
    result = try_cleanup_workspace(root)
    assert result is True
    assert not root.exists()


def test_try_cleanup_workspace_locked(tmp_path: Path) -> None:
    ws = RuntimeWorkspace.create(base=tmp_path)
    root = ws.root
    # Lock is held — should not clean up
    result = try_cleanup_workspace(root)
    assert result is False
    assert root.exists()
    ws.close()


def test_try_cleanup_workspace_no_lock_file(tmp_path: Path) -> None:
    fake_root = tmp_path / "nonexistent"
    result = try_cleanup_workspace(fake_root)
    assert result is False
