# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from ryuumonbuchi.session import (
    ProgramNotSelectedError,
    ProgramRecord,
    SessionWorkspace,
    stream_sha256,
    try_cleanup_workspace,
    validate_program_name,
)


def test_workspace_manifest_and_cleanup(workspace: SessionWorkspace) -> None:
    assert stat.S_IMODE(workspace.root.stat().st_mode) == 0o700
    manifest = workspace.read_manifest()
    assert manifest.session_id == workspace.session_id
    assert manifest.programs == {}


def test_manifest_program_transition(workspace: SessionWorkspace, tmp_path: Path) -> None:
    source = tmp_path / "input.bin"
    source.write_bytes(b"abc")
    record = ProgramRecord(
        "hello", str(source), stream_sha256(source), workspace.created_at.isoformat(), False
    )
    workspace.update_program(record)
    assert workspace.require_program("hello") == record
    assert workspace.remove_program("hello") == record


def test_manifest_write_is_atomic(workspace: SessionWorkspace, tmp_path: Path) -> None:
    source = tmp_path / "input.bin"
    source.write_bytes(b"abc")
    workspace.update_program(
        ProgramRecord(
            "hello", str(source), stream_sha256(source), workspace.created_at.isoformat(), False
        )
    )
    assert not list(workspace.root.glob(".session.json.*.tmp"))
    json.loads(workspace.manifest_path.read_text(encoding="utf-8"))


def test_unknown_program_is_rejected_before_worker(workspace: SessionWorkspace) -> None:
    with pytest.raises(ProgramNotSelectedError, match="provide an imported program_name"):
        workspace.require_program("unknown")


def test_program_name_rules() -> None:
    assert validate_program_name("hello") == "hello"
    for name in ("", ".", "..", "a/b", "a\\b", "\x00"):
        with pytest.raises(ValueError):
            validate_program_name(name)


def test_free_stale_workspace_can_be_removed(tmp_path: Path) -> None:
    stale = SessionWorkspace.create("12.0.4", temp_dir=tmp_path)
    root = stale.root
    stale._lock_file.close()  # type: ignore[reportPrivateUsage]
    assert try_cleanup_workspace(root)
    assert not root.exists()
