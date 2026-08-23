# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from pathlib import Path

import pytest

from ryuumonbuchi.config import AppConfig
from ryuumonbuchi.session import SessionWorkspace


@pytest.fixture
def fake_ghidra(tmp_path: Path) -> Path:
    root = tmp_path / "ghidra"
    (root / "Ghidra/Features/PyGhidra/lib").mkdir(parents=True)
    (root / "support").mkdir()
    (root / "Ghidra/application.properties").write_text(
        "application.version=12.0.4\n"
        "application.java.min=21\n"
        "application.python.supported=3.13,3.12\n",
        encoding="utf-8",
    )
    (root / "Ghidra/Features/PyGhidra/lib/PyGhidra.jar").touch()
    (root / "support/analyzeHeadless").touch()
    return root


@pytest.fixture
def app_config(fake_ghidra: Path) -> AppConfig:
    return AppConfig(fake_ghidra, max_heap_mb=256, max_cpu=1, operation_timeout_seconds=30)


@pytest.fixture
def workspace(tmp_path: Path) -> Iterator[SessionWorkspace]:
    value = SessionWorkspace.create("12.0.4", temp_dir=tmp_path)
    try:
        yield value
    finally:
        asyncio.run(value.close())
