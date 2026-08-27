from __future__ import annotations

import os
import re
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest

from ryuumonbuchi.config import AppConfig, ConfigError, validate_ghidra_installation
from ryuumonbuchi.session import RuntimeWorkspace


def _java_major(java_path: str) -> int | None:
    try:
        completed = subprocess.run(  # noqa: S603
            [java_path, "-version"], capture_output=True, text=True, check=False
        )
    except OSError:
        return None
    if completed.returncode != 0:
        return None
    match = re.search(r'"(\d+)(?:\.(\d+))?', completed.stdout + completed.stderr)
    if match is None:
        return None
    major = int(match.group(1))
    return int(match.group(2)) if major == 1 and match.group(2) else major


def _require_live(message: str) -> None:
    if os.environ.get("RYUUMONBUCHI_REQUIRE_LIVE") == "1":
        pytest.fail(message, pytrace=False)
    pytest.skip(message)


@pytest.fixture(autouse=True)
def live_ghidra(request: pytest.FixtureRequest) -> Path | None:
    node: Any = cast(Any, request).node
    marker = getattr(node, "get_closest_marker", None)
    if marker is None or marker("live") is None:
        return None
    ghidra_path = os.environ.get("GHIDRA_INSTALL_DIR", "/usr/share/ghidra")
    try:
        installation = validate_ghidra_installation(ghidra_path)
    except (ConfigError, FileNotFoundError) as exc:
        _require_live(f"live tests require a valid Ghidra installation: {exc}")
        return None
    java_path = shutil.which("java")
    if java_path is None or (_java_major(java_path) or 0) < installation.java_min:
        _require_live(f"live tests require Java {installation.java_min} or newer")
    return installation.path


@pytest.fixture(autouse=True)
def live_server(request: pytest.FixtureRequest) -> Path | None:
    node: Any = cast(Any, request).node
    marker = getattr(node, "get_closest_marker", None)
    if marker is None or marker("live_server") is None:
        return None
    url = os.environ.get("RYUUMONBUCHI_TEST_GHIDRA_URL")
    if not url:
        _require_live("live_server tests require RYUUMONBUCHI_TEST_GHIDRA_URL")
        return None
    ghidra_path = os.environ.get("GHIDRA_INSTALL_DIR", "/usr/share/ghidra")
    try:
        installation = validate_ghidra_installation(ghidra_path)
    except (ConfigError, FileNotFoundError) as exc:
        _require_live(f"live_server tests require a valid Ghidra installation: {exc}")
        return None
    return installation.path


@pytest.fixture
def c_compiler() -> str:
    compiler = shutil.which("cc")
    if compiler is None:
        _require_live("live test requires cc")
    return compiler or ""


@pytest.fixture
def fake_ghidra(tmp_path: Path) -> Path:
    root = tmp_path / "ghidra"
    (root / "Ghidra/Features/PyGhidra/lib").mkdir(parents=True)
    (root / "support").mkdir()
    (root / "Ghidra/application.properties").write_text(
        "application.version=12.0.4\n"
        "application.java.min=21\n"
        "application.python.supported=3.13,3.12,3.11\n",
        encoding="utf-8",
    )
    (root / "Ghidra/Features/PyGhidra/lib/PyGhidra.jar").touch()
    (root / "support/analyzeHeadless").touch()
    return root


@pytest.fixture
def app_config(fake_ghidra: Path) -> AppConfig:
    return AppConfig(
        ghidra_install_dir=fake_ghidra,
        max_heap_mb=256,
        max_cpu=1,
        operation_timeout_seconds=30,
    )


@pytest.fixture
def workspace(tmp_path: Path) -> Iterator[RuntimeWorkspace]:
    value = RuntimeWorkspace.create(base=tmp_path)
    try:
        yield value
    finally:
        value.close()
