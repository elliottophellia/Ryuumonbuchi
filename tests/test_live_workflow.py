# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors

"""Live regression test: the Flag Printer 2100 CTF workflow."""

from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path

import pytest
from mcp.client import Client

from ryuumonbuchi.config import AppConfig, build_config
from ryuumonbuchi.server import create_server

pytestmark = pytest.mark.live

FIXTURE = Path(__file__).resolve().parent / "print_flag"
SLEEP_INSTRUCTION_ADDRESS = "001019e7"
EXPECTED_FLAG = "Alpaca{G00d_Morning_AlpacaH4ck!}"


def _config() -> AppConfig:
    return build_config(max_cpu=1, max_heap_mb=512)


def test_print_flag_workflow_import_patch_export_run(tmp_path: Path) -> None:
    async def run() -> None:
        server = create_server(_config())
        async with Client(server, raise_exceptions=True) as client:
            imported = await client.call_tool(
                "program_import", {"source_path": str(FIXTURE), "program_name": "print_flag"}
            )
            assert not imported.is_error, imported

            decompiled = await client.call_tool(
                "function_decompile", {"program_name": "print_flag", "name": "main"}
            )
            assert not decompiled.is_error, decompiled
            assert "sleep(0x8d12cea0)" in decompiled.structured_content["c_code"]

            patched = await client.call_tool(
                "edit_patch_bytes",
                {
                    "program_name": "print_flag",
                    "address": SLEEP_INSTRUCTION_ADDRESS,
                    "bytes_hex": "bf00000000",
                },
            )
            assert not patched.is_error, patched
            assert patched.structured_content["changed"] is True


            analyzers = await client.call_tool(
                "analysis_list_analyzers", {"program_name": "print_flag"}
            )
            assert not analyzers.is_error, analyzers
            assert analyzers.structured_content["items"], analyzers

            defined = await client.call_tool(
                "edit_set_data_type",
                {
                    "program_name": "print_flag",
                    "address": "00102010",
                    "data_type": "string",
                    "length": 16,
                },
            )
            assert not defined.is_error, defined
            assert defined.structured_content["changed"] is True

            destination = tmp_path / "patched_flag"
            exported = await client.call_tool(
                "program_export",
                {"program_name": "print_flag", "destination_path": str(destination)},
            )
            assert not exported.is_error, exported
            assert exported.structured_content["bytes_written"] == FIXTURE.stat().st_size

    asyncio.run(run())

    completed = subprocess.run(  # noqa: S603
        [str(tmp_path / "patched_flag")],
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    assert EXPECTED_FLAG in completed.stdout.decode()


def test_print_flag_export_refuses_overwrite(tmp_path: Path) -> None:
    destination = tmp_path / "patched_flag"
    destination.write_bytes(b"occupied")

    async def run() -> None:
        server = create_server(_config())
        async with Client(server, raise_exceptions=True) as client:
            imported = await client.call_tool(
                "program_import", {"source_path": str(FIXTURE), "program_name": "print_flag"}
            )
            assert not imported.is_error, imported
            refused = await client.call_tool(
                "program_export",
                {"program_name": "print_flag", "destination_path": str(destination)},
            )
            assert refused.is_error, refused
            assert "destination already exists" in str(refused.content), refused
            overwritten = await client.call_tool(
                "program_export",
                {
                    "program_name": "print_flag",
                    "destination_path": str(destination),
                    "overwrite": True,
                },
            )
            assert not overwritten.is_error, overwritten
            assert overwritten.structured_content["overwritten"] is True

    asyncio.run(run())
    assert destination.read_bytes()[:4] == b"\x7fELF"
