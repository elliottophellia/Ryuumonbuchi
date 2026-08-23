# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors

from __future__ import annotations

from typing import Any

import pytest
from pydantic import TypeAdapter, ValidationError

from ryuumonbuchi.models import (
    FunctionGetOperation,
    Page,
    PatchBytesOperation,
    WorkerOperation,
    WorkerRequest,
)


def test_selector_requires_exactly_one() -> None:
    with pytest.raises(ValidationError):
        FunctionGetOperation()
    with pytest.raises(ValidationError):
        FunctionGetOperation(address="1", name="main")


def test_patch_hex_is_bounded_and_even() -> None:
    assert PatchBytesOperation(address="100", bytes_hex="90").bytes_hex == "90"
    with pytest.raises(ValidationError):
        PatchBytesOperation(address="100", bytes_hex="9")

    adapter: TypeAdapter[Any] = TypeAdapter(WorkerOperation)
    assert adapter.validate_python({"action": "function_list"}).action == "function_list"
    assert (
        adapter.validate_python(
            {"action": "program_import", "source_path": "fixture.bin", "program_name": "hello"}
        ).action
        == "program_import"
    )


def test_worker_request_round_trips_alias() -> None:
    request = WorkerRequest(
        request_id="request",
        session_id="session",
        project_dir="/tmp/project",
        ghidra_install_dir="/usr/share/ghidra",
        max_heap_mb=256,
        max_cpu=1,
        max_response_bytes=1024,
        read_only=True,
        program_name="hello",
        operations=[{"action": "function_list"}],
    )
    assert request.model_dump(by_alias=True)["schema"] == 1


def test_page_rejects_negative_offset() -> None:
    with pytest.raises(ValidationError):
        Page(items=[], offset=-1, limit=100, has_more=False)
