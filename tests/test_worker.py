# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors
# pyright: reportPrivateUsage=false

from __future__ import annotations

from ryuumonbuchi.models import ByteSearchOperation
from ryuumonbuchi.worker.operations import (  # type: ignore[reportPrivateUsage]
    _page,
    _pattern_arrays,
)


def test_bounded_page_stops_after_one_extra_item() -> None:
    page = _page(iter(range(4)), offset=1, limit=2)
    assert page.items == [1, 2]
    assert page.has_more is True


def test_byte_pattern_mask_supports_wildcards() -> None:
    values, masks = _pattern_arrays(ByteSearchOperation(pattern="90 ?? 90", mask="ff 00 ff"))
    assert values == [0x90, 0, 0x90]
    assert masks == [0xFF, 0, 0xFF]
