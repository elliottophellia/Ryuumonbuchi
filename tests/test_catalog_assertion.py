# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Ryuumonbuchi contributors

"""Catalog assertion branch: array-without-items raises AssertionError."""

from __future__ import annotations

# pyright: reportPrivateUsage=false

import pytest

import ryuumonbuchi.catalog as catalog_module
from ryuumonbuchi.catalog import ToolSpec


def test_assert_catalog_consistency_array_without_items_raises() -> None:
    """The array-without-items assertion branch triggers for malformed specs."""
    bad_spec = ToolSpec(
        name="test.bad",
        backend_method="test_bad",
        description="test description",
        input_schema={
            "type": "object",
            "properties": {
                "bad": {"type": "array"},  # missing "items"
            },
            "required": [],
            "additionalProperties": False,
        },
        read_only=True,
        destructive=False,
        open_world=False,
        batch_allowed=False,
    )
    original = catalog_module.TOOL_SPECS
    # Replace the last spec with our bad one to keep the count at 216
    bad_specs = list(original[:-1]) + [bad_spec]
    try:
        catalog_module.TOOL_SPECS = tuple(bad_specs)
        with pytest.raises(AssertionError, match="array without items"):
            catalog_module.assert_catalog_consistency()
    finally:
        catalog_module.TOOL_SPECS = original
