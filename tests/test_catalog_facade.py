"""Structural contract for the modular `ryuumonbuchi.catalog` façade.

Pin the registry snapshot and lock `ToolSpec`'s shape so that extracting
responsibility-focused spec modules behind an unchanged façade cannot silently
reorder, drop, or alter any tool definition.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json

import pytest

import ryuumonbuchi.catalog as catalog_module
from ryuumonbuchi import catalog_schema
from ryuumonbuchi.catalog import TOOL_SPECS, ToolSpec

# Full ordered digest over every spec field; guards against any field mutation.
ORDERED_DIGEST = "206c87dfd8bb05eae209ed3455965fe0710be531345e92617d07a54f81e8529e"
# Name-order digest; guards the observable `TOOL_SPECS` order independently.
NAME_ORDER_DIGEST = "ec7a7d374f67524cb2b73f76954d737ef77d3d0662c062202a14c07215998fa5"


def _ordered_digest() -> str:
    payload = json.dumps(
        [dataclasses.asdict(spec) for spec in TOOL_SPECS],
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def _name_order_digest() -> str:
    return hashlib.sha256("\n".join(spec.name for spec in TOOL_SPECS).encode()).hexdigest()


def test_registry_snapshot_digests() -> None:
    assert _ordered_digest() == ORDERED_DIGEST
    assert _name_order_digest() == NAME_ORDER_DIGEST


def test_tool_spec_is_frozen_slotted_eight_field_dataclass() -> None:
    assert dataclasses.is_dataclass(ToolSpec)
    assert [field.name for field in dataclasses.fields(ToolSpec)] == [
        "name",
        "backend_method",
        "description",
        "input_schema",
        "read_only",
        "destructive",
        "open_world",
        "batch_allowed",
    ]
    assert ToolSpec.__slots__ == (
        "name",
        "backend_method",
        "description",
        "input_schema",
        "read_only",
        "destructive",
        "open_world",
        "batch_allowed",
    )
    spec = TOOL_SPECS[0]
    with pytest.raises(dataclasses.FrozenInstanceError):
        spec.name = "mutated"  # type: ignore[misc]


def test_facade_re_exports_schema_definitions() -> None:
    assert catalog_module.ToolSpec is catalog_schema.ToolSpec
    assert catalog_module.ADDRESS_SCHEMA is catalog_schema.ADDRESS_SCHEMA
    assert catalog_module.ADDRESS_PARAM_NAMES is catalog_schema.ADDRESS_PARAM_NAMES
