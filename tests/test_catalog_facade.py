"""Structural contract for the modular `ryuumonbuchi.catalog` façade.

Pin the registry snapshot, lock `ToolSpec`'s shape, and assert that each
responsibility-focused spec module owns exactly its assigned tools and that the
façade exposes those objects by identity. An extraction cannot silently reorder,
drop, alter, or duplicate any tool definition.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json

import pytest

import ryuumonbuchi.catalog as catalog_module
from ryuumonbuchi.catalog import TOOL_SPECS, ToolSpec
from ryuumonbuchi.catalog import (
    analysis as catalog_analysis,
)
from ryuumonbuchi.catalog import (
    functions as catalog_functions,
)
from ryuumonbuchi.catalog import (
    listing as catalog_listing,
)
from ryuumonbuchi.catalog import (
    program as catalog_program,
)
from ryuumonbuchi.catalog import (
    references as catalog_references,
)
from ryuumonbuchi.catalog import (
    schema as catalog_schema,
)
from ryuumonbuchi.catalog import (
    search as catalog_search,
)
from ryuumonbuchi.catalog import (
    special as catalog_special,
)
from ryuumonbuchi.catalog import (
    symbols as catalog_symbols,
)
from ryuumonbuchi.catalog import (
    types as catalog_types,
)

# Full ordered digest over every spec field; guards against any field mutation.
ORDERED_DIGEST = "6c8f4adc07a273ec7f4fb7c563f459426788fd1e7cde12c329744b3a25416cf9"
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


MODULE_TO_PREFIXES: dict[str, tuple[str, ...]] = {
    "program": ("ghidra", "program", "project", "transaction", "metadata"),
    "analysis": ("analysis", "decomp", "pcode", "graph", "task"),
    "listing": ("memory", "listing", "context", "patch"),
    "search": ("search",),
    "symbols": ("symbol", "comment", "bookmark", "namespace", "class", "tag"),
    "references": ("external", "reference", "equate", "source", "relocation"),
    "functions": ("function", "parameter", "variable", "stackframe"),
    "types": ("type", "layout"),
}

SPECIAL_NAMES = ("health.ping", "mcp.response_format", "headless.run", "operation.batch")

DOMAIN_MODULES = (
    catalog_program,
    catalog_analysis,
    catalog_listing,
    catalog_search,
    catalog_symbols,
    catalog_references,
    catalog_functions,
    catalog_types,
    catalog_special,
)


def _owned_names(module: object) -> set[str]:
    return {spec.name for spec in module.TOOL_SPECS}  # type: ignore[attr-defined]


def _facade_by_identity() -> dict[str, ToolSpec]:
    return {spec.name: spec for spec in TOOL_SPECS}


def test_domain_ownership_matches_prefix_map() -> None:
    for module in DOMAIN_MODULES:
        if module is catalog_special:
            assert _owned_names(module) == set(SPECIAL_NAMES)
            continue
        prefixes = MODULE_TO_PREFIXES[module.__name__.rsplit(".", 1)[-1]]
        for name in _owned_names(module):
            assert name.split(".")[0] in prefixes, f"{module.__name__} owns unexpected {name}"


def test_domain_ownership_is_exhaustive() -> None:
    owned: set[str] = set()
    for module in DOMAIN_MODULES:
        owned |= _owned_names(module)
    assert owned == {spec.name for spec in TOOL_SPECS}
    assert len(owned) == 216


def test_domain_objects_present_by_identity_in_facade() -> None:
    facade = _facade_by_identity()
    for module in DOMAIN_MODULES:
        for spec in module.TOOL_SPECS:
            assert facade[spec.name] is spec, (
                f"{spec.name}: facade object differs from {module.__name__} object"
            )
