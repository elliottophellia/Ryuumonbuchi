"""Authoritative 216-tool registry: names, schemas, annotations, batch eligibility."""

from __future__ import annotations

from .analysis import TOOL_SPECS as _ANALYSIS_SPECS
from .functions import TOOL_SPECS as _FUNCTIONS_SPECS
from .listing import TOOL_SPECS as _LISTING_SPECS
from .order import order_specs as _order_specs
from .program import TOOL_SPECS as _PROGRAM_SPECS
from .references import TOOL_SPECS as _REFERENCES_SPECS
from .schema import (
    ADDRESS_PARAM_NAMES,
    ADDRESS_SCHEMA,
    ToolSpec,
)
from .schema import (
    apply_schema_bounds as _apply_schema_bounds,
)
from .search import TOOL_SPECS as _SEARCH_SPECS
from .special import TOOL_SPECS as _SPECIAL_SPECS
from .symbols import TOOL_SPECS as _SYMBOLS_SPECS
from .types import TOOL_SPECS as _TYPES_SPECS

__all__ = [
    "ADDRESS_PARAM_NAMES",
    "ADDRESS_SCHEMA",
    "TOOL_BY_NAME",
    "TOOL_SPECS",
    "ToolSpec",
    "assert_catalog_consistency",
    "get_tool",
]


def _build_specs() -> tuple[ToolSpec, ...]:
    specs: list[ToolSpec] = []
    specs.extend(_PROGRAM_SPECS)
    specs.extend(_ANALYSIS_SPECS)
    specs.extend(_LISTING_SPECS)
    specs.extend(_SEARCH_SPECS)
    specs.extend(_SYMBOLS_SPECS)
    specs.extend(_REFERENCES_SPECS)
    specs.extend(_FUNCTIONS_SPECS)
    specs.extend(_TYPES_SPECS)
    specs.extend(_SPECIAL_SPECS)
    return tuple(_order_specs(_apply_schema_bounds(specs)))


TOOL_SPECS: tuple[ToolSpec, ...] = _build_specs()
TOOL_BY_NAME: dict[str, ToolSpec] = {spec.name: spec for spec in TOOL_SPECS}


def get_tool(name: str) -> ToolSpec | None:
    """Look up a tool spec by dotted name."""
    return TOOL_BY_NAME.get(name)


def assert_catalog_consistency() -> None:
    """Verify no duplicates, exact count, no underscore legacy names, valid
    Draft 2020-12 schemas, complete special routing, and mutation/read-only
    classification."""
    import jsonschema

    names = [spec.name for spec in TOOL_SPECS]
    assert len(names) == len(set(names)), "duplicate tool names"
    assert len(TOOL_SPECS) == 216, f"expected 216 tools, got {len(TOOL_SPECS)}"
    for name in names:
        assert "." in name, f"non-dotted tool name: {name}"

    # Valid Draft 2020-12 schemas.
    Draft202012Validator = jsonschema.Draft202012Validator
    special = {"health.ping", "mcp.response_format", "headless.run", "operation.batch"}
    import inspect

    from ..backend import GhidraBackend

    for spec in TOOL_SPECS:
        Draft202012Validator.check_schema(spec.input_schema)
        for prop_name, prop_schema in spec.input_schema.get("properties", {}).items():
            if prop_schema.get("type") == "array" and "items" not in prop_schema:
                msg = f"{spec.name}.{prop_name}: array without items"
                raise AssertionError(msg)
        if spec.name in special:
            assert spec.backend_method is None, (
                f"{spec.name}: special tool must have no backend method"
            )
        else:
            assert spec.backend_method is not None, (
                f"{spec.name}: non-special tool missing backend method"
            )
            method = getattr(GhidraBackend, spec.backend_method, None)
            assert method is not None, f"{spec.name}: missing backend method {spec.backend_method}"
            signature = inspect.signature(method)
            params = {
                name
                for name, param in signature.parameters.items()
                if name != "self" and param.default is inspect.Parameter.empty
            }
            required = set(spec.input_schema.get("required", []))
            assert params == required, (
                f"{spec.name}: backend required {sorted(params)} != "
                f"catalog required {sorted(required)}"
            )

    backend_methods = {spec.backend_method for spec in TOOL_SPECS if spec.backend_method}
    assert len(backend_methods) == 212, f"expected 212 backend methods, got {len(backend_methods)}"
