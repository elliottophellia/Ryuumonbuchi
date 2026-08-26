"""Shared schema infrastructure for the tool registry: `ToolSpec`, address constants, and bounds."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

ADDRESS_SCHEMA: dict[str, Any] = {
    "oneOf": [{"type": "integer"}, {"type": "string"}],
}

ADDRESS_PARAM_NAMES: frozenset[str] = frozenset(
    {
        "address",
        "base_address",
        "callsite",
        "end",
        "external_address",
        "from_address",
        "function_start",
        "image_base",
        "source_function",
        "start",
        "storage_address",
        "symbol_address",
        "target_function",
        "thunk_target",
        "to_address",
    }
)


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """One tool definition: name, backend method, schema, classification."""

    name: str
    backend_method: str | None
    description: str
    input_schema: dict[str, Any]
    read_only: bool
    destructive: bool
    open_world: bool
    batch_allowed: bool


_INT_BOUNDS: dict[str, dict[str, int]] = {
    "offset": {"minimum": 0, "maximum": 10_000_000},
    "limit": {"minimum": 1, "maximum": 100_000},
    "count": {"minimum": 1, "maximum": 1_000_000},
    "max_depth": {"minimum": 1, "maximum": 64},
    "timeout_secs": {"minimum": 1, "maximum": 86400},
    "length": {"minimum": 1, "maximum": 512 * 1024 * 1024},
    "byte_length": {"minimum": 1, "maximum": 512 * 1024 * 1024},
    "size": {"minimum": 1, "maximum": 1_000_000_000},
    "bit_size": {"minimum": 1, "maximum": 1_000_000_000},
    "operand_index": {"minimum": 0, "maximum": 255},
    "ordinal": {"minimum": 0, "maximum": 1_000_000},
    "new_ordinal": {"minimum": 0, "maximum": 1_000_000},
}

_STRING_BOUNDS: dict[str, int] = {
    "session_id": 64,
    "data_base64": 1_000_000_000,
    "data_hex": 1_000_000_000,
    "pattern_base64": 1_000_000_000,
    "pattern_hex": 1_000_000_000,
}


def apply_schema_bounds(specs: list[ToolSpec]) -> list[ToolSpec]:
    """Add explicit bounds to limit/offset/count/depth/timeout and payloads."""
    for spec in specs:
        props: dict[str, Any] = spec.input_schema.get("properties", {})
        for prop_name, prop_schema in props.items():
            if prop_schema.get("type") == "integer" and prop_name in _INT_BOUNDS:
                for key, value in _INT_BOUNDS[prop_name].items():
                    prop_schema.setdefault(key, value)
            if prop_schema.get("type") == "string" and prop_name in _STRING_BOUNDS:
                prop_schema.setdefault("maxLength", _STRING_BOUNDS[prop_name])
    return specs
